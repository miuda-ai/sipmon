pub mod call;
pub mod stream;
pub mod turn;

use std::collections::HashMap;

use crate::analyze::rtcp_rtt;
use crate::config::Config;
use crate::decode::{frame, rtcp as rtcpc, rtp as rtpp, sdp, sip as sipd, stun};
use crate::diagnostics::{Diagnostic, Severity, rules};
use crate::model::media::NegotiatedMedia;
use crate::model::packet::Flow5Tuple;
use crate::model::sip::{CallState, Method};
use crate::store::registry::{Registry, StreamKey};
use turn::{Encap, Leg};

pub struct Correlator {
    pub reg: Registry,
    tcp_reasm: crate::decode::tcp_reasm::TcpReassembler,
    invite_rr: HashMap<String, bool>,
    terminal_done: std::collections::HashSet<String>,
    /// Per-stream last-known lost count, for attributing loss deltas to the
    /// per-IP network stats during the periodic flush.
    last_lost: HashMap<StreamKey, u64>,
    min_severity: Severity,
    raw_truncate: Option<usize>,
    no_media: bool,
    /// Buffered evlog events, drained by the pipeline writer.
    pending_events: Vec<crate::store::evlog::Event>,
    last_flush_us: Option<u64>,
    pub turn: turn::TurnTracker,
    /// When false (replay), skip building evlog records that would just be
    /// discarded — SIP ingest otherwise clones every raw message into a
    /// SipMsgEvt on the hot path.
    emit_evlog: bool,
    /// When false, drop a call from RAM as soon as it tears down.
    keep_terminated: bool,
    /// Idle/terminated call TTL in seconds (0 = disabled).
    call_ttl_secs: u64,
    /// Live-session stats (same report as `sipmon stats`), fed from correlator
    /// events so TTL eviction does not drop the summary.
    session_stats: Option<crate::store::evstats::StatsAcc>,
}

fn debug_enabled() -> bool {
    static ONCE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ONCE.get_or_init(|| std::env::var("SIPMON_DEBUG").is_ok())
}

impl Correlator {
    pub fn new(config: &Config, source: String) -> Self {
        let mut reg = Registry::with_source(source);
        reg.set_caps(config.max_calls, config.max_streams, config.max_diagnostics);
        reg.set_bucket(config.bucket.seconds());
        reg.heatmap_retain_us = config.ring_hours * 3600 * 1_000_000;
        Self {
            reg,
            tcp_reasm: crate::decode::tcp_reasm::TcpReassembler::new(),
            invite_rr: HashMap::new(),
            terminal_done: std::collections::HashSet::new(),
            last_lost: HashMap::new(),
            min_severity: Severity::from_level(&config.diag_level),
            raw_truncate: config.raw_truncate,
            no_media: config.no_media,
            pending_events: Vec::new(),
            last_flush_us: None,
            turn: turn::TurnTracker::new(&config.turn_servers),
            emit_evlog: true,
            keep_terminated: config.keep_terminated,
            call_ttl_secs: config.call_ttl_secs,
            session_stats: None,
        }
    }

    pub fn set_focus(&mut self, hint: Option<crate::store::registry::FocusHint>) {
        self.reg.focus_hint = hint;
    }

    /// Update the UI filter hint; pinned matches keep filter results stable.
    pub fn set_search(&mut self, q: Option<String>) {
        self.reg.set_search_hint(q.as_deref());
    }

    /// Reset all in-memory state (TUI `x` clear): registry + correlator
    /// bookkeeping. Evlog writing is unaffected.
    pub fn clear(&mut self) {
        self.reg.clear();
        self.last_lost.clear();
        self.invite_rr.clear();
        self.terminal_done.clear();
        self.pending_events.clear();
        self.last_flush_us = None;
        self.turn.clear();
        if self.session_stats.is_some() {
            self.session_stats = Some(crate::store::evstats::StatsAcc::new());
        }
    }

    /// Drain buffered evlog events (consumed by the pipeline's writer thread).
    pub fn take_events(&mut self) -> Vec<crate::store::evlog::Event> {
        std::mem::take(&mut self.pending_events)
    }

    /// Drain pending events into `out` (cleared first). Unlike `take_events`
    /// the vector keeps its capacity across calls, so the per-frame hot drain
    /// stops regrowing a Vec from zero after the first batch.
    pub fn drain_events_into(&mut self, out: &mut Vec<crate::store::evlog::Event>) {
        out.clear();
        out.append(&mut self.pending_events);
    }

    /// Replay does not write an evlog; skip building records that would be
    /// thrown away (most importantly a clone of every SIP message's raw bytes).
    pub fn disable_evlog_emit(&mut self) {
        self.emit_evlog = false;
    }

    /// Accumulate the same report `sipmon stats` produces, from in-memory
    /// correlator events (used on live exit).
    pub fn enable_session_stats(&mut self) {
        self.session_stats = Some(crate::store::evstats::StatsAcc::new());
    }

    /// Feed a replayed stream summary into the live session report (if on).
    pub fn replay_stream_summary(&mut self, ts_us: u64, s: &crate::model::media::StreamSummary) {
        if let Some(acc) = &mut self.session_stats {
            acc.ingest_stream_summary(ts_us, s);
        }
    }

    /// Feed a replayed RTCP RTT sample into the live session report (if on).
    pub fn replay_rtt_sample(&mut self, ts_us: u64, rtt_ms: f64) {
        if let Some(acc) = &mut self.session_stats {
            acc.ingest_rtt_sample(ts_us, rtt_ms);
        }
    }

    pub fn take_session_stats(&mut self) -> Option<crate::store::evstats::StatsAcc> {
        self.session_stats.take()
    }

    fn push_ev(&mut self, ev: crate::store::evlog::Event) {
        if let Some(s) = &mut self.session_stats {
            s.ingest(&ev);
        }
        if self.emit_evlog {
            self.pending_events.push(ev);
        }
    }

    /// Every ~5s of capture time: emit StreamSnap events for active streams.
    pub fn maybe_periodic_flush(&mut self, ts_us: u64) {
        let due = match self.last_flush_us {
            None => {
                self.last_flush_us = Some(ts_us);
                false
            }
            Some(last) => ts_us.saturating_sub(last) >= 5_000_000,
        };
        if !due {
            return;
        }
        self.last_flush_us = Some(ts_us);
        // Periodic bounded-memory maintenance.
        self.reg.prune_heatmap();
        self.turn.prune();
        self.tcp_reasm
            .prune(ts_us, crate::decode::tcp_reasm::IDLE_US);
        let keep_history = self.keep_terminated;
        let emit_snap = self.emit_evlog || self.session_stats.is_some();
        let keys: Vec<StreamKey> = self.reg.streams.keys().copied().collect();
        for key in keys {
            let Some((flow, lost_now, evt)) = self.reg.streams.get_mut(&key).map(|s| {
                if keep_history {
                    s.sample(ts_us);
                }
                let lost_now = s.snapshot_stats().lost_packets;
                let evt = emit_snap.then(|| s.to_snap_evt(ts_us));
                (s.flow, lost_now, evt)
            }) else {
                continue;
            };
            // Attribute the newly-observed lost packets to both endpoints of
            // the stream in the per-IP network stats (1s bucket resolution).
            // From each IP's viewpoint: lost egress packets at the source,
            // lost ingress packets at the destination.
            let lost_delta =
                lost_now.saturating_sub(self.last_lost.get(&key).copied().unwrap_or(0));
            self.last_lost.insert(key, lost_now);
            if lost_delta > 0 {
                self.reg.ipstats.observe_lost(
                    flow.src.ip(),
                    ts_us,
                    lost_delta,
                    crate::store::ipstats::Dir::Tx,
                );
                self.reg.ipstats.observe_lost(
                    flow.dst.ip(),
                    ts_us,
                    lost_delta,
                    crate::store::ipstats::Dir::Rx,
                );
            }
            if let Some(evt) = evt {
                self.push_ev(crate::store::evlog::Event::StreamSnap(evt));
            }
        }
        // Refresh search pins *before* eviction so newly-matched calls are
        // protected in this cycle (new calls / late-filled From/To users).
        if self.reg.search_hint.is_some() {
            self.reg.refresh_search_matches();
        }
        self.reg.evict_stale(self.call_ttl_secs, ts_us);
        self.reg.evict_if_needed();
        self.last_lost
            .retain(|k, _| self.reg.streams.contains_key(k));
        self.prune_removed_bookkeeping();
        // Drop IPs idle for more than an hour (1s buckets only retain 10 min).
        const IPSTATS_IDLE_US: u64 = 3_600_000_000;
        self.reg
            .ipstats
            .prune_idle(ts_us.saturating_sub(IPSTATS_IDLE_US));
        self.reg
            .sipstats
            .prune_idle(ts_us.saturating_sub(IPSTATS_IDLE_US));
    }

    fn prune_removed_bookkeeping(&mut self) {
        for removed in self.reg.drain_removed() {
            self.invite_rr.remove(&removed);
            self.terminal_done.remove(&removed);
        }
    }

    /// (cfg-test) sizes of per-call bookkeeping maps, for bounded-memory tests.
    #[cfg(test)]
    pub(crate) fn test_bookkeeping_lens(&self) -> (usize, usize) {
        (self.invite_rr.len(), self.terminal_done.len())
    }

    #[cfg(test)]
    pub(crate) fn test_last_lost_len(&self) -> usize {
        self.last_lost.len()
    }

    /// Process one raw frame end-to-end.
    ///
    /// `data` is borrowed from the capture ring and must not be retained.
    pub fn ingest_frame(&mut self, ts_us: u64, linktype: u32, data: &[u8]) {
        self.reg.pkts_total += 1;
        self.reg.touch_time(ts_us);

        let Some(decoded) = frame::decode(linktype, data) else {
            return;
        };
        match decoded.l4 {
            frame::L4::Udp(payload) => self.handle_udp(ts_us, decoded.flow, payload),
            frame::L4::Tcp(payload) => {
                for msg in self.tcp_reasm.feed(decoded.flow, payload, ts_us) {
                    if let Some(sip) = sipd::parse_sip(ts_us, decoded.flow, &msg, self.raw_truncate)
                    {
                        self.ingest_sip(sip);
                    }
                }
            }
        }
    }

    fn handle_udp(&mut self, ts: u64, flow: Flow5Tuple, payload: &[u8]) {
        // RTP/RTCP first: SIP never has version-bits `10`, and this is the
        // overwhelming majority of packets on a live VoIP capture.
        if !self.no_media {
            match rtpp::classify(payload) {
                rtpp::MediaKind::Rtp => {
                    if let Some(h) = rtpp::parse_rtp_header(payload) {
                        self.ingest_rtp(ts, flow, h, payload.len(), Encap::Direct);
                    }
                    return;
                }
                rtpp::MediaKind::Rtcp => {
                    for m in rtcpc::parse_all(payload) {
                        self.ingest_rtcp(ts, flow, &m);
                    }
                    return;
                }
                rtpp::MediaKind::Other => {}
            }
        }
        if sipd::looks_like_sip(payload) {
            if let Some(msg) = sipd::parse_sip(ts, flow, payload, self.raw_truncate) {
                self.ingest_sip(msg);
            }
            return;
        }
        if self.no_media {
            return;
        }
        if stun::is_stun(payload) {
            let (diags, media) = self.turn.ingest(ts, &flow, payload);
            for d in diags {
                self.add_diagnostic(d);
            }
            for m in media {
                self.dispatch_media(ts, flow, &m, Encap::SendIndication);
            }
        } else if stun::is_channel_data(payload)
            && let Some(inner) = stun::channel_data_payload(payload)
        {
            self.dispatch_media(ts, flow, inner, Encap::ChannelData);
        }
    }

    /// Route media bytes (possibly unwrapped from TURN encapsulation) into the
    /// RTP/RTCP paths.
    fn dispatch_media(&mut self, ts: u64, flow: Flow5Tuple, bytes: &[u8], encap: Encap) {
        match rtpp::classify(bytes) {
            rtpp::MediaKind::Rtp => {
                if let Some(h) = rtpp::parse_rtp_header(bytes) {
                    self.ingest_rtp(ts, flow, h, bytes.len(), encap);
                }
            }
            rtpp::MediaKind::Rtcp => {
                for m in rtcpc::parse_all(bytes) {
                    self.ingest_rtcp(ts, flow, &m);
                }
            }
            rtpp::MediaKind::Other => {}
        }
    }

    // ----------------------------- SIP -----------------------------

    fn peer_is_public(flow: &Flow5Tuple) -> bool {
        let s = flow.src.ip();
        let d = flow.dst.ip();
        is_public(s) || is_public(d)
    }

    pub fn ingest_sip(&mut self, msg: crate::model::sip::SipMsg) {
        let ts = msg.ts_us;
        let call_id = msg.call_id.clone();
        if debug_enabled() {
            eprintln!(
                "DEBUG sip ts={} req={} method={:?} status={:?} cseq_method={:?} has_sdp={}",
                ts, msg.is_request, msg.method, msg.status, msg.cseq_method, msg.has_sdp
            );
        }

        // Track whether the initial INVITE carried Record-Route.
        let is_initial_invite =
            matches!(msg.method, Some(Method::Invite)) && msg.is_request && msg.to_tag.is_none();

        // SIP signaling stats (SIP Stats page): request/response distribution
        // per sender IP. The first 2xx answering a dialog's INVITE is credited
        // back to the initial INVITE's source IP so B2BUA-originated 200s
        // still rate the originating sender.
        let answer_for_ip = if !msg.is_request
            && (200..300).contains(&(msg.status.unwrap_or(0)))
            && msg
                .cseq_method
                .as_deref()
                .is_some_and(|m| m.eq_ignore_ascii_case("INVITE"))
        {
            self.reg.calls.get(&call_id).and_then(|c| {
                (c.answer_ts.is_none() && c.invite_ts.is_some())
                    .then(|| {
                        c.invite_key
                            .as_deref()
                            .and_then(|k| k.parse::<std::net::IpAddr>().ok())
                    })
                    .flatten()
            })
        } else {
            None
        };
        self.reg.sipstats.observe(&crate::store::sipstats::SipObs {
            ip: msg.flow.src.ip(),
            ts_us: ts,
            is_request: msg.is_request,
            method: msg.method,
            status: msg.status,
            answer_for_ip,
            initial_invite: is_initial_invite,
        });
        if is_initial_invite {
            self.invite_rr
                .entry(call_id.clone())
                .or_insert(msg.record_route_count > 0);
            // Per-IP concurrent-call count (decremented at teardown).
            self.reg.ipstats.add_active(msg.flow.src.ip(), 1);
            self.reg.ipstats.add_active(msg.flow.dst.ip(), 1);
        }

        // Diagnostics that only need the message.
        let peer_pub = Self::peer_is_public(&msg.flow);
        let mut new_diags = rules::check_contact(ts, &call_id, &msg, peer_pub);
        let invite_had_rr = self.invite_rr.get(&call_id).copied().unwrap_or(false);
        new_diags.extend(rules::check_record_route(ts, &call_id, &msg, invite_had_rr));

        // SDP learning (INVITE / 2xx with SDP body).
        let mut learned: Option<NegotiatedMedia> = None;
        if msg.has_sdp {
            let body = body_of(&msg.raw);
            if let Some(sess) = sdp::parse(body) {
                if debug_enabled() {
                    eprintln!(
                        "DEBUG sdp learned call={} eps={:?}",
                        call_id,
                        sess.endpoints()
                    );
                }
                new_diags.extend(rules::check_sdp(ts, &call_id, &sess));
                let mut neg = NegotiatedMedia::default();
                neg.endpoints = sess.endpoints();
                neg.pts = sess.payload_types();
                neg.codecs = neg
                    .pts
                    .iter()
                    .filter_map(|pt| sess.codec_name_for_pt(*pt))
                    .collect();
                neg.clock_rates = neg
                    .pts
                    .iter()
                    .map(|pt| {
                        sess.clock_rate_for_pt(*pt).unwrap_or_else(|| {
                            crate::decode::rtp::rtp_clock_rate_for_payload_type(*pt)
                        })
                    })
                    .collect();
                learned = Some(neg);
            }
        }

        // Apply state machine.
        let call = self.reg.get_or_create_call(&call_id);
        crate::correlate::call::apply_sip(call, &msg);
        // Assemble the evlog event from &msg first (Copy fields + string/raw
        // clones), leaving msg whole for the move below — the full-SipMsg clone
        // that used to live in apply_sip is gone.
        let evt = crate::store::evlog::Event::SipMsg(crate::store::evlog::SipMsgEvt {
            ts_us: ts,
            flow: msg.flow,
            is_request: msg.is_request,
            method: msg.method.map(|m| m.name().to_string()),
            status: msg.status,
            call_id: msg.call_id.clone(),
            cseq: msg.cseq,
            branch: msg.branch.clone(),
            from_tag: msg.from_tag.clone(),
            to_tag: msg.to_tag.clone(),
            raw: msg.raw.to_vec(),
        });
        // Store the message by move; bound per-call message retention (a
        // pathological long-lived call must not grow without limit; focus
        // detail already caps at 1000 for display).
        call.messages.push(msg);
        const MAX_MSGS_PER_CALL: usize = 2000;
        if call.messages.len() > MAX_MSGS_PER_CALL {
            let excess = call.messages.len() - MAX_MSGS_PER_CALL;
            call.messages.drain(0..excess);
        }
        if let Some(n) = &learned {
            if call.negotiated.pts.is_empty() {
                call.negotiated = n.clone();
            } else {
                // Merge answer into the offer (intersect PTs at the endpoint set).
                call.negotiated
                    .endpoints
                    .extend(n.endpoints.iter().copied());
                for pt in &n.pts {
                    if !call.negotiated.pts.contains(pt) {
                        call.negotiated.pts.push(*pt);
                        call.negotiated.clock_rates.push(n.clock_rate_for_pt(*pt));
                    }
                }
                for c in &n.codecs {
                    if !call.negotiated.codecs.contains(c) {
                        call.negotiated.codecs.push(c.clone());
                    }
                }
            }
        }

        // Register SDP endpoints for RTP association.
        if let Some(n) = &learned {
            for ep in &n.endpoints {
                self.reg.endpoint_call.insert(*ep, call_id.clone());
            }
            self.apply_sdp_clocks(&call_id);
        }

        // Evlog: emit the pre-assembled SIP message event.
        self.push_ev(evt);

        // Apply diagnostics (counts + ring).
        for d in new_diags {
            self.add_diagnostic(d);
        }

        // Terminal transition handling (once per call).
        let terminal = self
            .reg
            .calls
            .get(&call_id)
            .map(|c| {
                matches!(
                    c.state,
                    CallState::Completed | CallState::Failed | CallState::Canceled
                )
            })
            .unwrap_or(false);
        if terminal && self.terminal_done.insert(call_id.clone()) {
            self.on_call_terminal(&call_id);
        }
    }

    /// Push SDP `a=rtpmap` clocks onto already-seen streams (early media
    /// before the answer, or a late INVITE SDP).
    fn apply_sdp_clocks(&mut self, call_id: &str) {
        let rates: Vec<(u8, u32)> = {
            let Some(call) = self.reg.calls.get(call_id) else {
                return;
            };
            if call.negotiated.pts.is_empty() {
                return;
            }
            call.negotiated
                .pts
                .iter()
                .copied()
                .map(|pt| (pt, call.negotiated.clock_rate_for_pt(pt)))
                .collect()
        };
        let keys = self
            .reg
            .stream_index
            .get(call_id)
            .cloned()
            .unwrap_or_default();
        for key in keys {
            let Some(stream) = self.reg.streams.get_mut(&key) else {
                continue;
            };
            let Some(pt) = stream.last_pt.or(stream.payload_type) else {
                continue;
            };
            if let Some((_, rate)) = rates.iter().find(|(p, _)| *p == pt) {
                stream.apply_clock_rate(*rate);
            }
        }
    }

    // ----------------------------- RTP -----------------------------

    pub fn ingest_rtp(
        &mut self,
        ts: u64,
        flow: Flow5Tuple,
        header: rtpp::RtpHeader,
        len: usize,
        encap: Encap,
    ) {
        let key = StreamKey {
            flow,
            ssrc: header.ssrc,
        };
        if self.observe_existing_rtp(ts, flow, header, len, key) {
            return;
        }
        // Resolve call via SDP endpoints (two O(1) lookups).
        let Some(call_id) = self
            .reg
            .endpoint_call
            .get(&flow.src)
            .or_else(|| self.reg.endpoint_call.get(&flow.dst))
            .cloned()
        else {
            if debug_enabled() {
                eprintln!("DEBUG rtp no-call flow={}", flow);
            }
            return;
        };
        if debug_enabled() {
            eprintln!(
                "DEBUG rtp call={} flow={} ssrc={:#x} pt={}",
                call_id, flow, header.ssrc, header.payload_type
            );
        }

        self.reg
            .ipstats
            .observe_packet(flow.src.ip(), ts, len, crate::store::ipstats::Dir::Tx);
        self.reg
            .ipstats
            .observe_packet(flow.dst.ip(), ts, len, crate::store::ipstats::Dir::Rx);

        let reverse_flow = flow.reverse();
        let reverse_exists = self
            .reg
            .stream_index
            .get(&call_id)
            .is_some_and(|keys| keys.iter().any(|k| k.flow == reverse_flow));
        let leg = self.turn.leg_of(&flow);
        let neg_for_new = self.reg.calls.get(&call_id).map(|c| c.negotiated.clone());

        let mut diags: Vec<Diagnostic> = Vec::new();
        {
            let stream = self.reg.streams.entry(key).or_insert_with(|| {
                crate::correlate::stream::RtpStream::new(flow, header.ssrc, call_id.clone())
            });
            if let Some(neg) = &neg_for_new {
                stream.codec = neg
                    .pts
                    .iter()
                    .position(|p| *p == header.payload_type)
                    .and_then(|i| neg.codecs.get(i).cloned());
                stream.apply_clock_rate(neg.clock_rate_for_pt(header.payload_type));
            }
            if let Some(l) = leg {
                stream.via_turn = true;
                stream.leg = Some(l);
            }
            if encap != Encap::Direct {
                stream.via_turn = true;
            }
            stream.observe(ts, header, len);
            if reverse_exists {
                stream.reverse_seen = true;
            }
        }

        self.reg.note_stream(&call_id, key);
        if let Some(c) = self.reg.calls.get_mut(&call_id) {
            for ip in [flow.src.ip(), flow.dst.ip()] {
                if !c.ips.contains(&ip) {
                    c.ips.push(ip);
                }
            }
        }
        if let Some(neg) = &neg_for_new {
            if let Some(d) =
                rules::check_rtp_pt(ts, &call_id, header.ssrc, header.payload_type, neg)
            {
                diags.push(d);
            }
            if let Some(d) = rules::check_rtp_flow(ts, &call_id, &flow, neg) {
                diags.push(d);
            }
        }
        if encap == Encap::ChannelData {
            diags.push(Diagnostic {
                ts_us: ts,
                call_id: call_id.clone(),
                severity: Severity::Info,
                code: crate::diagnostics::TURN_CHANNEL_MEDIA,
                message: format!(
                    "RTP ssrc={:#x} carried in TURN ChannelData on {}",
                    header.ssrc, flow
                ),
            });
        } else if encap == Encap::SendIndication {
            diags.push(Diagnostic {
                ts_us: ts,
                call_id: call_id.clone(),
                severity: Severity::Info,
                code: crate::diagnostics::TURN_SEND_IND_MEDIA,
                message: format!(
                    "RTP ssrc={:#x} carried in TURN Send/Data indication on {}",
                    header.ssrc, flow
                ),
            });
        }
        if let Some(l) = leg {
            diags.push(Diagnostic {
                ts_us: ts,
                call_id: call_id.clone(),
                severity: Severity::Info,
                code: crate::diagnostics::TURN_RELAY_MEDIA,
                message: format!("media relayed via TURN ({}-leg) on {}", l.label(), flow),
            });
        }
        if (leg.is_some() || encap != Encap::Direct)
            && let Some(c) = self.reg.calls.get_mut(&call_id)
        {
            c.via_turn = true;
        }

        for d in diags {
            self.add_diagnostic(d);
        }

        if reverse_exists
            && let Some(rs) = self.reg.streams.get_mut(&StreamKey {
                flow: reverse_flow,
                ssrc: header.ssrc,
            })
        {
            rs.reverse_seen = true;
        }

        if let Some(c) = self.reg.calls.get_mut(&call_id) {
            c.pkts_rtp += 1;
            c.last_ts_us = ts;
        }
    }

    /// Hot path for an already-tracked RTP stream: no Call-ID clone, no
    /// endpoint lookup, no stream creation. Returns false if `key` is unknown.
    fn observe_existing_rtp(
        &mut self,
        ts: u64,
        flow: Flow5Tuple,
        header: rtpp::RtpHeader,
        len: usize,
        key: StreamKey,
    ) -> bool {
        let pt_diag = {
            let streams = &mut self.reg.streams;
            let calls = &mut self.reg.calls;
            let ipstats = &mut self.reg.ipstats;
            let Some(stream) = streams.get_mut(&key) else {
                return false;
            };
            let prev_pt = stream.last_pt;
            stream.observe(ts, header, len);
            if let Some(c) = calls.get_mut(&stream.call_id) {
                c.pkts_rtp += 1;
                c.last_ts_us = ts;
            }
            ipstats.observe_packet(flow.src.ip(), ts, len, crate::store::ipstats::Dir::Tx);
            ipstats.observe_packet(flow.dst.ip(), ts, len, crate::store::ipstats::Dir::Rx);
            if prev_pt.is_some_and(|p| p != header.payload_type) {
                rules::check_pt_change(
                    ts,
                    &stream.call_id,
                    header.ssrc,
                    header.payload_type,
                    prev_pt,
                )
            } else {
                None
            }
        };
        if let Some(d) = pt_diag {
            self.add_diagnostic(d);
        }
        true
    }

    /// One-way media detection, invoked at call teardown.
    fn check_oneway_at_teardown(&mut self, call_id: &str) {
        let flows: Vec<Flow5Tuple> = self
            .reg
            .call_stream_keys(call_id)
            .iter()
            .filter_map(|k| self.reg.streams.get(k).map(|s| s.flow))
            .collect();
        if flows.is_empty() {
            return;
        }
        let any_reverse = flows
            .iter()
            .any(|f| flows.iter().any(|g| g == &f.reverse()));
        let ts = self.reg.last_us.unwrap_or(0);
        if !any_reverse && flows.len() == 1 {
            self.add_diagnostic(Diagnostic {
                ts_us: ts,
                call_id: call_id.to_string(),
                severity: Severity::Warn,
                code: crate::diagnostics::ONE_WAY_MEDIA,
                message: format!("only one RTP direction observed on {}", flows[0]),
            });
        }
    }

    // ----------------------------- RTCP -----------------------------

    pub fn ingest_rtcp(&mut self, ts: u64, _flow: Flow5Tuple, msg: &rtcpc::RtcpMessage) {
        // Count RTCP packets on the owning call (if any).
        let ssrc = match msg {
            rtcpc::RtcpMessage::Rr(rr) => rr.ssrc,
            rtcpc::RtcpMessage::Sr(sr) => sr.ssrc,
            _ => 0,
        };
        if ssrc != 0
            && let Some(cid) = self
                .reg
                .ssrc_index
                .get(&ssrc)
                .and_then(|keys| keys.first().copied())
                .and_then(|key| self.reg.streams.get(&key).map(|s| s.call_id.clone()))
            && let Some(c) = self.reg.calls.get_mut(&cid)
        {
            c.pkts_rtcp += 1;
            c.last_ts_us = ts;
        }
        let arrival_ntp = rtcp_rtt::unix_us_to_ntp_secs(ts);
        if debug_enabled() {
            let desc = match msg {
                rtcpc::RtcpMessage::Sr(sr) => format!(
                    "SR ssrc={:#x} ntp={}.{} rtp_ts={} blocks={:?}",
                    sr.ssrc,
                    sr.sender.ntp_secs,
                    sr.sender.ntp_frac,
                    sr.sender.rtp_timestamp,
                    sr.reports
                        .iter()
                        .map(|b| (b.ssrc, b.lsr, b.dlsr))
                        .collect::<Vec<_>>()
                ),
                rtcpc::RtcpMessage::Rr(rr) => format!(
                    "RR ssrc={:#x} blocks={:?}",
                    rr.ssrc,
                    rr.reports
                        .iter()
                        .map(|b| (b.ssrc, b.lsr, b.dlsr))
                        .collect::<Vec<_>>()
                ),
                rtcpc::RtcpMessage::Other(p) => format!("OTHER pt={p}"),
            };
            eprintln!("DEBUG rtcp {desc}");
        }
        let mut samples: Vec<(u32, Option<f64>, Option<f64>)> = Vec::new(); // (ssrc, rtt_ms, oneway_ms)
        match msg {
            rtcpc::RtcpMessage::Rr(rr) => {
                for b in &rr.reports {
                    if let Some(rtt) = rtcp_rtt::rtt_from_rr(arrival_ntp, b) {
                        samples.push((b.ssrc, Some(rtt), None));
                    }
                }
            }
            rtcpc::RtcpMessage::Sr(sr) => {
                if let Some(oneway) = rtcp_rtt::oneway_from_sr(arrival_ntp, sr) {
                    samples.push((sr.ssrc, None, Some(oneway)));
                }
                for b in &sr.reports {
                    if let Some(rtt) = rtcp_rtt::rtt_from_rr(arrival_ntp, b) {
                        samples.push((b.ssrc, Some(rtt), None));
                    }
                }
            }
            _ => {}
        }
        for (ssrc, rtt, oneway) in samples {
            // O(1) attachment via the SSRC index (no full-stream scan).
            let keys = self
                .reg
                .ssrc_index
                .get(&ssrc)
                .map(|v| v.iter().copied().collect::<Vec<_>>())
                .unwrap_or_default();
            let mut call_id = None;
            for key in &keys {
                if let Some(s) = self.reg.streams.get_mut(key) {
                    call_id = Some(s.call_id.clone());
                    if let Some(r) = rtt {
                        s.rtt_samples.push(r);
                        if s.rtt_samples.len() > 256 {
                            s.rtt_samples.remove(0);
                        }
                    }
                    if let Some(o) = oneway {
                        s.oneway_samples.push(o);
                        if s.oneway_samples.len() > 256 {
                            s.oneway_samples.remove(0);
                        }
                    }
                }
            }
            if let Some(cid) = call_id
                && rtt.is_some()
            {
                self.push_ev(crate::store::evlog::Event::RtcpRtt(
                    crate::store::evlog::RtcpRttEvt {
                        ts_us: ts,
                        call_id: cid,
                        ssrc,
                        rtt_ms: rtt.unwrap_or(0.0),
                        oneway_ms: oneway,
                    },
                ));
            }
        }
    }

    // ----------------------------- diagnostics bookkeeping -----------------------------

    fn add_diagnostic(&mut self, d: Diagnostic) {
        if d.severity < self.min_severity {
            return;
        }
        // Evlog record.
        self.push_ev(crate::store::evlog::Event::Diag(
            crate::store::evlog::DiagEvt {
                ts_us: d.ts_us,
                call_id: d.call_id.clone(),
                severity: match d.severity {
                    Severity::Info => 0,
                    Severity::Warn => 1,
                    Severity::Critical => 2,
                },
                code: d.code.to_string(),
                message: d.message.clone(),
            },
        ));
        // Update per-call counts.
        if let Some(c) = self.reg.calls.get_mut(&d.call_id) {
            match d.severity {
                Severity::Critical => c.critical_count += 1,
                Severity::Warn => c.warn_count += 1,
                Severity::Info => {}
            }
        }
        self.reg.push_event(format!(
            "[{}] {} {} ({})",
            d.severity.label(),
            d.call_id,
            d.code,
            d.message
        ));
        self.reg.diagnostics.push_back(d);
        while self.reg.diagnostics.len() > self.reg.max_diagnostics {
            self.reg.diagnostics.pop_front();
        }
    }

    /// Run end-of-call housekeeping (teardown diagnostics, heatmap, eviction).
    pub fn on_call_terminal(&mut self, call_id: &str) {
        self.check_oneway_at_teardown(call_id);
        self.check_turn_legs(call_id);
        self.record_heatmap(call_id);
        // Release the per-IP concurrent-call counters held by this call.
        if let Some(c) = self.reg.calls.get(call_id) {
            for ip in &c.active_ips {
                self.reg.ipstats.add_active(*ip, -1);
            }
        }
        let terminal = self
            .reg
            .calls
            .get(call_id)
            .map(|c| {
                matches!(
                    c.state,
                    CallState::Completed | CallState::Failed | CallState::Canceled
                )
            })
            .unwrap_or(false);
        if terminal {
            // Evlog teardown event.
            let info = self.reg.calls.get(call_id).map(|c| {
                (
                    c.state.label(),
                    state_code(c.state),
                    outcome_code(c.outcome),
                    c.end_ts.or(self.reg.last_us).unwrap_or(0),
                    c.from_user.clone(),
                    c.to_user.clone(),
                    c.from_uri.clone(),
                    c.to_uri.clone(),
                    c.invite_ts,
                    c.trying_ts,
                    c.ringing_ts,
                    c.answer_ts,
                    c.bye_ts,
                    c.end_ts,
                    c.pdd_ms,
                    c.setup_ms,
                    c.hangup.code,
                    c.hangup.reason.clone(),
                    c.pkts_sip,
                    c.pkts_rtp,
                    c.pkts_rtcp,
                    c.bytes,
                )
            });
            if let Some((
                state_label,
                state_c,
                outcome_c,
                evt_ts,
                from_user,
                to_user,
                from_uri,
                to_uri,
                invite_ts,
                trying_ts,
                ringing_ts,
                answer_ts,
                bye_ts,
                end_ts,
                pdd_ms,
                setup_ms,
                hangup_code,
                hangup_reason,
                pkts_sip,
                pkts_rtp,
                pkts_rtcp,
                bytes,
            )) = info
            {
                let code_str = hangup_code.map(|v| v.to_string()).unwrap_or_default();
                self.reg
                    .push_event(format!("call {call_id} -> {state_label} ({code_str})"));
                self.push_ev(crate::store::evlog::Event::Call(
                    crate::store::evlog::CallEvt {
                        ts_us: evt_ts,
                        call_id: call_id.to_string(),
                        kind: crate::store::evlog::CallEvtKind::Teardown,
                        from_user,
                        to_user,
                        from_uri,
                        to_uri,
                        state: state_c,
                        outcome: outcome_c,
                        invite_ts,
                        trying_ts,
                        ringing_ts,
                        answer_ts,
                        bye_ts,
                        end_ts,
                        pdd_ms,
                        setup_ms,
                        hangup_code,
                        hangup_reason,
                        pkts_sip,
                        pkts_rtp,
                        pkts_rtcp,
                        bytes,
                    },
                ));
            }
            match self.reg.calls.get(call_id).map(|c| c.state) {
                Some(CallState::Completed) => self.reg.completed += 1,
                Some(CallState::Failed) | Some(CallState::Canceled) => self.reg.failed += 1,
                _ => {}
            }
            if !self.keep_terminated {
                // Headless record: evlog already has the dialog; free RAM now.
                self.reg.remove_call(call_id);
            } else {
                self.reg.evict_if_needed();
            }
        }
        // Prune per-call bookkeeping for evicted calls so long-running sessions
        // stay bounded (invite_rr / terminal_done would otherwise grow forever).
        self.prune_removed_bookkeeping();
    }

    /// Per-leg quality decomposition for TURN-relayed calls: compare average
    /// loss on the client<->relay leg vs the relay<->peer leg to locate the
    /// bottleneck side.
    fn check_turn_legs(&mut self, call_id: &str) {
        let mut client_loss = 0.0;
        let mut client_n = 0u64;
        let mut peer_loss = 0.0;
        let mut peer_n = 0u64;
        let mut any_turn = false;
        for k in self.reg.call_stream_keys(call_id) {
            if let Some(s) = self.reg.streams.get(k) {
                if !s.via_turn {
                    continue;
                }
                any_turn = true;
                let st = s.summary();
                match s.leg {
                    Some(Leg::Client) => {
                        client_loss += st.loss_pct;
                        client_n += 1;
                    }
                    Some(Leg::Peer) => {
                        peer_loss += st.loss_pct;
                        peer_n += 1;
                    }
                    None => {}
                }
            }
        }
        if !any_turn {
            return;
        }
        let avg = |sum: f64, n: u64| if n == 0 { None } else { Some(sum / n as f64) };
        let (cl, pl) = (avg(client_loss, client_n), avg(peer_loss, peer_n));
        if let (Some(cl), Some(pl)) = (cl, pl) {
            let delta = (cl - pl).abs();
            if delta > 5.0 {
                let side = if cl > pl {
                    "client<->relay"
                } else {
                    "relay<->peer"
                };
                self.add_diagnostic(Diagnostic {
                    ts_us: self.reg.last_us.unwrap_or(0),
                    call_id: call_id.to_string(),
                    severity: Severity::Warn,
                    code: crate::diagnostics::TURN_LEG_IMBALANCE,
                    message: format!(
                        "TURN leg loss imbalance: client-leg {cl:.1}% vs peer-leg {pl:.1}% (bottleneck on {side})"
                    ),
                });
            }
        }
    }

    fn record_heatmap(&mut self, call_id: &str) {
        let Some(call) = self.reg.calls.get(call_id) else {
            return;
        };
        let terminal = matches!(
            call.state,
            CallState::Completed | CallState::Failed | CallState::Canceled
        );
        if !terminal {
            return;
        }
        let ts = call
            .end_ts
            .or(call.bye_ts)
            .or(call.answer_ts)
            .or(call.invite_ts)
            .unwrap_or(0);
        // Key: source IP of the first INVITE (the far end that initiated),
        // retained on the call so it survives message-buffer trimming.
        let key = call.invite_key.clone().unwrap_or_else(|| "?".to_string());
        let answered = call.answer_ts.is_some();
        let failed = matches!(call.state, CallState::Failed | CallState::Canceled);
        let pdd = call.pdd_ms.map(|p| p as f64);

        let mut jit = 0.0;
        let mut jit_n = 0u64;
        let mut loss = 0.0;
        let mut loss_n = 0u64;
        let mut rtt = 0.0;
        let mut rtt_n = 0u64;
        let mut mos_v = 0.0;
        let mut mos_n = 0u64;
        for s in self
            .reg
            .call_stream_keys(call_id)
            .iter()
            .filter_map(|k| self.reg.streams.get(k))
        {
            let sum = s.summary();
            if let Some(j) = sum.jitter_ms {
                jit += j;
                jit_n += 1;
            }
            loss += sum.loss_pct;
            loss_n += 1;
            if let Some(r) = sum.rtt_avg_ms {
                rtt += r;
                rtt_n += 1;
            }
            if let Some(m) = sum.mos {
                mos_v += m;
                mos_n += 1;
            }
        }
        let avg = |s: f64, n: u64| if n == 0 { None } else { Some(s / n as f64) };
        self.reg.heatmap.record_call(
            ts,
            key,
            answered,
            failed,
            pdd,
            avg(jit, jit_n),
            avg(loss, loss_n),
            avg(rtt, rtt_n),
            avg(mos_v, mos_n),
        );
    }
}

fn body_of(raw: &[u8]) -> &[u8] {
    match raw.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(i) => &raw[i + 4..],
        None => &[],
    }
}

fn is_public(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            !v4.is_private()
                && !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_unspecified()
                && !v4.is_broadcast()
        }
        std::net::IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unicast_link_local(),
    }
}

fn state_code(s: CallState) -> u8 {
    match s {
        CallState::Dialing => 0,
        CallState::Ringing => 1,
        CallState::Active => 2,
        CallState::Completed => 3,
        CallState::Failed => 4,
        CallState::Canceled => 5,
    }
}

fn outcome_code(o: crate::model::sip::Outcome) -> u8 {
    use crate::model::sip::Outcome::*;
    match o {
        InProgress => 0,
        Answered => 1,
        Rejected => 2,
        NoAnswer => 3,
        Canceled => 4,
        Failed => 5,
    }
}

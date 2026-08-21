use std::collections::{HashMap, HashSet, VecDeque};
use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use crate::diagnostics::Diagnostic;
use crate::model::media::StreamSummary;
use crate::model::sip::{B2buaInfo, Call, CallState, HangupBy, Method, Outcome, SipMsg};
use crate::store::ipstats::{Dir, IpStats, IpStatsStore};

/// UI focus request: primary Call-ID plus an optional linked b-leg Call-ID.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FocusHint {
    pub primary: String,
    pub linked: Option<String>,
}

impl FocusHint {
    pub fn primary(id: impl Into<String>) -> Self {
        Self {
            primary: id.into(),
            linked: None,
        }
    }

    pub fn with_linked(primary: impl Into<String>, linked: impl Into<String>) -> Self {
        Self {
            primary: primary.into(),
            linked: Some(linked.into()),
        }
    }
}

/// Focused-call detail payload for the Call Detail page.
#[derive(Debug, Clone, Default)]
pub struct Focus {
    pub call_id: String,
    pub state: Option<CallState>,
    pub from_user: Option<String>,
    pub to_user: Option<String>,
    /// Caller-side UA string (User-Agent of the initial INVITE).
    pub caller_ua: Option<String>,
    /// Callee-side UA string (Server/User-Agent of the first response).
    pub callee_ua: Option<String>,
    /// Caller signaling address (src of the initial INVITE).
    pub caller_addr: Option<std::net::SocketAddr>,
    /// Caller signaling IP (from the initial INVITE; survives message trimming
    /// via the call's `invite_key`). Used to split media into TX/RX.
    pub caller_ip: Option<std::net::IpAddr>,
    /// Callee signaling address (src of the first response).
    pub callee_addr: Option<std::net::SocketAddr>,
    pub messages: Vec<SipMsg>,
    /// Dialog (leg) index per message, parallel to `messages`. Messages of the
    /// same dialog share a leg index; a call with ≥2 legs is a same-Call-ID
    /// B2BUA split. Legs are derived from `from_tag` (fallback `branch`).
    pub legs: Vec<u8>,
    /// B2BUA evidence: dual-dialog split within this Call-ID, or a pairing
    /// with a sibling call-id whose INVITE the B2BUA rewrote.
    pub b2bua: Option<B2buaInfo>,
    pub streams: Vec<StreamSummary>,
    pub diagnostics: Vec<Diagnostic>,
    pub negotiated_endpoints: Vec<std::net::SocketAddr>,
    /// Call timing / outcome details for the header block.
    pub pdd_ms: Option<u32>,
    pub setup_ms: Option<u32>,
    pub ring_ms: Option<u32>,
    /// True if early media (183 with SDP) was negotiated.
    pub early_media: bool,
    /// Milestone timestamps for the setup timeline (chrome-devtools-style).
    pub invite_ts: Option<u64>,
    pub trying_ts: Option<u64>,
    pub ringing_ts: Option<u64>,
    pub answer_ts: Option<u64>,
    pub bye_ts: Option<u64>,
    pub end_ts: Option<u64>,
    pub hangup_by: Option<HangupBy>,
    pub hangup_code: Option<u32>,
    pub hangup_reason: Option<String>,
}

/// One RTP/RTCP stream keyed by (5-tuple, ssrc).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamKey {
    pub flow: crate::model::packet::Flow5Tuple,
    pub ssrc: u32,
}

/// Identity of an imported (replay) stream. `flow` is None for older/partial
/// summaries that didn't carry a 5-tuple.
#[derive(Clone, PartialEq, Eq, Hash)]
struct ImportKey {
    call_id: String,
    ssrc: u32,
    flow: Option<crate::model::packet::Flow5Tuple>,
}

fn import_key(s: &StreamSummary) -> ImportKey {
    ImportKey {
        call_id: s.call_id.clone().unwrap_or_default(),
        ssrc: s.ssrc,
        flow: s.flow,
    }
}

/// Recent-activity ordering helper.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CallSummary {
    pub call_id: String,
    pub from_user: Option<String>,
    pub to_user: Option<String>,
    /// Source IP of the initial INVITE (the caller side).
    pub caller_ip: Option<std::net::IpAddr>,
    /// Source `ip:port` of the initial INVITE (first message).
    pub caller_src: Option<String>,
    pub state: CallState,
    pub outcome: Outcome,
    pub invite_ts: Option<u64>,
    pub duration_ms: Option<u64>,
    pub pdd_ms: Option<u32>,
    pub setup_ms: Option<u32>,
    /// Ringing duration (ring → answer).
    pub ring_ms: Option<u32>,
    /// Provisional code that started ringing: 180 or 183.
    pub ring_code: Option<u16>,
    /// True if early media (183 with SDP) was negotiated.
    pub early_media: bool,
    /// Who initiated the hangup.
    pub hangup_by: Option<HangupBy>,
    pub hangup_code: Option<u32>,
    pub pkts_sip: u64,
    pub pkts_rtp: u64,
    pub best_mos: Option<f64>,
    pub warn_count: u32,
    pub critical_count: u32,
    pub stream_count: usize,
    /// True if the call's media traversed a learned TURN relay.
    pub via_turn: bool,
    /// Distinct IPs involved in the call (drill-down from the IP page).
    pub ips: Vec<std::net::IpAddr>,
}

/// Lightweight immutable snapshot for the TUI/export.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub source: String,
    pub elapsed_us: Option<u64>,
    /// Absolute (epoch us) timestamp of the first observed frame: the
    /// recording/session start used to compute each event's already-recorded
    /// duration in the Call Detail flow / call lists.
    pub start_us: Option<u64>,
    /// UTC offset (seconds) of the machine that recorded the event log, when
    /// known (replay). Used to render the original local wall-clock.
    pub tz_offset_secs: Option<i32>,
    pub pps: f64,
    pub pkts_total: u64,
    /// Packets the monitor itself dropped (kernel/libpcap ring overflow) on
    /// live captures. Non-zero means loss figures may include monitor-side
    /// drops, not network loss.
    pub pkts_dropped: u64,
    pub calls_total: u64,
    pub active: usize,
    pub completed: usize,
    pub failed: usize,
    pub avg_pdd_ms: f64,
    pub avg_setup_ms: f64,
    pub avg_jitter_ms: f64,
    pub avg_loss_pct: f64,
    pub avg_rtt_ms: f64,
    pub avg_mos: f64,
    pub asr: f64,
    pub calls: Vec<CallSummary>,
    pub streams: Vec<StreamSummary>,
    pub events: VecDeque<String>,
    /// Diagnostics for the focused call (filtered by the UI).
    pub diagnostics: Vec<Diagnostic>,
    /// Per-IP network stats (IP page).
    pub ip_stats: Vec<IpStats>,
    /// Per-IP SIP signaling stats (SIP Stats page): global ALL row first.
    pub sip_stats: Vec<crate::store::sipstats::SipIpRow>,
    /// Heatmap cells: (bucket_us, key, metrics).
    pub buckets: Vec<(u64, String, crate::model::stats::MetricSet)>,
    /// Focused call detail (set by the UI via Correlator focus hint).
    pub focus: Option<Focus>,
    #[allow(dead_code)]
    pub paused: bool,
}

/// In-memory application state. Updated by the pipeline thread, snapshotted by
/// the UI/export thread.
pub struct Registry {
    pub calls: FxHashMap<String, Call>,
    /// Insertion order for stable recent-first listing.
    pub order: Vec<String>,
    pub streams: FxHashMap<StreamKey, crate::correlate::stream::RtpStream>,
    /// call_id per stream (reverse lookup).
    pub stream_call: FxHashMap<StreamKey, String>,
    /// SDP-advertised media endpoint -> call_id (for RTP association). Looked
    /// up only on the new-stream slow path (`observe_existing_rtp` handles
    /// known streams without it), so a plain String value is fine.
    pub endpoint_call: FxHashMap<std::net::SocketAddr, String>,
    pub events: VecDeque<String>,
    pub source: String,
    pub start_us: Option<u64>,
    pub last_us: Option<u64>,
    pub pkts_total: u64,
    /// UTC offset (seconds) of the machine that recorded the event log
    /// (populated on replay); used to render the original local wall-clock.
    pub tz_offset_secs: Option<i32>,
    /// Live-capture drop counter (kernel/libpcap stats), see Snapshot's field.
    pub pkts_dropped: u64,
    pub pkts_last_window: u64,
    pub window_start_us: Option<u64>,
    pub pps: f64,
    pub completed: u64,
    pub failed: u64,
    /// Diagnostic ring buffer.
    pub diagnostics: VecDeque<Diagnostic>,
    /// Heatmap aggregation buckets.
    pub heatmap: crate::store::heatmap::Heatmap,
    /// UI focus hint: primary (+ optional linked b-leg) whose detail is included
    /// in snapshots.
    pub focus_hint: Option<FocusHint>,
    /// UI filter hint: the current filter query (rule syntax, see
    /// `filter.rs`). Matching calls are pinned in snapshots (even outside
    /// the recent-calls window) and protected from TTL / capacity eviction,
    /// so filter results don't vanish mid-analysis.
    pub search_hint: Option<String>,
    /// Call-ids currently matching `search_hint` (refreshed on hint change and
    /// on periodic maintenance; bounded by [`SEARCH_PIN_MAX`]).
    search_matches: Vec<String>,
    /// Call-ids removed by eviction since the last drain (lets the correlator
    /// prune its own per-call maps like `invite_rr` / `terminal_done`, keeping
    /// long-running sessions bounded).
    pub removed: VecDeque<String>,
    /// Heatmap bucket window in microseconds (older buckets are pruned).
    pub heatmap_retain_us: u64,
    /// Per-call stream index (call_id -> stream keys): keeps per-packet and
    /// per-call paths O(streams-in-call) instead of O(total streams).
    pub stream_index: FxHashMap<String, Vec<StreamKey>>,
    /// SSRC -> stream keys: O(1) RTCP sample attachment (no full scan). The
    /// same SSRC almost always maps to ≤2 streams, so inline storage avoids a
    /// heap alloc on the RTCP path.
    pub ssrc_index: FxHashMap<u32, SmallVec<[StreamKey; 2]>>,
    /// Per-IP packet/loss statistics (updated on the RTP hot path + 5s flush).
    pub ipstats: IpStatsStore,
    /// Per-IP SIP signaling statistics (SIP Stats page).
    pub sipstats: crate::store::sipstats::SipStatsStore,
    /// Stream summaries reconstructed from a replay/import, keyed for O(1)
    /// upsert (StreamSnap is emitted every 5s; a Vec + linear scan was O(n²)
    /// on multi-hour recordings).
    imported_streams: HashMap<ImportKey, StreamSummary>,
    /// call_id → import keys, so summarize/focus don't scan every imported stream.
    imported_by_call: HashMap<String, Vec<ImportKey>>,
    pub max_calls: usize,
    pub max_streams: usize,
    pub max_diagnostics: usize,
}

/// Upper bound on search-pinned call-ids (protection + snapshot injection).
pub const SEARCH_PIN_MAX: usize = 1000;

impl Default for Registry {
    fn default() -> Self {
        Self {
            calls: FxHashMap::default(),
            order: Vec::new(),
            streams: FxHashMap::default(),
            stream_call: FxHashMap::default(),
            endpoint_call: FxHashMap::default(),
            events: VecDeque::with_capacity(512),
            source: String::new(),
            start_us: None,
            last_us: None,
            pkts_total: 0,
            tz_offset_secs: None,
            pkts_dropped: 0,
            pkts_last_window: 0,
            window_start_us: None,
            pps: 0.0,
            completed: 0,
            failed: 0,
            diagnostics: VecDeque::new(),
            heatmap: crate::store::heatmap::Heatmap::new(900),
            focus_hint: None,
            search_hint: None,
            search_matches: Vec::new(),
            stream_index: FxHashMap::default(),
            ssrc_index: FxHashMap::default(),
            ipstats: IpStatsStore::new(),
            sipstats: crate::store::sipstats::SipStatsStore::new(),
            imported_streams: HashMap::new(),
            imported_by_call: HashMap::new(),
            removed: VecDeque::new(),
            heatmap_retain_us: 24 * 3600 * 1_000_000,
            max_calls: 100_000,
            max_streams: 50_000,
            max_diagnostics: 50_000,
        }
    }
}

impl Registry {
    pub fn with_source(source: String) -> Self {
        Self {
            source,
            ..Self::default()
        }
    }

    pub fn set_caps(&mut self, max_calls: usize, max_streams: usize, max_diagnostics: usize) {
        self.max_calls = max_calls;
        self.max_streams = max_streams;
        self.max_diagnostics = max_diagnostics;
    }

    pub fn set_bucket(&mut self, bucket_secs: u64) {
        let heat = std::mem::replace(
            &mut self.heatmap,
            crate::store::heatmap::Heatmap::new(bucket_secs),
        );
        if heat.bucket_secs() != bucket_secs {
            // Buckets are incompatible; rebuild empty (v1: heatmap is
            // forward-accumulating only).
        }
    }

    /// Reset all runtime state (the `x` / clear shortcut): calls, streams,
    /// diagnostics, events, heatmap, per-IP stats and counters. The evlog
    /// writer keeps its own file and is unaffected.
    pub fn clear(&mut self) {
        self.calls.clear();
        self.order.clear();
        self.streams.clear();
        self.stream_call.clear();
        self.endpoint_call.clear();
        self.stream_index.clear();
        self.ssrc_index.clear();
        self.events.clear();
        self.diagnostics.clear();
        self.heatmap = crate::store::heatmap::Heatmap::new(self.heatmap.bucket_secs());
        self.ipstats.clear();
        self.sipstats.clear();
        self.imported_streams.clear();
        self.imported_by_call.clear();
        self.pkts_total = 0;
        self.pkts_last_window = 0;
        self.window_start_us = None;
        self.start_us = None;
        self.last_us = None;
        self.pps = 0.0;
        self.completed = 0;
        self.failed = 0;
        self.focus_hint = None;
        self.search_matches.clear();
    }

    /// Update the search hint (from the TUI). Recomputes the pinned match list
    /// only when the normalized query actually changed.
    pub fn set_search_hint(&mut self, q: Option<&str>) {
        let norm = q
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        if norm.as_deref() == self.search_hint.as_deref() {
            return;
        }
        self.search_hint = norm;
        self.refresh_search_matches();
    }

    /// Recompute the search-pinned call-ids from the current query (same rule
    /// syntax as the TUI filter bar, see [`crate::filter`]). Called on hint
    /// change and on periodic maintenance (new calls / late-filled From/To
    /// users must be picked up).
    pub fn refresh_search_matches(&mut self) {
        self.search_matches.clear();
        let Some(q) = self.search_hint.as_deref() else {
            return;
        };
        let rules = crate::filter::parse(q);
        let mut matched: Vec<(Option<u64>, String)> = self
            .calls
            .values()
            .filter(|c| crate::filter::matches(*c, &rules))
            .map(|c| (c.invite_ts, c.call_id.clone()))
            .collect();
        matched.sort_by_key(|(ts, _)| std::cmp::Reverse(ts.unwrap_or(0)));
        self.search_matches = matched
            .into_iter()
            .take(SEARCH_PIN_MAX)
            .map(|(_, id)| id)
            .collect();
    }

    /// True when the call-id is focus- or search-protected.
    fn pinned_set(&self) -> HashSet<&str> {
        let mut set: HashSet<&str> = self.search_matches.iter().map(String::as_str).collect();
        if let Some(h) = &self.focus_hint {
            set.insert(h.primary.as_str());
            if let Some(l) = h.linked.as_deref() {
                set.insert(l);
            }
        }
        set
    }

    /// Record that `key` belongs to `call_id` (called on stream creation).
    pub fn note_stream(&mut self, call_id: &str, key: StreamKey) {
        self.stream_index
            .entry(call_id.to_string())
            .or_default()
            .push(key);
        self.ssrc_index.entry(key.ssrc).or_default().push(key);
    }

    /// Remove a stream key from the per-call index (and reverse maps).
    fn forget_stream(&mut self, key: &StreamKey) {
        if let Some(cid) = self.stream_call.remove(key)
            && let Some(v) = self.stream_index.get_mut(&cid)
        {
            v.retain(|k| k != key);
            if v.is_empty() {
                self.stream_index.remove(&cid);
            }
        }
        if let Some(v) = self.ssrc_index.get_mut(&key.ssrc) {
            v.retain(|k| k != key);
            if v.is_empty() {
                self.ssrc_index.remove(&key.ssrc);
            }
        }
    }

    /// Streams belonging to a call (empty slice if none).
    pub fn call_stream_keys(&self, call_id: &str) -> &[StreamKey] {
        self.stream_index
            .get(call_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Drain the list of call-ids removed since last call.
    pub fn drain_removed(&mut self) -> Vec<String> {
        self.removed.drain(..).collect()
    }

    /// Prune heatmap buckets older than the retention window.
    pub fn prune_heatmap(&mut self) {
        if let Some(last) = self.last_us {
            let cutoff = last.saturating_sub(self.heatmap_retain_us);
            self.heatmap.prune_older_than(cutoff);
        }
    }

    /// Evict oldest *terminated* calls when above `max_calls`. Falls back to
    /// evicting the oldest active call only if all are still active.
    /// Focus- and search-pinned calls are never evicted here.
    pub fn evict_if_needed(&mut self) {
        while self.calls.len() > self.max_calls {
            let pinned = self.pinned_set();
            // Find oldest terminated call by invite_ts.
            let target = self
                .order
                .iter()
                .filter_map(|id| self.calls.get(id).map(|c| (id.as_str(), c)))
                .filter(|(id, _)| !pinned.contains(id))
                .filter(|(_, c)| {
                    matches!(
                        c.state,
                        CallState::Completed | CallState::Failed | CallState::Canceled
                    )
                })
                .min_by_key(|(_, c)| c.invite_ts.unwrap_or(u64::MAX))
                .map(|(id, _)| id.to_string());

            let cid = target.or_else(|| {
                // All evictable calls are active; evict oldest by invite_ts.
                self.order
                    .iter()
                    .filter_map(|id| self.calls.get(id).map(|c| (id.as_str(), c)))
                    .filter(|(id, _)| !pinned.contains(id))
                    .min_by_key(|(_, c)| c.invite_ts.unwrap_or(u64::MAX))
                    .map(|(id, _)| id.to_string())
            });

            // Nothing evictable (all remaining calls are pinned): keep them.
            let Some(cid) = cid else { break };
            self.remove_call(&cid);
        }

        // Stream eviction.
        if self.streams.len() > self.max_streams {
            let mut keyed: Vec<(StreamKey, u64)> = self
                .streams
                .iter()
                .map(|(k, s)| (*k, s.first_ts_us.unwrap_or(u64::MAX)))
                .collect();
            keyed.sort_by_key(|(_, t)| *t);
            let to_remove: Vec<StreamKey> = keyed
                .into_iter()
                .take(self.streams.len().saturating_sub(self.max_streams))
                .map(|(k, _)| k)
                .collect();
            for k in to_remove {
                self.streams.remove(&k);
                self.forget_stream(&k);
            }
        }
    }

    /// Drop idle and terminated calls older than `ttl_secs` of capture time.
    /// `ttl_secs == 0` disables time-based eviction (file/replay). Focus- and
    /// search-pinned calls are retained.
    pub fn evict_stale(&mut self, ttl_secs: u64, now_us: u64) {
        if ttl_secs == 0 || now_us == 0 {
            return;
        }
        let cutoff = now_us.saturating_sub(ttl_secs.saturating_mul(1_000_000));
        let pinned = self.pinned_set();
        let stale: Vec<String> = self
            .calls
            .iter()
            .filter(|(id, _)| !pinned.contains(id.as_str()))
            .filter(|(_, c)| {
                let terminal = matches!(
                    c.state,
                    CallState::Completed | CallState::Failed | CallState::Canceled
                );
                let t = if terminal {
                    c.end_ts.or(c.bye_ts).unwrap_or(c.last_ts_us)
                } else {
                    c.last_ts_us
                };
                t != 0 && t < cutoff
            })
            .map(|(id, _)| id.clone())
            .collect();
        self.remove_calls(&stale);
    }

    /// Remove a call and its streams from in-memory indexes.
    pub(crate) fn remove_call(&mut self, call_id: &str) {
        self.remove_calls(&[call_id.to_string()]);
    }

    fn remove_calls(&mut self, ids: &[String]) {
        if ids.is_empty() {
            return;
        }
        let drop: HashSet<String> = ids.iter().cloned().collect();
        for id in ids {
            self.calls.remove(id);
            self.removed.push_back(id.clone());
            let stream_keys: Vec<StreamKey> = self.stream_index.remove(id).unwrap_or_default();
            for k in stream_keys {
                self.streams.remove(&k);
                self.stream_call.remove(&k);
                if let Some(v) = self.ssrc_index.get_mut(&k.ssrc) {
                    v.retain(|k2| k2 != &k);
                    if v.is_empty() {
                        self.ssrc_index.remove(&k.ssrc);
                    }
                }
            }
        }
        self.order.retain(|id| !drop.contains(id));
        self.endpoint_call.retain(|_, v| !drop.contains(v));
    }

    pub fn touch_time(&mut self, ts_us: u64) {
        if self.start_us.is_none() {
            self.start_us = Some(ts_us);
        }
        self.last_us = Some(ts_us);
        // pps over a 1s sliding window.
        match self.window_start_us {
            None => self.window_start_us = Some(ts_us),
            Some(w) => {
                if ts_us.saturating_sub(w) >= 1_000_000 {
                    let elapsed_s = (ts_us.saturating_sub(w)) as f64 / 1_000_000.0;
                    self.pps = self.pkts_last_window as f64 / elapsed_s.max(1e-6);
                    self.pkts_last_window = 0;
                    self.window_start_us = Some(ts_us);
                }
            }
        }
        self.pkts_last_window += 1;
    }

    /// Record the session/replay start if not already set (used by replay so
    /// the first evlog event, not just the first SIP message, anchors the
    /// already-recorded-duration delta).
    pub fn ensure_start(&mut self, ts_us: u64) {
        if self.start_us.is_none() {
            self.start_us = Some(ts_us);
        }
    }

    pub fn get_or_create_call(&mut self, call_id: &str) -> &mut Call {
        if !self.calls.contains_key(call_id) {
            self.calls
                .insert(call_id.to_string(), Call::new(call_id.to_string()));
            self.order.push(call_id.to_string());
        }
        self.calls.get_mut(call_id).unwrap()
    }

    pub fn push_event(&mut self, line: String) {
        self.events.push_back(line);
        while self.events.len() > 1000 {
            self.events.pop_front();
        }
    }

    /// Register a stream summary reconstructed from an evlog record (replay
    /// path). Consecutive snaps of the same (call, ssrc, flow) replace the
    /// previous row so the Streams page doesn't accumulate one row per 5s flush.
    pub fn add_imported_stream(&mut self, s: StreamSummary) {
        let key = import_key(&s);
        if let Some(slot) = self.imported_streams.get_mut(&key) {
            *slot = s;
            return;
        }
        if self.imported_streams.len() >= self.max_streams {
            return;
        }
        if !key.call_id.is_empty() {
            self.imported_by_call
                .entry(key.call_id.clone())
                .or_default()
                .push(key.clone());
        }
        self.imported_streams.insert(key, s);
    }

    /// Import a StreamSnap from an evlog (replay). Upserts the stream summary
    /// and attributes the packet/loss *delta* since the previous snap of the
    /// same stream onto per-IP stats.
    pub fn import_stream_snap(&mut self, ts_us: u64, s: StreamSummary) {
        if ts_us > self.last_us.unwrap_or(0) {
            self.last_us = Some(ts_us);
        }
        let key = import_key(&s);
        let (prev_pkts, prev_lost, prev_bytes) = self
            .imported_streams
            .get(&key)
            .map(|p| (p.packets, p.lost, p.bytes))
            .unwrap_or((0, 0, 0));
        let pkts_delta = s.packets.saturating_sub(prev_pkts);
        let lost_delta = s.lost.saturating_sub(prev_lost);
        let bytes_delta = s.bytes.saturating_sub(prev_bytes);
        let flow = s.flow;
        self.add_imported_stream(s);
        let Some(flow) = flow else {
            return;
        };
        if pkts_delta > 0 || bytes_delta > 0 {
            self.ipstats
                .observe_packets(flow.src.ip(), ts_us, pkts_delta, bytes_delta, Dir::Tx);
            self.ipstats
                .observe_packets(flow.dst.ip(), ts_us, pkts_delta, bytes_delta, Dir::Rx);
        }
        if lost_delta > 0 {
            self.ipstats
                .observe_lost(flow.src.ip(), ts_us, lost_delta, Dir::Tx);
            self.ipstats
                .observe_lost(flow.dst.ip(), ts_us, lost_delta, Dir::Rx);
        }
    }

    fn imported_for_call(&self, call_id: &str) -> impl Iterator<Item = &StreamSummary> {
        self.imported_by_call
            .get(call_id)
            .into_iter()
            .flatten()
            .filter_map(|k| self.imported_streams.get(k))
    }

    /// Build a UI snapshot: recent calls capped to `limit`, streams capped to
    /// 1000 (display only; exports use `snapshot_full`).
    pub fn snapshot(&self, limit: usize) -> Snapshot {
        self.snapshot_with(limit, 1000)
    }

    /// Full-fidelity snapshot for exports / end-of-run output.
    pub fn snapshot_full(&self) -> Snapshot {
        self.snapshot_with(usize::MAX, usize::MAX)
    }

    pub fn snapshot_with(&self, limit: usize, stream_limit: usize) -> Snapshot {
        // Summarize each stream exactly once and reuse everywhere: the
        // aggregate averages (over ALL streams), the bounded `streams`
        // snapshot Vec, and the per-call aggregates below (which used to
        // re-run the full summary() per stream per call just to read .mos).
        let stream_summaries: Vec<_> = self.streams.values().map(|s| s.summary()).collect();
        // Per-call live-stream aggregates from that single pass: min MOS +
        // stream count, keyed by borrowed call-id (no String clones).
        let mut live_by_call: FxHashMap<&str, (Option<f64>, usize)> = FxHashMap::default();
        for st in &stream_summaries {
            if let Some(cid) = st.call_id.as_deref() {
                let e = live_by_call.entry(cid).or_insert((None, 0));
                e.1 += 1;
                if let Some(m) = st.mos {
                    e.0 = Some(e.0.map_or(m, |a: f64| a.min(m)));
                }
            }
        }
        // Imported (replay/jsonl) summaries grouped once per publish instead
        // of a linear scan per call (O(calls × imported) -> O(imported)).
        let mut imported_by_call: FxHashMap<&str, Vec<&StreamSummary>> = FxHashMap::default();
        for (k, s) in &self.imported_streams {
            imported_by_call.entry(k.call_id.as_str()).or_default().push(s);
        }
        let mut summaries: Vec<CallSummary> = self
            .order
            .iter()
            .rev()
            .take(limit)
            .filter_map(|id| self.calls.get(id))
            .map(|c| {
                self.summarize(
                    c,
                    live_by_call.get(c.call_id.as_str()),
                    imported_by_call
                        .get(c.call_id.as_str())
                        .map(|v| v.as_slice()),
                )
            })
            .collect();

        // Search-pinned calls stay visible even when they have fallen out of
        // the recent-calls window (skipped for full snapshots, which already
        // include every call).
        if limit != usize::MAX && !self.search_matches.is_empty() {
            let cap = limit.saturating_add(SEARCH_PIN_MAX);
            let in_window: HashSet<String> = summaries.iter().map(|s| s.call_id.clone()).collect();
            for id in &self.search_matches {
                if summaries.len() >= cap {
                    break;
                }
                if in_window.contains(id.as_str()) {
                    continue;
                }
                if let Some(c) = self.calls.get(id) {
                    summaries.push(self.summarize(
                        c,
                        live_by_call.get(c.call_id.as_str()),
                        imported_by_call.get(c.call_id.as_str()).map(|v| v.as_slice()),
                    ));
                }
            }
        }

        let (active_n, comp_n, fail_n) =
            summaries
                .iter()
                .fold((0usize, 0usize, 0usize), |(a, c, f), s| match s.state {
                    CallState::Dialing | CallState::Ringing | CallState::Active => (a + 1, c, f),
                    CallState::Completed => (a, c + 1, f),
                    CallState::Failed | CallState::Canceled => (a, c, f + 1),
                });

        // aggregate averages over terminated calls with data.
        let mut pdd = 0.0;
        let mut pdd_n = 0u64;
        let mut setup = 0.0;
        let mut setup_n = 0u64;
        for c in self.calls.values() {
            if let Some(p) = c.pdd_ms {
                pdd += p as f64;
                pdd_n += 1;
            }
            if let Some(s) = c.setup_ms {
                setup += s as f64;
                setup_n += 1;
            }
        }
        let mut jit = 0.0;
        let mut jit_n = 0u64;
        let mut loss = 0.0;
        let mut loss_n = 0u64;
        let mut mos = 0.0;
        let mut mos_n = 0u64;
        let mut rtt = 0.0;
        let mut rtt_n = 0u64;
        // Summarize each stream exactly once (above); fold the aggregates.
        for st in &stream_summaries {
            if let Some(j) = st.jitter_ms {
                jit += j;
                jit_n += 1;
            }
            loss += st.loss_pct;
            loss_n += 1;
            if let Some(m) = st.mos {
                mos += m;
                mos_n += 1;
            }
            if let Some(r) = st.rtt_avg_ms {
                rtt += r;
                rtt_n += 1;
            }
        }
        for s in self.imported_streams.values() {
            if let Some(j) = s.jitter_ms {
                jit += j;
                jit_n += 1;
            }
            loss += s.loss_pct;
            loss_n += 1;
            if let Some(m) = s.mos {
                mos += m;
                mos_n += 1;
            }
            if let Some(r) = s.rtt_avg_ms {
                rtt += r;
                rtt_n += 1;
            }
        }
        let avg = |sum: f64, n: u64| if n == 0 { 0.0 } else { sum / n as f64 };
        let calls_total = self.completed + self.failed + active_n as u64;
        let answered = self.completed;
        let asr = if calls_total == 0 {
            0.0
        } else {
            answered as f64 / calls_total as f64 * 100.0
        };

        summaries.sort_by_key(|s| std::cmp::Reverse(s.invite_ts.unwrap_or(0)));

        Snapshot {
            source: self.source.clone(),
            elapsed_us: match (self.start_us, self.last_us) {
                (Some(a), Some(b)) => Some(b.saturating_sub(a)),
                _ => None,
            },
            start_us: self.start_us,
            tz_offset_secs: self.tz_offset_secs,
            pps: self.pps,
            pkts_total: self.pkts_total,
            pkts_dropped: self.pkts_dropped,
            calls_total: calls_total.max(self.calls.len() as u64),
            active: active_n,
            completed: comp_n,
            failed: fail_n,
            avg_pdd_ms: avg(pdd, pdd_n),
            avg_setup_ms: avg(setup, setup_n),
            avg_jitter_ms: avg(jit, jit_n),
            avg_loss_pct: avg(loss, loss_n),
            avg_rtt_ms: avg(rtt, rtt_n),
            avg_mos: avg(mos, mos_n),
            asr,
            calls: summaries,
            streams: {
                let mut s: Vec<_> = stream_summaries
                    .into_iter()
                    .take(stream_limit)
                    .collect();
                let remaining = stream_limit.saturating_sub(s.len());
                s.extend(self.imported_streams.values().take(remaining).cloned());
                s
            },
            events: self.events.clone(),
            diagnostics: self.diagnostics.iter().cloned().collect(),
            ip_stats: self.ipstats.snapshot(),
            sip_stats: self.sipstats.snapshot(),
            buckets: self.heatmap.flat(),
            focus: self.focus_hint.as_ref().and_then(|h| self.focus_detail(h)),
            paused: false,
        }
    }

    /// Build the focus payload for the Call Detail page.
    fn focus_detail(&self, hint: &FocusHint) -> Option<Focus> {
        let call = self.calls.get(&hint.primary)?;
        let primary_msgs = trim_msgs(&call.messages);
        // Linked b-leg (different Call-ID): merge chronologically and force
        // legs 0/1 so the swimlane can draw a 3-column A|mid|B view. Linked
        // overrides same-Call-ID dual-dialog classification.
        let (msgs, legs, leg_count) = if let Some(linked_id) = hint.linked.as_deref() {
            let linked_msgs = self
                .calls
                .get(linked_id)
                .map(|c| trim_msgs(&c.messages))
                .unwrap_or_default();
            merge_leg_msgs(primary_msgs, linked_msgs)
        } else {
            let (legs, leg_count) = dialog_legs(&primary_msgs);
            (primary_msgs, legs, leg_count)
        };
        // Party identities from the SIP messages: the initial INVITE identifies
        // the caller, the first response identifies the callee.
        let invite = msgs.iter().find(|m| {
            m.is_request && matches!(m.method, Some(Method::Invite)) && m.to_tag.is_none()
        });
        let response = msgs.iter().find(|m| !m.is_request);
        let caller_ua = invite.and_then(|m| sip_header(&m.raw, "User-Agent"));
        let callee_ua = response
            .and_then(|m| sip_header(&m.raw, "Server"))
            .or_else(|| response.and_then(|m| sip_header(&m.raw, "User-Agent")));
        let caller_addr = invite.map(|m| m.flow.src);
        let callee_addr = response.map(|m| m.flow.src);
        // Caller IP survives message trimming via the call's invite_key.
        let caller_ip = invite
            .map(|m| m.flow.src.ip())
            .or_else(|| call.invite_key.as_deref().and_then(|k| k.parse().ok()));
        let mut streams: Vec<_> = self
            .call_stream_keys(&hint.primary)
            .iter()
            .filter_map(|k| self.streams.get(k))
            .map(|s| s.summary())
            .collect();
        streams.extend(self.imported_for_call(&hint.primary).cloned());
        let diagnostics = self
            .diagnostics
            .iter()
            .filter(|d| d.call_id == hint.primary)
            .cloned()
            .collect();
        let b2bua = (leg_count >= 2).then(|| B2buaInfo {
            addr: common_flow_ip(&msgs, &legs),
            legs: leg_count,
        });
        Some(Focus {
            call_id: hint.primary.clone(),
            state: Some(call.state),
            from_user: call.from_user.clone(),
            to_user: call.to_user.clone(),
            caller_ua,
            callee_ua,
            caller_addr,
            caller_ip,
            callee_addr,
            messages: msgs,
            legs,
            b2bua,
            streams,
            diagnostics,
            negotiated_endpoints: call.negotiated.endpoints.clone(),
            pdd_ms: call.pdd_ms,
            setup_ms: call.setup_ms,
            ring_ms: call.ring_ms,
            early_media: call.early_media,
            invite_ts: call.invite_ts,
            trying_ts: call.trying_ts,
            ringing_ts: call.ringing_ts,
            answer_ts: call.answer_ts,
            bye_ts: call.bye_ts,
            end_ts: call.end_ts,
            hangup_by: call.hangup_by,
            hangup_code: call.hangup.code,
            hangup_reason: call.hangup.reason.clone(),
        })
    }

    /// Build a `CallSummary`. `live` carries (min MOS, stream count) for the
    /// call's live RTP streams and `imported` the replayed summaries, both
    /// precomputed once per snapshot from the single per-stream `summary()`
    /// pass (see `snapshot_with`) — re-deriving them here would re-run the
    /// full summary per stream per call on every publish.
    fn summarize(
        &self,
        c: &Call,
        live: Option<&(Option<f64>, usize)>,
        imported: Option<&[&StreamSummary]>,
    ) -> CallSummary {
        let (mut best_mos, mut stream_count) = live.copied().unwrap_or((None, 0));
        let mut pkts_rtp = c.pkts_rtp;
        if let Some(v) = imported {
            stream_count += v.len();
            pkts_rtp += v.iter().map(|s| s.packets).sum::<u64>();
            for s in v {
                if let Some(m) = s.mos {
                    best_mos = Some(best_mos.map_or(m, |a: f64| a.min(m)));
                }
            }
        }
        CallSummary {
            call_id: c.call_id.clone(),
            from_user: c.from_user.clone(),
            to_user: c.to_user.clone(),
            caller_ip: c.invite_key.as_deref().and_then(|k| k.parse().ok()),
            caller_src: c.invite_src.clone(),
            state: c.state,
            outcome: c.outcome,
            invite_ts: c.invite_ts,
            duration_ms: c.duration_ms(),
            pdd_ms: c.pdd_ms,
            setup_ms: c.setup_ms,
            ring_ms: c.ring_ms,
            ring_code: c.ring_code,
            early_media: c.early_media,
            hangup_by: c.hangup_by,
            hangup_code: c.hangup.code,
            pkts_sip: c.pkts_sip,
            pkts_rtp,
            best_mos,
            warn_count: c.warn_count,
            critical_count: c.critical_count,
            stream_count,
            via_turn: c.via_turn,
            ips: c.ips.clone(),
        }
    }

    /// Call summaries for a specific call (for call-detail view).
    #[allow(dead_code)]
    pub fn call_messages(&self, call_id: &str) -> Option<&[crate::model::sip::SipMsg]> {
        self.calls.get(call_id).map(|c| c.messages.as_slice())
    }
}

/// Cap stored messages for the focus payload (keeps the TUI responsive).
fn trim_msgs(msgs: &[SipMsg]) -> Vec<SipMsg> {
    if msgs.len() > 1000 {
        msgs[msgs.len() - 1000..].to_vec()
    } else {
        msgs.to_vec()
    }
}

/// Merge primary + linked call messages by timestamp; primary → leg 0, linked → leg 1.
fn merge_leg_msgs(primary: Vec<SipMsg>, linked: Vec<SipMsg>) -> (Vec<SipMsg>, Vec<u8>, u8) {
    let mut merged: Vec<(SipMsg, u8)> = primary
        .into_iter()
        .map(|m| (m, 0u8))
        .chain(linked.into_iter().map(|m| (m, 1u8)))
        .collect();
    merged.sort_by_key(|(m, _)| m.ts_us);
    let legs: Vec<u8> = merged.iter().map(|(_, l)| *l).collect();
    let msgs: Vec<SipMsg> = merged.into_iter().map(|(m, _)| m).collect();
    let leg_count = if msgs.is_empty() { 0 } else { 2 };
    (msgs, legs, leg_count)
}

/// Extract the value of a single-line SIP header from raw message bytes.
fn sip_header(raw: &[u8], name: &str) -> Option<String> {
    let text = std::str::from_utf8(raw).ok()?;
    text.lines().find_map(|line| {
        let (n, v) = line.split_once(':')?;
        n.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().to_string())
    })
}

/// Per-message dialog (leg) index, keyed by From tag (fallback: branch).
/// Returns (per-message legs, number of distinct legs). Messages without any
/// tag key collapse into leg 0.
fn dialog_legs(msgs: &[SipMsg]) -> (Vec<u8>, u8) {
    let mut leg_of: FxHashMap<String, u8> = FxHashMap::default();
    let legs: Vec<u8> = msgs
        .iter()
        .map(|m| {
            let key = m
                .from_tag
                .clone()
                .or_else(|| m.branch.clone())
                .unwrap_or_default();
            if key.is_empty() {
                0
            } else {
                let n = leg_of.len().min(u8::MAX as usize) as u8;
                *leg_of.entry(key).or_insert(n)
            }
        })
        .collect();
    let count = leg_of.len().max(1).min(u8::MAX as usize) as u8;
    (legs, count)
}

/// The one IP shared by the flows of both the first two legs — i.e. the
/// B2BUA/SBC in a same-Call-ID dual-dialog split. None when ambiguous.
fn common_flow_ip(msgs: &[SipMsg], legs: &[u8]) -> Option<std::net::IpAddr> {
    let mut by_leg: FxHashMap<u8, Vec<std::net::IpAddr>> =
        FxHashMap::default();
    for (m, l) in msgs.iter().zip(legs) {
        by_leg
            .entry(*l)
            .or_default()
            .extend([m.flow.src.ip(), m.flow.dst.ip()]);
    }
    let l0 = by_leg.get(&0)?;
    let l1 = by_leg.get(&1)?;
    let shared: Vec<std::net::IpAddr> = l0.iter().copied().filter(|ip| l1.contains(ip)).collect();
    (shared.len() == 1).then(|| shared[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::media::StreamSummary;
    use crate::model::packet::{Flow5Tuple, Proto};
    use crate::model::sip::Method;

    fn mk_sip(from_tag: Option<&str>, from: &str, to: &str) -> SipMsg {
        SipMsg {
            ts_us: 0,
            flow: Flow5Tuple {
                proto: Proto::Udp,
                src: from.parse().unwrap(),
                dst: to.parse().unwrap(),
            },
            is_request: true,
            method: Some(Method::Invite),
            status: None,
            call_id: "c1".into(),
            cseq: Some(1),
            cseq_method: Some("INVITE".into()),
            branch: Some("b".into()),
            from_tag: from_tag.map(str::to_owned),
            to_tag: None,
            from_uri: None,
            to_uri: None,
            raw: bytes::Bytes::new(),
            contact_addr: None,
            route_count: 0,
            record_route_count: 0,
            has_sdp: false,
        }
    }

    #[test]
    fn dialog_legs_groups_by_from_tag() {
        let msgs = vec![
            mk_sip(Some("t1"), "1.1.1.1:5060", "2.2.2.2:5060"),
            mk_sip(Some("t2"), "2.2.2.2:5060", "3.3.3.3:5060"),
            mk_sip(Some("t1"), "2.2.2.2:5060", "1.1.1.1:5060"),
        ];
        let (legs, n) = dialog_legs(&msgs);
        assert_eq!(legs, vec![0, 1, 0]);
        assert_eq!(n, 2);
        // A re-INVITE (same From tag) stays in the same dialog → not a B2BUA.
        let msgs2 = vec![
            mk_sip(Some("t1"), "1.1.1.1:5060", "2.2.2.2:5060"),
            mk_sip(Some("t1"), "1.1.1.1:5060", "2.2.2.2:5060"),
        ];
        let (_, n2) = dialog_legs(&msgs2);
        assert_eq!(n2, 1);
    }

    #[test]
    fn common_flow_ip_finds_same_call_id_b2bua() {
        let msgs = vec![
            mk_sip(Some("t1"), "1.1.1.1:5060", "2.2.2.2:5060"),
            mk_sip(Some("t2"), "2.2.2.2:5060", "3.3.3.3:5060"),
        ];
        let (legs, _) = dialog_legs(&msgs);
        assert_eq!(
            common_flow_ip(&msgs, &legs),
            Some("2.2.2.2".parse().unwrap()),
            "shared flow IP (the B2BUA) must be found"
        );
        // No shared IP → None (ambiguous).
        let msgs2 = vec![
            mk_sip(Some("t1"), "1.1.1.1:5060", "2.2.2.2:5060"),
            mk_sip(Some("t2"), "3.3.3.3:5060", "4.4.4.4:5060"),
        ];
        let (legs2, _) = dialog_legs(&msgs2);
        assert_eq!(common_flow_ip(&msgs2, &legs2), None);
    }

    #[test]
    fn focus_detail_exposes_legs_and_b2bua() {
        let mut reg = Registry::with_source("t".into());
        let call = reg.get_or_create_call("c1");
        call.from_user = Some("alice".into());
        call.to_user = Some("bob".into());
        call.invite_ts = Some(1_000_000);
        let msgs = vec![
            mk_sip(Some("t1"), "1.1.1.1:5060", "2.2.2.2:5060"),
            mk_sip(Some("t2"), "2.2.2.2:5060", "3.3.3.3:5060"),
        ];
        call.messages = msgs;
        reg.focus_hint = Some(FocusHint::primary("c1"));
        let focus = reg.snapshot_full().focus.expect("focus detail present");
        assert_eq!(focus.legs, vec![0, 1]);
        let b2bua = focus.b2bua.expect("same Call-ID split must be detected");
        assert_eq!(b2bua.legs, 2);
        assert_eq!(b2bua.addr, Some("2.2.2.2".parse().unwrap()));
    }

    #[test]
    fn focus_detail_no_b2bua_for_single_dialog() {
        let mut reg = Registry::with_source("t".into());
        let call = reg.get_or_create_call("c1");
        call.from_user = Some("alice".into());
        call.to_user = Some("bob".into());
        call.invite_ts = Some(1_000_000);
        call.messages = vec![
            mk_sip(Some("t1"), "1.1.1.1:5060", "2.2.2.2:5060"),
            mk_sip(Some("t1"), "2.2.2.2:5060", "1.1.1.1:5060"),
        ];
        reg.focus_hint = Some(FocusHint::primary("c1"));
        let focus = reg.snapshot_full().focus.expect("focus detail present");
        assert_eq!(focus.legs, vec![0, 0]);
        assert!(focus.b2bua.is_none(), "single dialog must not be a B2BUA");
    }

    #[test]
    fn focus_detail_merges_linked_b_leg_by_timestamp() {
        let mut reg = Registry::with_source("t".into());
        {
            let a = reg.get_or_create_call("a-leg");
            let mut m0 = mk_sip(Some("t1"), "1.1.1.1:5060", "2.2.2.2:5060");
            m0.ts_us = 1_000_000;
            let mut m2 = mk_sip(Some("t1"), "2.2.2.2:5060", "1.1.1.1:5060");
            m2.ts_us = 1_100_000;
            m2.is_request = false;
            m2.method = None;
            m2.status = Some(100);
            a.messages = vec![m0, m2];
        }
        {
            let b = reg.get_or_create_call("b-leg");
            let mut m1 = mk_sip(Some("t2"), "2.2.2.2:5060", "3.3.3.3:5060");
            m1.ts_us = 1_050_000;
            b.messages = vec![m1];
        }
        reg.focus_hint = Some(FocusHint::with_linked("a-leg", "b-leg"));
        let focus = reg.snapshot_full().focus.expect("focus detail present");
        assert_eq!(focus.call_id, "a-leg");
        assert_eq!(focus.messages.len(), 3);
        assert_eq!(focus.legs, vec![0, 1, 0]);
        assert_eq!(focus.messages[0].ts_us, 1_000_000);
        assert_eq!(focus.messages[1].ts_us, 1_050_000);
        assert_eq!(focus.messages[2].ts_us, 1_100_000);
        assert_eq!(focus.b2bua.as_ref().map(|b| b.legs), Some(2));
    }

    #[test]
    fn search_pin_protects_from_ttl_and_window() {
        let mut reg = Registry::with_source("t".into());
        {
            let a = reg.get_or_create_call("alice-call");
            a.invite_ts = Some(1_000);
            a.last_ts_us = 1_000;
            a.end_ts = Some(2_000);
            a.state = CallState::Completed;
            a.from_user = Some("alice".into());
        }
        {
            let b = reg.get_or_create_call("bob-call");
            b.invite_ts = Some(3_000);
            b.last_ts_us = 3_000;
            b.end_ts = Some(4_000);
            b.state = CallState::Completed;
            b.from_user = Some("bob".into());
        }
        reg.set_search_hint(Some("alice"));

        // TTL eviction past the cutoff: the pinned call survives.
        reg.evict_stale(60, 120_000_000);
        assert!(reg.calls.contains_key("alice-call"), "pin must protect");
        assert!(!reg.calls.contains_key("bob-call"), "unpinned evicts");

        // Window of 1 would only hold the newest call; pinned stays visible.
        let snap = reg.snapshot(1);
        assert!(snap.calls.iter().any(|c| c.call_id == "alice-call"));

        // Clearing the hint lifts the protection.
        reg.set_search_hint(None);
        reg.evict_stale(60, 120_000_000);
        assert!(!reg.calls.contains_key("alice-call"));
    }

    #[test]
    fn capacity_eviction_skips_pinned_calls() {
        let mut reg = Registry::with_source("t".into());
        reg.set_caps(2, 10, 10);
        {
            let a = reg.get_or_create_call("focused");
            a.invite_ts = Some(1_000);
            a.last_ts_us = 1_000;
            a.end_ts = Some(1_500);
            a.state = CallState::Completed;
        }
        {
            let b = reg.get_or_create_call("pinned-by-search");
            b.invite_ts = Some(2_000);
            b.last_ts_us = 2_000;
            b.end_ts = Some(2_500);
            b.state = CallState::Completed;
        }
        reg.focus_hint = Some(FocusHint::primary("focused"));
        reg.set_search_hint(Some("pinned-by-search"));
        reg.evict_if_needed();
        assert_eq!(reg.calls.len(), 2, "all calls pinned: nothing evictable");
        assert!(reg.calls.contains_key("focused"));
        assert!(reg.calls.contains_key("pinned-by-search"));
    }

    #[test]
    fn imported_streams_surface_in_snapshot_focus_and_summary() {
        let mut reg = Registry::with_source("replay".into());
        reg.get_or_create_call("c1");
        let mut st = StreamSummary {
            ssrc: 0x1000,
            packets: 500,
            lost: 4,
            loss_pct: 0.8,
            bytes: 4000,
            mos: Some(4.3),
            ..StreamSummary::default()
        };
        st.call_id = Some("c1".into());
        reg.add_imported_stream(st);

        // Snapshot streams include the imported stream.
        let snap = reg.snapshot_full();
        assert_eq!(snap.streams.len(), 1);
        assert_eq!(snap.streams[0].ssrc, 0x1000);

        // Focus detail (Call Detail media table) includes it with flow/pkts.
        reg.focus_hint = Some(FocusHint::primary("c1"));
        let snap = reg.snapshot_full();
        let focus = snap.focus.expect("focus detail present");
        assert_eq!(focus.streams.len(), 1, "media table must show the stream");
        assert_eq!(focus.streams[0].packets, 500);
        assert_eq!(focus.streams[0].bytes, 4000);

        // Call summary aggregates RTP packets + MOS from imported streams.
        let call = &snap.calls[0];
        assert_eq!(call.pkts_rtp, 500);
        assert_eq!(call.best_mos, Some(4.3));
        assert_eq!(call.stream_count, 1);
    }

    #[test]
    fn import_stream_snap_feeds_ip_stats_and_upserts() {
        let mut reg = Registry::with_source("replay".into());
        let flow = Flow5Tuple {
            proto: Proto::Udp,
            src: "10.10.0.8:4000".parse().unwrap(),
            dst: "10.20.0.8:4000".parse().unwrap(),
        };
        let mut snap = StreamSummary {
            ssrc: 0xabc,
            packets: 100,
            lost: 2,
            bytes: 16000,
            loss_pct: 2.0,
            ..StreamSummary::default()
        };
        snap.call_id = Some("c1".into());
        snap.flow = Some(flow);

        // First 5s snap: 100 pkts / 2 lost.
        reg.import_stream_snap(1_000_000, snap.clone());
        // Second snap of the same stream: cumulative 250 pkts / 5 lost.
        snap.packets = 250;
        snap.lost = 5;
        snap.bytes = 40000;
        reg.import_stream_snap(6_000_000, snap);

        let ip_stats = reg.snapshot_full().ip_stats;
        assert_eq!(ip_stats.len(), 2, "both endpoints must appear");
        let src = ip_stats
            .iter()
            .find(|s| s.ip.to_string() == "10.10.0.8")
            .unwrap();
        let dst = ip_stats
            .iter()
            .find(|s| s.ip.to_string() == "10.20.0.8")
            .unwrap();
        assert_eq!(src.pkts_tx, 250);
        assert_eq!(src.lost_tx, 5);
        assert_eq!(dst.pkts_rx, 250);
        assert_eq!(dst.lost_rx, 5);
        let src_loss = src.loss_pct(0, Dir::Tx).unwrap();
        assert!((src_loss - 2.0).abs() < 1e-9, "all-time TX loss {src_loss}");

        // Consecutive snaps of the same stream replace, not accumulate, the row.
        assert_eq!(reg.snapshot_full().streams.len(), 1);
        assert_eq!(reg.snapshot_full().streams[0].packets, 250);
    }

    #[test]
    fn import_many_stream_snaps_stays_fast() {
        let mut reg = Registry::with_source("replay".into());
        let flow = Flow5Tuple {
            proto: Proto::Udp,
            src: "10.10.0.8:4000".parse().unwrap(),
            dst: "10.20.0.8:4000".parse().unwrap(),
        };
        let t0 = std::time::Instant::now();
        for i in 0..20_000u64 {
            let mut s = StreamSummary {
                ssrc: (i % 200) as u32,
                packets: 100 + i,
                lost: i / 40,
                bytes: (100 + i) * 160,
                loss_pct: 1.0,
                ..StreamSummary::default()
            };
            s.call_id = Some("c1".into());
            s.flow = Some(flow);
            reg.import_stream_snap(1_000_000 + i * 5_000_000, s);
        }
        let snap = reg.snapshot_full();
        assert!(
            t0.elapsed().as_millis() < 1_000,
            "20k stream snaps must stay O(n), took {:?}",
            t0.elapsed()
        );
        assert_eq!(snap.streams.len(), 200, "upsert keeps one row per ssrc");
        assert_eq!(snap.ip_stats.len(), 2);
        assert!(snap.calls.is_empty()); // snaps don't create calls
    }
}

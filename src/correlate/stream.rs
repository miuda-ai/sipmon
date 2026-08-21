use std::collections::VecDeque;

use crate::analyze::media_stats::{MediaStats, MediaStatsAccumulator};
use crate::analyze::mos;
use crate::model::media::{RatePoint, StreamSummary};
use crate::model::packet::Flow5Tuple;

/// Periodic sample window (capture microseconds) and retention cap.
const SAMPLE_WINDOW_US: u64 = 5_000_000;
const MAX_SAMPLES: usize = 120; // 5s x 120 = 10 minutes

/// One observed RTP stream (directed flow + ssrc).
#[allow(dead_code)]
pub struct RtpStream {
    pub flow: Flow5Tuple,
    pub ssrc: u32,
    pub call_id: String,
    pub payload_type: Option<u8>,
    pub clock_rate: Option<u32>,
    pub codec: Option<String>,
    pub direction: Option<String>,
    pub first_ts_us: Option<u64>,
    pub last_ts_us: Option<u64>,
    pub last_pt: Option<u8>,
    pub acc: MediaStatsAccumulator,
    pub rtt_samples: Vec<f64>,
    pub oneway_samples: Vec<f64>,
    /// Whether the reverse-direction stream for this call has been observed.
    pub reverse_seen: bool,
    /// TURN relay leg (client/peer) if this stream traverses a relay.
    pub leg: Option<crate::correlate::turn::Leg>,
    pub via_turn: bool,
    /// Cumulative RTP bytes observed.
    pub bytes: u64,
    /// Periodic 5s throughput/quality samples (oldest first, capped).
    pub history: VecDeque<RatePoint>,
    last_sample_bytes: u64,
    last_sample_packets: u64,
}

impl RtpStream {
    pub fn new(flow: Flow5Tuple, ssrc: u32, call_id: String) -> Self {
        Self {
            flow,
            ssrc,
            call_id,
            payload_type: None,
            clock_rate: None,
            codec: None,
            direction: None,
            first_ts_us: None,
            last_ts_us: None,
            last_pt: None,
            acc: MediaStatsAccumulator::new(),
            rtt_samples: Vec::new(),
            oneway_samples: Vec::new(),
            reverse_seen: false,
            leg: None,
            via_turn: false,
            bytes: 0,
            history: VecDeque::new(),
            last_sample_bytes: 0,
            last_sample_packets: 0,
        }
    }

    #[inline]
    pub fn observe(&mut self, ts_us: u64, header: crate::decode::rtp::RtpHeader, len: usize) {
        if self.first_ts_us.is_none() {
            self.first_ts_us = Some(ts_us);
        }
        self.last_ts_us = Some(ts_us);
        self.bytes += len as u64;
        let stats_header = crate::analyze::media_stats::RtpStatsHeader {
            payload_type: header.payload_type,
            sequence_number: header.sequence_number,
            rtp_timestamp: header.timestamp,
            ssrc: header.ssrc,
        };
        self.payload_type.get_or_insert(header.payload_type);
        if self.clock_rate.is_none() {
            let rate = crate::decode::rtp::rtp_clock_rate_for_payload_type(header.payload_type);
            self.apply_clock_rate(rate);
        }
        self.acc.observe(ts_us, Some(stats_header));
        self.last_pt = Some(header.payload_type);
    }

    /// Apply SDP (or fallback) clock rate, rescaling an in-flight jitter estimator.
    pub fn apply_clock_rate(&mut self, rate: u32) {
        if rate == 0 {
            return;
        }
        self.clock_rate = Some(rate);
        self.acc.set_clock_rate(rate);
    }

    /// Append a 5s throughput/quality sample (at most one per window).
    pub fn sample(&mut self, ts_us: u64) {
        if self
            .history
            .back()
            .is_some_and(|h| ts_us.saturating_sub(h.ts_us) < SAMPLE_WINDOW_US)
        {
            return;
        }
        let st = self.acc.snapshot();
        let oneway =
            mean(&self.oneway_samples).or_else(|| mean(&self.rtt_samples).map(|r| r / 2.0));
        self.history.push_back(RatePoint {
            ts_us,
            bytes: self.bytes.saturating_sub(self.last_sample_bytes),
            packets: st.packet_count.saturating_sub(self.last_sample_packets),
            loss_pct: st.loss_percent,
            jitter_ms: st.jitter_ms,
            mos: mos::estimate_mos(
                self.codec.as_deref(),
                self.payload_type,
                st.loss_percent,
                oneway,
                st.jitter_ms,
            ),
        });
        if self.history.len() > MAX_SAMPLES {
            self.history.pop_front();
        }
        self.last_sample_bytes = self.bytes;
        self.last_sample_packets = st.packet_count;
    }

    pub fn snapshot_stats(&self) -> MediaStats {
        self.acc.snapshot()
    }

    /// Build the export/UI summary, including RTT/MOS aggregation.
    pub fn summary(&self) -> StreamSummary {
        let st = self.snapshot_stats();
        let rtt_avg = mean(&self.rtt_samples);
        let rtt_min = self.rtt_samples.iter().copied().fold(None, min_opt);
        let rtt_max = self.rtt_samples.iter().copied().fold(None, max_opt);
        let oneway = mean(&self.oneway_samples).or_else(|| {
            // Fall back to RTT/2 if only round-trip is available (labeled as estimate upstream).
            rtt_avg.map(|r| r / 2.0)
        });
        let mos = mos::estimate_mos(
            self.codec.as_deref(),
            self.payload_type,
            st.loss_percent,
            oneway,
            st.jitter_ms,
        );
        StreamSummary {
            call_id: Some(self.call_id.clone()),
            ssrc: self.ssrc,
            flow: Some(self.flow),
            codec: self.codec.clone(),
            payload_type: self.payload_type,
            packets: st.packet_count,
            lost: st.lost_packets,
            expected: st.expected_packets,
            loss_pct: st.loss_percent,
            jitter_ms: st.jitter_ms,
            first_ts_us: self.first_ts_us,
            last_ts_us: self.last_ts_us,
            rtt_min_ms: rtt_min,
            rtt_avg_ms: rtt_avg,
            rtt_max_ms: rtt_max,
            oneway_ms: oneway,
            mos,
            direction: self.direction.clone(),
            leg: self.leg.map(|l| l.label().to_string()),
            via_turn: self.via_turn,
            bytes: self.bytes,
            history: self.history.iter().cloned().collect(),
        }
    }

    /// StreamSnap for the evlog: same numbers as `summary()` without cloning
    /// the 10-minute sparkline history (unused by the event).
    pub fn to_snap_evt(&self, ts_us: u64) -> crate::store::evlog::StreamSnapEvt {
        let st = self.snapshot_stats();
        let rtt_avg = mean(&self.rtt_samples);
        let rtt_min = self.rtt_samples.iter().copied().fold(None, min_opt);
        let rtt_max = self.rtt_samples.iter().copied().fold(None, max_opt);
        let oneway = mean(&self.oneway_samples).or_else(|| rtt_avg.map(|r| r / 2.0));
        let mos = mos::estimate_mos(
            self.codec.as_deref(),
            self.payload_type,
            st.loss_percent,
            oneway,
            st.jitter_ms,
        );
        crate::store::evlog::StreamSnapEvt {
            ts_us,
            call_id: self.call_id.clone(),
            ssrc: self.ssrc,
            flow: self.flow,
            codec: self.codec.clone(),
            payload_type: self.payload_type,
            packets: st.packet_count,
            lost: st.lost_packets,
            expected: st.expected_packets,
            loss_pct: st.loss_percent,
            jitter_ms: st.jitter_ms,
            mos,
            direction: self.direction.clone(),
            bytes: self.bytes,
            first_ts_us: self.first_ts_us,
            last_ts_us: self.last_ts_us,
            rtt_min_ms: rtt_min,
            rtt_avg_ms: rtt_avg,
            rtt_max_ms: rtt_max,
            oneway_ms: oneway,
            leg: self.leg.map(|l| l.label().to_string()),
            via_turn: self.via_turn,
        }
    }
}

fn mean(v: &[f64]) -> Option<f64> {
    if v.is_empty() {
        None
    } else {
        Some(v.iter().sum::<f64>() / v.len() as f64)
    }
}
fn min_opt(a: Option<f64>, b: f64) -> Option<f64> {
    Some(a.map_or(b, |x| x.min(b)))
}
fn max_opt(a: Option<f64>, b: f64) -> Option<f64> {
    Some(a.map_or(b, |x| x.max(b)))
}

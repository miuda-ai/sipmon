//! Vendored RTP media statistics accumulator (RFC 3550 jitter/loss with a
//! 64-packet reorder window). Adapted from rustpbx-sipflow's `rtp_stats.rs`,
//! kept self-contained (no external struct dependency).
//!
//! Interarrival jitter follows RFC 3550 A.8 (`J += (|D| − J) / 16`). Packet
//! pairs whose `|D|` exceeds [`JITTER_DISCONT_MS`] are treated as a timestamp
//! restart (hold, DTX gap, codec switch) and do not update `J`.

pub const RTP_REORDER_WINDOW: u16 = 64;

/// Forward sequence jump larger than this between two consecutive arrivals is
/// treated as a sender restart / SSRC+port reuse, not packet loss: a single
/// inter-arrival gap cannot legitimately skip thousands of packets (50 pps
/// audio would need ~80s of sending into a black hole to reach it). The
/// reorder window is flushed and tracking resumes from the new sequence.
pub const RTP_RESTART_WINDOW: u16 = 4096;

/// `|D|` larger than this (milliseconds) is a discontinuity, not jitter.
pub const JITTER_DISCONT_MS: f64 = 1000.0;

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct RtpStatsHeader {
    pub payload_type: u8,
    pub sequence_number: u16,
    pub rtp_timestamp: u32,
    pub ssrc: u32,
}

#[derive(Debug, Default)]
pub struct MediaStatsAccumulator {
    pub packet_count: u64,
    pub lost_packets: u64,
    /// Detected sequence restarts (SSRC/port reuse, sender restart) — not
    /// counted as loss.
    pub restarts: u64,
    pub payload_type: Option<u8>,
    pub clock_rate: Option<u32>,
    pub first_sequence: Option<u16>,
    pub last_sequence: Option<u16>,
    /// Pending (missing) sequence numbers inside the 64-packet reorder
    /// window, as a bitmap relative to `last_sequence`: bit `age-1` set =
    /// `last-age` has not arrived yet.
    pub pending_mask: u64,
    pub prev_arrival_micros: Option<u64>,
    pub prev_rtp_timestamp: Option<u32>,
    pub jitter_rtp_units: f64,
    pub jitter_samples: u64,
}

#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct MediaStats {
    pub packet_count: u64,
    pub lost_packets: u64,
    pub expected_packets: u64,
    pub loss_percent: f64,
    pub restarts: u64,
    pub jitter_ms: Option<f64>,
    pub payload_type: Option<u8>,
    pub clock_rate: Option<u32>,
}

impl MediaStatsAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Prefer SDP `a=rtpmap` clock when known; rescale an in-flight estimator
    /// so `jitter_ms` stays continuous across a late SDP apply.
    pub fn set_clock_rate(&mut self, rate: u32) {
        if rate == 0 {
            return;
        }
        if let Some(old) = self.clock_rate
            && old != 0
            && old != rate
        {
            self.jitter_rtp_units *= rate as f64 / old as f64;
        }
        self.clock_rate = Some(rate);
    }

    pub fn observe(&mut self, arrival_micros: u64, header: Option<RtpStatsHeader>) {
        self.packet_count += 1;
        let Some(header) = header else { return };

        self.payload_type.get_or_insert(header.payload_type);
        let clock_rate = *self.clock_rate.get_or_insert_with(|| {
            crate::decode::rtp::rtp_clock_rate_for_payload_type(header.payload_type)
        });

        self.observe_sequence(header.sequence_number);
        self.observe_jitter(arrival_micros, header.rtp_timestamp, clock_rate);
    }

    fn observe_sequence(&mut self, seq: u16) {
        if self.first_sequence.is_none() {
            self.first_sequence = Some(seq);
            self.last_sequence = Some(seq);
            return;
        }
        let last = match self.last_sequence {
            Some(l) => l,
            None => {
                self.last_sequence = Some(seq);
                return;
            }
        };
        let diff = seq.wrapping_sub(last);
        if diff == 0 {
            return;
        }
        if diff < 0x8000 {
            if diff > RTP_RESTART_WINDOW {
                // Sender restart / SSRC+port reuse: booking thousands of
                // packets lost off a single arrival would permanently inflate
                // the cumulative loss rate. Reset tracking instead.
                self.pending_mask = 0;
                self.restarts += 1;
                self.last_sequence = Some(seq);
                return;
            }
            // Forward: `last` advances by `diff`. Each pending bit's age grows
            // by `diff`; bits shifted past the 64-packet reorder window expire
            // and count as loss. (A bitmap replaces the per-gap set inserts
            // and the per-packet retain scan of the set-based version.)
            let d = diff as u32;
            if d >= 64 {
                self.lost_packets += self.pending_mask.count_ones() as u64;
                self.pending_mask = 0;
            } else {
                let expired = (self.pending_mask >> (64 - d)).count_ones();
                self.lost_packets += expired as u64;
                self.pending_mask <<= d;
            }
            // Defer the gap (last+1..seq-1) into the window. Skips beyond the
            // window count as immediate loss.
            let missing = (diff - 1) as u64;
            let buffered = missing.min(RTP_REORDER_WINDOW as u64);
            self.lost_packets += missing - buffered;
            if buffered >= 64 {
                self.pending_mask = u64::MAX;
            } else {
                self.pending_mask |= (1u64 << buffered) - 1;
            }
            self.last_sequence = Some(seq);
        } else {
            // Reorder: seq arrived before `last`. If it sits inside the
            // window, clear its pending bit (recovered, not lost).
            let age = last.wrapping_sub(seq);
            if age > 0 && age <= RTP_REORDER_WINDOW {
                self.pending_mask &= !(1u64 << (age - 1));
            }
        }
    }

    fn observe_jitter(&mut self, arrival_us: u64, rtp_ts: u32, clock_rate: u32) {
        if let (Some(prev_arr), Some(prev_rtp)) =
            (self.prev_arrival_micros, self.prev_rtp_timestamp)
        {
            let arr_delta = arrival_us as i128 - prev_arr as i128;
            let arr_delta_units = arr_delta as f64 * clock_rate as f64 / 1_000_000.0;
            let rtp_delta_units = rtp_ts_delta(rtp_ts, prev_rtp) as f64;
            let delta = (arr_delta_units - rtp_delta_units).abs();
            if delta.is_finite() && clock_rate > 0 {
                let delta_ms = delta * 1000.0 / clock_rate as f64;
                // Hold / timestamp reset / capture stall: keep the RFC estimator
                // but do not let a multi-second |D| leak into displayed jitter.
                if delta_ms <= JITTER_DISCONT_MS {
                    self.jitter_rtp_units += (delta - self.jitter_rtp_units) / 16.0;
                    self.jitter_samples += 1;
                }
            }
        }
        self.prev_arrival_micros = Some(arrival_us);
        self.prev_rtp_timestamp = Some(rtp_ts);
    }

    pub fn snapshot(&self) -> MediaStats {
        let lost = self.lost_packets + self.pending_mask.count_ones() as u64;
        let expected = self.packet_count + lost;
        let loss_pct = if expected > 0 {
            lost as f64 / expected as f64 * 100.0
        } else {
            0.0
        };
        let jitter_ms = match (self.clock_rate, self.jitter_samples > 0) {
            (Some(cr), true) if cr > 0 => Some(self.jitter_rtp_units * 1000.0 / cr as f64),
            _ => None,
        };
        MediaStats {
            packet_count: self.packet_count,
            lost_packets: lost,
            expected_packets: expected,
            loss_percent: loss_pct,
            restarts: self.restarts,
            jitter_ms,
            payload_type: self.payload_type,
            clock_rate: self.clock_rate,
        }
    }
}

pub fn rtp_ts_delta(cur: u32, prev: u32) -> i64 {
    let forward = cur.wrapping_sub(prev);
    if forward <= i32::MAX as u32 {
        forward as i64
    } else {
        -(prev.wrapping_sub(cur) as i64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(seq: u16, ts: u32) -> RtpStatsHeader {
        RtpStatsHeader {
            payload_type: 0,
            sequence_number: seq,
            rtp_timestamp: ts,
            ssrc: 1,
        }
    }

    #[test]
    fn gap_overflow_counts_immediate_loss() {
        let mut s = MediaStatsAccumulator::new();
        s.observe(0, Some(hdr(10, 0)));
        // diff 70: 69 skipped, 64 buffered + 5 immediate loss.
        s.observe(1_000, Some(hdr(80, 0)));
        let st = s.snapshot();
        assert_eq!(st.packet_count, 2);
        assert_eq!(st.lost_packets, 69);
        assert_eq!(st.expected_packets, 71);
    }

    #[test]
    fn pending_expires_after_window() {
        let mut s = MediaStatsAccumulator::new();
        s.observe(0, Some(hdr(10, 0)));
        s.observe(1_000, Some(hdr(12, 0))); // gap at 11 (pending)
        s.observe(2_000, Some(hdr(100, 0))); // big jump: 11 now beyond window
        let st = s.snapshot();
        // 87 gap (12..100) = 64 buffered + 23 immediate; 11 expired (+1).
        assert_eq!(st.lost_packets, 88);
        assert_eq!(st.expected_packets, 91);
    }

    #[test]
    fn duplicate_packet_is_noop() {
        let mut s = MediaStatsAccumulator::new();
        s.observe(0, Some(hdr(10, 0)));
        s.observe(1_000, Some(hdr(10, 0))); // diff 0
        let st = s.snapshot();
        assert_eq!(st.packet_count, 2);
        assert_eq!(st.lost_packets, 0);
    }

    #[test]
    fn reordered_packet_clears_pending_loss() {
        let mut s = MediaStatsAccumulator::new();
        s.observe(10_000, Some(hdr(10, 1_600)));
        s.observe(30_000, Some(hdr(12, 1_920)));
        s.observe(40_000, Some(hdr(11, 1_760)));
        let st = s.snapshot();
        assert_eq!(st.packet_count, 3);
        assert_eq!(st.lost_packets, 0);
    }

    #[test]
    fn unfilled_gap_counts_as_loss() {
        let mut s = MediaStatsAccumulator::new();
        s.observe(10_000, Some(hdr(10, 1_600)));
        s.observe(30_000, Some(hdr(12, 1_920)));
        let st = s.snapshot();
        assert_eq!(st.lost_packets, 1);
        assert_eq!(st.expected_packets, 3);
    }

    #[test]
    fn large_forward_jump_is_restart_not_loss() {
        // SSRC/port reuse or sender restart: the new session starts at an
        // unrelated random sequence number.
        let mut s = MediaStatsAccumulator::new();
        s.observe(1_000_000, Some(hdr(100, 1_600)));
        s.observe(1_020_000, Some(hdr(30_000, 480_000)));
        s.observe(1_040_000, Some(hdr(30_001, 480_160)));
        s.observe(1_060_000, Some(hdr(30_002, 480_320)));
        let st = s.snapshot();
        assert_eq!(st.lost_packets, 0, "restart must not book ~29k lost");
        assert_eq!(st.restarts, 1);
        assert_eq!(st.expected_packets, 4);
    }

    #[test]
    fn restart_across_seq_wraparound() {
        let mut s = MediaStatsAccumulator::new();
        s.observe(1_000_000, Some(hdr(65_500, 1_600)));
        s.observe(1_020_000, Some(hdr(5_000, 480_000)));
        s.observe(1_040_000, Some(hdr(5_001, 480_160)));
        let st = s.snapshot();
        assert_eq!(st.lost_packets, 0, "wrapped restart must not book loss");
        assert_eq!(st.restarts, 1);
    }

    #[test]
    fn moderate_gap_still_counts_as_loss() {
        // A 100-packet gap is below the restart threshold: still real loss.
        let mut s = MediaStatsAccumulator::new();
        s.observe(1_000_000, Some(hdr(100, 1_600)));
        s.observe(1_020_000, Some(hdr(200, 3_200)));
        let st = s.snapshot();
        assert_eq!(st.lost_packets, 99);
        assert_eq!(st.restarts, 0);
    }

    fn pcmu(seq: u16, ts: u32) -> RtpStatsHeader {
        hdr(seq, ts)
    }

    #[test]
    fn steady_pcmu_has_near_zero_jitter() {
        let mut s = MediaStatsAccumulator::new();
        for i in 0..40u16 {
            let arr = 1_000_000 + u64::from(i) * 20_000;
            s.observe(arr, Some(pcmu(i, u32::from(i) * 160)));
        }
        let j = s.snapshot().jitter_ms.unwrap();
        assert!(j < 1.0, "expected ~0 jitter, got {j}");
    }

    #[test]
    fn multi_second_hold_does_not_inflate_jitter() {
        let mut s = MediaStatsAccumulator::new();
        s.observe(1_000_000, Some(pcmu(1, 160)));
        s.observe(1_020_000, Some(pcmu(2, 320)));
        // 5s hold; RTP timestamp barely advances (frozen / CN).
        s.observe(6_040_000, Some(pcmu(3, 480)));
        s.observe(6_060_000, Some(pcmu(4, 640)));
        let j = s.snapshot().jitter_ms.unwrap();
        assert!(
            j < 20.0,
            "5s hold must be treated as a timestamp jump, got {j}ms"
        );
    }

    #[test]
    fn rtp_timestamp_reset_does_not_inflate_jitter() {
        let mut s = MediaStatsAccumulator::new();
        s.observe(1_000_000, Some(pcmu(1, 800_000)));
        s.observe(1_020_000, Some(pcmu(2, 800_160)));
        s.observe(1_040_000, Some(pcmu(3, 160)));
        s.observe(1_060_000, Some(pcmu(4, 320)));
        let j = s.snapshot().jitter_ms.unwrap();
        assert!(
            j < 20.0,
            "timestamp reset must be treated as a jump, got {j}ms"
        );
    }

    #[test]
    fn set_clock_rate_rescales_units_not_milliseconds() {
        let mut s = MediaStatsAccumulator::new();
        // 1ms extra delay on one interval at 8 kHz → D = 8 units.
        s.observe(1_000_000, Some(pcmu(1, 160)));
        s.observe(1_021_000, Some(pcmu(2, 320)));
        let before = s.snapshot().jitter_ms.unwrap();
        s.set_clock_rate(48_000);
        let after = s.snapshot().jitter_ms.unwrap();
        assert!(
            (before - after).abs() < 1e-9,
            "rescale must keep jitter_ms, {before} vs {after}"
        );
        assert_eq!(s.clock_rate, Some(48_000));
    }
}

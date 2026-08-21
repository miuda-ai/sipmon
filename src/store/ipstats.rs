//! Per-IP network statistics: time-windowed packet loss / volume, split by
//! direction (TX = this IP sent, RX = this IP received).
//!
//! For every observed endpoint IP we keep two rolling ring buffers — per-second
//! buckets (600s of 1s buckets) and per-minute buckets (60m of 1m buckets) — plus
//! all-time directional totals. Loss rates for the 1s/5s/10s/20s/1m/10m/1h/all
//! windows are derived by summing the relevant buckets, so the UI can show
//! short-term and long-term quality side by side. The 1s series also feeds the
//! per-IP heatmap.

use std::collections::VecDeque; use rustc_hash::FxHashMap;
use std::net::IpAddr;

/// Loss-rate windows supported by the UI: (window_secs, label). 0 = all-time.
pub const WINDOWS: [(u64, &str); 8] = [
    (1, "1s"),
    (5, "5s"),
    (10, "10s"),
    (20, "20s"),
    (60, "1m"),
    (600, "10m"),
    (3600, "1h"),
    (0, "all"),
];

const SEC1_RETAIN: u64 = 600; // 600 one-second buckets (10 minutes)
const SEC60_RETAIN: u64 = 60; // 60 one-minute buckets (1 hour)

/// Direction of a packet relative to the tracked IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// The IP is the source: it sent the packet (egress).
    Tx,
    /// The IP is the destination: it received the packet (ingress).
    Rx,
}

/// One fixed-width time bucket, split by direction.
#[derive(Debug, Clone, Copy, Default)]
pub struct Bucket {
    pub pkts_tx: u64,
    pub pkts_rx: u64,
    pub lost_tx: u64,
    pub lost_rx: u64,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
}

impl Bucket {
    fn packets(&self) -> u64 {
        self.pkts_tx + self.pkts_rx
    }
    fn lost(&self) -> u64 {
        self.lost_tx + self.lost_rx
    }
}

#[derive(Debug, Clone)]
pub struct IpStats {
    pub ip: IpAddr,
    /// Concurrent calls involving this IP (decremented at call teardown).
    pub active_calls: u32,
    /// All-time directional totals (TX = sent by this IP, RX = received).
    pub pkts_tx: u64,
    pub pkts_rx: u64,
    pub lost_tx: u64,
    pub lost_rx: u64,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub first_seen_us: Option<u64>,
    pub last_seen_us: Option<u64>,
    /// 1s buckets, oldest first (bounded to SEC1_RETAIN).
    sec1: VecDeque<(u64, Bucket)>,
    /// 1m buckets, oldest first (bounded to SEC60_RETAIN).
    sec60: VecDeque<(u64, Bucket)>,
}

impl IpStats {
    fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            active_calls: 0,
            pkts_tx: 0,
            pkts_rx: 0,
            lost_tx: 0,
            lost_rx: 0,
            bytes_tx: 0,
            bytes_rx: 0,
            first_seen_us: None,
            last_seen_us: None,
            sec1: VecDeque::new(),
            sec60: VecDeque::new(),
        }
    }

    /// Ensure a bucket exists for `ts_us` in the given ring, pushing empty
    /// buckets to fill gaps and pruning entries older than `retain`. The common
    /// in-order case is O(1); only reordered timestamps fall back to a scan.
    fn bucket_mut(
        ring: &mut VecDeque<(u64, Bucket)>,
        ts_us: u64,
        width_us: u64,
        retain: u64,
    ) -> &mut Bucket {
        let key = ts_us / width_us;
        if ring.is_empty() {
            ring.push_back((key, Bucket::default()));
            let tail = ring.back_mut().unwrap();
            return &mut tail.1;
        }
        // Align the tail forward to `key`, filling gaps and pruning the front.
        while ring.back().map(|(k, _)| *k).unwrap_or(0) < key && (ring.len() as u64) < retain {
            let next = ring.back().unwrap().0 + 1;
            ring.push_back((next, Bucket::default()));
        }
        if ring.back().unwrap().0 < key {
            // Ring is full and `key` is still ahead: shift forward bucket by bucket.
            while ring.back().unwrap().0 < key {
                ring.pop_front();
                let next = ring.back().unwrap().0 + 1;
                ring.push_back((next, Bucket::default()));
            }
        }
        if ring.back().unwrap().0 == key {
            let tail = ring.back_mut().unwrap();
            return &mut tail.1;
        }
        // Reordered timestamp behind the tail: find the bucket, else fold into
        // the oldest (retention dropped the real one — negligible inaccuracy).
        match ring.iter().position(|(k, _)| *k == key) {
            Some(i) => &mut ring[i].1,
            None => {
                let front = ring.front_mut().unwrap();
                &mut front.1
            }
        }
    }

    fn add_packet(&mut self, ts_us: u64, len: usize, dir: Dir) {
        self.add_packets(ts_us, 1, len as u64, dir);
    }

    /// Bulk packet/byte update used when reconstructing IP stats from a
    /// 5-second StreamSnap (replay: RTP packets themselves are not in the log).
    fn add_packets(&mut self, ts_us: u64, count: u64, bytes: u64, dir: Dir) {
        if count == 0 && bytes == 0 {
            return;
        }
        if self.first_seen_us.is_none() {
            self.first_seen_us = Some(ts_us);
        }
        self.last_seen_us = Some(ts_us);
        match dir {
            Dir::Tx => {
                self.pkts_tx += count;
                self.bytes_tx += bytes;
            }
            Dir::Rx => {
                self.pkts_rx += count;
                self.bytes_rx += bytes;
            }
        }
        let b = Self::bucket_mut(&mut self.sec1, ts_us, 1_000_000, SEC1_RETAIN);
        match dir {
            Dir::Tx => {
                b.pkts_tx += count;
                b.bytes_tx += bytes;
            }
            Dir::Rx => {
                b.pkts_rx += count;
                b.bytes_rx += bytes;
            }
        }
        let b = Self::bucket_mut(&mut self.sec60, ts_us, 60_000_000, SEC60_RETAIN);
        match dir {
            Dir::Tx => {
                b.pkts_tx += count;
                b.bytes_tx += bytes;
            }
            Dir::Rx => {
                b.pkts_rx += count;
                b.bytes_rx += bytes;
            }
        }
    }

    fn add_lost(&mut self, ts_us: u64, lost: u64, dir: Dir) {
        if lost == 0 {
            return;
        }
        if self.last_seen_us.is_none() {
            self.last_seen_us = Some(ts_us);
        }
        match dir {
            Dir::Tx => self.lost_tx += lost,
            Dir::Rx => self.lost_rx += lost,
        }
        let b = Self::bucket_mut(&mut self.sec1, ts_us, 1_000_000, SEC1_RETAIN);
        match dir {
            Dir::Tx => b.lost_tx += lost,
            Dir::Rx => b.lost_rx += lost,
        }
        let b = Self::bucket_mut(&mut self.sec60, ts_us, 60_000_000, SEC60_RETAIN);
        match dir {
            Dir::Tx => b.lost_tx += lost,
            Dir::Rx => b.lost_rx += lost,
        }
    }

    fn active_add(&mut self, delta: i32) {
        self.active_calls = self.active_calls.saturating_add_signed(delta);
    }

    /// All-time packet count in one direction.
    pub fn pkts_total(&self, dir: Dir) -> u64 {
        match dir {
            Dir::Tx => self.pkts_tx,
            Dir::Rx => self.pkts_rx,
        }
    }

    /// All-time lost-packet count in one direction.
    pub fn lost_total(&self, dir: Dir) -> u64 {
        match dir {
            Dir::Tx => self.lost_tx,
            Dir::Rx => self.lost_rx,
        }
    }

    /// All-time bytes in one direction.
    #[allow(dead_code)]
    pub fn bytes_total(&self, dir: Dir) -> u64 {
        match dir {
            Dir::Tx => self.bytes_tx,
            Dir::Rx => self.bytes_rx,
        }
    }

    /// All-time bytes in both directions.
    #[allow(dead_code)]
    pub fn bytes_total_all(&self) -> u64 {
        self.bytes_tx + self.bytes_rx
    }

    /// Aggregate (packets, lost) over the last `window_secs` (0 = all-time)
    /// for one direction.
    fn window(&self, window_secs: u64, dir: Dir) -> (u64, u64) {
        if window_secs == 0 {
            return (self.pkts_total(dir), self.lost_total(dir));
        }
        if window_secs <= SEC1_RETAIN {
            return Self::sum_ring(&self.sec1, window_secs, dir);
        }
        Self::sum_ring(&self.sec60, window_secs.div_ceil(60), dir)
    }

    fn sum_ring(ring: &VecDeque<(u64, Bucket)>, n: u64, dir: Dir) -> (u64, u64) {
        let (mut pkts, mut lost) = (0u64, 0u64);
        for (_, b) in ring.iter().rev().take(n as usize) {
            match dir {
                Dir::Tx => {
                    pkts += b.pkts_tx;
                    lost += b.lost_tx;
                }
                Dir::Rx => {
                    pkts += b.pkts_rx;
                    lost += b.lost_rx;
                }
            }
        }
        (pkts, lost)
    }

    /// Loss percentage (0..100) for a window and direction, or None when no
    /// packets were observed in that direction.
    pub fn loss_pct(&self, window_secs: u64, dir: Dir) -> Option<f64> {
        let (pkts, lost) = self.window(window_secs, dir);
        if pkts == 0 {
            None
        } else {
            Some(lost as f64 / pkts as f64 * 100.0)
        }
    }

    /// Merged TX+RX loss percentage (sort keys, compact summaries).
    pub fn loss_pct_total(&self, window_secs: u64) -> Option<f64> {
        let (p1, l1) = self.window(window_secs, Dir::Tx);
        let (p2, l2) = self.window(window_secs, Dir::Rx);
        let pkts = p1 + p2;
        if pkts == 0 {
            None
        } else {
            Some((l1 + l2) as f64 / pkts as f64 * 100.0)
        }
    }

    /// Packets in a window for one direction.
    #[allow(dead_code)]
    pub fn pkts_in(&self, window_secs: u64, dir: Dir) -> u64 {
        self.window(window_secs, dir).0
    }

    /// Bytes in a window for one direction.
    #[allow(dead_code)]
    pub fn bytes_in(&self, window_secs: u64, dir: Dir) -> u64 {
        if window_secs == 0 {
            return self.bytes_total(dir);
        }
        let (ring, n) = if window_secs <= SEC1_RETAIN {
            (&self.sec1, window_secs)
        } else {
            (&self.sec60, window_secs.div_ceil(60))
        };
        let mut bytes = 0u64;
        for (_, b) in ring.iter().rev().take(n as usize) {
            match dir {
                Dir::Tx => bytes += b.bytes_tx,
                Dir::Rx => bytes += b.bytes_rx,
            }
        }
        bytes
    }

    /// Column series for the bottom heatmap: up to `cols` buckets covering the
    /// last `window_secs`, each a (bucket_start_us, loss_pct). Uses the 1s ring
    /// (aggregated) for ≤10m windows and the 1m ring for longer ones. Loss is
    /// the merged TX+RX rate.
    pub fn heatmap_columns(&self, window_secs: u64, cols: u64) -> Vec<(u64, f64)> {
        let (ring, bucket_us, secs_per_key) = if window_secs <= SEC1_RETAIN * 10 {
            (&self.sec1, 1_000_000u64, 1u64)
        } else {
            (&self.sec60, 60_000_000u64, 60u64)
        };
        // Aggregate ring keys into ~cols groups.
        let group = (window_secs / secs_per_key / cols).max(1);
        let mut map: std::collections::BTreeMap<u64, (u64, u64)> =
            std::collections::BTreeMap::new();
        for (key, b) in ring {
            let g = key / group;
            let e = map.entry(g).or_default();
            e.0 += b.packets();
            e.1 += b.lost();
        }
        map.into_iter()
            .map(|(g, (p, l))| {
                let pct = if p == 0 {
                    0.0
                } else {
                    l as f64 / p as f64 * 100.0
                };
                (g * group * bucket_us, pct)
            })
            .collect()
    }
}

/// All the per-IP stats, keyed by IP.
#[derive(Debug, Clone, Default)]
pub struct IpStatsStore {
    map: FxHashMap<IpAddr, IpStats>,
}

impl IpStatsStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&mut self) {
        self.map.clear();
    }

    fn entry(&mut self, ip: IpAddr) -> &mut IpStats {
        self.map.entry(ip).or_insert_with(|| IpStats::new(ip))
    }

    pub fn observe_packet(&mut self, ip: IpAddr, ts_us: u64, len: usize, dir: Dir) {
        self.entry(ip).add_packet(ts_us, len, dir);
    }

    /// Attribute `count` packets totaling `bytes` to `ip` in one shot.
    pub fn observe_packets(&mut self, ip: IpAddr, ts_us: u64, count: u64, bytes: u64, dir: Dir) {
        self.entry(ip).add_packets(ts_us, count, bytes, dir);
    }

    pub fn observe_lost(&mut self, ip: IpAddr, ts_us: u64, lost: u64, dir: Dir) {
        self.entry(ip).add_lost(ts_us, lost, dir);
    }

    pub fn add_active(&mut self, ip: IpAddr, delta: i32) {
        self.entry(ip).active_add(delta);
    }

    /// Snapshot of all tracked IPs (sorted by IP for stable display).
    pub fn snapshot(&self) -> Vec<IpStats> {
        let mut v: Vec<IpStats> = self.map.values().cloned().collect();
        v.sort_by_key(|s| s.ip);
        v
    }

    /// Drop IPs with no active calls and no packets since `cutoff_us`.
    pub fn prune_idle(&mut self, cutoff_us: u64) {
        self.map
            .retain(|_, s| s.active_calls > 0 || s.last_seen_us.unwrap_or(0) >= cutoff_us);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_and_totals() {
        let mut st = IpStatsStore::new();
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        // 10 pkts/s for 30s at ts=1_000_000 + i*1s
        for i in 0..30 {
            let ts = 1_000_000 + i * 1_000_000;
            for _ in 0..10 {
                st.observe_packet(ip, ts, 160, Dir::Tx);
            }
            if i % 10 == 0 {
                st.observe_lost(ip, ts, 1, Dir::Tx); // 1 lost / 100 pkts = 1%
            }
        }
        let s = st.snapshot().pop().unwrap();
        assert_eq!(s.pkts_total(Dir::Tx), 300);
        assert_eq!(s.pkts_tx, 300);
        assert_eq!(s.pkts_rx, 0);
        assert_eq!(s.bytes_total(Dir::Tx), 300 * 160);
        assert_eq!(s.lost_total(Dir::Tx), 3);
        assert!((s.loss_pct(0, Dir::Tx).unwrap() - 1.0).abs() < 1e-9); // all-time
        assert!((s.loss_pct(10, Dir::Tx).unwrap() - 1.0).abs() < 1e-9); // 10s window includes one lost
        assert_eq!(s.loss_pct(1, Dir::Tx).unwrap(), 0.0); // last 1s: no loss
        assert_eq!(s.pkts_in(10, Dir::Tx), 100);
        assert_eq!(s.bytes_in(5, Dir::Tx), 5 * 10 * 160);
        // RX untouched → no loss rate.
        assert_eq!(s.loss_pct(0, Dir::Rx), None);
        assert!((s.loss_pct_total(0).unwrap() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn directions_stay_separate() {
        let mut st = IpStatsStore::new();
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        let ts = 1_000_000;
        for _ in 0..10 {
            st.observe_packet(ip, ts, 100, Dir::Tx);
        }
        for _ in 0..20 {
            st.observe_packet(ip, ts, 200, Dir::Rx);
        }
        st.observe_lost(ip, ts, 2, Dir::Tx);
        st.observe_lost(ip, ts, 4, Dir::Rx);
        let s = st.snapshot().pop().unwrap();
        assert_eq!(s.pkts_tx, 10);
        assert_eq!(s.pkts_rx, 20);
        assert_eq!(s.bytes_tx, 10 * 100);
        assert_eq!(s.bytes_rx, 20 * 200);
        assert!((s.loss_pct(0, Dir::Tx).unwrap() - 20.0).abs() < 1e-9);
        assert!((s.loss_pct(0, Dir::Rx).unwrap() - 20.0).abs() < 1e-9);
        // Merged view is the sum.
        assert!((s.loss_pct_total(0).unwrap() - 20.0).abs() < 1e-9);
        assert_eq!(s.bytes_total_all(), 10 * 100 + 20 * 200);
    }

    #[test]
    fn active_call_counting() {
        let mut st = IpStatsStore::new();
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        st.add_active(ip, 1);
        st.add_active(ip, 1);
        st.add_active(ip, -1);
        let s = st.snapshot().pop().unwrap();
        assert_eq!(s.active_calls, 1);
    }

    #[test]
    fn heatmap_columns_produce_loss_pct() {
        let mut st = IpStatsStore::new();
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        let ts = 1_000_000;
        for _ in 0..8 {
            st.observe_packet(ip, ts, 160, Dir::Tx);
        }
        st.observe_lost(ip, ts, 2, Dir::Tx);
        let s = st.snapshot().pop().unwrap();
        let cols = s.heatmap_columns(60, 60);
        assert_eq!(cols.len(), 1);
        assert!((cols[0].1 - 25.0).abs() < 1e-9);
    }

    #[test]
    fn observe_packets_matches_per_packet_totals() {
        let mut st = IpStatsStore::new();
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        st.observe_packets(ip, 1_000_000, 50, 50 * 160, Dir::Tx);
        st.observe_lost(ip, 1_000_000, 2, Dir::Tx);
        let s = st.snapshot().pop().unwrap();
        assert_eq!(s.pkts_tx, 50);
        assert_eq!(s.bytes_tx, 50 * 160);
        assert_eq!(s.lost_tx, 2);
        assert!((s.loss_pct(0, Dir::Tx).unwrap() - 4.0).abs() < 1e-9);
    }

    #[test]
    fn prune_idle_drops_stale_ips() {
        let mut st = IpStatsStore::new();
        let old: IpAddr = "10.1.2.3".parse().unwrap();
        let live: IpAddr = "10.1.2.4".parse().unwrap();
        let held: IpAddr = "10.1.2.5".parse().unwrap();
        st.observe_packet(old, 1_000_000, 100, Dir::Tx);
        st.observe_packet(live, 3_600_000_000, 100, Dir::Tx);
        st.add_active(held, 1);
        st.prune_idle(3_000_000_000);
        let ips: Vec<_> = st.snapshot().into_iter().map(|s| s.ip).collect();
        assert!(!ips.contains(&old));
        assert!(ips.contains(&live));
        assert!(ips.contains(&held));
    }
}

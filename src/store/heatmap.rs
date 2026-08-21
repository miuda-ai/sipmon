use rustc_hash::FxHashMap;

use crate::model::stats::MetricSet;

/// Two-dimensional time×key aggregation for reliability/quality heatmap.
pub struct Heatmap {
    bucket_secs: u64,
    /// bucket_index_us -> key -> metrics.
    cells: FxHashMap<u64, FxHashMap<String, MetricSet>>,
}

impl Heatmap {
    pub fn new(bucket_secs: u64) -> Self {
        Self {
            bucket_secs,
            cells: FxHashMap::default(),
        }
    }

    pub fn bucket_secs(&self) -> u64 {
        self.bucket_secs
    }

    fn bucket_of(&self, ts_us: u64) -> u64 {
        let secs = ts_us / 1_000_000;
        let b = secs / self.bucket_secs.max(1);
        b * self.bucket_secs * 1_000_000
    }

    /// Record a terminated call's contributions into its (bucket, key) cell.
    #[allow(clippy::too_many_arguments)]
    pub fn record_call(
        &mut self,
        ts_us: u64,
        key: String,
        answered: bool,
        failed: bool,
        pdd_ms: Option<f64>,
        jitter_ms: Option<f64>,
        loss_pct: Option<f64>,
        rtt_ms: Option<f64>,
        mos: Option<f64>,
    ) {
        let bucket = self.bucket_of(ts_us);
        let cell = self
            .cells
            .entry(bucket)
            .or_default()
            .entry(key)
            .or_default();
        cell.calls += 1;
        if answered {
            cell.answered += 1;
        }
        if failed {
            cell.failed += 1;
        }
        if let Some(p) = pdd_ms {
            cell.pdd_sum_ms += p;
            cell.pdd_n += 1;
        }
        if let Some(j) = jitter_ms {
            cell.jitter_sum_ms += j;
            cell.jitter_n += 1;
        }
        if let Some(l) = loss_pct {
            cell.loss_sum_pct += l;
            cell.loss_n += 1;
        }
        if let Some(r) = rtt_ms {
            cell.rtt_sum_ms += r;
            cell.rtt_n += 1;
        }
        if let Some(m) = mos {
            cell.mos_sum += m;
            cell.mos_n += 1;
        }
    }

    #[allow(dead_code)]
    pub fn cells(&self) -> &FxHashMap<u64, FxHashMap<String, MetricSet>> {
        &self.cells
    }

    pub fn flat(&self) -> Vec<(u64, String, MetricSet)> {
        let mut out = Vec::new();
        for (b, m) in &self.cells {
            for (k, v) in m {
                out.push((*b, k.clone(), v.clone()));
            }
        }
        out.sort_by_key(|(b, _, _)| *b);
        out
    }

    /// Drop buckets whose window ended before `cutoff_us` (bounds memory on
    /// long-running sessions / many distinct keys).
    pub fn prune_older_than(&mut self, cutoff_us: u64) {
        self.cells.retain(|bucket, _| *bucket >= cutoff_us);
    }

    /// Number of retained cells (observable for tests).
    #[cfg(test)]
    pub fn cell_count(&self) -> usize {
        self.cells.values().map(|m| m.len()).sum()
    }
}

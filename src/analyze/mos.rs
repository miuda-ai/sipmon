//! Simplified E-model (ITU-T G.107) MOS estimation.
//!
//! `R = 93.2 - Id(delay) - Ie-eff(codec, loss)`
//! `MOS = 1 + 0.035*R + 7e-6 * R*(R-60)*(100-R)` for R<100; R>=100 -> 4.5.

/// Case-insensitive ASCII substring test without allocating. Codec names are
/// short, and this runs per MOS estimate (per stream per snapshot/sample) —
/// the old `to_ascii_uppercase` allocated a String on every call.
fn contains_ci(haystack: &str, needle: &str) -> bool {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    n.len() <= h.len() && h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
}

/// Codec impairment parameters `(Ie, Bpl)` with packet-loss concealment
/// (ITU-T G.107 Annex B typical values).
fn codec_params(codec: Option<&str>, pt: Option<u8>) -> (f64, f64) {
    // `""` contains no codec pattern, so a missing codec falls through to the
    // payload-type arms — same behavior as the old Option-based match.
    let c = codec.unwrap_or("");
    if contains_ci(c, "PCMU") || contains_ci(c, "PCMA") || contains_ci(c, "G.711") {
        (0.0, 25.1)
    } else if contains_ci(c, "G.729") {
        (10.0, 19.0)
    } else if contains_ci(c, "G.723") {
        (15.0, 13.0)
    } else if contains_ci(c, "G.722") {
        (4.0, 15.7)
    } else if contains_ci(c, "OPUS") || contains_ci(c, "TELEPHONE") {
        (0.0, 25.0)
    } else {
        match pt {
            Some(0) | Some(8) => (0.0, 25.1),
            _ => (10.0, 10.0),
        }
    }
}

/// Delay impairment Id (simplified G.107 default, no echo term).
fn delay_impairment(oneway_ms: f64) -> f64 {
    let d = oneway_ms.max(0.0);
    0.024 * d + 0.11 * (d - 177.3).max(0.0)
}

/// Effective equipment impairment Ie-eff (G.107):
/// `Ie + (95 - Ie) * Ppl / (Ppl / BurstR + Bpl)`, BurstR = 1 for random loss.
fn equipment_impairment(codec: Option<&str>, pt: Option<u8>, loss_pct: f64) -> f64 {
    let (ie, bpl) = codec_params(codec, pt);
    let p = loss_pct.max(0.0);
    ie + (95.0 - ie) * p / (p / 1.0 + bpl)
}

/// Compute MOS.
///
/// `oneway_ms` is the one-way delay (use RTT/2 if only round-trip is known).
/// `jitter_ms` adds a de-jitter buffer contribution to the effective delay.
pub fn estimate_mos(
    codec: Option<&str>,
    pt: Option<u8>,
    loss_pct: f64,
    oneway_ms: Option<f64>,
    jitter_ms: Option<f64>,
) -> Option<f64> {
    let oneway = oneway_ms.unwrap_or(0.0);
    let jitter = jitter_ms.unwrap_or(0.0);
    // Approximate mouth-to-ear delay: network one-way + de-jitter buffer.
    let dejitter = (40.0_f64).max(jitter * 3.0);
    let d = oneway + dejitter;

    let id = delay_impairment(d);
    let ie = equipment_impairment(codec, pt, loss_pct);
    let r = (93.2 - id - ie).clamp(0.0, 100.0);
    let mos = if r >= 100.0 {
        4.5
    } else {
        1.0 + 0.035 * r + 7e-6 * r * (r - 60.0) * (100.0 - r)
    };
    Some(mos.clamp(1.0, 4.5))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn g711_lossless_low_delay_is_high_mos() {
        let m = estimate_mos(Some("PCMU"), Some(0), 0.0, Some(10.0), Some(2.0)).unwrap();
        assert!(m > 4.0, "expected high MOS, got {m}");
    }

    #[test]
    fn high_loss_lowers_mos() {
        let good = estimate_mos(Some("PCMU"), Some(0), 0.0, Some(20.0), None).unwrap();
        let bad = estimate_mos(Some("PCMU"), Some(0), 20.0, Some(20.0), None).unwrap();
        assert!(bad < good, "{bad} should be < {good}");
    }

    #[test]
    fn high_delay_lowers_mos() {
        let low = estimate_mos(Some("PCMU"), Some(0), 0.0, Some(50.0), None).unwrap();
        let high = estimate_mos(Some("PCMU"), Some(0), 0.0, Some(300.0), None).unwrap();
        assert!(high < low, "{high} should be < {low}");
    }
}

#[cfg(test)]
mod codec_match_tests {
    use super::contains_ci;

    #[test]
    fn finds_case_insensitive_substring() {
        assert!(contains_ci("audio PCMU/8000", "pcmu"));
        assert!(contains_ci("g.711alaw", "G.711"));
        assert!(contains_ci("telephone-event", "TELEPHONE"));
    }

    #[test]
    fn no_match_and_empty_cases() {
        assert!(!contains_ci("opus", "G.729"));
        assert!(!contains_ci("", "OPUS"));
        assert!(!contains_ci("op", "OPUS")); // needle longer than haystack
    }
}

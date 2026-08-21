/// Minimal RTP fixed-header parse.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct RtpHeader {
    pub version: u8,
    pub payload_type: u8,
    pub sequence_number: u16,
    pub timestamp: u32,
    pub ssrc: u32,
}

/// True if `payload` looks like an RTP/RTCP packet (version 2).
pub fn is_rtp_like(payload: &[u8]) -> bool {
    payload.len() >= 2 && (payload[0] >> 6) == 2
}

#[inline]
pub fn parse_rtp_header(payload: &[u8]) -> Option<RtpHeader> {
    if payload.len() < 12 || (payload[0] >> 6) != 2 {
        return None;
    }
    Some(RtpHeader {
        version: 2,
        payload_type: payload[1] & 0x7f,
        sequence_number: u16::from_be_bytes([payload[2], payload[3]]),
        timestamp: u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]),
        ssrc: u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]),
    })
}

/// RTP/RTCP classification per the design doc.
///
/// Note: RTCP packet types (200..207) live in the full second byte; masking
/// with 0x7f would map them to 72..79 and never match. RTP payload types
/// 64..95 are reserved for RTCP demux (RFC 5761), so the unmasked check is
/// unambiguous in practice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaKind {
    Rtp,
    Rtcp,
    Other,
}

pub fn classify(payload: &[u8]) -> MediaKind {
    if !is_rtp_like(payload) {
        return MediaKind::Other;
    }
    let pt_byte = payload.get(1).copied().unwrap_or(0);
    if (200..=207).contains(&pt_byte) {
        MediaKind::Rtcp
    } else {
        MediaKind::Rtp
    }
}

/// Clock rate lookup for common PTs (RFC 3551 + common dynamic defaults).
pub fn rtp_clock_rate_for_payload_type(payload_type: u8) -> u32 {
    match payload_type {
        0 | 8 | 9 | 18 => 8000,
        96..=127 => 48000,
        _ => 8000,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_rtp_vs_rtcp() {
        // RTP: v=2, PT=0 (PCMU)
        let rtp = [0x80u8, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(classify(&rtp), MediaKind::Rtp);
        // RTP with marker bit: 0x80 | marker → PT stays small
        let rtp_m = [0x80u8, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(classify(&rtp_m), MediaKind::Rtp);
        // RTCP SR: v=2, PT=200
        let sr = [0x80u8, 200, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0];
        assert_eq!(classify(&sr), MediaKind::Rtcp);
        // RTCP RR: PT=201
        let rr = [0x80u8, 201, 0, 1, 0, 0, 0, 1];
        assert_eq!(classify(&rr), MediaKind::Rtcp);
        // RTCP SDES: PT=202
        let sdes = [0x81u8, 202, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0];
        assert_eq!(classify(&sdes), MediaKind::Rtcp);
        // RTCP with P bit: 0xA0
        let sr_p = [0xA0u8, 200, 0, 1, 0, 0, 0, 1];
        assert_eq!(classify(&sr_p), MediaKind::Rtcp);
        // Garbage
        assert_eq!(classify(&[0x00, 0x00]), MediaKind::Other);
    }
}

//! Pure call state-machine transitions, applied to a `Call` for each SIP msg.

use crate::model::sip::{Call, CallState, HangupBy, Method, Outcome, SipMsg};

/// Extract a user portion from a SIP From/To header value.
pub fn user_of(value: &str) -> Option<String> {
    let candidate = match value.find('<') {
        Some(s) => value[s + 1..].split('>').next().unwrap_or(""),
        None => value,
    };
    let after = candidate
        .strip_prefix("sips:")
        .or_else(|| candidate.strip_prefix("sip:"))
        .unwrap_or(candidate);
    let no_params = after.split(';').next().unwrap_or(after);
    let userhost = match no_params.rfind('@') {
        Some(i) => &no_params[..i],
        None => no_params,
    }
    .trim();
    if userhost.is_empty() {
        None
    } else {
        Some(userhost.to_string())
    }
}

pub fn apply_sip(call: &mut Call, msg: &SipMsg) {
    call.pkts_sip += 1;
    call.bytes += msg.raw.len() as u64;
    // Eviction key (bounded-memory): newest activity across SIP + RTP.
    call.last_ts_us = msg.ts_us;
    // The message itself is stored by the caller (`ingest_sip`) via a move, so
    // the full-SipMsg clone that used to happen here is gone.

    // Populate identities from the first INVITE if not set.
    if matches!(msg.method, Some(Method::Invite)) {
        if call.from_uri.is_none() {
            call.from_uri = msg.from_uri.clone();
            call.from_user = msg.from_uri.as_deref().and_then(user_of);
        }
        if call.to_uri.is_none() {
            call.to_uri = msg.to_uri.clone();
            call.to_user = msg.to_uri.as_deref().and_then(user_of);
        }
    }

    let is_initial_invite =
        matches!(msg.method, Some(Method::Invite)) && msg.is_request && msg.to_tag.is_none();

    if is_initial_invite {
        if call.invite_ts.is_none() {
            call.invite_ts = Some(msg.ts_us);
        }
        if call.invite_key.is_none() {
            call.invite_key = Some(msg.flow.src.ip().to_string());
        }
        if call.invite_src.is_none() {
            call.invite_src = Some(msg.flow.src.to_string());
        }
        // Track the signaling endpoints for the per-IP active-call counter.
        if call.active_ips.is_empty() {
            call.active_ips = vec![msg.flow.src.ip(), msg.flow.dst.ip()];
        }
        call.ips.push(msg.flow.src.ip());
        call.ips.push(msg.flow.dst.ip());
        call.state = CallState::Dialing;
        return;
    }

    if msg.is_request {
        match msg.method {
            Some(Method::Bye) => {
                if call.bye_ts.is_none() {
                    call.bye_ts = Some(msg.ts_us);
                }
                // Who hung up: compare the BYE source to the caller (INVITE src).
                if call.hangup_by.is_none() {
                    call.hangup_by = match call
                        .invite_key
                        .as_deref()
                        .and_then(|k| k.parse::<std::net::IpAddr>().ok())
                    {
                        Some(caller_ip) if caller_ip == msg.flow.src.ip() => Some(HangupBy::Caller),
                        Some(_) => Some(HangupBy::Callee),
                        None => None,
                    };
                }
                // Hangup cause from the Reason header, if present.
                if let Some((code, text)) = reason_from_raw(&msg.raw) {
                    call.hangup.code = Some(code);
                    if !text.is_empty() {
                        call.hangup.reason = Some(text);
                    }
                }
            }
            Some(Method::Cancel)
                if !matches!(call.state, CallState::Completed | CallState::Failed) =>
            {
                call.state = CallState::Canceled;
                call.end_ts = Some(msg.ts_us);
                call.hangup_by.get_or_insert(HangupBy::Caller);
            }
            _ => {}
        }
        return;
    }

    // Responses.
    let Some(code) = msg.status else {
        return;
    };
    let cm = msg.cseq_method.as_deref();

    // Provisional responses to INVITE.
    if (100..200).contains(&code)
        && cm.is_none_or(|m| m.eq_ignore_ascii_case("INVITE"))
        && matches!(call.state, CallState::Dialing | CallState::Ringing)
    {
        // PDD = INVITE → first provisional (100 Trying or 180 Ringing/183).
        if call.trying_ts.is_none() && call.ringing_ts.is_none() {
            call.pdd_ms = Some(((msg.ts_us - call.invite_ts.unwrap_or(msg.ts_us)) / 1000) as u32);
        }
        if (180..190).contains(&code) || code == 183 {
            if call.ringing_ts.is_none() {
                call.ringing_ts = Some(msg.ts_us);
            }
            // Record which provisional started the ring-back (180 vs 183 early media).
            call.ring_code.get_or_insert(code);
            // Early media: 183 Session Progress carrying an SDP body.
            if code == 183 && msg.has_sdp {
                call.early_media = true;
            }
            call.state = CallState::Ringing;
        } else if code >= 100 && call.trying_ts.is_none() {
            call.trying_ts = Some(msg.ts_us);
        }
        return;
    }

    // 2xx responses.
    if (200..300).contains(&code) {
        if cm.is_some_and(|m| m.eq_ignore_ascii_case("BYE")) {
            // Final response to BYE: teardown.
            if call.end_ts.is_none() {
                call.end_ts = Some(msg.ts_us);
            }
            call.state = if call.answer_ts.is_some() {
                CallState::Completed
            } else {
                CallState::Failed
            };
            return;
        }
        // 2xx to INVITE (or assume INVITE when CSeq method unknown).
        if call.answer_ts.is_none() {
            call.answer_ts = Some(msg.ts_us);
            if let Some(inv) = call.invite_ts {
                call.setup_ms = Some(((msg.ts_us - inv) / 1000) as u32);
            }
            if let Some(r) = call.ringing_ts {
                call.ring_ms = Some(((msg.ts_us - r) / 1000) as u32);
            }
            call.state = CallState::Active;
            call.outcome = Outcome::Answered;
        }
        return;
    }

    // Non-2xx final responses.
    if code >= 300 {
        call.hangup.code = Some(code as u32);
        if cm.is_some_and(|m| m.eq_ignore_ascii_case("BYE")) {
            call.state = if call.answer_ts.is_some() {
                CallState::Completed
            } else {
                CallState::Failed
            };
            if call.end_ts.is_none() {
                call.end_ts = Some(msg.ts_us);
            }
            return;
        }
        if code == 487 {
            call.state = CallState::Canceled;
            call.outcome = Outcome::Canceled;
            call.hangup_by.get_or_insert(HangupBy::Caller);
        } else if matches!(call.state, CallState::Dialing | CallState::Ringing) {
            call.state = CallState::Failed;
            call.outcome = if (400..500).contains(&code) {
                Outcome::Rejected
            } else {
                Outcome::Failed
            };
            // The callee side refused the INVITE.
            call.hangup_by.get_or_insert(HangupBy::Reject);
            if call.end_ts.is_none() {
                call.end_ts = Some(msg.ts_us);
            }
        } else {
            call.state = if call.answer_ts.is_some() {
                CallState::Completed
            } else {
                CallState::Failed
            };
            if call.end_ts.is_none() {
                call.end_ts = Some(msg.ts_us);
            }
        }
    }
}

/// Extract hangup cause (code/reason) from a Reason header in the raw message,
/// if present. Returns (code, reason_text).
pub fn reason_from_raw(raw: &[u8]) -> Option<(u32, String)> {
    let text = std::str::from_utf8(raw).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Reason:") {
            let rest = rest.trim();
            let cause = extract_attr(rest, "cause").and_then(|c| c.parse::<u32>().ok());
            let text_val = extract_attr(rest, "text").map(|t| t.trim_matches('"').to_string());
            if let Some(c) = cause {
                return Some((c, text_val.unwrap_or_default()));
            }
        }
    }
    None
}

fn extract_attr<'a>(s: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("{name}=");
    let idx = s.find(&needle)?;
    let rest = &s[idx + needle.len()..];
    let end = rest
        .find([';', ' ', '\t', '\r', '\n'])
        .unwrap_or(rest.len());
    Some(rest[..end].trim_matches('"'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::packet::{Flow5Tuple, Proto};
    use bytes::Bytes;

    fn mk(
        ts: u64,
        is_req: bool,
        method: Option<Method>,
        status: Option<u16>,
        to_tag: Option<&str>,
    ) -> SipMsg {
        SipMsg {
            ts_us: ts,
            flow: Flow5Tuple {
                proto: Proto::Udp,
                src: "1.1.1.1:5060".parse().unwrap(),
                dst: "2.2.2.2:5060".parse().unwrap(),
            },
            is_request: is_req,
            method,
            status,
            call_id: "c1".into(),
            cseq: Some(1),
            cseq_method: Some("INVITE".into()),
            branch: Some("b".into()),
            from_tag: Some("f".into()),
            to_tag: to_tag.map(str::to_owned),
            from_uri: Some("<sip:alice@1.1.1.1>".into()),
            to_uri: Some("<sip:bob@2.2.2.2>".into()),
            raw: Bytes::new(),
            contact_addr: None,
            route_count: 0,
            record_route_count: 0,
            has_sdp: false,
        }
    }

    #[test]
    fn happy_path_state_machine() {
        let mut call = Call::new("c1".into());
        apply_sip(
            &mut call,
            &mk(1_000_000, true, Some(Method::Invite), None, None),
        );
        apply_sip(&mut call, &mk(1_100_000, false, None, Some(180), None));
        assert_eq!(call.state, CallState::Ringing);
        assert_eq!(call.pdd_ms, Some(100));
        assert_eq!(call.ring_code, Some(180));
        apply_sip(&mut call, &mk(1_500_000, false, None, Some(200), None));
        assert_eq!(call.state, CallState::Active);
        assert_eq!(call.setup_ms, Some(500));
        assert_eq!(call.ring_ms, Some(400));
        let mut bye = mk(3_000_000, true, Some(Method::Bye), None, Some("x"));
        bye.cseq_method = Some("BYE".into());
        apply_sip(&mut call, &bye);
        let mut bye_ok = mk(3_010_000, false, None, Some(200), Some("x"));
        bye_ok.cseq_method = Some("BYE".into());
        apply_sip(&mut call, &bye_ok);
        assert_eq!(call.state, CallState::Completed);
        assert_eq!(call.outcome, Outcome::Answered);
    }

    #[test]
    fn pdd_measured_at_first_provisional() {
        // 100 Trying arrives first → PDD is INV→100, not INV→180.
        let mut call = Call::new("c1".into());
        apply_sip(
            &mut call,
            &mk(1_000_000, true, Some(Method::Invite), None, None),
        );
        apply_sip(&mut call, &mk(1_050_000, false, None, Some(100), None));
        assert_eq!(call.trying_ts, Some(1_050_000));
        assert_eq!(call.pdd_ms, Some(50));
        apply_sip(&mut call, &mk(1_200_000, false, None, Some(180), None));
        assert_eq!(call.pdd_ms, Some(50), "PDD must not move to the 180 time");
        assert_eq!(call.ringing_ts, Some(1_200_000));
        assert_eq!(call.ring_code, Some(180));

        // 180 without a prior 100 → PDD is INV→180.
        let mut call2 = Call::new("c2".into());
        apply_sip(
            &mut call2,
            &mk(1_000_000, true, Some(Method::Invite), None, None),
        );
        apply_sip(&mut call2, &mk(1_150_000, false, None, Some(180), None));
        assert_eq!(call2.pdd_ms, Some(150));
    }

    #[test]
    fn ring_code_183_and_ring_ms() {
        let mut call = Call::new("c1".into());
        apply_sip(
            &mut call,
            &mk(1_000_000, true, Some(Method::Invite), None, None),
        );
        apply_sip(&mut call, &mk(1_100_000, false, None, Some(183), None));
        assert_eq!(call.state, CallState::Ringing);
        assert_eq!(call.ring_code, Some(183));
        apply_sip(&mut call, &mk(1_600_000, false, None, Some(200), None));
        assert_eq!(call.ring_ms, Some(500));
    }

    #[test]
    fn early_media_only_when_183_carries_sdp() {
        // 183 Session Progress with an SDP body = early media.
        let mut call = Call::new("c1".into());
        apply_sip(
            &mut call,
            &mk(1_000_000, true, Some(Method::Invite), None, None),
        );
        let mut m183 = mk(1_100_000, false, None, Some(183), None);
        m183.has_sdp = true;
        apply_sip(&mut call, &m183);
        assert!(call.early_media, "183+SDP must set early media");
        assert_eq!(call.ring_code, Some(183));

        // Plain 183 without media, and 180, must not.
        let mut call2 = Call::new("c2".into());
        apply_sip(
            &mut call2,
            &mk(1_000_000, true, Some(Method::Invite), None, None),
        );
        apply_sip(&mut call2, &mk(1_100_000, false, None, Some(183), None));
        assert!(!call2.early_media, "183 without SDP is not early media");
        let mut call3 = Call::new("c3".into());
        apply_sip(
            &mut call3,
            &mk(1_000_000, true, Some(Method::Invite), None, None),
        );
        apply_sip(&mut call3, &mk(1_100_000, false, None, Some(180), None));
        assert!(!call3.early_media, "180 is not early media");
    }

    #[test]
    fn hangup_initiator_detection() {
        // Caller sends the BYE.
        let mut call = Call::new("c1".into());
        apply_sip(
            &mut call,
            &mk(1_000_000, true, Some(Method::Invite), None, None),
        );
        apply_sip(&mut call, &mk(1_100_000, false, None, Some(180), None));
        apply_sip(&mut call, &mk(1_500_000, false, None, Some(200), None));
        let mut bye = mk(3_000_000, true, Some(Method::Bye), None, Some("x"));
        bye.cseq_method = Some("BYE".into());
        // BYE source = caller IP (1.1.1.1, the INVITE src).
        apply_sip(&mut call, &bye);
        assert_eq!(call.hangup_by, Some(HangupBy::Caller));

        // Callee sends the BYE (source differs from the INVITE src).
        let mut call2 = Call::new("c1".into());
        apply_sip(
            &mut call2,
            &mk(1_000_000, true, Some(Method::Invite), None, None),
        );
        apply_sip(&mut call2, &mk(1_100_000, false, None, Some(180), None));
        apply_sip(&mut call2, &mk(1_500_000, false, None, Some(200), None));
        let mut bye2 = mk(3_000_000, true, Some(Method::Bye), None, Some("x"));
        bye2.cseq_method = Some("BYE".into());
        bye2.flow.src = "2.2.2.2:5060".parse().unwrap(); // callee side
        apply_sip(&mut call2, &bye2);
        assert_eq!(call2.hangup_by, Some(HangupBy::Callee));

        // Cancel from the caller.
        let mut call3 = Call::new("c1".into());
        apply_sip(
            &mut call3,
            &mk(1_000_000, true, Some(Method::Invite), None, None),
        );
        apply_sip(&mut call3, &mk(1_100_000, false, None, Some(180), None));
        apply_sip(
            &mut call3,
            &mk(2_000_000, true, Some(Method::Cancel), None, None),
        );
        assert_eq!(call3.state, CallState::Canceled);
        assert_eq!(call3.hangup_by, Some(HangupBy::Caller));

        // Reject from the callee.
        let mut call4 = Call::new("c1".into());
        apply_sip(
            &mut call4,
            &mk(1_000_000, true, Some(Method::Invite), None, None),
        );
        apply_sip(&mut call4, &mk(1_200_000, false, None, Some(486), None));
        assert_eq!(call4.state, CallState::Failed);
        assert_eq!(call4.outcome, Outcome::Rejected);
        assert_eq!(call4.hangup_by, Some(HangupBy::Reject));
        assert_eq!(call4.hangup.code, Some(486));
    }

    #[test]
    fn rejected_path() {
        let mut call = Call::new("c1".into());
        apply_sip(
            &mut call,
            &mk(1_000_000, true, Some(Method::Invite), None, None),
        );
        apply_sip(&mut call, &mk(1_200_000, false, None, Some(486), None));
        assert_eq!(call.state, CallState::Failed);
        assert_eq!(call.outcome, Outcome::Rejected);
    }
}

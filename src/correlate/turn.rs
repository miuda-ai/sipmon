//! Passive TURN (RFC 5766/8656) tracking: learns allocations from Allocate
//! request/response, relays via XOR-RELAYED-ADDRESS, channel bindings, and
//! emits diagnostics for allocation failures / relay usage / per-leg quality.

use rustc_hash::{FxHashMap, FxHashSet};
use std::net::{IpAddr, SocketAddr};

use crate::decode::stun::{self, StunClass};
use crate::diagnostics::{Diagnostic, Severity};
use crate::model::packet::Flow5Tuple;

/// One learned allocation, keyed by the client control endpoint.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TurnAlloc {
    pub client: SocketAddr,
    pub server: SocketAddr,
    pub relayed: Option<SocketAddr>,
    pub lifetime: u32,
    pub created_at_us: u64,
    pub last_refresh_us: u64,
    /// Channel number -> peer address (learned from ChannelBind).
    pub channels: FxHashMap<u16, SocketAddr>,
}

/// Leg classification for a relayed media flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leg {
    /// client -> TURN server relay address.
    Client,
    /// TURN server relay address -> peer.
    Peer,
}

impl Leg {
    pub fn label(self) -> &'static str {
        match self {
            Leg::Client => "client",
            Leg::Peer => "peer",
        }
    }
}

/// How media reached us: direct RTP, wrapped in TURN ChannelData, or carried
/// in a Send/Data indication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encap {
    Direct,
    ChannelData,
    SendIndication,
}

pub struct TurnTracker {
    /// Keyed by client control endpoint.
    pub allocs: FxHashMap<SocketAddr, TurnAlloc>,
    /// Configured + auto-learned TURN server IPs (bounded).
    pub turn_servers: FxHashSet<IpAddr>,
    /// All learned relayed (server:relay_port) addresses (bounded).
    pub relays: FxHashSet<SocketAddr>,
    pub pkts_turn: u64,
}

// Bounds so a hostile/busy environment cannot grow these unboundedly.
const MAX_ALLOCS: usize = 8192;
const MAX_RELAYS: usize = 4096;
const MAX_SERVERS: usize = 512;

impl TurnTracker {
    pub fn new(configured: &[IpAddr]) -> Self {
        let mut servers: FxHashSet<IpAddr> = configured.iter().copied().collect();
        if servers.len() > MAX_SERVERS {
            servers = servers.into_iter().take(MAX_SERVERS).collect();
        }
        Self {
            allocs: FxHashMap::default(),
            turn_servers: servers,
            relays: FxHashSet::default(),
            pkts_turn: 0,
        }
    }

    /// Reset learned state (TUI clear); configured servers are kept.
    pub fn clear(&mut self) {
        self.allocs.clear();
        self.relays.clear();
        self.pkts_turn = 0;
    }

    /// Bounded-memory maintenance: cap sizes by evicting oldest allocations.
    pub fn prune(&mut self) {
        while self.allocs.len() > MAX_ALLOCS {
            let oldest = self
                .allocs
                .iter()
                .min_by_key(|(_, a)| a.created_at_us)
                .map(|(k, _)| *k);
            if let Some(k) = oldest {
                self.allocs.remove(&k);
            } else {
                break;
            }
        }
        if self.relays.len() > MAX_RELAYS {
            // Relays have no ordering info; keep a bounded recent subset.
            let drop: Vec<SocketAddr> = self.relays.iter().copied().skip(MAX_RELAYS).collect();
            for r in drop {
                self.relays.remove(&r);
            }
        }
        if self.turn_servers.len() > MAX_SERVERS {
            let drop: Vec<IpAddr> = self
                .turn_servers
                .iter()
                .copied()
                .skip(MAX_SERVERS)
                .collect();
            for s in drop {
                self.turn_servers.remove(&s);
            }
        }
    }

    pub fn is_turn_server(&self, ip: &IpAddr) -> bool {
        self.turn_servers.contains(ip)
    }

    /// Is this address one of the learned relay endpoints?
    #[allow(dead_code)]
    pub fn is_relay_addr(&self, addr: &SocketAddr) -> bool {
        self.relays.contains(addr)
    }

    /// Classify a media flow as a relay leg, if it touches a relay endpoint.
    pub fn leg_of(&self, flow: &Flow5Tuple) -> Option<Leg> {
        if self.relays.contains(&flow.dst) && !self.relays.contains(&flow.src) {
            Some(Leg::Client)
        } else if self.relays.contains(&flow.src) && !self.relays.contains(&flow.dst) {
            Some(Leg::Peer)
        } else {
            None
        }
    }

    fn diag(ts: u64, sev: Severity, code: &'static str, msg: impl Into<String>) -> Diagnostic {
        Diagnostic {
            ts_us: ts,
            call_id: String::new(), // filled by caller (needs call context)
            severity: sev,
            code,
            message: msg.into(),
        }
    }

    /// Process one STUN/TURN datagram. Returns diagnostics (call_id filled by
    /// the caller) plus media payloads to unwrap (Send/Data indications).
    pub fn ingest(
        &mut self,
        ts: u64,
        flow: &Flow5Tuple,
        payload: &[u8],
    ) -> (Vec<Diagnostic>, Vec<Vec<u8>>) {
        self.pkts_turn += 1;
        let mut diags = Vec::new();
        let mut media = Vec::new();
        let Some(msg) = stun::parse(payload) else {
            return (diags, media);
        };

        // Decide the server side of this flow.
        let server_side = if self.is_turn_server(&flow.dst.ip()) {
            flow.dst
        } else if self.is_turn_server(&flow.src.ip()) {
            flow.src
        } else if msg.method == stun::METHOD_ALLOCATE {
            // First allocation request: dst is the TURN server control address.
            flow.dst
        } else {
            flow.src
        };
        if msg.method == stun::METHOD_ALLOCATE && !self.is_turn_server(&server_side.ip()) {
            self.turn_servers.insert(server_side.ip());
        }

        match (msg.method, msg.class) {
            // --- Allocation lifecycle ---
            (stun::METHOD_ALLOCATE, StunClass::Request) => {
                let client = flow.src;
                self.allocs.insert(
                    client,
                    TurnAlloc {
                        client,
                        server: flow.dst,
                        relayed: None,
                        lifetime: 0,
                        created_at_us: ts,
                        last_refresh_us: ts,
                        channels: FxHashMap::default(),
                    },
                );
            }
            (stun::METHOD_ALLOCATE, StunClass::Success) => {
                let client = flow.dst;
                if let Some(alloc) = self.allocs.get_mut(&client) {
                    if let Some(r) = msg.relayed_address() {
                        alloc.relayed = Some(r);
                        self.relays.insert(r);
                        self.turn_servers.insert(r.ip());
                    }
                    alloc.lifetime = msg
                        .attrs
                        .iter()
                        .find_map(|a| a.lifetime())
                        .unwrap_or(alloc.lifetime);
                    diags.push(Self::diag(
                        ts,
                        Severity::Info,
                        crate::diagnostics::TURN_ALLOC_OK,
                        format!(
                            "TURN allocation ok client={client} relayed={} lifetime={}s",
                            alloc
                                .relayed
                                .map(|r| r.to_string())
                                .unwrap_or_else(|| "-".into()),
                            alloc.lifetime
                        ),
                    ));
                }
            }
            (stun::METHOD_ALLOCATE, StunClass::Error) => {
                let client = flow.dst;
                let (code, reason) = msg.error_code().unwrap_or((0, "?".into()));
                diags.push(Self::diag(
                    ts,
                    Severity::Warn,
                    crate::diagnostics::TURN_ALLOC_FAILED,
                    format!(
                        "TURN allocation failed client={client} server={server_side} error={code} {reason}"
                    ),
                ));
                self.allocs.remove(&client);
            }
            (stun::METHOD_REFRESH, StunClass::Request) => {
                if let Some(alloc) = self.allocs.get_mut(&flow.src) {
                    alloc.last_refresh_us = ts;
                }
            }
            (stun::METHOD_REFRESH, StunClass::Error) => {
                let (code, reason) = msg.error_code().unwrap_or((0, "?".into()));
                diags.push(Self::diag(
                    ts,
                    Severity::Info,
                    crate::diagnostics::TURN_REFRESH_FAILED,
                    format!(
                        "TURN refresh failed client={} error={code} {reason}",
                        flow.dst
                    ),
                ));
            }
            // --- Channel binding (media encapsulation) ---
            (stun::METHOD_CHANNEL_BIND, StunClass::Request) => {
                let client = flow.src;
                if let Some(alloc) = self.allocs.get_mut(&client)
                    && let Some(ch) = msg.attrs.iter().find_map(|a| a.channel_number())
                    && let Some(peer) = msg.peer_address()
                {
                    alloc.channels.insert(ch, peer);
                }
            }
            // --- Send/Data indications carry RTP for unwrapping ---
            (stun::METHOD_SEND, StunClass::Indication)
            | (stun::METHOD_DATA, StunClass::Indication) => {
                if let Some(d) = msg.data_payload() {
                    media.push(d.to_vec());
                }
            }
            _ => {}
        }

        (diags, media)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::packet::Proto;

    fn flow(src: &str, dst: &str) -> Flow5Tuple {
        Flow5Tuple {
            proto: Proto::Udp,
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
        }
    }

    fn alloc_request(txn: &[u8; 12]) -> Vec<u8> {
        build_stun(stun::METHOD_ALLOCATE, StunClass::Request, txn, &[])
    }

    fn build_stun(
        method: u16,
        class: StunClass,
        txn: &[u8; 12],
        attrs: &[(u16, Vec<u8>)],
    ) -> Vec<u8> {
        let type_bits = match class {
            StunClass::Request => 0x0000,
            StunClass::Indication => 0x0010,
            StunClass::Success => 0x0100,
            StunClass::Error => 0x0110,
        };
        let typ = method | type_bits;
        let mut body = Vec::new();
        for (at, av) in attrs {
            body.extend_from_slice(&at.to_be_bytes());
            body.extend_from_slice(&(av.len() as u16).to_be_bytes());
            body.extend_from_slice(av);
            while body.len() % 4 != 0 {
                body.push(0);
            }
        }
        let mut out = Vec::new();
        out.extend_from_slice(&typ.to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&stun::MAGIC_COOKIE.to_be_bytes());
        out.extend_from_slice(txn);
        out.extend_from_slice(&body);
        out
    }

    fn xor_addr(addr: SocketAddr, txn: &[u8; 12]) -> Vec<u8> {
        let key: Vec<u8> = stun::MAGIC_COOKIE
            .to_be_bytes()
            .iter()
            .chain(txn.iter())
            .copied()
            .collect();
        let mut out = vec![0u8, 0x01];
        let xport = addr.port() ^ (stun::MAGIC_COOKIE >> 16) as u16;
        out.extend_from_slice(&xport.to_be_bytes());
        if let IpAddr::V4(v4) = addr.ip() {
            for (i, b) in v4.octets().iter().enumerate() {
                out.push(b ^ key[i]);
            }
        }
        out
    }

    #[test]
    fn learns_relay_from_allocate() {
        let mut t = TurnTracker::new(&[]);
        let txn = [5u8; 12];
        let f = flow("10.0.0.1:3000", "203.0.113.9:3478");
        // request
        let (d, m) = t.ingest(1_000, &f, &alloc_request(&txn));
        assert!(d.is_empty() && m.is_empty());
        assert!(t.is_turn_server(&"203.0.113.9".parse().unwrap()));
        // success response with relayed 203.0.113.9:5000
        let relayed: SocketAddr = "203.0.113.9:5000".parse().unwrap();
        let resp = build_stun(
            stun::METHOD_ALLOCATE,
            StunClass::Success,
            &txn,
            &[(stun::ATTR_XOR_RELAYED_ADDRESS, xor_addr(relayed, &txn))],
        );
        let (d, m) = t.ingest(1_050, &f.reverse(), &resp);
        assert!(m.is_empty());
        assert!(
            d.iter()
                .any(|x| x.code == crate::diagnostics::TURN_ALLOC_OK)
        );
        assert!(t.is_relay_addr(&relayed));
        // leg classification
        assert_eq!(
            t.leg_of(&flow("10.0.0.1:4000", "203.0.113.9:5000")),
            Some(Leg::Client)
        );
        assert_eq!(
            t.leg_of(&flow("203.0.113.9:5000", "10.20.0.1:4000")),
            Some(Leg::Peer)
        );
    }

    #[test]
    fn allocate_error_emits_warning() {
        let mut t = TurnTracker::new(&[]);
        let txn = [6u8; 12];
        let f = flow("10.0.0.1:3000", "203.0.113.9:3478");
        t.ingest(1_000, &f, &alloc_request(&txn));
        let mut ev = vec![0u8, 0, 4, 86];
        ev.extend_from_slice(b"Allocation Quota Reached");
        let err = build_stun(
            stun::METHOD_ALLOCATE,
            StunClass::Error,
            &txn,
            &[(stun::ATTR_ERROR_CODE, ev)],
        );
        let (d, _) = t.ingest(1_050, &f.reverse(), &err);
        assert!(d.iter().any(|x| {
            x.code == crate::diagnostics::TURN_ALLOC_FAILED
                && x.severity == Severity::Warn
                && x.message.contains("486")
        }));
    }
}

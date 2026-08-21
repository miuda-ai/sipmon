use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use anyhow::{Context, Result};
use chrono::Offset;

use crate::model::media::StreamSummary;
use crate::model::packet::{Flow5Tuple, Proto};
use crate::model::stats::{HealthBucket, MetricSet};

pub const MAGIC: &[u8; 4] = b"SMON";
/// v2: the header's tz_offset field now carries the recording machine's UTC
/// offset (v1 always wrote 0, which read as "unset").
pub const VERSION: u16 = 2;

/// Sanity cap for a single evlog record payload (32 MiB). A length field
/// beyond this means the file is corrupt/hostile; fail cleanly instead of
/// attempting a giant allocation.
pub const MAX_RECORD_LEN: usize = 32 * 1024 * 1024;

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
enum EvType {
    SipMsg = 1,
    Txn = 2,
    Call = 3,
    StreamSnap = 4,
    RtcpRtt = 5,
    HealthBucket = 6,
    Error = 7,
    Diag = 8,
}

// ----------------------------- payload structs -----------------------------

#[derive(Debug, Clone)]
pub struct SipMsgEvt {
    pub ts_us: u64,
    pub flow: Flow5Tuple,
    pub is_request: bool,
    pub method: Option<String>,
    pub status: Option<u16>,
    pub call_id: String,
    pub cseq: Option<u32>,
    pub branch: Option<String>,
    pub from_tag: Option<String>,
    pub to_tag: Option<String>,
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CallEvt {
    pub ts_us: u64,
    pub call_id: String,
    pub kind: CallEvtKind,
    pub from_user: Option<String>,
    pub to_user: Option<String>,
    pub from_uri: Option<String>,
    pub to_uri: Option<String>,
    pub state: u8,
    pub outcome: u8,
    pub invite_ts: Option<u64>,
    pub trying_ts: Option<u64>,
    pub ringing_ts: Option<u64>,
    pub answer_ts: Option<u64>,
    pub bye_ts: Option<u64>,
    pub end_ts: Option<u64>,
    pub pdd_ms: Option<u32>,
    pub setup_ms: Option<u32>,
    pub hangup_code: Option<u32>,
    pub hangup_reason: Option<String>,
    pub pkts_sip: u64,
    pub pkts_rtp: u64,
    pub pkts_rtcp: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum CallEvtKind {
    Setup = 1,
    Update = 2,
    Teardown = 3,
}

#[derive(Debug, Clone)]
pub struct StreamSnapEvt {
    pub ts_us: u64,
    pub call_id: String,
    pub ssrc: u32,
    pub flow: Flow5Tuple,
    pub codec: Option<String>,
    pub payload_type: Option<u8>,
    pub packets: u64,
    pub lost: u64,
    pub expected: u64,
    pub loss_pct: f64,
    pub jitter_ms: Option<f64>,
    pub mos: Option<f64>,
    pub direction: Option<String>,
    /// Cumulative RTP bytes observed (added in v1.1; absent in older logs).
    pub bytes: u64,
    pub first_ts_us: Option<u64>,
    pub last_ts_us: Option<u64>,
    pub rtt_min_ms: Option<f64>,
    pub rtt_avg_ms: Option<f64>,
    pub rtt_max_ms: Option<f64>,
    pub oneway_ms: Option<f64>,
    /// TURN relay leg label ("client"/"peer") if the stream traverses a relay.
    pub leg: Option<String>,
    pub via_turn: bool,
}

#[derive(Debug, Clone)]
pub struct RtcpRttEvt {
    pub ts_us: u64,
    pub call_id: String,
    pub ssrc: u32,
    pub rtt_ms: f64,
    pub oneway_ms: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct TxnEvt {
    pub ts_us: u64,
    pub call_id: String,
    pub branch: String,
    pub method: String,
    pub response_code: Option<u16>,
    pub delay_ms: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct ErrorEvt {
    pub ts_us: u64,
    pub kind: String,
    pub msg: String,
}

#[derive(Debug, Clone)]
pub struct DiagEvt {
    pub ts_us: u64,
    pub call_id: String,
    pub severity: u8, // 0=info 1=warn 2=critical
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub enum Event {
    SipMsg(SipMsgEvt),
    Txn(TxnEvt),
    Call(CallEvt),
    StreamSnap(StreamSnapEvt),
    RtcpRtt(RtcpRttEvt),
    HealthBucket(HealthBucket),
    Error(ErrorEvt),
    Diag(DiagEvt),
}

impl Event {
    pub fn ts_us(&self) -> u64 {
        match self {
            Event::SipMsg(e) => e.ts_us,
            Event::Txn(e) => e.ts_us,
            Event::Call(e) => e.ts_us,
            Event::StreamSnap(e) => e.ts_us,
            Event::RtcpRtt(e) => e.ts_us,
            Event::HealthBucket(e) => e.bucket_us,
            Event::Error(e) => e.ts_us,
            Event::Diag(e) => e.ts_us,
        }
    }
}

// ----------------------------- varint helpers -----------------------------

fn write_varint(buf: &mut Vec<u8>, mut n: u64) {
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            buf.push(b);
            break;
        } else {
            buf.push(b | 0x80);
        }
    }
}

fn read_varint<R: Read>(r: &mut R) -> std::io::Result<u64> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        let mut byte = [0u8; 1];
        r.read_exact(&mut byte)?;
        let b = byte[0];
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift >= 64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "varint too long",
            ));
        }
    }
}

fn write_string(buf: &mut Vec<u8>, s: &str) {
    write_varint(buf, s.len() as u64);
    buf.extend_from_slice(s.as_bytes());
}

fn write_opt_string(buf: &mut Vec<u8>, s: &Option<String>) {
    match s {
        Some(s) => {
            // len+1 so 0 encodes None.
            write_varint(buf, s.len() as u64 + 1);
            buf.extend_from_slice(s.as_bytes());
        }
        None => write_varint(buf, 0),
    }
}

fn write_bytes(buf: &mut Vec<u8>, b: &[u8]) {
    write_varint(buf, b.len() as u64);
    buf.extend_from_slice(b);
}

fn write_opt_u32(buf: &mut Vec<u8>, v: Option<u32>) {
    match v {
        Some(x) => {
            buf.push(1);
            write_varint(buf, x as u64);
        }
        None => buf.push(0),
    }
}

fn write_opt_u64(buf: &mut Vec<u8>, v: Option<u64>) {
    match v {
        Some(x) => {
            buf.push(1);
            write_varint(buf, x);
        }
        None => buf.push(0),
    }
}

fn write_opt_u16(buf: &mut Vec<u8>, v: Option<u16>) {
    match v {
        Some(x) => {
            buf.push(1);
            buf.extend_from_slice(&x.to_be_bytes());
        }
        None => buf.push(0),
    }
}

fn write_opt_u8(buf: &mut Vec<u8>, v: Option<u8>) {
    match v {
        Some(x) => {
            buf.push(1);
            buf.push(x);
        }
        None => buf.push(0),
    }
}

fn write_opt_f64(buf: &mut Vec<u8>, v: Option<f64>) {
    match v {
        Some(x) => {
            buf.push(1);
            buf.extend_from_slice(&x.to_be_bytes());
        }
        None => buf.push(0),
    }
}

fn write_f64(buf: &mut Vec<u8>, v: f64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn write_flow(buf: &mut Vec<u8>, flow: &Flow5Tuple) {
    buf.push(match flow.proto {
        Proto::Udp => 0,
        Proto::Tcp => 1,
    });
    write_sockaddr(buf, &flow.src);
    write_sockaddr(buf, &flow.dst);
}

fn write_sockaddr(buf: &mut Vec<u8>, sa: &SocketAddr) {
    match sa.ip() {
        IpAddr::V4(v4) => {
            buf.push(4);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(6);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf.extend_from_slice(&sa.port().to_be_bytes());
}

/// Encode one event's payload into the caller's (reused) buffer. Returning
/// a fresh `Vec<u8>` per event used to cost one allocation per record on the
/// capture path.
fn encode_event_payload(buf: &mut Vec<u8>, ev: &Event) -> EvType {
    buf.clear();
    match ev {
        Event::SipMsg(e) => {
            write_flow(buf, &e.flow);
            buf.push(e.is_request as u8);
            write_opt_string(buf, &e.method);
            write_opt_u16(buf, e.status);
            write_string(buf, &e.call_id);
            write_opt_u32(buf, e.cseq);
            write_opt_string(buf, &e.branch);
            write_opt_string(buf, &e.from_tag);
            write_opt_string(buf, &e.to_tag);
            write_bytes(buf, &e.raw);
            EvType::SipMsg
        }
        Event::Txn(e) => {
            write_string(buf, &e.call_id);
            write_string(buf, &e.branch);
            write_string(buf, &e.method);
            write_opt_u16(buf, e.response_code);
            write_opt_u32(buf, e.delay_ms);
            EvType::Txn
        }
        Event::Call(e) => {
            write_string(buf, &e.call_id);
            buf.push(e.kind as u8);
            write_opt_string(buf, &e.from_user);
            write_opt_string(buf, &e.to_user);
            write_opt_string(buf, &e.from_uri);
            write_opt_string(buf, &e.to_uri);
            buf.push(e.state);
            buf.push(e.outcome);
            write_opt_u64(buf, e.invite_ts);
            write_opt_u64(buf, e.trying_ts);
            write_opt_u64(buf, e.ringing_ts);
            write_opt_u64(buf, e.answer_ts);
            write_opt_u64(buf, e.bye_ts);
            write_opt_u64(buf, e.end_ts);
            write_opt_u32(buf, e.pdd_ms);
            write_opt_u32(buf, e.setup_ms);
            write_opt_u32(buf, e.hangup_code);
            write_opt_string(buf, &e.hangup_reason);
            write_varint(buf, e.pkts_sip);
            write_varint(buf, e.pkts_rtp);
            write_varint(buf, e.pkts_rtcp);
            write_varint(buf, e.bytes);
            EvType::Call
        }
        Event::StreamSnap(e) => {
            write_string(buf, &e.call_id);
            buf.extend_from_slice(&e.ssrc.to_be_bytes());
            write_flow(buf, &e.flow);
            write_opt_string(buf, &e.codec);
            write_opt_u8(buf, e.payload_type);
            write_varint(buf, e.packets);
            write_varint(buf, e.lost);
            write_varint(buf, e.expected);
            write_f64(buf, e.loss_pct);
            write_opt_f64(buf, e.jitter_ms);
            write_opt_f64(buf, e.mos);
            write_opt_string(buf, &e.direction);
            // v1.1+ fields (readers tolerate their absence in older logs).
            write_varint(buf, e.bytes);
            write_opt_u64(buf, e.first_ts_us);
            write_opt_u64(buf, e.last_ts_us);
            write_opt_f64(buf, e.rtt_min_ms);
            write_opt_f64(buf, e.rtt_avg_ms);
            write_opt_f64(buf, e.rtt_max_ms);
            write_opt_f64(buf, e.oneway_ms);
            write_opt_string(buf, &e.leg);
            buf.push(e.via_turn as u8);
            EvType::StreamSnap
        }
        Event::RtcpRtt(e) => {
            write_string(buf, &e.call_id);
            buf.extend_from_slice(&e.ssrc.to_be_bytes());
            write_f64(buf, e.rtt_ms);
            write_opt_f64(buf, e.oneway_ms);
            EvType::RtcpRtt
        }
        Event::HealthBucket(e) => {
            write_varint(buf, e.bucket_us);
            write_string(buf, &e.dim_key);
            write_metric_set(buf, &e.metrics);
            EvType::HealthBucket
        }
        Event::Error(e) => {
            write_string(buf, &e.kind);
            write_string(buf, &e.msg);
            EvType::Error
        }
        Event::Diag(e) => {
            write_string(buf, &e.call_id);
            buf.push(e.severity);
            write_string(buf, &e.code);
            write_string(buf, &e.message);
            EvType::Diag
        }
    }
}

fn write_metric_set(buf: &mut Vec<u8>, m: &MetricSet) {
    write_varint(buf, m.calls);
    write_varint(buf, m.answered);
    write_varint(buf, m.failed);
    write_f64(buf, m.pdd_sum_ms);
    write_varint(buf, m.pdd_n);
    write_f64(buf, m.jitter_sum_ms);
    write_varint(buf, m.jitter_n);
    write_f64(buf, m.loss_sum_pct);
    write_varint(buf, m.loss_n);
    write_f64(buf, m.rtt_sum_ms);
    write_varint(buf, m.rtt_n);
    write_f64(buf, m.mos_sum);
    write_varint(buf, m.mos_n);
}

// ----------------------------- writer -----------------------------

pub struct EvlogWriter<W: Write + Send> {
    w: BufWriter<W>,
    last_ts: u64,
    bytes_written: u64,
    /// Reused encode buffers: payload first, then the framed record (header +
    /// payload). Both live for the writer's lifetime, so steady-state record
    /// writes allocate nothing (the old path built two Vecs per event).
    payload_buf: Vec<u8>,
    rec_buf: Vec<u8>,
}

impl EvlogWriter<File> {
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_ref())
            .with_context(|| format!("open evlog {}", path.as_ref().display()))?;
        Self::new(file)
    }
}

impl<W: Write + Send> EvlogWriter<W> {
    pub fn new(w: W) -> Result<Self> {
        let mut bw = BufWriter::new(w);
        // Header. `tz_offset` records the writing machine's UTC offset so a
        // replay can render the original local wall-clock ("当时的时间") even on
        // a host in a different timezone. Readers of v1 files (tz always 0)
        // treat it as unset and fall back to the current machine's timezone.
        bw.write_all(MAGIC)?;
        bw.write_all(&VERSION.to_be_bytes())?;
        bw.write_all(&0u16.to_be_bytes())?; // flags
        let tz = chrono::Local::now().offset().fix().local_minus_utc();
        bw.write_all(&tz.to_be_bytes())?; // tz_offset
        bw.flush()?;
        Ok(Self {
            w: bw,
            last_ts: 0,
            bytes_written: 0,
            payload_buf: Vec::new(),
            rec_buf: Vec::new(),
        })
    }

    pub fn write(&mut self, ev: &Event) -> Result<()> {
        let ts = ev.ts_us();
        let ty = encode_event_payload(&mut self.payload_buf, ev);
        let delta = ts.saturating_sub(self.last_ts);
        let rec = &mut self.rec_buf;
        rec.clear();
        rec.reserve(16 + self.payload_buf.len());
        write_varint(rec, delta);
        rec.push(ty as u8);
        write_varint(rec, self.payload_buf.len() as u64);
        rec.extend_from_slice(&self.payload_buf);
        self.w.write_all(rec)?;
        self.last_ts = ts;
        self.bytes_written += rec.len() as u64;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.w.flush()?;
        Ok(())
    }

    /// Total payload bytes handed to the underlying writer (headers + records).
    /// The on-disk size trails this by at most the internal buffer between
    /// flushes; used by the TUI to show live recording growth.
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }
}

// ----------------------------- reader -----------------------------

fn read_string<R: Read>(r: &mut R) -> Result<String> {
    let len = read_varint(r)? as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn read_opt_string<R: Read>(r: &mut R) -> Result<Option<String>> {
    let len = read_varint(r)?;
    if len == 0 {
        return Ok(None);
    }
    let real = len as usize - 1;
    let mut buf = vec![0u8; real];
    r.read_exact(&mut buf)?;
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

fn read_bytes<R: Read>(r: &mut R) -> Result<Vec<u8>> {
    let len = read_varint(r)? as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_opt_u32<R: Read>(r: &mut R) -> Result<Option<u32>> {
    let mut flag = [0u8; 1];
    r.read_exact(&mut flag)?;
    if flag[0] == 0 {
        return Ok(None);
    }
    Ok(Some(read_varint(r)? as u32))
}

fn read_opt_u64<R: Read>(r: &mut R) -> Result<Option<u64>> {
    let mut flag = [0u8; 1];
    r.read_exact(&mut flag)?;
    if flag[0] == 0 {
        return Ok(None);
    }
    Ok(Some(read_varint(r)?))
}

fn read_opt_u16<R: Read>(r: &mut R) -> Result<Option<u16>> {
    let mut flag = [0u8; 1];
    r.read_exact(&mut flag)?;
    if flag[0] == 0 {
        return Ok(None);
    }
    let mut b = [0u8; 2];
    r.read_exact(&mut b)?;
    Ok(Some(u16::from_be_bytes(b)))
}

fn read_opt_u8<R: Read>(r: &mut R) -> Result<Option<u8>> {
    let mut flag = [0u8; 1];
    r.read_exact(&mut flag)?;
    if flag[0] == 0 {
        return Ok(None);
    }
    let mut b = [0u8; 1];
    r.read_exact(&mut b)?;
    Ok(Some(b[0]))
}

fn read_opt_f64<R: Read>(r: &mut R) -> Result<Option<f64>> {
    let mut flag = [0u8; 1];
    r.read_exact(&mut flag)?;
    if flag[0] == 0 {
        return Ok(None);
    }
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(Some(f64::from_be_bytes(b)))
}

fn read_f64<R: Read>(r: &mut R) -> Result<f64> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(f64::from_be_bytes(b))
}

fn read_u8<R: Read>(r: &mut R) -> Result<u8> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b)?;
    Ok(b[0])
}

fn read_flow<R: Read>(r: &mut R) -> Result<Flow5Tuple> {
    let mut pb = [0u8; 1];
    r.read_exact(&mut pb)?;
    let proto = if pb[0] == 1 { Proto::Tcp } else { Proto::Udp };
    let src = read_sockaddr(r)?;
    let dst = read_sockaddr(r)?;
    Ok(Flow5Tuple { proto, src, dst })
}

fn read_sockaddr<R: Read>(r: &mut R) -> Result<SocketAddr> {
    let mut tag = [0u8; 1];
    r.read_exact(&mut tag)?;
    let ip = match tag[0] {
        4 => {
            let mut b = [0u8; 4];
            r.read_exact(&mut b)?;
            IpAddr::V4(Ipv4Addr::from(b))
        }
        _ => {
            let mut b = [0u8; 16];
            r.read_exact(&mut b)?;
            IpAddr::V6(Ipv6Addr::from(b))
        }
    };
    let mut p = [0u8; 2];
    r.read_exact(&mut p)?;
    Ok(SocketAddr::new(ip, u16::from_be_bytes(p)))
}

fn read_metric_set<R: Read>(r: &mut R) -> Result<MetricSet> {
    Ok(MetricSet {
        calls: read_varint(r)?,
        answered: read_varint(r)?,
        failed: read_varint(r)?,
        pdd_sum_ms: read_f64(r)?,
        pdd_n: read_varint(r)?,
        jitter_sum_ms: read_f64(r)?,
        jitter_n: read_varint(r)?,
        loss_sum_pct: read_f64(r)?,
        loss_n: read_varint(r)?,
        rtt_sum_ms: read_f64(r)?,
        rtt_n: read_varint(r)?,
        mos_sum: read_f64(r)?,
        mos_n: read_varint(r)?,
    })
}

pub(crate) fn decode_payload(ty: u8, ts_us: u64, mut rd: &[u8]) -> Result<Event> {
    let ev = match ty {
        1 => {
            let flow = read_flow(&mut rd)?;
            let mut b = [0u8; 1];
            rd.read_exact(&mut b)?;
            let is_request = b[0] != 0;
            let method = read_opt_string(&mut rd)?;
            let status = read_opt_u16(&mut rd)?;
            let call_id = read_string(&mut rd)?;
            let cseq = read_opt_u32(&mut rd)?;
            let branch = read_opt_string(&mut rd)?;
            let from_tag = read_opt_string(&mut rd)?;
            let to_tag = read_opt_string(&mut rd)?;
            let raw = read_bytes(&mut rd)?;
            Event::SipMsg(SipMsgEvt {
                ts_us,
                flow,
                is_request,
                method,
                status,
                call_id,
                cseq,
                branch,
                from_tag,
                to_tag,
                raw,
            })
        }
        3 => {
            let call_id = read_string(&mut rd)?;
            let mut kb = [0u8; 1];
            rd.read_exact(&mut kb)?;
            let kind = match kb[0] {
                3 => CallEvtKind::Teardown,
                2 => CallEvtKind::Update,
                _ => CallEvtKind::Setup,
            };
            let from_user = read_opt_string(&mut rd)?;
            let to_user = read_opt_string(&mut rd)?;
            let from_uri = read_opt_string(&mut rd)?;
            let to_uri = read_opt_string(&mut rd)?;
            let mut sb = [0u8; 1];
            rd.read_exact(&mut sb)?;
            let state = sb[0];
            let mut ob = [0u8; 1];
            rd.read_exact(&mut ob)?;
            let outcome = ob[0];
            let invite_ts = read_opt_u64(&mut rd)?;
            let trying_ts = read_opt_u64(&mut rd)?;
            let ringing_ts = read_opt_u64(&mut rd)?;
            let answer_ts = read_opt_u64(&mut rd)?;
            let bye_ts = read_opt_u64(&mut rd)?;
            let end_ts = read_opt_u64(&mut rd)?;
            let pdd_ms = read_opt_u32(&mut rd)?;
            let setup_ms = read_opt_u32(&mut rd)?;
            let hangup_code = read_opt_u32(&mut rd)?;
            let hangup_reason = read_opt_string(&mut rd)?;
            let pkts_sip = read_varint(&mut rd)?;
            let pkts_rtp = read_varint(&mut rd)?;
            let pkts_rtcp = read_varint(&mut rd)?;
            let bytes = read_varint(&mut rd)?;
            Event::Call(CallEvt {
                ts_us,
                call_id,
                kind,
                from_user,
                to_user,
                from_uri,
                to_uri,
                state,
                outcome,
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
            })
        }
        4 => {
            let call_id = read_string(&mut rd)?;
            let mut s = [0u8; 4];
            rd.read_exact(&mut s)?;
            let ssrc = u32::from_be_bytes(s);
            let flow = read_flow(&mut rd)?;
            let codec = read_opt_string(&mut rd)?;
            let payload_type = read_opt_u8(&mut rd)?;
            let packets = read_varint(&mut rd)?;
            let lost = read_varint(&mut rd)?;
            let expected = read_varint(&mut rd)?;
            let loss_pct = read_f64(&mut rd)?;
            let jitter_ms = read_opt_f64(&mut rd)?;
            let mos = read_opt_f64(&mut rd)?;
            let direction = read_opt_string(&mut rd)?;
            // v1.1+ fields appended after `direction`; older logs stop there.
            let (
                bytes,
                first_ts_us,
                last_ts_us,
                rtt_min_ms,
                rtt_avg_ms,
                rtt_max_ms,
                oneway_ms,
                leg,
                via_turn,
            ) = if rd.is_empty() {
                (0, None, None, None, None, None, None, None, false)
            } else {
                (
                    read_varint(&mut rd)?,
                    read_opt_u64(&mut rd)?,
                    read_opt_u64(&mut rd)?,
                    read_opt_f64(&mut rd)?,
                    read_opt_f64(&mut rd)?,
                    read_opt_f64(&mut rd)?,
                    read_opt_f64(&mut rd)?,
                    read_opt_string(&mut rd)?,
                    read_u8(&mut rd)? != 0,
                )
            };
            Event::StreamSnap(StreamSnapEvt {
                ts_us,
                call_id,
                ssrc,
                flow,
                codec,
                payload_type,
                packets,
                lost,
                expected,
                loss_pct,
                jitter_ms,
                mos,
                direction,
                bytes,
                first_ts_us,
                last_ts_us,
                rtt_min_ms,
                rtt_avg_ms,
                rtt_max_ms,
                oneway_ms,
                leg,
                via_turn,
            })
        }
        5 => {
            let call_id = read_string(&mut rd)?;
            let mut s = [0u8; 4];
            rd.read_exact(&mut s)?;
            let ssrc = u32::from_be_bytes(s);
            let rtt_ms = read_f64(&mut rd)?;
            let oneway_ms = read_opt_f64(&mut rd)?;
            Event::RtcpRtt(RtcpRttEvt {
                ts_us,
                call_id,
                ssrc,
                rtt_ms,
                oneway_ms,
            })
        }
        6 => {
            let bucket_us = read_varint(&mut rd)?;
            let dim_key = read_string(&mut rd)?;
            let metrics = read_metric_set(&mut rd)?;
            Event::HealthBucket(HealthBucket {
                bucket_us,
                dim_key,
                metrics,
            })
        }
        7 => {
            let kind = read_string(&mut rd)?;
            let msg = read_string(&mut rd)?;
            Event::Error(ErrorEvt { ts_us, kind, msg })
        }
        2 => {
            let call_id = read_string(&mut rd)?;
            let branch = read_string(&mut rd)?;
            let method = read_string(&mut rd)?;
            let response_code = read_opt_u16(&mut rd)?;
            let delay_ms = read_opt_u32(&mut rd)?;
            Event::Txn(TxnEvt {
                ts_us,
                call_id,
                branch,
                method,
                response_code,
                delay_ms,
            })
        }
        8 => {
            let call_id = read_string(&mut rd)?;
            let mut sb = [0u8; 1];
            rd.read_exact(&mut sb)?;
            let severity = sb[0];
            let code = read_string(&mut rd)?;
            let message = read_string(&mut rd)?;
            Event::Diag(DiagEvt {
                ts_us,
                call_id,
                severity,
                code,
                message,
            })
        }
        _ => {
            // Unknown event type from a newer writer: skip transparently.
            Event::Error(ErrorEvt {
                ts_us,
                kind: "unknown_event".into(),
                msg: format!("skipped event type {ty}"),
            })
        }
    };
    Ok(ev)
}

/// Zero-copy walk of an evlog image (file header optional). Avoids allocating
/// a payload `Vec` per record — the callback receives a borrow of `data`.
#[cfg(test)]
pub(crate) fn walk_records(
    data: &[u8],
    mut f: impl FnMut(u8, u64, &[u8]) -> Result<()>,
) -> Result<Option<i32>> {
    let mut tz_offset_secs = None;
    let mut cur = data;
    if cur.len() >= 12 && cur[..4] == *MAGIC {
        let version = u16::from_be_bytes([cur[4], cur[5]]);
        if version >= 2 {
            tz_offset_secs = Some(i32::from_be_bytes([cur[8], cur[9], cur[10], cur[11]]));
        }
        cur = &cur[12..];
    }
    let mut last_ts = 0u64;
    while !cur.is_empty() {
        let delta = match slice_varint(&mut cur) {
            Some(v) => v,
            None => break,
        };
        if cur.is_empty() {
            break;
        }
        let ty = cur[0];
        cur = &cur[1..];
        let Some(len) = slice_varint(&mut cur) else {
            break;
        };
        let len = len as usize;
        if len > MAX_RECORD_LEN || cur.len() < len {
            // Truncated tail (kill mid-write) or hostile length: stop, keep
            // whatever was already walked.
            break;
        }
        let (payload, rest) = cur.split_at(len);
        cur = rest;
        let ts_us = last_ts.saturating_add(delta);
        last_ts = ts_us;
        f(ty, ts_us, payload)?;
    }
    Ok(tz_offset_secs)
}

fn slice_varint(rd: &mut &[u8]) -> Option<u64> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    for _ in 0..10 {
        if rd.is_empty() {
            return None;
        }
        let b = rd[0];
        *rd = &rd[1..];
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    None
}

fn slice_str<'a>(rd: &mut &'a [u8]) -> Result<&'a str> {
    let Some(len) = slice_varint(rd) else {
        anyhow::bail!("truncated string length");
    };
    let len = len as usize;
    if rd.len() < len {
        anyhow::bail!("truncated string");
    }
    let (head, rest) = rd.split_at(len);
    *rd = rest;
    Ok(std::str::from_utf8(head).unwrap_or(""))
}

fn skip_opt_string(rd: &mut &[u8]) -> Result<()> {
    let Some(len) = slice_varint(rd) else {
        anyhow::bail!("truncated optional string");
    };
    if len == 0 {
        return Ok(());
    }
    let n = (len as usize).saturating_sub(1);
    if rd.len() < n {
        anyhow::bail!("truncated optional string body");
    }
    *rd = &rd[n..];
    Ok(())
}

fn skip_opt_tagged(rd: &mut &[u8], body: usize) -> Result<()> {
    if rd.is_empty() {
        anyhow::bail!("truncated optional flag");
    }
    let flag = rd[0];
    *rd = &rd[1..];
    if flag == 0 {
        return Ok(());
    }
    if rd.len() < body {
        anyhow::bail!("truncated optional body");
    }
    *rd = &rd[body..];
    Ok(())
}

fn skip_opt_varint(rd: &mut &[u8]) -> Result<()> {
    if rd.is_empty() {
        anyhow::bail!("truncated optional varint flag");
    }
    let flag = rd[0];
    *rd = &rd[1..];
    if flag == 0 {
        return Ok(());
    }
    if slice_varint(rd).is_none() {
        anyhow::bail!("truncated optional varint");
    }
    Ok(())
}

fn need<'a>(rd: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if rd.len() < n {
        anyhow::bail!("truncated evlog field ({n} bytes)");
    }
    let (head, rest) = rd.split_at(n);
    *rd = rest;
    Ok(head)
}

fn slice_flow(rd: &mut &[u8]) -> Result<Flow5Tuple> {
    let proto = if need(rd, 1)?[0] == 1 {
        Proto::Tcp
    } else {
        Proto::Udp
    };
    let src = slice_sockaddr(rd)?;
    let dst = slice_sockaddr(rd)?;
    Ok(Flow5Tuple { proto, src, dst })
}

fn slice_sockaddr(rd: &mut &[u8]) -> Result<SocketAddr> {
    let tag = need(rd, 1)?[0];
    let ip = match tag {
        4 => {
            let b = need(rd, 4)?;
            IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
        }
        _ => {
            let b = need(rd, 16)?;
            let mut oct = [0u8; 16];
            oct.copy_from_slice(b);
            IpAddr::V6(Ipv6Addr::from(oct))
        }
    };
    let p = need(rd, 2)?;
    Ok(SocketAddr::new(ip, u16::from_be_bytes([p[0], p[1]])))
}

fn slice_opt_f64(rd: &mut &[u8]) -> Result<Option<f64>> {
    let flag = need(rd, 1)?[0];
    if flag == 0 {
        return Ok(None);
    }
    Ok(Some(slice_f64(rd)?))
}

fn slice_f64(rd: &mut &[u8]) -> Result<f64> {
    let b = need(rd, 8)?;
    Ok(f64::from_be_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

fn slice_opt_u8(rd: &mut &[u8]) -> Result<Option<u8>> {
    let flag = need(rd, 1)?[0];
    if flag == 0 {
        return Ok(None);
    }
    Ok(Some(need(rd, 1)?[0]))
}

fn slice_opt_u64(rd: &mut &[u8]) -> Result<Option<u64>> {
    let flag = need(rd, 1)?[0];
    if flag == 0 {
        return Ok(None);
    }
    slice_u64_field(rd).map(Some)
}

fn slice_opt_owned_string(rd: &mut &[u8]) -> Result<Option<String>> {
    let Some(len) = slice_varint(rd) else {
        anyhow::bail!("truncated optional string");
    };
    if len == 0 {
        return Ok(None);
    }
    let n = (len as usize).saturating_sub(1);
    let head = need(rd, n)?;
    Ok(Some(String::from_utf8_lossy(head).into_owned()))
}

fn slice_u64_field(rd: &mut &[u8]) -> Result<u64> {
    slice_varint(rd).ok_or_else(|| anyhow::anyhow!("truncated varint"))
}

/// Fields `stats` needs from a StreamSnap payload, with `call_id` borrowed.
pub(crate) struct StreamSnapLite<'a> {
    pub call_id: &'a str,
    pub ssrc: u32,
    /// None for summaries that predate 5-tuple logging.
    pub flow: Option<Flow5Tuple>,
    pub packets: u64,
    pub lost: u64,
    pub bytes: u64,
    pub jitter_ms: Option<f64>,
    pub mos: Option<f64>,
    pub rtt_avg_ms: Option<f64>,
}

pub(crate) fn parse_stream_snap_lite(mut rd: &[u8]) -> Result<StreamSnapLite<'_>> {
    let call_id = slice_str(&mut rd)?;
    let ssrc_b = need(&mut rd, 4)?;
    let ssrc = u32::from_be_bytes([ssrc_b[0], ssrc_b[1], ssrc_b[2], ssrc_b[3]]);
    let flow = slice_flow(&mut rd)?;
    skip_opt_string(&mut rd)?; // codec
    skip_opt_tagged(&mut rd, 1)?; // payload_type
    let packets = slice_u64_field(&mut rd)?;
    let lost = slice_u64_field(&mut rd)?;
    let _expected = slice_u64_field(&mut rd)?;
    let _loss_pct = need(&mut rd, 8)?;
    let jitter_ms = slice_opt_f64(&mut rd)?;
    let mos = slice_opt_f64(&mut rd)?;
    skip_opt_string(&mut rd)?; // direction
    if rd.is_empty() {
        return Ok(StreamSnapLite {
            call_id,
            ssrc,
            flow: Some(flow),
            packets,
            lost,
            bytes: 0,
            jitter_ms,
            mos,
            rtt_avg_ms: None,
        });
    }
    let bytes = slice_u64_field(&mut rd)?;
    skip_opt_varint(&mut rd)?; // first_ts_us
    skip_opt_varint(&mut rd)?; // last_ts_us
    skip_opt_tagged(&mut rd, 8)?; // rtt_min_ms
    let rtt_avg_ms = slice_opt_f64(&mut rd)?;
    Ok(StreamSnapLite {
        call_id,
        ssrc,
        flow: Some(flow),
        packets,
        lost,
        bytes,
        jitter_ms,
        mos,
        rtt_avg_ms,
    })
}

/// Full StreamSnap → `StreamSummary` for replay (one string alloc pass, no `Event`).
pub(crate) fn parse_stream_summary(mut rd: &[u8]) -> Result<StreamSummary> {
    let call_id = slice_str(&mut rd)?.to_owned();
    let ssrc_b = need(&mut rd, 4)?;
    let ssrc = u32::from_be_bytes([ssrc_b[0], ssrc_b[1], ssrc_b[2], ssrc_b[3]]);
    let flow = slice_flow(&mut rd)?;
    let codec = slice_opt_owned_string(&mut rd)?;
    let payload_type = slice_opt_u8(&mut rd)?;
    let packets = slice_u64_field(&mut rd)?;
    let lost = slice_u64_field(&mut rd)?;
    let expected = slice_u64_field(&mut rd)?;
    let loss_pct = slice_f64(&mut rd)?;
    let jitter_ms = slice_opt_f64(&mut rd)?;
    let mos = slice_opt_f64(&mut rd)?;
    let direction = slice_opt_owned_string(&mut rd)?;
    let (
        bytes,
        first_ts_us,
        last_ts_us,
        rtt_min_ms,
        rtt_avg_ms,
        rtt_max_ms,
        oneway_ms,
        leg,
        via_turn,
    ) = if rd.is_empty() {
        (0, None, None, None, None, None, None, None, false)
    } else {
        let bytes = slice_u64_field(&mut rd)?;
        let first_ts_us = slice_opt_u64(&mut rd)?;
        let last_ts_us = slice_opt_u64(&mut rd)?;
        let rtt_min_ms = slice_opt_f64(&mut rd)?;
        let rtt_avg_ms = slice_opt_f64(&mut rd)?;
        let rtt_max_ms = slice_opt_f64(&mut rd)?;
        let oneway_ms = slice_opt_f64(&mut rd)?;
        let leg = if rd.is_empty() {
            None
        } else {
            slice_opt_owned_string(&mut rd)?
        };
        let via_turn = if rd.is_empty() {
            false
        } else {
            need(&mut rd, 1)?[0] != 0
        };
        (
            bytes,
            first_ts_us,
            last_ts_us,
            rtt_min_ms,
            rtt_avg_ms,
            rtt_max_ms,
            oneway_ms,
            leg,
            via_turn,
        )
    };
    Ok(StreamSummary {
        call_id: Some(call_id),
        ssrc,
        flow: Some(flow),
        codec,
        payload_type,
        packets,
        lost,
        expected,
        loss_pct,
        jitter_ms,
        first_ts_us,
        last_ts_us,
        rtt_min_ms,
        rtt_avg_ms,
        rtt_max_ms,
        oneway_ms,
        mos,
        direction,
        leg,
        via_turn,
        bytes,
        history: Vec::new(),
    })
}

/// RTCP RTT sample only (skips call_id / ssrc).
pub(crate) fn parse_rtcp_rtt_ms(mut rd: &[u8]) -> Result<f64> {
    let _ = slice_str(&mut rd)?; // call_id
    if rd.len() < 4 + 8 {
        anyhow::bail!("truncated rtcp rtt");
    }
    rd = &rd[4..]; // ssrc
    Ok(f64::from_be_bytes([
        rd[0], rd[1], rd[2], rd[3], rd[4], rd[5], rd[6], rd[7],
    ]))
}

/// Sequential read buffer: large enough to cut syscalls on GB-scale logs,
/// small enough that `sipmon stats` cannot OOM from the file image itself.
const EVLOG_READ_BUF: usize = 1024 * 1024;

pub struct EvlogReader {
    r: BufReader<Box<dyn Read + Send>>,
    last_ts: u64,
    /// Reused across records so `stats` does not allocate a payload `Vec` per event.
    buf: Vec<u8>,
    /// UTC offset (seconds) of the machine that recorded the log. `None` for
    /// v1 files (offset was never stored) or unreadable headers.
    tz_offset_secs: Option<i32>,
}

impl EvlogReader {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let f = File::open(path.as_ref())
            .with_context(|| format!("open evlog {}", path.as_ref().display()))?;
        Self::new(f)
    }
}

impl EvlogReader {
    pub fn new(r: impl Read + Send + 'static) -> Result<Self> {
        let mut r = r;
        // Peek 4 bytes to detect/strip the file header.
        let mut head = [0u8; 4];
        let n = r.read(&mut head)?;
        let mut tz_offset_secs = None;
        let inner: Box<dyn Read + Send> = if n == 4 && &head == MAGIC {
            // Consume the remaining header bytes (version/flags/tz).
            let mut rest = [0u8; 8];
            let ok = r.read_exact(&mut rest).is_ok();
            if ok {
                let version = u16::from_be_bytes([rest[0], rest[1]]);
                if version >= 2 {
                    let tz = i32::from_be_bytes([rest[4], rest[5], rest[6], rest[7]]);
                    tz_offset_secs = Some(tz);
                }
            }
            Box::new(r)
        } else {
            Box::new(std::io::Cursor::new(head[..n].to_vec()).chain(r))
        };
        Ok(Self {
            r: BufReader::with_capacity(EVLOG_READ_BUF, inner),
            last_ts: 0,
            buf: Vec::new(),
            tz_offset_secs,
        })
    }

    /// UTC offset (seconds) of the recording machine, if the log carried one.
    pub fn tz_offset_secs(&self) -> Option<i32> {
        self.tz_offset_secs
    }

    /// Next record as `(type, ts_us, payload)`, borrowing a reused buffer.
    /// `None` at a clean EOF **or** a truncated last record (kill mid-write).
    pub(crate) fn next_raw(&mut self) -> Result<Option<(u8, u64, &[u8])>> {
        let delta = match read_varint(&mut self.r) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let ts_us = self.last_ts.saturating_add(delta);
        self.last_ts = ts_us;
        let mut ty = [0u8; 1];
        match self.r.read_exact(&mut ty) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let len = match read_varint(&mut self.r) {
            Ok(v) => v as usize,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if len > MAX_RECORD_LEN {
            anyhow::bail!("evlog record length {len} exceeds cap {MAX_RECORD_LEN} — corrupt file?");
        }
        self.buf.resize(len, 0);
        match self.r.read_exact(&mut self.buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        Ok(Some((ty[0], ts_us, &self.buf)))
    }

    pub fn next_event(&mut self) -> Result<Option<Event>> {
        loop {
            let Some((ty, ts_us, payload)) = self.next_raw()? else {
                return Ok(None);
            };
            match decode_payload(ty, ts_us, payload) {
                Ok(ev) => return Ok(Some(ev)),
                // Framed record whose body does not decode (truncated fields,
                // partial write). Skip and keep going so one bad record does
                // not abort replay/query/stats.
                Err(_) => continue,
            }
        }
    }
}

impl Iterator for EvlogReader {
    type Item = Result<Event>;
    fn next(&mut self) -> Option<Result<Event>> {
        match self.next_event() {
            Ok(Some(ev)) => Some(Ok(ev)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_basic() {
        let mut buf: Vec<u8> = Vec::new();
        let mut w = EvlogWriter::new(&mut buf).unwrap();
        w.write(&Event::SipMsg(SipMsgEvt {
            ts_us: 1_000_000,
            flow: Flow5Tuple {
                proto: Proto::Udp,
                src: "1.2.3.4:5060".parse().unwrap(),
                dst: "5.6.7.8:5060".parse().unwrap(),
            },
            is_request: true,
            method: Some("INVITE".into()),
            status: None,
            call_id: "abc@host".into(),
            cseq: Some(1),
            branch: Some("z9hG4bKx".into()),
            from_tag: Some("ft".into()),
            to_tag: None,
            raw: b"INVITE sip:bob@x SIP/2.0\r\n\r\n".to_vec(),
        }))
        .unwrap();
        w.write(&Event::RtcpRtt(RtcpRttEvt {
            ts_us: 1_500_000,
            call_id: "abc@host".into(),
            ssrc: 42,
            rtt_ms: 23.5,
            oneway_ms: Some(12.0),
        }))
        .unwrap();
        w.flush().unwrap();
        drop(w);

        let mut r = EvlogReader::new(std::io::Cursor::new(buf.clone())).unwrap();
        let e1 = r.next_event().unwrap().unwrap();
        let e2 = r.next_event().unwrap().unwrap();
        assert!(matches!(e1, Event::SipMsg(_)));
        assert!(matches!(e2, Event::RtcpRtt(_)));
        assert_eq!(e1.ts_us(), 1_000_000);
        assert_eq!(e2.ts_us(), 1_500_000);
        assert!(r.next_event().unwrap().is_none());

        let mut seen_rtt = false;
        walk_records(&buf, |ty, _ts, payload| {
            if ty == 5 {
                assert!((parse_rtcp_rtt_ms(payload)? - 23.5).abs() < 1e-9);
                seen_rtt = true;
            }
            Ok(())
        })
        .unwrap();
        assert!(seen_rtt);
    }

    #[test]
    fn stream_snap_lite_matches_full_decode() {
        let mut buf: Vec<u8> = Vec::new();
        let mut w = EvlogWriter::new(&mut buf).unwrap();
        w.write(&Event::StreamSnap(StreamSnapEvt {
            ts_us: 2_000_000,
            call_id: "cid-lite".into(),
            ssrc: 0xabcdef,
            flow: Flow5Tuple {
                proto: Proto::Udp,
                src: "10.0.0.1:4000".parse().unwrap(),
                dst: "10.0.0.2:4000".parse().unwrap(),
            },
            codec: Some("PCMU".into()),
            payload_type: Some(0),
            packets: 1234,
            lost: 5,
            expected: 1239,
            loss_pct: 0.4,
            jitter_ms: Some(1.5),
            mos: Some(4.2),
            direction: Some("up".into()),
            bytes: 99_000,
            first_ts_us: Some(1_000_000),
            last_ts_us: Some(2_000_000),
            rtt_min_ms: Some(10.0),
            rtt_avg_ms: Some(18.5),
            rtt_max_ms: Some(30.0),
            oneway_ms: Some(9.0),
            leg: Some("leg-a".into()),
            via_turn: true,
        }))
        .unwrap();
        w.flush().unwrap();
        drop(w);

        let mut n = 0;
        walk_records(&buf, |ty, ts, payload| {
            if ty != 4 {
                return Ok(());
            }
            n += 1;
            let lite = parse_stream_snap_lite(payload)?;
            match decode_payload(ty, ts, payload)? {
                Event::StreamSnap(e) => {
                    assert_eq!(lite.call_id, e.call_id);
                    assert_eq!(lite.ssrc, e.ssrc);
                    assert_eq!(lite.flow, Some(e.flow));
                    assert_eq!(lite.packets, e.packets);
                    assert_eq!(lite.lost, e.lost);
                    assert_eq!(lite.bytes, e.bytes);
                    assert_eq!(lite.jitter_ms, e.jitter_ms);
                    assert_eq!(lite.mos, e.mos);
                    assert_eq!(lite.rtt_avg_ms, e.rtt_avg_ms);
                    let sum = parse_stream_summary(payload)?;
                    assert_eq!(sum.call_id.as_deref(), Some(e.call_id.as_str()));
                    assert_eq!(sum.ssrc, e.ssrc);
                    assert_eq!(sum.flow, Some(e.flow));
                    assert_eq!(sum.codec, e.codec);
                    assert_eq!(sum.payload_type, e.payload_type);
                    assert_eq!(sum.packets, e.packets);
                    assert_eq!(sum.lost, e.lost);
                    assert_eq!(sum.expected, e.expected);
                    assert_eq!(sum.bytes, e.bytes);
                    assert_eq!(sum.direction, e.direction);
                    assert_eq!(sum.leg, e.leg);
                    assert_eq!(sum.via_turn, e.via_turn);
                    assert_eq!(sum.rtt_avg_ms, e.rtt_avg_ms);
                }
                other => panic!("expected StreamSnap, got {other:?}"),
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn truncated_tail_is_eof_not_error() {
        let mut buf: Vec<u8> = Vec::new();
        let mut w = EvlogWriter::new(&mut buf).unwrap();
        w.write(&Event::RtcpRtt(RtcpRttEvt {
            ts_us: 1_000_000,
            call_id: "abc@host".into(),
            ssrc: 42,
            rtt_ms: 23.5,
            oneway_ms: None,
        }))
        .unwrap();
        w.write(&Event::RtcpRtt(RtcpRttEvt {
            ts_us: 2_000_000,
            call_id: "abc@host".into(),
            ssrc: 42,
            rtt_ms: 24.0,
            oneway_ms: None,
        }))
        .unwrap();
        w.flush().unwrap();
        drop(w);

        let mut r = EvlogReader::new(std::io::Cursor::new(buf.clone())).unwrap();
        assert!(r.next_event().unwrap().is_some());
        assert!(r.next_event().unwrap().is_some());
        assert!(r.next_event().unwrap().is_none());

        let cut = buf.len().saturating_sub(9);
        let mut r = EvlogReader::new(std::io::Cursor::new(buf[..cut].to_vec())).unwrap();
        let first = r.next_event().unwrap();
        assert!(first.is_some(), "first complete record must survive");
        assert!(
            r.next_event().unwrap().is_none(),
            "truncated last record must be ignored, not Err"
        );
    }
}

# sipmon

A passive SIP/RTP signaling and media quality monitoring tool. A standalone Rust
executable deployed on a mirrored port / packet capture box, **with no dependency
on a running PBX**. Inputs may be a live capture, a pcap file, a stdin stream, or a
previously recorded event log; output is a live TUI monitor plus exportable
analysis results (JSONL).

![sipmon call detail](call_detail.png)

![sipmon sip stats](sip_stats.png)

![sipmon rtp stats](rtp_stats.png)


## Features

- **Inputs**: live interface (libpcap + BPF), offline pcap/pcapng, stdin `tcpdump -w -` stream, event-log replay
- **Modes**: `live` interactive monitoring / `record` recording with live TUI (`--headless` = no UI, `-d` daemonizable) / `replay`
- **SIP correlation**: Call-ID call state machine, transactions, Call-ID / number / IP / SSRC indexes, SIP-over-TCP reassembly
- **Media quality**: RFC3550 jitter/loss, RTCP RR RTT, one-way delay estimate, E-model MOS
- **TURN detection**: auto-learns TURN servers, labels `turn-client` / `turn-peer` relay legs
- **Diagnostics**: 20+ rules for Contact reachability, Record-Route, SDP/RTP consistency, one-way media, TURN allocation/refresh
- **TUI**: Overview / Call Detail / SIP Stats / Streams / Event Log / IP Stats pages
- **Analysis**: PDD/setup/ring timing, hangup initiator (BYE, CANCEL, reject), per-IP loss over 1s…1h windows
- **Export**: JSONL on exit or via `export`; `query` fetches a Call-ID flow for scripting

## Quick start

```sh
sipmon live -i any                 # live monitoring (TUI); quit prints a stats report
sipmon live -i eth0 -f "udp port 5060"   # with a BPF filter
sipmon record -i any -w cap.evlog --headless   # record to an event log
sipmon record -i any -w cap.evlog -d --pidfile /run/sipmon.pid --logfile /var/log/sipmon.log
sipmon replay cap.evlog            # replay a recording (TUI)
sipmon stats cap.evlog             # ASR, traffic, 5-minute call-availability + network tables
sipmon file -r capture.pcap        # offline pcap analysis
sipmon capture.pcap                # default mode: dispatch by extension
sipmon cap.evlog                   #   *.pcap/.pcapng → file, *.evlog → replay, *.jsonl → snapshot view
sipmon out.jsonl
tcpdump -i eth0 -w - | sipmon -    # read a live tcpdump stream
```

## Capturing rtpengine (kernel-forwarded) media

With rtpengine's kernel forwarding enabled (`xt_RTPENGINE`), RTP is rewritten and
forwarded inside netfilter — rtpengine's own sockets only see the first
packet(s) of each flow and RTCP. Capturing **on the sockets** is therefore not
an option, but the packets still traverse the NIC and the kernel input/output
paths, so **passive capture works unchanged**: AF_PACKET (`sipmon live -i any`)
and switch mirror ports both see the two legs of every stream — the original
ingress (A → rtpengine:port) and the rewritten egress (rtpengine:port → B).
sipmon models rtpengine as a media relay: the SDP advertises rtpengine's media
endpoints, so both legs correlate to the same Call-ID (two directed streams per
call; SSRC is preserved end-to-end unless transcoding is enabled, in which case
each leg appears as its own stream).

**Topology 1 — Kamailio + rtpengine on the same host:**

```sh
sudo sipmon live -i any -f "udp portrange 30000-40000 or udp port 5060"
```

Adjust `30000-40000` to the `port-min`/`port-max` of your `rtpengine.conf`. The
BPF pre-filter is strongly recommended on a shared host — it keeps the capture
out of control-plane traffic and cuts CPU.

**Topology 2 — Kamailio on a separate host:** sipmon correlates RTP to calls
via SIP/SDP, so SIP must reach the same capture. Mirror Kamailio's SIP onto a
spare NIC of the rtpengine host (a SPAN destination port with no IP configured
is fine) and keep `live -i any` — local RTP and mirrored SIP then feed the same
correlator.

**Before going live**, verify both legs are observable on your kernel/driver:

```sh
sudo tools/check-rtp-capture.sh                 # 15s capture + leg analysis
sipmon file -r /tmp/rtp-check.pcap              # offline correlation check
```

Acceptance: calls appear on the Overview page, each call shows two directed RTP
streams on the Streams page, and RTCP-derived RTT is populated. If the script
reports the rewritten egress leg missing (exit 1), capture via a switch mirror
port instead — mirroring is unaffected by the kernel forwarding path.

Caveats: on a busy relay the capture process competes with rtpengine for CPU
(prefilter hard, or mirror to a dedicated box at high packet rates — see the
performance notes in `docs/`); with transcoding enabled rtpengine rewrites the
SSRC per leg, so quality views split per leg (expected for a transcoder).

## Commands

| Command | Description |
|---|---|
| `(none)` | Default mode: positional `FILE` dispatched by extension (`.pcap/.pcapng` → `file`, `.evlog` → `replay`, `.jsonl` → snapshot view); no FILE starts a live capture. `--no-tui` for headless output |
| `live` | Live capture + TUI. `-i` interface, `-f` BPF filter, `--no-media` disables RTP/RTCP analysis, `-w` also writes an event log. On quit, prints the same ASR/traffic/5-minute report as `stats` (from in-memory events, not the TTL-trimmed call table) |
| `record` | Live capture → event log (`-w` required). Live TUI on a tty; `--headless` disables it. `-d` daemonizes, `--pidfile`/`--logfile` for daemon runs. Flushes gracefully on SIGTERM/SIGINT. Headless/`-d` drops completed calls from RAM immediately (they are already in the evlog); live TUI keeps them for `--call-ttl-mins` |
| `-` | Read a pcap byte stream from stdin |
| `file` | Offline pcap/pcapng. `--rate 1x` replay speed multiplier, `--no-tui`, `--print-events` |
| `replay` | Replay an event log (`sipmon replay FILE`; `-l/--evlog` still works). TUI / `--no-tui` |
| `query` | No TUI; exports flow + stream stats + RTT + diagnostics for a Call-ID (script friendly) |
| `stats` | No TUI; ASR / CCR / NER / PDD / ACD, fail split (NF/REJ/BUSY/TMO/FAIL), RTP+SIP traffic, MOS/jitter/RTT, top-50 IP loss table, and 5-minute call-availability + network windows (`sipmon stats FILE`, `--json`, `--top N`) |
| `export` | Rebuild a snapshot from an event log → JSONL, with `--from/--to` time filtering |

### Common options

```
--dry-run            In-memory analysis only, writes no files
--max-calls N        Max calls retained in memory (default 100000)
--call-ttl-mins N    Drop idle/terminated calls after N minutes (default 15;
                     0 = keep until --max-calls). File/replay ignore this.
--max-streams N      RTP stream ring cap (default 50000)
--max-diagnostics N  Diagnostics ring cap (default 50000)
--diag-level X       info|warn|critical (default warn)
--turn-servers IP,…  TURN server IP list (auto-learning also supported)
--local-ips IP,…     Local (monitored) machine IPs: Call Detail flow/media pin
                     the local endpoint to the right with ingress/egress arrows
                     (default: this host's own interface addresses)
--raw-truncate N     Truncate stored raw SIP messages to N bytes
--bucket 15m|1h|1d   Heatmap bucket granularity (default 15m)
-w/--evlog PATH      Write the binary event log to PATH
--export-jsonl PATH  Export JSONL on exit
```

## TUI

Pages: **Overview** `1` · **Call Detail** `2` · **SIP Stats** `3` · **Streams** `4` · **Event Log** `5` · **IP Stats** `6`. `Tab`/`Shift-Tab` cycles pages, `Space` pauses, `e` exports JSONL, `p` toggles privacy masking, `x` clears in-memory stats, `q`/`Esc`/`Ctrl-C` quits. Quitting a TUI session prints the full in-memory stats report (same output as `sipmon stats`, 5-minute windows).

The Overview page carries a rule-based filter bar (`/` to edit, `c` to clear): tokens `ip:1.2.3.4[:port]`, `caller:1001`, `callee:2002`, `callid:abc` are AND-ed together (a bare word matches any field; a full IP matches exactly, a partial one as a substring). While typing, the list filters live (`↑`/`↓` select, `Enter` applies, `Esc` rolls back, `Ctrl-U` clears the input); matching calls are also pinned in the pipeline so they survive TTL/capacity eviction. The state filter `f` (all/dialing/ringing/active/success/failed/canceled) ANDs with the rule filter.

Call Detail uses a fixed four-pane layout: **Flow** (sngrep-style swimlane, `↑`/`↓` selects) · **Raw** (syntax-highlighted bytes of the selected message, `PgUp`/`PgDn` scrolls) · **Diagnostics** · **Network** (traffic totals + per-stream media table). Flow headers are `ip:port` columns with a vertical bar under each party; rows are `Time | -- INVITE ->` / `<- 100 --` (short centered arrows; responses show the status code only). Same-Call-ID dual dialogs (or a manually linked b-leg via `l`) expand to three parties. `L` unlinks the b-leg.

IP Stats aggregates per-IP conditions, split by direction (**TX** = sent by the IP, **RX** = received): `c` collapses to a loss-only summary, `w` cycles the time window, `s` sorts, `Enter` drills down to the calls involving an IP.

SIP Stats shows the signaling health per endpoint IP: a request/response distribution table (`INVITE ACK BYE CANCEL OPTION INFO REGISTER MESSAGE oth | 100 180 183 200 486 404 403 408 480 487 3xx 4xx 5xx 6xx oth`) and an INVITE answer-rate heatmap (1m/5m/15m buckets via `w`, `s` sorts). Heatmap colors are relative to the window's global ASR baseline — cyan within ±10pp, green ≥ +10pp, orange −25pp, red below — so a naturally low-ASR route (e.g. 40% outbound) stays neutral and only real degradation turns red; cells with fewer than 3 invites are dimmed.

## Event log format

Private binary append-only format. Header holds the `SMON` magic, version, and timezone; records are `ts_delta | ev_type | len | payload`. Event types: `1` SipMsgEvt, `2` TxnEvt, `3` CallEvt, `4` StreamSnapEvt (every 5s), `5` RtcpRttEvt, `6` HealthBucketEvt, `7` ErrorEvt, `8` DiagEvt.

**No raw RTP payload is stored** — only the summaries needed to rebuild the analysis, plus truncated raw SIP messages (`--raw-truncate` controls the cap). `record` always writes to disk; `live` needs an explicit `-w`.

## Diagnostic codes

| Code | Meaning |
|---|---|
| `CONTACT_UNREACHABLE` / `CONTACT_PRIVATE_NAT` / `CONTACT_MCAST` | Contact address unreachable, private NAT, or multicast |
| `RR_NOT_HONORED` / `RR_DEPTH_MISMATCH` | Record-Route not honored / depth mismatch |
| `SDP_HOLD` | SDP carries hold (`sendonly`/`inactive`) |
| `RTP_PT_MISMATCH` / `RTP_PT_CHANGED` / `RTP_FLOW_UNEXPECTED` | Payload type mismatch / changed mid-call / RTP flow disagrees with SDP |
| `ONE_WAY_MEDIA` | One-way media (only receiving, not sending) |
| `TURN_ALLOC_OK` / `TURN_ALLOC_FAILED` / `TURN_REFRESH_FAILED` | TURN allocation succeeded / failed / refresh failed |
| `TURN_RELAY_MEDIA` / `TURN_CHANNEL_MEDIA` / `TURN_SEND_IND_MEDIA` | Media relayed via TURN Relay / ChannelData / Send-Ind |
| `TURN_LEG_IMBALANCE` | TURN leg packet imbalance (suspected one-way) |

## Metric definitions

- **RTT**: `RTT = arrival_NTP − LSR − DLSR` from the RTCP RR
- **One-way delay**: RTCP SR NTP↔RTP mapping (when both directions are visible); otherwise an indirect estimate from RTP arrival intervals (labeled "estimate")
- **jitter/loss**: RFC3550, 64-packet reorder window; `|D| > 1s` is treated as a timestamp jump (hold/DTX/reset), not jitter. `stats` reports packet-weighted p50/p95 (SDP `a=rtpmap` clock when known)
- **MOS**: simplified E-model (G.107): `R = 93.2 − Id − Ie`, labeled "estimate"

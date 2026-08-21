#!/usr/bin/env bash
# Pre-flight check: are RTP flows forwarded by rtpengine in KERNEL mode
# (xt_RTPENGINE) visible to a passive on-host capture?
#
# Kernel forwarding moves the packet rewrite from userspace into netfilter:
# rtpengine's UDP sockets no longer receive the RTP (only the first packet(s)
# of each flow and RTCP). The packets still traverse the NIC and the kernel
# input/output paths, so AF_PACKET (tcpdump / `sipmon live -i any`) sees BOTH
# legs of each stream:
#   ingress  A -> <local-ip>:<media-port>    (original packet)
#   egress   <local-ip>:<media-port> -> B    (rewritten, sent by the kernel)
# This script captures briefly, verifies both directions are observable, and
# prints the sipmon command line to use.
#
# Usage:
#   tools/check-rtp-capture.sh [--iface any] [--ports MIN-MAX] [--duration 15]
#                              [--conf /etc/rtpengine/rtpengine.conf]
#                              [--out /tmp/rtp-check.pcap]
#
# Exit codes:
#   0  both legs visible — on-host capture is good to go
#   1  egress (or ingress) not visible — fall back to a switch mirror port
#   2  no media traffic captured — check port range / place a call
#   64 usage / preflight error
set -euo pipefail

IFACE=any
DURATION=15
CONF=/etc/rtpengine/rtpengine.conf
OUT=/tmp/rtp-check.pcap
PORTS=""

usage() {
  sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --iface)    IFACE="$2";    shift 2 ;;
    --ports)    PORTS="$2";    shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --conf)     CONF="$2";     shift 2 ;;
    --out)      OUT="$2";      shift 2 ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "error: unknown option: $1" >&2; usage >&2; exit 64 ;;
  esac
done

# ----------------------------- preflight -----------------------------
if [[ "$(id -u)" -ne 0 ]]; then
  echo "error: must run as root (raw capture on '$IFACE' needs CAP_NET_RAW)" >&2
  exit 64
fi
for bin in tcpdump timeout; do
  command -v "$bin" >/dev/null 2>&1 || { echo "error: $bin not found on PATH" >&2; exit 64; }
done

# Media port range: --ports wins; else read port-min/port-max from the
# rtpengine config (tolerates `key = value` spacing variants); else default.
if [[ -z "$PORTS" ]]; then
  read -r PMIN PMAX < <(
    awk -F= '
      /^[[:space:]]*port-min[[:space:]]*=/ { gsub(/[[:space:]]/, "", $2); print $2 }
      /^[[:space:]]*port-max[[:space:]]*=/ { gsub(/[[:space:]]/, "", $2); print $2 }
    ' "$CONF" 2>/dev/null | paste -sd ' ' - || true
  )
  if [[ "${PMIN:-}" =~ ^[0-9]+$ && "${PMAX:-}" =~ ^[0-9]+$ ]]; then
    PORTS="$PMIN-$PMAX"
    echo ">> media port range $PORTS (from $CONF)"
  else
    PORTS="30000-40000"
    echo ">> media port range $PORTS (default: no port-min/port-max in $CONF)"
  fi
else
  echo ">> media port range $PORTS (--ports)"
fi

# Global-scope local IPs, used to tell the rewritten egress leg apart.
if command -v ip >/dev/null 2>&1; then
  LOCAL_IPS="$(ip -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1)"
else
  LOCAL_IPS="$(hostname -I 2>/dev/null || true)"
fi
[[ -n "$LOCAL_IPS" ]] || { echo "error: cannot determine local IP addresses" >&2; exit 64; }
echo ">> local IPs: $(echo "$LOCAL_IPS" | tr '\n' ' ')"

# ----------------------------- capture -----------------------------
echo ">> capturing ${DURATION}s on $IFACE (udp portrange $PORTS) — place an active call now ..."
rm -f "$OUT"
# SIGINT is tcpdump's clean stop; ignore its timeout exit status (124).
timeout --signal=INT --kill-after=5 "$DURATION" \
  tcpdump -i "$IFACE" -U -nn -w "$OUT" "udp portrange $PORTS" 2>/dev/null || true
[[ -s "$OUT" ]] || {
  echo "RESULT: no packets captured in the media port range."
  echo "        check the port range (--ports) and that a call is in progress."
  exit 2
}

# ----------------------------- analysis -----------------------------
count() { tcpdump -nn -r "$OUT" "$1" 2>/dev/null | wc -l | tr -d ' '; }

TOTAL=$(count "udp portrange $PORTS")
# RTP version nibble check: first payload byte's top two bits == 2.
RTPISH=$(count "udp portrange $PORTS and (udp[8] & 0xc0) = 0x80")

INGRESS=0
EGRESS=0
for ip in $LOCAL_IPS; do
  INGRESS=$((INGRESS + $(count "dst host $ip and udp dst portrange $PORTS")))
  EGRESS=$((EGRESS + $(count "src host $ip and udp src portrange $PORTS")))
done

cat <<EOF
>> total media-range packets : $TOTAL
>> RTP-like (v=2 payload)    : $RTPISH
>> ingress (dst = this host) : $INGRESS
>> egress  (src = this host) : $EGRESS   <- kernel-forwarded, rewritten leg
>> pcap kept at: $OUT (verify with: sipmon file -r $OUT)
EOF

if (( INGRESS > 0 && EGRESS > 0 )); then
  cat <<EOF
RESULT: OK — both legs visible. Kernel forwarding does not hide media
        from AF_PACKET; on-host passive capture works.

Suggested command:
  sudo sipmon live -i $IFACE --filter "udp portrange $PORTS or udp port 5060"

Note: sipmon correlates RTP to calls via SIP/SDP. Make sure SIP is visible
too (Kamailio on this host, or its SIP mirrored onto an interface here) —
see the "Capturing rtpengine" section in the README.
EOF
  exit 0
fi

if (( TOTAL > 0 )); then
  echo "RESULT: PARTIAL — media traffic seen but not both directions"
  (( EGRESS == 0 )) && echo "        (egress missing: rewritten packets not visible on this kernel/driver)."
  (( INGRESS == 0 )) && echo "        (ingress missing: unexpected — check local IP detection)."
  echo "        Recommendation: capture via a switch mirror port instead, which is"
  echo "        unaffected by the kernel forwarding path."
  exit 1
fi

echo "RESULT: no analyzable traffic — see notes above."
exit 2

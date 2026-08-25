#!/usr/bin/env bash
# Build a static musl release of sipmon, linking against a musl-built libpcap.
#
# The musl target cannot link against the glibc libpcap in /usr/lib (it pulls in
# __snprintf_chk/__longjmp_chk/dbus, none of which exist in musl), so we first
# build a static musl libpcap and point the pcap crate at it via LIBPCAP_LIBDIR.
#
# Usage:
#   tools/build-musl.sh              # build musl libpcap if needed, then cargo build
#   LIBPCAP_LIBDIR=/path cargo ...   # skip libpcap step, use a prebuilt one
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${TARGET:-x86_64-unknown-linux-musl}"
PCAP_VERSION="${PCAP_VERSION:-1.10.5}"

# Cache dir for a locally-built musl libpcap. Override with MUSL_PCAP_DIR.
MUSL_PCAP_DIR="${MUSL_PCAP_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/sipmon/muspcap}"

if [[ -z "${LIBPCAP_LIBDIR:-}" ]]; then
  if [[ ! -f "$MUSL_PCAP_DIR/install/lib/libpcap.a" ]]; then
    if ! command -v musl-gcc >/dev/null 2>&1; then
      echo "error: musl-gcc not found (install musl-tools)" >&2
      exit 1
    fi
    echo ">> building musl libpcap $PCAP_VERSION ..."
    mkdir -p "$MUSL_PCAP_DIR"
    if [[ ! -f "$MUSL_PCAP_DIR/libpcap.tar.gz" ]]; then
      curl -fsSL "https://www.tcpdump.org/release/libpcap-$PCAP_VERSION.tar.gz" \
        -o "$MUSL_PCAP_DIR/libpcap.tar.gz"
    fi
    tar -xzf "$MUSL_PCAP_DIR/libpcap.tar.gz" -C "$MUSL_PCAP_DIR"
    (
      cd "$MUSL_PCAP_DIR/libpcap-$PCAP_VERSION"
      ./configure --host=x86_64-unknown-linux-musl --disable-shared --enable-static \
        --prefix="$MUSL_PCAP_DIR/install" --without-libnl CC=musl-gcc
      make -j"$(nproc)"
      make install
    )
  fi
  export LIBPCAP_LIBDIR="$MUSL_PCAP_DIR/install/lib"
fi

echo ">> LIBPCAP_LIBDIR=$LIBPCAP_LIBDIR"
cd "$ROOT"
exec cargo build --release --target "$TARGET" "$@"

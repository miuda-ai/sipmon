#!/usr/bin/env bash
# Cross-build a static libpcap for a Zig target using `zig cc`, so sipmon can
# be cross-compiled with `cargo zigbuild` from a single host (e.g. macOS)
# without a native cross toolchain (musl-tools / multilib). Mirrors the
# libpcap dance in tools/build-musl.sh but swaps `musl-gcc` for
# `zig cc -target <zig-target>`.
#
# Why a separate build: the `pcap` crate links libpcap, a C library. Zig ships
# the libc (glibc/musl) but NOT libpcap, so libpcap must be built per target
# with the same `zig cc` so its objects match the target ABI, then handed to the
# crate via LIBPCAP_LIBDIR.
#
# Usage:
#   tools/build-pcap-zig.sh <zig-target> <host-triple> [pcap-version]
#   e.g. tools/build-pcap-zig.sh x86_64-linux-musl x86_64-linux-musl
#        tools/build-pcap-zig.sh aarch64-linux-musl aarch64-linux-musl
#        tools/build-pcap-zig.sh x86_64-linux-gnu  x86_64-unknown-linux-gnu
#
# Cache: results land in $XDG_CACHE_HOME/sipmon/pcap-zig/<zig-target>/ (override
# with PCAP_ZIG_DIR). Re-runs are instant once libpcap.a exists.
#
# Stdout: the lib dir to pass as LIBPCAP_LIBDIR (final line).
set -euo pipefail

ZIG_TARGET="${1:?usage: build-pcap-zig.sh <zig-target> <host-triple> [version]}"
HOST_TRIPLE="${2:?missing host-triple (e.g. x86_64-linux-musl)}"
PCAP_VERSION="${3:-1.10.5}"

command -v zig >/dev/null 2>&1 || { echo "error: zig not found on PATH" >&2; exit 1; }

CACHE="${PCAP_ZIG_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/sipmon/pcap-zig}"
WORK="$CACHE/$ZIG_TARGET"
PREFIX="$WORK/install"
LIBDIR="$PREFIX/lib"

if [[ -f "$LIBDIR/libpcap.a" && -f "$LIBDIR/libpcap.so" ]]; then
  echo ">> cached libpcap ($ZIG_TARGET) at $LIBDIR" >&2
  echo "$LIBDIR"
  exit 0
fi

echo ">> building libpcap $PCAP_VERSION for $ZIG_TARGET (zig cc) ..." >&2
mkdir -p "$WORK"

TARBALL="$WORK/libpcap-$PCAP_VERSION.tar.gz"
SRC="$WORK/libpcap-$PCAP_VERSION"
if [[ ! -d "$SRC" ]]; then
  # Preferred source: the tcpdump.org release tarball (ships a pre-generated
  # configure, so no autotools needed). When it is unreachable — e.g. on some
  # CI runners behind CDNs — fall back to a github clone + autoreconf
  # (requires autoconf/automake/libtool on the host).
  if [[ -f "$TARBALL" ]] || curl -fsSL --retry 3 --retry-delay 5 \
      "${PCAP_URL:-https://www.tcpdump.org/release/libpcap-$PCAP_VERSION.tar.gz}" \
      -o "$TARBALL"; then
    rm -rf "$SRC"
    tar -xzf "$TARBALL" -C "$WORK"
  else
    echo ">> tcpdump.org unreachable — cloning libpcap from github + autoreconf" >&2
    rm -f "$TARBALL"
    git clone --depth 1 --branch "libpcap-$PCAP_VERSION" \
      https://github.com/the-tcpdump-group/libpcap "$SRC"
    (cd "$SRC" && autoreconf -i)
  fi
fi

# nproc is Linux-only; sysctl -n hw.ncpu covers macOS/BSD.
JOBS="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)"

# Use Zig's own `ar`/`ranlib` (LLVM-backed, universal across ELF/Mach-O/COFF).
# The macOS system `ar`/`ranlib` are BSD and only handle Mach-O, so archiving
# zig-compiled Linux ELF objects with them yields an empty/broken libpcap.a.
AR_BIN="zig ar"
RANLIB_BIN="zig ranlib"

(
  cd "$SRC"
  # --host != build puts configure in cross-compile mode (compile-only tests).
  # --with-pcap=linux pins the capture backend (configure can't run probes).
  # The --disable-* flags mirror the release CI so optional deps (dbus,
  # bluetooth, usb, dag, ...) don't leak in and break the static link.
  # Both .a and .so are built: the musl (+crt-static) link resolves the .a,
  # while gnu targets put `-lpcap` in the dynamic group and zig's linker
  # refuses to fall back to the archive ("strategy no_fallback") — it needs
  # the .so at link time. The .so's SONAME (libpcap.so.1) is then satisfied
  # by the target host's system libpcap at runtime, same mechanism as zig's
  # bundled glibc stub libraries.
  CC="zig cc -target $ZIG_TARGET" AR="$AR_BIN" RANLIB="$RANLIB_BIN" ./configure \
    --host="$HOST_TRIPLE" \
    --without-libnl --disable-dbus --disable-bluetooth --disable-usb \
    --disable-manual --without-dag --without-septel --without-snf \
    --disable-rdma --disable-srp \
    --with-pcap=linux \
    --prefix="$PREFIX"
  make -j"$JOBS"
  make install
)

echo "$LIBDIR"

# Makefile — cross-compile sipmon with `cargo zigbuild` (Zig as the C/linker
# toolchain), from a single host (e.g. macOS) to many targets, no musl-tools /
# multilib needed. libpcap (the one C dependency) is cross-built per target
# with `zig cc` by tools/build-pcap-zig.sh and handed to the pcap crate via
# LIBPCAP_LIBDIR.
#
# Prerequisites (install once):
#   brew install zig                  # Zig 0.13+ (bundled glibc/musl/SDK glue)
#   cargo install cargo-zigbuild      # the cargo subcommand
#   rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl \
#     x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
#   # macOS universal needs no extra target (cargo-zigbuild synthesizes it).
#
# Usage:
#   make help            # list targets
#   make musl-x86_64     # portable static Linux/x86_64 (matches release CI)
#   make musl-aarch64    # portable static Linux/ARM64
#   make all             # all portable static targets (musl x86_64 + aarch64)
#   make dist            # all + package each binary as sipmon-<target>
#
# Re-runs are cheap: the cross libpcap is cached per target
# ($XDG_CACHE_HOME/sipmon/pcap-zig/<zig-target>/) and cargo's target/ is reused.

ZIG           ?= zig
CARGO         ?= cargo
PCAP_VERSION  ?= 1.10.5
BIN           := sipmon
TARGET_DIR    := target

# musl targets are linked fully static (+crt-static); gnu/glibc targets are
# dynamically linked (interpreter + libc.so.6 + libpcap.so.1 from the target
# host at runtime — the zig-built libpcap.so is only used at link time).
MUSL_RUSTFLAGS := -C target-feature=+crt-static

.PHONY: help all dist prereqs \
        musl-x86_64 musl-aarch64 gnu-x86_64 gnu-aarch64 macos-universal \
        clean clean-cache

help: ## Show this help.
	@grep -E '^[a-zA-Z][a-zA-Z0-9_-]*:.*##' $(MAKEFILE_LIST) | \
	  awk -F':.*##' '{ printf "  %-20s %s\n", $$1, $$2 }'

prereqs: ## Check that zig + cargo-zigbuild are installed.
	@command -v $(ZIG) >/dev/null 2>&1 || { \
	  echo "error: zig not found — run 'brew install zig'"; exit 1; }
	@$(CARGO) zigbuild --help >/dev/null 2>&1 || { \
	  echo "error: cargo-zigbuild not found — run 'cargo install cargo-zigbuild'"; exit 1; }
	@echo ">> zig and cargo-zigbuild OK"

# ── Linux targets: cross-build libpcap with zig, then cargo zigbuild ──────
# build_linux <rust-target> <zig-target> <host-triple> <rustflags>
define build_linux
LIBDIR=$$(tools/build-pcap-zig.sh $(2) $(3) $(PCAP_VERSION) | tail -1); \
echo ">> LIBPCAP_LIBDIR=$$LIBDIR"; \
LIBPCAP_LIBDIR="$$LIBDIR" LIBPCAP_VER="$(PCAP_VERSION)" \
  RUSTFLAGS="$(4)" $(CARGO) zigbuild --release --target $(1); \
echo ">> $(1):"; file $(TARGET_DIR)/$(1)/release/$(BIN)
endef

musl-x86_64: ## Portable static Linux/x86_64 (matches the release CI artifact).
	$(call build_linux,x86_64-unknown-linux-musl,x86_64-linux-musl,x86_64-linux-musl,$(MUSL_RUSTFLAGS))

musl-aarch64: ## Portable static Linux/ARM64.
	$(call build_linux,aarch64-unknown-linux-musl,aarch64-linux-musl,aarch64-linux-musl,$(MUSL_RUSTFLAGS))

gnu-x86_64: ## Linux/x86_64 glibc (dynamically linked, needs a glibc host).
	$(call build_linux,x86_64-unknown-linux-gnu,x86_64-linux-gnu,x86_64-unknown-linux-gnu,)

gnu-aarch64: ## Linux/ARM64 glibc (dynamically linked, needs a glibc host).
	$(call build_linux,aarch64-unknown-linux-gnu,aarch64-linux-gnu,aarch64-linux-gnu,)

macos-universal: ## macOS universal2 (x86_64 + aarch64) via the macOS SDK.
	$(CARGO) zigbuild --release --target universal2-apple-darwin
	@echo ">> universal2-apple-darwin:"; file $(TARGET_DIR)/universal2-apple-darwin/release/$(BIN)

# ── Aggregate ─────────────────────────────────────────────────────────────
all: musl-x86_64 musl-aarch64 ## Build all portable static targets.

dist: all ## Build `all` and package each as sipmon-<target> + SHA256SUMS.
	@set -e; for t in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do \
	  d=$(TARGET_DIR)/$$t/release; \
	  cp $$d/$(BIN) $$d/$(BIN)-$$t; \
	  shasum -a 256 $$d/$(BIN)-$$t; \
	done | tee $(TARGET_DIR)/SHA256SUMS
	@echo ">> packaged: $$(grep -c sipmon $(TARGET_DIR)/SHA256SUMS) binaries"

clean: ## `cargo clean` (remove all build artifacts).
	$(CARGO) clean

clean-cache: ## Remove the cached cross libpcap builds (forces a rebuild).
	rm -rf "$${XDG_CACHE_HOME:-$$HOME/.cache}/sipmon/pcap-zig"

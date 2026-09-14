#!/bin/sh

set -eu

REPOSITORY="miuda-ai/sipmon"
INSTALL_DIR="${SIPMON_INSTALL_DIR:-/usr/local/bin}"
VERSION="${SIPMON_VERSION:-latest}"

info() {
    printf '%s\n' "sipmon installer: $*"
}

fail() {
    printf '%s\n' "sipmon installer: error: $*" >&2
    exit 1
}

command -v uname >/dev/null 2>&1 || fail "uname is required"
command -v mktemp >/dev/null 2>&1 || fail "mktemp is required"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required"
command -v install >/dev/null 2>&1 || fail "install is required"

case "$(uname -s)" in
    Linux) ;;
    *) fail "only Linux is currently supported by the prebuilt binaries" ;;
esac

case "$(uname -m)" in
    x86_64|amd64)
        TARGET="x86_64-unknown-linux-musl"
        ;;
    aarch64|arm64)
        TARGET="aarch64-unknown-linux-musl"
        ;;
    *)
        fail "unsupported CPU architecture: $(uname -m)"
        ;;
esac

if command -v curl >/dev/null 2>&1; then
    download() {
        curl --fail --location --silent --show-error --retry 3 \
            --output "$2" "$1"
    }
elif command -v wget >/dev/null 2>&1; then
    download() {
        wget --quiet --output-document="$2" "$1"
    }
else
    fail "curl or wget is required"
fi

if [ "$VERSION" = "latest" ]; then
    RELEASE_URL="https://github.com/${REPOSITORY}/releases/latest/download"
else
    case "$VERSION" in
        v*) ;;
        *) VERSION="v${VERSION}" ;;
    esac
    RELEASE_URL="https://github.com/${REPOSITORY}/releases/download/${VERSION}"
fi

ASSET="sipmon-${TARGET}"
TMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t sipmon)
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup 0 HUP INT TERM

info "downloading ${ASSET} (${VERSION})"
download "${RELEASE_URL}/${ASSET}" "${TMP_DIR}/${ASSET}"
download "${RELEASE_URL}/${ASSET}.sha256" "${TMP_DIR}/${ASSET}.sha256"

info "verifying SHA256 checksum"
(
    cd "$TMP_DIR"
    sha256sum -c "${ASSET}.sha256"
)

if { [ -d "$INSTALL_DIR" ] || mkdir -p "$INSTALL_DIR" 2>/dev/null; } && [ -w "$INSTALL_DIR" ]; then
    install -m 0755 "${TMP_DIR}/${ASSET}" "${INSTALL_DIR}/sipmon"
elif command -v sudo >/dev/null 2>&1; then
    info "requesting elevated permissions to install to ${INSTALL_DIR}"
    sudo mkdir -p "$INSTALL_DIR"
    sudo install -m 0755 "${TMP_DIR}/${ASSET}" "${INSTALL_DIR}/sipmon"
else
    fail "cannot write to ${INSTALL_DIR}; rerun as root or set SIPMON_INSTALL_DIR"
fi

info "installed to ${INSTALL_DIR}/sipmon"
"${INSTALL_DIR}/sipmon" --version

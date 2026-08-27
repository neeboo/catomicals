#!/bin/sh
# Install an official Bitcoin Inquisition v29.4-inq binary release.
# Source: https://github.com/bitcoin-inquisition/bitcoin/releases/tag/v29.4-inq
#
# This script verifies the selected archive against the release SHA256SUMS,
# installs into a new operator-owned prefix, copies a safe sample config, and
# exits. It never starts bitcoind or chain synchronization.

set -eu

VERSION="29.4"
TAG="v29.4-inq"
RELEASE_BASE="https://github.com/bitcoin-inquisition/bitcoin/releases/download/${TAG}"
PREFIX="${PWD}/.local/bitcoin-inquisition-${VERSION}"

usage() {
    printf '%s\n' "usage: $0 [--prefix PATH]"
    printf '%s\n' "downloads and verifies Bitcoin Inquisition ${TAG}; does not start bitcoind"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --prefix)
            [ "$#" -ge 2 ] || { printf '%s\n' "--prefix requires a path" >&2; exit 2; }
            PREFIX="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf '%s\n' "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

case "$(uname -s):$(uname -m)" in
    Linux:x86_64|Linux:amd64) ARCHIVE="bitcoin-${VERSION}-inq-x86_64-linux-gnu.tar.gz" ;;
    Linux:aarch64|Linux:arm64) ARCHIVE="bitcoin-${VERSION}-inq-aarch64-linux-gnu.tar.gz" ;;
    Darwin:x86_64) ARCHIVE="bitcoin-${VERSION}-inq-x86_64-apple-darwin-unsigned.tar.gz" ;;
    Darwin:arm64|Darwin:aarch64) ARCHIVE="bitcoin-${VERSION}-inq-arm64-apple-darwin-unsigned.tar.gz" ;;
    *)
        printf '%s\n' "unsupported platform: $(uname -s) $(uname -m)" >&2
        exit 1
        ;;
esac
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)
SAMPLE_CONFIG="${REPO_ROOT}/config/bitcoin-signet.conf"

[ -f "${SAMPLE_CONFIG}" ] || {
    printf '%s\n' "sample config not found: ${SAMPLE_CONFIG}" >&2
    exit 1
}
[ ! -e "${PREFIX}" ] || {
    printf '%s\n' "refusing to overwrite existing path: ${PREFIX}" >&2
    exit 1
}

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/catomicals-inq.XXXXXX")
cleanup() {
    rm -rf -- "${WORK_DIR}"
}
trap cleanup EXIT HUP INT TERM

download() {
    url="$1"
    output="$2"
    if command -v curl >/dev/null 2>&1; then
        curl --fail --location --proto '=https' --tlsv1.2 --output "${output}" "${url}"
    elif command -v wget >/dev/null 2>&1; then
        wget --https-only --output-document="${output}" "${url}"
    else
        printf '%s\n' "curl or wget is required" >&2
        exit 1
    fi
}

download "${RELEASE_BASE}/SHA256SUMS" "${WORK_DIR}/SHA256SUMS"
download "${RELEASE_BASE}/${ARCHIVE}" "${WORK_DIR}/${ARCHIVE}"

grep -E "^[0-9a-fA-F]{64} [ *]${ARCHIVE}$" "${WORK_DIR}/SHA256SUMS" \
    > "${WORK_DIR}/SHA256SUMS.selected" || {
        printf '%s\n' "${ARCHIVE} is not listed in the official SHA256SUMS" >&2
        exit 1
    }

if command -v sha256sum >/dev/null 2>&1; then
    (cd "${WORK_DIR}" && sha256sum --check SHA256SUMS.selected)
elif command -v shasum >/dev/null 2>&1; then
    (cd "${WORK_DIR}" && shasum --algorithm 256 --check SHA256SUMS.selected)
else
    printf '%s\n' "sha256sum or shasum is required" >&2
    exit 1
fi

tar -xzf "${WORK_DIR}/${ARCHIVE}" -C "${WORK_DIR}"
EXTRACTED=$(find "${WORK_DIR}" -mindepth 1 -maxdepth 1 -type d -name "bitcoin-${VERSION}*" -print | head -n 1)
[ -n "${EXTRACTED}" ] && [ -d "${EXTRACTED}" ] || {
    printf '%s\n' "archive did not contain a bitcoin-${VERSION} release directory" >&2
    exit 1
}

mkdir -p "${PREFIX}"
cp -R "${EXTRACTED}/." "${PREFIX}/"

# The official macOS "unsigned" archive is intentionally not runnable under
# modern macOS execution policy until the operator applies a local signature.
# The downloaded archive has already been verified above; this ad-hoc
# signature only authorizes the exact local copy to execute.
if [ "$(uname -s)" = "Darwin" ]; then
    command -v codesign >/dev/null 2>&1 || {
        printf '%s\n' "codesign is required to activate the verified unsigned macOS release" >&2
        exit 1
    }
    for executable in "${PREFIX}"/bin/*; do
        [ -f "${executable}" ] || continue
        codesign --force --sign - "${executable}"
    done
fi

mkdir -p "${PREFIX}/share/catomicals"
cp "${SAMPLE_CONFIG}" "${PREFIX}/share/catomicals/bitcoin-signet.conf"

printf '%s\n' "installed verified Bitcoin Inquisition ${TAG} to ${PREFIX}"
[ "$(uname -s)" != "Darwin" ] || printf '%s\n' "macOS binaries were locally ad-hoc signed after archive verification"
printf '%s\n' "sample config: ${PREFIX}/share/catomicals/bitcoin-signet.conf"
printf '%s\n' "bitcoind was not started; no chain synchronization was launched"

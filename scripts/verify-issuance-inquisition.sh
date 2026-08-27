#!/bin/sh
set -eu

INQUISITION_UTIL="${BITCOIN_UTIL_INQ:-}"
if [ -z "${INQUISITION_UTIL}" ]; then
    INQUISITION_UTIL="$(command -v bitcoin-util-inq || true)"
fi
if [ -z "${INQUISITION_UTIL}" ] && [ -x ".runtime/bitcoin-inquisition-v29.4/bin/bitcoin-util" ]; then
    INQUISITION_UTIL=".runtime/bitcoin-inquisition-v29.4/bin/bitcoin-util"
fi
if [ -z "${INQUISITION_UTIL}" ] || [ ! -x "${INQUISITION_UTIL}" ]; then
    echo "bitcoin-util-inq was not found; set BITCOIN_UTIL_INQ to an executable Bitcoin Inquisition bitcoin-util" >&2
    exit 1
fi

cargo run --quiet -p catomicals-issuance --example verify_inquisition -- "${INQUISITION_UTIL}"

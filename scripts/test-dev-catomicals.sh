#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)"

export CATOMICALS_DEV_SOURCE_ONLY=1
# shellcheck source=dev-catomicals.sh
source "${SCRIPT_DIR}/dev-catomicals.sh"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

assert_eq() {
  local expected="$1"
  local actual="$2"
  local message="$3"
  [[ "${actual}" == "${expected}" ]] || fail "${message}: expected '${expected}', got '${actual}'"
}

test_versioned_binary_uses_the_current_commit() {
  local actual
  actual="$(versioned_binary_path "/tmp/catomicals" "abc123def456")"
  assert_eq "/tmp/catomicals/.runtime/bin/catomicals-walletd-abc123def456" "${actual}" \
    "versioned wallet binary path"
}

test_inquisition_uses_the_current_repository_config() {
  local actual repository
  repository="$(mktemp -d)"
  mkdir -p "${repository}/config"
  : > "${repository}/config/bitcoin-signet.conf"
  actual="$(default_inquisition_config "${repository}" "/installed")"
  assert_eq "${repository}/config/bitcoin-signet.conf" "${actual}" \
    "Inquisition config must come from the current repository"
  rm -rf "${repository}"
}

test_wallet_process_matching_is_narrow() {
  is_catomicals_wallet_command "/repo/.runtime/bin/catomicals-walletd-deadbeef wallet serve --addr 127.0.0.1:18788" \
    || fail "current wallet command should match"
  ! is_catomicals_wallet_command "/Applications/Docker.app/Contents/MacOS/com.docker.backend" \
    || fail "Docker listener must not match"
  ! is_catomicals_wallet_command "/repo/target/debug/catomicals signer serve" \
    || fail "signer process must not match"
}

test_retirement_only_stops_wallet_processes() {
  local stopped_file
  stopped_file="$(mktemp)"

  wallet_listener_pids() {
    printf '%s\n' 101 202
  }
  process_command() {
    case "$1" in
      101) printf '%s\n' "/old/catomicals-walletd wallet serve --addr 127.0.0.1:18788" ;;
      202) printf '%s\n' "/Applications/Docker.app/Contents/MacOS/com.docker.backend" ;;
      *) return 1 ;;
    esac
  }
  terminate_process() {
    printf '%s\n' "$1" >> "${stopped_file}"
  }

  retire_old_wallet_processes 18788
  assert_eq "101" "$(tr -d '\n' < "${stopped_file}")" \
    "retirement must only terminate wallet serve"
  rm -f "${stopped_file}"
}

test_command_uses_exact_versioned_binary() {
  command_uses_binary \
    "/repo/.runtime/bin/catomicals-walletd-abc123 wallet serve --addr 127.0.0.1:18788" \
    "/repo/.runtime/bin/catomicals-walletd-abc123" \
    || fail "exact versioned binary should match"
  ! command_uses_binary \
    "/repo/.runtime/bin/catomicals-walletd-old wallet serve --addr 127.0.0.1:18788" \
    "/repo/.runtime/bin/catomicals-walletd-abc123" \
    || fail "old binary must not match"
}

test_txindex_must_be_synced_at_the_chain_tip() {
  txindex_at_tip 120 120 true || fail "synced txindex at tip should be ready"
  ! txindex_at_tip 120 119 true || fail "lagging txindex must not be ready"
  ! txindex_at_tip 120 120 false || fail "unsynced txindex must not be ready"
}

test_wallet_contract_requires_signet_and_seven_chains() {
  local seven_chains='{"schema_version":1,"chains":[{"chain_scope":{"chain":"bitcoin"}},{"chain_scope":{"chain":"bitcoin-cash"}},{"chain_scope":{"chain":"bsv"}},{"chain_scope":{"chain":"fractal-bitcoin"}},{"chain_scope":{"chain":"kaspa"}},{"chain_scope":{"chain":"chia"}},{"chain_scope":{"chain":"ergo"}}]}'
  wallet_contract_ready "${seven_chains}" '{"network":"signet"}' \
    || fail "Signet wallet with seven chains should be ready"
  ! wallet_contract_ready '{"schema_version":1,"chains":[{}]}' '{"network":"signet"}' \
    || fail "incomplete chain inventory must not be ready"
  ! wallet_contract_ready "${seven_chains}" '{"network":"unconfigured"}' \
    || fail "wallet without a trusted Signet snapshot must not be ready"
}

test_wallet_readiness_matches_the_cordis_health_route() {
  local requests seven_chains
  requests="$(mktemp)"
  seven_chains='{"schema_version":1,"chains":[{"chain_scope":{"chain":"bitcoin"}},{"chain_scope":{"chain":"bitcoin-cash"}},{"chain_scope":{"chain":"bsv"}},{"chain_scope":{"chain":"fractal-bitcoin"}},{"chain_scope":{"chain":"kaspa"}},{"chain_scope":{"chain":"chia"}},{"chain_scope":{"chain":"ergo"}}]}'
  curl() {
    local url="${!#}"
    printf '%s\n' "${url}" >> "${requests}"
    case "${url}" in
      */api/v1/wallet/status) return 22 ;;
      */api/v1/chains/status) printf '%s\n' "${seven_chains}" ;;
      */api/v1/node/status) printf '%s\n' '{"network":"signet"}' ;;
      *) return 22 ;;
    esac
  }

  ! wallet_routes_ready || fail "wallet readiness must fail when Cordis wallet health fails"
  grep -q '/api/v1/wallet/status' "${requests}" \
    || fail "wallet readiness must probe the Cordis wallet health route"
  unset -f curl
  rm -f "${requests}"
}

test_launcher_does_not_rewrite_cordis_state() {
  ! grep -q "Application Support/catomicals-desktop" "${SCRIPT_DIR}/dev-catomicals.sh" \
    || fail "launcher must not edit the desktop Cordis state directory"
  ! grep -q "settingsDigest" "${SCRIPT_DIR}/dev-catomicals.sh" \
    || fail "launcher must not rewrite Cordis settings digests"
}

test_desktop_receives_the_development_wallet_endpoint() {
  local capture fake_bin
  capture="$(mktemp)"
  fake_bin="$(mktemp -d)"
  printf '%s\n' '#!/usr/bin/env bash' 'printf "%s" "${CATOMICALS_DEV_WALLET_ENDPOINT:-}" > "${CATOMICALS_TEST_CAPTURE}"' \
    > "${fake_bin}/pnpm"
  chmod 0755 "${fake_bin}/pnpm"

  CATOMICALS_TEST_CAPTURE="${capture}" PATH="${fake_bin}:${PATH}" launch_desktop
  wait "${DESKTOP_PID}"

  assert_eq "${WALLET_URL}" "$(cat "${capture}")" \
    "desktop wallet endpoint environment"
  rm -f "${capture}"
  rm -rf "${fake_bin}"
  DESKTOP_PID=""
}

test_versioned_binary_uses_the_current_commit
test_inquisition_uses_the_current_repository_config
test_wallet_process_matching_is_narrow
test_retirement_only_stops_wallet_processes
test_command_uses_exact_versioned_binary
test_txindex_must_be_synced_at_the_chain_tip
test_wallet_contract_requires_signet_and_seven_chains
test_wallet_readiness_matches_the_cordis_health_route
test_launcher_does_not_rewrite_cordis_state
test_desktop_receives_the_development_wallet_endpoint

printf 'PASS: dev-catomicals startup helpers\n'

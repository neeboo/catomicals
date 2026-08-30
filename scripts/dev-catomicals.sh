#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)"
RUNTIME_ROOT="${REPO_ROOT}/.runtime"
LOG_ROOT="${RUNTIME_ROOT}/logs"
WALLET_PORT="${CATOMICALS_WALLET_PORT:-18787}"
RENDERER_PORT="${CATOMICALS_RENDERER_PORT:-5173}"
WALLET_ADDR="127.0.0.1:${WALLET_PORT}"
WALLET_URL="http://${WALLET_ADDR}"
WALLET_PID=""
DESKTOP_PID=""
WALLET_ONLY=0

usage() {
  printf '%s\n' "usage: $0 [--wallet-only]"
  printf '%s\n' "builds the current wallet binary, retires old services, starts Signet and the desktop app"
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --wallet-only)
      WALLET_ONLY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

versioned_binary_path() {
  local root="$1"
  local revision="$2"
  printf '%s/.runtime/bin/catomicals-walletd-%s\n' "${root}" "${revision}"
}

is_catomicals_wallet_command() {
  local command="$1"
  [[ "${command}" == *catomicals*wallet*serve* ]]
}

command_uses_binary() {
  local command="$1"
  local binary="$2"
  [[ "${command}" == "${binary} "* ]]
}

wallet_listener_pids() {
  local port="$1"
  command -v lsof >/dev/null 2>&1 || return 0
  lsof -nP -a -iTCP:"${port}" -sTCP:LISTEN -t 2>/dev/null | sort -u
}

process_command() {
  ps -p "$1" -o command= 2>/dev/null
}

terminate_process() {
  local pid="$1"
  kill -TERM "${pid}" 2>/dev/null || return 0
  for _ in {1..50}; do
    kill -0 "${pid}" 2>/dev/null || return 0
    sleep 0.1
  done
  kill -KILL "${pid}" 2>/dev/null || true
}

retire_old_wallet_processes() {
  local port="$1"
  local pid command
  while IFS= read -r pid; do
    [[ -n "${pid}" ]] || continue
    command="$(process_command "${pid}" || true)"
    if is_catomicals_wallet_command "${command}"; then
      printf 'Stopping old wallet process %s\n' "${pid}"
      terminate_process "${pid}"
    fi
  done < <(wallet_listener_pids "${port}")
}

retire_all_wallet_processes() {
  local pid command
  while read -r pid command; do
    [[ -n "${pid:-}" ]] || continue
    if is_catomicals_wallet_command "${command:-}"; then
      printf 'Stopping old wallet process %s\n' "${pid}"
      terminate_process "${pid}"
    fi
  done < <(ps -axo pid=,command=)
}

retire_old_desktop_processes() {
  local pid command
  while read -r pid command; do
    [[ -n "${pid:-}" ]] || continue
    [[ "${command:-}" == *"${REPO_ROOT}"* ]] || continue
    case "${command}" in
      *concurrently*|*node*vite*|*Electron.app/Contents/MacOS/Electron*)
        printf 'Stopping old desktop process %s\n' "${pid}"
        terminate_process "${pid}"
        ;;
    esac
  done < <(ps -axo pid=,command=)
}

retire_launch_agent() {
  [[ "$(uname -s)" == "Darwin" ]] || return 0
  local domain="gui/$(id -u)"
  local label="com.catomicals.walletd"
  local plist="${HOME}/Library/LaunchAgents/${label}.plist"

  launchctl bootout "${domain}" "${plist}" >/dev/null 2>&1 || true
  launchctl disable "${domain}/${label}" >/dev/null 2>&1 || true
}

common_checkout_root() {
  local common_dir
  common_dir="$(git -C "${REPO_ROOT}" rev-parse --git-common-dir)"
  if [[ "${common_dir}" != /* ]]; then
    common_dir="${REPO_ROOT}/${common_dir}"
  fi
  CDPATH= cd -- "$(dirname -- "${common_dir}")" && pwd
}

default_inquisition_config() {
  local repository_root="$1"
  local install_root="$2"
  if [[ -f "${repository_root}/config/bitcoin-signet.conf" ]]; then
    printf '%s/config/bitcoin-signet.conf\n' "${repository_root}"
  else
    printf '%s/share/catomicals/bitcoin-signet.conf\n' "${install_root}"
  fi
}

wait_for_command() {
  local attempts="$1"
  shift
  for ((i = 0; i < attempts; i += 1)); do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

txindex_at_tip() {
  local chain_tip="$1"
  local index_tip="$2"
  local synced="$3"
  [[ "${synced}" == "true" && "${chain_tip}" == "${index_tip}" ]]
}

ensure_inquisition() {
  local common_root="$1"
  local install_root="${CATOMICALS_INQUISITION_ROOT:-${common_root}/.runtime/bitcoin-inquisition-v29.4}"
  local bitcoind="${CATOMICALS_BITCOIND:-${install_root}/bin/bitcoind}"
  local bitcoin_cli="${CATOMICALS_BITCOIN_CLI:-${install_root}/bin/bitcoin-cli}"
  local config="${CATOMICALS_BITCOIN_CONFIG:-$(default_inquisition_config "${REPO_ROOT}" "${install_root}")}"
  local data_dir="${CATOMICALS_BITCOIN_DATADIR:-${common_root}/.runtime/inquisition-signet-data}"

  [[ -x "${bitcoind}" ]] || { printf 'Bitcoin Inquisition binary not found: %s\n' "${bitcoind}" >&2; return 1; }
  [[ -x "${bitcoin_cli}" ]] || { printf 'bitcoin-cli not found: %s\n' "${bitcoin_cli}" >&2; return 1; }
  [[ -f "${config}" ]] || { printf 'Bitcoin Inquisition config not found: %s\n' "${config}" >&2; return 1; }
  mkdir -p "${data_dir}"
  chmod 700 "${data_dir}"

  inquisition_rpc_ready() {
    "${bitcoin_cli}" -datadir="${data_dir}" -conf="${config}" getblockchaininfo >/dev/null 2>&1
  }

  inquisition_txindex_ready() {
    local blockchain indexes chain_tip index_tip synced
    blockchain="$("${bitcoin_cli}" -datadir="${data_dir}" -conf="${config}" getblockchaininfo 2>/dev/null)" || return 1
    indexes="$("${bitcoin_cli}" -datadir="${data_dir}" -conf="${config}" getindexinfo txindex 2>/dev/null)" || return 1
    read -r chain_tip index_tip synced < <(node -e '
      const blockchain = JSON.parse(process.argv[1]);
      const indexes = JSON.parse(process.argv[2]);
      const txindex = indexes.txindex || {};
      process.stdout.write(`${blockchain.blocks ?? ""} ${txindex.best_block_height ?? ""} ${txindex.synced === true}`);
    ' "${blockchain}" "${indexes}")
    txindex_at_tip "${chain_tip}" "${index_tip}" "${synced}"
  }

  if ! inquisition_rpc_ready; then
    printf 'Starting Bitcoin Inquisition Signet\n'
    "${bitcoind}" \
      -datadir="${data_dir}" \
      -conf="${config}" \
      -daemon=1 \
      -pid="${RUNTIME_ROOT}/inquisition.pid" >/dev/null
    wait_for_command 240 inquisition_rpc_ready || {
      printf 'Bitcoin Inquisition did not expose RPC on 127.0.0.1:38332\n' >&2
      return 1
    }
  fi

  if ! inquisition_txindex_ready; then
    printf 'Waiting for the Signet transaction index to reach the chain tip\n'
    wait_for_command 240 inquisition_txindex_ready || {
      printf 'Bitcoin Inquisition transaction index did not reach the chain tip\n' >&2
      return 1
    }
  fi

  CATOMICALS_ACTIVE_BITCOIN_DATADIR="${data_dir}"
  printf 'Bitcoin Inquisition ready: %s\n' "${data_dir}"
}

build_versioned_wallet() {
  local revision source_binary destination temp_destination
  revision="$(git -C "${REPO_ROOT}" rev-parse --short=12 HEAD)"
  source_binary="${REPO_ROOT}/target/debug/catomicals"
  destination="$(versioned_binary_path "${REPO_ROOT}" "${revision}")"
  temp_destination="${destination}.tmp.$$"

  printf 'Building wallet from commit %s\n' "${revision}" >&2
  "${REPO_ROOT}/scripts/cargo-rocksdb.sh" build --locked -p catomicals --bin catomicals >&2
  [[ -x "${source_binary}" ]] || { printf 'built wallet binary missing: %s\n' "${source_binary}" >&2; return 1; }

  mkdir -p "$(dirname -- "${destination}")"
  install -m 0755 "${source_binary}" "${temp_destination}"
  mv -f "${temp_destination}" "${destination}"
  printf '%s\n' "${destination}"
}

wallet_contract_ready() {
  local chains="$1"
  local node_status="$2"
  node -e '
    const chains = JSON.parse(process.argv[1]);
    const nodeStatus = JSON.parse(process.argv[2]);
    const expected = ["bitcoin", "bitcoin-cash", "bsv", "fractal-bitcoin", "kaspa", "chia", "ergo"];
    const actual = Array.isArray(chains.chains)
      ? chains.chains.map((entry) => entry?.chain_scope?.chain)
      : [];
    if (chains.schema_version !== 1 || JSON.stringify(actual) !== JSON.stringify(expected) || nodeStatus.network !== "signet") {
      process.exit(1);
    }
  ' "${chains}" "${node_status}" >/dev/null 2>&1
}

wallet_routes_ready() {
  local chains node_status
  curl --fail --silent --show-error --max-time 2 "${WALLET_URL}/api/v1/wallet/status" >/dev/null || return 1
  chains="$(curl --fail --silent --show-error --max-time 2 "${WALLET_URL}/api/v1/chains/status")" || return 1
  node_status="$(curl --fail --silent --show-error --max-time 2 "${WALLET_URL}/api/v1/node/status")" || return 1
  wallet_contract_ready "${chains}" "${node_status}"
}

start_wallet() {
  local binary="$1"
  local common_root="$2"
  local data_dir="${CATOMICALS_WALLET_DATA_DIR:-${common_root}/.runtime/walletd-data}"
  local log_file="${LOG_ROOT}/wallet.log"
  local command

  mkdir -p "${data_dir}" "${LOG_ROOT}"
  chmod 700 "${data_dir}"

  "${binary}" wallet serve \
    --addr "${WALLET_ADDR}" \
    --cors-origin "http://localhost:${RENDERER_PORT}" \
    --rp-id localhost \
    --rp-origin "http://localhost:${RENDERER_PORT}" \
    --data-dir "${data_dir}" \
    --datadir "${CATOMICALS_ACTIVE_BITCOIN_DATADIR}" \
    --allow-self-hosted-development-secrets \
    >"${log_file}" 2>&1 &
  WALLET_PID="$!"
  printf '%s\n' "${WALLET_PID}" > "${RUNTIME_ROOT}/wallet.pid"

  wait_for_command 120 wallet_routes_ready || {
    printf 'New wallet failed health checks; log: %s\n' "${log_file}" >&2
    tail -n 80 "${log_file}" >&2 || true
    return 1
  }

  command="$(process_command "${WALLET_PID}" || true)"
  command_uses_binary "${command}" "${binary}" || {
    printf 'Wallet PID %s is not using %s\n' "${WALLET_PID}" "${binary}" >&2
    return 1
  }

  printf 'Wallet ready: pid=%s binary=%s\n' "${WALLET_PID}" "${binary}"
  printf 'Wallet SHA-256: '
  shasum -a 256 "${binary}" | awk '{print $1}'
}

launch_desktop() {
  CATOMICALS_DEV_WALLET_ENDPOINT="${WALLET_URL}" pnpm --dir "${REPO_ROOT}/desktop" dev &
  DESKTOP_PID="$!"
}

cleanup() {
  if [[ -n "${DESKTOP_PID}" ]]; then
    terminate_process "${DESKTOP_PID}"
  fi
  if [[ -n "${WALLET_PID}" ]]; then
    terminate_process "${WALLET_PID}"
  fi
}

main() {
  local common_root wallet_binary
  common_root="$(common_checkout_root)"
  mkdir -p "${RUNTIME_ROOT}" "${LOG_ROOT}"

  retire_launch_agent
  retire_all_wallet_processes
  retire_old_wallet_processes "${WALLET_PORT}"
  retire_old_desktop_processes
  ensure_inquisition "${common_root}"
  wallet_binary="$(build_versioned_wallet)"
  start_wallet "${wallet_binary}" "${common_root}"

  trap cleanup EXIT INT TERM
  if [[ "${WALLET_ONLY}" -eq 1 ]]; then
    printf 'Wallet-only mode is running. Press Ctrl-C to stop.\n'
    wait "${WALLET_PID}"
    return
  fi

  printf 'Starting Catomicals desktop\n'
  launch_desktop
  wait "${DESKTOP_PID}"
}

if [[ "${CATOMICALS_DEV_SOURCE_ONLY:-0}" != "1" ]]; then
  main "$@"
fi

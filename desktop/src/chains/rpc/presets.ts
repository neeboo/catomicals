import { ChainRpcError } from "./errors.js";
import type { ChainId } from "./types.js";

export type ChainRpcPresetTransport = "json-rpc" | "https-api" | "https-rpc" | "rest";
export type ChainRpcPresetAccess = "local" | "private-network" | "public";

export interface ChainRpcPreset {
  readonly chain: ChainId;
  readonly networkId: string;
  readonly endpoint: string;
  readonly transport: ChainRpcPresetTransport;
  readonly access: ChainRpcPresetAccess;
}

const loopback = (port: number): string => `http://127.0.0.1:${port}`;
const secureLoopback = (port: number): string => `https://127.0.0.1:${port}`;

export const CHAIN_RPC_PRESETS: readonly ChainRpcPreset[] = Object.freeze([
  { chain: "bitcoin", networkId: "bitcoin-inquisition", endpoint: loopback(38332), transport: "json-rpc", access: "local" },
  { chain: "bitcoin", networkId: "bitcoin-mainnet", endpoint: loopback(8332), transport: "json-rpc", access: "local" },
  { chain: "bitcoin", networkId: "bitcoin-testnet3", endpoint: loopback(18332), transport: "json-rpc", access: "local" },
  { chain: "bitcoin", networkId: "bitcoin-testnet4", endpoint: loopback(48332), transport: "json-rpc", access: "local" },
  { chain: "bitcoin", networkId: "bitcoin-signet", endpoint: loopback(38332), transport: "json-rpc", access: "local" },
  { chain: "bitcoin", networkId: "bitcoin-regtest", endpoint: loopback(18443), transport: "json-rpc", access: "local" },

  { chain: "fractal-bitcoin", networkId: "fractal-bitcoin-mainnet", endpoint: loopback(8332), transport: "json-rpc", access: "local" },
  { chain: "fractal-bitcoin", networkId: "fractal-bitcoin-testnet3", endpoint: loopback(18332), transport: "json-rpc", access: "local" },
  { chain: "fractal-bitcoin", networkId: "fractal-bitcoin-testnet4", endpoint: loopback(48332), transport: "json-rpc", access: "local" },
  { chain: "fractal-bitcoin", networkId: "fractal-bitcoin-signet", endpoint: loopback(38332), transport: "json-rpc", access: "local" },
  { chain: "fractal-bitcoin", networkId: "fractal-bitcoin-regtest", endpoint: loopback(18443), transport: "json-rpc", access: "local" },

  { chain: "bitcoin-cash", networkId: "bitcoin-cash-mainnet", endpoint: loopback(8332), transport: "json-rpc", access: "local" },
  { chain: "bitcoin-cash", networkId: "bitcoin-cash-testnet3", endpoint: loopback(18332), transport: "json-rpc", access: "local" },
  { chain: "bitcoin-cash", networkId: "bitcoin-cash-testnet4", endpoint: loopback(28342), transport: "json-rpc", access: "local" },
  { chain: "bitcoin-cash", networkId: "bitcoin-cash-chipnet", endpoint: loopback(48332), transport: "json-rpc", access: "local" },
  { chain: "bitcoin-cash", networkId: "bitcoin-cash-regtest", endpoint: loopback(18443), transport: "json-rpc", access: "local" },

  { chain: "bsv", networkId: "bsv-mainnet", endpoint: loopback(8332), transport: "json-rpc", access: "local" },
  { chain: "bsv", networkId: "bsv-testnet", endpoint: loopback(18332), transport: "json-rpc", access: "local" },
  { chain: "bsv", networkId: "bsv-regtest", endpoint: loopback(18443), transport: "json-rpc", access: "local" },

  { chain: "kaspa", networkId: "kaspa-mainnet", endpoint: "https://api.kaspa.org", transport: "https-api", access: "public" },
  { chain: "kaspa", networkId: "kaspa-testnet-10", endpoint: "https://api-tn10.kaspa.org", transport: "https-api", access: "public" },
  { chain: "kaspa", networkId: "kaspa-testnet-11", endpoint: "https://api-tn11.kaspa.org", transport: "https-api", access: "public" },

  { chain: "chia", networkId: "chia-mainnet", endpoint: secureLoopback(8555), transport: "https-rpc", access: "local" },
  { chain: "chia", networkId: "chia-testnet11", endpoint: secureLoopback(8555), transport: "https-rpc", access: "local" },

  { chain: "ergo", networkId: "ergo-mainnet", endpoint: loopback(9053), transport: "rest", access: "local" },
  { chain: "ergo", networkId: "ergo-testnet", endpoint: loopback(9052), transport: "rest", access: "local" },
]);

export function chainRpcNetworkIds(chain: ChainId): readonly string[] {
  return CHAIN_RPC_PRESETS.filter((preset) => preset.chain === chain).map((preset) => preset.networkId);
}

export function resolveChainRpcPreset(chain: ChainId, networkId: string): ChainRpcPreset {
  const preset = CHAIN_RPC_PRESETS.find((candidate) => candidate.chain === chain && candidate.networkId === networkId);
  if (!preset) throw new ChainRpcError("invalid_config", `unsupported ${chain} network preset`);
  return preset;
}

import {
  RPC_PRESET_IDS,
  resolveRpcPresetNetwork,
  type ChainNetwork,
  type RpcPresetId,
} from "../network-contract.js";
import { ChainRpcError } from "./errors.js";
import type { ChainId } from "./types.js";

export type ChainRpcPresetTransport = "json-rpc" | "https-api" | "https-rpc" | "rest";
export type ChainRpcPresetAccess = "local" | "private-network" | "public";

export interface ChainRpcPreset {
  readonly chain: ChainId;
  readonly id: RpcPresetId;
  readonly chainNetwork: ChainNetwork;
  readonly endpoint: string;
  readonly transport: ChainRpcPresetTransport;
  readonly access: ChainRpcPresetAccess;
}

const loopback = (port: number): string => `http://127.0.0.1:${port}`;
const secureLoopback = (port: number): string => `https://127.0.0.1:${port}`;

function chainIdFromNetwork(chainNetwork: ChainNetwork): ChainId {
  return chainNetwork.slice(0, chainNetwork.indexOf(".")) as ChainId;
}

function preset(
  id: RpcPresetId,
  endpoint: string,
  transport: ChainRpcPresetTransport,
  access: ChainRpcPresetAccess,
): ChainRpcPreset {
  const chainNetwork = resolveRpcPresetNetwork(id);
  return { id, chain: chainIdFromNetwork(chainNetwork), chainNetwork, endpoint, transport, access };
}

export const CHAIN_RPC_PRESETS: readonly ChainRpcPreset[] = Object.freeze([
  preset("bitcoin-inquisition", loopback(38332), "json-rpc", "local"),
  preset("bitcoin-mainnet", loopback(8332), "json-rpc", "local"),
  preset("bitcoin-testnet3", loopback(18332), "json-rpc", "local"),
  preset("bitcoin-testnet4", loopback(48332), "json-rpc", "local"),
  preset("bitcoin-signet", loopback(38332), "json-rpc", "local"),
  preset("bitcoin-regtest", loopback(18443), "json-rpc", "local"),

  preset("bitcoin-cash-mainnet", loopback(8332), "json-rpc", "local"),
  preset("bitcoin-cash-testnet3", loopback(18332), "json-rpc", "local"),
  preset("bitcoin-cash-testnet4", loopback(28332), "json-rpc", "local"),
  preset("bitcoin-cash-chipnet", loopback(48332), "json-rpc", "local"),
  preset("bitcoin-cash-scalenet", loopback(38332), "json-rpc", "local"),
  preset("bitcoin-cash-regtest", loopback(18443), "json-rpc", "local"),

  preset("bsv-mainnet", loopback(8332), "json-rpc", "local"),
  preset("bsv-testnet", loopback(18332), "json-rpc", "local"),
  preset("bsv-stn", loopback(9332), "json-rpc", "local"),
  preset("bsv-regtest", loopback(18332), "json-rpc", "local"),

  preset("fractal-bitcoin-mainnet", loopback(8332), "json-rpc", "local"),
  preset("fractal-bitcoin-testnet3", loopback(18332), "json-rpc", "local"),
  preset("fractal-bitcoin-testnet4", loopback(48332), "json-rpc", "local"),
  preset("fractal-bitcoin-signet", loopback(38332), "json-rpc", "local"),
  preset("fractal-bitcoin-regtest", loopback(18443), "json-rpc", "local"),

  preset("kaspa-mainnet", "https://api.kaspa.org", "https-api", "public"),
  preset("kaspa-testnet-10", "https://api-tn10.kaspa.org", "https-api", "public"),
  preset("kaspa-testnet-11", "https://api-tn11.kaspa.org", "https-api", "public"),
  preset("kaspa-simnet", loopback(16510), "json-rpc", "local"),
  preset("kaspa-devnet", loopback(16610), "json-rpc", "local"),

  preset("chia-mainnet", secureLoopback(8555), "https-rpc", "local"),
  preset("chia-testnet11", secureLoopback(8555), "https-rpc", "local"),

  preset("ergo-mainnet", loopback(9053), "rest", "local"),
  preset("ergo-testnet", loopback(9052), "rest", "local"),
]);

if (CHAIN_RPC_PRESETS.length !== RPC_PRESET_IDS.length) {
  throw new Error("RPC preset definitions and network mappings are out of sync");
}

export function chainRpcNetworkIds(chain: ChainId): readonly RpcPresetId[] {
  return CHAIN_RPC_PRESETS.filter((candidate) => candidate.chain === chain).map((candidate) => candidate.id);
}

export function resolveChainRpcPreset(chain: ChainId, presetId: string): ChainRpcPreset {
  const preset = CHAIN_RPC_PRESETS.find((candidate) => candidate.id === presetId);
  if (!preset) throw new ChainRpcError("invalid_config", `unsupported ${chain} RPC preset: ${presetId}`);
  if (preset.chain !== chain) {
    throw new ChainRpcError("invalid_config", `RPC preset ${presetId} belongs to ${preset.chain}, not ${chain}`);
  }
  return preset;
}

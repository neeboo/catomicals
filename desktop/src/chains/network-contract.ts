export const CHAIN_IDS = Object.freeze([
  "bitcoin",
  "bitcoin-cash",
  "bsv",
  "fractal-bitcoin",
  "kaspa",
  "chia",
  "ergo",
] as const);

export type ChainId = (typeof CHAIN_IDS)[number];

export const CHAIN_NETWORKS = Object.freeze([
  "bitcoin.mainnet",
  "bitcoin.testnet3",
  "bitcoin.testnet4",
  "bitcoin.signet",
  "bitcoin.regtest",
  "bitcoin-cash.mainnet",
  "bitcoin-cash.testnet3",
  "bitcoin-cash.testnet4",
  "bitcoin-cash.chipnet",
  "bitcoin-cash.scalenet",
  "bitcoin-cash.regtest",
  "bsv.mainnet",
  "bsv.testnet",
  "bsv.stn",
  "bsv.regtest",
  "fractal-bitcoin.mainnet",
  "fractal-bitcoin.testnet3",
  "fractal-bitcoin.testnet4",
  "fractal-bitcoin.signet",
  "fractal-bitcoin.regtest",
  "kaspa.mainnet",
  "kaspa.testnet10",
  "kaspa.testnet11",
  "kaspa.simnet",
  "kaspa.devnet",
  "chia.mainnet",
  "chia.testnet11",
  "ergo.mainnet",
  "ergo.testnet",
] as const);

export type ChainNetwork = (typeof CHAIN_NETWORKS)[number];

export function chainIdFromNetwork(chainNetwork: ChainNetwork): ChainId {
  return chainNetwork.slice(0, chainNetwork.indexOf(".")) as ChainId;
}

export const RPC_PRESET_NETWORKS = Object.freeze({
  "bitcoin-inquisition": "bitcoin.signet",
  "bitcoin-mainnet": "bitcoin.mainnet",
  "bitcoin-testnet3": "bitcoin.testnet3",
  "bitcoin-testnet4": "bitcoin.testnet4",
  "bitcoin-signet": "bitcoin.signet",
  "bitcoin-regtest": "bitcoin.regtest",
  "bitcoin-cash-mainnet": "bitcoin-cash.mainnet",
  "bitcoin-cash-testnet3": "bitcoin-cash.testnet3",
  "bitcoin-cash-testnet4": "bitcoin-cash.testnet4",
  "bitcoin-cash-chipnet": "bitcoin-cash.chipnet",
  "bitcoin-cash-scalenet": "bitcoin-cash.scalenet",
  "bitcoin-cash-regtest": "bitcoin-cash.regtest",
  "bsv-mainnet": "bsv.mainnet",
  "bsv-testnet": "bsv.testnet",
  "bsv-stn": "bsv.stn",
  "bsv-regtest": "bsv.regtest",
  "fractal-bitcoin-mainnet": "fractal-bitcoin.mainnet",
  "fractal-bitcoin-testnet3": "fractal-bitcoin.testnet3",
  "fractal-bitcoin-testnet4": "fractal-bitcoin.testnet4",
  "fractal-bitcoin-signet": "fractal-bitcoin.signet",
  "fractal-bitcoin-regtest": "fractal-bitcoin.regtest",
  "kaspa-mainnet": "kaspa.mainnet",
  "kaspa-testnet-10": "kaspa.testnet10",
  "kaspa-testnet-11": "kaspa.testnet11",
  "kaspa-simnet": "kaspa.simnet",
  "kaspa-devnet": "kaspa.devnet",
  "chia-mainnet": "chia.mainnet",
  "chia-testnet11": "chia.testnet11",
  "ergo-mainnet": "ergo.mainnet",
  "ergo-testnet": "ergo.testnet",
} as const satisfies Readonly<Record<string, ChainNetwork>>);

export type RpcPresetId = keyof typeof RPC_PRESET_NETWORKS;

export const RPC_PRESET_IDS = Object.freeze(
  Object.keys(RPC_PRESET_NETWORKS) as RpcPresetId[],
);

const chainNetworkValues: ReadonlySet<string> = new Set(CHAIN_NETWORKS);
const rpcPresetIdValues: ReadonlySet<string> = new Set(RPC_PRESET_IDS);

export function isChainNetwork(value: string): value is ChainNetwork {
  return chainNetworkValues.has(value);
}

export function isRpcPresetId(value: string): value is RpcPresetId {
  return rpcPresetIdValues.has(value);
}

export function resolveRpcPresetNetwork(presetId: string): ChainNetwork {
  if (!isRpcPresetId(presetId)) throw new Error(`unknown RPC preset: ${presetId}`);
  return RPC_PRESET_NETWORKS[presetId];
}

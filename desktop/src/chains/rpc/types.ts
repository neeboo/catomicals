export const CHAIN_IDS = [
  "bitcoin",
  "fractal-bitcoin",
  "bitcoin-cash",
  "bsv",
  "kaspa",
  "chia",
  "ergo",
] as const;

export type ChainId = typeof CHAIN_IDS[number];
export type BitcoinFamilyChainId = Extract<ChainId, "bitcoin" | "fractal-bitcoin" | "bitcoin-cash" | "bsv">;
export type KaspaTransport = "https-api" | "json-rpc" | "wrpc";

interface BaseChainRpcConfig {
  readonly endpoint: string;
  readonly enabled?: boolean;
  readonly networkId?: string;
  readonly credentialRef?: string;
  readonly broadcastEnabled?: boolean;
  readonly timeoutMs?: number;
  readonly maxResponseBytes?: number;
  readonly access?: "local" | "private-network" | "public";
}

export type ChainRpcConfig =
  | (BaseChainRpcConfig & {
    readonly chain: BitcoinFamilyChainId;
    readonly transport?: "json-rpc";
  })
  | (BaseChainRpcConfig & {
    readonly chain: "kaspa";
    readonly transport: KaspaTransport;
  })
  | (BaseChainRpcConfig & {
    readonly chain: "chia";
    readonly transport?: "https-rpc";
  })
  | (BaseChainRpcConfig & {
    readonly chain: "ergo";
    readonly transport?: "rest";
  });

export interface RpcHealth {
  readonly chain: ChainId;
  readonly ok: true;
  readonly latencyMs: number;
}

export interface ChainTip {
  readonly height: number;
  readonly hash?: string;
}

export interface RawChainObject {
  readonly chain: ChainId;
  readonly id: string;
  readonly raw: unknown;
}

export interface BroadcastResult {
  readonly accepted: true;
  readonly transactionId?: string;
}

export interface ChainRpcAdapter {
  readonly chain: ChainId;
  health(): Promise<RpcHealth>;
  getTip(): Promise<ChainTip>;
  getTransaction(transactionId: string): Promise<RawChainObject>;
  broadcast(rawTransaction: string): Promise<BroadcastResult>;
}

export interface SecretHeaderContext {
  readonly chain: ChainId;
  readonly endpointOrigin: string;
}

export type SecretHeaderResolver = (
  credentialRef: string,
  context: SecretHeaderContext,
) => Promise<Readonly<Record<string, string>>>;

export interface ChainRpcAdapterOptions {
  readonly resolveSecretHeaders?: SecretHeaderResolver;
  readonly fetcher?: typeof fetch;
  readonly now?: () => number;
}

export const CHAIN_RPC_PERMISSIONS = ["chain.rpc.read", "chain.rpc.broadcast", "chain.address.read"] as const;

export function chainHealthServiceName(chain: ChainId): string {
  return chain === "bitcoin" ? "bitcoin.node.health" : `chain.${chain}.health`;
}

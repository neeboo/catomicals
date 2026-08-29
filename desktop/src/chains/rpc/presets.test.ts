import { describe, expect, expectTypeOf, it } from "vitest";

import {
  CHAIN_NETWORKS,
  RPC_PRESET_IDS,
  resolveRpcPresetNetwork,
  type RpcPresetId,
} from "../network-contract.js";
import { CHAIN_RPC_PRESETS, chainRpcNetworkIds, resolveChainRpcPreset } from "./presets.js";

describe("chain RPC presets", () => {
  it("covers every concrete chain network and keeps every preset mapping explicit", () => {
    expect(new Set(CHAIN_RPC_PRESETS.map(({ chainNetwork }) => chainNetwork)))
      .toEqual(new Set(CHAIN_NETWORKS));
    expect(CHAIN_RPC_PRESETS.map(({ id }) => id)).toEqual(RPC_PRESET_IDS);

    for (const preset of CHAIN_RPC_PRESETS) {
      expect(resolveRpcPresetNetwork(preset.id)).toBe(preset.chainNetwork);
      expect(preset.chainNetwork.startsWith(`${preset.chain}.`)).toBe(true);
    }
  });

  it("uses the official BCH, BSV, and local Kaspa ports", () => {
    expect(resolveChainRpcPreset("bitcoin-cash", "bitcoin-cash-testnet4").endpoint)
      .toBe("http://127.0.0.1:28332");
    expect(resolveChainRpcPreset("bitcoin-cash", "bitcoin-cash-scalenet").endpoint)
      .toBe("http://127.0.0.1:38332");
    expect(resolveChainRpcPreset("bsv", "bsv-stn").endpoint)
      .toBe("http://127.0.0.1:9332");
    expect(resolveChainRpcPreset("bsv", "bsv-regtest").endpoint)
      .toBe("http://127.0.0.1:18332");
    expect(resolveChainRpcPreset("kaspa", "kaspa-simnet")).toMatchObject({
      endpoint: "http://127.0.0.1:16510",
      transport: "json-rpc",
      access: "local",
      chainNetwork: "kaspa.simnet",
    });
    expect(resolveChainRpcPreset("kaspa", "kaspa-devnet")).toMatchObject({
      endpoint: "http://127.0.0.1:16610",
      transport: "json-rpc",
      access: "local",
      chainNetwork: "kaspa.devnet",
    });
  });

  it("returns typed preset IDs in product order", () => {
    const bitcoinCashPresetIds = chainRpcNetworkIds("bitcoin-cash");
    expectTypeOf(bitcoinCashPresetIds).toEqualTypeOf<readonly RpcPresetId[]>();
    expect(bitcoinCashPresetIds).toEqual([
      "bitcoin-cash-mainnet",
      "bitcoin-cash-testnet3",
      "bitcoin-cash-testnet4",
      "bitcoin-cash-chipnet",
      "bitcoin-cash-scalenet",
      "bitcoin-cash-regtest",
    ]);
  });

  it("rejects unknown or cross-chain preset IDs explicitly", () => {
    expect(() => resolveChainRpcPreset("bitcoin", "mainnet")).toThrow(
      "unsupported bitcoin RPC preset: mainnet",
    );
    expect(() => resolveChainRpcPreset("bitcoin", "ergo-mainnet")).toThrow(
      "RPC preset ergo-mainnet belongs to ergo, not bitcoin",
    );
  });
});

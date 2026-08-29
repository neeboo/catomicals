import { describe, expect, expectTypeOf, it } from "vitest";

import {
  CHAIN_IDS,
  CHAIN_NETWORKS,
  RPC_PRESET_IDS,
  isChainNetwork,
  isRpcPresetId,
  resolveRpcPresetNetwork,
  type ChainNetwork,
  type RpcPresetId,
} from "./network-contract.js";

describe("seven-chain network contract", () => {
  it("keeps the product chain order stable", () => {
    expect(CHAIN_IDS).toEqual([
      "bitcoin",
      "bitcoin-cash",
      "bsv",
      "fractal-bitcoin",
      "kaspa",
      "chia",
      "ergo",
    ]);
    expect(Object.isFrozen(CHAIN_IDS)).toBe(true);
  });

  it("names every supported consensus network concretely", () => {
    expect(CHAIN_NETWORKS).toEqual([
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
    ]);
    expect(Object.isFrozen(CHAIN_NETWORKS)).toBe(true);
  });

  it("keeps consensus networks and RPC preset IDs as distinct types and values", () => {
    expectTypeOf<ChainNetwork>().not.toEqualTypeOf<RpcPresetId>();
    expect(isChainNetwork("bitcoin.signet")).toBe(true);
    expect(isRpcPresetId("bitcoin.signet")).toBe(false);
    expect(isRpcPresetId("bitcoin-inquisition")).toBe(true);
    expect(isChainNetwork("bitcoin-inquisition")).toBe(false);
    expect(RPC_PRESET_IDS).toContain("bitcoin-inquisition");
  });

  it("maps RPC presets to consensus networks explicitly", () => {
    expect(resolveRpcPresetNetwork("bitcoin-inquisition")).toBe("bitcoin.signet");
    expect(resolveRpcPresetNetwork("bitcoin-testnet4")).toBe("bitcoin.testnet4");
    expect(resolveRpcPresetNetwork("bitcoin-cash-scalenet")).toBe("bitcoin-cash.scalenet");
    expect(resolveRpcPresetNetwork("bsv-stn")).toBe("bsv.stn");
    expect(resolveRpcPresetNetwork("kaspa-devnet")).toBe("kaspa.devnet");
    expect(resolveRpcPresetNetwork("chia-testnet11")).toBe("chia.testnet11");
  });

  it("rejects unknown presets and generic address-family names without a Bitcoin fallback", () => {
    expect(() => resolveRpcPresetNetwork("mainnet")).toThrow("unknown RPC preset: mainnet");
    expect(() => resolveRpcPresetNetwork("unknown-preset")).toThrow("unknown RPC preset: unknown-preset");
  });
});

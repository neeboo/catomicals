import { bech32m } from "@scure/base"

import { AddressParseError, bytesToHex } from "./shared.js"
import type { NetworkDescriptor, ParsedAddress } from "./types.js"

const PREFIXES = { mainnet: "xch", testnet: "txch" } as const

export function parseChiaAddress(descriptor: NetworkDescriptor, value: string): ParsedAddress {
  let decoded: ReturnType<typeof bech32m.decode>
  try {
    decoded = bech32m.decode(value, 90)
  } catch {
    throw new AddressParseError("bad-checksum", "invalid Chia Bech32m address")
  }
  const expectedPrefix = PREFIXES[descriptor.networkId as keyof typeof PREFIXES]
  if (decoded.prefix.toLowerCase() !== expectedPrefix) {
    throw new AddressParseError("wrong-network", `expected ${expectedPrefix} Chia address`)
  }
  let puzzleHash: Uint8Array
  try {
    puzzleHash = bech32m.fromWords(decoded.words)
  } catch {
    throw new AddressParseError("invalid-encoding", "invalid Chia address padding")
  }
  if (puzzleHash.length !== 32) throw new AddressParseError("invalid-length", "Chia puzzle hash must be 32 bytes")
  return {
    schemaVersion: 1,
    chainId: descriptor.chainId,
    networkId: descriptor.networkId,
    format: "bech32m",
    addressType: "puzzle-hash",
    canonical: value.toLowerCase(),
    payloadHex: bytesToHex(puzzleHash),
  }
}


import { bech32m } from "@scure/base"

import { AddressParseError, bytesToHex } from "./shared.js"
import type { NetworkDescriptor, ParsedAddress } from "./types.js"

function expectedPrefix(descriptor: NetworkDescriptor): "xch" | "txch" {
  switch (descriptor.chainNetwork) {
    case "chia.mainnet":
      return "xch"
    case "chia.testnet11":
      return "txch"
    default:
      throw new AddressParseError("invalid-descriptor", "unsupported chain or network descriptor")
  }
}

export function parseChiaAddress(descriptor: NetworkDescriptor, value: string): ParsedAddress {
  const normalized = value.toLowerCase()
  const separator = normalized.lastIndexOf("1")
  if (
    separator <= 0 ||
    separator === normalized.length - 1 ||
    !/^[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+$/u.test(normalized.slice(separator + 1))
  ) {
    throw new AddressParseError("invalid-encoding", "invalid Chia Bech32m characters")
  }
  let decoded: ReturnType<typeof bech32m.decode>
  try {
    decoded = bech32m.decode(value, 90)
  } catch {
    throw new AddressParseError("bad-checksum", "invalid Chia Bech32m address")
  }
  const expected = expectedPrefix(descriptor)
  if (decoded.prefix.toLowerCase() !== expected) {
    throw new AddressParseError("wrong-network", `expected ${expected} Chia address`)
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
    chainNetwork: descriptor.chainNetwork,
    format: "bech32m",
    addressType: "puzzle-hash",
    canonical: normalized,
    payloadHex: bytesToHex(puzzleHash),
  }
}

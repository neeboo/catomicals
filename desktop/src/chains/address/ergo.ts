import { base58 } from "@scure/base"
import { blake2b } from "@noble/hashes/blake2.js"

import { AddressParseError, bytesToHex } from "./shared.js"
import type { AddressType, NetworkDescriptor, ParsedAddress } from "./types.js"

function expectedNetworkNibble(descriptor: NetworkDescriptor): 0x00 | 0x10 {
  switch (descriptor.chainNetwork) {
    case "ergo.mainnet":
      return 0x00
    case "ergo.testnet":
      return 0x10
    default:
      throw new AddressParseError("invalid-descriptor", "unsupported chain or network descriptor")
  }
}

export function parseErgoAddress(descriptor: NetworkDescriptor, value: string): ParsedAddress {
  let decoded: Uint8Array
  try {
    decoded = base58.decode(value)
  } catch {
    throw new AddressParseError("invalid-encoding", "invalid Ergo Base58 encoding")
  }
  if (base58.encode(decoded) !== value) throw new AddressParseError("invalid-encoding", "non-canonical Ergo Base58 encoding")
  if (decoded.length < 6) throw new AddressParseError("invalid-length", "Ergo address is too short")
  const body = decoded.subarray(0, -4)
  const checksum = decoded.subarray(-4)
  const expectedChecksum = blake2b(body, { dkLen: 32 }).subarray(0, 4)
  if (!Buffer.from(checksum).equals(expectedChecksum)) {
    throw new AddressParseError("bad-checksum", "invalid Ergo address checksum")
  }
  const head = body[0]!
  const expectedNetwork = expectedNetworkNibble(descriptor)
  if ((head & 0xf0) !== expectedNetwork) throw new AddressParseError("wrong-network", "Ergo address belongs to another network")
  const type = head & 0x0f
  const addressTypes: Readonly<Record<number, AddressType>> = { 1: "p2pk", 2: "p2sh", 3: "p2s" }
  const addressType = addressTypes[type]
  if (!addressType) throw new AddressParseError("unsupported-address-type", "unsupported Ergo address type")
  const payload = body.subarray(1)
  if (addressType === "p2pk" && (payload.length !== 33 || (payload[0] !== 0x02 && payload[0] !== 0x03))) {
    throw new AddressParseError("invalid-length", "Ergo P2PK payload must contain a compressed public key")
  }
  if (addressType === "p2sh" && payload.length !== 24) {
    throw new AddressParseError("invalid-length", "Ergo P2SH payload must contain a 24 byte script hash")
  }
  if (addressType === "p2s" && payload.length === 0) throw new AddressParseError("invalid-length", "Ergo P2S payload is empty")
  return {
    schemaVersion: 1,
    chainId: descriptor.chainId,
    chainNetwork: descriptor.chainNetwork,
    format: "ergo-base58",
    addressType,
    canonical: value,
    payloadHex: bytesToHex(payload),
  }
}

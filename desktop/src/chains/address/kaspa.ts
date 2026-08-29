import { AddressParseError, bytesToHex, cashaddrPolymod, cashaddrPrefixWords, convertBits } from "./shared.js"
import type { AddressType, NetworkDescriptor, ParsedAddress } from "./types.js"

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
const PREFIXES = { mainnet: "kaspa", testnet: "kaspatest", simnet: "kaspasim" } as const

function checksumValue(words: readonly number[]): bigint {
  return words.reduce((value, word) => (value << 5n) | BigInt(word), 0n)
}

export function parseKaspaAddress(descriptor: NetworkDescriptor, value: string): ParsedAddress {
  const normalized = value.toLowerCase()
  const separator = normalized.indexOf(":")
  if (separator < 0) throw new AddressParseError("missing-prefix", "Kaspa address prefix is required")
  if (separator === 0 || separator !== normalized.lastIndexOf(":")) {
    throw new AddressParseError("invalid-encoding", "Kaspa address must contain exactly one prefix separator")
  }
  const prefix = normalized.slice(0, separator)
  const expectedPrefix = PREFIXES[descriptor.networkId as keyof typeof PREFIXES]
  if (prefix !== expectedPrefix) throw new AddressParseError("wrong-network", `expected ${expectedPrefix} address prefix`)
  const encoded = normalized.slice(separator + 1)
  if (encoded.length < 9) throw new AddressParseError("invalid-length", "Kaspa address payload is too short")
  const words = [...encoded].map((character) => {
    const value = CHARSET.indexOf(character)
    if (value < 0) throw new AddressParseError("invalid-encoding", "Kaspa address contains an invalid character")
    return value
  })
  const payloadWords = words.slice(0, -8)
  const expectedChecksum = cashaddrPolymod([
    ...cashaddrPrefixWords(prefix),
    0,
    ...payloadWords,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
  ])
  if (checksumValue(words.slice(-8)) !== expectedChecksum) {
    throw new AddressParseError("bad-checksum", "invalid Kaspa address checksum")
  }
  const body = convertBits(payloadWords, 5, 8, false)
  if (body.length < 2) throw new AddressParseError("invalid-length", "Kaspa address body is too short")
  const version = body[0]!
  const addressTypes: Readonly<Record<number, { type: AddressType; length: number }>> = {
    0: { type: "pubkey", length: 32 },
    1: { type: "pubkey-ecdsa", length: 33 },
    8: { type: "script-hash", length: 32 },
  }
  const address = addressTypes[version]
  if (!address) throw new AddressParseError("unsupported-address-type", "unsupported Kaspa address version")
  const payload = body.subarray(1)
  if (payload.length !== address.length) throw new AddressParseError("invalid-length", "Kaspa payload length does not match its version")
  return {
    schemaVersion: 1,
    chainId: descriptor.chainId,
    networkId: descriptor.networkId,
    format: "kaspa",
    addressType: address.type,
    canonical: normalized,
    payloadHex: bytesToHex(payload),
  }
}


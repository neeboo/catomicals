import { AddressParseError, bytesToHex, cashaddrPolymod, cashaddrPrefixWords, convertBits } from "./shared.js"
import type { AddressType, NetworkDescriptor, ParsedAddress } from "./types.js"

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
const HASH_LENGTHS = [20, 24, 28, 32, 40, 48, 56, 64] as const
const PREFIXES = { mainnet: "bitcoincash", testnet: "bchtest", regtest: "bchreg" } as const

export function parseCashAddress(descriptor: NetworkDescriptor, value: string): ParsedAddress {
  const normalized = value.toLowerCase()
  const separator = normalized.indexOf(":")
  if (separator < 0) throw new AddressParseError("missing-prefix", "CashAddr prefix is required")
  if (separator === 0 || separator !== normalized.lastIndexOf(":")) {
    throw new AddressParseError("invalid-encoding", "CashAddr must contain exactly one prefix separator")
  }
  const prefix = normalized.slice(0, separator)
  const expectedPrefix = PREFIXES[descriptor.networkId as keyof typeof PREFIXES]
  if (prefix !== expectedPrefix) throw new AddressParseError("wrong-network", `expected ${expectedPrefix} CashAddr prefix`)
  const encoded = normalized.slice(separator + 1)
  if (encoded.length < 9) throw new AddressParseError("invalid-length", "CashAddr payload is too short")
  const words = [...encoded].map((character) => {
    const value = CHARSET.indexOf(character)
    if (value < 0) throw new AddressParseError("invalid-encoding", "CashAddr contains an invalid character")
    return value
  })
  if (cashaddrPolymod([...cashaddrPrefixWords(prefix), 0, ...words]) !== 0n) {
    throw new AddressParseError("bad-checksum", "invalid CashAddr checksum")
  }
  const bodyWords = words.slice(0, -8)
  const body = convertBits(bodyWords, 5, 8, false)
  if (body.length < 2) throw new AddressParseError("invalid-length", "CashAddr body is too short")
  const version = body[0]!
  if ((version & 0x80) !== 0) throw new AddressParseError("unsupported-address-type", "reserved CashAddr version bit is set")
  const hash = body.subarray(1)
  if (hash.length !== HASH_LENGTHS[version & 0x07]) {
    throw new AddressParseError("invalid-length", "CashAddr hash length does not match its version")
  }
  const type = version >> 3
  const addressTypes: Readonly<Record<number, AddressType>> = {
    0: "p2pkh",
    1: "p2sh",
    2: "token-p2pkh",
    3: "token-p2sh",
  }
  const addressType = addressTypes[type]
  if (!addressType) throw new AddressParseError("unsupported-address-type", "unsupported CashAddr address type")
  return {
    schemaVersion: 1,
    chainId: descriptor.chainId,
    networkId: descriptor.networkId,
    format: "cashaddr",
    addressType,
    canonical: normalized,
    payloadHex: bytesToHex(hash),
  }
}


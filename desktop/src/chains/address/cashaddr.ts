import { AddressParseError, bytesToHex, cashaddrPolymod, cashaddrPrefixWords, convertBits } from "./shared.js"
import type { AddressParseOptions, AddressType, NetworkDescriptor, ParsedAddress } from "./types.js"

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
const HASH_LENGTHS = [20, 24, 28, 32, 40, 48, 56, 64] as const

function expectedPrefix(descriptor: NetworkDescriptor): "bitcoincash" | "bchtest" | "bchreg" {
  switch (descriptor.chainNetwork) {
    case "bitcoin-cash.mainnet":
      return "bitcoincash"
    case "bitcoin-cash.testnet3":
    case "bitcoin-cash.testnet4":
    case "bitcoin-cash.chipnet":
    case "bitcoin-cash.scalenet":
      return "bchtest"
    case "bitcoin-cash.regtest":
      return "bchreg"
    default:
      throw new AddressParseError("invalid-descriptor", "unsupported chain or network descriptor")
  }
}

export function parseCashAddress(
  descriptor: NetworkDescriptor,
  value: string,
  options: AddressParseOptions,
): ParsedAddress {
  const normalized = value.toLowerCase()
  const separator = normalized.indexOf(":")
  if (separator < 0 && !options.allowPrefixlessCashAddr) {
    throw new AddressParseError("missing-prefix", "CashAddr prefix is required")
  }
  if (separator === 0 || (separator >= 0 && separator !== normalized.lastIndexOf(":"))) {
    throw new AddressParseError("invalid-encoding", "CashAddr must contain exactly one prefix separator")
  }
  const expected = expectedPrefix(descriptor)
  const prefix = separator < 0 ? expected : normalized.slice(0, separator)
  if (prefix !== expected) throw new AddressParseError("wrong-network", `expected ${expected} CashAddr prefix`)
  const encoded = separator < 0 ? normalized : normalized.slice(separator + 1)
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
  if ((addressType === "token-p2pkh" || addressType === "token-p2sh") && !options.allowCashTokens) {
    throw new AddressParseError("unsupported-address-type", "token-aware CashAddr capability is disabled")
  }
  return {
    schemaVersion: 1,
    chainId: descriptor.chainId,
    chainNetwork: descriptor.chainNetwork,
    format: "cashaddr",
    addressType,
    canonical: `${prefix}:${encoded}`,
    payloadHex: bytesToHex(hash),
  }
}

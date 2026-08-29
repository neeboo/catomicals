import { bech32, bech32m } from "@scure/base"

import { AddressParseError, bytesToHex, decodeBase58Check } from "./shared.js"
import type { AddressType, NetworkDescriptor, ParsedAddress } from "./types.js"

interface BitcoinAddressParameters {
  readonly hrp: "bc" | "tb" | "bcrt"
  readonly p2pkh: number
  readonly p2sh: number
}

function networkParameters(descriptor: NetworkDescriptor): BitcoinAddressParameters {
  switch (descriptor.chainNetwork) {
    case "bitcoin.mainnet":
    case "fractal-bitcoin.mainnet":
    case "bsv.mainnet":
      return { hrp: "bc", p2pkh: 0x00, p2sh: 0x05 }
    case "bitcoin.testnet3":
    case "bitcoin.testnet4":
    case "bitcoin.signet":
    case "fractal-bitcoin.testnet3":
    case "fractal-bitcoin.testnet4":
    case "fractal-bitcoin.signet":
    case "bsv.testnet":
    case "bsv.stn":
      return { hrp: "tb", p2pkh: 0x6f, p2sh: 0xc4 }
    case "bitcoin.regtest":
    case "fractal-bitcoin.regtest":
    case "bsv.regtest":
      return { hrp: "bcrt", p2pkh: 0x6f, p2sh: 0xc4 }
    default:
      throw new AddressParseError("invalid-descriptor", "unsupported chain or network descriptor")
  }
}

function parsed(
  descriptor: NetworkDescriptor,
  format: ParsedAddress["format"],
  addressType: AddressType,
  canonical: string,
  payload: Uint8Array,
  witnessVersion?: number,
): ParsedAddress {
  return {
    schemaVersion: 1,
    chainId: descriptor.chainId,
    chainNetwork: descriptor.chainNetwork,
    format,
    addressType,
    canonical,
    payloadHex: bytesToHex(payload),
    ...(witnessVersion === undefined ? {} : { witnessVersion }),
  }
}

function parseSegwit(descriptor: NetworkDescriptor, value: string): ParsedAddress {
  const parameters = networkParameters(descriptor)
  const normalized = value.toLowerCase()
  let decodedBech32: ReturnType<typeof bech32.decode> | undefined
  let decodedBech32m: ReturnType<typeof bech32m.decode> | undefined
  try {
    decodedBech32 = bech32.decode(value, 90)
  } catch {
    // Checked as Bech32m below.
  }
  try {
    decodedBech32m = bech32m.decode(value, 90)
  } catch {
    // The combined failure is reported below.
  }
  const decoded = decodedBech32 ?? decodedBech32m
  if (!decoded) throw new AddressParseError("invalid-encoding", "invalid SegWit checksum or encoding")
  if (decoded.prefix.toLowerCase() !== parameters.hrp) {
    throw new AddressParseError("wrong-network", `expected ${parameters.hrp} SegWit address`)
  }
  if (decoded.words.length < 2) throw new AddressParseError("invalid-length", "SegWit address has no witness program")
  const witnessVersion = decoded.words[0]!
  if (witnessVersion > 16) throw new AddressParseError("unsupported-address-type", "unsupported witness version")
  let program: Uint8Array
  try {
    program = bech32.fromWords(decoded.words.slice(1))
  } catch {
    throw new AddressParseError("invalid-encoding", "invalid SegWit conversion padding")
  }
  if (program.length < 2 || program.length > 40) {
    throw new AddressParseError("invalid-length", "witness program must contain 2 to 40 bytes")
  }
  if (witnessVersion === 0) {
    if (!decodedBech32 || (program.length !== 20 && program.length !== 32)) {
      throw new AddressParseError("invalid-encoding", "witness v0 requires Bech32 and a 20 or 32 byte program")
    }
  } else if (!decodedBech32m) {
    throw new AddressParseError("invalid-encoding", "witness v1+ requires Bech32m")
  }
  const addressType: AddressType =
    witnessVersion === 0 ? (program.length === 20 ? "p2wpkh" : "p2wsh") : witnessVersion === 1 && program.length === 32 ? "p2tr" : "witness-unknown"
  return parsed(descriptor, witnessVersion === 0 ? "bech32" : "bech32m", addressType, normalized, program, witnessVersion)
}

export function parseBitcoinFamilyAddress(descriptor: NetworkDescriptor, value: string): ParsedAddress {
  if (descriptor.chainId === "bsv") {
    if (/^(?:bc|tb|bcrt)1/iu.test(value)) {
      throw new AddressParseError("unsupported-address-type", "BSV does not support native SegWit addresses")
    }
  } else if (/^(?:bc|tb|bcrt)1/iu.test(value)) {
    return parseSegwit(descriptor, value)
  }

  const parameters = networkParameters(descriptor)
  const { version, payload } = decodeBase58Check(value)
  if (version !== parameters.p2pkh && version !== parameters.p2sh) {
    const knownVersion = version === 0x00 || version === 0x05 || version === 0x6f || version === 0xc4
    throw new AddressParseError(
      knownVersion ? "wrong-network" : "unsupported-address-type",
      knownVersion ? "Base58Check address belongs to another network" : "unsupported Base58Check version",
    )
  }
  return parsed(descriptor, "base58check", version === parameters.p2pkh ? "p2pkh" : "p2sh", value, payload)
}

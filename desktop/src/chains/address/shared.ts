import { createHash } from "node:crypto"

import { base58 } from "@scure/base"

import type { AddressErrorCode, AddressParseOptions, ChainId, NetworkDescriptor, NetworkId } from "./types.js"

const NETWORKS: Readonly<Record<ChainId, readonly NetworkId[]>> = {
  bitcoin: ["mainnet", "testnet", "signet", "regtest"],
  "fractal-bitcoin": ["mainnet", "testnet"],
  "bitcoin-cash": ["mainnet", "testnet", "regtest"],
  bsv: ["mainnet", "testnet", "regtest"],
  kaspa: ["mainnet", "testnet", "simnet"],
  chia: ["mainnet", "testnet"],
  ergo: ["mainnet", "testnet"],
}

export class AddressParseError extends Error {
  constructor(
    readonly code: AddressErrorCode,
    message: string,
  ) {
    super(message)
    this.name = "AddressParseError"
  }
}

export function assertDescriptor(value: NetworkDescriptor): void {
  if (
    typeof value !== "object" ||
    value === null ||
    Object.keys(value).length !== 3 ||
    value.schemaVersion !== 1 ||
    !Object.hasOwn(NETWORKS, value.chainId) ||
    !NETWORKS[value.chainId].includes(value.networkId)
  ) {
    throw new AddressParseError("invalid-descriptor", "unsupported chain or network descriptor")
  }
}

export function assertParseOptions(value: AddressParseOptions): void {
  if (
    typeof value !== "object" ||
    value === null ||
    Object.keys(value).length !== 3 ||
    value.schemaVersion !== 1 ||
    typeof value.allowPrefixlessCashAddr !== "boolean" ||
    typeof value.allowCashTokens !== "boolean"
  ) {
    throw new AddressParseError("invalid-descriptor", "invalid address parsing options")
  }
}

export function assertAddressInput(value: string): void {
  if (typeof value !== "string" || value.length === 0 || value !== value.trim() || /[\s\u0000-\u001f\u007f]/u.test(value)) {
    throw new AddressParseError("invalid-encoding", "address must be non-empty text without whitespace")
  }
  if (value.length > 2_048) {
    throw new AddressParseError("input-too-long", "address exceeds the 2048 character limit")
  }
}

export function assertChainAddressLength(descriptor: NetworkDescriptor, value: string): void {
  const limits: Readonly<Record<ChainId, number>> = {
    bitcoin: 90,
    "fractal-bitcoin": 90,
    "bitcoin-cash": 128,
    bsv: 64,
    kaspa: 90,
    chia: 90,
    ergo: 2_048,
  }
  if (value.length > limits[descriptor.chainId]) {
    throw new AddressParseError("input-too-long", `address exceeds the ${limits[descriptor.chainId]} character chain limit`)
  }
}

export function assertNotMixedCase(value: string): void {
  const letters = value.replace(/[^A-Za-z]/gu, "")
  if (letters !== letters.toLowerCase() && letters !== letters.toUpperCase()) {
    throw new AddressParseError("mixed-case", "mixed-case address is not allowed")
  }
}

export function bytesToHex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex")
}

function sha256(value: Uint8Array): Uint8Array {
  return createHash("sha256").update(value).digest()
}

export function decodeBase58Check(value: string): { version: number; payload: Uint8Array } {
  let decoded: Uint8Array
  try {
    decoded = base58.decode(value)
  } catch {
    throw new AddressParseError("invalid-encoding", "invalid Base58 encoding")
  }
  if (base58.encode(decoded) !== value) {
    throw new AddressParseError("invalid-encoding", "non-canonical Base58 encoding")
  }
  if (decoded.length !== 25) {
    throw new AddressParseError("invalid-length", "Base58Check payment address must decode to 25 bytes")
  }
  const body = decoded.subarray(0, 21)
  const checksum = decoded.subarray(21)
  const expected = sha256(sha256(body)).subarray(0, 4)
  if (!Buffer.from(checksum).equals(expected)) {
    throw new AddressParseError("bad-checksum", "invalid Base58Check checksum")
  }
  return { version: body[0]!, payload: body.subarray(1) }
}

export function convertBits(data: readonly number[], fromBits: number, toBits: number, pad: boolean): Uint8Array {
  let accumulator = 0
  let bitCount = 0
  const maxValue = (1 << toBits) - 1
  const maxAccumulator = (1 << (fromBits + toBits - 1)) - 1
  const output: number[] = []

  for (const value of data) {
    if (value < 0 || value >> fromBits !== 0) {
      throw new AddressParseError("invalid-encoding", "address contains an out-of-range symbol")
    }
    accumulator = ((accumulator << fromBits) | value) & maxAccumulator
    bitCount += fromBits
    while (bitCount >= toBits) {
      bitCount -= toBits
      output.push((accumulator >> bitCount) & maxValue)
    }
  }

  if (pad) {
    if (bitCount > 0) output.push((accumulator << (toBits - bitCount)) & maxValue)
  } else if (bitCount >= fromBits || ((accumulator << (toBits - bitCount)) & maxValue) !== 0) {
    throw new AddressParseError("invalid-encoding", "address has invalid conversion padding")
  }
  return Uint8Array.from(output)
}

const CASHADDR_GENERATORS = [0x98f2bc8e61n, 0x79b76d99e2n, 0xf33e5fb3c4n, 0xae2eabe2a8n, 0x1e4f43e470n] as const

export function cashaddrPolymod(values: readonly number[]): bigint {
  let checksum = 1n
  for (const value of values) {
    const high = checksum >> 35n
    checksum = ((checksum & 0x07ffffffffn) << 5n) ^ BigInt(value)
    for (let index = 0; index < CASHADDR_GENERATORS.length; index += 1) {
      if (((high >> BigInt(index)) & 1n) !== 0n) checksum ^= CASHADDR_GENERATORS[index]!
    }
  }
  return checksum ^ 1n
}

export function cashaddrPrefixWords(prefix: string): number[] {
  return [...prefix].map((character) => character.charCodeAt(0) & 31)
}

export const CHAIN_IDS = [
  "bitcoin",
  "fractal-bitcoin",
  "bitcoin-cash",
  "bsv",
  "kaspa",
  "chia",
  "ergo",
] as const

export type ChainId = (typeof CHAIN_IDS)[number]

export type NetworkId = "mainnet" | "testnet" | "signet" | "regtest" | "simnet"

export interface NetworkDescriptor {
  readonly schemaVersion: 1
  readonly chainId: ChainId
  readonly networkId: NetworkId
}

export type AddressFormat = "base58check" | "bech32" | "bech32m" | "cashaddr" | "kaspa" | "ergo-base58"

export type AddressType =
  | "p2pkh"
  | "p2sh"
  | "p2wpkh"
  | "p2wsh"
  | "p2tr"
  | "witness-unknown"
  | "token-p2pkh"
  | "token-p2sh"
  | "pubkey"
  | "pubkey-ecdsa"
  | "script-hash"
  | "puzzle-hash"
  | "p2pk"
  | "p2s"

export interface ParsedAddress {
  readonly schemaVersion: 1
  readonly chainId: ChainId
  readonly networkId: NetworkId
  readonly format: AddressFormat
  readonly addressType: AddressType
  readonly canonical: string
  readonly payloadHex: string
  readonly witnessVersion?: number
}

export type AddressErrorCode =
  | "invalid-descriptor"
  | "input-too-long"
  | "invalid-encoding"
  | "bad-checksum"
  | "wrong-network"
  | "unsupported-address-type"
  | "mixed-case"
  | "missing-prefix"
  | "invalid-length"

export interface AddressValidationError {
  readonly schemaVersion: 1
  readonly code: AddressErrorCode
  readonly message: string
}

export type AddressValidation =
  | { readonly schemaVersion: 1; readonly valid: true; readonly parsed: ParsedAddress }
  | { readonly schemaVersion: 1; readonly valid: false; readonly error: AddressValidationError }


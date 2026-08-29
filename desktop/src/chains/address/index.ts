import { parseBitcoinFamilyAddress } from "./bitcoin.js"
import { parseCashAddress } from "./cashaddr.js"
import { parseChiaAddress } from "./chia.js"
import { parseErgoAddress } from "./ergo.js"
import { parseKaspaAddress } from "./kaspa.js"
import {
  AddressParseError,
  assertAddressInput,
  assertChainAddressLength,
  assertDescriptor,
  assertNotMixedCase,
} from "./shared.js"
import type { AddressValidation, NetworkDescriptor, ParsedAddress } from "./types.js"

export { AddressParseError } from "./shared.js"
export type {
  AddressErrorCode,
  AddressFormat,
  AddressType,
  AddressValidation,
  AddressValidationError,
  ChainId,
  NetworkDescriptor,
  NetworkId,
  ParsedAddress,
} from "./types.js"
export { CHAIN_IDS } from "./types.js"

export function parseAddress(descriptor: NetworkDescriptor, value: string): ParsedAddress {
  assertDescriptor(descriptor)
  assertAddressInput(value)
  assertChainAddressLength(descriptor, value)
  const isBitcoinBech32 =
    (descriptor.chainId === "bitcoin" || descriptor.chainId === "fractal-bitcoin") &&
    /^(?:bc|tb|bcrt)1/iu.test(value)
  if (isBitcoinBech32 || ["bitcoin-cash", "kaspa", "chia"].includes(descriptor.chainId)) {
    assertNotMixedCase(value)
  }

  switch (descriptor.chainId) {
    case "bitcoin":
    case "fractal-bitcoin":
    case "bsv":
      return parseBitcoinFamilyAddress(descriptor, value)
    case "bitcoin-cash":
      return parseCashAddress(descriptor, value)
    case "kaspa":
      return parseKaspaAddress(descriptor, value)
    case "chia":
      return parseChiaAddress(descriptor, value)
    case "ergo":
      return parseErgoAddress(descriptor, value)
  }
}

export function canonicalizeAddress(descriptor: NetworkDescriptor, value: string): string {
  return parseAddress(descriptor, value).canonical
}

export function validateAddress(descriptor: NetworkDescriptor, value: string): AddressValidation {
  try {
    return { schemaVersion: 1, valid: true, parsed: parseAddress(descriptor, value) }
  } catch (error) {
    const parsedError =
      error instanceof AddressParseError
        ? error
        : new AddressParseError("invalid-encoding", "address validation failed")
    return {
      schemaVersion: 1,
      valid: false,
      error: { schemaVersion: 1, code: parsedError.code, message: parsedError.message },
    }
  }
}

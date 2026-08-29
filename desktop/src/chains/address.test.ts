import { describe, expect, it } from "vitest"

import {
  AddressParseError,
  canonicalizeAddress,
  parseAddress,
  validateAddress,
  type NetworkDescriptor,
} from "./address/index.js"

const network = (
  chainId: NetworkDescriptor["chainId"],
  networkId: NetworkDescriptor["networkId"],
): NetworkDescriptor => ({ schemaVersion: 1, chainId, networkId })

const expectError = (operation: () => unknown, code: AddressParseError["code"]) => {
  try {
    operation()
    throw new Error("expected address parsing to fail")
  } catch (error) {
    expect(error).toBeInstanceOf(AddressParseError)
    expect((error as AddressParseError).code).toBe(code)
  }
}

describe("Bitcoin-family addresses", () => {
  it("parses Base58Check and native SegWit addresses for Bitcoin", () => {
    const legacy = parseAddress(network("bitcoin", "mainnet"), "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    expect(legacy).toMatchObject({
      schemaVersion: 1,
      chainId: "bitcoin",
      networkId: "mainnet",
      format: "base58check",
      addressType: "p2pkh",
      canonical: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    })

    const segwit = parseAddress(
      network("bitcoin", "mainnet"),
      "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
    )
    expect(segwit).toMatchObject({
      format: "bech32",
      addressType: "p2wpkh",
      canonical: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    })

    const taproot = parseAddress(
      network("bitcoin", "mainnet"),
      "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
    )
    expect(taproot).toMatchObject({ format: "bech32m", addressType: "p2tr", witnessVersion: 1 })
  })

  it("binds identical Fractal and Bitcoin strings to the explicit chain context", () => {
    const address = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
    expect(parseAddress(network("bitcoin", "mainnet"), address).chainId).toBe("bitcoin")
    expect(parseAddress(network("fractal-bitcoin", "mainnet"), address).chainId).toBe("fractal-bitcoin")
  })

  it("rejects wrong networks, invalid witness encodings, mixed case and bad checksums", () => {
    expectError(
      () => parseAddress(network("bitcoin", "testnet"), "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
      "wrong-network",
    )
    expectError(
      () =>
        parseAddress(
          network("bitcoin", "mainnet"),
          "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
        ),
      "invalid-encoding",
    )
    expectError(
      () =>
        parseAddress(
          network("bitcoin", "testnet"),
          "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
        ),
      "mixed-case",
    )
    expectError(
      () => parseAddress(network("bitcoin", "mainnet"), "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"),
      "bad-checksum",
    )
  })

  it("accepts only Base58Check payment addresses for BSV", () => {
    const parsed = parseAddress(network("bsv", "mainnet"), "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    expect(parsed).toMatchObject({ chainId: "bsv", addressType: "p2pkh", format: "base58check" })
    expectError(
      () =>
        parseAddress(
          network("bsv", "mainnet"),
          "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        ),
      "unsupported-address-type",
    )
  })
})

describe("Bitcoin Cash addresses", () => {
  it("parses prefixed mainnet and testnet CashAddr values", () => {
    const mainnet = parseAddress(
      network("bitcoin-cash", "mainnet"),
      "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",
    )
    expect(mainnet).toMatchObject({
      chainId: "bitcoin-cash",
      networkId: "mainnet",
      format: "cashaddr",
      addressType: "p2pkh",
    })

    const testnet = parseAddress(
      network("bitcoin-cash", "testnet"),
      "BCHTEST:PR6M7J9NJLdWWZLG9V7V53UNLR4JKMX6EYVWC0UZ5T".toUpperCase(),
    )
    expect(testnet).toMatchObject({
      networkId: "testnet",
      addressType: "p2sh",
      canonical: "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t",
    })
  })

  it("requires an explicit CashAddr prefix and rejects mixed case and wrong networks", () => {
    expectError(
      () =>
        parseAddress(
          network("bitcoin-cash", "mainnet"),
          "qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",
        ),
      "missing-prefix",
    )
    expectError(
      () =>
        parseAddress(
          network("bitcoin-cash", "mainnet"),
          "bitcoincash:Qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",
        ),
      "mixed-case",
    )
    expectError(
      () =>
        parseAddress(
          network("bitcoin-cash", "testnet"),
          "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",
        ),
      "wrong-network",
    )
  })
})

describe("Kaspa addresses", () => {
  it.each([
    ["mainnet", "kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e"],
    ["testnet", "kaspatest:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhqrxplya"],
    ["simnet", "kaspasim:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqekcujlt2"],
  ] as const)("parses a %s address with the official checksum", (networkId, address) => {
    const parsed = parseAddress(network("kaspa", networkId), address)
    expect(parsed).toMatchObject({ chainId: "kaspa", networkId, format: "kaspa", addressType: "pubkey" })
  })

  it("rejects the wrong prefix, malformed checksum and mixed case", () => {
    const mainnet = "kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e"
    expectError(() => parseAddress(network("kaspa", "testnet"), mainnet), "wrong-network")
    expectError(
      () => parseAddress(network("kaspa", "mainnet"), `${mainnet.slice(0, -1)}l`),
      "bad-checksum",
    )
    expectError(
      () => parseAddress(network("kaspa", "mainnet"), `K${mainnet.slice(1)}`),
      "mixed-case",
    )
  })
})

describe("Chia addresses", () => {
  it("parses and canonicalizes 32-byte Bech32m puzzle hashes", () => {
    const parsed = parseAddress(
      network("chia", "mainnet"),
      "XCH1PWRZYY35QXK0RZ76JL0648FVT6QL905VWD7ZS0SCJQANT5SF25LQL4HZ3Z",
    )
    expect(parsed).toMatchObject({
      chainId: "chia",
      networkId: "mainnet",
      format: "bech32m",
      addressType: "puzzle-hash",
      canonical: "xch1pwrzyy35qxk0rz76jl0648fvt6ql905vwd7zs0scjqant5sf25lql4hz3z",
    })
    expect(parsed.payloadHex).toBe("0b8622123401acf18bda97dfaa9d2c5e81f2be8c737c283e18903b35d209553e")
  })

  it("rejects wrong networks and Bech32 rather than Bech32m", () => {
    expectError(
      () =>
        parseAddress(
          network("chia", "testnet"),
          "xch1pwrzyy35qxk0rz76jl0648fvt6ql905vwd7zs0scjqant5sf25lql4hz3z",
        ),
      "wrong-network",
    )
    expectError(
      () =>
        parseAddress(
          network("chia", "mainnet"),
          "xch1pwrzyy35qxk0rz76jl0648fvt6ql905vwd7zs0scjqant5sf25lql4hz3q",
        ),
      "bad-checksum",
    )
  })
})

describe("Ergo addresses", () => {
  it.each([
    ["mainnet", "9fRAWhdxEsTcdb8PhGNrZfwqa65zfkuYHAMmkQLcic1gdLSV5vA"],
    ["testnet", "3WvsT2Gm4EpsM9Pg18PdY6XyhNNMqXDsvJTbbf6ihLvAmSb7u5RN"],
  ] as const)("parses a %s P2PK address", (networkId, address) => {
    const parsed = parseAddress(network("ergo", networkId), address)
    expect(parsed).toMatchObject({ chainId: "ergo", networkId, format: "ergo-base58", addressType: "p2pk" })
  })

  it("checks network/type byte and BLAKE2b-256 checksum", () => {
    expectError(
      () =>
        parseAddress(
          network("ergo", "testnet"),
          "9fRAWhdxEsTcdb8PhGNrZfwqa65zfkuYHAMmkQLcic1gdLSV5vA",
        ),
      "wrong-network",
    )
    expectError(
      () =>
        parseAddress(
          network("ergo", "mainnet"),
          "9fRAWhdxEsTcdb8PhGNrZfwqa65zfkuYHAMmkQLcic1gdLSV5vB",
        ),
      "bad-checksum",
    )
  })
})

describe("strict address boundary", () => {
  it("returns a versioned non-throwing validation result", () => {
    expect(
      validateAddress(network("bitcoin", "mainnet"), "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
    ).toMatchObject({ schemaVersion: 1, valid: true, parsed: { chainId: "bitcoin" } })
    expect(validateAddress(network("bitcoin", "mainnet"), "not-an-address")).toMatchObject({
      schemaVersion: 1,
      valid: false,
      error: { code: "invalid-encoding" },
    })
  })

  it("rejects invalid descriptors, surrounding whitespace, and overlong inputs", () => {
    expectError(
      () =>
        parseAddress(
          { schemaVersion: 2, chainId: "bitcoin", networkId: "mainnet" } as unknown as NetworkDescriptor,
          "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        ),
      "invalid-descriptor",
    )
    expectError(
      () =>
        parseAddress(
          { schemaVersion: 1, chainId: "bitcoin", networkId: "mainnet", inferred: true } as unknown as NetworkDescriptor,
          "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        ),
      "invalid-descriptor",
    )
    expectError(
      () => parseAddress(network("bitcoin", "mainnet"), " 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
      "invalid-encoding",
    )
    expectError(
      () => parseAddress(network("ergo", "mainnet"), "1".repeat(2_049)),
      "input-too-long",
    )
    expectError(
      () => parseAddress(network("bitcoin", "mainnet"), "1".repeat(91)),
      "input-too-long",
    )
  })

  it("canonicalizes only after complete validation", () => {
    expect(
      canonicalizeAddress(
        network("bitcoin", "mainnet"),
        "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
      ),
    ).toBe("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    expectError(
      () => canonicalizeAddress(network("bitcoin", "mainnet"), "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"),
      "bad-checksum",
    )
  })
})

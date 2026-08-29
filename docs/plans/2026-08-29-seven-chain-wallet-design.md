# Seven-chain wallet design

## Goal

Catomicals exposes one wallet experience for Bitcoin, Bitcoin Cash, BSV,
Fractal Bitcoin, Kaspa, Chia, and Ergo. Each supported network must have an
explicit address format, derivation policy, transaction review implementation,
signing suite, independent verification path, and broadcast adapter.

The user-facing custody policy remains 2-of-3. The cryptographic mechanism may
differ by chain because the final signature must remain byte-for-byte compatible
with that chain's consensus rules.

## Product contract

For every activated `(chain, network)` profile, the wallet provides:

1. deterministic address derivation from an account profile;
2. strict address parsing with explicit chain and network context;
3. local reconstruction of the transaction signing message;
4. Passkey-authorized signing through a declared signer topology;
5. independent local verification of the final signature;
6. node preflight and broadcast through the matching network profile.

Address text is never used to infer chain identity. Bitcoin test networks share
address prefixes, while Fractal Bitcoin can share address text with Bitcoin.

## Architecture

The implementation has three independent layers:

- `chain-domain`: chain IDs, network profiles, derivation, addresses,
  transaction review, signing-message construction, final verification;
- `signing-domain`: algorithm suite IDs, signer sets, epochs, execution
  topology, operation state and public receipts;
- `wallet-core`: intent creation, Passkey authorization, policy binding,
  orchestration, durable state and activation gates.

Existing `threshold-signer` and `signer-transport` remain execution modules.
They do not parse transactions and do not decide wallet policy.

The common execution modes are:

- `threshold-interactive`: a native threshold protocol such as FROST;
- `single-signer-isolated`: an isolated chain-native signer protected by the
  same 2-of-3 authorization policy until a mature MPC backend is available;
- `native-chain-coordinator`: an external chain-native threshold system whose
  result is independently verified by Catomicals.

FROST is preferred whenever an existing or narrowly defined ciphersuite produces
the exact signature required by the chain. It is not used to alter a chain's
signature algorithm.

## Network model

The current `networkId` ambiguity is removed by using two types:

- `ChainNetwork`: consensus identity used by address derivation, signing and
  activation, for example `bitcoin.signet` or `chia.testnet11`;
- `RpcPresetId`: a node connection preset, for example
  `bitcoin-inquisition` or `kaspa-testnet-11`.

An explicit `RpcPresetId -> ChainNetwork` mapping is required. RPC preset IDs
are rejected by address APIs, and generic address-family names are rejected by
RPC preset resolution.

Each network profile binds:

- chain and concrete network identity;
- address-family parameters;
- derivation policy and version;
- transaction codec and signing-message rules;
- RPC expectations and genesis/tip identity checks;
- allowed signing suites;
- mainnet activation state.

## Initial suite matrix

| Chain | Initial signature path | Threshold direction |
| --- | --- | --- |
| Bitcoin | BIP340 Taproot key spend | `frost-secp256k1-tr` |
| Fractal Bitcoin | Bitcoin-compatible BIP340 after network conformance | `frost-secp256k1-tr`, isolated chain domain |
| Bitcoin Cash | chain-native transaction digest and signature | prefer compatible Schnorr FROST where consensus path permits; threshold ECDSA otherwise |
| BSV | chain-native ECDSA transaction signature | threshold ECDSA unless an explicitly supported Schnorr spend is selected |
| Kaspa | chain-native Schnorr/ECDSA rules | prefer secp256k1 FROST with a Kaspa-specific ciphersuite if required |
| Chia | BLS12-381 aggregate signature | threshold BLS backend; FROST is incompatible |
| Ergo | chain-native Sigma proof | chain-native MPC or isolated signer until a mature compatible backend is selected |

Suite IDs are stable semantic strings. Changing their meaning creates a new
version, for example `btc.bip340.frost-secp256k1-tr.v1`.

## Signing data flow

1. `ChainSuite::review_transaction` parses complete transaction material and
   authoritative chain facts.
2. It produces a versioned `ReviewArtifact` containing the canonical signing
   message and human review summary.
3. `wallet-core` creates an immutable intent binding chain, concrete network,
   suite, signer set, epoch, review digest, expiry and nonce.
4. Passkey approval authorizes this exact intent. Passkey material never becomes
   a chain signature.
5. `SigningSuite` drives the selected backend. Threshold rounds remain outside
   database transactions and the wallet's global request lock.
6. `ChainSuite::verify_finalized_signature` independently verifies the result.
7. Only a verified result can enter a signed transaction and reach broadcast.

The signer domain separator includes chain, concrete network, suite, review
schema, intent schema, signer set and epoch. Nonces cannot cross any of these
boundaries.

## Address and derivation rules

- Bitcoin uses BIP84/BIP86 and explicit network parameters.
- Fractal Bitcoin uses Bitcoin-compatible encoding but always retains a distinct
  chain identity. Its derivation policy is versioned because no separate
  official SLIP-0044 coin type is currently published.
- Chia uses `m/12381/8444/2/index`, standard synthetic keys and puzzle hashes;
  `xch/txch` only identify the address family, not a specific testnet.
- Other chain profiles use official wallet derivation and address fixtures from
  their respective implementations.

Private derivation material remains in signer backends. The wallet core stores
public account profiles and secret references only.

## Mainnet activation

Mainnet stays disabled until all three gates pass:

1. the build declares the `(chain, network, suite, backend)` combination;
2. a durable activation record binds that exact combination and policy version;
3. the combination is marked audited after official vectors and node E2E pass.

Enabling an RPC plugin alone never enables signing or broadcast.

## Testing contract

Each concrete network requires:

- official positive address and derivation fixtures;
- wrong-network, checksum and encoding failures;
- official transaction/message/signature vectors;
- independent verification and wrong-message rejection;
- signer-set, epoch, suite and nonce-domain mismatch rejection;
- node profile identity checks and broadcast preflight;
- a local-node E2E where practical.

Bitcoin Inquisition Signet remains the first full E2E. Other mainnets remain
read-only until their activation gates are satisfied.

## Out of scope for the first implementation slice

- generalizing OP_CAT issuance and trading to all chains;
- inventing a new threshold cryptographic protocol;
- claiming mainnet readiness from address/RPC support alone;
- importing raw private keys through MCP or the renderer;
- allowing MCP to approve, produce signature shares or broadcast.

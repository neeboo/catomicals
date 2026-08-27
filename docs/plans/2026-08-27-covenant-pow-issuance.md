# OP_CAT proof-of-work issuance gate

## Implemented scope

The issuance crate implements a Bitcoin Inquisition Signet research artifact. A creator commits terms and one issuer state into a single-leaf P2TR output. Spending that leaf requires a proof-of-work witness and fails when the leaf's committed `remaining` value is zero.

The OP_CAT-only leaf does not inspect outputs. It therefore does not enforce an item output, the owner of an item, a successor issuer output, a decrement, a fee, or a unique continuing state machine. Those are wallet-verification rules in `verify_mint`. A consensus-valid spender can satisfy the mint gate and create different outputs or stop the issuance. Code and documentation must not describe the current leaf as an output covenant or a consensus-enforced recursive issuance.

## Commitments and encoding

Creator terms are serialized as:

```text
"catomicals-issuance-v1" || item_id || target_prefix || total_supply ||
successor_rule || lane_count || salt || metadata_len_le64 || metadata
```

The issuer leaf commits `terms_hash`, `lane`, `seq`, `remaining`, and `target_prefix`. Scalar script constants carry a nonzero `0x01` field tag:

```text
tagged_lane      = 0x01 || lane_u8
tagged_seq       = 0x01 || seq_le32
tagged_remaining = 0x01 || remaining_le32
tagged_target    = 0x01 || target_prefix_u8
```

The tag preserves exact widths for zero-valued fields while using minimal pushes. The PoW input is:

```text
terms_hash || tagged_lane || tagged_seq || item_commitment || nonce_le64
```

`target_prefix = k` requires the digest to start with `k` copies of `0x01`. This has the same `256^-k` success probability as a `k`-zero-byte prefix, while a one-byte target can be constructed with `OP_1` under `SCRIPT_VERIFY_MINIMALDATA`. It is a protocol encoding choice, not Bitcoin's compact difficulty representation.

An item commitment binds a recipient chosen before mining:

```text
SHA256("catomicals-item-v1" || terms_hash || lane || seq || owner_xonly || payload)
```

The wallet-policy item output is `OP_1 <owner_xonly>`. It is spendable by the owner of that real x-only key. Commitment bytes are never interpreted as an x-only public key.

## OP_CAT leaf

The argument witness is:

```text
[nonce_le64, item_commitment, hash_tail, owner_xonly, payload]
```

The leaf recomputes the digest with four `OP_CAT` operations and `OP_SHA256`, compares it with `0x01^k || hash_tail`, compares tagged `remaining` against tagged zero, drops all ten leftover stack elements, and ends with explicit `OP_TRUE`. The internal key is BIP341's published NUMS x-coordinate `50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0`; the implementation does not derive it from a known secret scalar.

## Wallet verification

`verify_mint` recovers the issuer tapscript from the input witness, parses only the canonical leaf template, decodes the control block, and verifies that control block and leaf against the spent P2TR output key. It then applies wallet policy:

- terms and current state match;
- PoW, hash tail, owner-bound item commitment, and payload match;
- exactly one owner-controlled item output exists;
- the expected canonical successor exists unless this is the final wallet-policy slot;
- there are no extra outputs, value is conserved, and the fee is positive.

These output and transition checks are verifiable client policy. They are not consensus properties of the OP_CAT leaf.

The indexer reports a canonical issuer-leaf reveal and, only in such transactions, unclassified P2TR output candidates. It does not verify the spent output/control block and does not label every P2TR output as an item. Classification requires wallet verification with the spent UTXO and terms.

## Optional additional opcode

BIP446 `OP_TEMPLATEHASH` could support a separate hardened design that commits an output template. That would add an opcode dependency beyond OP_CAT and would need its own executable transaction template, fee policy, tests, and Inquisition evidence. No such hardened variant is implemented here, so this repository makes no BIP446 enforcement claim.

## Reproducible evidence and measurements

Run:

```sh
scripts/verify-issuance-inquisition.sh
cargo run -p catomicals-issuance --example measure_models
```

The evidence uses Bitcoin Inquisition v29.4 `bitcoin-util evalscript` with `TAPSCRIPT` and `P2SH,WITNESS,TAPROOT,MINIMALDATA,CLEANSTACK,OP_CAT`. It requires valid and nonce-zero vectors to succeed, and wrong nonce, altered hash tail, changed state, and exhausted supply vectors to fail. It also rejects any `OP_SUCCESS` bypass.

The target-one issuer leaf is 94 bytes; `dump_issuer` reproduces its exact hex and witness. Fresh transaction measurements for 1,000 wallet-policy items, a one-byte target, 1,000,000-sat issuer outputs, 1,000-sat item outputs, and the documented placeholder funding witness are:

| model | initial lanes | issuance vbytes | representative mint vbytes | policy latency estimate | independent policy chains |
|---|---:|---:|---:|---:|---:|
| A: shared issuer | 1 | 122 | 199 | 1,000 blocks | 1 |
| B: sharded lanes | 8 | 423 | 199 | 125 blocks | 8 |

The expected work is 256 hashes for a one-byte target. Transaction sizes are serialization measurements of the example builders, while latency assumes at most one accepted mint per lane per block. They are not fee quotes, throughput guarantees, or evidence that successor outputs are consensus-enforced.

# ADR 0003: immutable, content-addressed policy objects

- Status: Accepted for B0
- Date: 2026-08-27
- Scope: covenant policy, wallet bindings, compilation, activation, review, recovery

## Context

Catomicals needs to manage covenant rules, signer thresholds, recovery constraints, issuance and market semantics, and experimental deployment assumptions. Keeping these rules only in source code or chat context prevents deterministic review, activation, backup, and recovery.

Policy changes also affect custody. A mutable policy record or a UI-only diff cannot establish which exact rules were approved and used for signing.

## Decision

A policy is a family of immutable, content-addressed objects:

- `policy_document`: canonical source document containing network profile, participants, thresholds, approval rules, recovery rules, script dependencies, asset semantics, and experimental markers.
- `policy_hash`: digest of the canonical serialized policy document; it is the policy identity.
- `policy_artifact`: reproducible compiler output such as tapscript, Taproot tree, typed template, parser schema, or UI metadata.
- `policy_test_vector`: positive, negative, boundary, fee, witness-size, and deployment tests.
- `policy_binding`: binds an exact policy hash to a wallet, signer set and epoch, asset set, and chain profile.
- `policy_activation`: records the human approvals, previous version, prerequisites, activation time, and rollback conditions for one binding.

Documents and artifacts are append-only. Editing creates a new version and hash. A policy name or semantic version is a discovery label and cannot replace `policy_hash` in a custody decision.

### Lifecycle

```text
draft -> validated -> pending_activation -> active -> superseded
                     \-> rejected             \-> revoked
```

- `validated` means canonicalization, compilation, test vectors, deployment checks, and artifact digests succeeded.
- `pending_activation` means an activation proposal exists but carries no signing authority.
- `active` requires the policy-defined human and signer approvals.
- `superseded` and `revoked` remain auditable; records are never overwritten.

### Wallet binding

Every transaction review and signing intent records the exact `policy_hash`, binding identifier, signer epoch, and `node_snapshot_id`. At proposal review and again immediately before signing, `walletd`:

1. loads the immutable policy and binding;
2. verifies the policy is active for the wallet and chain profile;
3. reproduces or validates compiler artifact digests;
4. evaluates the transaction against the policy;
5. checks activation, expiry, recovery, and signer-epoch conditions.

Chat messages, plugin configuration, index projections, and generated UI cards may reference a policy. They cannot activate it or substitute a policy verifier.

### Canonicalization and hashing

The policy schema defines valid structure, while a separately versioned canonicalization profile defines byte serialization. The first profile is named `catomicals-policy-jcs-v1` and uses RFC 8785 JSON Canonicalization Scheme semantics. The hash declaration includes both canonicalization and digest algorithms. A future algorithm requires a new profile; silent reinterpretation is prohibited.

Compiler identity, compiler version, input policy hash, build profile, and output digests are part of every artifact record. Reproducibility is verified by test vectors and artifact digest comparison.

### Backup and recovery

Backups include policy documents, artifacts required to reproduce wallet behavior, bindings, activations, and their digests. Restoring a backup does not reactivate unfinished approvals or signing ceremonies. Recovery increments the wallet recovery epoch and forces fresh node snapshots and signer availability checks.

Each FROST share remains separately owned and backed up by its holder. A policy backup never centralizes quorum shares.

## Consequences

- Policy review, compilation, activation, and recovery can be audited independently from chat.
- The UI can show understandable diffs while the wallet binds the full canonical document.
- Storage grows append-only and needs retention rules for unbound drafts, while activated history remains permanent.
- Policy schema compatibility and canonicalization profiles become public protocol contracts.

## Rejected alternatives

- Mutable policy rows: destroys the exact approval and signing history.
- Version strings as identity: labels can collide or be moved.
- Storing only compiled script: loses author intent, test vectors, and reproducibility evidence.
- Letting an agent or plugin activate policy: crosses the human approval and wallet authority boundary.

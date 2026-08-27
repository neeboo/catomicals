# Catomicals Engineering Direction

## Core-first security and performance

- Concentrate security work in the trust-bearing core: wallet authority, policy evaluation, approvals, signing, nonce and replay protection, secret handling, node snapshots, UTXO verification, protocol validation, and durable state transitions.
- Do not spread speculative defensive programming across every boundary. Boundary validation must be small, explicit, typed, and tied to a concrete threat or invariant. Avoid layers of fallback logic that hide errors or weaken the core model.
- Treat performance in the core as a product requirement. Measure critical paths, benchmark meaningful workloads, and remove redundant serialization, copying, RPC calls, database scans, lock contention, and abstraction overhead before accepting a design.
- Keep boundaries and interaction surfaces simple and intuitive. Prefer a small number of stable concepts, direct error messages, predictable state transitions, and obvious user actions. Put necessary complexity behind narrow core interfaces.
- Review work in this order: core correctness and security, core performance, boundary and interaction simplicity, then optional hardening and convenience features.

## Practical review rule

A change should be rejected when it adds edge complexity without strengthening a documented core invariant, or when it protects a low-value boundary at the cost of clarity or critical-path performance. Security-sensitive core code must remain strict, testable, observable, and fail closed.

# ADR 0004: provider-neutral executors and fixed Cordis plugins

- Status: Accepted for B0
- Date: 2026-08-27
- Scope: Codex, DeepSeek Harness, Claude Code, MCP, chat protocol, Cordis settings

## Context

The desktop shell must support Codex, DeepSeek Harness, and Claude Code while presenting one chat, tool-event, review, and generated-interface protocol. Infrastructure capabilities such as `walletd`, node access, indexing, MCP, backup, browser policy, and model selection also need discoverable configuration. Those settings should appear as Cordis plugins rather than a growing hard-coded settings page.

Executor-specific message models or dynamically generated wallet plugins would couple the wallet to one harness and make agent output part of the custody boundary.

## Decision

The desktop host owns a provider-neutral executor registry. Provider adapters implement process probing, model discovery, session creation and recovery, message submission, cancellation, and normalized events. They do not implement wallet business logic.

An executor session records:

- provider and provider-native session reference;
- selected model and reasoning effort;
- MCP enablement and allowed tool scopes;
- workspace capability;
- normalized lifecycle state and sanitized errors;
- optional plugin identity that created the session.

Codex and Claude Code use the same local stdio MCP schema. DeepSeek Harness uses its external MCP client bridge with the same schema. Disabling MCP leaves a chat-only executor.

### Cordis plugin contract

The first release loads only fixed, signed, allowlisted Catomicals plugins. A plugin manifest declares package digest, signature, runtime API, host/client entry points, injected services, permission scopes, settings namespace and schema, UI surfaces, health service, and migrations.

Plugins register capabilities and presentation surfaces. Wallet actions still route through `walletd` or the unified MCP contract. The Cordis runtime is an extension lifecycle manager, not a wallet security sandbox.

Agent-created code, arbitrary package installation, generic script execution, `cordis_define`, and `cordis_run` are outside the wallet-facing capability surface.

### Agent-assisted configuration

Executors may use this configuration capability family:

- `list_plugins`
- `read_plugin_manifest`
- `read_plugin_settings_schema`
- `read_plugin_health`
- `validate_plugin_settings_patch`
- `create_plugin_settings_intent`

The first five operations do not mutate active configuration. The last creates a pending, human-reviewable intent. No `apply_plugin_settings` operation exists in the agent protocol.

After a person confirms the settings intent, the desktop host:

1. re-reads the installed plugin version, active configuration digest, and opaque secret references;
2. rejects stale intents and permission expansion not shown in the review;
3. parses and migrates the candidate in an isolated profile;
4. runs the plugin health check;
5. atomically promotes the candidate to the last-good tree, or rolls it back.

API keys, OAuth tokens, cookies, wallet key material, FROST shares, HSM material, and raw authenticator secrets are never MCP values. Agents may refer only to host-created opaque secret references.

### Presentation protocol

Chat messages contain typed parts. Tool events contain digests, state, redacted summaries, and immutable references. Generated UI uses an allowlisted JSON schema for cards and charts; it cannot contain executable JavaScript, HTML, remote components, or wallet authorization payloads.

The host resolves review references and re-reads authoritative values before displaying a confirmation or running a human-triggered action. An agent-generated amount or transaction summary is informative until the trusted component replaces it with a verified review.

## Consequences

- One chat surface can switch providers without changing wallet semantics.
- Cordis plugins can contribute settings and health UI while the host retains validation and rollback.
- Adapter and plugin failures remain isolated from signing authority.
- New wallet tools require an explicit schema and permission-version change; adding a provider does not expand wallet authority.

## Rejected alternatives

- Provider-specific wallet APIs: duplicates policy and authorization logic.
- Dynamic agent-authored wallet plugins: makes generated code part of the trusted computing base.
- Direct settings apply from MCP: bypasses stale checks, confirmation, migration, health, and rollback.
- Executable generated UI: lets presentation data become code execution.

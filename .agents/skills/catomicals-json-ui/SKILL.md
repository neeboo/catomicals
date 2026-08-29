---
name: catomicals-json-ui
description: "Use when a Catomicals wallet answer benefits from a host-authoritative status, settings review, policy, fee, or transaction component rendered inside chat."
---

# Catomicals controlled JSON UI

Use Markdown for ordinary explanation. Prefer one controlled component when it makes wallet state or a review materially easier to understand and a valid host reference already exists.

## Output contract

After the Markdown explanation, emit each component exactly inside this envelope:

```text
<catomicals-ui>
{"schema_version":1,"block_id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","component":"health_status","data_bindings":[{"slot":"health","source":"desktop_host","reference_kind":"plugin_id","reference_id":"@catomicals/plugin-walletd"}],"action_bindings":[]}
</catomicals-ui>
```

Rules:

- Use a fresh UUID for `block_id`.
- Emit no more blocks than the active `@catomicals/plugin-generative-ui` setting permits.
- Provide references only. Never put display values, balances, addresses, amounts, transaction contents, secrets, component props, or executable actions in the block.
- Never invent a reference. Fall back to Markdown when a valid reference is unavailable.
- Keep `action_bindings` empty. The desktop host owns every permitted action.
- Keep the surrounding explanation concise; do not repeat every value the component will reload.

## Components available now

### `health_status`

Use one binding:

```json
{"slot":"health","source":"desktop_host","reference_kind":"plugin_id","reference_id":"@catomicals/plugin-walletd"}
```

### `plugin_settings_diff` and `review_card`

Use one binding with an existing settings review UUID:

```json
{"slot":"review","source":"desktop_host","reference_kind":"review_id","reference_id":"11111111-2222-4333-8444-555555555555"}
```

Use `plugin_settings_diff` for a read-only comparison. Use `review_card` only when the host can present its own confirmation action.

Other names in the shared protocol are reserved until a host loader is implemented. Do not emit them yet.

## UI development

When changing Catomicals UI itself, inspect the configured DeepSeek Harness reference repository, especially `apps/web` and `packages/client`. Reuse its shallow hierarchy, plugin-owned settings surfaces, loading states, and scroll ownership patterns without cloning its full plugin inventory.

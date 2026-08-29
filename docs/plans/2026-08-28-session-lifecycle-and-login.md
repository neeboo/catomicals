# Session lifecycle and login UX plan

## Goal

Complete the chat shell's first-run and session lifecycle: lightweight empty-state guidance, first-turn agent-generated titles, recoverable deletion, and an in-app identity entry that does not expose the raw Passkey administration route.

## Workstream A: sessions

Files owned by the session agent:

- `web/src/components/workbench/WalletWorkbench.tsx`
- `web/src/components/workbench/WalletWorkbench.test.tsx`
- `web/src/components/sessions/SessionList.tsx`
- `web/src/components/sessions/SessionList.test.tsx`
- `web/src/lib/session-title.ts`
- `web/src/lib/session-title.test.ts`
- session-related selectors in `web/src/index.css`

Steps:

1. Add failing tests for empty-state prompt suggestions, first-turn title generation/fallback/manual-rename precedence, move-to-trash, restore, and permanent-delete confirmation.
2. Implement a quiet empty-state guide visible only for an empty transcript; suggestions populate the composer.
3. Generate a short title in an isolated auxiliary executor session after the first completed turn; persist via `session/title`; retain a deterministic fallback and never block chat.
4. Keep deletion recoverable by default. Refresh the trash list after delete/restore/purge, label restore and permanent delete clearly, and require confirmation for permanent deletion.
5. Run targeted tests, full web tests, and type checking.

## Workstream B: identity entry

Files owned by the identity agent:

- a new identity/login component and its tests under `web/src/components/account/`
- the login integration points in `web/src/components/workbench/WalletWorkbench.tsx`
- account-related selectors in `web/src/index.css`
- `web/src/lib/account.ts` and tests only when needed

Steps:

1. Add failing tests proving the sidebar Login action opens an in-app identity dialog/sheet and does not navigate to `/passkeys`.
2. Implement a concise identity surface for Google, Apple, and email/passkey entry as product UI; keep wallet authorization Passkeys separate and reachable from Security/Settings.
3. Do not claim unavailable remote authentication is connected. Mark unavailable providers as coming later or keep them disabled, while local Passkey enrollment remains an explicit secondary action.
4. Run targeted tests, full web tests, and type checking.

## Verification

1. Independent spec review for both workstreams.
2. Independent code-quality review after spec approval.
3. Full web and desktop regression tests.
4. Run the Electron application, verify the empty state, trash lifecycle, and login surface, capture screenshots, and update `design-qa.md` with a final `passed` or `blocked` result.

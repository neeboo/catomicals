# Design QA

## Target

- Reference: `/var/folders/0n/mlts398n6mb3hnzp_q2qsc500000gn/T/codex-clipboard-d722cd2b-efc7-48db-91bf-00b783e90d98.png`
- Implementation: `artifacts/design-qa/catomicals-window-compact-sidebar-v2.png`
- Combined comparison: `artifacts/design-qa/codex-vs-catomicals-top.png`
- Window: 2048 × 1030 logical pixels, 2× Retina capture
- State: native Electron window, left rail open, tool rail collapsed, empty session

## Visible comparison

- Native title bar: hidden; traffic lights occupy the left rail overlay.
- Left rail: one product label, one new-session row, one search action, flat session rows, quiet footer actions.
- Search: expanded search replaces the action row; the close action stays inside the field.
- Session rows: 36px single-line density, no provider/time subtitle, no permanent action icons.
- Borders: one pane separator; no stacked footer separators or bordered cards in the rail.
- Center: local conversation context row only; no app-wide title strip, status prose, or subtitle.

## Findings resolved

- P1: oversized new-session/search controls and card-like active rows.
- P1: duplicate search close button competing with the primary action.
- P2: provider/time metadata made each session row visually heavy.
- P2: repeated rail footer borders created unnecessary hierarchy.
- P1: stale Electron main process preserved the native title strip after renderer hot reload.

## Remaining severity

- P0: none
- P1: none
- P2: none

## Final result

passed

---

## 2026-08-29 — empty session, account entry, and trash lifecycle

### Target

- User-reported empty state: `/var/folders/0n/mlts398n6mb3hnzp_q2qsc500000gn/T/codex-clipboard-ed6381a6-cd99-465a-8ce8-42eea024946e.png`
- Implemented empty state: `artifacts/design-qa/catomicals-session-lifecycle-login.png`
- Implemented account dialog: `artifacts/design-qa/catomicals-login-dialog.png`
- Implemented trash state: `artifacts/design-qa/catomicals-trash-panel.png`
- Prompt-selection state: `artifacts/design-qa/catomicals-starter-filled.png`
- Before/after comparison: `artifacts/design-qa/empty-state-before-after.png`
- Window: 1920 × 958 logical pixels, 2× Retina capture
- State: native Electron window, tool rail collapsed, empty persistent session

### Visible and interactive checks

- The empty transcript now has one quiet heading, one supporting sentence, and three compact prompt suggestions; there are no dashboard cards or tool panels.
- Selecting a suggestion only fills and focuses the composer. It does not submit a message or open a wallet tool.
- The account entry opens a centered in-app dialog and leaves the route and right browser pane unchanged.
- Google, Apple, email, and local identity Passkey are visibly unavailable; the dialog does not claim that remote authentication is connected.
- Local identity Passkey is described separately from Bitcoin transaction authorization.
- The recycle bin expands in the left rail, exposes recoverable restore and explicit permanent deletion, and reports the empty state without adding a new full-screen surface.
- The titlebar remains hidden and the traffic lights remain aligned with the left rail.

### Functional evidence

- Web: 24 test files, 148 tests passed; TypeScript check passed.
- Desktop: 33 test files, 262 tests passed; TypeScript check passed.
- Desktop session E2E covers create, persist, search, lifecycle management, deeplink navigation, deletion, restore, and restart.
- New regression coverage confirms that pending replies cannot leak across sessions, provider switches rebind the executor, and pointer-driven rename actions survive focus changes.

### Findings resolved

- P1: empty new sessions had no guidance.
- P1: sidebar Login exposed the raw Passkey administration page.
- P1: a pending reply could update the wrong visible session after navigation.
- P1: switching providers could reuse an executor created for another provider.
- P2: restore and permanent-delete actions used ambiguous icon-only controls and stale trash state.
- P2: pointer-clicking Save during rename could be swallowed by blur teardown.

### Remaining severity

- P0: none
- P1: none
- P2: none

### Final result

passed

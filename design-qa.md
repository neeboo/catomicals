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

---

## 2026-08-29 — settings list and configuration dialog

### Target and evidence

- Source visual truth: `artifacts/design-qa/source-inline-settings.png`
- Original source: `/var/folders/0n/mlts398n6mb3hnzp_q2qsc500000gn/T/codex-clipboard-48591d04-66ce-4401-996e-46b53de881f6.png`
- Implementation screenshot: `artifacts/design-qa/implementation-settings-dialog.jpeg`
- Combined comparison: `artifacts/design-qa/settings-before-after-comparison.jpeg`
- Source pixels: 2678 × 1980; normalized to 1039 × 768 for comparison.
- Implementation pixels: 1531 × 768; Electron viewport captured at the current macOS display density.
- State: native Electron window, settings → plugins, BSV configuration dialog open.

The source is the rejected state: a duplicate chain overview, page-level review card, and an inline form split the settings page vertically. The implementation is expected to remove those structures rather than reproduce them.

### Full-view comparison evidence

- The seven chain rows remain in one stable, compact list.
- Configuration is isolated in one centered dialog with a dimmed backdrop.
- The page-level review notice, review card, duplicate chain overview, and inline configuration panel are absent.
- The dialog exposes only Cancel and Save. Backend validation and atomic application remain invisible to the user.

### Focused region evidence

- Typography: plugin names, field labels, helper text, and actions preserve the existing Catomicals font stack and optical hierarchy; no new display font was introduced.
- Spacing and layout: chain rows use a 72px minimum height; general settings use 64px; the dialog is capped at 760px wide and 80vh high with an independently scrolling body.
- Colors and tokens: the dialog reuses the monochrome surface, low-contrast separators, semantic error color, and white primary action already used by the desktop shell.
- Image and icon fidelity: this surface contains no raster artwork. The close control uses the existing project icon component; no handcrafted SVG or placeholder asset was introduced.
- Copy: all visible review, approval, waiting, and confirmation language has been removed from normal settings interaction.
- Interaction: configuration opens from its row; Escape closes the dialog and returns to the list; tests cover cancel, direct save, direct enable/disable, local errors, focus cycling, and focus restoration.

### Findings and comparison history

- P1 resolved: inline configuration expanded the ledger and destroyed list continuity. It now opens in a portal dialog.
- P1 resolved: normal settings exposed an enterprise-style review and confirmation workflow. Save and enable/disable now complete in one visible action.
- P2 resolved: the seven-chain overview duplicated the list beneath it. The overview was removed.
- P2 resolved: save errors could take over the page. Errors now remain inside the dialog or affected row.
- Post-fix visual inspection found no remaining actionable P0, P1, or P2 issue in the requested settings flow.

### Browser and runtime checks

- The in-app browser could not access localhost because its enforced local-network policy was unavailable; no security control was bypassed.
- The native Electron window was restarted after a stale hot-reload blank state, then inspected directly.
- Primary interactions checked: settings navigation, plugin category selection, configuration dialog open, and Escape close.
- Electron runtime output showed no renderer error during the final inspection.

### Final result

passed

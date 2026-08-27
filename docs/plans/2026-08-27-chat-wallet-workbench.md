# Catomicals Chat Wallet Workbench Implementation Plan

> **For Codex:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the route-first wallet dashboard with a working three-column chat wallet workbench grounded in the supplied Codex screenshot and DeepSeek Harness shell patterns.

**Architecture:** Keep the existing React/TanStack Query API layer. Introduce one workbench route with local panel selection, a real chat transcript/composer in the center, and compact contextual tools on the right. Preserve existing detail routes for deep-link approval while making the root and chat routes share the new shell.

**Tech Stack:** React 19, TypeScript, TanStack Query/Router, Tailwind CSS 4, Tabler Icons, Vitest.

---

### Task 1: Lock the workbench interaction contract

**Files:**
- Create: `web/src/lib/workbench.test.ts`
- Create: `web/src/lib/workbench.ts`
- Modify: `web/package.json`

1. Write failing tests for the available wallet tools and panel transitions.
2. Run the focused test and confirm the missing implementation failure.
3. Add the smallest typed workbench model that passes.

### Task 2: Build the three-column workbench

**Files:**
- Create: `web/src/components/workbench/WalletWorkbench.tsx`
- Create: `web/src/components/workbench/TransactionInspector.tsx`
- Modify: `web/src/routes/index.tsx`
- Modify: `web/src/routes/chat.tsx`
- Modify: `web/src/routes/root.tsx`
- Modify: `web/src/index.css`

1. Add the left wallet/session rail.
2. Add the center conversation transcript and fixed composer using the existing chat hooks.
3. Add right-side transaction, intent, issuance, and security panels using existing live hooks.
4. Add narrow viewport drawer behavior and keyboard-safe composer behavior.

### Task 3: Verify behavior and visual fidelity

**Files:**
- Create: `design-qa.md`

1. Run unit tests, typecheck, and production build.
2. Start the wallet node and frontend preview.
3. Capture the implementation at the source screenshot viewport.
4. Compare the source and implementation together, fix visible layout issues, and repeat.
5. Record the final QA result in `design-qa.md` and keep the preview running.

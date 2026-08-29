/**
 * Electron E2E driver for the Catomicals chat shell. Runs as the Electron main
 * entry, imports the real compiled main (desktop/dist/main.js), and drives the
 * renderer through `webContents.executeJavaScript` to prove the session
 * lifecycle: create two sessions, send/store messages, rename/archive/delete/
 * restore, cross-session search, deeplink open, and transcript restoration
 * after a restart (phase 2 reuses the same userData and a launch deep link).
 *
 * The wallet node is skipped (CATOMICALS_E2E=1) and prompts are wallet-safe
 * ("describe a local todo", no broadcast). The test process shadows `dsh`
 * with a deterministic local adapter so session lifecycle coverage never
 * depends on network latency, credentials, or global plugins.
 *
 * Contract: prints one `E2E_RESULT <json>` line and exits 0 on success.
 *
 * Usage: electron driver.mjs --user-data-dir=<dir> --phase=1|2
 *        [--session-a=<id> --session-b=<id>] [catomicals://session/<id>]
 */

import { app, BrowserWindow } from "electron";

const argv = process.argv.slice(1);
function flag(name) {
  const prefix = `${name}=`;
  const found = argv.find((argument) => argument.startsWith(prefix));
  return found ? found.slice(prefix.length) : undefined;
}

const userDataDir = flag("--user-data-dir");
const phase = flag("--phase") ?? "1";
const sessionA = flag("--session-a");
const sessionB = flag("--session-b");

if (!userDataDir) {
  console.error("E2E_RESULT " + JSON.stringify({ error: "missing --user-data-dir" }));
  app.exit(2);
}
app.setPath("userData", userDataDir);

const outcome = { phase: Number(phase), steps: [] };
function step(name, ok, detail = "") {
  outcome.steps.push({ name, ok: Boolean(ok), detail });
}
function finish(ok) {
  outcome.ok = Boolean(ok);
  console.log("E2E_RESULT " + JSON.stringify(outcome));
  app.exit(ok ? 0 : 1);
}

async function waitForWindow() {
  const deadline = Date.now() + 30_000;
  for (;;) {
    const windows = BrowserWindow.getAllWindows();
    if (windows.length > 0 && !windows[0].webContents.isLoading()) return windows[0];
    if (Date.now() > deadline) throw new Error("window did not appear");
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

const RENDERER_HELPERS = `
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const waitFor = async (fn, timeout = 20000, label = "condition") => {
    const start = Date.now();
    for (;;) {
      const value = fn();
      if (value) return value;
      if (Date.now() - start > timeout) throw new Error("timeout: " + label);
      await sleep(60);
    }
  };
  const click = (el) => { el.click(); };
  const setValue = (el, value) => {
    const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, "value").set;
    setter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
  };
  const setSelect = (el, value) => {
    const proto = HTMLSelectElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, "value").set;
    setter.call(el, value);
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const send = async (text) => {
    const completedBefore = document.querySelectorAll('article[data-role="agent"]').length;
    const composer = await waitFor(() => document.querySelector(".composer textarea"), 10000, "composer");
    setValue(composer, text);
    await waitFor(() => !document.querySelector('button[aria-label="发送消息"]').disabled, 5000, "send enabled");
    await sleep(100);
    click(document.querySelector('button[aria-label="发送消息"]'));
    await waitFor(() => userMessages().some((item) => item.includes(text)), 20000, "user message stored: " + text);
    await waitFor(
      () => document.querySelectorAll('article[data-role="agent"]').length > completedBefore
        && document.querySelector(".processing-row") === null,
      90000,
      "turn reached a terminal state",
    );
  };
  const rows = () => Array.from(document.querySelectorAll('[data-testid^="session-row-"]'))
    .map((el) => el.dataset.testid.replace("session-row-", ""));
  const currentTitle = () => (document.querySelector('[data-testid="conversation-title"]')?.textContent ?? "").trim();
  const userMessages = () => Array.from(document.querySelectorAll('article[data-role="user"]'))
    .map((el) => el.textContent ?? "");
`;

async function runScenario(win, body) {
  return win.webContents.executeJavaScript(`(async () => { ${RENDERER_HELPERS}\n${body}\n})()`);
}

async function phase1(win) {
  const result = await runScenario(win, `
    const result = {};
    // Create session A via the rail's new-session action.
    click(document.querySelector("button.new-session"));
    await waitFor(() => rows().length === 1, 20000, "session A row");
    const sessionA = rows()[0];
    result.sessionA = sessionA;

    // Use DeepSeek for the real adapter path. The wallet-safe prompt never
    // requests a transaction or broadcast.
    const select = await waitFor(() => document.querySelector(".executor-selector select"), 10000, "executor select");
    setSelect(select, "deepseek");
    await sleep(600);

    await send("E2E 消息甲：仅描述本地待办，不广播。");
    result.turnAStored = true;

    // Create session B and store a second message.
    click(document.querySelector("button.new-session"));
    await waitFor(() => rows().length === 2, 20000, "session B row");
    const sessionB = rows().find((id) => id !== sessionA);
    result.sessionB = sessionB;

    await send("E2E 消息乙：本地清单第二项。");
    result.rowCount = rows().length;

    // Cross-session content search opens the matched session.
    click(document.querySelector("button.session-search-toggle"));
    const searchInput = await waitFor(() => document.querySelector('input[aria-label="搜索会话内容"]'), 10000, "search input");
    setValue(searchInput, "消息甲");
    searchInput.closest("form").requestSubmit();
    await waitFor(() => document.querySelector('[data-testid="session-search-results"]') !== null, 20000, "search results");
    click(document.querySelector('[data-testid="session-search-results"] button'));
    await waitFor(() => userMessages().some((text) => text.includes("E2E 消息甲")), 20000, "search opened session A");
    result.searchOpenedSession = true;

    // Rename, archive, unarchive, delete (recoverable), restore.
    const rowA = await waitFor(() => document.querySelector('[data-testid="session-row-' + sessionA + '"]'), 10000, "row A after search");
    click(rowA.querySelector('button[aria-label^="重命名 "]'));
    const renameInput = await waitFor(() => document.querySelector('input[aria-label="会话新名称"]'), 10000, "rename input");
    setValue(renameInput, "重命名甲");
    renameInput.closest("form").requestSubmit();
    await waitFor(() => rowA.textContent.includes("重命名甲"), 20000, "row A renamed");
    result.renamed = true;

    click(rowA.querySelector('button[aria-label^="归档 "]'));
    await waitFor(() => rowA.textContent.includes("已归档"), 20000, "row A archived");
    click(rowA.querySelector('button[aria-label^="取消归档"]'));
    await waitFor(() => !rowA.textContent.includes("已归档"), 20000, "row A unarchived");
    result.archiveToggled = true;

    click(rowA.querySelector('button[aria-label^="删除 "]'));
    await waitFor(() => rows().length === 1, 20000, "row A deleted");
    click(document.querySelector('[data-testid="trash-toggle"]'));
    await waitFor(() => document.querySelector('[data-testid="trash-panel"]') !== null, 10000, "trash panel");
    const restoreButton = await waitFor(() => document.querySelector('button[aria-label^="恢复 "]'), 10000, "restore button");
    click(restoreButton);
    await waitFor(() => rows().length === 2, 20000, "row A restored");
    result.restored = true;

    result.ok = true;
    return result;
  `);

  step("create two sessions", result.sessionA && result.sessionB);
  step("send and store message A with a terminal agent turn", result.turnAStored === true);
  step("send and store message B", result.rowCount === 2);
  step("cross-session search opens the matched session", result.searchOpenedSession === true);
  step("rename session", result.renamed === true);
  step("archive/unarchive session", result.archiveToggled === true);
  step("recoverable delete + restore", result.restored === true);

  // Deeplink while running: open-url → session B.
  app.emit("open-url", {}, `catomicals://session/${result.sessionB}`);
  const deeplink = await runScenario(win, `
    const result = {};
    await waitFor(() => userMessages().some((text) => text.includes("E2E 消息乙")), 20000, "deeplink opened session B");
    result.opened = true;
    return result;
  `).catch((cause) => ({ error: String(cause) }));
  step("catomicals://session/<id> opens the exact session", deeplink.opened === true);

  outcome.sessionA = result.sessionA;
  outcome.sessionB = result.sessionB;
  finish(result.ok && deeplink.opened === true);
}

async function phase2(win) {
  const sa = JSON.stringify(sessionA ?? "");
  const result = await runScenario(win, `
    const result = {};
    // Launch-time deeplink should have opened session A; the transcript is
    // reconstructed from the persisted JSONL log, not React state.
    await waitFor(() => userMessages().length > 0, 30000, "transcript restored after restart");
    result.transcriptRestored = userMessages().some((text) => text.includes("E2E 消息甲"));
    result.title = currentTitle();

    await waitFor(() => rows().length === 2, 20000, "two sessions after restart");
    const rowA = document.querySelector('[data-testid="session-row-' + ${sa} + '"]');
    result.renamedPersisted = rowA !== null && rowA.textContent.includes("重命名甲");

    // Cross-session search works after restart too.
    click(document.querySelector("button.session-search-toggle"));
    const searchInput = await waitFor(() => document.querySelector('input[aria-label="搜索会话内容"]'), 10000, "search input");
    setValue(searchInput, "消息乙");
    searchInput.closest("form").requestSubmit();
    await waitFor(() => document.querySelector('[data-testid="session-search-results"]') !== null, 20000, "search results after restart");
    click(document.querySelector('[data-testid="session-search-results"] button'));
    await waitFor(() => userMessages().some((text) => text.includes("E2E 消息乙")), 20000, "session B transcript after restart");
    result.searchAfterRestart = true;

    result.ok = true;
    return result;
  `);

  step("transcript restored after restart (launch deeplink)", result.transcriptRestored === true);
  step("session title persisted through restart", result.renamedPersisted === true);
  step("cross-session search after restart", result.searchAfterRestart === true);
  outcome.title = result.title;
  finish(result.ok === true);
}

async function main() {
  await import("../dist/main.js");
  // NOTE: never `await app.whenReady()` at module top level — with the real
  // main imported, a pending top-level await deadlocks Electron's readiness.
  // Poll `app.isReady()` from inside this async task instead (the imported
  // main registers its own whenReady work and creates the window).
  const readyDeadline = Date.now() + 30_000;
  while (!app.isReady()) {
    if (Date.now() > readyDeadline) throw new Error("app never became ready");
    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  try {
    const win = await waitForWindow();
    await win.webContents.executeJavaScript(`
      new Promise((resolve, reject) => {
        const start = Date.now();
        const tick = () => {
          if (document.querySelector(".workbench-shell")) return resolve(true);
          if (Date.now() - start > 25000) return reject(new Error("shell did not mount"));
          setTimeout(tick, 100);
        };
        tick();
      });
    `);
    if (phase === "2") await phase2(win);
    else await phase1(win);
  } catch (error) {
    outcome.error = error instanceof Error ? error.message : String(error);
    finish(false);
  }
}

void main();

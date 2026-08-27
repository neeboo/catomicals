import { createReadStream, existsSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { dirname, extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import {
  app,
  BrowserWindow,
  ipcMain,
  safeStorage,
  session,
  WebContentsView,
  type IpcMainInvokeEvent,
} from "electron";
import type { DesktopState, PaneBounds, ToolTabId } from "./contracts.js";
import {
  IPC_CHANNELS,
  parseBrowserUrl,
  parseHarnessRequest,
  parsePaneBounds,
  parseToolTab,
  shouldBlockBrowserRequest,
} from "./ipc.js";
import { SettingsStore } from "./settings-store.js";

const currentDirectory = dirname(fileURLToPath(import.meta.url));
const desktopRoot = join(currentDirectory, "..");
const projectRoot = join(desktopRoot, "..");
const rendererDist = join(projectRoot, "web", "dist");
const browserPartition = "persist:catomicals-browser";

let window: BrowserWindow | null = null;
let browserView: WebContentsView | null = null;
let browserBounds: PaneBounds = { x: 0, y: 0, width: 0, height: 0 };
let activeTab: ToolTabId | null = null;
let toolsOpen = false;
let staticServer: Server | null = null;
let settingsStore: SettingsStore;

function assertRenderer(event: IpcMainInvokeEvent): void {
  if (!window || event.sender.id !== window.webContents.id) throw new Error("untrusted IPC sender");
}

function state(): DesktopState {
  return { desktop: true, toolsOpen, activeTab, safeStorageAvailable: safeStorage.isEncryptionAvailable() };
}

function destroyBrowserView(): void {
  if (!browserView) return;
  if (window && !window.isDestroyed()) window.contentView.removeChildView(browserView);
  if (!browserView.webContents.isDestroyed()) browserView.webContents.close();
  browserView = null;
}

function attachBrowserView(): WebContentsView {
  if (!window) throw new Error("window unavailable");
  destroyBrowserView();
  const view = new WebContentsView({
    webPreferences: {
      partition: browserPartition,
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  view.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  view.webContents.on("will-navigate", (event, url) => {
    try { parseBrowserUrl(url); } catch { event.preventDefault(); }
  });
  view.setBounds(browserBounds);
  window.contentView.addChildView(view);
  browserView = view;
  return view;
}

async function selectTab(tab: ToolTabId): Promise<DesktopState> {
  activeTab = tab;
  toolsOpen = true;
  if (tab !== "browser") {
    destroyBrowserView();
    return state();
  }
  const view = attachBrowserView();
  const settings = await settingsStore.read();
  await view.webContents.loadURL(parseBrowserUrl(settings.browserHome));
  return state();
}

function contentType(path: string): string {
  return ({ ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png" } as Record<string, string>)[extname(path)] ?? "application/octet-stream";
}

async function startRendererServer(): Promise<string> {
  return new Promise((resolve, reject) => {
    const server = createServer((request, response) => {
      const rawPath = decodeURIComponent(new URL(request.url ?? "/", "http://localhost").pathname);
      const relative = rawPath === "/" ? "index.html" : rawPath.slice(1);
      const candidate = normalize(join(rendererDist, relative));
      const rootWithSeparator = `${normalize(rendererDist)}/`;
      const filePath = candidate.startsWith(rootWithSeparator) && existsSync(candidate) ? candidate : join(rendererDist, "index.html");
      response.setHeader("Content-Type", contentType(filePath));
      response.setHeader("Content-Security-Policy", "default-src 'self'; connect-src 'self' http://127.0.0.1:18787 http://localhost:18787; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'");
      createReadStream(filePath).on("error", () => { response.statusCode = 404; response.end("Not found"); }).pipe(response);
    });
    server.once("error", reject);
    server.listen(5180, "127.0.0.1", () => {
      staticServer = server;
      resolve("http://localhost:5180");
    });
  });
}

function registerIpc(): void {
  ipcMain.handle(IPC_CHANNELS.getState, (event) => { assertRenderer(event); return state(); });
  ipcMain.handle(IPC_CHANNELS.selectTab, async (event, value: unknown) => { assertRenderer(event); return selectTab(parseToolTab(value)); });
  ipcMain.handle(IPC_CHANNELS.closeTools, (event) => { assertRenderer(event); destroyBrowserView(); toolsOpen = false; activeTab = null; return state(); });
  ipcMain.handle(IPC_CHANNELS.setPaneBounds, (event, value: unknown) => {
    assertRenderer(event);
    browserBounds = parsePaneBounds(value);
    browserView?.setBounds(browserBounds);
  });
  ipcMain.handle(IPC_CHANNELS.browserNavigate, async (event, value: unknown) => {
    assertRenderer(event);
    const url = parseBrowserUrl(value);
    if (activeTab !== "browser") throw new Error("browser tab inactive");
    const view = browserView ?? attachBrowserView();
    await view.webContents.loadURL(url);
    return url;
  });
  ipcMain.handle(IPC_CHANNELS.browserBack, (event) => { assertRenderer(event); if (browserView?.webContents.navigationHistory.canGoBack()) browserView.webContents.navigationHistory.goBack(); });
  ipcMain.handle(IPC_CHANNELS.browserForward, (event) => { assertRenderer(event); if (browserView?.webContents.navigationHistory.canGoForward()) browserView.webContents.navigationHistory.goForward(); });
  ipcMain.handle(IPC_CHANNELS.browserReload, (event) => { assertRenderer(event); browserView?.webContents.reload(); });
  ipcMain.handle(IPC_CHANNELS.settingsGet, (event) => { assertRenderer(event); return settingsStore.read(); });
  ipcMain.handle(IPC_CHANNELS.settingsUpdate, (event, value: unknown) => { assertRenderer(event); return settingsStore.write(value); });
  ipcMain.handle(IPC_CHANNELS.harnessInvoke, (event, value: unknown) => {
    assertRenderer(event);
    parseHarnessRequest(value);
    return { ok: false, status: "not-connected", message: "执行器适配器尚未接通；没有执行命令，也没有获得交易批准或签名权限。" };
  });
}

async function createWindow(): Promise<void> {
  settingsStore = new SettingsStore(app.getPath("userData"));
  const preload = join(currentDirectory, "preload.js");
  window = new BrowserWindow({
    width: 1480,
    height: 920,
    minWidth: 900,
    minHeight: 620,
    backgroundColor: "#111212",
    webPreferences: { preload, contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  window.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  window.on("closed", () => { destroyBrowserView(); window = null; });
  const rendererArgument = process.argv.find((argument) => argument.startsWith("--renderer-url="));
  const rendererUrl = rendererArgument?.slice("--renderer-url=".length) ?? await startRendererServer();
  await window.loadURL(rendererUrl);
}

app.whenReady().then(async () => {
  const browserSession = session.fromPartition(browserPartition);
  browserSession.webRequest.onBeforeRequest((details, callback) => callback({ cancel: shouldBlockBrowserRequest(details.url) }));
  registerIpc();
  await createWindow();
  app.on("activate", () => { if (BrowserWindow.getAllWindows().length === 0) void createWindow(); });
}).catch((error: unknown) => { console.error(error); app.quit(); });

app.on("window-all-closed", () => { if (process.platform !== "darwin") app.quit(); });
app.on("before-quit", () => { destroyBrowserView(); staticServer?.close(); });

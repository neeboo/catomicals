import { createReadStream, existsSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { dirname, extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import {
  app,
  BrowserWindow,
  ipcMain,
  safeStorage,
  session,
  WebContentsView,
  type IpcMainInvokeEvent,
  type Session,
} from "electron";
import {
  assertPublicBrowserUrl,
  createBrowserPartitionName,
  releaseBrowserPartition,
} from "./browser-security.js";
import type { DesktopState, PaneBounds, ToolTabId } from "./contracts.js";
import {
  IPC_CHANNELS,
  parseDesktopSettingsUpdate,
  parseExecutorCreateRequest,
  parseExecutorProbeRequest,
  parseExecutorResumeRequest,
  parseExecutorSendRequest,
  parseExecutorSessionRequest,
  parseHarnessRequest,
  parseIpcArguments,
  parsePaneBounds,
  parseToolTab,
} from "./ipc.js";
import {
  DESKTOP_ENDPOINTS,
  assertTrustedIpcFrame,
  rendererSecurityHeaders,
  resolveRendererUrl,
  trustedRendererNavigation,
} from "./runtime-security.js";
import { SettingsStore } from "./settings-store.js";
import { ShutdownCoordinator } from "./shutdown.js";
import { NodeProcessHost } from "./executors/process-manager.js";
import { ExecutorRegistry } from "./executors/registry.js";
import { createBuiltinCordisHost } from "./cordis/builtins.js";
import type { CordisHost } from "./cordis/host.js";
import { parsePluginIdRequest, parsePluginSettingsPatchRequest } from "./cordis/ipc.js";
import { FileCordisStateStore } from "./cordis/store.js";
import { cordisAccess } from "./cordis/permissions.js";
import { createDesktopCordisServices } from "./cordis/services.js";

const currentDirectory = dirname(fileURLToPath(import.meta.url));
const desktopRoot = join(currentDirectory, "..");
const projectRoot = join(desktopRoot, "..");
const rendererDist = join(projectRoot, "web", "dist");
let window: BrowserWindow | null = null;
let browserView: WebContentsView | null = null;
let browserViewSession: Session | null = null;
let browserBounds: PaneBounds = { x: 0, y: 0, width: 0, height: 0 };
let activeTab: ToolTabId | null = null;
let toolsOpen = false;
let staticServer: Server | null = null;
let settingsStore: SettingsStore;
let executorRegistry: ExecutorRegistry;
let cordisHost: CordisHost;
const rendererPluginAccess = cordisAccess(
  "plugin.catalog.read",
  "plugin.manifest.read",
  "plugin.settings_schema.read",
  "plugin.health.read",
  "plugin.settings.validate",
  "plugin.settings_intent.create",
);

function assertRenderer(event: IpcMainInvokeEvent): void {
  if (!window || window.isDestroyed() || !event.senderFrame) throw new Error("untrusted IPC sender");
  assertTrustedIpcFrame({
    senderId: event.sender.id,
    expectedSenderId: window.webContents.id,
    frameUrl: event.senderFrame.url,
    isMainFrame: event.senderFrame === window.webContents.mainFrame,
    parentFramePresent: event.senderFrame.parent !== null,
  });
}

function state(): DesktopState {
  return { desktop: true, toolsOpen, activeTab, safeStorageAvailable: safeStorage.isEncryptionAvailable() };
}

async function destroyBrowserView(): Promise<void> {
  const view = browserView;
  const viewSession = browserViewSession;
  browserView = null;
  browserViewSession = null;
  if (!view) return;
  if (window && !window.isDestroyed()) window.contentView.removeChildView(view);
  await releaseBrowserPartition({
    close: () => { if (!view.webContents.isDestroyed()) view.webContents.close(); },
    clearStorageData: () => viewSession?.clearStorageData() ?? Promise.resolve(),
    clearCache: () => viewSession?.clearCache() ?? Promise.resolve(),
  });
}

async function resolvePublicUrl(viewSession: Session, url: unknown): Promise<string> {
  return assertPublicBrowserUrl(url, async (hostname) => {
    const resolved = await viewSession.resolveHost(hostname, { source: "system" });
    return resolved.endpoints;
  });
}

async function loadPublicUrl(view: WebContentsView, url: unknown): Promise<string> {
  const trustedUrl = await resolvePublicUrl(view.webContents.session, url);
  await view.webContents.loadURL(trustedUrl);
  return trustedUrl;
}

async function attachBrowserView(): Promise<WebContentsView> {
  if (!window) throw new Error("window unavailable");
  await destroyBrowserView();
  const partition = createBrowserPartitionName("tool-pane", randomUUID());
  const viewSession = session.fromPartition(partition);
  viewSession.setPermissionCheckHandler(() => false);
  viewSession.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
  const view = new WebContentsView({
    webPreferences: {
      partition,
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  viewSession.webRequest.onBeforeRequest((details, callback) => {
    void resolvePublicUrl(viewSession, details.url).then(
      () => callback({ cancel: false }),
      () => callback({ cancel: true }),
    );
  });
  view.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  view.webContents.on("will-navigate", (event, url) => {
    event.preventDefault();
    void loadPublicUrl(view, url).catch(() => undefined);
  });
  view.webContents.on("will-redirect", (event, url) => {
    event.preventDefault();
    void loadPublicUrl(view, url).catch(() => undefined);
  });
  view.setBounds(browserBounds);
  window.contentView.addChildView(view);
  browserView = view;
  browserViewSession = viewSession;
  return view;
}

async function selectTab(tab: ToolTabId): Promise<DesktopState> {
  activeTab = tab;
  toolsOpen = true;
  if (tab !== "browser") {
    await destroyBrowserView();
    return state();
  }
  const view = await attachBrowserView();
  const settings = await settingsStore.read();
  await loadPublicUrl(view, settings.browserHome);
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
      for (const [name, value] of Object.entries(rendererSecurityHeaders())) response.setHeader(name, value);
      createReadStream(filePath).on("error", () => { response.statusCode = 404; response.end("Not found"); }).pipe(response);
    });
    server.once("error", reject);
    server.listen(5173, "127.0.0.1", () => {
      staticServer = server;
      resolve(DESKTOP_ENDPOINTS.rendererOrigin);
    });
  });
}

async function closeRendererServer(): Promise<void> {
  const server = staticServer;
  staticServer = null;
  if (!server) return;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => { if (error) reject(error); else resolve(); });
  });
}

function registerIpc(): void {
  ipcMain.handle(IPC_CHANNELS.getState, (event, ...args: unknown[]) => { assertRenderer(event); parseIpcArguments(args, 0); return state(); });
  ipcMain.handle(IPC_CHANNELS.selectTab, async (event, ...args: unknown[]) => { assertRenderer(event); const [value] = parseIpcArguments(args, 1); return selectTab(parseToolTab(value)); });
  ipcMain.handle(IPC_CHANNELS.closeTools, async (event, ...args: unknown[]) => { assertRenderer(event); parseIpcArguments(args, 0); await destroyBrowserView(); toolsOpen = false; activeTab = null; return state(); });
  ipcMain.handle(IPC_CHANNELS.setPaneBounds, (event, ...args: unknown[]) => {
    assertRenderer(event);
    const [value] = parseIpcArguments(args, 1);
    browserBounds = parsePaneBounds(value);
    browserView?.setBounds(browserBounds);
  });
  ipcMain.handle(IPC_CHANNELS.browserNavigate, async (event, ...args: unknown[]) => {
    assertRenderer(event);
    const [value] = parseIpcArguments(args, 1);
    if (activeTab !== "browser") throw new Error("browser tab inactive");
    const view = browserView ?? await attachBrowserView();
    return loadPublicUrl(view, value);
  });
  ipcMain.handle(IPC_CHANNELS.browserBack, (event, ...args: unknown[]) => { assertRenderer(event); parseIpcArguments(args, 0); if (browserView?.webContents.navigationHistory.canGoBack()) browserView.webContents.navigationHistory.goBack(); });
  ipcMain.handle(IPC_CHANNELS.browserForward, (event, ...args: unknown[]) => { assertRenderer(event); parseIpcArguments(args, 0); if (browserView?.webContents.navigationHistory.canGoForward()) browserView.webContents.navigationHistory.goForward(); });
  ipcMain.handle(IPC_CHANNELS.browserReload, (event, ...args: unknown[]) => { assertRenderer(event); parseIpcArguments(args, 0); browserView?.webContents.reload(); });
  ipcMain.handle(IPC_CHANNELS.settingsGet, (event, ...args: unknown[]) => { assertRenderer(event); parseIpcArguments(args, 0); return settingsStore.read(); });
  ipcMain.handle(IPC_CHANNELS.settingsUpdate, (event, ...args: unknown[]) => { assertRenderer(event); const [value] = parseIpcArguments(args, 1); return settingsStore.write(parseDesktopSettingsUpdate(value)); });
  ipcMain.handle(IPC_CHANNELS.harnessInvoke, (event, ...args: unknown[]) => {
    assertRenderer(event);
    const [value] = parseIpcArguments(args, 1);
    parseHarnessRequest(value);
    return { ok: false, status: "not-connected", message: "执行器适配器尚未接通；没有执行命令，也没有获得交易批准或签名权限。" };
  });
  ipcMain.handle(IPC_CHANNELS.executorProbe, (event, ...args: unknown[]) => {
    assertRenderer(event);
    const [value] = parseIpcArguments(args, 1);
    return executorRegistry.probe(parseExecutorProbeRequest(value).provider);
  });
  ipcMain.handle(IPC_CHANNELS.executorCreate, (event, ...args: unknown[]) => {
    assertRenderer(event);
    const [value] = parseIpcArguments(args, 1);
    return executorRegistry.create(parseExecutorCreateRequest(value));
  });
  ipcMain.handle(IPC_CHANNELS.executorResume, (event, ...args: unknown[]) => {
    assertRenderer(event);
    const [value] = parseIpcArguments(args, 1);
    return executorRegistry.resume(parseExecutorResumeRequest(value));
  });
  ipcMain.handle(IPC_CHANNELS.executorSend, (event, ...args: unknown[]) => {
    assertRenderer(event);
    const [value] = parseIpcArguments(args, 1);
    return executorRegistry.send(parseExecutorSendRequest(value));
  });
  ipcMain.handle(IPC_CHANNELS.executorInterrupt, (event, ...args: unknown[]) => {
    assertRenderer(event);
    const [value] = parseIpcArguments(args, 1);
    return executorRegistry.interrupt(parseExecutorSessionRequest(value).sessionId);
  });
  ipcMain.handle(IPC_CHANNELS.executorStatus, (event, ...args: unknown[]) => {
    assertRenderer(event);
    const [value] = parseIpcArguments(args, 1);
    return executorRegistry.status(parseExecutorSessionRequest(value).sessionId);
  });
  ipcMain.handle(IPC_CHANNELS.executorDispose, (event, ...args: unknown[]) => {
    assertRenderer(event);
    const [value] = parseIpcArguments(args, 1);
    return executorRegistry.dispose(parseExecutorSessionRequest(value).sessionId);
  });
  ipcMain.handle(IPC_CHANNELS.pluginList, (event, ...args: unknown[]) => {
    assertRenderer(event);
    parseIpcArguments(args, 0);
    return cordisHost.listPlugins(rendererPluginAccess);
  });
  ipcMain.handle(IPC_CHANNELS.pluginManifest, (event, ...args: unknown[]) => {
    assertRenderer(event);
    const [value] = parseIpcArguments(args, 1);
    return cordisHost.readManifest(parsePluginIdRequest(value).pluginId, rendererPluginAccess);
  });
  ipcMain.handle(IPC_CHANNELS.pluginSettingsSchema, (event, ...args: unknown[]) => {
    assertRenderer(event);
    const [value] = parseIpcArguments(args, 1);
    return cordisHost.readSettingsSchema(parsePluginIdRequest(value).pluginId, rendererPluginAccess);
  });
  ipcMain.handle(IPC_CHANNELS.pluginHealth, (event, ...args: unknown[]) => {
    assertRenderer(event);
    const [value] = parseIpcArguments(args, 1);
    return cordisHost.readHealth(parsePluginIdRequest(value).pluginId, rendererPluginAccess);
  });
  ipcMain.handle(IPC_CHANNELS.pluginValidateSettings, (event, ...args: unknown[]) => {
    assertRenderer(event);
    const [value] = parseIpcArguments(args, 1);
    const request = parsePluginSettingsPatchRequest(value);
    return cordisHost.validateSettingsPatch(request.pluginId, request.patch, rendererPluginAccess);
  });
  ipcMain.handle(IPC_CHANNELS.pluginCreateSettingsIntent, (event, ...args: unknown[]) => {
    assertRenderer(event);
    const [value] = parseIpcArguments(args, 1);
    const request = parsePluginSettingsPatchRequest(value);
    return cordisHost.createSettingsIntent(request.pluginId, request.patch, rendererPluginAccess);
  });
}

async function createWindow(): Promise<void> {
  const preload = join(currentDirectory, "preload.cjs");
  window = new BrowserWindow({
    width: 1480,
    height: 920,
    minWidth: 900,
    minHeight: 620,
    backgroundColor: "#111212",
    webPreferences: { preload, contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  window.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  const guardRendererNavigation = (event: Electron.Event, url: string): void => {
    if (!trustedRendererNavigation(url)) event.preventDefault();
  };
  window.webContents.on("will-navigate", guardRendererNavigation);
  window.webContents.on("will-redirect", guardRendererNavigation);
  window.on("closed", () => { void destroyBrowserView(); window = null; });
  const hasRendererOverride = process.argv.some((argument) => argument.startsWith("--renderer-url="));
  const resolvedRendererUrl = resolveRendererUrl({ packaged: app.isPackaged, argv: process.argv });
  const rendererUrl = !app.isPackaged && hasRendererOverride
    ? resolvedRendererUrl
    : await startRendererServer();
  await window.loadURL(rendererUrl);
}

app.whenReady().then(async () => {
  settingsStore = new SettingsStore(app.getPath("userData"));
  executorRegistry = new ExecutorRegistry({
    host: new NodeProcessHost(),
    readSettings: () => settingsStore.read(),
  });
  cordisHost = createBuiltinCordisHost(
    new FileCordisStateStore(app.getPath("userData")),
    createDesktopCordisServices({ readSettings: () => settingsStore.read() }),
  );
  await cordisHost.initialize();
  registerIpc();
  await createWindow();
  app.on("activate", () => { if (BrowserWindow.getAllWindows().length === 0) void createWindow(); });
}).catch((error: unknown) => { console.error(error); app.quit(); });

app.on("window-all-closed", () => { if (process.platform !== "darwin") app.quit(); });
const shutdownCoordinator = new ShutdownCoordinator({
  cleanupExecutors: () => executorRegistry?.disposeAll() ?? Promise.resolve(),
  cleanupBrowser: destroyBrowserView,
  closeServer: closeRendererServer,
  quit: () => app.quit(),
});
app.on("before-quit", (event) => {
  shutdownCoordinator.handleBeforeQuit(event).catch((error: unknown) => console.error(error));
});

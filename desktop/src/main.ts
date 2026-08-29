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
import { buildGenerativeUiPrompt } from "./executors/generative-ui.js";
import { createBuiltinCordisHost } from "./cordis/builtins.js";
import type { CordisHost } from "./cordis/host.js";
import {
  parsePluginIdRequest,
  parsePluginSettingsPatchRequest,
  parsePluginSettingsReviewRequest,
} from "./cordis/ipc.js";
import { FileCordisStateStore } from "./cordis/store.js";
import { cordisAccess, cordisDesktopAccess } from "./cordis/permissions.js";
import { createDesktopCordisServices } from "./cordis/services.js";
import { CordisRuntimeConfig } from "./cordis/runtime-config.js";
import { applyRuntimeSettingsImpact } from "./runtime-coordinator.js";
import { LegacyRuntimeMigrationCoordinator } from "./runtime-migration.js";
import { createWalletProxy } from "./wallet-proxy.js";
import { startCordisAgentBridge, type CordisAgentBridge } from "./cordis/agent-bridge.js";
import { resolveCatomicalsCommand } from "./catomicals-command.js";
import { WalletNodeSupervisor } from "./wallet-supervisor.js";
import { SessionManager } from "./sessions/manager.js";
import { createRendererNavigationPusher, registerSessionIpc } from "./sessions/ipc.js";
import { createCatomicalsDeeplinkService, findDeeplinkInArgv } from "./deeplink.js";
import { IdentityStore } from "./identity/store.js";
import { IdentityService } from "./identity/service.js";
import { LocalDeviceIdentityProvider } from "./identity/provider.js";
import { createIdentityCipher } from "./identity/secure-storage.js";
import { registerIdentityIpc } from "./identity/ipc.js";

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
let runtimeConfig: CordisRuntimeConfig;
let walletProxy: ReturnType<typeof createWalletProxy>;
let walletSupervisor: WalletNodeSupervisor | undefined;
let sessionManager: SessionManager | undefined;
let cordisAgentBridge: CordisAgentBridge | undefined;
const identityCipherSource = { current: () => createIdentityCipher(safeStorage) };
const rendererPluginAccess = cordisAccess(
  "plugin.catalog.read",
  "plugin.manifest.read",
  "plugin.settings.read",
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
  return { desktop: true, toolsOpen, activeTab, safeStorageAvailable: identityCipherSource.current() !== undefined };
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
  await loadPublicUrl(view, await runtimeConfig.browserHome());
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
  ipcMain.handle(IPC_CHANNELS.walletRequest, (event, ...args: unknown[]) => {
    assertRenderer(event);
    const [value] = parseIpcArguments(args, 1);
    return walletProxy(value);
  });
  ipcMain.handle(IPC_CHANNELS.mcpEnabledGet, (event, ...args: unknown[]) => {
    assertRenderer(event);
    parseIpcArguments(args, 0);
    return runtimeConfig.mcpEnabled();
  });
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
  ipcMain.handle(IPC_CHANNELS.pluginSettingsRead, (event, ...args: unknown[]) => {
    assertRenderer(event);
    const [value] = parseIpcArguments(args, 1);
    return cordisHost.readPluginSettings(parsePluginIdRequest(value).pluginId, rendererPluginAccess);
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
  ipcMain.handle(IPC_CHANNELS.pluginSettingsReview, (event, ...args: unknown[]) => {
    assertRenderer(event);
    const [value] = parseIpcArguments(args, 1);
    return cordisHost.readSettingsReview(parsePluginSettingsReviewRequest(value).reviewId, rendererPluginAccess);
  });
  ipcMain.handle(IPC_CHANNELS.pluginConfirmSettingsIntent, (event, ...args: unknown[]) => {
    assertRenderer(event);
    const [value] = parseIpcArguments(args, 1);
    const reviewId = parsePluginSettingsReviewRequest(value).reviewId;
    return cordisHost.readSettingsReview(reviewId, rendererPluginAccess).then(async (review) => {
      const confirmed = await cordisHost.confirmSettingsIntent(reviewId, cordisDesktopAccess);
      applyRuntimeSettingsImpact(executorRegistry, review);
      return confirmed;
    });
  });
}

async function createWindow(): Promise<void> {
  const preload = join(currentDirectory, "preload.cjs");
  const isMac = process.platform === "darwin";
  window = new BrowserWindow({
    width: 1480,
    height: 920,
    minWidth: 900,
    minHeight: 620,
    // DSH near-black canvas (design-platform.css bluish-950).
    backgroundColor: "#151517",
    // Frameless hidden title style on macOS: no OS/app title row and no
    // renderer titlebar strip — panes begin at y=0. The traffic lights float
    // over the left sidebar, which owns that zone via its top padding and an
    // invisible drag overlay; the center conversation header is the other
    // drag surface. Other platforms keep the native frame.
    ...(isMac
      ? { titleBarStyle: "hidden" as const, trafficLightPosition: { x: 10, y: 10 } }
      : {}),
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
  const cordisStateStore = new FileCordisStateStore(app.getPath("userData"));
  const runtimeMigration = new LegacyRuntimeMigrationCoordinator({
    userDataPath: app.getPath("userData"),
    settingsStore,
    stateStore: cordisStateStore,
  });
  await runtimeMigration.recoverBeforeRuntime();
  const legacyRuntimeSettings = await settingsStore.readLegacyRuntimeSettings();
  const executorProcessHost = new NodeProcessHost();
  const catomicalsCommand = resolveCatomicalsCommand(projectRoot);
  executorRegistry = new ExecutorRegistry({
    host: executorProcessHost,
    readProfile: (provider) => runtimeConfig.executor(provider),
    cordisAgentBridge: () => {
      if (!cordisAgentBridge) throw new Error("Cordis agent bridge unavailable");
      return cordisAgentBridge;
    },
    cordisMcpCommand: catomicalsCommand,
    mcpEnabled: () => runtimeConfig.mcpEnabled(),
    walletEndpoint: () => runtimeConfig.walletEndpoint(),
    preparePrompt: async (provider, prompt) => buildGenerativeUiPrompt(provider, prompt, await runtimeConfig.generativeUi()),
  });
  cordisHost = createBuiltinCordisHost(
    cordisStateStore,
    createDesktopCordisServices({
      executorProbe: (provider, profile) => executorRegistry.probeConfigured(provider, profile),
      mcpProbe: async () => {
        const result = await executorProcessHost.probe({
          executable: catomicalsCommand,
          args: ["mcp", "serve", "--help"],
          environmentKeys: [],
        });
        return result.exitCode === 0 && result.signal === null && !result.error;
      },
    }),
  );
  runtimeConfig = new CordisRuntimeConfig(cordisHost, runtimeMigration);
  walletProxy = createWalletProxy({ walletEndpoint: () => runtimeConfig.walletEndpoint() });
  await cordisHost.initialize();
  if (legacyRuntimeSettings) {
    try {
      await runtimeMigration.migrate(cordisHost, legacyRuntimeSettings);
    } catch (error: unknown) {
      runtimeMigration.assertRuntimeReady();
      console.error("legacy runtime settings migration deferred", error);
    }
  }
  const configuredWallet = await runtimeConfig.walletRuntime();
  const repositoryBitcoinDataDirectory = join(projectRoot, ".runtime", "inquisition-signet-data");
  const bitcoinDataDirectory = process.env.CATOMICALS_BITCOIN_DATADIR
    ?? (existsSync(repositoryBitcoinDataDirectory) ? repositoryBitcoinDataDirectory : undefined);
  const rendererOverride = process.argv.find((argument) => argument.startsWith("--renderer-url="));
  const rpOrigin = rendererOverride
    ? new URL(rendererOverride.slice("--renderer-url=".length)).origin
    : DESKTOP_ENDPOINTS.rendererOrigin;
  walletSupervisor = new WalletNodeSupervisor({
    command: catomicalsCommand,
    processHost: new NodeProcessHost(),
  });
  // The E2E harness runs the shell without a wallet node: chat is
  // session-backed and wallet actions stay executor tools, so a missing node
  // must not block the integration test (no broadcast is attempted).
  const e2eHarness = process.env.CATOMICALS_E2E === "1";
  if (e2eHarness) {
    console.info("wallet runtime skipped (E2E harness)");
  } else {
    const walletRuntime = await walletSupervisor.start({
      ...configuredWallet,
      rpOrigin,
      ...(bitcoinDataDirectory ? { bitcoinDataDirectory } : {}),
    });
    console.info(`wallet runtime ${walletRuntime.state} at ${walletRuntime.endpoint}`);
  }
  cordisAgentBridge = await startCordisAgentBridge({ host: cordisHost });
  registerIpc();
  registerIdentityIpc({
    service: new IdentityService(
      new IdentityStore(app.getPath("userData"), identityCipherSource),
      [new LocalDeviceIdentityProvider()],
    ),
    assertSender: assertRenderer,
  });
  // Persistent session store: canonical append-only JSONL logs, FTS5 search,
  // and recoverable trash. Wired after registerIpc() so the renderer's initial
  // session list call finds a handler, and before createWindow() so deeplink
  // navigation reaches a live window.
  sessionManager = new SessionManager({ root: join(app.getPath("userData"), "sessions") });
  registerSessionIpc({
    manager: sessionManager,
    assertSender: assertRenderer,
    pushNavigation: createRendererNavigationPusher(() => window),
  });
  await createWindow();
  createCatomicalsDeeplinkService(
    {
      registerProtocolClient: () => app.setAsDefaultProtocolClient("catomicals"),
      onOpenUrl: (listener) => app.on("open-url", (_event, url) => listener(url)),
      removeOpenUrlListener: (listener) => app.removeListener("open-url", listener as never),
      onSecondInstance: (listener) => app.on("second-instance", (_event, argv) => listener(argv)),
      removeSecondInstanceListener: (listener) => app.removeListener("second-instance", listener as never),
      // Launch-time deep links are honored once below, after the renderer has
      // mounted its navigation listener (the service's own argv microtask can
      // race the React effect that subscribes).
      currentArgv: [],
    },
    (event) => sessionManager!.navigate(
      event.kind === "session-open" ? { kind: "session-open", sessionId: event.sessionId! } : { kind: "session-list" },
      "deeplink",
    ),
  );
  const launchTarget = findDeeplinkInArgv(process.argv);
  if (launchTarget?.ok) {
    setTimeout(() => {
      sessionManager?.navigate(
        launchTarget.target.kind === "session"
          ? { kind: "session-open", sessionId: launchTarget.target.sessionId }
          : { kind: "session-list" },
        "deeplink",
      );
    }, 250);
  }
  app.on("activate", () => { if (BrowserWindow.getAllWindows().length === 0) void createWindow(); });
}).catch((error: unknown) => { console.error(error); app.quit(); });

app.on("window-all-closed", () => { if (process.platform !== "darwin") app.quit(); });
const shutdownCoordinator = new ShutdownCoordinator({
  closeAgentBridge: () => cordisAgentBridge?.close() ?? Promise.resolve(),
  cleanupExecutors: () => executorRegistry?.disposeAll() ?? Promise.resolve(),
  cleanupWallet: () => walletSupervisor?.dispose() ?? Promise.resolve(),
  cleanupBrowser: destroyBrowserView,
  closeServer: closeRendererServer,
  closeSessions: () => sessionManager?.close() ?? Promise.resolve(),
  quit: () => app.quit(),
});
app.on("before-quit", (event) => {
  shutdownCoordinator.handleBeforeQuit(event).catch((error: unknown) => console.error(error));
});

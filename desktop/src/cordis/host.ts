import { randomUUID } from "node:crypto";
import { runHealthCheck, type CordisHealthReport, type CordisService } from "./health.js";
import {
  digestJson,
  parsePluginId,
  verifyFixedPluginPackage,
  type FixedPluginRegistration,
  type PluginManifest,
  type TrustedPlugin,
} from "./manifest.js";
import { runMigrations } from "./migrations.js";
import {
  applySettingsPatch,
  defaultSettings,
  parseSettingsSchema,
  validateSettings,
  type CordisSettings,
  type CordisSettingsPatch,
  type CordisSettingsSchema,
  type RestartImpact,
} from "./settings.js";
import type { CordisStateStore, PluginTree, StoredPluginState } from "./store.js";

export type PluginStatus = "ready" | "isolated";
export type PluginErrorCode = "package_invalid" | "missing_service" | "state_invalid" | "migration_failed" | "health_failed";

interface PluginRuntime {
  readonly registration: FixedPluginRegistration;
  manifest?: PluginManifest;
  schema?: CordisSettingsSchema;
  state?: StoredPluginState;
  status: PluginStatus;
  health: CordisHealthReport;
  errorCode?: PluginErrorCode;
}

export interface PluginListEntry {
  readonly pluginId: string;
  readonly pluginVersion?: string;
  readonly status: PluginStatus;
  readonly errorCode?: PluginErrorCode;
}

export interface PluginView extends PluginListEntry {
  readonly manifest: PluginManifest;
  readonly settings: CordisSettings;
  readonly settingsDigest: string;
}

export interface SettingsValidationResult {
  readonly valid: boolean;
  readonly settingsDigest?: string;
  readonly restartImpact?: RestartImpact;
  readonly error?: string;
}

export interface SettingsIntent {
  readonly intentId: string;
  readonly pluginId: string;
  readonly pluginVersion: string;
  readonly baseSettingsDigest: string;
  readonly candidateSettingsDigest: string;
  readonly patchDigest: string;
  readonly restartImpact: RestartImpact;
  readonly permissionDelta: readonly [];
  readonly createdAt: string;
}

interface PendingIntent extends SettingsIntent {
  readonly candidateSettings: CordisSettings;
}

interface CordisHostOptions {
  readonly registrations: readonly FixedPluginRegistration[];
  readonly trust: readonly TrustedPlugin[];
  readonly stateStore: CordisStateStore;
  readonly services?: readonly CordisService[];
  readonly now?: () => Date;
  readonly createId?: () => string;
}

function isolatedHealth(code: PluginErrorCode, checkedAt: string): CordisHealthReport {
  return { status: "isolated", code, message: "plugin isolated", checkedAt };
}

function tree(options: {
  manifest: PluginManifest;
  settings: CordisSettings;
}): PluginTree {
  return {
    pluginVersion: options.manifest.plugin_version,
    settingsSchemaVersion: options.manifest.settings.schema_version,
    migrationVersion: options.manifest.migration?.current ?? 0,
    settings: structuredClone(options.settings),
    settingsDigest: digestJson(options.settings),
  };
}

export class CordisHost {
  private readonly registrations: readonly FixedPluginRegistration[];
  private readonly trust = new Map<string, TrustedPlugin>();
  private readonly services = new Map<string, CordisService>();
  private readonly runtimes = new Map<string, PluginRuntime>();
  private readonly intents = new Map<string, PendingIntent>();
  private readonly promotionTails = new Map<string, Promise<void>>();
  private readonly now: () => Date;
  private readonly createId: () => string;

  constructor(private readonly options: CordisHostOptions) {
    this.registrations = [...options.registrations];
    this.now = options.now ?? (() => new Date());
    this.createId = options.createId ?? randomUUID;
    for (const item of options.trust) {
      parsePluginId(item.pluginId);
      if (this.trust.has(item.pluginId)) throw new Error("duplicate trusted plugin");
      this.trust.set(item.pluginId, item);
    }
    for (const service of options.services ?? []) {
      if (this.services.has(service.name)) throw new Error("duplicate Cordis service");
      this.services.set(service.name, service);
    }
  }

  async initialize(): Promise<void> {
    this.runtimes.clear();
    const seen = new Set<string>();
    for (const registration of this.registrations) {
      parsePluginId(registration.id);
      if (seen.has(registration.id)) throw new Error("duplicate fixed plugin registration");
      seen.add(registration.id);
      await this.initializePlugin(registration);
    }
  }

  private async initializePlugin(registration: FixedPluginRegistration): Promise<void> {
    const checkedAt = this.now().toISOString();
    const runtime: PluginRuntime = {
      registration,
      status: "isolated",
      health: isolatedHealth("package_invalid", checkedAt),
      errorCode: "package_invalid",
    };
    this.runtimes.set(registration.id, runtime);
    const trust = this.trust.get(registration.id);
    try {
      if (!trust) throw new Error("plugin is not allowlisted");
      runtime.manifest = verifyFixedPluginPackage(registration, trust);
      runtime.schema = parseSettingsSchema(registration.settingsSchema);
    } catch {
      return;
    }
    const missing = runtime.manifest.inject.required.find((service) => !this.services.has(service));
    if (missing) {
      runtime.errorCode = "missing_service";
      runtime.health = isolatedHealth("missing_service", checkedAt);
      return;
    }
    let stored: StoredPluginState | undefined;
    try {
      stored = await this.options.stateStore.load(registration.id);
      if (stored && stored.lastGood.settingsDigest !== digestJson(stored.lastGood.settings)) throw new Error("stored settings digest mismatch");
    } catch {
      runtime.errorCode = "state_invalid";
      runtime.health = isolatedHealth("state_invalid", checkedAt);
      return;
    }
    let candidate: CordisSettings;
    try {
      if (!stored) {
        candidate = defaultSettings(runtime.schema);
      } else {
        candidate = runMigrations(
          stored.lastGood.settings,
          stored.lastGood.migrationVersion,
          runtime.manifest.migration?.current ?? 0,
          registration.migrations ?? [],
        );
        candidate = validateSettings(runtime.schema, candidate);
      }
    } catch {
      runtime.state = stored;
      runtime.errorCode = "migration_failed";
      runtime.health = isolatedHealth("migration_failed", checkedAt);
      return;
    }
    const health = await this.checkHealth(runtime, candidate, checkedAt);
    if (health.status === "unhealthy" || health.status === "isolated") {
      runtime.state = stored;
      runtime.errorCode = "health_failed";
      runtime.health = isolatedHealth("health_failed", checkedAt);
      return;
    }
    const nextState: StoredPluginState = {
      storageVersion: 1,
      pluginId: registration.id,
      lastGood: tree({ manifest: runtime.manifest, settings: candidate }),
    };
    try {
      await this.options.stateStore.save(registration.id, nextState);
    } catch {
      runtime.state = stored;
      runtime.errorCode = "state_invalid";
      runtime.health = isolatedHealth("state_invalid", checkedAt);
      return;
    }
    runtime.state = nextState;
    runtime.status = "ready";
    runtime.errorCode = undefined;
    runtime.health = health;
  }

  private async checkHealth(runtime: PluginRuntime, settings: CordisSettings, checkedAt = this.now().toISOString()): Promise<CordisHealthReport> {
    if (!runtime.manifest) throw new Error("plugin manifest unavailable");
    return runHealthCheck({
      settings,
      requiredServices: runtime.manifest.inject.required,
      optionalServices: runtime.manifest.inject.optional,
      services: this.services,
      check: runtime.registration.healthCheck,
      checkedAt,
    });
  }

  listPlugins(): PluginListEntry[] {
    return [...this.runtimes.values()].map((runtime) => ({
      pluginId: runtime.registration.id,
      ...(runtime.manifest ? { pluginVersion: runtime.manifest.plugin_version } : {}),
      status: runtime.status,
      ...(runtime.errorCode ? { errorCode: runtime.errorCode } : {}),
    }));
  }

  readPlugin(pluginIdValue: unknown): PluginView {
    const runtime = this.readyRuntime(pluginIdValue);
    return {
      pluginId: runtime.registration.id,
      pluginVersion: runtime.manifest.plugin_version,
      status: runtime.status,
      manifest: structuredClone(runtime.manifest),
      settings: structuredClone(runtime.state.lastGood.settings),
      settingsDigest: runtime.state.lastGood.settingsDigest,
    };
  }

  readManifest(pluginIdValue: unknown): PluginManifest {
    return structuredClone(this.readyRuntime(pluginIdValue).manifest);
  }

  readSettingsSchema(pluginIdValue: unknown): CordisSettingsSchema {
    return structuredClone(this.readyRuntime(pluginIdValue).schema);
  }

  readHealth(pluginIdValue: unknown): CordisHealthReport {
    const pluginId = parsePluginId(pluginIdValue);
    const runtime = this.runtimes.get(pluginId);
    if (!runtime) throw new Error("plugin not found");
    return structuredClone(runtime.health);
  }

  validateSettingsPatch(pluginIdValue: unknown, patch: unknown): SettingsValidationResult {
    try {
      const runtime = this.readyRuntime(pluginIdValue);
      const result = applySettingsPatch(runtime.schema, runtime.state.lastGood.settings, patch);
      return { valid: true, settingsDigest: digestJson(result.settings), restartImpact: result.restartImpact };
    } catch (error) {
      return { valid: false, error: error instanceof Error ? error.message : "invalid settings patch" };
    }
  }

  createSettingsIntent(pluginIdValue: unknown, patchValue: unknown): SettingsIntent {
    const runtime = this.readyRuntime(pluginIdValue);
    const patch = patchValue as CordisSettingsPatch;
    const result = applySettingsPatch(runtime.schema, runtime.state.lastGood.settings, patch);
    const intent: PendingIntent = {
      intentId: this.createId(),
      pluginId: runtime.registration.id,
      pluginVersion: runtime.manifest.plugin_version,
      baseSettingsDigest: runtime.state.lastGood.settingsDigest,
      candidateSettingsDigest: digestJson(result.settings),
      patchDigest: digestJson(patchValue),
      restartImpact: result.restartImpact,
      permissionDelta: [],
      createdAt: this.now().toISOString(),
      candidateSettings: result.settings,
    };
    this.intents.set(intent.intentId, intent);
    const { candidateSettings: _candidateSettings, ...view } = intent;
    return view;
  }

  async promoteSettingsIntent(intentId: string): Promise<PluginView> {
    if (!/^[0-9A-Za-z._:-]{1,128}$/.test(intentId)) throw new Error("invalid settings intent");
    const intent = this.intents.get(intentId);
    if (!intent) throw new Error("settings intent not found");
    return this.withPluginPromotionLock(intent.pluginId, () => this.promotePendingIntent(intent));
  }

  private async promotePendingIntent(intent: PendingIntent): Promise<PluginView> {
    const runtime = this.readyRuntime(intent.pluginId);
    if (runtime.manifest.plugin_version !== intent.pluginVersion
      || runtime.state.lastGood.settingsDigest !== intent.baseSettingsDigest) throw new Error("stale settings intent");
    const health = await this.checkHealth(runtime, intent.candidateSettings);
    if (health.status === "unhealthy" || health.status === "isolated") throw new Error("plugin health check failed");
    const nextState: StoredPluginState = {
      storageVersion: 1,
      pluginId: runtime.registration.id,
      lastGood: tree({ manifest: runtime.manifest, settings: intent.candidateSettings }),
    };
    await this.options.stateStore.save(runtime.registration.id, nextState);
    runtime.state = nextState;
    runtime.health = health;
    this.intents.delete(intent.intentId);
    return this.readPlugin(runtime.registration.id);
  }

  private async withPluginPromotionLock<T>(pluginId: string, work: () => Promise<T>): Promise<T> {
    const previous = this.promotionTails.get(pluginId) ?? Promise.resolve();
    let release = (): void => undefined;
    const current = new Promise<void>((resolve) => { release = resolve; });
    const tail = previous.then(() => current);
    this.promotionTails.set(pluginId, tail);
    await previous;
    try {
      return await work();
    } finally {
      release();
      if (this.promotionTails.get(pluginId) === tail) this.promotionTails.delete(pluginId);
    }
  }

  private readyRuntime(pluginIdValue: unknown): PluginRuntime & {
    manifest: PluginManifest;
    schema: CordisSettingsSchema;
    state: StoredPluginState;
  } {
    const pluginId = parsePluginId(pluginIdValue);
    const runtime = this.runtimes.get(pluginId);
    if (!runtime) throw new Error("plugin not found");
    if (runtime.status !== "ready" || !runtime.manifest || !runtime.schema || !runtime.state) throw new Error("plugin isolated");
    return runtime as PluginRuntime & { manifest: PluginManifest; schema: CordisSettingsSchema; state: StoredPluginState };
  }
}

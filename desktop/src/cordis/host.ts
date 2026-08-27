import { randomUUID } from "node:crypto";
import { runHealthCheck, type CordisHealthReport, type CordisService } from "./health.js";
import {
  canonicalJson, digestJson, parsePluginId, verifyFixedPluginPackage,
  type FixedPluginRegistration, type PluginManifest, type TrustedPlugin,
} from "./manifest.js";
import { runMigrations } from "./migrations.js";
import { assertCordisPermission, type CordisAccessContext } from "./permissions.js";
import {
  applySettingsPatch, defaultSettings, parseSettingsPatch, parseSettingsSchema, validateSettings,
  type CordisSettings, type CordisSettingsSchema, type RestartImpact,
} from "./settings.js";
import type { CordisStateStore, PluginTree, StoredPluginState } from "./store.js";

export type PluginStatus = "ready" | "isolated";
export type PluginErrorCode = "package_invalid" | "missing_service" | "state_invalid" | "migration_failed" | "health_failed";

interface PluginRuntime {
  readonly registration: FixedPluginRegistration;
  manifest?: PluginManifest;
  schema?: CordisSettingsSchema;
  recoverySettings?: CordisSettings;
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

interface PendingIntent extends SettingsIntent { readonly patchJson: string }

export interface SecretReferenceRegistry {
  exists(reference: string): Promise<boolean>;
}

interface CordisHostOptions {
  readonly registrations: readonly FixedPluginRegistration[];
  readonly trust: readonly TrustedPlugin[];
  readonly stateStore: CordisStateStore;
  readonly services?: readonly CordisService[];
  readonly secretReferences?: SecretReferenceRegistry;
  readonly now?: () => Date;
  readonly createId?: () => string;
}

function isolatedHealth(code: PluginErrorCode, checkedAt: string): CordisHealthReport {
  return { status: "isolated", code, message: "plugin isolated", checkedAt };
}

function tree(options: { manifest: PluginManifest; settings: CordisSettings }): PluginTree {
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
      registration, status: "isolated", health: isolatedHealth("package_invalid", checkedAt), errorCode: "package_invalid",
    };
    this.runtimes.set(registration.id, runtime);
    try {
      const trust = this.trust.get(registration.id);
      if (!trust) throw new Error("plugin is not allowlisted");
      runtime.manifest = verifyFixedPluginPackage(registration, trust);
      runtime.schema = parseSettingsSchema(registration.settingsSchema);
      runtime.recoverySettings = defaultSettings(runtime.schema);
    } catch {
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
    try {
      const candidate = stored
        ? runMigrations(stored.lastGood.settings, stored.lastGood.migrationVersion,
          runtime.manifest.migration?.current ?? 0, registration.migrations ?? [])
        : runtime.recoverySettings;
      runtime.recoverySettings = validateSettings(runtime.schema, candidate);
    } catch {
      runtime.state = stored;
      runtime.errorCode = "migration_failed";
      runtime.health = isolatedHealth("migration_failed", checkedAt);
      return;
    }
    runtime.state = stored;
    if (this.missingRequiredService(runtime.manifest)) {
      runtime.errorCode = "missing_service";
      runtime.health = isolatedHealth("missing_service", checkedAt);
      return;
    }
    await this.activateIfHealthy(this.verifiedRuntime(registration.id), checkedAt);
  }

  private requiredServices(manifest: PluginManifest): readonly string[] {
    return [...new Set([...manifest.inject.required, ...(manifest.health_service ? [manifest.health_service] : [])])];
  }

  private missingRequiredService(manifest: PluginManifest): string | undefined {
    return this.requiredServices(manifest).find((service) => !this.services.has(service));
  }

  private async checkHealth(
    runtime: PluginRuntime & { manifest: PluginManifest },
    settings: CordisSettings,
    checkedAt = this.now().toISOString(),
  ): Promise<CordisHealthReport> {
    return runHealthCheck({
      settings,
      requiredServices: this.requiredServices(runtime.manifest),
      optionalServices: runtime.manifest.inject.optional,
      services: this.services,
      check: runtime.registration.healthCheck,
      checkedAt,
    });
  }

  private async activateIfHealthy(
    runtime: PluginRuntime & { manifest: PluginManifest; schema: CordisSettingsSchema; recoverySettings: CordisSettings },
    checkedAt = this.now().toISOString(),
  ): Promise<void> {
    const health = await this.checkHealth(runtime, runtime.recoverySettings, checkedAt);
    if (health.status === "unhealthy" || health.status === "isolated") {
      runtime.status = "isolated";
      runtime.errorCode = "health_failed";
      runtime.health = isolatedHealth("health_failed", checkedAt);
      return;
    }
    const nextState: StoredPluginState = {
      storageVersion: 1,
      pluginId: runtime.registration.id,
      lastGood: tree({ manifest: runtime.manifest, settings: runtime.recoverySettings }),
    };
    try {
      await this.options.stateStore.save(runtime.registration.id, nextState);
    } catch {
      runtime.status = "isolated";
      runtime.errorCode = "state_invalid";
      runtime.health = isolatedHealth("state_invalid", checkedAt);
      return;
    }
    runtime.state = nextState;
    runtime.status = "ready";
    runtime.errorCode = undefined;
    runtime.health = health;
  }

  listPlugins(access: CordisAccessContext): PluginListEntry[] {
    assertCordisPermission(access, "plugin.catalog.read");
    return [...this.runtimes.values()].map((runtime) => ({
      pluginId: runtime.registration.id,
      ...(runtime.manifest ? { pluginVersion: runtime.manifest.plugin_version } : {}),
      status: runtime.status,
      ...(runtime.errorCode ? { errorCode: runtime.errorCode } : {}),
    }));
  }

  readPlugin(pluginIdValue: unknown): PluginView {
    return this.pluginView(this.readyRuntime(pluginIdValue));
  }

  readManifest(pluginIdValue: unknown, access: CordisAccessContext): PluginManifest {
    assertCordisPermission(access, "plugin.manifest.read");
    return structuredClone(this.verifiedRuntime(pluginIdValue).manifest);
  }

  readSettingsSchema(pluginIdValue: unknown, access: CordisAccessContext): CordisSettingsSchema {
    assertCordisPermission(access, "plugin.settings_schema.read");
    return structuredClone(this.verifiedRuntime(pluginIdValue).schema);
  }

  async readHealth(pluginIdValue: unknown, access: CordisAccessContext): Promise<CordisHealthReport> {
    assertCordisPermission(access, "plugin.health.read");
    const pluginId = parsePluginId(pluginIdValue);
    const runtime = this.runtimes.get(pluginId);
    if (!runtime) throw new Error("plugin not found");
    if (!runtime.manifest || !runtime.schema || !runtime.recoverySettings
      || runtime.errorCode === "package_invalid" || runtime.errorCode === "state_invalid" || runtime.errorCode === "migration_failed") {
      return structuredClone(runtime.health);
    }
    const verified = this.verifiedRuntime(pluginId);
    if (this.missingRequiredService(verified.manifest)) {
      verified.status = "isolated";
      verified.errorCode = "missing_service";
      verified.health = isolatedHealth("missing_service", this.now().toISOString());
      return structuredClone(verified.health);
    }
    if (verified.status === "ready" && verified.state) {
      const health = await this.checkHealth(verified, verified.state.lastGood.settings);
      if (health.status === "unhealthy" || health.status === "isolated") {
        verified.status = "isolated";
        verified.errorCode = "health_failed";
        verified.health = isolatedHealth("health_failed", this.now().toISOString());
      } else {
        verified.health = health;
      }
      return structuredClone(verified.health);
    }
    await this.activateIfHealthy(verified);
    return structuredClone(verified.health);
  }

  validateSettingsPatch(pluginIdValue: unknown, patch: unknown, access: CordisAccessContext): SettingsValidationResult {
    assertCordisPermission(access, "plugin.settings.validate");
    try {
      const runtime = this.verifiedRuntime(pluginIdValue);
      const result = applySettingsPatch(runtime.schema, runtime.recoverySettings, patch);
      return { valid: true, settingsDigest: digestJson(result.settings), restartImpact: result.restartImpact };
    } catch (error) {
      return { valid: false, error: error instanceof Error ? error.message : "invalid settings patch" };
    }
  }

  createSettingsIntent(pluginIdValue: unknown, patchValue: unknown, access: CordisAccessContext): SettingsIntent {
    assertCordisPermission(access, "plugin.settings_intent.create");
    const runtime = this.verifiedRuntime(pluginIdValue);
    const patch = parseSettingsPatch(patchValue);
    const result = applySettingsPatch(runtime.schema, runtime.recoverySettings, patch);
    const intent: PendingIntent = {
      intentId: this.createId(),
      pluginId: runtime.registration.id,
      pluginVersion: runtime.manifest.plugin_version,
      baseSettingsDigest: digestJson(runtime.recoverySettings),
      candidateSettingsDigest: digestJson(result.settings),
      patchDigest: digestJson(patch),
      restartImpact: result.restartImpact,
      permissionDelta: [],
      createdAt: this.now().toISOString(),
      patchJson: canonicalJson(patch),
    };
    this.intents.set(intent.intentId, intent);
    return this.intentView(intent);
  }

  async promoteSettingsIntent(intentId: string): Promise<PluginView> {
    if (!/^[0-9A-Za-z._:-]{1,128}$/.test(intentId)) throw new Error("invalid settings intent");
    const intent = this.intents.get(intentId);
    if (!intent) throw new Error("settings intent not found");
    return this.withPluginPromotionLock(intent.pluginId, () => this.promotePendingIntent(intent));
  }

  private async promotePendingIntent(intent: PendingIntent): Promise<PluginView> {
    const runtime = this.readyRuntime(intent.pluginId);
    const stored = await this.options.stateStore.load(runtime.registration.id);
    if (!stored || stored.lastGood.settingsDigest !== digestJson(stored.lastGood.settings)
      || stored.lastGood.pluginVersion !== intent.pluginVersion || stored.lastGood.settingsDigest !== intent.baseSettingsDigest) {
      throw new Error("stale settings intent");
    }
    const migrated = runMigrations(stored.lastGood.settings, stored.lastGood.migrationVersion,
      runtime.manifest.migration?.current ?? 0, runtime.registration.migrations ?? []);
    const base = validateSettings(runtime.schema, migrated);
    if (digestJson(base) !== intent.baseSettingsDigest) throw new Error("stale settings intent");
    const patch = parseSettingsPatch(JSON.parse(intent.patchJson) as unknown);
    if (digestJson(patch) !== intent.patchDigest) throw new Error("settings intent patch changed");
    const result = applySettingsPatch(runtime.schema, base, patch);
    if (digestJson(result.settings) !== intent.candidateSettingsDigest) throw new Error("settings intent candidate changed");
    await this.assertSecretReferences(runtime.schema, result.settings);
    const health = await this.checkHealth(runtime, result.settings);
    if (health.status === "unhealthy" || health.status === "isolated") throw new Error("plugin health check failed");
    const nextState: StoredPluginState = {
      storageVersion: 1,
      pluginId: runtime.registration.id,
      lastGood: tree({ manifest: runtime.manifest, settings: result.settings }),
    };
    await this.options.stateStore.save(runtime.registration.id, nextState);
    runtime.state = nextState;
    runtime.recoverySettings = result.settings;
    runtime.health = health;
    this.intents.delete(intent.intentId);
    return this.pluginView(runtime);
  }

  private async assertSecretReferences(schema: CordisSettingsSchema, settings: CordisSettings): Promise<void> {
    for (const field of schema.fields) {
      if (!field.secretReference) continue;
      const reference = settings[field.id];
      if (reference === undefined || reference === null) continue;
      if (typeof reference !== "string" || !this.options.secretReferences || !await this.options.secretReferences.exists(reference)) {
        throw new Error("secret reference unavailable");
      }
    }
  }

  private intentView(intent: PendingIntent): SettingsIntent {
    const { patchJson: _patchJson, ...view } = intent;
    return view;
  }

  private pluginView(runtime: PluginRuntime & {
    manifest: PluginManifest; schema: CordisSettingsSchema; state: StoredPluginState; recoverySettings: CordisSettings;
  }): PluginView {
    return {
      pluginId: runtime.registration.id,
      pluginVersion: runtime.manifest.plugin_version,
      status: runtime.status,
      manifest: structuredClone(runtime.manifest),
      settings: structuredClone(runtime.state.lastGood.settings),
      settingsDigest: runtime.state.lastGood.settingsDigest,
    };
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

  private verifiedRuntime(pluginIdValue: unknown): PluginRuntime & {
    manifest: PluginManifest; schema: CordisSettingsSchema; recoverySettings: CordisSettings;
  } {
    const pluginId = parsePluginId(pluginIdValue);
    const runtime = this.runtimes.get(pluginId);
    if (!runtime) throw new Error("plugin not found");
    if (!runtime.manifest || !runtime.schema || !runtime.recoverySettings) throw new Error("plugin package invalid");
    return runtime as PluginRuntime & { manifest: PluginManifest; schema: CordisSettingsSchema; recoverySettings: CordisSettings };
  }

  private readyRuntime(pluginIdValue: unknown): PluginRuntime & {
    manifest: PluginManifest; schema: CordisSettingsSchema; state: StoredPluginState; recoverySettings: CordisSettings;
  } {
    const runtime = this.verifiedRuntime(pluginIdValue);
    if (runtime.status !== "ready" || !runtime.state) throw new Error("plugin isolated");
    return runtime as PluginRuntime & {
      manifest: PluginManifest; schema: CordisSettingsSchema; state: StoredPluginState; recoverySettings: CordisSettings;
    };
  }
}

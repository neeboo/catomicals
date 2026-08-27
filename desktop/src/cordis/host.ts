import { randomUUID } from "node:crypto";
import { runHealthCheck, type CordisHealthReport, type CordisService } from "./health.js";
import {
  canonicalJson, digestJson, parsePluginId, verifyFixedPluginPackage,
  type FixedPluginRegistration, type PluginManifest, type TrustedPlugin,
} from "./manifest.js";
import { runMigrations } from "./migrations.js";
import {
  assertCordisPermission,
  assertCordisDesktopAccess,
  calculatePermissionDelta,
  parsePermissionScopes,
  type CordisAccessContext,
  type CordisDesktopAccessContext,
  type CordisPermissionDelta,
} from "./permissions.js";
import {
  applySettingsPatch, defaultSettings, parseSettingsPatch, parseSettingsSchema, validateSettings,
  type CordisSettingValue, type CordisSettings, type CordisSettingsField, type CordisSettingsSchema, type RestartImpact,
} from "./settings.js";
import {
  MAX_PENDING_SETTINGS_REVIEWS,
  type CordisStateStore,
  type PluginTree,
  type StoredPluginState,
  type StoredSettingsReview,
} from "./store.js";

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

export type SecretSettingState = "unset" | "set";

export interface PluginSettingsView extends PluginListEntry {
  readonly pluginVersion: string;
  readonly settingsSchemaVersion: number;
  readonly settingsDigest: string;
  readonly settings: CordisSettings;
  readonly secretStates: Readonly<Record<string, SecretSettingState>>;
  readonly schema: CordisSettingsSchema;
}

export interface SettingsValidationResult {
  readonly valid: boolean;
  readonly settingsDigest?: string;
  readonly restartImpact?: RestartImpact;
  readonly error?: string;
}

export interface PlainSettingsChange {
  readonly id: string;
  readonly label: string;
  readonly type: CordisSettingsField["type"];
  readonly restart: RestartImpact;
  readonly before: CordisSettingValue;
  readonly after: CordisSettingValue;
}

export interface SecretSettingsChange {
  readonly id: string;
  readonly label: string;
  readonly type: "string";
  readonly restart: RestartImpact;
  readonly secretState: "unset" | "set" | "changed";
}

export type SettingsReviewChange = PlainSettingsChange | SecretSettingsChange;

export interface SettingsReview {
  readonly intentId: string;
  readonly reviewId: string;
  readonly pluginId: string;
  readonly pluginVersion: string;
  readonly baseSettingsDigest: string;
  readonly candidateSettingsDigest: string;
  readonly patchDigest: string;
  readonly restartImpact: RestartImpact;
  readonly permissionDelta: CordisPermissionDelta;
  readonly changes: readonly SettingsReviewChange[];
  readonly state: "current" | "stale";
  readonly createdAt: string;
  readonly expiresAt: string;
}

interface PendingSettingsReview extends Omit<SettingsReview, "state"> { readonly patchJson: string }

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

const SETTINGS_REVIEW_LIFETIME_MS = 30 * 60 * 1000;
const settingsReviewIdPattern = /^[0-9A-Za-z._:-]{1,128}$/;
const impactRank: Readonly<Record<RestartImpact, number>> = { none: 0, plugin: 1, desktop: 2 };

function parseSettingsReviewId(value: unknown): string {
  if (typeof value !== "string" || !settingsReviewIdPattern.test(value)) throw new Error("invalid settings review");
  return value;
}

function validIsoTimestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  try {
    return new Date(value).toISOString() === value;
  } catch {
    return false;
  }
}

function reviewPrimitive(value: unknown): value is CordisSettingValue {
  return value === null || typeof value === "string" || typeof value === "boolean"
    || (typeof value === "number" && Number.isSafeInteger(value));
}

function reviewChanges(
  schema: CordisSettingsSchema,
  before: CordisSettings,
  after: CordisSettings,
  patch: ReturnType<typeof parseSettingsPatch>,
): { changes: SettingsReviewChange[]; restartImpact: RestartImpact } {
  const fields = new Map(schema.fields.map((field) => [field.id, field]));
  const changes: SettingsReviewChange[] = [];
  let restartImpact: RestartImpact = "none";
  for (const patchChange of patch.changes) {
    const field = fields.get(patchChange.id);
    if (!field) throw new Error("unknown setting");
    const previous = before[field.id] ?? null;
    const candidate = after[field.id] ?? null;
    if (Object.is(previous, candidate)) continue;
    if (field.secretReference) {
      changes.push({
        id: field.id,
        label: field.label,
        type: "string",
        restart: field.restart,
        secretState: candidate === null ? "unset" : previous === null ? "set" : "changed",
      });
    } else {
      changes.push({
        id: field.id,
        label: field.label,
        type: field.type,
        restart: field.restart,
        before: previous,
        after: candidate,
      });
    }
    if (impactRank[field.restart] > impactRank[restartImpact]) restartImpact = field.restart;
  }
  if (changes.length === 0) throw new Error("settings patch has no effect");
  return { changes, restartImpact };
}

function pendingPayload(value: StoredSettingsReview): PendingSettingsReview {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value.payloadJson) as unknown;
  } catch {
    throw new Error("invalid pending settings review");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("invalid pending settings review");
  const input = parsed as Record<string, unknown>;
  const expected = [
    "baseSettingsDigest", "candidateSettingsDigest", "changes", "createdAt", "expiresAt", "intentId",
    "patchDigest", "patchJson", "permissionDelta", "pluginId", "pluginVersion", "restartImpact", "reviewId",
  ].sort();
  if (canonicalJson(parsed) !== value.payloadJson
    || Object.keys(input).sort().some((key, index) => key !== expected[index]) || Object.keys(input).length !== expected.length
    || input.reviewId !== value.reviewId || input.intentId !== value.intentId || input.expiresAt !== value.expiresAt
    || typeof input.pluginId !== "string" || typeof input.pluginVersion !== "string"
    || typeof input.baseSettingsDigest !== "string" || !/^sha256:[0-9a-f]{64}$/.test(input.baseSettingsDigest)
    || typeof input.candidateSettingsDigest !== "string" || !/^sha256:[0-9a-f]{64}$/.test(input.candidateSettingsDigest)
    || typeof input.patchDigest !== "string" || !/^sha256:[0-9a-f]{64}$/.test(input.patchDigest)
    || (input.restartImpact !== "none" && input.restartImpact !== "plugin" && input.restartImpact !== "desktop")
    || !validIsoTimestamp(input.createdAt) || !validIsoTimestamp(input.expiresAt)
    || typeof input.patchJson !== "string" || canonicalJson(JSON.parse(input.patchJson) as unknown) !== input.patchJson
    || !Array.isArray(input.changes) || input.changes.length === 0) {
    throw new Error("invalid pending settings review");
  }
  const permissionDelta = input.permissionDelta;
  if (!permissionDelta || typeof permissionDelta !== "object" || Array.isArray(permissionDelta)) {
    throw new Error("invalid pending settings review");
  }
  const permissionRecord = permissionDelta as Record<string, unknown>;
  if (Object.keys(permissionRecord).sort().join(",") !== "added,removed") throw new Error("invalid pending settings review");
  const changes = input.changes as SettingsReviewChange[];
  for (const change of changes) {
    if (!change || typeof change !== "object" || Array.isArray(change)
      || typeof change.id !== "string" || typeof change.label !== "string"
      || (change.type !== "string" && change.type !== "boolean" && change.type !== "integer")
      || (change.restart !== "none" && change.restart !== "plugin" && change.restart !== "desktop")) {
      throw new Error("invalid pending settings review");
    }
    if ("secretState" in change) {
      if (change.secretState !== "unset" && change.secretState !== "set" && change.secretState !== "changed"
        || Object.keys(change).sort().join(",") !== "id,label,restart,secretState,type") {
        throw new Error("invalid pending settings review");
      }
    } else if (Object.keys(change).sort().join(",") !== "after,before,id,label,restart,type"
      || !reviewPrimitive(change.before) || !reviewPrimitive(change.after)) {
      throw new Error("invalid pending settings review");
    }
  }
  if (new Set(changes.map((change) => change.id)).size !== changes.length) throw new Error("invalid pending settings review");
  return {
    intentId: parseSettingsReviewId(input.intentId),
    reviewId: parseSettingsReviewId(input.reviewId),
    pluginId: parsePluginId(input.pluginId),
    pluginVersion: input.pluginVersion,
    baseSettingsDigest: input.baseSettingsDigest,
    candidateSettingsDigest: input.candidateSettingsDigest,
    patchDigest: input.patchDigest,
    restartImpact: input.restartImpact,
    permissionDelta: {
      added: parsePermissionScopes(permissionRecord.added),
      removed: parsePermissionScopes(permissionRecord.removed),
    },
    changes,
    createdAt: input.createdAt,
    expiresAt: input.expiresAt,
    patchJson: input.patchJson,
  };
}

function storedReview(payload: PendingSettingsReview): StoredSettingsReview {
  const payloadJson = canonicalJson(payload);
  return {
    reviewId: payload.reviewId,
    intentId: payload.intentId,
    expiresAt: payload.expiresAt,
    payloadJson,
    payloadDigest: digestJson(payload),
  };
}

export class CordisHost {
  private readonly registrations: readonly FixedPluginRegistration[];
  private readonly trust = new Map<string, TrustedPlugin>();
  private readonly services = new Map<string, CordisService>();
  private readonly runtimes = new Map<string, PluginRuntime>();
  private readonly promotionTails = new Map<string, Promise<void>>();
  private reviewCreationTail: Promise<void> = Promise.resolve();
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
    }
    await Promise.all(this.registrations.map((registration) => this.initializePlugin(registration)));
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
      pendingSettingsReviews: runtime.state?.pendingSettingsReviews ?? [],
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

  readManifest(pluginIdValue: unknown, access: CordisAccessContext): PluginManifest {
    assertCordisPermission(access, "plugin.manifest.read");
    return structuredClone(this.verifiedRuntime(pluginIdValue).manifest);
  }

  readSettingsSchema(pluginIdValue: unknown, access: CordisAccessContext): CordisSettingsSchema {
    assertCordisPermission(access, "plugin.settings_schema.read");
    return structuredClone(this.verifiedRuntime(pluginIdValue).schema);
  }

  async readPluginSettings(pluginIdValue: unknown, access: CordisAccessContext): Promise<PluginSettingsView> {
    assertCordisPermission(access, "plugin.settings.read");
    const runtime = this.verifiedRuntime(pluginIdValue);
    const stored = await this.options.stateStore.load(runtime.registration.id);
    if (!stored || stored.lastGood.settingsDigest !== digestJson(stored.lastGood.settings)) {
      throw new Error("plugin settings unavailable");
    }
    return this.settingsView(runtime, stored);
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

  async createSettingsIntent(
    pluginIdValue: unknown,
    patchValue: unknown,
    access: CordisAccessContext,
  ): Promise<SettingsReview> {
    assertCordisPermission(access, "plugin.settings_intent.create");
    const runtime = this.verifiedRuntime(pluginIdValue);
    const patch = parseSettingsPatch(patchValue);
    return this.withPluginPromotionLock(runtime.registration.id, async () => {
      const stored = await this.loadStateWithLiveReviews(runtime);
      if (stored.pendingSettingsReviews!.length >= MAX_PENDING_SETTINGS_REVIEWS) {
        throw new Error("too many pending settings reviews");
      }
      const migrated = runMigrations(stored.lastGood.settings, stored.lastGood.migrationVersion,
        runtime.manifest.migration?.current ?? 0, runtime.registration.migrations ?? []);
      const base = validateSettings(runtime.schema, migrated);
      const result = applySettingsPatch(runtime.schema, base, patch);
      const summary = reviewChanges(runtime.schema, base, result.settings, patch);
      const createdAt = this.now();
      return this.withReviewCreationLock(async () => {
        const intentId = parseSettingsReviewId(this.createId());
        const reviewId = parseSettingsReviewId(this.createId());
        const existingIdentifiers = await this.persistedReviewIdentifiers();
        if (intentId === reviewId || existingIdentifiers.has(intentId) || existingIdentifiers.has(reviewId)) {
          throw new Error("duplicate settings review identifier");
        }
        const payload: PendingSettingsReview = {
          intentId,
          reviewId,
          pluginId: runtime.registration.id,
          pluginVersion: runtime.manifest.plugin_version,
          baseSettingsDigest: stored.lastGood.settingsDigest,
          candidateSettingsDigest: digestJson(result.settings),
          patchDigest: digestJson(patch),
          restartImpact: summary.restartImpact,
          permissionDelta: calculatePermissionDelta(
            runtime.manifest.permission_scopes,
            runtime.manifest.permission_scopes,
          ),
          changes: summary.changes,
          createdAt: createdAt.toISOString(),
          expiresAt: new Date(createdAt.getTime() + SETTINGS_REVIEW_LIFETIME_MS).toISOString(),
          patchJson: canonicalJson(patch),
        };
        const nextState: StoredPluginState = {
          ...stored,
          pendingSettingsReviews: [...stored.pendingSettingsReviews!, storedReview(payload)],
        };
        await this.options.stateStore.save(runtime.registration.id, nextState);
        runtime.state = nextState;
        return this.reviewView(payload, "current");
      });
    });
  }

  async readSettingsReview(reviewIdValue: unknown, access: CordisAccessContext): Promise<SettingsReview> {
    assertCordisPermission(access, "plugin.settings.read");
    const found = await this.findPendingReview(parseSettingsReviewId(reviewIdValue));
    if (!found) throw new Error("settings review not found");
    const payload = pendingPayload(found.review);
    const runtime = this.verifiedRuntime(found.pluginId);
    if (payload.pluginId !== found.pluginId) throw new Error("invalid pending settings review");
    const stale = found.state.lastGood.settingsDigest !== payload.baseSettingsDigest
      || runtime.manifest.plugin_version !== payload.pluginVersion;
    return this.reviewView(payload, stale ? "stale" : "current");
  }

  async confirmSettingsIntent(
    reviewIdValue: unknown,
    access: CordisDesktopAccessContext,
  ): Promise<PluginSettingsView> {
    assertCordisDesktopAccess(access);
    const reviewId = parseSettingsReviewId(reviewIdValue);
    const found = await this.findPendingReview(reviewId);
    if (!found) throw new Error("settings review not found");
    return this.withPluginPromotionLock(found.pluginId, () => this.confirmPendingReview(found.pluginId, reviewId));
  }

  private async confirmPendingReview(pluginId: string, reviewId: string): Promise<PluginSettingsView> {
    const runtime = this.verifiedRuntime(pluginId);
    if (runtime.status !== "ready" && runtime.errorCode !== "health_failed") throw new Error("plugin isolated");
    const stored = await this.loadStateWithLiveReviews(runtime);
    const envelope = stored.pendingSettingsReviews!.find((review) => review.reviewId === reviewId);
    if (!envelope) throw new Error("settings review not found");
    const intent = pendingPayload(envelope);
    if (intent.pluginId !== runtime.registration.id || runtime.manifest.plugin_version !== intent.pluginVersion
      || stored.lastGood.settingsDigest !== intent.baseSettingsDigest) {
      throw new Error("stale settings intent");
    }
    const migrated = runMigrations(stored.lastGood.settings, stored.lastGood.migrationVersion,
      runtime.manifest.migration?.current ?? 0, runtime.registration.migrations ?? []);
    const base = validateSettings(runtime.schema, migrated);
    const patch = parseSettingsPatch(JSON.parse(intent.patchJson) as unknown);
    if (digestJson(patch) !== intent.patchDigest) throw new Error("settings intent patch changed");
    const result = applySettingsPatch(runtime.schema, base, patch);
    if (digestJson(result.settings) !== intent.candidateSettingsDigest) throw new Error("settings intent candidate changed");
    const summary = reviewChanges(runtime.schema, base, result.settings, patch);
    const permissionDelta = calculatePermissionDelta(
      runtime.manifest.permission_scopes,
      runtime.manifest.permission_scopes,
    );
    if (summary.restartImpact !== intent.restartImpact
      || canonicalJson(summary.changes) !== canonicalJson(intent.changes)
      || canonicalJson(permissionDelta) !== canonicalJson(intent.permissionDelta)) {
      throw new Error("settings review changed");
    }
    await this.assertSecretReferences(runtime.schema, result.settings);
    const health = await this.checkHealth(runtime, result.settings);
    if (health.status === "unhealthy" || health.status === "isolated") throw new Error("plugin health check failed");
    const nextState: StoredPluginState = {
      storageVersion: 1,
      pluginId: runtime.registration.id,
      lastGood: tree({ manifest: runtime.manifest, settings: result.settings }),
      pendingSettingsReviews: stored.pendingSettingsReviews!.filter((review) => review.reviewId !== reviewId),
    };
    await this.options.stateStore.save(runtime.registration.id, nextState);
    runtime.state = nextState;
    runtime.recoverySettings = result.settings;
    runtime.status = "ready";
    runtime.errorCode = undefined;
    runtime.health = health;
    return this.settingsView(runtime, nextState);
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

  private reviewView(intent: PendingSettingsReview, state: SettingsReview["state"]): SettingsReview {
    const { patchJson: _patchJson, ...view } = intent;
    return structuredClone({ ...view, state });
  }

  private settingsView(
    runtime: PluginRuntime & { manifest: PluginManifest; schema: CordisSettingsSchema },
    stored: StoredPluginState,
  ): PluginSettingsView {
    const secretFields = new Set(runtime.schema.fields.filter((field) => field.secretReference).map((field) => field.id));
    const knownFields = new Set(runtime.schema.fields.map((field) => field.id));
    const settings = Object.fromEntries(Object.entries(stored.lastGood.settings)
      .filter(([id]) => knownFields.has(id) && !secretFields.has(id)));
    const secretStates = Object.fromEntries([...secretFields].map((id) => [
      id,
      stored.lastGood.settings[id] === undefined || stored.lastGood.settings[id] === null ? "unset" : "set",
    ])) as Record<string, SecretSettingState>;
    return {
      pluginId: runtime.registration.id,
      pluginVersion: stored.lastGood.pluginVersion,
      status: runtime.status,
      ...(runtime.errorCode ? { errorCode: runtime.errorCode } : {}),
      settingsSchemaVersion: stored.lastGood.settingsSchemaVersion,
      settingsDigest: stored.lastGood.settingsDigest,
      settings,
      secretStates,
      schema: structuredClone(runtime.schema),
    };
  }

  private async persistedReviewIdentifiers(): Promise<Set<string>> {
    const identifiers = new Set<string>();
    for (const runtime of this.runtimes.values()) {
      const state = await this.options.stateStore.load(runtime.registration.id);
      for (const review of state?.pendingSettingsReviews ?? []) {
        identifiers.add(review.reviewId);
        identifiers.add(review.intentId);
      }
    }
    return identifiers;
  }

  private async loadStateWithLiveReviews(
    runtime: PluginRuntime & { manifest: PluginManifest; schema: CordisSettingsSchema; recoverySettings: CordisSettings },
  ): Promise<StoredPluginState & { pendingSettingsReviews: readonly StoredSettingsReview[] }> {
    const stored = await this.loadOptionalStateWithLiveReviews(runtime);
    if (!stored) throw new Error("plugin settings unavailable");
    return stored;
  }

  private async loadOptionalStateWithLiveReviews(
    runtime: PluginRuntime & { manifest: PluginManifest; schema: CordisSettingsSchema; recoverySettings: CordisSettings },
  ): Promise<(StoredPluginState & { pendingSettingsReviews: readonly StoredSettingsReview[] }) | undefined> {
    const stored = await this.options.stateStore.load(runtime.registration.id);
    if (!stored) return undefined;
    if (stored.lastGood.settingsDigest !== digestJson(stored.lastGood.settings)) throw new Error("invalid plugin settings state");
    const pending = stored.pendingSettingsReviews ?? [];
    const cutoff = this.now().getTime();
    const live = pending.filter((review) => new Date(review.expiresAt).getTime() > cutoff);
    const nextState: StoredPluginState & { pendingSettingsReviews: readonly StoredSettingsReview[] } = {
      ...stored,
      pendingSettingsReviews: live,
    };
    if (live.length !== pending.length || stored.pendingSettingsReviews === undefined) {
      await this.options.stateStore.save(runtime.registration.id, nextState);
    }
    runtime.state = nextState;
    return nextState;
  }

  private async findPendingReview(
    value: string,
  ): Promise<{ pluginId: string; review: StoredSettingsReview; state: StoredPluginState } | undefined> {
    for (const runtime of this.runtimes.values()) {
      if (!runtime.manifest || !runtime.schema || !runtime.recoverySettings) continue;
      const found = await this.withPluginPromotionLock(runtime.registration.id, async () => {
        const state = await this.loadOptionalStateWithLiveReviews(this.verifiedRuntime(runtime.registration.id));
        if (!state) return undefined;
        const review = state.pendingSettingsReviews.find((candidate) => candidate.reviewId === value);
        return review ? { pluginId: runtime.registration.id, review, state } : undefined;
      });
      if (found) return found;
    }
    return undefined;
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

  private async withReviewCreationLock<T>(work: () => Promise<T>): Promise<T> {
    const previous = this.reviewCreationTail;
    let release = (): void => undefined;
    const current = new Promise<void>((resolve) => { release = resolve; });
    this.reviewCreationTail = previous.then(() => current);
    await previous;
    try {
      return await work();
    } finally {
      release();
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

}

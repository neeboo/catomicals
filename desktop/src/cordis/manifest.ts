import { createHash, createPublicKey, verify } from "node:crypto";
import type { FixedHealthCheck } from "./health.js";
import type { CordisMigration } from "./migrations.js";
import { parsePermissionScopes, type CordisPermissionScope } from "./permissions.js";
import type { CordisSettingsSchema } from "./settings.js";

export type PluginCategory = "system" | "wallet" | "chain" | "data" | "agent" | "interface" | "storage";
export type PluginCapability = "wallet" | "chain.rpc" | "chain.address" | "indexer" | "agent.mcp" | "agent.executor" | "ui.generative" | "browser" | "backup";

export interface PluginManifest {
  schema_version: 1;
  manifest_id: string;
  plugin_id: string;
  plugin_version: string;
  runtime_api: 1;
  publisher: { publisher_id: string; key_id: string };
  package_digest: string;
  package_attestation: { algorithm: "ed25519"; attestation_digest: string };
  entries: { host: string; client: string; bundle_patch?: string };
  inject: { required: string[]; optional: string[] };
  permission_scopes: CordisPermissionScope[];
  settings: { namespace: string; mode: "intent_only"; schema_version: number; schema_digest: string };
  ui_surfaces?: { surface_id: string; placement: "settings" | "workbench" | "details"; client_entry: string }[];
  health_service?: string;
  migration?: { namespace: string; current: number };
  catalog?: {
    category: PluginCategory;
    capabilities: PluginCapability[];
  };
}

export interface FixedPluginRegistration {
  readonly id: string;
  readonly manifest: unknown;
  readonly descriptor: string;
  readonly signature: string;
  readonly settingsSchema: CordisSettingsSchema;
  healthCheck?: FixedHealthCheck;
  migrations?: readonly CordisMigration[];
}

export interface TrustedPlugin {
  readonly pluginId: string;
  readonly pluginVersion: string;
  readonly publisherId: string;
  readonly keyId: string;
  readonly packageDigest: string;
  readonly publicKey: string;
}

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("expected object");
  return value as Record<string, unknown>;
}

function exactFields(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): void {
  const allowed = new Set([...required, ...optional]);
  if (required.some((field) => !(field in value)) || Object.keys(value).some((field) => !allowed.has(field))) {
    throw new Error("unexpected fields");
  }
}

function text(value: unknown, name: string, pattern: RegExp, maximum = 128): string {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum || !pattern.test(value)) throw new Error(`invalid ${name}`);
  return value;
}

export function parsePluginId(value: unknown): string {
  return text(value, "plugin id", /^@catomicals\/plugin-[a-z0-9]+(?:-[a-z0-9]+)*$/);
}

function digest(value: unknown, name: string): string {
  return text(value, name, /^(?:sha256|blake3):[0-9a-f]{64}$/, 71);
}

function namespace(value: unknown): string {
  return text(value, "namespace", /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/);
}

function serviceName(value: unknown): string {
  return text(value, "service name", /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/);
}

function safeEntry(value: unknown): string {
  return text(value, "entry", /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]+$/, 240);
}

function integer(value: unknown, name: string, minimum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) throw new Error(`invalid ${name}`);
  return value as number;
}

function uniqueStrings(value: unknown, parser: (item: unknown) => string, name: string): string[] {
  if (!Array.isArray(value)) throw new Error(`invalid ${name}`);
  const result = value.map(parser);
  if (new Set(result).size !== result.length) throw new Error(`duplicate ${name}`);
  return result;
}

export function parsePluginManifest(value: unknown): PluginManifest {
  const input = record(value);
  exactFields(input, [
    "schema_version", "manifest_id", "plugin_id", "plugin_version", "runtime_api", "publisher",
    "package_digest", "package_attestation", "entries", "inject", "permission_scopes", "settings",
  ], ["ui_surfaces", "health_service", "migration", "catalog"]);
  if (input.schema_version !== 1 || input.runtime_api !== 1) throw new Error("unsupported plugin runtime");
  const publisher = record(input.publisher);
  exactFields(publisher, ["publisher_id", "key_id"]);
  const attestation = record(input.package_attestation);
  exactFields(attestation, ["algorithm", "attestation_digest"]);
  if (attestation.algorithm !== "ed25519") throw new Error("invalid attestation algorithm");
  const entries = record(input.entries);
  exactFields(entries, ["host", "client"], ["bundle_patch"]);
  const inject = record(input.inject);
  exactFields(inject, ["required", "optional"]);
  const requiredServices = uniqueStrings(inject.required, serviceName, "required service");
  const optionalServices = uniqueStrings(inject.optional, serviceName, "optional service");
  if (requiredServices.some((item) => optionalServices.includes(item))) throw new Error("service cannot be required and optional");
  const settings = record(input.settings);
  exactFields(settings, ["namespace", "mode", "schema_version", "schema_digest"]);
  if (settings.mode !== "intent_only") throw new Error("plugin settings must be intent only");
  const uiSurfaces: PluginManifest["ui_surfaces"] = input.ui_surfaces === undefined ? undefined : (() => {
    if (!Array.isArray(input.ui_surfaces)) throw new Error("invalid UI surfaces");
    const ids = new Set<string>();
    return input.ui_surfaces.map((surface) => {
      const parsed = record(surface);
      exactFields(parsed, ["surface_id", "placement", "client_entry"]);
      const surfaceId = text(parsed.surface_id, "surface id", /^[a-z0-9]+(?:-[a-z0-9]+)*$/);
      if (ids.has(surfaceId)) throw new Error("duplicate UI surface");
      ids.add(surfaceId);
      const placement = parsed.placement;
      if (placement !== "settings" && placement !== "workbench" && placement !== "details") {
        throw new Error("invalid UI placement");
      }
      return { surface_id: surfaceId, placement, client_entry: safeEntry(parsed.client_entry) };
    });
  })();
  const migration = input.migration === undefined ? undefined : (() => {
    const parsed = record(input.migration);
    exactFields(parsed, ["namespace", "current"]);
    return { namespace: namespace(parsed.namespace), current: integer(parsed.current, "migration version", 0) };
  })();
  const catalog = input.catalog === undefined ? undefined : (() => {
    const parsed = record(input.catalog);
    exactFields(parsed, ["category", "capabilities"]);
    const categories = new Set(["system", "wallet", "chain", "data", "agent", "interface", "storage"]);
    if (typeof parsed.category !== "string" || !categories.has(parsed.category)) throw new Error("invalid plugin category");
    const capabilitySet = new Set([
      "wallet", "chain.rpc", "chain.address", "indexer", "agent.mcp", "agent.executor", "ui.generative", "browser", "backup",
    ]);
    const capabilities = uniqueStrings(parsed.capabilities, (capability) => {
      if (typeof capability !== "string" || !capabilitySet.has(capability)) throw new Error("invalid plugin capability");
      return capability;
    }, "plugin capability") as PluginCapability[];
    return {
      category: parsed.category as PluginCategory,
      capabilities,
    };
  })();
  const pluginNamespace = namespace(settings.namespace);
  if (migration && migration.namespace !== pluginNamespace) throw new Error("migration namespace mismatch");
  return {
    schema_version: 1,
    manifest_id: text(input.manifest_id, "manifest id", /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i, 36),
    plugin_id: parsePluginId(input.plugin_id),
    plugin_version: text(input.plugin_version, "plugin version", /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/),
    runtime_api: 1,
    publisher: {
      publisher_id: text(publisher.publisher_id, "publisher id", /^[a-z0-9]+(?:-[a-z0-9]+)*$/),
      key_id: text(publisher.key_id, "publisher key", /^[A-Za-z0-9._-]+$/),
    },
    package_digest: digest(input.package_digest, "package digest"),
    package_attestation: { algorithm: "ed25519", attestation_digest: digest(attestation.attestation_digest, "attestation digest") },
    entries: {
      host: safeEntry(entries.host),
      client: safeEntry(entries.client),
      ...(entries.bundle_patch === undefined ? {} : { bundle_patch: safeEntry(entries.bundle_patch) }),
    },
    inject: { required: requiredServices, optional: optionalServices },
    permission_scopes: parsePermissionScopes(input.permission_scopes),
    settings: {
      namespace: pluginNamespace,
      mode: "intent_only",
      schema_version: integer(settings.schema_version, "settings schema version", 1),
      schema_digest: digest(settings.schema_digest, "settings schema digest"),
    },
    ...(uiSurfaces ? { ui_surfaces: uiSurfaces } : {}),
    ...(input.health_service === undefined ? {} : { health_service: serviceName(input.health_service) }),
    ...(migration ? { migration } : {}),
    ...(catalog ? { catalog } : {}),
  };
}

function canonicalValue(value: unknown): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => [key, canonicalValue(item)]));
  }
  throw new Error("value is not canonical JSON");
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalValue(value));
}

export function digestBytes(value: Uint8Array): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

export function digestJson(value: unknown): string {
  return digestBytes(Buffer.from(canonicalJson(value)));
}

export function attestationStatement(manifestValue: unknown): string {
  const manifest = parsePluginManifest(manifestValue);
  return canonicalJson({
    ...manifest,
    package_attestation: { algorithm: manifest.package_attestation.algorithm },
  });
}

export function verifyFixedPluginPackage(
  registration: FixedPluginRegistration,
  trust: TrustedPlugin,
): PluginManifest {
  const manifest = parsePluginManifest(registration.manifest);
  if (registration.id !== manifest.plugin_id || trust.pluginId !== manifest.plugin_id
    || trust.pluginVersion !== manifest.plugin_version
    || trust.publisherId !== manifest.publisher.publisher_id
    || trust.keyId !== manifest.publisher.key_id
    || trust.packageDigest !== manifest.package_digest) {
    throw new Error("plugin is outside the fixed trust entry");
  }
  if (digestBytes(Buffer.from(registration.descriptor)) !== manifest.package_digest) throw new Error("package digest mismatch");
  if (digestJson(registration.settingsSchema) !== manifest.settings.schema_digest) throw new Error("settings schema digest mismatch");
  let signature: Buffer;
  try {
    signature = Buffer.from(registration.signature, "base64");
  } catch {
    throw new Error("invalid package attestation");
  }
  if (signature.length !== 64 || digestBytes(signature) !== manifest.package_attestation.attestation_digest) {
    throw new Error("invalid package attestation");
  }
  let valid = false;
  try {
    valid = verify(null, Buffer.from(attestationStatement(manifest)), createPublicKey(trust.publicKey), signature);
  } catch {
    valid = false;
  }
  if (!valid) throw new Error("invalid package attestation");
  return manifest;
}

import { generateKeyPairSync, sign } from "node:crypto";
import {
  attestationStatement,
  canonicalJson,
  digestBytes,
  digestJson,
  type FixedPluginRegistration,
  type PluginManifest,
  type TrustedPlugin,
} from "./manifest.js";
import type { CordisSettingsSchema } from "./settings.js";

export const testSettingsSchema: CordisSettingsSchema = {
  version: 1,
  fields: [
    {
      id: "endpoint",
      label: "Endpoint",
      type: "string",
      required: true,
      default: "http://127.0.0.1:18787",
      restart: "plugin",
      maxLength: 512,
    },
    {
      id: "enabled",
      label: "Enabled",
      type: "boolean",
      required: true,
      default: true,
      restart: "none",
    },
    {
      id: "credential",
      label: "Credential",
      type: "string",
      required: false,
      secretReference: true,
      restart: "plugin",
    },
  ],
};

export function createSignedFixture(options: {
  id?: string;
  version?: string;
  requiredServices?: readonly string[];
  optionalServices?: readonly string[];
  migrationCurrent?: number;
  settingsSchema?: CordisSettingsSchema;
} = {}): { registration: FixedPluginRegistration; trust: TrustedPlugin } {
  const pluginId = options.id ?? "@catomicals/plugin-walletd";
  const pluginVersion = options.version ?? "1.0.0";
  const settingsSchema = options.settingsSchema ?? testSettingsSchema;
  const descriptor = canonicalJson({ pluginId, pluginVersion, implementation: "test-fixture" });
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const manifest: PluginManifest = {
    schema_version: 1,
    manifest_id: "11111111-1111-4111-8111-111111111111",
    plugin_id: pluginId,
    plugin_version: pluginVersion,
    runtime_api: 1,
    publisher: { publisher_id: "catomicals-test", key_id: "test-key" },
    package_digest: digestBytes(Buffer.from(descriptor)),
    package_attestation: { algorithm: "ed25519", attestation_digest: "sha256:" + "0".repeat(64) },
    entries: { host: "dist/host.js", client: "dist/client.js" },
    inject: {
      required: [...(options.requiredServices ?? [])],
      optional: [...(options.optionalServices ?? [])],
    },
    permission_scopes: ["plugin.catalog.read", "plugin.health.read", "plugin.settings.validate"],
    settings: {
      namespace: pluginId.replace("@catomicals/plugin-", "").replaceAll("-", "."),
      mode: "intent_only",
      schema_version: settingsSchema.version,
      schema_digest: digestJson(settingsSchema),
    },
    migration: {
      namespace: pluginId.replace("@catomicals/plugin-", "").replaceAll("-", "."),
      current: options.migrationCurrent ?? 0,
    },
  };
  const signature = sign(null, Buffer.from(attestationStatement(manifest)), privateKey).toString("base64");
  manifest.package_attestation.attestation_digest = digestBytes(Buffer.from(signature, "base64"));
  return {
    registration: {
      id: pluginId,
      manifest,
      descriptor,
      signature,
      settingsSchema,
    },
    trust: {
      pluginId,
      pluginVersion,
      publisherId: manifest.publisher.publisher_id,
      keyId: manifest.publisher.key_id,
      packageDigest: manifest.package_digest,
      publicKey: publicKey.export({ type: "spki", format: "pem" }).toString(),
    },
  };
}

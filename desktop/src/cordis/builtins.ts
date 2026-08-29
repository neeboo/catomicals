import { CordisHost } from "./host.js";
import {
  canonicalJson,
  digestBytes,
  digestJson,
  type FixedPluginRegistration,
  type PluginManifest,
  type TrustedPlugin,
} from "./manifest.js";
import type { CordisPermissionScope } from "./permissions.js";
import type { CordisSettingsField, CordisSettingsSchema } from "./settings.js";
import type { CordisStateStore } from "./store.js";
import type { CordisService } from "./health.js";
import type { CordisMigration } from "./migrations.js";

export const FIXED_PLUGIN_IDS = [
  "@catomicals/plugin-walletd",
  "@catomicals/plugin-bitcoin-node",
  "@catomicals/plugin-indexer",
  "@catomicals/plugin-mcp",
  "@catomicals/plugin-executor-codex",
  "@catomicals/plugin-executor-deepseek",
  "@catomicals/plugin-executor-claude-code",
  "@catomicals/plugin-generative-ui",
  "@catomicals/plugin-backup",
  "@catomicals/plugin-browser",
  "@catomicals/plugin-chain-fractal-bitcoin",
  "@catomicals/plugin-chain-bitcoin-cash",
  "@catomicals/plugin-chain-bsv",
  "@catomicals/plugin-chain-kaspa",
  "@catomicals/plugin-chain-chia",
  "@catomicals/plugin-chain-ergo",
] as const;

type FixedPluginId = (typeof FIXED_PLUGIN_IDS)[number];

interface BuiltinSpec {
  readonly id: FixedPluginId;
  readonly manifestId: string;
  readonly namespace: string;
  readonly fields: readonly CordisSettingsField[];
  readonly permissions: readonly CordisPermissionScope[];
  readonly optionalServices: readonly string[];
  readonly healthService?: string;
  readonly runtimeHealthService?: string;
  readonly publisherKey?: string;
  readonly catalog?: PluginManifest["catalog"];
  readonly pluginVersion?: string;
  readonly schemaVersion?: number;
  readonly migrationCurrent?: number;
  readonly migrations?: readonly CordisMigration[];
}

const stringField = (
  id: string,
  label: string,
  defaultValue: string,
  restart: "none" | "plugin" | "desktop" = "plugin",
): CordisSettingsField => ({ id, label, type: "string", required: true, default: defaultValue, restart, maxLength: 1024 });

const enabledField: CordisSettingsField = {
  id: "enabled",
  label: "Enabled",
  type: "boolean",
  required: true,
  default: true,
  restart: "plugin",
};

const chainPublisherKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAe9vfu+XONv56O9HO1aGcEs9LlkFMLpWqucc4guNv26Q=
-----END PUBLIC KEY-----
`;

const chainFields = (options: {
  enabled: boolean;
  networkId: string;
  transport: "wallet-gateway" | "json-rpc" | "rest" | "grpc";
  endpoint?: string;
}): readonly CordisSettingsField[] => [
  { ...enabledField, default: options.enabled },
  stringField("networkId", "Network", options.networkId),
  {
    id: "transport",
    label: "Transport",
    type: "string",
    required: true,
    default: options.transport,
    choices: ["wallet-gateway", "json-rpc", "rest", "grpc"],
    restart: "plugin",
  },
  {
    id: "endpoint",
    label: "RPC endpoint",
    type: "string",
    required: false,
    ...(options.endpoint ? { default: options.endpoint } : {}),
    restart: "plugin",
    maxLength: 1024,
    format: "rpc-endpoint",
  },
  {
    id: "credentialRef",
    label: "RPC credential",
    type: "string",
    required: false,
    secretReference: true,
    restart: "plugin",
  },
  {
    id: "access",
    label: "RPC access",
    type: "string",
    required: true,
    default: "read",
    choices: ["read", "broadcast"],
    restart: "plugin",
  },
];

const chainPermissions: readonly CordisPermissionScope[] = [
  "chain.rpc.read",
  "chain.rpc.broadcast",
  "chain.address.read",
  "plugin.health.read",
  "plugin.settings.validate",
  "plugin.settings_intent.create",
];

const chainCatalog: NonNullable<PluginManifest["catalog"]> = {
  category: "chain",
  capabilities: ["chain.rpc", "chain.address"],
};

const executorFields = (command: string): readonly CordisSettingsField[] => [
  stringField("command", "Command", command),
  stringField("defaultModel", "Default model", "", "none"),
  {
    id: "reasoningEffort",
    label: "Reasoning effort",
    type: "string",
    required: true,
    default: "high",
    choices: ["low", "medium", "high", "xhigh"],
    restart: "none",
  },
  stringField("workingDirectory", "Working directory", "", "none"),
];

const specs: readonly BuiltinSpec[] = [
  {
    id: "@catomicals/plugin-walletd",
    manifestId: "00000000-0000-4000-8000-000000000001",
    namespace: "walletd",
    fields: [
      stringField("endpoint", "Wallet node endpoint", "http://127.0.0.1:18787"),
      { id: "processMode", label: "Process mode", type: "string", required: true, default: "managed", choices: ["managed", "external"], restart: "plugin" },
    ],
    permissions: ["wallet.status.read", "plugin.health.read", "plugin.settings.validate", "plugin.settings_intent.create"],
    optionalServices: [],
    healthService: "walletd.health",
  },
  {
    id: "@catomicals/plugin-bitcoin-node",
    manifestId: "00000000-0000-4000-8000-000000000002",
    namespace: "bitcoin.node",
    fields: chainFields({ enabled: true, networkId: "bitcoin-inquisition", transport: "wallet-gateway", endpoint: "http://127.0.0.1:18787" }),
    permissions: chainPermissions,
    optionalServices: [],
    healthService: "bitcoin.node.health",
    publisherKey: chainPublisherKey,
    catalog: chainCatalog,
    pluginVersion: "1.1.0",
    schemaVersion: 2,
    migrationCurrent: 1,
    migrations: [{
      from: 0,
      to: 1,
      migrate: (settings) => ({
        enabled: true,
        networkId: settings.profile === "inquisition" ? "bitcoin-inquisition" : "bitcoin-signet",
        transport: "wallet-gateway",
        endpoint: settings.endpoint ?? "http://127.0.0.1:18787",
        access: "read",
      }),
    }],
  },
  {
    id: "@catomicals/plugin-indexer",
    manifestId: "00000000-0000-4000-8000-000000000003",
    namespace: "indexer",
    fields: [enabledField, stringField("databasePath", "Database path", "")],
    permissions: ["indexer.query.read", "plugin.health.read", "plugin.settings.validate", "plugin.settings_intent.create"],
    optionalServices: [],
    healthService: "indexer.health",
    runtimeHealthService: "indexer.health",
  },
  {
    id: "@catomicals/plugin-mcp",
    manifestId: "00000000-0000-4000-8000-000000000004",
    namespace: "mcp",
    fields: [enabledField, { id: "transport", label: "Transport", type: "string", required: true, default: "stdio", choices: ["stdio", "http-oauth"], restart: "plugin" }],
    permissions: ["plugin.catalog.read", "plugin.manifest.read", "plugin.settings_schema.read", "plugin.health.read", "plugin.settings.validate", "plugin.settings_intent.create"],
    optionalServices: [],
    healthService: "mcp.health",
    runtimeHealthService: "mcp.health",
  },
  {
    id: "@catomicals/plugin-executor-codex",
    manifestId: "00000000-0000-4000-8000-000000000005",
    namespace: "executor.codex",
    fields: executorFields("codex"),
    permissions: ["plugin.health.read", "plugin.settings.validate", "plugin.settings_intent.create"],
    optionalServices: ["executor.codex.health"],
    runtimeHealthService: "executor.codex.health",
  },
  {
    id: "@catomicals/plugin-executor-deepseek",
    manifestId: "00000000-0000-4000-8000-000000000006",
    namespace: "executor.deepseek",
    fields: executorFields("dsh"),
    permissions: ["plugin.health.read", "plugin.settings.validate", "plugin.settings_intent.create"],
    optionalServices: ["executor.deepseek.health"],
    runtimeHealthService: "executor.deepseek.health",
  },
  {
    id: "@catomicals/plugin-executor-claude-code",
    manifestId: "00000000-0000-4000-8000-000000000007",
    namespace: "executor.claude.code",
    fields: executorFields("claude"),
    permissions: ["plugin.health.read", "plugin.settings.validate", "plugin.settings_intent.create"],
    optionalServices: ["executor.claude.code.health"],
    runtimeHealthService: "executor.claude.code.health",
  },
  {
    id: "@catomicals/plugin-generative-ui",
    manifestId: "00000000-0000-4000-8000-00000000000a",
    namespace: "generative.ui",
    fields: [
      { ...enabledField, restart: "none" },
      {
        id: "preference",
        label: "组件输出偏好",
        type: "string",
        required: true,
        default: "prefer",
        choices: ["prefer", "automatic", "off"],
        restart: "none",
      },
      {
        id: "maxBlocks",
        label: "每条回复最多组件数",
        type: "integer",
        required: true,
        default: 2,
        minimum: 1,
        maximum: 2,
        restart: "none",
      },
      {
        id: "referenceRepository",
        label: "界面参考仓库",
        type: "string",
        required: true,
        default: "/Users/ghostcorn/dev/deepseek-harness",
        restart: "none",
        maxLength: 1024,
      },
      {
        id: "customInstructions",
        label: "追加生成规范",
        type: "string",
        required: true,
        default: "",
        restart: "none",
        maxLength: 4096,
        control: "textarea",
      },
    ],
    permissions: ["plugin.health.read", "plugin.settings.validate", "plugin.settings_intent.create"],
    optionalServices: [],
    publisherKey: `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA4C3L9i1clPkZH/NsjZgdZh5O0j3aDUODfT7jE2bp9JE=
-----END PUBLIC KEY-----
`,
  },
  {
    id: "@catomicals/plugin-backup",
    manifestId: "00000000-0000-4000-8000-000000000008",
    namespace: "backup",
    fields: [
      stringField("directory", "Backup directory", ""),
      { id: "retention", label: "Retention count", type: "integer", required: true, default: 7, minimum: 1, maximum: 365, restart: "none" },
      stringField("schedule", "Schedule", "manual", "none"),
    ],
    permissions: ["plugin.health.read", "plugin.settings.validate", "plugin.settings_intent.create"],
    optionalServices: ["backup.health"],
    runtimeHealthService: "backup.health",
  },
  {
    id: "@catomicals/plugin-browser",
    manifestId: "00000000-0000-4000-8000-000000000009",
    namespace: "browser",
    fields: [stringField("home", "Browser home", "https://mempool.space/signet", "none")],
    permissions: ["browser.open.public", "plugin.health.read", "plugin.settings.validate", "plugin.settings_intent.create"],
    optionalServices: ["browser.health"],
    runtimeHealthService: "browser.health",
  },
  {
    id: "@catomicals/plugin-chain-fractal-bitcoin",
    manifestId: "00000000-0000-4000-8000-00000000000b",
    namespace: "chain.fractal.bitcoin",
    fields: chainFields({ enabled: false, networkId: "fractal-bitcoin-mainnet", transport: "json-rpc" }),
    permissions: chainPermissions,
    optionalServices: [],
    healthService: "chain.fractal-bitcoin.health",
    publisherKey: chainPublisherKey,
    catalog: chainCatalog,
  },
  {
    id: "@catomicals/plugin-chain-bitcoin-cash",
    manifestId: "00000000-0000-4000-8000-00000000000c",
    namespace: "chain.bitcoin.cash",
    fields: chainFields({ enabled: false, networkId: "bitcoin-cash-mainnet", transport: "json-rpc" }),
    permissions: chainPermissions,
    optionalServices: [],
    healthService: "chain.bitcoin-cash.health",
    publisherKey: chainPublisherKey,
    catalog: chainCatalog,
  },
  {
    id: "@catomicals/plugin-chain-bsv",
    manifestId: "00000000-0000-4000-8000-00000000000d",
    namespace: "chain.bsv",
    fields: chainFields({ enabled: false, networkId: "bsv-mainnet", transport: "json-rpc" }),
    permissions: chainPermissions,
    optionalServices: [],
    healthService: "chain.bsv.health",
    publisherKey: chainPublisherKey,
    catalog: chainCatalog,
  },
  {
    id: "@catomicals/plugin-chain-kaspa",
    manifestId: "00000000-0000-4000-8000-00000000000e",
    namespace: "chain.kaspa",
    fields: chainFields({ enabled: false, networkId: "kaspa-mainnet", transport: "grpc" }),
    permissions: chainPermissions,
    optionalServices: [],
    healthService: "chain.kaspa.health",
    publisherKey: chainPublisherKey,
    catalog: chainCatalog,
  },
  {
    id: "@catomicals/plugin-chain-chia",
    manifestId: "00000000-0000-4000-8000-00000000000f",
    namespace: "chain.chia",
    fields: chainFields({ enabled: false, networkId: "chia-mainnet", transport: "rest" }),
    permissions: chainPermissions,
    optionalServices: [],
    healthService: "chain.chia.health",
    publisherKey: chainPublisherKey,
    catalog: chainCatalog,
  },
  {
    id: "@catomicals/plugin-chain-ergo",
    manifestId: "00000000-0000-4000-8000-000000000010",
    namespace: "chain.ergo",
    fields: chainFields({ enabled: false, networkId: "ergo-mainnet", transport: "rest" }),
    permissions: chainPermissions,
    optionalServices: [],
    healthService: "chain.ergo.health",
    publisherKey: chainPublisherKey,
    catalog: chainCatalog,
  },
];

const publisherKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA7W8WSsvBKb6whyJYKFp9VhqZGvJ5PEkhin0FvWkXsGM=
-----END PUBLIC KEY-----
`;

const signatures: Readonly<Record<FixedPluginId, string>> = {
  "@catomicals/plugin-walletd": "CKjtmFYRMTve9CtgtIKJrd5Kipg8hOzzRBik4Bu7KY3QJcBg/etOxePNZsnF261B9rmY9CCftP7I1aN4FHAuBA==",
  "@catomicals/plugin-bitcoin-node": "XYJcSuwnxSLFhEX2clI5tkYoVQ1lYlC7kXZXBIuuSK3UVhtxgCD2HSqFdfuGTMicAPoFCltHfQFqdH49W+/pDw==",
  "@catomicals/plugin-indexer": "PX/DVyyIGs5mMmujB+xioUlltEqSlVVhz+eSgGqHZ950zxsBOQW/WJsbaYZGdra2jcWdn2MVJ02sp7TtjsXNCQ==",
  "@catomicals/plugin-mcp": "g6WKVIlkn9sPNGSNeSpMRl6ZxdimTqTFtSqc3yG+AlPuEWQl4uXoSsxAORQBL/zwnJ0Q5odSVRGWn+jHWfcfAA==",
  "@catomicals/plugin-executor-codex": "yUzds6wig0/SA5RUwl7txdMt0k9tfAMQn4ChkcI1cfk+mh/Hu48BQgBHoKXjHLyt8yxPPrI40JengRfABWA7Bw==",
  "@catomicals/plugin-executor-deepseek": "/uG1bryz/mtAv80mjLOTaBnJJCYoyg7Rc13EfwTE0lPUz3ykEgHeEgsxpcIidqcocf4N6e5YKE68yBdCb7nPAw==",
  "@catomicals/plugin-executor-claude-code": "nNLF86vlSDvlZXqYYy9otQGoXaMiE5FUvom0GlMesC7sZMg/pqvi4t9/A86vxcl1Cp73M25pVrxm2cKeVsmEAQ==",
  "@catomicals/plugin-generative-ui": "SuuuJb84JBq0xUryuifWXv3Lm/EU8SI9QLIjaEsxwW6MhpvzO8bbW9NAm9vpHNBaF8JgR5P3HXkyeR3+PNFdAg==",
  "@catomicals/plugin-backup": "azpzHPFLpkcsPpO0TWz5SWbeVMudtJnzPzDY4+RZTJDX6gUqRLQo9TyZm1O8IWSu4ukLOnb9TQ0NSFJY+KfZDw==",
  "@catomicals/plugin-browser": "GL04RzqgDeWiDG8yBHAGJr4ph8xIe0CJjfQEPIAj2PILfYo7OYRfLjvzA526cwplrU8CW+4IHUUGxTr4ELHDCg==",
  "@catomicals/plugin-chain-fractal-bitcoin": "MLO+izHkVgSp6iLlItmtdUrO6UGjUVgfZwvGyMcy2/2RVyuXNMnaf6GyoSXgpi2RahXmHMKrLsk8sd02fiHIAQ==",
  "@catomicals/plugin-chain-bitcoin-cash": "avBdCQxBGtlzyx5B4bjN7byXN7Av1BHNSnxog6OCOolKdgU40uFr4zV/ixmIkplsbkENb9HwhI6+xuGWcITPAQ==",
  "@catomicals/plugin-chain-bsv": "xYyiP/NQNFY9Le1mYRJ6TT5OGnRKJk8AQ1lwRxNVrMKExzFc3cLXX8oIiM1Xo0+B0KAzkjOMGa6tov72cnI5AQ==",
  "@catomicals/plugin-chain-kaspa": "sHTUD+j+X67sc0uYvIrduSVT/UZizynupu1Fv8AZRr8H5ArYv7BovCYdLEWoE2jxdFh+ObiFmXIZ1dRZC4eaDg==",
  "@catomicals/plugin-chain-chia": "ILmyQo9ohSEzXhK5E0X+619RgukmNe0zxLcSVTwviWpAu3fY/pOrP6srwU5pZJq9tGvJHU50TVnJ4jNyB3AlDw==",
  "@catomicals/plugin-chain-ergo": "bYwiouN54GyHFEsB6ySzCMbnMFnqx2WXCwq3cn0WuLB8er1JGiief35d5YVHH7HcEFJUFY+BMHgaV3msb9T9Aw==",
};

function buildPackage(spec: BuiltinSpec): { registration: FixedPluginRegistration; trust: TrustedPlugin } {
  const pluginVersion = spec.pluginVersion ?? "1.0.0";
  const descriptor = canonicalJson({
    pluginId: spec.id,
    pluginVersion,
    implementation: "catomicals-cordis-declarative-v1",
  });
  const schema: CordisSettingsSchema = { version: spec.schemaVersion ?? 1, fields: spec.fields };
  const signature = signatures[spec.id];
  const manifest: PluginManifest = {
    schema_version: 1,
    manifest_id: spec.manifestId,
    plugin_id: spec.id,
    plugin_version: pluginVersion,
    runtime_api: 1,
    publisher: { publisher_id: "catomicals-core", key_id: "desktop-release-2026-01" },
    package_digest: digestBytes(Buffer.from(descriptor)),
    package_attestation: {
      algorithm: "ed25519",
      attestation_digest: digestBytes(Buffer.from(signature, "base64")),
    },
    entries: { host: "dist/cordis/builtins.js", client: "dist/cordis/client.js" },
    inject: { required: spec.healthService ? [spec.healthService] : [], optional: [...spec.optionalServices] },
    permission_scopes: [...spec.permissions],
    settings: {
      namespace: spec.namespace,
      mode: "intent_only",
      schema_version: schema.version,
      schema_digest: digestJson(schema),
    },
    ui_surfaces: [{ surface_id: "settings", placement: "settings", client_entry: "dist/cordis/client.js" }],
    migration: { namespace: spec.namespace, current: spec.migrationCurrent ?? 0 },
    ...(spec.healthService ? { health_service: spec.healthService } : {}),
    ...(spec.catalog ? { catalog: spec.catalog } : {}),
  };
  return {
    registration: {
      id: spec.id,
      manifest,
      descriptor,
      signature,
      settingsSchema: schema,
      ...(spec.migrations ? { migrations: spec.migrations } : {}),
      ...(spec.runtimeHealthService ? {
        healthCheck: async ({ services }) => {
          const snapshot = services.get(spec.runtimeHealthService!);
          return snapshot
            ? { status: snapshot.status, ...(snapshot.message ? { message: snapshot.message } : {}) }
            : { status: "degraded" as const, message: `${spec.runtimeHealthService} unavailable` };
        },
      } : {}),
    },
    trust: {
      pluginId: spec.id,
      pluginVersion,
      publisherId: manifest.publisher.publisher_id,
      keyId: manifest.publisher.key_id,
      packageDigest: manifest.package_digest,
      publicKey: spec.publisherKey ?? publisherKey,
    },
  };
}

export function builtinPackages(): readonly { registration: FixedPluginRegistration; trust: TrustedPlugin }[] {
  return specs.map(buildPackage);
}

export function createBuiltinCordisHost(stateStore: CordisStateStore, services: readonly CordisService[] = []): CordisHost {
  const packages = builtinPackages();
  return new CordisHost({
    registrations: packages.map((item) => item.registration),
    trust: packages.map((item) => item.trust),
    stateStore,
    services,
  });
}

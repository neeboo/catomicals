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
import type { CordisSettings, CordisSettingsField, CordisSettingsSchema } from "./settings.js";
import type { CordisStateStore } from "./store.js";
import type { CordisService } from "./health.js";
import type { CordisMigration } from "./migrations.js";
import { chainRpcNetworkIds, type ChainId } from "../chains/rpc/index.js";

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
  "@catomicals/plugin-chain-bitcoin",
  "@catomicals/plugin-chain-bitcoin-cash",
  "@catomicals/plugin-chain-bsv",
  "@catomicals/plugin-chain-fractal-bitcoin",
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

const legacyBitcoinPublisherKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAE+KnOsSbhZyoU83LQJ9WU/R6setsTKzwC4vdM4SIHZo=
-----END PUBLIC KEY-----
`;

const chainPublisherKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA4gVFeGb6DtIF4OVmhfNj+YwIGcPMoMQpXgYpABKsMN0=
-----END PUBLIC KEY-----
`;

const chainFields = (options: {
  enabled: boolean;
  chain?: ChainId;
  networkId: string;
  transport: string;
  transports: readonly string[];
  networkAccess: "local" | "private-network" | "public";
  endpoint?: string;
}): readonly CordisSettingsField[] => [
  { ...enabledField, default: options.enabled },
  {
    ...stringField("networkId", options.chain ? "网络" : "Network", options.networkId),
    ...(options.chain ? { choices: chainRpcNetworkIds(options.chain) } : {}),
  },
  ...(options.chain ? [{
    id: "nodeSource",
    label: "节点来源",
    type: "string" as const,
    required: true,
    default: "preset",
    choices: ["preset", "custom"],
    restart: "plugin" as const,
  }] : []),
  {
    id: "transport",
    label: options.chain ? "传输协议" : "Transport",
    type: "string",
    required: true,
    default: options.transport,
    choices: options.transports,
    restart: "plugin",
  },
  {
    id: "endpoint",
    label: options.chain ? "RPC 地址" : "RPC endpoint",
    type: "string",
    required: false,
    ...(!options.chain && options.endpoint ? { default: options.endpoint } : {}),
    restart: "plugin",
    maxLength: 1024,
    format: "rpc-endpoint",
  },
  {
    id: "networkAccess",
    label: options.chain ? "网络访问" : "Network access",
    type: "string",
    required: true,
    default: options.networkAccess,
    choices: ["local", "private-network", "public"],
    restart: "plugin",
  },
  {
    id: "credentialRef",
    label: options.chain ? "RPC 凭证" : "RPC credential",
    type: "string",
    required: false,
    secretReference: true,
    restart: "plugin",
  },
  {
    id: "access",
    label: options.chain ? "RPC 权限" : "RPC access",
    type: "string",
    required: true,
    default: "read",
    choices: ["read", "broadcast"],
    restart: "plugin",
  },
  ...(options.chain ? [{
    id: "addressValidation",
    label: "地址校验",
    type: "string" as const,
    required: true,
    default: "strict",
    choices: ["strict"],
    restart: "none" as const,
  }] : []),
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

function migratedChainSettings(
  settings: CordisSettings,
  options: {
    readonly transport: string;
    readonly networkAccess: "local" | "private-network" | "public";
    readonly includeNodeSource?: boolean;
  },
): CordisSettings {
  return {
    enabled: settings.enabled !== false,
    networkId: typeof settings.networkId === "string" ? settings.networkId : "mainnet",
    transport: options.transport,
    networkAccess: options.networkAccess,
    access: settings.access === "broadcast" ? "broadcast" : "read",
    ...(options.includeNodeSource
      ? { nodeSource: typeof settings.endpoint === "string" ? "custom" : "preset" }
      : {}),
    ...(typeof settings.endpoint === "string" ? { endpoint: settings.endpoint } : {}),
    ...(typeof settings.credentialRef === "string" ? { credentialRef: settings.credentialRef } : {}),
  };
}

const legacyChainMigration = (
  transport: string,
  networkAccess: "local" | "private-network" | "public",
): CordisMigration => ({
  from: 0,
  to: 1,
  migrate: (settings) => ({
    ...migratedChainSettings(settings, { transport, networkAccess, includeNodeSource: true }),
    addressValidation: "strict",
  }),
});

const strictAddressMigration: CordisMigration = {
  from: 1,
  to: 2,
  migrate: (settings) => ({
    ...settings,
    nodeSource: typeof settings.endpoint === "string" ? "custom" : "preset",
    addressValidation: "strict",
  }),
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
    fields: chainFields({
      enabled: true,
      networkId: "bitcoin-inquisition",
      transport: "wallet-gateway",
      transports: ["wallet-gateway", "json-rpc"],
      networkAccess: "local",
      endpoint: "http://127.0.0.1:18787",
    }),
    permissions: chainPermissions,
    optionalServices: [],
    healthService: "bitcoin.node.health",
    publisherKey: legacyBitcoinPublisherKey,
    catalog: chainCatalog,
    pluginVersion: "1.2.0",
    schemaVersion: 3,
    migrationCurrent: 2,
    migrations: [{
      from: 0,
      to: 1,
      migrate: (settings) => ({
        enabled: true,
        networkId: settings.profile === "inquisition" ? "bitcoin-inquisition" : "bitcoin-signet",
        transport: "wallet-gateway",
        endpoint: settings.endpoint ?? "http://127.0.0.1:18787",
        networkAccess: "local",
        access: "read",
      }),
    }, {
      from: 1,
      to: 2,
      migrate: (settings) => migratedChainSettings(settings, {
        transport: settings.transport === "json-rpc" ? "json-rpc" : "wallet-gateway",
        networkAccess: "local",
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
    id: "@catomicals/plugin-chain-bitcoin",
    manifestId: "00000000-0000-4000-8000-000000000011",
    namespace: "chain.bitcoin",
    fields: chainFields({
      enabled: true,
      chain: "bitcoin",
      networkId: "bitcoin-inquisition",
      transport: "json-rpc",
      transports: ["json-rpc"],
      networkAccess: "local",
    }),
    permissions: chainPermissions,
    optionalServices: [],
    healthService: "bitcoin.node.health",
    publisherKey: chainPublisherKey,
    catalog: chainCatalog,
  },
  {
    id: "@catomicals/plugin-chain-bitcoin-cash",
    manifestId: "00000000-0000-4000-8000-00000000000c",
    namespace: "chain.bitcoin.cash",
    fields: chainFields({ enabled: false, chain: "bitcoin-cash", networkId: "bitcoin-cash-mainnet", transport: "json-rpc", transports: ["json-rpc"], networkAccess: "local" }),
    permissions: chainPermissions,
    optionalServices: [],
    healthService: "chain.bitcoin-cash.health",
    publisherKey: chainPublisherKey,
    catalog: chainCatalog,
    pluginVersion: "1.2.0",
    schemaVersion: 3,
    migrationCurrent: 2,
    migrations: [legacyChainMigration("json-rpc", "local"), strictAddressMigration],
  },
  {
    id: "@catomicals/plugin-chain-bsv",
    manifestId: "00000000-0000-4000-8000-00000000000d",
    namespace: "chain.bsv",
    fields: chainFields({ enabled: false, chain: "bsv", networkId: "bsv-mainnet", transport: "json-rpc", transports: ["json-rpc"], networkAccess: "local" }),
    permissions: chainPermissions,
    optionalServices: [],
    healthService: "chain.bsv.health",
    publisherKey: chainPublisherKey,
    catalog: chainCatalog,
    pluginVersion: "1.2.0",
    schemaVersion: 3,
    migrationCurrent: 2,
    migrations: [legacyChainMigration("json-rpc", "local"), strictAddressMigration],
  },
  {
    id: "@catomicals/plugin-chain-fractal-bitcoin",
    manifestId: "00000000-0000-4000-8000-00000000000b",
    namespace: "chain.fractal.bitcoin",
    fields: chainFields({ enabled: false, chain: "fractal-bitcoin", networkId: "fractal-bitcoin-mainnet", transport: "json-rpc", transports: ["json-rpc"], networkAccess: "local" }),
    permissions: chainPermissions,
    optionalServices: [],
    healthService: "chain.fractal-bitcoin.health",
    publisherKey: chainPublisherKey,
    catalog: chainCatalog,
    pluginVersion: "1.2.0",
    schemaVersion: 3,
    migrationCurrent: 2,
    migrations: [legacyChainMigration("json-rpc", "local"), strictAddressMigration],
  },
  {
    id: "@catomicals/plugin-chain-kaspa",
    manifestId: "00000000-0000-4000-8000-00000000000e",
    namespace: "chain.kaspa",
    fields: chainFields({
      enabled: false,
      chain: "kaspa",
      networkId: "kaspa-mainnet",
      transport: "https-api",
      transports: ["https-api", "json-rpc", "wrpc"],
      networkAccess: "public",
    }),
    permissions: chainPermissions,
    optionalServices: [],
    healthService: "chain.kaspa.health",
    publisherKey: chainPublisherKey,
    catalog: chainCatalog,
    pluginVersion: "1.2.0",
    schemaVersion: 3,
    migrationCurrent: 2,
    migrations: [legacyChainMigration("https-api", "public"), strictAddressMigration],
  },
  {
    id: "@catomicals/plugin-chain-chia",
    manifestId: "00000000-0000-4000-8000-00000000000f",
    namespace: "chain.chia",
    fields: chainFields({ enabled: false, chain: "chia", networkId: "chia-mainnet", transport: "https-rpc", transports: ["https-rpc"], networkAccess: "local" }),
    permissions: chainPermissions,
    optionalServices: [],
    healthService: "chain.chia.health",
    publisherKey: chainPublisherKey,
    catalog: chainCatalog,
    pluginVersion: "1.2.0",
    schemaVersion: 3,
    migrationCurrent: 2,
    migrations: [legacyChainMigration("https-rpc", "local"), strictAddressMigration],
  },
  {
    id: "@catomicals/plugin-chain-ergo",
    manifestId: "00000000-0000-4000-8000-000000000010",
    namespace: "chain.ergo",
    fields: chainFields({ enabled: false, chain: "ergo", networkId: "ergo-mainnet", transport: "rest", transports: ["rest"], networkAccess: "local" }),
    permissions: chainPermissions,
    optionalServices: [],
    healthService: "chain.ergo.health",
    publisherKey: chainPublisherKey,
    catalog: chainCatalog,
    pluginVersion: "1.2.0",
    schemaVersion: 3,
    migrationCurrent: 2,
    migrations: [legacyChainMigration("rest", "local"), strictAddressMigration],
  },
];

const publisherKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA7W8WSsvBKb6whyJYKFp9VhqZGvJ5PEkhin0FvWkXsGM=
-----END PUBLIC KEY-----
`;

const signatures: Readonly<Record<FixedPluginId, string>> = {
  "@catomicals/plugin-walletd": "CKjtmFYRMTve9CtgtIKJrd5Kipg8hOzzRBik4Bu7KY3QJcBg/etOxePNZsnF261B9rmY9CCftP7I1aN4FHAuBA==",
  "@catomicals/plugin-bitcoin-node": "xWCSLrdICN8NXQUYcBcwafyBjG+6fUvT2E0Xs/QbRkydb9Ck8TQquDNUeQfUZ6qWvpmto11Db0/ceAGqgg5xDg==",
  "@catomicals/plugin-indexer": "PX/DVyyIGs5mMmujB+xioUlltEqSlVVhz+eSgGqHZ950zxsBOQW/WJsbaYZGdra2jcWdn2MVJ02sp7TtjsXNCQ==",
  "@catomicals/plugin-mcp": "g6WKVIlkn9sPNGSNeSpMRl6ZxdimTqTFtSqc3yG+AlPuEWQl4uXoSsxAORQBL/zwnJ0Q5odSVRGWn+jHWfcfAA==",
  "@catomicals/plugin-executor-codex": "yUzds6wig0/SA5RUwl7txdMt0k9tfAMQn4ChkcI1cfk+mh/Hu48BQgBHoKXjHLyt8yxPPrI40JengRfABWA7Bw==",
  "@catomicals/plugin-executor-deepseek": "/uG1bryz/mtAv80mjLOTaBnJJCYoyg7Rc13EfwTE0lPUz3ykEgHeEgsxpcIidqcocf4N6e5YKE68yBdCb7nPAw==",
  "@catomicals/plugin-executor-claude-code": "nNLF86vlSDvlZXqYYy9otQGoXaMiE5FUvom0GlMesC7sZMg/pqvi4t9/A86vxcl1Cp73M25pVrxm2cKeVsmEAQ==",
  "@catomicals/plugin-generative-ui": "SuuuJb84JBq0xUryuifWXv3Lm/EU8SI9QLIjaEsxwW6MhpvzO8bbW9NAm9vpHNBaF8JgR5P3HXkyeR3+PNFdAg==",
  "@catomicals/plugin-backup": "azpzHPFLpkcsPpO0TWz5SWbeVMudtJnzPzDY4+RZTJDX6gUqRLQo9TyZm1O8IWSu4ukLOnb9TQ0NSFJY+KfZDw==",
  "@catomicals/plugin-browser": "GL04RzqgDeWiDG8yBHAGJr4ph8xIe0CJjfQEPIAj2PILfYo7OYRfLjvzA526cwplrU8CW+4IHUUGxTr4ELHDCg==",
  "@catomicals/plugin-chain-bitcoin": "APK4JoWmr1yCcdOGQWOGcOFpUacZirl3e1cfYmD9CLn8xAXMo3pl1em7CZ+SP6k0qWn2XZUDy3qM52HdP+voCA==",
  "@catomicals/plugin-chain-fractal-bitcoin": "blfob69OldlbyUFXIV6wI+lNLV1BpzJaMbac9v0LPDU23XLja8L0XFnJ3hkrQlni9fWQIHusSwLHEwONUSmUCg==",
  "@catomicals/plugin-chain-bitcoin-cash": "mRsYh8BtHcu9Eah4nXkRmnEvvMRbmhigPLlMEjkcvpydlf4ayNFUaTVMMEU/2pIEHdeqjEnrs/Ai7iwxG3PzCQ==",
  "@catomicals/plugin-chain-bsv": "rjP4zrqYt5IlC07AONZeodSUz+kkGvLnN5hS1j5CRlO+ACGgIESc6MA9ku0ulqkqH6DSXmajRxcAhJ8yKBkQDA==",
  "@catomicals/plugin-chain-kaspa": "O71vG3HpUxxFbV70ImAvsoPskOZcxsk8de/8HjYkByWW4zG5uI8cMO9feiDwfchzSej+y7Rg30WK068yDTD7Dg==",
  "@catomicals/plugin-chain-chia": "DZlZv0B5MWOjrPJV4bb1N2PO9zRuxIxgoa0oG5emZGqobEx8SyEm8ljSMESJNZPw51ijyRAV5+ecOYL4I4gJCQ==",
  "@catomicals/plugin-chain-ergo": "NnrCQ/NWIZW2/P7hXMqTnExH/xjbN+VTSTdzEuNJfFqcQJg+whTjSAsnNNUrazPGldmC7ymySSgKvYiWNlx+Dw==",
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

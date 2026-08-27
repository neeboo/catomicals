import type { DesktopBridge } from "./desktop";

export type ControlledUiComponent =
  | "fee_chart"
  | "health_status"
  | "plugin_settings_diff"
  | "policy_diff"
  | "review_card"
  | "transaction_summary";
export type ControlledReferenceKind = "intent_id" | "node_snapshot_id" | "plugin_id" | "policy_hash" | "review_id";
export type ControlledUiSource = "desktop_host" | "indexer" | "policy_registry" | "walletd";
export type ControlledUiAction = "dismiss_block" | "open_health" | "open_intent" | "open_plugin" | "open_review";

export interface ControlledUiDataBinding {
  slot: string;
  source: ControlledUiSource;
  reference_kind: ControlledReferenceKind;
  reference_id: string;
}

export interface ControlledUiActionBinding {
  action_id: string;
  action: ControlledUiAction;
  target_binding: string;
}

export interface AgentUiBlockReference {
  schema_version: 1;
  block_id: string;
  component: ControlledUiComponent;
  data_bindings: ControlledUiDataBinding[];
  action_bindings: [];
}

export interface HostProjectedUiBlock extends Omit<AgentUiBlockReference, "action_bindings"> {
  action_bindings: ControlledUiActionBinding[];
  title?: string;
  description?: string;
}

export interface ChatReviewReference {
  schema_version: 1;
  review_id: string;
  kind: "transaction" | "protected_trade" | "policy_activation" | "plugin_settings";
  source: "walletd" | "policy_registry" | "desktop_host";
  review_digest: string;
  created_at: string;
  state: "current" | "stale" | "expired" | "revoked";
  valid_until?: string;
  intent_id?: string;
  policy_hash?: string;
  node_snapshot_id?: string;
  plugin_id?: string;
  plugin_version?: string;
}

type UiBlockReader = Pick<DesktopBridge, "readPluginHealth" | "readPluginSettingsReview">;

const UUID = /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/;
const PLUGIN_ID = /^@catomicals\/plugin-[a-z0-9]+(?:-[a-z0-9]+)*$/;
const BINDING_NAME = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;
const CONTENT_DIGEST = /^(?:sha256|blake3):[0-9a-f]{64}$/;
const SEMANTIC_VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

function plainRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid UI block");
  return value as Record<string, unknown>;
}

function exactFields(value: Record<string, unknown>, expected: readonly string[]): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((field, index) => field !== wanted[index])) {
    throw new Error("unexpected UI block fields");
  }
}

function strictUuid(value: unknown, name: string): string {
  if (typeof value !== "string" || !UUID.test(value)) throw new Error(`invalid ${name}`);
  return value;
}

function bindingName(value: unknown): string {
  if (typeof value !== "string" || value.length > 64 || !BINDING_NAME.test(value)) {
    throw new Error("invalid UI block binding");
  }
  return value;
}

function contentDigest(value: unknown, name: string): string {
  if (typeof value !== "string" || !CONTENT_DIGEST.test(value)) throw new Error(`invalid ${name}`);
  return value;
}

function timestamp(value: unknown, name: string): string {
  if (typeof value !== "string" || !TIMESTAMP.test(value) || Number.isNaN(Date.parse(value))) {
    throw new Error(`invalid ${name}`);
  }
  return value;
}

function optionalUuid(value: unknown, name: string): string | undefined {
  return value === undefined ? undefined : strictUuid(value, name);
}

function optionalDigest(value: unknown, name: string): string | undefined {
  return value === undefined ? undefined : contentDigest(value, name);
}

function optionalPluginId(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length > 128 || !PLUGIN_ID.test(value)) {
    throw new Error("invalid plugin id");
  }
  return value;
}

function optionalSemanticVersion(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !SEMANTIC_VERSION.test(value)) {
    throw new Error("invalid plugin version");
  }
  return value;
}

export function parseReviewReference(value: unknown): ChatReviewReference {
  const input = plainRecord(value);
  const fields = [
    "schema_version", "review_id", "kind", "source", "review_digest", "intent_id",
    "policy_hash", "node_snapshot_id", "plugin_id", "plugin_version", "created_at",
    "valid_until", "state",
  ] as const;
  if (Object.keys(input).some((field) => !fields.includes(field as typeof fields[number]))) {
    throw new Error("unexpected review reference fields");
  }
  if (input.schema_version !== 1) throw new Error("unsupported review reference schema");
  const reviewId = strictUuid(input.review_id, "review id");
  if (input.kind !== "transaction" && input.kind !== "protected_trade"
    && input.kind !== "policy_activation" && input.kind !== "plugin_settings") {
    throw new Error("invalid review kind");
  }
  if (input.source !== "walletd" && input.source !== "policy_registry" && input.source !== "desktop_host") {
    throw new Error("invalid review source");
  }
  if (input.state !== "current" && input.state !== "stale" && input.state !== "expired" && input.state !== "revoked") {
    throw new Error("invalid review state");
  }
  const intentId = optionalUuid(input.intent_id, "intent id");
  const policyHash = optionalDigest(input.policy_hash, "policy hash");
  const nodeSnapshotId = optionalDigest(input.node_snapshot_id, "node snapshot id");
  const pluginId = optionalPluginId(input.plugin_id);
  const pluginVersion = optionalSemanticVersion(input.plugin_version);
  if ((input.kind === "transaction" || input.kind === "protected_trade") && (!policyHash || !nodeSnapshotId)) {
    throw new Error("incomplete transaction review reference");
  }
  if (input.kind === "policy_activation" && !policyHash) {
    throw new Error("incomplete policy review reference");
  }
  if (input.kind === "plugin_settings" && (!intentId || !pluginId || !pluginVersion)) {
    throw new Error("incomplete plugin review reference");
  }
  return {
    schema_version: 1,
    review_id: reviewId,
    kind: input.kind,
    source: input.source,
    review_digest: contentDigest(input.review_digest, "review digest"),
    created_at: timestamp(input.created_at, "created at"),
    state: input.state,
    ...(input.valid_until === undefined ? {} : { valid_until: timestamp(input.valid_until, "valid until") }),
    ...(intentId ? { intent_id: intentId } : {}),
    ...(policyHash ? { policy_hash: policyHash } : {}),
    ...(nodeSnapshotId ? { node_snapshot_id: nodeSnapshotId } : {}),
    ...(pluginId ? { plugin_id: pluginId } : {}),
    ...(pluginVersion ? { plugin_version: pluginVersion } : {}),
  };
}

function parseBinding(value: unknown): ControlledUiDataBinding {
  const binding = plainRecord(value);
  exactFields(binding, ["slot", "source", "reference_kind", "reference_id"]);
  const slot = bindingName(binding.slot);
  if (binding.source !== "desktop_host" && binding.source !== "indexer"
    && binding.source !== "policy_registry" && binding.source !== "walletd") {
    throw new Error("unsupported UI block source");
  }
  if (binding.reference_kind !== "intent_id" && binding.reference_kind !== "node_snapshot_id"
    && binding.reference_kind !== "plugin_id" && binding.reference_kind !== "policy_hash"
    && binding.reference_kind !== "review_id") {
    throw new Error("invalid UI block reference kind");
  }
  let referenceId: string;
  if (binding.reference_kind === "intent_id" || binding.reference_kind === "review_id") {
    referenceId = strictUuid(binding.reference_id, binding.reference_kind === "review_id" ? "review reference" : "intent reference");
  } else if (binding.reference_kind === "plugin_id") {
    if (typeof binding.reference_id !== "string" || binding.reference_id.length > 128 || !PLUGIN_ID.test(binding.reference_id)) {
      throw new Error("invalid plugin reference");
    }
    referenceId = binding.reference_id;
  } else {
    referenceId = contentDigest(binding.reference_id, "content reference");
  }
  return {
    slot,
    source: binding.source,
    reference_kind: binding.reference_kind,
    reference_id: referenceId,
  };
}

function parseAgentActions(value: unknown): [] {
  if (!Array.isArray(value)) throw new Error("invalid UI block actions");
  if (value.length !== 0) throw new Error("unsupported UI block action");
  return [];
}

export function parseControlledUiBlock(value: unknown): AgentUiBlockReference {
  const input = plainRecord(value);
  const allowedFields = new Set(["schema_version", "block_id", "component", "data_bindings", "action_bindings"]);
  if (Object.keys(input).some((field) => !allowedFields.has(field))) throw new Error("unexpected UI block fields");
  if (input.schema_version !== 1) throw new Error("unsupported UI block schema");
  const blockId = strictUuid(input.block_id, "block id");
  if (input.component !== "fee_chart" && input.component !== "health_status"
    && input.component !== "plugin_settings_diff" && input.component !== "policy_diff"
    && input.component !== "review_card" && input.component !== "transaction_summary") {
    throw new Error("unsupported UI block");
  }
  if (!Array.isArray(input.data_bindings) || input.data_bindings.length < 1) {
    throw new Error("invalid UI block bindings");
  }
  const bindings = input.data_bindings.map(parseBinding);
  if (new Set(bindings.map((binding) => JSON.stringify(binding))).size !== bindings.length) {
    throw new Error("duplicate UI block binding");
  }
  return {
    schema_version: 1,
    block_id: blockId,
    component: input.component,
    data_bindings: bindings,
    action_bindings: parseAgentActions(input.action_bindings),
  };
}

export function createReviewCardBlock(reviewId: string, blockId = crypto.randomUUID()): AgentUiBlockReference {
  return parseControlledUiBlock({
    schema_version: 1,
    block_id: blockId,
    component: "review_card",
    data_bindings: [{
      slot: "review",
      source: "desktop_host",
      reference_kind: "review_id",
      reference_id: reviewId,
    }],
    action_bindings: [],
  });
}

export async function loadControlledUiBlock(value: unknown, bridge: UiBlockReader) {
  const block = parseControlledUiBlock(value);
  const binding = block.data_bindings[0];
  if (block.component === "health_status") {
    if (block.data_bindings.length !== 1 || binding.source !== "desktop_host"
      || binding.slot !== "health" || binding.reference_kind !== "plugin_id") {
      throw new Error("unsupported health status binding");
    }
    return {
      kind: block.component,
      block,
      health: await bridge.readPluginHealth(binding.reference_id),
    } as const;
  }
  if (block.component !== "plugin_settings_diff" && block.component !== "review_card") {
    throw new Error("UI block renderer unavailable");
  }
  if (block.data_bindings.length !== 1 || binding.source !== "desktop_host"
    || binding.slot !== "review" || binding.reference_kind !== "review_id") {
    throw new Error("unsupported settings review binding");
  }
  return {
    kind: block.component,
    block,
    review: await bridge.readPluginSettingsReview(binding.reference_id),
  } as const;
}

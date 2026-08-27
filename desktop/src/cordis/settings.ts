export type CordisSettingValue = string | boolean | number | null;
export type CordisSettings = Readonly<Record<string, CordisSettingValue>>;
export type RestartImpact = "none" | "plugin" | "desktop";

export interface CordisSettingsField {
  id: string;
  label: string;
  type: "string" | "boolean" | "integer";
  required: boolean;
  restart: RestartImpact;
  default?: Exclude<CordisSettingValue, null>;
  secretReference?: true;
  choices?: readonly string[];
  minLength?: number;
  maxLength?: number;
  minimum?: number;
  maximum?: number;
}

export interface CordisSettingsSchema {
  version: number;
  fields: readonly CordisSettingsField[];
}

export interface CordisSettingsPatch {
  schemaVersion: number;
  changes: readonly { id: string; value: CordisSettingValue }[];
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

function positiveInteger(value: unknown, field: string, allowZero = false): number {
  if (!Number.isSafeInteger(value) || (value as number) < (allowZero ? 0 : 1)) throw new Error(`invalid ${field}`);
  return value as number;
}

function settingId(value: unknown): string {
  if (typeof value !== "string" || !/^[a-z][A-Za-z0-9]*(?:[.-][A-Za-z0-9]+)*$/.test(value) || value.length > 128) {
    throw new Error("invalid setting id");
  }
  return value;
}

function primitive(value: unknown): CordisSettingValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  throw new Error("setting value must be a primitive");
}

function parseField(value: unknown): CordisSettingsField {
  const input = record(value);
  exactFields(input, ["id", "label", "type", "required", "restart"], [
    "default", "secretReference", "choices", "minLength", "maxLength", "minimum", "maximum",
  ]);
  const type = input.type;
  if (type !== "string" && type !== "boolean" && type !== "integer") throw new Error("invalid setting type");
  if (typeof input.label !== "string" || input.label.length < 1 || input.label.length > 160) throw new Error("invalid setting label");
  if (typeof input.required !== "boolean") throw new Error("invalid required setting");
  if (input.restart !== "none" && input.restart !== "plugin" && input.restart !== "desktop") throw new Error("invalid restart impact");
  if (input.secretReference !== undefined && input.secretReference !== true) throw new Error("invalid secret reference field");
  if (input.secretReference && type !== "string") throw new Error("secret reference field must be a string");
  const id = settingId(input.id);
  if (/(?:secret|token|password|credential|api[-_.]?key|oauth)/i.test(id) && input.secretReference !== true) {
    throw new Error("secret-bearing setting must use a secret reference");
  }
  const choices = input.choices === undefined ? undefined : (() => {
    if (type !== "string" || !Array.isArray(input.choices) || input.choices.length === 0
      || input.choices.some((choice) => typeof choice !== "string")
      || new Set(input.choices).size !== input.choices.length) throw new Error("invalid setting choices");
    return input.choices as string[];
  })();
  const result: CordisSettingsField = {
    id,
    label: input.label,
    type,
    required: input.required,
    restart: input.restart,
    ...(input.default !== undefined ? { default: primitive(input.default) as Exclude<CordisSettingValue, null> } : {}),
    ...(input.secretReference ? { secretReference: true as const } : {}),
    ...(choices ? { choices } : {}),
    ...(input.minLength !== undefined ? { minLength: positiveInteger(input.minLength, "minimum length", true) } : {}),
    ...(input.maxLength !== undefined ? { maxLength: positiveInteger(input.maxLength, "maximum length", true) } : {}),
    ...(input.minimum !== undefined ? { minimum: positiveInteger(input.minimum, "minimum", true) } : {}),
    ...(input.maximum !== undefined ? { maximum: positiveInteger(input.maximum, "maximum", true) } : {}),
  };
  if (result.required && result.default === undefined) throw new Error("required setting needs a default");
  if (result.secretReference && result.default !== undefined) throw new Error("secret references cannot have defaults");
  if ((result.minLength !== undefined || result.maxLength !== undefined) && type !== "string") throw new Error("length applies only to strings");
  if ((result.minimum !== undefined || result.maximum !== undefined) && type !== "integer") throw new Error("range applies only to integers");
  if (result.minLength !== undefined && result.maxLength !== undefined && result.minLength > result.maxLength) throw new Error("invalid string range");
  if (result.minimum !== undefined && result.maximum !== undefined && result.minimum > result.maximum) throw new Error("invalid integer range");
  if (result.default !== undefined) validateFieldValue(result, result.default);
  return result;
}

export function parseSettingsSchema(value: unknown): CordisSettingsSchema {
  const input = record(value);
  exactFields(input, ["version", "fields"]);
  const version = positiveInteger(input.version, "settings schema version");
  if (!Array.isArray(input.fields)) throw new Error("invalid settings fields");
  const fields = input.fields.map(parseField);
  if (new Set(fields.map((field) => field.id)).size !== fields.length) throw new Error("duplicate setting field");
  return { version, fields };
}

function validateFieldValue(field: CordisSettingsField, value: CordisSettingValue): void {
  if (value === null) {
    if (field.required) throw new Error(`required setting ${field.id}`);
    return;
  }
  if (field.type === "string" && typeof value !== "string") throw new Error(`invalid setting ${field.id}`);
  if (field.type === "boolean" && typeof value !== "boolean") throw new Error(`invalid setting ${field.id}`);
  if (field.type === "integer" && (typeof value !== "number" || !Number.isSafeInteger(value))) throw new Error(`invalid setting ${field.id}`);
  if (typeof value === "string") {
    if (field.secretReference && !/^secret-ref:[A-Za-z0-9_-]{16,128}$/.test(value)) throw new Error("invalid secret reference");
    if (field.choices && !field.choices.includes(value)) throw new Error(`invalid setting ${field.id}`);
    if (field.minLength !== undefined && value.length < field.minLength) throw new Error(`invalid setting ${field.id}`);
    if (field.maxLength !== undefined && value.length > field.maxLength) throw new Error(`invalid setting ${field.id}`);
  }
  if (typeof value === "number") {
    if (field.minimum !== undefined && value < field.minimum) throw new Error(`invalid setting ${field.id}`);
    if (field.maximum !== undefined && value > field.maximum) throw new Error(`invalid setting ${field.id}`);
  }
}

export function validateSettings(schemaValue: unknown, value: unknown): CordisSettings {
  const schema = parseSettingsSchema(schemaValue);
  const input = record(value);
  const known = new Map(schema.fields.map((field) => [field.id, field]));
  if (Object.keys(input).some((id) => !known.has(id))) throw new Error("unknown setting");
  const result: Record<string, CordisSettingValue> = {};
  for (const field of schema.fields) {
    const raw = input[field.id];
    if (raw === undefined) {
      if (field.required) throw new Error(`required setting ${field.id}`);
      continue;
    }
    const parsed = primitive(raw);
    validateFieldValue(field, parsed);
    if (parsed !== null) result[field.id] = parsed;
  }
  return result;
}

export function defaultSettings(schemaValue: unknown): CordisSettings {
  const schema = parseSettingsSchema(schemaValue);
  return Object.fromEntries(schema.fields.flatMap((field) => field.default === undefined ? [] : [[field.id, field.default]]));
}

export function parseSettingsPatch(value: unknown): CordisSettingsPatch {
  const input = record(value);
  exactFields(input, ["schemaVersion", "changes"]);
  const schemaVersion = positiveInteger(input.schemaVersion, "patch schema version");
  if (!Array.isArray(input.changes) || input.changes.length === 0) throw new Error("invalid settings changes");
  const changes = input.changes.map((change) => {
    const parsed = record(change);
    exactFields(parsed, ["id", "value"]);
    return { id: settingId(parsed.id), value: primitive(parsed.value) };
  });
  if (new Set(changes.map((change) => change.id)).size !== changes.length) throw new Error("duplicate setting change");
  return { schemaVersion, changes };
}

const impactRank: Record<RestartImpact, number> = { none: 0, plugin: 1, desktop: 2 };

export function applySettingsPatch(
  schemaValue: unknown,
  currentValue: unknown,
  patchValue: unknown,
): { settings: CordisSettings; restartImpact: RestartImpact } {
  const schema = parseSettingsSchema(schemaValue);
  const current = validateSettings(schema, currentValue);
  const patch = parseSettingsPatch(patchValue);
  if (patch.schemaVersion !== schema.version) throw new Error("settings schema version mismatch");
  const fields = new Map(schema.fields.map((field) => [field.id, field]));
  const candidate: Record<string, CordisSettingValue> = { ...current };
  let restartImpact: RestartImpact = "none";
  for (const change of patch.changes) {
    const field = fields.get(change.id);
    if (!field) throw new Error("unknown setting");
    validateFieldValue(field, change.value);
    if (change.value === null) delete candidate[change.id];
    else candidate[change.id] = change.value;
    if (impactRank[field.restart] > impactRank[restartImpact]) restartImpact = field.restart;
  }
  return { settings: validateSettings(schema, candidate), restartImpact };
}

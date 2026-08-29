import { describe, expect, it } from "vitest";
import { testSettingsSchema } from "./test-fixtures.js";
import {
  applySettingsPatch,
  defaultSettings,
  parseSettingsPatch,
  parseSettingsSchema,
} from "./settings.js";

describe("Cordis plugin settings", () => {
  it("uses whole-field replacement with a closed patch contract", () => {
    const schema = parseSettingsSchema(testSettingsSchema);
    const current = defaultSettings(schema);
    const result = applySettingsPatch(schema, current, {
      schemaVersion: 1,
      changes: [{ id: "endpoint", value: "http://127.0.0.1:18888" }],
    });

    expect(result.settings).toEqual({
      endpoint: "http://127.0.0.1:18888",
      enabled: true,
    });
    expect(result.restartImpact).toBe("plugin");
    expect(current.endpoint).toBe("http://127.0.0.1:18787");
  });

  it("rejects unknown, duplicate, and nested patch values", () => {
    expect(() => applySettingsPatch(testSettingsSchema, defaultSettings(testSettingsSchema), {
      schemaVersion: 1,
      changes: [{ id: "unknown", value: true }],
    })).toThrow("unknown setting");
    expect(() => parseSettingsPatch({
      schemaVersion: 1,
      changes: [{ id: "enabled", value: true }, { id: "enabled", value: false }],
    })).toThrow("duplicate setting");
    expect(() => parseSettingsPatch({
      schemaVersion: 1,
      changes: [{ id: "enabled", value: { shell: "rm" } }],
    })).toThrow("primitive");
  });

  it("accepts only opaque references for secret fields", () => {
    const current = defaultSettings(testSettingsSchema);
    expect(() => applySettingsPatch(testSettingsSchema, current, {
      schemaVersion: 1,
      changes: [{ id: "credential", value: "plaintext-api-key" }],
    })).toThrow("secret reference");

    const result = applySettingsPatch(testSettingsSchema, current, {
      schemaVersion: 1,
      changes: [{ id: "credential", value: "secret-ref:abcdefghijklmnop" }],
    });
    expect(result.settings.credential).toBe("secret-ref:abcdefghijklmnop");
  });

  it("requires secret-bearing field names to use opaque references", () => {
    const unsafe = {
      ...testSettingsSchema,
      fields: testSettingsSchema.fields.map((field) => field.id === "credential"
        ? { ...field, secretReference: undefined }
        : field),
    };

    expect(() => parseSettingsSchema(unsafe)).toThrow("secret-bearing setting");
  });

  it("bounds schemas and patches before field validation", () => {
    expect(() => parseSettingsSchema({
      version: 1,
      fields: Array.from({ length: 129 }, (_, index) => ({
        id: `field-${index}`,
        label: `Field ${index}`,
        type: "string",
        required: false,
        restart: "none",
      })),
    })).toThrow("too many settings fields");
    expect(() => parseSettingsPatch({
      schemaVersion: 1,
      changes: Array.from({ length: 129 }, (_, index) => ({ id: `field-${index}`, value: "value" })),
    })).toThrow("too many settings changes");
    expect(() => parseSettingsPatch({
      schemaVersion: 1,
      changes: [{ id: "endpoint", value: "x".repeat(70_000) }],
    })).toThrow("too large");
  });

  it("accepts a typed multiline hint only for string settings", () => {
    expect(parseSettingsSchema({
      version: 1,
      fields: [{
        id: "instructions",
        label: "Instructions",
        type: "string",
        required: true,
        default: "",
        restart: "none",
        control: "textarea",
      }],
    }).fields[0]).toMatchObject({ control: "textarea" });
    expect(() => parseSettingsSchema({
      version: 1,
      fields: [{
        id: "limit",
        label: "Limit",
        type: "integer",
        required: true,
        default: 1,
        restart: "none",
        control: "textarea",
      }],
    })).toThrow("only to strings");
  });
});

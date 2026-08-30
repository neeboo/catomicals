import { readFile } from "node:fs/promises";
import Ajv2020, { type ValidateFunction } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { describe, expect, it } from "vitest";
import { agentSchemaFile } from "./agent-schema-contract.js";
import { CORDIS_PERMISSION_SCOPES } from "./cordis/permissions.js";

const schemaRoot = new URL("../../schemas/agent/", import.meta.url);

async function json(path: string): Promise<unknown> {
  return JSON.parse(await readFile(new URL(path, schemaRoot), "utf8")) as unknown;
}

async function validator(schemaFile: string, dependencies: readonly string[] = []): Promise<ValidateFunction> {
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false, strictTypes: false });
  addFormats(ajv);
  for (const dependency of dependencies) ajv.addSchema(await json(dependency));
  return ajv.compile(await json(schemaFile));
}

function sequenceIsStrictlyIncreasing(events: readonly Record<string, unknown>[]): boolean {
  return events.every((event, index) => index === 0
    || typeof event.sequence === "number"
      && typeof events[index - 1]?.sequence === "number"
      && event.sequence > events[index - 1]!.sequence);
}

function completedMessageReferencesMatch(event: Record<string, unknown>): boolean {
  if (event.event_type !== "message_completed") return true;
  const message = event.message;
  return Boolean(message && typeof message === "object"
    && (message as Record<string, unknown>).session_id === event.protocol_session_id
    && (message as Record<string, unknown>).message_id === event.message_id);
}

describe("agent protocol JSON schemas", () => {
  it("keeps the schema permission enum aligned with runtime scopes", async () => {
    const common = await json("common.schema.json") as {
      $defs: { permissionScope: { enum: string[] } };
    };

    expect(common.$defs.permissionScope.enum).toEqual(CORDIS_PERMISSION_SCOPES);
  });

  it("validates only the v2 executor session shape and rejects legacy fields", async () => {
    const fixture = await json("fixtures/executor-session.valid.json") as Record<string, unknown>;
    const invalidFixture = await json("fixtures/executor-session.invalid.json") as Record<string, unknown>;
    const validate = await validator(agentSchemaFile("executor-session", fixture), ["common.schema.json"]);

    expect(validate(fixture), validate.errors?.map((error) => error.message).join(", ")).toBe(true);
    expect(fixture).toMatchObject({
      schema_version: 2,
      session_id: "local-session-01",
      protocol_session_id: expect.stringMatching(/^[0-9a-f-]{36}$/),
      native_session_id: "thread_local_01",
    });

    expect(validate({ ...fixture, schema_version: 1 })).toBe(false);
    expect(validate({ ...fixture, provider_session_id: "thread_legacy" })).toBe(false);
    expect(invalidFixture).toMatchObject({ schema_version: 2 });
    expect(validate(invalidFixture)).toBe(false);

    const legacyTransport = structuredClone(fixture) as { mcp: { transport: string } };
    legacyTransport.mcp.transport = "http_oauth";
    expect(validate(legacyTransport)).toBe(false);

    const leakedCredential = structuredClone(fixture) as { mcp: Record<string, unknown> };
    leakedCredential.mcp.token = "must-not-be-public";
    expect(validate(leakedCredential)).toBe(false);
  });

  it("uses the canonical transport spelling for persisted tool events", async () => {
    const fixture = await json("fixtures/tool-event.valid.json") as Record<string, unknown>;
    const invalidFixture = await json("fixtures/tool-event.invalid.json") as Record<string, unknown>;
    const validate = await validator(agentSchemaFile("tool-event", fixture), ["common.schema.json"]);

    expect(validate(fixture)).toBe(true);
    expect(fixture).toMatchObject({ schema_version: 2 });
    expect(validate({ ...fixture, transport: "http-oauth" })).toBe(true);
    expect(validate({ ...fixture, schema_version: 1 })).toBe(false);
    expect(validate({ ...fixture, transport: "http_oauth" })).toBe(false);
    expect(invalidFixture).toMatchObject({ schema_version: 2 });
    expect(validate(invalidFixture)).toBe(false);
  });

  it("routes and validates historical v1 session and tool-event documents without mixing versions", async () => {
    const sessionV1 = await json("fixtures/executor-session.v1.valid.json") as Record<string, unknown>;
    const sessionV2 = await json("fixtures/executor-session.valid.json") as Record<string, unknown>;
    const toolEventV1 = await json("fixtures/tool-event.v1.valid.json") as Record<string, unknown>;
    const toolEventV2 = await json("fixtures/tool-event.valid.json") as Record<string, unknown>;

    expect(sessionV1).toMatchObject({
      schema_version: 1,
      provider_session_id: "thread_local_01",
      capabilities: expect.any(Array),
      workspace: expect.any(Object),
      created_at: expect.any(String),
      updated_at: expect.any(String),
      mcp: { transport: "http_oauth" },
    });
    expect(toolEventV1).toMatchObject({ schema_version: 1, transport: "http_oauth" });
    const sessionV1SchemaFile = agentSchemaFile("executor-session", sessionV1);
    const sessionV2SchemaFile = agentSchemaFile("executor-session", sessionV2);
    const toolEventV1SchemaFile = agentSchemaFile("tool-event", toolEventV1);
    const toolEventV2SchemaFile = agentSchemaFile("tool-event", toolEventV2);
    const validateSessionV1 = await validator(sessionV1SchemaFile, ["common.schema.json"]);
    const validateSessionV2 = await validator(sessionV2SchemaFile, ["common.schema.json"]);
    const validateToolEventV1 = await validator(toolEventV1SchemaFile, ["common.schema.json"]);
    const validateToolEventV2 = await validator(toolEventV2SchemaFile, ["common.schema.json"]);

    expect(sessionV1SchemaFile).toBe("executor-session.v1.schema.json");
    expect(sessionV2SchemaFile).toBe("executor-session.schema.json");
    expect(toolEventV1SchemaFile).toBe("tool-event.v1.schema.json");
    expect(toolEventV2SchemaFile).toBe("tool-event.schema.json");
    expect(validateSessionV1(sessionV1)).toBe(true);
    expect(validateSessionV2(sessionV2)).toBe(true);
    expect(validateToolEventV1(toolEventV1)).toBe(true);
    expect(validateToolEventV2(toolEventV2)).toBe(true);
    expect(validateSessionV2(sessionV1)).toBe(false);
    expect(validateSessionV1(sessionV2)).toBe(false);
    expect(validateToolEventV2(toolEventV1)).toBe(false);
    expect(validateToolEventV1(toolEventV2)).toBe(false);
    expect(() => agentSchemaFile("executor-session", { schema_version: 3 })).toThrow("unsupported agent schema version");
    expect(() => agentSchemaFile("tool-event", { schema_version: 3 })).toThrow("unsupported agent schema version");
  });

  it("accepts exactly the six read-or-intent Cordis tools and rejects authority expansion", async () => {
    const validate = await validator("plugin-config-tools.schema.json", ["common.schema.json"]);
    const valid = await json("fixtures/plugin-config-tools.valid.json") as unknown[];
    const invalid = await json("fixtures/plugin-config-tools.invalid.json") as unknown[];

    expect(valid).toHaveLength(6);
    expect(valid.every((call) => validate(call))).toBe(true);
    expect(invalid.every((call) => !validate(call))).toBe(true);
    const names = valid.map((call) => (call as { tool_name: string }).tool_name).sort();
    expect(names).toEqual([
      "create_plugin_settings_intent",
      "list_plugins",
      "read_plugin_health",
      "read_plugin_manifest",
      "read_plugin_settings_schema",
      "validate_plugin_settings_patch",
    ]);
    expect(names.some((name) => /(apply|approve|broadcast|confirm|install|secret|sign|uninstall|upgrade)/i.test(name)))
      .toBe(false);
    for (const call of valid) {
      const patch = (call as { arguments?: { patch?: { changes?: unknown } } }).arguments?.patch;
      if (!patch) continue;
      expect(patch.changes).not.toBeInstanceOf(Array);
      expect(Object.keys(patch.changes as object).length).toBeGreaterThan(0);
    }
  });

  it("validates all six stream event variants and enforces UUID and sequence fields", async () => {
    const validate = await validator("chat-stream-event.schema.json", [
      "common.schema.json",
      "review-reference.schema.json",
      "ui-block.schema.json",
      "chat-message.schema.json",
    ]);
    const fixture = await json("fixtures/chat-stream-event.valid.json") as {
      completed_stream: Record<string, unknown>[];
      failed_stream: Record<string, unknown>[];
    };

    expect([...fixture.completed_stream, ...fixture.failed_stream].every((event) => validate(event))).toBe(true);
    expect(sequenceIsStrictlyIncreasing(fixture.completed_stream)).toBe(true);
    expect(sequenceIsStrictlyIncreasing(fixture.failed_stream)).toBe(true);
    expect(fixture.completed_stream.every(completedMessageReferencesMatch)).toBe(true);
    expect(new Set([...fixture.completed_stream, ...fixture.failed_stream].map((event) => event.event_type)))
      .toEqual(new Set([
        "message_started",
        "text_delta",
        "tool_started",
        "tool_completed",
        "message_completed",
        "message_failed",
      ]));
  });

  it("rejects malformed stream events and non-monotonic fixture sequences", async () => {
    const validate = await validator("chat-stream-event.schema.json", [
      "common.schema.json",
      "review-reference.schema.json",
      "ui-block.schema.json",
      "chat-message.schema.json",
    ]);
    const fixture = await json("fixtures/chat-stream-event.invalid.json") as {
      invalid_events: Record<string, unknown>[];
      non_monotonic_stream: Record<string, unknown>[];
      reference_mismatch_events: Record<string, unknown>[];
    };

    expect(fixture.invalid_events.every((event) => !validate(event))).toBe(true);
    expect(fixture.non_monotonic_stream.every((event) => validate(event))).toBe(true);
    expect(sequenceIsStrictlyIncreasing(fixture.non_monotonic_stream)).toBe(false);
    expect(fixture.reference_mismatch_events.every((event) => validate(event))).toBe(true);
    expect(fixture.reference_mismatch_events.every(completedMessageReferencesMatch)).toBe(false);
  });
});

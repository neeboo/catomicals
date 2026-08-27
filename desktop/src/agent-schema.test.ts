import { readFile } from "node:fs/promises";
import Ajv2020, { type ValidateFunction } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { describe, expect, it } from "vitest";

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

describe("agent protocol JSON schemas", () => {
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
    };

    expect(fixture.invalid_events.every((event) => !validate(event))).toBe(true);
    expect(fixture.non_monotonic_stream.every((event) => validate(event))).toBe(true);
    expect(sequenceIsStrictlyIncreasing(fixture.non_monotonic_stream)).toBe(false);
  });
});

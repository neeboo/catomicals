import { createHash, randomUUID } from "node:crypto";
import type { ExecutorProviderId } from "./types.js";

const MAX_TEXT_PART_LENGTH = 65_536;

export interface ExecutorTextPart {
  readonly type: "text";
  readonly text: string;
}

export type ExecutorMessagePart = ExecutorTextPart;

export interface ExecutorFinalMessage {
  readonly schema_version: 1;
  readonly message_id: string;
  readonly session_id: string;
  readonly role: "assistant";
  readonly content_digest: string;
  readonly created_at: string;
  readonly parts: readonly ExecutorMessagePart[];
}

function objectRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function* jsonLines(output: string): Generator<Record<string, unknown>> {
  for (const line of output.split(/\r?\n/)) {
    if (line.trim() === "") continue;
    try {
      const record = objectRecord(JSON.parse(line) as unknown);
      if (record) yield record;
    } catch {
      // Structured providers may emit diagnostics. They are never display text.
    }
  }
}

function codexFinalText(output: string): string | undefined {
  let finalText: string | undefined;
  for (const record of jsonLines(output)) {
    if (record.type !== "item.completed") continue;
    const item = objectRecord(record.item);
    if (item?.type !== "agent_message") continue;
    finalText = typeof item.text === "string" && item.text.trim() !== "" ? item.text : undefined;
  }
  return finalText;
}

function claudeFinalText(output: string): string | undefined {
  let finalText: string | undefined;
  for (const record of jsonLines(output)) {
    if (record.type !== "assistant") continue;
    const message = objectRecord(record.message);
    if (message?.role !== "assistant" || !Array.isArray(message.content)) continue;
    const text = message.content.flatMap((value) => {
      const block = objectRecord(value);
      return block?.type === "text" && typeof block.text === "string" ? [block.text] : [];
    }).join("");
    finalText = text.trim() === "" ? undefined : text;
  }
  return finalText;
}

export function extractExecutorFinalText(provider: ExecutorProviderId, output: string): string | undefined {
  if (provider === "codex") return codexFinalText(output);
  if (provider === "claude-code") return claudeFinalText(output);
  return output.trim() === "" ? undefined : output;
}

function textParts(output: string): ExecutorMessagePart[] {
  const parts: ExecutorTextPart[] = [];
  let start = 0;
  let codePoints = 0;
  let offset = 0;
  for (const character of output) {
    if (codePoints === MAX_TEXT_PART_LENGTH) {
      parts.push({ type: "text", text: output.slice(start, offset) });
      start = offset;
      codePoints = 0;
    }
    offset += character.length;
    codePoints += 1;
  }
  parts.push({ type: "text", text: output.slice(start) });
  return parts;
}

export function createExecutorFinalMessage(protocolSessionId: string, output: string): ExecutorFinalMessage {
  if (output.trim() === "") throw new Error("executor message is missing final text");
  const parts = textParts(output);
  const contentDigest = createHash("sha256").update(JSON.stringify(parts), "utf8").digest("hex");
  return {
    schema_version: 1,
    message_id: randomUUID(),
    session_id: protocolSessionId,
    role: "assistant",
    content_digest: `sha256:${contentDigest}`,
    created_at: new Date().toISOString(),
    parts,
  };
}

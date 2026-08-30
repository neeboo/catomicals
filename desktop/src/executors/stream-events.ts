import { createHash, randomUUID } from "node:crypto";

const MAX_TEXT_PART_LENGTH = 65_536;

export interface ExecutorTextPart {
  readonly type: "text";
  readonly text: string;
}

export interface ExecutorErrorPart {
  readonly type: "error";
  readonly code: string;
  readonly message: string;
  readonly retriable: boolean;
}

export type ExecutorMessagePart = ExecutorTextPart | ExecutorErrorPart;

export interface ExecutorFinalMessage {
  readonly schema_version: 1;
  readonly message_id: string;
  readonly session_id: string;
  readonly role: "assistant";
  readonly content_digest: string;
  readonly created_at: string;
  readonly parts: readonly ExecutorMessagePart[];
}

function textParts(output: string): ExecutorMessagePart[] {
  if (output.length === 0) {
    return [{
      type: "error",
      code: "executor_empty_output",
      message: "The executor completed without output.",
      retriable: false,
    }];
  }

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

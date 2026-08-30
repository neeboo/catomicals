export type VersionedAgentDocumentKind = "executor-session" | "tool-event";

const AGENT_SCHEMA_FILES = Object.freeze({
  "executor-session": Object.freeze({
    1: "executor-session.v1.schema.json",
    2: "executor-session.schema.json",
  }),
  "tool-event": Object.freeze({
    1: "tool-event.v1.schema.json",
    2: "tool-event.schema.json",
  }),
} as const);

export type AgentSchemaFile =
  (typeof AGENT_SCHEMA_FILES)[VersionedAgentDocumentKind][1 | 2];

export function agentSchemaFile(kind: VersionedAgentDocumentKind, document: unknown): AgentSchemaFile {
  if (document && typeof document === "object" && !Array.isArray(document)) {
    const version = (document as { schema_version?: unknown }).schema_version;
    if (version === 1 || version === 2) return AGENT_SCHEMA_FILES[kind][version];
  }
  throw new Error("unsupported agent schema version");
}

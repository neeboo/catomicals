/**
 * On-disk format helpers for the Catomicals JSONL session backend: path
 * sanitization, the per-project/session directory layout, header-line
 * (de)serialization, and the truncation-repair offset computation.
 *
 * Ported from DeepSeek Harness `packages/session/session-persistence-jsonl/src/format.ts`
 * (MIT) — path escaping, layout, scanner, and torn-tail semantics are faithful;
 * Zstandard framing and chunk-run packing are intentionally omitted (plaintext
 * JSONL, one event per line).
 *
 * @module catomicals-desktop/sessions/format
 */

import { join } from "node:path";
import { SESSION_FORMAT_VERSION, type SessionEvent, type SessionHeader, type SessionId } from "./types.js";

/** Physical encoding selected for JSONL session artifacts. */
export type JsonlCompression = "none" | "zstd";

/** The artifact suffix for one physical encoding. */
export function logSuffix(compression: JsonlCompression): ".jsonl" | ".jsonl.zstd" {
  return compression === "zstd" ? ".jsonl.zstd" : ".jsonl";
}

/** The first JSONL record of a session artifact: the immutable header. */
export interface HeaderLine {
  type: "session";
  version: number;
  id: SessionId;
  createdAt: number;
  cwd?: string;
  parentSession?: SessionId;
  seedLength?: number;
  provider?: string;
  model?: string;
  executor?: string;
  origin?: "subagent";
  delegationDepth: number;
  agentPreset?: string;
}

/** Build the header line object from a {@link SessionHeader}. */
export function toHeaderLine(header: SessionHeader): HeaderLine {
  return {
    type: "session",
    version: header.version,
    id: header.id,
    createdAt: header.createdAt,
    ...header.cwd !== undefined ? { cwd: header.cwd } : {},
    ...header.parentSession !== undefined ? { parentSession: header.parentSession } : {},
    ...header.seedLength !== undefined ? { seedLength: header.seedLength } : {},
    ...header.provider !== undefined ? { provider: header.provider } : {},
    ...header.model !== undefined ? { model: header.model } : {},
    ...header.executor !== undefined ? { executor: header.executor } : {},
    ...header.origin !== undefined ? { origin: header.origin } : {},
    delegationDepth: header.delegationDepth ?? 0,
    ...header.agentPreset !== undefined ? { agentPreset: header.agentPreset } : {},
  };
}

/** Parse a header line back into a {@link SessionHeader}. */
export function fromHeaderLine(line: HeaderLine): SessionHeader {
  return {
    version: line.version,
    id: line.id,
    createdAt: line.createdAt,
    ...line.cwd !== undefined ? { cwd: line.cwd } : {},
    ...line.parentSession !== undefined ? { parentSession: line.parentSession } : {},
    ...line.seedLength !== undefined ? { seedLength: line.seedLength } : {},
    ...line.provider !== undefined ? { provider: line.provider } : {},
    ...line.model !== undefined ? { model: line.model } : {},
    ...line.executor !== undefined ? { executor: line.executor } : {},
    ...line.origin !== undefined ? { origin: line.origin } : {},
    ...line.delegationDepth > 0 ? { delegationDepth: line.delegationDepth } : {},
    ...line.agentPreset !== undefined ? { agentPreset: line.agentPreset } : {},
  };
}

/** Type guard: a parsed first line is a well-formed session header. */
export function isHeaderLine(value: unknown): value is HeaderLine {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  if (record.type !== "session") return false;
  if (typeof record.version !== "number") return false;
  if (typeof record.id !== "string" || record.id.length === 0 || record.id.length > 80) return false;
  if (typeof record.createdAt !== "number" || !Number.isSafeInteger(record.createdAt) || record.createdAt < 0) {
    return false;
  }
  if (typeof record.delegationDepth !== "number"
    || !Number.isSafeInteger(record.delegationDepth) || record.delegationDepth < 0) {
    return false;
  }
  if (record.cwd !== undefined && typeof record.cwd !== "string") return false;
  if (record.parentSession !== undefined && typeof record.parentSession !== "string") return false;
  if (record.seedLength !== undefined && (typeof record.seedLength !== "number" || record.seedLength < 0)) return false;
  if (record.provider !== undefined && typeof record.provider !== "string") return false;
  if (record.model !== undefined && typeof record.model !== "string") return false;
  if (record.executor !== undefined && typeof record.executor !== "string") return false;
  if (record.origin !== undefined && record.origin !== "subagent") return false;
  if (record.agentPreset !== undefined && typeof record.agentPreset !== "string") return false;
  return true;
}

/**
 * Encode an arbitrary string as a single safe path segment, injectively over
 * ALL JS (UTF-16) strings — including lone surrogates. Safe code units remain
 * literal; every other unit, including `~`, becomes `~XXXX`.
 */
export function encodeSegment(raw: string): string {
  if (raw.length === 0) throw new Error("cannot encode an empty path segment");
  if (raw === ".") return "~002E";
  if (raw === "..") return "~002E~002E";
  let out = "";
  for (let i = 0; i < raw.length; i++) {
    const code = raw.charCodeAt(i);
    const ch = String.fromCharCode(code);
    if (ch !== "~" && /^[A-Za-z0-9._-]$/.test(ch)) {
      out += ch;
    } else {
      out += "~" + code.toString(16).toUpperCase().padStart(4, "0");
    }
  }
  return out;
}

/** Build the readable directory key for a project path. */
export function projectKey(cwd: string): string {
  if (cwd.length === 0) throw new Error("cannot encode an empty project path");
  let readable = "";
  let separatorRun = false;
  for (let i = 0; i < cwd.length; i++) {
    const code = cwd.charCodeAt(i);
    const ch = String.fromCharCode(code);
    if (ch === "/" || ch === "\\" || ch === ":") {
      if (!separatorRun) readable += "-";
      separatorRun = true;
    } else if (ch !== "~" && /^[A-Za-z0-9._-]$/.test(ch)) {
      readable += ch;
      separatorRun = false;
    } else {
      readable += "~" + code.toString(16).toUpperCase().padStart(4, "0");
      separatorRun = false;
    }
  }
  const slug = readable.replace(/^-+/, "") || "root";
  return `--${slug.slice(0, 251)}--`;
}

/** The configured root's human-navigable project directory. */
export function projectDir(root: string, cwd: string | undefined): string {
  if (cwd === undefined) return join(root, "_no-cwd");
  return join(root, projectKey(cwd));
}

/** The directory owned by one session. */
export function sessionDir(root: string, cwd: string | undefined, id: SessionId): string {
  return join(projectDir(root, cwd), encodeSegment(id));
}

/** The append-only event-log file path for a session. */
export function logPath(
  root: string,
  cwd: string | undefined,
  id: SessionId,
  compression: JsonlCompression,
): string {
  return join(sessionDir(root, cwd, id), `session${logSuffix(compression)}`);
}

/** Serialize an event batch as JSONL lines (no trailing newline). */
export function eventLines(events: readonly SessionEvent[]): string {
  return events.map(event => JSON.stringify(event)).join("\n");
}

/** The folder that holds recoverable-deleted session artifacts. */
export function trashDir(root: string): string {
  return join(root, ".trash");
}

interface SessionLogScan {
  meta: SessionHeader;
  events: SessionEvent[];
  committedBytes: number;
}

/** Refuse a header carrying a format version this build does not read. */
function refuseForeignFormatVersion(parsed: unknown): void {
  if (typeof parsed !== "object" || parsed === null) return;
  const { version, id } = parsed as { version?: unknown; id?: unknown };
  if (typeof version !== "number" || version === SESSION_FORMAT_VERSION) return;
  const label = typeof id === "string" ? id : String(id);
  throw new Error(
    version > SESSION_FORMAT_VERSION
      ? `session "${label}" uses log format v${version}, but this build reads only v${SESSION_FORMAT_VERSION}: upgrade the harness to open it`
      : `session "${label}" uses log format v${version}, older than the supported v${SESSION_FORMAT_VERSION}`,
  );
}

function parseHeaderRecord(record: Buffer): SessionHeader {
  if (record.length === 0 || record.at(-1) !== 0x0A || record.indexOf(0x0A) !== record.length - 1) {
    throw new Error("empty or header-less session log");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(record.subarray(0, -1).toString("utf8"));
  } catch {
    throw new Error("corrupt session log: header line is not valid JSON");
  }
  refuseForeignFormatVersion(parsed);
  if (!isHeaderLine(parsed)) {
    throw new Error("corrupt session log: first line is not a session header");
  }
  return fromHeaderLine(parsed);
}

/**
 * Incrementally scan complete JSONL event records after an independently
 * supplied header record. Newline search and byte offsets stay on raw buffers;
 * only complete records are decoded to UTF-8.
 */
export class SessionLogScanner {
  private readonly meta: SessionHeader;
  private readonly events: SessionEvent[] = [];
  private fragments: Buffer[] = [];
  private fragmentBytes = 0;
  private inputBytes: number;
  private committedBytes: number;
  private eventLine = 0;
  private issue: Error | undefined;

  /** Create an event scanner from exactly one newline-terminated header record. */
  constructor(headerRecord: Buffer) {
    this.meta = parseHeaderRecord(headerRecord);
    this.inputBytes = headerRecord.length;
    this.committedBytes = headerRecord.length;
  }

  /** Consume the next raw plaintext chunk, retaining only an incomplete final record. */
  write(chunk: Buffer): void {
    const chunkStart = this.inputBytes;
    this.inputBytes += chunk.length;
    let lineStart = 0;
    for (
      let newline = chunk.indexOf(0x0A);
      newline !== -1;
      newline = chunk.indexOf(0x0A, lineStart)
    ) {
      const fragment = chunk.subarray(lineStart, newline);
      let line = fragment;
      if (this.fragments.length > 0) {
        if (fragment.length > 0) this.fragments.push(fragment);
        line = Buffer.concat(this.fragments, this.fragmentBytes + fragment.length);
        this.fragments = [];
        this.fragmentBytes = 0;
      }
      this.consumeEventLine(line, chunkStart + newline + 1);
      lineStart = newline + 1;
    }
    if (lineStart < chunk.length) {
      const fragment = Buffer.from(chunk.subarray(lineStart));
      this.fragments.push(fragment);
      this.fragmentBytes += fragment.length;
    }
  }

  /** Snapshot progress before appending a recoverable torn-frame prefix. */
  checkpoint(): { inputBytes: number; committedBytes: number; eventCount: number } {
    return {
      inputBytes: this.inputBytes,
      committedBytes: this.committedBytes,
      eventCount: this.events.length,
    };
  }

  /** Finish scanning, ignoring a final record without a newline as a torn tail. */
  finish(): SessionLogScan {
    return { meta: this.meta, events: this.events, committedBytes: this.committedBytes };
  }

  /** Decode one complete event row and update the contiguous prefix. */
  private consumeEventLine(line: Buffer, endByte: number): void {
    this.eventLine += 1;
    let parsed: unknown;
    try {
      parsed = JSON.parse(line.toString("utf8"));
    } catch {
      this.issue ??= new Error(
        `corrupt session log: unparsable committed event at line ${this.eventLine}`,
      );
      return;
    }
    const event = parsed as SessionEvent;
    if (this.issue !== undefined) {
      if (event.type === "turn/end") throw this.issue;
      return;
    }
    if (typeof event !== "object" || event === null || typeof event.type !== "string") {
      this.issue ??= new Error(
        `corrupt session log: invalid event record at line ${this.eventLine}`,
      );
      if ((parsed as { type?: unknown }).type === "turn/end") throw this.issue;
      return;
    }
    if (event.seq !== this.events.length) {
      const expected = this.events.length;
      this.issue = new Error(
        `corrupt session log: seq gap in committed region at line ${this.eventLine} `
        + `(expected ${expected}, got ${String(event.seq)})`,
      );
      if (event.type === "turn/end") throw this.issue;
      return;
    }
    this.events.push(event);
    this.committedBytes = endByte;
  }
}

/**
 * Parse a complete or torn JSONL buffer into its preserved event prefix.
 * @returns the header, preserved event prefix, and byte offset safe to append at.
 */
export function scanLog(buffer: Buffer): SessionLogScan {
  const headerEnd = buffer.indexOf(0x0A);
  if (headerEnd === -1) throw new Error("empty or header-less session log");
  const scanner = new SessionLogScanner(buffer.subarray(0, headerEnd + 1));
  scanner.write(buffer.subarray(headerEnd + 1));
  return scanner.finish();
}

/**
 * Parse just the header line of a log into a {@link SessionHeader}, or
 * `undefined` if it is missing/not a header. Used by `list()` so a session
 * picker scales with session count, not total conversation size.
 */
export function parseHeaderMeta(firstLine: string): SessionHeader | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(firstLine);
  } catch {
    return undefined;
  }
  if (!isHeaderLine(parsed)) return undefined;
  return fromHeaderLine(parsed);
}

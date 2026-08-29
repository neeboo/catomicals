import { describe, expect, it } from "vitest";
import {
  encodeSegment,
  eventLines,
  fromHeaderLine,
  isHeaderLine,
  parseHeaderMeta,
  projectKey,
  scanLog,
  SessionLogScanner,
  toHeaderLine,
} from "./format";
import { SESSION_FORMAT_VERSION, SessionId, type SessionEvent, type SessionHeader } from "./types";

function header(overrides: Partial<SessionHeader> = {}): SessionHeader {
  return {
    version: SESSION_FORMAT_VERSION,
    id: SessionId("session-1"),
    createdAt: 1_700_000_000_000,
    ...overrides,
  };
}

function event(type: SessionEvent["type"], seq: number, data: Record<string, unknown>, time = 1000): SessionEvent {
  return { type, seq, time, data } as SessionEvent;
}

describe("encodeSegment", () => {
  it("keeps safe code units literal", () => {
    expect(encodeSegment("abc-123_XYZ.9")).toBe("abc-123_XYZ.9");
  });

  it("escapes separators and tilde injectively; dot chars inside a segment stay literal", () => {
    // `/` is escaped so `../etc` can never traverse, even though `.` itself is safe.
    expect(encodeSegment("../etc/passwd")).toBe("..~002Fetc~002Fpasswd");
    expect(encodeSegment("a~b")).toBe("a~007Eb");
  });

  it("special-cases dot segments to prevent traversal", () => {
    expect(encodeSegment(".")).toBe("~002E");
    expect(encodeSegment("..")).toBe("~002E~002E");
  });

  it("rejects empty input", () => {
    expect(() => encodeSegment("")).toThrow("empty");
  });

  it("preserves lone surrogates losslessly", () => {
    const raw = "a\uD800b";
    const encoded = encodeSegment(raw);
    expect(encoded).not.toBe(raw);
    expect(encoded).toMatch(/^a~D800b$/);
  });
});

describe("projectKey", () => {
  it("turns separators into dashes and bounds the slug", () => {
    const key = projectKey("/Users/ghostcorn/dev/catomicals");
    expect(key.startsWith("--Users-ghostcorn-dev-catomicals")).toBe(true);
    expect(key.endsWith("--")).toBe(true);
    expect(key.length).toBeLessThanOrEqual(255);
  });

  it("uses root for an all-separator path", () => {
    expect(projectKey("///")).toBe("--root--");
  });
});

describe("header line (de)serialization", () => {
  it("round-trips all header fields", () => {
    const h: SessionHeader = {
      version: SESSION_FORMAT_VERSION,
      id: SessionId("abc"),
      createdAt: 123,
      cwd: "/tmp/proj",
      parentSession: SessionId("parent-1"),
      seedLength: 2,
      provider: "codex",
      model: "gpt-5.3",
      executor: "codex",
      origin: "subagent",
      delegationDepth: 1,
      agentPreset: "wallet",
    };
    const line = toHeaderLine(h);
    expect(isHeaderLine(line)).toBe(true);
    expect(fromHeaderLine(line)).toEqual(h);
  });

  it("omits absent optional fields (never null)", () => {
    const line = toHeaderLine(header());
    expect("cwd" in line).toBe(false);
    expect("provider" in line).toBe(false);
    expect(line.delegationDepth).toBe(0);
  });

  it("rejects malformed header candidates", () => {
    expect(isHeaderLine(null)).toBe(false);
    expect(isHeaderLine({ type: "session", version: 1, id: "x", createdAt: -1, delegationDepth: 0 })).toBe(false);
    expect(isHeaderLine({ type: "event", version: 1, id: "x", createdAt: 1, delegationDepth: 0 })).toBe(false);
  });
});

describe("SessionLogScanner / scanLog", () => {
  function logBuffer(headerLine: string, events: SessionEvent[]): Buffer {
    return Buffer.from([headerLine, ...events.map(e => JSON.stringify(e))].join("\n") + "\n", "utf8");
  }

  it("scans a complete log and reports the committed byte offset", () => {
    const events = [event("user/message", 0, { content: "hi" }), event("assistant/message", 1, { content: "hello" })];
    const buffer = logBuffer(JSON.stringify(toHeaderLine(header())), events);
    const scan = scanLog(buffer);
    expect(scan.meta.id).toBe("session-1");
    expect(scan.events).toEqual(events);
    expect(scan.committedBytes).toBe(buffer.byteLength);
  });

  it("treats a final record without a newline as a torn tail", () => {
    const events = [event("user/message", 0, { content: "hi" })];
    const buffer = logBuffer(JSON.stringify(toHeaderLine(header())), events);
    const torn = Buffer.concat([buffer, Buffer.from(JSON.stringify(event("assistant/message", 1, { content: "partial" })))]);
    const scan = scanLog(torn);
    expect(scan.events).toEqual(events);
    expect(scan.committedBytes).toBe(buffer.byteLength);
    expect(scan.committedBytes).toBeLessThan(torn.byteLength);
  });

  it("keeps the contiguous prefix across a mid-line fragment split", () => {
    const events = [event("user/message", 0, { content: "hi" }), event("assistant/message", 1, { content: "yo" })];
    const buffer = logBuffer(JSON.stringify(toHeaderLine(header())), events);
    const split = Math.floor(buffer.byteLength / 2);
    const scanner = new SessionLogScanner(buffer.subarray(0, buffer.indexOf(0x0a) + 1));
    scanner.write(buffer.subarray(buffer.indexOf(0x0a) + 1, split));
    scanner.write(buffer.subarray(split));
    const scan = scanner.finish();
    expect(scan.events).toEqual(events);
  });

  it("throws on a header-less or unparsable header", () => {
    expect(() => scanLog(Buffer.from("not json\n", "utf8"))).toThrow();
    expect(() => scanLog(Buffer.from("no newline", "utf8"))).toThrow("header-less");
  });

  it("refuses a foreign format version before structural checks", () => {
    const future = Buffer.from(
      `${JSON.stringify({ type: "session", version: SESSION_FORMAT_VERSION + 1, id: "x", createdAt: 1, delegationDepth: 0 })}\n`,
      "utf8",
    );
    expect(() => scanLog(future)).toThrow(/upgrade/);
  });
});

describe("parseHeaderMeta", () => {
  it("parses a valid first line without decoding the log", () => {
    const meta = parseHeaderMeta(JSON.stringify(toHeaderLine(header({ provider: "deepseek" }))));
    expect(meta?.provider).toBe("deepseek");
  });

  it("returns undefined for non-header or invalid JSON", () => {
    expect(parseHeaderMeta("not json")).toBeUndefined();
    expect(parseHeaderMeta(JSON.stringify({ type: "event", seq: 0 }))).toBeUndefined();
  });
});

describe("eventLines", () => {
  it("serializes one event per line with no trailing newline", () => {
    const events = [event("user/message", 0, { content: "a" }), event("turn/end", 1, { turn: 0, reason: { kind: "completed" } })];
    expect(eventLines(events)).toBe(
      `${JSON.stringify(events[0])}\n${JSON.stringify(events[1])}`,
    );
  });
});

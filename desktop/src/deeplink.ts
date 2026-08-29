/**
 * Catomicals deep-link model: `catomicals://session/<id>` parsing and the
 * navigation-event contract. The parser is a pure function (separately
 * testable); the Electron integration is a small service that bridges
 * `open-url` (macOS) and `second-instance` argv (Windows/Linux) into the
 * shared {@link CatomicalsNavigationEvent} stream. Main-process wiring is a
 * one-liner (see the summary for the integration point); nothing here touches
 * the visual shell.
 *
 * @module catomicals-desktop/deeplink
 */

import { SESSION_ID_PATTERN, type CatomicalsNavigationEvent, type SessionId } from "./sessions/types.js";

/** Supported deep-link scheme. */
export const CATOMICALS_SCHEME = "catomicals";

/** A parsed deep-link target. */
export type CatomicalsDeeplinkTarget =
  | { kind: "session"; sessionId: SessionId }
  | { kind: "sessions" };

/** Result of parsing one URL. */
export type CatomicalsDeeplinkParse =
  | { ok: true; target: CatomicalsDeeplinkTarget; url: string }
  | { ok: false; reason: "unsupported-scheme" | "malformed" | "unknown-target"; url: string };

/**
 * Parse a Catomicals deep-link URL into a navigation target.
 *
 * Accepted forms (scheme case-insensitive, trailing slash tolerated):
 * - `catomicals://session/<id>`          → open a session
 * - `catomicals://sessions`              → open the session list
 * Query strings are ignored (reserved for future targets).
 *
 * @param raw - the URL to parse (a full URL or a bare `catomicals://` path).
 * @returns a discriminated parse result; malformed input never throws.
 */
export function parseCatomicalsDeeplink(raw: string): CatomicalsDeeplinkParse {
  const url = typeof raw === "string" ? raw.trim() : "";
  if (url.length === 0) return { ok: false, reason: "malformed", url: raw };
  const withoutScheme = stripScheme(url);
  if (withoutScheme === undefined) return { ok: false, reason: "unsupported-scheme", url: raw };
  const path = withoutScheme.replace(/^\/+/, "").replace(/\/+$/, "");
  if (path.length === 0) return { ok: false, reason: "unknown-target", url: raw };
  const [first, second] = path.split("/", 2);
  if (first === "sessions" && second === undefined) {
    return { ok: true, target: { kind: "sessions" }, url: raw };
  }
  if (first === "session") {
    if (second === undefined || second.length === 0) {
      return { ok: false, reason: "malformed", url: raw };
    }
    const sessionId = second.split("?")[0] as string;
    if (!SESSION_ID_PATTERN.test(sessionId)) {
      return { ok: false, reason: "malformed", url: raw };
    }
    return { ok: true, target: { kind: "session", sessionId: sessionId as SessionId }, url: raw };
  }
  return { ok: false, reason: "unknown-target", url: raw };
}

/** Strip the scheme and `//` authority from a URL, returning the path portion. */
function stripScheme(raw: string): string | undefined {
  const colon = raw.indexOf(":");
  if (colon === -1) return undefined;
  const scheme = raw.slice(0, colon).toLowerCase();
  if (scheme !== CATOMICALS_SCHEME) return undefined;
  const rest = raw.slice(colon + 1);
  // `catomicals://session/x` → rest = `//session/x`; `catomicals:session/x` also accepted.
  return rest.replace(/^\/\//, "");
}

/** Map a parsed target to a navigation event. */
export function navigationEventFromTarget(
  target: CatomicalsDeeplinkTarget,
  source: CatomicalsNavigationEvent["source"],
  at: number = Date.now(),
): CatomicalsNavigationEvent {
  return {
    kind: target.kind === "session" ? "session-open" : "session-list",
    ...target.kind === "session" ? { sessionId: target.sessionId } : {},
    source,
    at,
  };
}

/** Extract the first Catomicals deep-link URL from a process argv list. */
export function findDeeplinkInArgv(argv: readonly string[]): CatomicalsDeeplinkParse | undefined {
  for (const argument of argv) {
    if (typeof argument !== "string") continue;
    const parsed = parseCatomicalsDeeplink(argument);
    if (parsed.ok) return parsed;
  }
  return undefined;
}

/** Dependencies for the Electron deep-link service (kept minimal for testability). */
export interface CatomicalsDeeplinkServiceDeps {
  /** Subscribe to `open-url` (macOS). Receives the raw URL. */
  onOpenUrl(listener: (url: string) => void): void;
  removeOpenUrlListener(listener: (url: string) => void): void;
  /** Subscribe to `second-instance` (Windows/Linux). Receives the full argv. */
  onSecondInstance(listener: (argv: readonly string[]) => void): void;
  removeSecondInstanceListener(listener: (argv: readonly string[]) => void): void;
  /** Register the app as the default handler for the scheme. */
  registerProtocolClient(): boolean;
  /** The current process argv (used to honor a launch-time deep link). */
  currentArgv: readonly string[];
}

/**
 * Wire Electron protocol-client events into the navigation stream. Idempotent
 * per service instance; returns a dispose function.
 */
export function createCatomicalsDeeplinkService(
  deps: CatomicalsDeeplinkServiceDeps,
  onNavigate: (event: CatomicalsNavigationEvent) => void,
): { dispose(): void; registered: boolean } {
  deps.registerProtocolClient();
  const handleOpenUrl = (url: string): void => {
    const parsed = parseCatomicalsDeeplink(url);
    if (parsed.ok) onNavigate(navigationEventFromTarget(parsed.target, "deeplink"));
  };
  const handleSecondInstance = (argv: readonly string[]): void => {
    const parsed = findDeeplinkInArgv(argv);
    if (parsed !== undefined && parsed.ok) {
      onNavigate(navigationEventFromTarget(parsed.target, "deeplink"));
    }
  };
  deps.onOpenUrl(handleOpenUrl);
  deps.onSecondInstance(handleSecondInstance);
  const launch = findDeeplinkInArgv(deps.currentArgv);
  if (launch !== undefined && launch.ok) {
    // A launch-time deep link is honored on the next tick so the window can
    // exist before navigation is dispatched.
    queueMicrotask(() => onNavigate(navigationEventFromTarget(launch.target, "deeplink")));
  }
  return {
    registered: true,
    dispose(): void {
      deps.removeOpenUrlListener(handleOpenUrl);
      deps.removeSecondInstanceListener(handleSecondInstance);
    },
  };
}

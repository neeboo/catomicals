/**
 * JSONL durable session-persistence backend: header + contiguous events in one
 * append-only file per session, with atomic first-write, fsync'd appends with
 * rollback, crash-tail truncation repair, and header-only listing.
 *
 * Ported from DeepSeek Harness
 * `packages/session/session-persistence-jsonl/src/index.ts` (MIT): atomic
 * materialization (temp-write + fsync + link publish), append rollback,
 * revision-stable reads, torn-tail repair, and the project/session directory
 * layout are faithful. Zstandard framing and the Cordis plugin shell are
 * omitted — Catomicals writes plaintext JSONL.
 *
 * @module catomicals-desktop/sessions/jsonl-store
 */

import { open, mkdir, readFile, readdir, realpath, link, rm, stat, truncate } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { randomBytes } from "node:crypto";
import {
  encodeSegment,
  eventLines,
  logPath,
  logSuffix,
  parseHeaderMeta,
  projectDir,
  scanLog,
  sessionDir,
  toHeaderLine,
  trashDir,
} from "./format.js";
import {
  type SessionEvent,
  type SessionHeader,
  type SessionId,
  type SessionInspection,
  type SessionPersistenceSnapshot,
  type SessionSummary,
} from "./types.js";

/** Logical artifact name regardless of physical encoding suffix. */
export const SESSION_ARTIFACT_NAME = "session.jsonl";

/** Bytes of log tail folded into a {@link SessionSummary}. */
const SUMMARY_TAIL_BYTES = 64 * 1024;

/** Supported physical encoding; only `none` is implemented (zstd is reserved). */
export type StoreCompression = "none";

/** Identity of a stored prefix, source-qualified. */
export type StoredRevision = string;

/** A stored prefix plus the byte offset to truncate a torn tail at. */
export interface StoredPrefix {
  readonly meta: SessionHeader;
  readonly events: SessionEvent[];
  /** Revision observed for exactly this detached prefix. */
  readonly revision: StoredRevision;
  /** Present iff a torn tail exists; the log is safe to truncate at this offset. */
  readonly tornMarker?: { readonly truncateTo: number; readonly recoveredEvents: SessionEvent[] };
}

/** Whether a filesystem error means absence; every non-ENOENT failure must surface. */
function isENOENT(error: unknown): boolean {
  return (error as NodeJS.ErrnoException | null)?.code === "ENOENT";
}

function fileRevision(identity: { dev: bigint; ino: bigint; size: bigint; mtimeNs: bigint; ctimeNs: bigint }): string {
  return [identity.dev, identity.ino, identity.size, identity.mtimeNs, identity.ctimeNs].join(":");
}

/**
 * The JSONL persistence backend. Owns only file-bytes mechanics; the
 * coordinator supplies orchestration (create/append/load/inspect/repair).
 */
export class JsonlSessionStore {
  /** Backend label for diagnostics. */
  readonly name = "session-persistence-jsonl";
  private readonly root: string;
  private readonly compression: StoreCompression = "none";

  /** @param root - resolved once so later cwd changes cannot split one backend across roots. */
  constructor(root: string) {
    this.root = resolve(root);
  }

  /** Resolve the absolute target path without touching the filesystem. */
  locate(meta: SessionHeader): string {
    return logPath(this.root, meta.cwd, meta.id, this.compression);
  }

  /** The root directory (for diagnostics and trash layout). */
  get rootDir(): string {
    return this.root;
  }

  /** Read a stored prefix by id across all project directories when cwd is unknown. */
  async loadStored(id: SessionId, signal?: AbortSignal): Promise<StoredPrefix | undefined> {
    signal?.throwIfAborted();
    const path = await this.findLog(id, signal);
    if (path === undefined) return undefined;
    return this.readPrefix(path, id, signal);
  }

  /** Read one log's stat-derived revision without loading its event bytes. */
  async readStoredRevision(id: SessionId, signal?: AbortSignal): Promise<StoredRevision | undefined> {
    signal?.throwIfAborted();
    const path = await this.findLog(id, signal);
    if (path === undefined) return undefined;
    try {
      const identity = await stat(path, { bigint: true });
      signal?.throwIfAborted();
      return fileRevision(identity);
    } catch (error: unknown) {
      signal?.throwIfAborted();
      if (isENOENT(error)) return undefined;
      throw error;
    }
  }

  /** Read a stored session's raw JSONL text verbatim (header + committed lines). */
  async readRaw(id: SessionId, signal?: AbortSignal): Promise<{ meta: SessionHeader; filename: string; content: string } | undefined> {
    signal?.throwIfAborted();
    const path = await this.findLog(id, signal);
    if (path === undefined) return undefined;
    const { buffer } = await this.readStableFile(path, signal);
    const content = buffer.toString("utf8");
    const meta = parseHeaderMeta(content.split("\n", 1)[0] as string);
    if (meta === undefined || meta.id !== id) {
      throw new Error(`corrupt session log: invalid header line in "${path}"`);
    }
    return { meta, filename: SESSION_ARTIFACT_NAME, content };
  }

  /** Read a file's bytes under a revision-stable loop (writer appends between stat/read retried). */
  private async readStableFile(
    path: string,
    signal?: AbortSignal,
  ): Promise<{ buffer: Buffer; revision: StoredRevision }> {
    for (;;) {
      signal?.throwIfAborted();
      const before = fileRevision(await stat(path, { bigint: true }));
      const buffer = await readFile(path, { signal });
      signal?.throwIfAborted();
      const after = fileRevision(await stat(path, { bigint: true }));
      if (before === after) return { buffer, revision: after };
    }
  }

  /** Read a stored prefix and convert torn-tail state to a truncation marker. */
  private async readPrefix(path: string, expectedId?: SessionId, signal?: AbortSignal): Promise<StoredPrefix> {
    const { buffer, revision } = await this.readStableFile(path, signal);
    signal?.throwIfAborted();
    const { meta, events, committedBytes } = scanLog(buffer);
    signal?.throwIfAborted();
    await this.assertStoredIdentity(path, meta, expectedId, signal);
    signal?.throwIfAborted();
    return {
      meta,
      events,
      revision,
      ...committedBytes < buffer.byteLength
        ? { tornMarker: { truncateTo: committedBytes, recoveredEvents: [] } }
        : {},
    };
  }

  /** Durably append a batch, lazily materializing the file when not yet present. */
  async appendBatch(meta: SessionHeader, events: readonly SessionEvent[], isMaterialized: boolean): Promise<void> {
    if (isMaterialized) {
      await this.appendLines(meta, events);
    } else {
      await this.materialize(meta, events);
    }
  }

  /** Make a crash repair durable: truncate the torn tail, then append closers. */
  async commitRepair(
    meta: SessionHeader,
    tornMarker: StoredPrefix["tornMarker"],
    closers: readonly SessionEvent[],
  ): Promise<void> {
    if (tornMarker !== undefined) await this.repair(meta, tornMarker.truncateTo);
    const repairedEvents = [...(tornMarker?.recoveredEvents ?? []), ...closers];
    if (repairedEvents.length > 0) await this.appendLines(meta, repairedEvents);
  }

  /** List all valid stored sessions' metadata (header line only — no full-log parse). */
  async list(signal?: AbortSignal): Promise<SessionHeader[]> {
    return (await this.listArtifacts(signal)).map(artifact => artifact.header);
  }

  /** List metadata plus a stat-derived revision for each append-only log. */
  async listSnapshots(signal?: AbortSignal): Promise<SessionPersistenceSnapshot[]> {
    const snapshots: SessionPersistenceSnapshot[] = [];
    for (const artifact of await this.listArtifacts(signal)) {
      signal?.throwIfAborted();
      try {
        const identity = await stat(artifact.path, { bigint: true });
        signal?.throwIfAborted();
        snapshots.push({ header: artifact.header, revision: fileRevision(identity) });
      } catch (error: unknown) {
        signal?.throwIfAborted();
        if (!isENOENT(error)) throw error;
      }
    }
    return snapshots;
  }

  /** List summaries: header plus tail-folded mutable metadata (title, archive, mtime). */
  async listSummaries(signal?: AbortSignal): Promise<SessionSummary[]> {
    const summaries: SessionSummary[] = [];
    for (const artifact of await this.listArtifacts(signal)) {
      signal?.throwIfAborted();
      summaries.push(await this.summarize(artifact.path, artifact.header, signal));
    }
    return summaries;
  }

  /** Fold a header + bounded log tail into a lightweight {@link SessionSummary}. */
  async summarize(path: string, header: SessionHeader, signal?: AbortSignal): Promise<SessionSummary> {
    signal?.throwIfAborted();
    const tail = await this.readTail(path, signal);
    let title: string | undefined;
    let archived = false;
    let lastTime = header.createdAt;
    let lastSeq = -1;
    let lastError: { message: string; code: string } | undefined;
    for (const line of tail) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch {
        continue; // torn/unparsable tail lines are skipped in summaries
      }
      const event = parsed as { type?: unknown; seq?: unknown; time?: unknown; data?: unknown };
      if (typeof event?.type !== "string") continue;
      if (typeof event.seq === "number" && event.seq > lastSeq) lastSeq = event.seq;
      if (typeof event.time === "number" && event.time > lastTime) lastTime = event.time;
      const data = event.data as { title?: unknown; archived?: unknown; reason?: unknown } | undefined;
      if (event.type === "session/title" && typeof data?.title === "string") title = data.title;
      else if (event.type === "session/archive" && typeof data?.archived === "boolean") archived = data.archived;
      else if (event.type === "turn/end") {
        const reason = data?.reason as { kind?: unknown; error?: unknown } | undefined;
        const failure = reason?.error as { message?: unknown; code?: unknown } | undefined;
        if (reason?.kind === "error" && typeof failure?.message === "string" && typeof failure?.code === "string") {
          lastError = { message: failure.message, code: failure.code };
        }
      }
    }
    return {
      id: header.id,
      ...title !== undefined ? { title } : {},
      archived,
      ...header.provider !== undefined ? { provider: header.provider } : {},
      ...header.model !== undefined ? { model: header.model } : {},
      ...header.executor !== undefined ? { executor: header.executor } : {},
      createdAt: header.createdAt,
      updatedAt: lastTime,
      eventCount: lastSeq + 1,
      ...lastError !== undefined ? { lastError } : {},
    };
  }

  /** Read the last complete newline-terminated lines of a file (bounded). */
  private async readTail(path: string, signal?: AbortSignal): Promise<string[]> {
    signal?.throwIfAborted();
    const handle = await open(path, "r");
    try {
      signal?.throwIfAborted();
      const { size } = await handle.stat();
      const readLength = Math.min(size, SUMMARY_TAIL_BYTES);
      if (readLength === 0) return [];
      const buffer = Buffer.alloc(readLength);
      await handle.read(buffer, 0, readLength, size - readLength);
      signal?.throwIfAborted();
      const text = buffer.toString("utf8");
      const lines = text.split("\n");
      // The first fragment may start mid-line; drop it unless the window covered the file.
      const start = size > SUMMARY_TAIL_BYTES ? 1 : 0;
      const complete = lines.slice(start);
      if (complete.length > 0 && complete.at(-1) === "") complete.pop();
      return complete;
    } finally {
      await handle.close();
    }
  }

  // --- materialization / append / repair (file mechanics) ---

  /** Atomically write the header line + first batch (temp-write, fsync, publish). */
  private async materialize(meta: SessionHeader, events: readonly SessionEvent[]): Promise<void> {
    const project = projectDir(this.root, meta.cwd);
    const dir = sessionDir(this.root, meta.cwd, meta.id);
    const finalPath = logPath(this.root, meta.cwd, meta.id, this.compression);
    const content = await this.encodeMaterialization(meta, events);
    await this.materializePosix(project, dir, finalPath, meta.id, content);
  }

  private async materializePosix(
    project: string,
    dir: string,
    finalPath: string,
    id: SessionId,
    content: Buffer | string,
  ): Promise<void> {
    await mkdir(this.root, { recursive: true, mode: 0o700 });
    await this.syncDirPosix(dirname(this.root));
    await mkdir(project, { recursive: true, mode: 0o700 });
    await this.syncDirPosix(this.root);
    await mkdir(dir, { recursive: true, mode: 0o700 });
    await this.syncDirPosix(project);
    await this.rejectExistingLog(finalPath, id);
    const tmp = await this.writeSyncedTempFile(finalPath, content);
    // Publish via link()+unlink(), NOT rename(): link fails with EEXIST if the
    // final path already exists, so concurrent materialization cannot clobber.
    let linked = false;
    try {
      await link(tmp, finalPath);
      linked = true;
    } finally {
      if (!linked) await rm(tmp, { force: true });
    }
    // The new link is not crash-durable until the parent directory is synced.
    await this.syncDirPosix(dir);
    try {
      await rm(tmp, { force: true });
    } catch {
      // Redundant temp link; publish is already durable.
    }
  }

  private async rejectExistingLog(finalPath: string, id: SessionId): Promise<void> {
    if (await this.exists(finalPath)) {
      throw new Error(`refusing to materialize "${id}": a log already exists on disk (load/resume it instead)`);
    }
  }

  private async writeSyncedTempFile(finalPath: string, content: Buffer | string): Promise<string> {
    const tmp = `${finalPath}.${randomBytes(6).toString("hex")}.tmp`;
    const handle = await open(tmp, "wx", 0o600);
    try {
      await handle.writeFile(content);
      await handle.sync();
    } finally {
      await handle.close();
    }
    return tmp;
  }

  private async encodeMaterialization(meta: SessionHeader, events: readonly SessionEvent[]): Promise<string> {
    const header = JSON.stringify(toHeaderLine(meta)) + "\n";
    const body = eventLines(events) + "\n";
    return header + body;
  }

  /** Encode one durable append batch. */
  private async encodeEventBatch(events: readonly SessionEvent[]): Promise<string> {
    return eventLines(events) + "\n";
  }

  /** fsync a directory so a just-created/renamed entry is crash-durable. */
  private async syncDirPosix(dir: string): Promise<void> {
    const handle = await open(dir, "r");
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
  }

  /**
   * Append and fsync event lines. On a partial write or sync failure, restore
   * the previous size before rethrowing — the unchanged cursor retries the
   * batch, so partial bytes would create duplicate sequence numbers.
   */
  private async appendLines(meta: SessionHeader, events: readonly SessionEvent[]): Promise<void> {
    const content = await this.encodeEventBatch(events);
    const path = logPath(this.root, meta.cwd, meta.id, this.compression);
    const handle = await open(path, "a");
    let closed = false;
    const closeAppendHandle = async (): Promise<void> => {
      if (closed) return;
      closed = true;
      await handle.close();
    };
    try {
      const { size: before } = await handle.stat();
      try {
        await handle.writeFile(content);
        await handle.sync();
      } catch (error) {
        try {
          await closeAppendHandle();
          await this.rollbackAppend(path, before);
        } catch (rollbackError) {
          throw new AggregateError([error, rollbackError], `failed to roll back append to "${path}"`);
        }
        throw error;
      }
    } finally {
      await closeAppendHandle();
    }
  }

  private async rollbackAppend(path: string, size: number): Promise<void> {
    const handle = await open(path, "r+");
    try {
      await handle.truncate(size);
      await handle.sync();
    } finally {
      await handle.close();
    }
  }

  /** Truncate the log file to `offset` bytes and fsync (discard the crash tail). */
  private async repair(meta: SessionHeader, offset: number): Promise<void> {
    const path = logPath(this.root, meta.cwd, meta.id, this.compression);
    await truncate(path, offset);
    const handle = await open(path, "r+");
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
  }

  // --- discovery helpers ---

  /** Read the first newline-terminated line of a file in bounded chunks. */
  private async readFirstLine(path: string, signal?: AbortSignal): Promise<string | undefined> {
    signal?.throwIfAborted();
    const handle = await open(path, "r");
    try {
      signal?.throwIfAborted();
      const chunks: Buffer[] = [];
      const buf = Buffer.alloc(8192);
      for (;;) {
        signal?.throwIfAborted();
        const { bytesRead } = await handle.read(buf, 0, buf.length, null);
        signal?.throwIfAborted();
        if (bytesRead === 0) return undefined;
        const slice = buf.subarray(0, bytesRead);
        const nl = slice.indexOf(0x0a);
        if (nl !== -1) {
          chunks.push(slice.subarray(0, nl));
          return Buffer.concat(chunks).toString("utf8");
        }
        chunks.push(Buffer.from(slice));
      }
    } finally {
      await handle.close();
    }
  }

  /** Find the unique physical log for an id across every project directory. */
  private async findLog(id: SessionId, signal?: AbortSignal): Promise<string | undefined> {
    const matches: string[] = [];
    for (const project of await this.listProjectDirs()) {
      signal?.throwIfAborted();
      const path = join(project, encodeSegment(id), `session${logSuffix(this.compression)}`);
      if (await this.exists(path)) matches.push(path);
    }
    if (matches.length > 1) {
      throw new Error(`duplicate JSONL session id "${id}" appears in multiple project directories`);
    }
    return matches[0];
  }

  /** Reject metadata that does not identify the selected physical log. */
  private async assertStoredIdentity(
    path: string,
    meta: SessionHeader,
    expectedId?: SessionId,
    signal?: AbortSignal,
  ): Promise<void> {
    signal?.throwIfAborted();
    if (expectedId !== undefined && meta.id !== expectedId) {
      throw new Error(`corrupt session log "${path}": requested id "${expectedId}" does not match header id "${meta.id}"`);
    }
    const expectedPath = logPath(this.root, meta.cwd, meta.id, this.compression);
    if (path !== expectedPath && !await this.sameFile(path, expectedPath, signal)) {
      throw new Error(`corrupt session log "${path}": header id "${meta.id}" and cwd identify "${expectedPath}"`);
    }
  }

  private async sameFile(path: string, expectedPath: string, signal?: AbortSignal): Promise<boolean> {
    signal?.throwIfAborted();
    try {
      const [actual, expected] = await Promise.all([realpath(path), realpath(expectedPath)]);
      return actual === expected;
    } catch (error: unknown) {
      if (isENOENT(error)) return false;
      throw error;
    }
  }

  private async listArtifacts(signal?: AbortSignal): Promise<Array<{ header: SessionHeader; path: string }>> {
    signal?.throwIfAborted();
    const artifacts: Array<{ header: SessionHeader; path: string }> = [];
    const ids = new Set<SessionId>();
    for (const project of await this.listProjectDirs()) {
      signal?.throwIfAborted();
      for (const dir of await this.listSessionDirs(project, signal)) {
        signal?.throwIfAborted();
        const path = join(dir, `session${logSuffix(this.compression)}`);
        if (!await this.exists(path)) continue;
        // Read only headers so listing scales with session count, not log size.
        const first = await this.readFirstLine(path, signal);
        if (first === undefined) continue; // empty/half-written file
        const meta = parseHeaderMeta(first);
        if (meta === undefined) continue; // not a session header
        await this.assertStoredIdentity(path, meta, undefined, signal);
        signal?.throwIfAborted();
        if (ids.has(meta.id)) {
          throw new Error(`duplicate JSONL session id "${meta.id}" appears in multiple project directories`);
        }
        ids.add(meta.id);
        artifacts.push({ header: meta, path });
      }
    }
    return artifacts;
  }

  private async listProjectDirs(): Promise<string[]> {
    try {
      const entries = await readdir(this.root, { withFileTypes: true });
      return entries.filter(e => e.isDirectory() && e.name !== ".trash").map(e => join(this.root, e.name));
    } catch (error: unknown) {
      // Only an absent root means no sessions; rethrow every other I/O failure.
      if (isENOENT(error)) return [];
      throw error;
    }
  }

  private async listSessionDirs(project: string, signal?: AbortSignal): Promise<string[]> {
    signal?.throwIfAborted();
    const entries = await readdir(project, { withFileTypes: true });
    return entries.filter(entry => entry.isDirectory()).map(entry => join(project, entry.name));
  }

  private async exists(path: string): Promise<boolean> {
    try {
      const handle = await open(path, "r");
      await handle.close();
      return true;
    } catch (error: unknown) {
      if (isENOENT(error)) return false;
      throw error;
    }
  }

  /** Trash layout helpers (see trash.ts for the recoverable-delete policy). */
  trashRoot(): string {
    return trashDir(this.root);
  }
}

/** A stored session's header plus events at or past a requested seq. */
export interface StoredSuffix {
  readonly meta: SessionHeader;
  readonly events: SessionEvent[];
}

/** Convenience: read a full inspection off a stored prefix (no repair side effects). */
export function inspectionFromStored(stored: StoredPrefix): SessionInspection {
  return { meta: stored.meta, events: stored.events };
}

/**
 * Recoverable delete for JSONL sessions: a deleted session's directory moves
 * under the store root's `.trash/` folder with a tombstone, and restore moves
 * it back to its original project directory. Purge removes it permanently.
 * Canonical history stays append-only JSONL; delete never rewrites a log.
 *
 * @module catomicals-desktop/sessions/trash
 */

import { mkdir, open, readdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { encodeSegment, parseHeaderMeta, sessionDir, trashDir } from "./format.js";
import type { JsonlSessionStore } from "./jsonl-store.js";
import type { SessionHeader, SessionId, TrashEntry } from "./types.js";

/** Tombstone file written inside a trashed session directory. */
export const TRASH_TOMBSTONE = "trash.json";

/** One trashed session directory plus its tombstone. */
export interface TrashRecord {
  readonly entry: TrashEntry;
  /** Absolute path of the trashed session directory (holds the log + tombstone). */
  readonly dir: string;
}

function isENOENT(error: unknown): boolean {
  return (error as NodeJS.ErrnoException | null)?.code === "ENOENT";
}

/**
 * Owns the trash layout for one store root. All paths derive from the store's
 * root so delete/restore/purge never touch canonical logs.
 */
export class TrashStore {
  /** @param store - the JSONL store whose root owns this trash. */
  constructor(private readonly store: JsonlSessionStore) {}

  /** Move one stored session into trash (recoverable delete). */
  async trash(header: SessionHeader, deletedAt: number): Promise<TrashEntry> {
    const source = sessionDir(this.store.rootDir, header.cwd, header.id);
    const root = trashDir(this.store.rootDir);
    await mkdir(root, { recursive: true, mode: 0o700 });
    const suffix = `${encodeSegment(header.id)}-${deletedAt}-${randomBytes(3).toString("hex")}`;
    const target = join(root, suffix);
    await mkdir(target, { recursive: true, mode: 0o700 });
    const entry: TrashEntry = {
      id: header.id,
      deletedAt,
      ...header.cwd !== undefined ? { originalCwd: header.cwd } : {},
    };
    // Write the tombstone first: a crash between tombstone and rename leaves a
    // listable entry whose directory may be absent (list skips missing dirs).
    await writeFile(join(target, TRASH_TOMBSTONE), JSON.stringify(entry) + "\n", { mode: 0o600 });
    await rename(source, join(target, "session"));
    // Rewrite the tombstone with the title folded from the moved log.
    const title = await this.foldTitle(join(target, "session"));
    const finalEntry = title === undefined ? entry : { ...entry, title };
    await writeFile(join(target, TRASH_TOMBSTONE), JSON.stringify(finalEntry) + "\n", { mode: 0o600 });
    return finalEntry;
  }

  /** List trashed sessions (tombstones; falls back to the moved log header). */
  async list(): Promise<TrashRecord[]> {
    const root = trashDir(this.store.rootDir);
    let names: string[];
    try {
      const entries = await readdir(root, { withFileTypes: true });
      names = entries.filter(e => e.isDirectory()).map(e => e.name);
    } catch (error: unknown) {
      if (isENOENT(error)) return [];
      throw error;
    }
    const records: TrashRecord[] = [];
    for (const name of names) {
      const dir = join(root, name);
      const record = await this.readRecord(dir);
      if (record !== undefined) records.push(record);
    }
    return records;
  }

  /** Restore a trashed session to its original project directory. */
  async restore(id: SessionId, deletedAt: number): Promise<SessionHeader> {
    const record = await this.find(id, deletedAt);
    if (record === undefined) throw new Error(`trashed session "${id}" not found`);
    const header = await this.readMovedHeader(record.dir);
    if (header === undefined) throw new Error(`trashed session "${id}" has no readable header`);
    const target = sessionDir(this.store.rootDir, header.cwd, header.id);
    await mkdir(join(target, ".."), { recursive: true, mode: 0o700 });
    // The moved log lives at <trash>/<slug>/session/; move that inner dir back.
    await rename(join(record.dir, "session"), target);
    await rm(join(record.dir, TRASH_TOMBSTONE), { force: true });
    return header;
  }

  /** Permanently delete a trashed session. */
  async purge(id: SessionId, deletedAt: number): Promise<void> {
    const record = await this.find(id, deletedAt);
    if (record === undefined) throw new Error(`trashed session "${id}" not found`);
    await rm(record.dir, { recursive: true, force: true });
  }

  private async find(id: SessionId, deletedAt: number): Promise<TrashRecord | undefined> {
    for (const record of await this.list()) {
      if (record.entry.id === id && record.entry.deletedAt === deletedAt) return record;
    }
    return undefined;
  }

  private async readRecord(dir: string): Promise<TrashRecord | undefined> {
    let tombstone: TrashEntry | undefined;
    try {
      const raw = await readFile(join(dir, TRASH_TOMBSTONE), "utf8");
      tombstone = parseTrashEntry(raw);
    } catch {
      tombstone = undefined;
    }
    if (tombstone !== undefined) return { entry: tombstone, dir };
    // Tombstone-less (crash between rename and rewrite): fall back to the header.
    const header = await this.readMovedHeader(dir);
    if (header === undefined) return undefined;
    return {
      entry: {
        id: header.id,
        deletedAt: await this.directoryMtimeMs(dir),
        ...header.cwd !== undefined ? { originalCwd: header.cwd } : {},
      },
      dir,
    };
  }

  private async readMovedHeader(dir: string): Promise<SessionHeader | undefined> {
    // The moved log lives at <trash>/<slug>/session/session.jsonl.
    const movedLog = join(dir, "session", "session.jsonl");
    try {
      const handle = await open(movedLog, "r");
      let headerText = "";
      try {
        const buffer = Buffer.alloc(64 * 1024);
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
        headerText = buffer.subarray(0, bytesRead).toString("utf8").split("\n", 1)[0];
      } finally {
        await handle.close();
      }
      return parseHeaderMeta(headerText);
    } catch {
      return undefined;
    }
  }

  private async directoryMtimeMs(dir: string): Promise<number> {
    try {
      return Math.floor((await stat(dir)).mtimeMs);
    } catch {
      return Date.now();
    }
  }

  private async foldTitle(movedDir: string): Promise<string | undefined> {
    const movedLog = join(movedDir, "session.jsonl");
    try {
      const handle = await open(movedLog, "r");
      let title: string | undefined;
      try {
        const buffer = Buffer.alloc(64 * 1024);
        await handle.read(buffer, 0, buffer.length, null);
        for (const line of buffer.toString("utf8").split("\n")) {
          let parsed: unknown;
          try {
            parsed = JSON.parse(line);
          } catch {
            continue;
          }
          const event = parsed as { type?: unknown; data?: { title?: unknown } };
          if (event.type === "session/title" && typeof event.data?.title === "string") title = event.data.title;
        }
      } finally {
        await handle.close();
      }
      return title;
    } catch {
      return undefined;
    }
  }
}

/** Parse a tombstone line into a {@link TrashEntry}. */
export function parseTrashEntry(raw: string): TrashEntry | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (typeof parsed !== "object" || parsed === null) return undefined;
  const record = parsed as Record<string, unknown>;
  if (typeof record.id !== "string" || typeof record.deletedAt !== "number") return undefined;
  return {
    id: record.id as SessionId,
    deletedAt: record.deletedAt,
    ...typeof record.originalCwd === "string" ? { originalCwd: record.originalCwd } : {},
    ...typeof record.title === "string" ? { title: record.title } : {},
  };
}

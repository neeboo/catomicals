import { randomUUID } from "node:crypto";
import { mkdir, open, rename, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";

export type IdentityProviderId = "local-device";

export interface IdentitySession {
  version: 1;
  provider: IdentityProviderId;
  accountId: string;
  sessionId: string;
  displayName: string;
  createdAt: number;
  authenticatedAt: number;
}

export interface IdentityProfile {
  version: 1;
  provider: IdentityProviderId;
  accountId: string;
  displayName: string;
  createdAt: number;
}

export interface IdentityCipher {
  encrypt(value: string): Buffer;
  decrypt(value: Buffer): string;
}

export interface IdentityCipherSource {
  current(): IdentityCipher | undefined;
}

export type IdentityDataKind = "session" | "profile";

export class IdentityStoreCorruptionError extends Error {
  readonly code = "identity-data-corrupt" as const;

  constructor(readonly kind: IdentityDataKind) {
    super("identity data is corrupted");
    this.name = "IdentityStoreCorruptionError";
  }
}

interface PersistedIdentityEnvelope {
  version: 1;
  ciphertext: string;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
export const IDENTITY_FILE_MAX_BYTES = 16 * 1024;

function exactKeys(record: Record<string, unknown>, expected: readonly string[]): void {
  const actual = Object.keys(record).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error("invalid identity fields");
  }
}

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid identity record");
  return value as Record<string, unknown>;
}

export function parseIdentitySession(value: unknown): IdentitySession {
  const input = record(value);
  exactKeys(input, ["version", "provider", "accountId", "sessionId", "displayName", "createdAt", "authenticatedAt"]);
  if (input.version !== 1 || input.provider !== "local-device") throw new Error("invalid identity session version");
  if (typeof input.accountId !== "string" || !UUID.test(input.accountId)
    || typeof input.sessionId !== "string" || !UUID.test(input.sessionId)) {
    throw new Error("invalid identity identifier");
  }
  if (typeof input.displayName !== "string" || input.displayName.trim() !== input.displayName
    || input.displayName.length < 1 || input.displayName.length > 80 || /[\u0000-\u001f\u007f]/.test(input.displayName)) {
    throw new Error("invalid identity display name");
  }
  if (!Number.isSafeInteger(input.createdAt) || (input.createdAt as number) <= 0
    || !Number.isSafeInteger(input.authenticatedAt) || (input.authenticatedAt as number) < (input.createdAt as number)) {
    throw new Error("invalid identity timestamp");
  }
  return input as unknown as IdentitySession;
}

export function parseIdentityProfile(value: unknown): IdentityProfile {
  const input = record(value);
  exactKeys(input, ["version", "provider", "accountId", "displayName", "createdAt"]);
  if (input.version !== 1 || input.provider !== "local-device") throw new Error("invalid identity profile version");
  if (typeof input.accountId !== "string" || !UUID.test(input.accountId)) throw new Error("invalid identity identifier");
  if (typeof input.displayName !== "string" || input.displayName.trim() !== input.displayName
    || input.displayName.length < 1 || input.displayName.length > 80 || /[\u0000-\u001f\u007f]/.test(input.displayName)) {
    throw new Error("invalid identity display name");
  }
  if (!Number.isSafeInteger(input.createdAt) || (input.createdAt as number) <= 0) throw new Error("invalid identity timestamp");
  return input as unknown as IdentityProfile;
}

function parseEnvelope(value: unknown): PersistedIdentityEnvelope {
  const input = record(value);
  exactKeys(input, ["version", "ciphertext"]);
  if (input.version !== 1 || typeof input.ciphertext !== "string" || input.ciphertext.length < 1) {
    throw new Error("invalid identity envelope");
  }
  if (!BASE64.test(input.ciphertext)) throw new Error("invalid identity ciphertext");
  return input as unknown as PersistedIdentityEnvelope;
}

export class IdentityStore {
  readonly path: string;
  readonly profilePath: string;
  private readonly cipherSource: IdentityCipherSource;

  constructor(root: string, cipher?: IdentityCipher | IdentityCipherSource) {
    this.path = join(root, "identity-session.json");
    this.profilePath = join(root, "identity-profile.json");
    this.cipherSource = cipher && "current" in cipher
      ? cipher
      : { current: () => cipher };
  }

  get available(): boolean {
    return this.cipherSource.current() !== undefined;
  }

  async read(): Promise<IdentitySession | null> {
    return this.readEncrypted(this.path, "session", parseIdentitySession);
  }

  async readProfile(): Promise<IdentityProfile | null> {
    return this.readEncrypted(this.profilePath, "profile", parseIdentityProfile);
  }

  private async readEncrypted<T>(path: string, kind: IdentityDataKind, parse: (value: unknown) => T): Promise<T | null> {
    const cipher = this.cipherSource.current();
    if (!cipher) return null;
    let serialized: string;
    try {
      serialized = await this.readBounded(path, kind);
    } catch (error: unknown) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw error;
    }
    try {
      const envelope = parseEnvelope(JSON.parse(serialized) as unknown);
      const plaintext = cipher.decrypt(Buffer.from(envelope.ciphertext, "base64"));
      return parse(JSON.parse(plaintext) as unknown);
    } catch (error: unknown) {
      if (error instanceof IdentityStoreCorruptionError) throw error;
      throw new IdentityStoreCorruptionError(kind);
    }
  }

  async write(session: IdentitySession): Promise<void> {
    return this.writeEncrypted(this.path, parseIdentitySession(session));
  }

  async writeProfile(profile: IdentityProfile): Promise<void> {
    return this.writeEncrypted(this.profilePath, parseIdentityProfile(profile));
  }

  private async writeEncrypted(path: string, value: IdentitySession | IdentityProfile): Promise<void> {
    const cipher = this.cipherSource.current();
    if (!cipher) throw new Error("secure storage unavailable");
    const ciphertext = cipher.encrypt(JSON.stringify(value)).toString("base64");
    const envelope: PersistedIdentityEnvelope = { version: 1, ciphertext };
    const serialized = `${JSON.stringify(envelope)}\n`;
    if (Buffer.byteLength(serialized, "utf8") > IDENTITY_FILE_MAX_BYTES) throw new Error("identity data exceeds size limit");
    await mkdir(dirname(path), { recursive: true });
    const temporaryPath = `${path}.${process.pid}.${randomUUID()}.tmp`;
    let file: Awaited<ReturnType<typeof open>> | undefined;
    try {
      file = await open(temporaryPath, "wx", 0o600);
      await file.writeFile(serialized, "utf8");
      await file.sync();
      await file.close();
      file = undefined;
      await rename(temporaryPath, path);
      await this.syncDirectory();
    } catch (error: unknown) {
      await file?.close().catch(() => undefined);
      await unlink(temporaryPath).catch(() => undefined);
      throw error;
    }
  }

  async clear(): Promise<void> {
    if (await this.remove(this.path)) await this.syncDirectory();
  }

  async reset(): Promise<void> {
    const removed = await Promise.all([this.remove(this.path), this.remove(this.profilePath)]);
    if (removed.some(Boolean)) await this.syncDirectory();
  }

  private async remove(path: string): Promise<boolean> {
    try {
      await unlink(path);
      return true;
    } catch (error: unknown) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
      throw error;
    }
  }

  private async readBounded(path: string, kind: IdentityDataKind): Promise<string> {
    const file = await open(path, "r");
    try {
      const buffer = Buffer.allocUnsafe(IDENTITY_FILE_MAX_BYTES + 1);
      let offset = 0;
      while (offset < buffer.length) {
        const { bytesRead } = await file.read(buffer, offset, buffer.length - offset, offset);
        if (bytesRead === 0) break;
        offset += bytesRead;
      }
      if (offset > IDENTITY_FILE_MAX_BYTES) throw new IdentityStoreCorruptionError(kind);
      return buffer.subarray(0, offset).toString("utf8");
    } finally {
      await file.close();
    }
  }

  private async syncDirectory(): Promise<void> {
    const directory = await open(dirname(this.path), "r");
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  }
}

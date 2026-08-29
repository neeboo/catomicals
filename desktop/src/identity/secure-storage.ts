import type { IdentityCipher } from "./store.js";

export interface OperatingSystemStorage {
  isEncryptionAvailable(): boolean;
  getSelectedStorageBackend(): string;
  encryptString(value: string): Buffer;
  decryptString(value: Buffer): string;
}

export function createIdentityCipher(
  storage: OperatingSystemStorage,
  platform: NodeJS.Platform = process.platform,
): IdentityCipher | undefined {
  if (!storage.isEncryptionAvailable()) return undefined;
  if (platform === "linux" && storage.getSelectedStorageBackend() === "basic_text") return undefined;
  return {
    encrypt: (value) => storage.encryptString(value),
    decrypt: (value) => storage.decryptString(value),
  };
}

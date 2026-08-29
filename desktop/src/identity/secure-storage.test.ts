import { describe, expect, it, vi } from "vitest";
import { createIdentityCipher } from "./secure-storage";

describe("identity secure storage adapter", () => {
  it("uses the operating-system protected storage backend", () => {
    const encryptString = vi.fn((value: string) => Buffer.from(`os:${value}`));
    const decryptString = vi.fn((value: Buffer) => value.toString().slice(3));
    const cipher = createIdentityCipher({
      isEncryptionAvailable: () => true,
      getSelectedStorageBackend: () => "keychain",
      encryptString,
      decryptString,
    }, "darwin");

    expect(cipher?.decrypt(cipher.encrypt("identity"))).toBe("identity");
    expect(encryptString).toHaveBeenCalledWith("identity");
  });

  it("rejects unavailable encryption and Linux basic-text fallback", () => {
    const storage = {
      isEncryptionAvailable: () => true,
      getSelectedStorageBackend: () => "basic_text",
      encryptString: (value: string) => Buffer.from(value),
      decryptString: (value: Buffer) => value.toString(),
    };

    expect(createIdentityCipher({ ...storage, isEncryptionAvailable: () => false }, "darwin")).toBeUndefined();
    expect(createIdentityCipher(storage, "linux")).toBeUndefined();
  });
});

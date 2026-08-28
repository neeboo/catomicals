import { describe, expect, it, vi } from "vitest";
import { join } from "node:path";
import { resolveCatomicalsCommand } from "./catomicals-command";

describe("Catomicals executable resolution", () => {
  it("uses the workspace binary when it exists", () => {
    const exists = vi.fn((path: string) => path === join("/repo", "target", "debug", "catomicals"));
    expect(resolveCatomicalsCommand("/repo", exists, "darwin"))
      .toBe(join("/repo", "target", "debug", "catomicals"));
  });

  it("falls back to PATH when the workspace binary is absent", () => {
    expect(resolveCatomicalsCommand("/repo", () => false, "darwin")).toBe("catomicals");
  });

  it("uses the Windows executable suffix", () => {
    const candidate = join("C:\\repo", "target", "debug", "catomicals.exe");
    expect(resolveCatomicalsCommand("C:\\repo", (path) => path === candidate, "win32"))
      .toBe(candidate);
  });
});

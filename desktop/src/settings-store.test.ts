import { describe, expect, it } from "vitest";
import { parsePersistedSettings } from "./settings-store";

describe("desktop settings persistence", () => {
  it("drops unknown and secret-like fields before writing plain JSON", () => {
    const parsed = parsePersistedSettings({
      defaultHarness: "claude-code",
      adapters: {},
      apiKey: "secret",
    });
    expect(parsed.defaultHarness).toBe("claude-code");
    expect(JSON.stringify(parsed)).not.toContain("secret");
  });
});

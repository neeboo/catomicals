import { describe, expect, it } from "vitest";
import { errorMessage } from "./errors";

describe("errorMessage", () => {
  it("reads Error messages", () => {
    expect(errorMessage(new Error("Not allowed"))).toBe("Not allowed");
  });

  it("safely normalizes non-Error throws", () => {
    expect(errorMessage("cancelled")).toBe("cancelled");
    expect(errorMessage({ message: "credential failed" })).toBe("credential failed");
    expect(errorMessage(null)).toBe("Unknown error");
  });
});

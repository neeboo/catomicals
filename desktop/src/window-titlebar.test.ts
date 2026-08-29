import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const main = readFileSync(new URL("./main.ts", import.meta.url), "utf8");

describe("desktop window title bar options", () => {
  it("removes the native title bar on macOS", () => {
    expect(main).toContain('titleBarStyle: "hidden"');
    expect(main).not.toContain('titleBarStyle: "hiddenInset"');
    expect(main).toContain('process.platform === "darwin"');
  });

  it("keeps the traffic lights at the far left of the title bar", () => {
    expect(main).toContain("trafficLightPosition");
    expect(main).toContain("{ x: 10, y: 10 }");
  });

  it("leaves other platforms on the native frame (no overlay options)", () => {
    // The custom title bar is macOS-only: non-darwin must not get a
    // titleBarStyle or overlay option that would fight the native frame.
    expect(main).not.toContain("titleBarOverlay");
  });

  it("paints the DSH near-black canvas as the window background", () => {
    expect(main).toContain('backgroundColor: "#151517"');
  });
});

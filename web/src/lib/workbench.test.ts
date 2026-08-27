import { describe, expect, it } from "vitest";
import {
  INSPECTOR_MODES,
  DEFAULT_TOOL_AREA,
  TOOL_TABS,
  starterActions,
  transitionDrawer,
  transitionToolArea,
  type InspectorMode,
} from "./workbench";

describe("wallet workbench model", () => {
  it("exposes the four contextual inspector modes", () => {
    expect(INSPECTOR_MODES).toEqual([
      "transaction",
      "intents",
      "security",
      "issuance",
    ] satisfies InspectorMode[]);
  });

  it("maps each starter action to a real inspector mode", () => {
    expect(starterActions.map((action) => action.mode)).toEqual([
      "transaction",
      "intents",
      "security",
      "issuance",
    ]);
  });

  it("keeps issuance honest about its current implementation boundary", () => {
    const issuance = starterActions.find((action) => action.mode === "issuance");

    expect(issuance?.available).toBe(false);
    expect(issuance?.description).toContain("尚未实现");
  });

  it("uses one drawer state so opening one side always closes the other", () => {
    expect(transitionDrawer(null, "open-left")).toBe("left");
    expect(transitionDrawer("left", "open-right")).toBe("right");
    expect(transitionDrawer("right", "open-left")).toBe("left");
    expect(transitionDrawer("left", "close")).toBeNull();
  });

  it("moves from the left drawer to the right drawer when a tool is selected", () => {
    expect(transitionDrawer("left", "select-tool")).toBe("right");
  });

  it("keeps the right tool area collapsed until its corner control is used", () => {
    expect(DEFAULT_TOOL_AREA).toEqual({ open: false, activeTab: null });
    const expanded = transitionToolArea(DEFAULT_TOOL_AREA, { type: "expand" });
    expect(expanded).toEqual({ open: true, activeTab: null });
    const selected = transitionToolArea(expanded, { type: "select", tab: "security" });
    expect(selected).toEqual({ open: true, activeTab: "security" });
    expect(transitionToolArea(selected, { type: "back" })).toEqual({ open: true, activeTab: null });
    expect(transitionToolArea(selected, { type: "close" })).toEqual(DEFAULT_TOOL_AREA);
  });

  it("models the real Electron browser as a first-class tool tab", () => {
    expect(TOOL_TABS).toEqual([
      "browser",
      "transaction",
      "intents",
      "security",
      "issuance",
    ]);
    expect(transitionToolArea(DEFAULT_TOOL_AREA, { type: "select", tab: "browser" }))
      .toEqual({ open: true, activeTab: "browser" });
  });
});

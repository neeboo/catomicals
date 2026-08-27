import { describe, expect, it } from "vitest";
import {
  INSPECTOR_MODES,
  DEFAULT_PLUGIN_PANEL,
  starterActions,
  transitionDrawer,
  transitionPluginPanel,
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

  it("keeps plugins closed until selected and restores the conversation when closed", () => {
    expect(DEFAULT_PLUGIN_PANEL).toBeNull();
    const opened = transitionPluginPanel(DEFAULT_PLUGIN_PANEL, {
      type: "select",
      mode: "transaction",
    });
    expect(opened).toBe("transaction");
    expect(transitionPluginPanel(opened, { type: "close" })).toBeNull();
  });
});

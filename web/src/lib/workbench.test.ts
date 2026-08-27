import { describe, expect, it } from "vitest";
import {
  INSPECTOR_MODES,
  starterActions,
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
});

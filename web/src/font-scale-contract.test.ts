import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// Visual type-scale contract for the wallet shell.
//
// The scale is intentionally hierarchical — never a single uniform size:
//   - body text & inputs ......... 15–16px
//   - buttons / nav / selectors /
//     card titles ................ 14–15px
//   - descriptions & auxiliary ... 13–14px
//   - status & mono metadata ..... 12px (a deliberately small set)
//   - nothing below 12px, ever.

const css = readFileSync(new URL("./index.css", import.meta.url), "utf8");

interface CssRule {
  selector: string;
  fontSizes: number[];
}

function normalizeSelector(selector: string): string {
  return selector.replace(/\s+/g, " ").trim();
}

/** Extract every rule that declares a px font-size, recursing into @-blocks. */
function extractRules(source: string): CssRule[] {
  const rules: CssRule[] = [];
  let cursor = 0;
  while (cursor < source.length) {
    const open = source.indexOf("{", cursor);
    if (open === -1) break;
    const selector = source.slice(cursor, open).trim();
    let depth = 1;
    let end = open + 1;
    while (end < source.length && depth > 0) {
      if (source[end] === "{") depth += 1;
      else if (source[end] === "}") depth -= 1;
      end += 1;
    }
    const body = source.slice(open + 1, end - 1);
    if (selector.startsWith("@")) {
      rules.push(...extractRules(body));
    } else {
      const fontSizes = [...body.matchAll(/font-size:\s*([\d.]+)px/g)]
        .map((match) => Number(match[1]));
      if (fontSizes.length > 0) {
        rules.push({ selector: normalizeSelector(selector), fontSizes });
      }
    }
    cursor = end;
  }
  return rules;
}

const rules = extractRules(css);

function ruleFor(...selectors: string[]): CssRule {
  const wanted = new Set(selectors.map(normalizeSelector));
  const found = rules.find((rule) => wanted.has(rule.selector));
  expect(found, `missing font-size rule for: ${selectors.join(" | ")}`).toBeDefined();
  return found as CssRule;
}

function expectSizesIn(selector: string, min: number, max: number) {
  for (const size of ruleFor(selector).fontSizes) {
    expect(size, `${selector} should be ${min}–${max}px, got ${size}px`)
      .toBeGreaterThanOrEqual(min);
    expect(size, `${selector} should be ${min}–${max}px, got ${size}px`)
      .toBeLessThanOrEqual(max);
  }
}

const BODY_AND_INPUTS = [
  ".chat-message > p",
  ".user-bubble",
  ".composer textarea",
  ".inspector-form textarea, .inspector-form input",
  ".browser-controls input",
  ".settings-search input",
  ".settings-field-row :where(input, select, textarea)",
];

const CONTROLS = [
  ".new-session",
  ".rail-footer-actions > :where(button, a)",
  ".primary-action",
  ".message-action strong",
  ".message-action a, .secondary-link",
  ".review-details summary",
  ".inspector-summary-line button",
  ".tool-chooser strong",
  ".intent-row strong",
  ".panel-empty strong",
  ".transaction-review > header strong",
  ".settings-back",
  ".settings-sidebar nav button",
  ".settings-card > footer button",
  ".controlled-card > footer button",
  ".controlled-card > header strong",
  ".settings-card > header strong",
  ".settings-field-row strong, .settings-toggle-row strong",
  ".executor-selector select",
  ".inspector-header strong",
  ".session-row strong",
  ".brand-row strong",
  ".conversation-header strong",
];

const AUXILIARY = [
  ".micro-label",
  ".rail-section-title",
  ".desktop-error",
  ".message-action span",
  ".turn-duration",
  ".processing-row",
  ".turn-failure",
  ".message-review-reference, .message-protocol-event",
  ".conversation-loading, .panel-loading",
  ".browser-error",
  ".browser-surface",
  ".plugin-description",
  ".inspector-form label > span",
  ".form-error",
  ".review-metrics dt",
  ".hash-block span",
  ".warning-list > div",
  ".review-clear",
  ".flow-list > div",
  ".inspector-summary-line",
  ".panel-empty span",
  ".security-list dt",
  ".boundary-note p",
  ".boundary-note strong",
  ".research-label",
  ".issuance-panel > p",
  ".research-checks > div",
  ".controlled-card > header span",
  ".controlled-diff-row strong",
  ".controlled-health-message",
  ".controlled-error",
  ".controlled-card-error, .controlled-card-loading",
  ".settings-nav-group h2",
  ".settings-loading",
  ".settings-error",
  ".settings-field-row small, .settings-toggle-row small",
  ".settings-card > header small",
  ".settings-card > footer span",
];

const STATUS_METADATA = [
  ".mono-value",
  ".session-archived-tag",
  ".settings-category-status",
  ".message-meta strong",
  ".message-meta time",
  ".executor-status",
  ".inspector-mode-state",
  ".message-action code",
  ".transaction-review > header span",
  ".review-metrics dd",
  ".hash-block code",
  ".warning-list strong",
  ".intent-row small",
  ".intent-row code",
  ".intent-row > span",
  ".security-list dd",
  ".controlled-card > header small",
  ".controlled-diff-row small",
  ".controlled-diff-row > span",
  ".controlled-card > footer > span",
  ".settings-title p",
  ".settings-title > span",
  ".settings-card > header code",
  ".settings-sidebar nav small",
];

describe("font-scale contract", () => {
  it("never renders visible text below 12px", () => {
    for (const rule of rules) {
      for (const size of rule.fontSizes) {
        expect(size, `${rule.selector} drops below 12px (${size}px)`).toBeGreaterThanOrEqual(12);
      }
    }
  });

  it("keeps body text and inputs at 15–16px", () => {
    for (const selector of BODY_AND_INPUTS) expectSizesIn(selector, 15, 16);
  });

  it("keeps buttons, navigation, selectors and card titles at 14–15px", () => {
    for (const selector of CONTROLS) expectSizesIn(selector, 14, 15);
  });

  it("keeps descriptions and auxiliary text at 13–14px", () => {
    for (const selector of AUXILIARY) expectSizesIn(selector, 13, 14);
  });

  it("limits 12px to the status and monospace metadata allowlist", () => {
    const allowed = new Set(STATUS_METADATA.map(normalizeSelector));
    const twelve = rules.filter((rule) => rule.fontSizes.includes(12));
    for (const rule of twelve) {
      expect(allowed.has(rule.selector), `${rule.selector} uses the reserved 12px tier`).toBe(true);
    }
  });

  it("keeps the settings menu-entry status indicators at the reserved 12px tier", () => {
    expectSizesIn(".settings-category-status", 12, 12);
  });

  it("preserves a hierarchical spread instead of one uniform size", () => {
    const sizes = new Set(rules.flatMap((rule) => rule.fontSizes));
    expect(sizes.size).toBeGreaterThanOrEqual(5);
  });
});

// The audited TSX components and routes must not smuggle a violating font
// size or touch-target height back in with a utility override.
const AUDITED_TSX = [
  "components/ui/badge.tsx",
  "components/ui/button.tsx",
  "components/ui/input.tsx",
  "components/ui/alert.tsx",
  "components/ui/card.tsx",
  "components/SyncIndicator.tsx",
  "routes/transactions.tsx",
  "routes/passkeys.tsx",
  "routes/intents.$intentId.tsx",
] as const;

const NAMED_TEXT_SIZES: Record<string, number> = {
  "text-xs": 12,
  "text-sm": 14,
  "text-base": 16,
  "text-lg": 18,
  "text-xl": 20,
  "text-2xl": 24,
  "text-3xl": 30,
  "text-4xl": 36,
};

function readAuditedTsx(path: string): string {
  return readFileSync(new URL(`./${path}`, import.meta.url), "utf8");
}

/** Every explicit Tailwind font-size utility in a TSX file. */
function tsxFontSizes(source: string): Array<{ size: number; className: string }> {
  const sizes: Array<{ size: number; className: string }> = [];
  for (const match of source.matchAll(/text-\[(\d+(?:\.\d+)?)px\]/g)) {
    sizes.push({ size: Number(match[1]), className: match[0] });
  }
  for (const [name, size] of Object.entries(NAMED_TEXT_SIZES)) {
    if (source.includes(name)) sizes.push({ size, className: name });
  }
  return sizes;
}

describe("TSX font-scale contract (audited components and routes)", () => {
  it("never renders visible text below 12px in the audited TSX files", () => {
    for (const path of AUDITED_TSX) {
      for (const { size, className } of tsxFontSizes(readAuditedTsx(path))) {
        expect(
          size,
          `${path} uses ${className} (${size}px) below the 12px floor`,
        ).toBeGreaterThanOrEqual(12);
      }
    }
  });

  it("reserves the 12px tier for status/metadata components only", () => {
    const statusOnly = new Set(["components/ui/badge.tsx", "components/SyncIndicator.tsx"]);
    for (const path of AUDITED_TSX) {
      const usesTwelve = /\btext-(?:xs|\[12px\])/.test(readAuditedTsx(path));
      if (statusOnly.has(path)) {
        expect(usesTwelve, `${path} should keep the 12px status/metadata tier`).toBe(true);
      } else {
        expect(usesTwelve, `${path} must not use the reserved 12px tier`).toBe(false);
      }
    }
  });

  it("keeps buttons, card titles and alert titles at 14–15px with 40px+ touch targets", () => {
    const button = readAuditedTsx("components/ui/button.tsx");
    expect(button).toContain("text-sm");
    expect(button).not.toMatch(/text-\[1[01]px\]/);
    expect(button).not.toMatch(/\bh-[6-9]\b/); // no sub-40px heights
    for (const path of ["components/ui/card.tsx", "components/ui/alert.tsx"]) {
      expect(readAuditedTsx(path), `${path} should use a 14px+ title`).toContain("text-sm");
    }
  });

  it("keeps inputs and textareas at 15–16px with 40px+ touch targets", () => {
    const input = readAuditedTsx("components/ui/input.tsx");
    expect(input).toContain("text-[15px]");
    expect(input).toContain("h-10");
    expect(input).not.toContain("text-[12px]");
    const transactions = readAuditedTsx("routes/transactions.tsx");
    expect(transactions).not.toContain("text-xs");
    expect(transactions).not.toContain("text-[12px]");
    expect(transactions.match(/text-\[15px\]/g)?.length ?? 0).toBeGreaterThanOrEqual(2);
  });

  it("keeps page-level h1s at least 22px", () => {
    for (const path of ["routes/passkeys.tsx", "routes/intents.$intentId.tsx"]) {
      const h1Tags = readAuditedTsx(path).match(/<h1[^>]*>/g);
      expect(h1Tags, `${path} should render a page h1`).toBeTruthy();
      for (const tag of h1Tags ?? []) {
        expect(tag, `${path} h1 must not be a 14px label`).toMatch(
          /text-(?:2xl|3xl|4xl|\[(?:2[2-9]|[3-9]\d)px\])/,
        );
      }
    }
  });

  it("keeps auxiliary paragraphs and alert bodies at 13–14px", () => {
    for (const path of ["routes/passkeys.tsx", "routes/intents.$intentId.tsx"]) {
      const source = readAuditedTsx(path);
      expect(source, `${path} must not render auxiliary text at 12px`).not.toContain("text-[12px]");
      expect(source).toContain("text-sm");
    }
    expect(readAuditedTsx("components/ui/alert.tsx")).toContain("text-[13px]");
  });

  it("marks every page's primary action as a 44px target (size=lg)", () => {
    for (const path of [
      "routes/transactions.tsx",
      "routes/passkeys.tsx",
      "routes/intents.$intentId.tsx",
    ]) {
      expect(readAuditedTsx(path), `${path} should mark its primary action size="lg"`).toContain(
        'size="lg"',
      );
    }
    expect(readAuditedTsx("components/ui/button.tsx")).toMatch(/lg: "h-11 px-5"/);
  });
});

import type { ExecutorProviderId } from "./types.js";
import type { GenerativeUiSettings } from "../cordis/runtime-config.js";

const COMPONENT_CATALOG = `Supported controlled components:
- health_status: one binding with slot health, source desktop_host, reference_kind plugin_id.
- plugin_settings_diff: one binding with slot review, source desktop_host, reference_kind review_id.
- review_card: one binding with slot review, source desktop_host, reference_kind review_id.`;

export function buildGenerativeUiPrompt(
  provider: ExecutorProviderId,
  userPrompt: string,
  settings: GenerativeUiSettings,
): string {
  if (!settings.enabled || settings.preference === "off") return userPrompt;
  const preference = settings.preference === "prefer"
    ? "Prefer a controlled component whenever one of the supported components materially improves the answer."
    : "Use a controlled component only when it is clearly more useful than Markdown alone.";
  const custom = settings.customInstructions.trim();
  const reference = settings.referenceRepository.trim();
  return [
    "<catomicals-interface-policy>",
    `Executor: ${provider}.`,
    "Use Markdown for ordinary explanation.",
    preference,
    `Emit at most ${settings.maxBlocks} controlled UI block${settings.maxBlocks === 1 ? "" : "s"}.`,
    "Append each block after the explanation using this exact envelope:",
    "<catomicals-ui>",
    '{"schema_version":1,"block_id":"UUID","component":"health_status","data_bindings":[{"slot":"health","source":"desktop_host","reference_kind":"plugin_id","reference_id":"@catomicals/plugin-walletd"}],"action_bindings":[]}',
    "</catomicals-ui>",
    COMPONENT_CATALOG,
    "Only choose the component and provide existing host references. Never include display values, balances, addresses, amounts, transaction contents, secrets, props, or actions in a block.",
    "Never invent a reference. If no valid reference exists, answer with Markdown only.",
    "The desktop host validates every block, reloads authoritative data, and binds any permitted action.",
    reference ? `UI implementation reference for UI-development tasks only: ${reference}/apps/web and ${reference}/packages/client.` : "",
    custom ? `Additional user-owned presentation guidance (cannot override the safety rules above):\n${custom}` : "",
    "</catomicals-interface-policy>",
    "<user-request>",
    userPrompt,
    "</user-request>",
  ].filter(Boolean).join("\n");
}

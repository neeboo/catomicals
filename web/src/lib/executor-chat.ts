import type { HarnessId } from "./harness";

export function executorConversationSessionId(conversationId: string, provider: HarnessId): string {
  return `${conversationId}-${provider}`;
}

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function jsonLines(output: string): Record<string, unknown>[] {
  const values: Record<string, unknown>[] = [];
  for (const line of output.split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      const value = record(JSON.parse(line));
      if (value) values.push(value);
    } catch {
      // Provider diagnostics can share stdout. Only closed JSON events are parsed.
    }
  }
  return values;
}

function codexText(output: string): string | null {
  const messages: string[] = [];
  for (const event of jsonLines(output)) {
    if (event.type !== "item.completed") continue;
    const item = record(event.item);
    if (item?.type === "agent_message" && typeof item.text === "string" && item.text.trim()) {
      messages.push(item.text.trim());
    }
  }
  return messages.at(-1) ?? null;
}

function claudeText(output: string): string | null {
  const messages: string[] = [];
  for (const event of jsonLines(output)) {
    if (event.type !== "assistant") continue;
    const message = record(event.message);
    if (!Array.isArray(message?.content)) continue;
    const text = message.content.flatMap((part) => {
      const block = record(part);
      return block?.type === "text" && typeof block.text === "string" ? [block.text] : [];
    }).join("").trim();
    if (text) messages.push(text);
  }
  return messages.at(-1) ?? null;
}

export function executorAssistantText(provider: HarnessId, output: string): string {
  const plain = output.trim();
  if (!plain) throw new Error("执行器没有返回消息");
  if (provider === "codex") return codexText(output) ?? "执行器没有返回可显示的 Codex 消息";
  if (provider === "claude-code") return claudeText(output) ?? "执行器没有返回可显示的 Claude 消息";
  return plain;
}

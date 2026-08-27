import { useState } from "react";
import { cn } from "@/lib/cn";
import { shortHex } from "@/lib/format";

export function HexValue({
  value,
  head = 10,
  tail = 8,
  full = false,
  copyable = true,
  className,
}: {
  value: string;
  head?: number;
  tail?: number;
  full?: boolean;
  copyable?: boolean;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);
  const text = full || !value ? value : shortHex(value, head, tail);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      setCopied(false);
    }
  }

  return (
    <span
      className={cn(
        "mono-value inline-flex items-center gap-2",
        className,
      )}
      title={copyable ? `${value}\nclick to copy` : value}
    >
      <span className="text-dim">{text}</span>
      {copyable && value && (
        <button
          type="button"
          onClick={copy}
          className="micro-label shrink-0 cursor-pointer border border-line px-1 py-px text-dim hover:border-line-strong hover:text-muted"
          aria-label="copy value"
        >
          {copied ? "copied" : "copy"}
        </button>
      )}
    </span>
  );
}

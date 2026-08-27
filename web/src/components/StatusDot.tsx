import { cn } from "@/lib/cn";

export type DotTone = "ok" | "off" | "warn";

export function StatusDot({
  tone,
  className,
}: {
  tone: DotTone;
  className?: string;
}) {
  return (
    <span
      aria-hidden
      className={cn(
        "inline-block size-2 shrink-0 rounded-full align-middle",
        tone === "ok" && "dot-ok",
        tone === "off" && "dot-off",
        tone === "warn" && "dot-warn",
        className,
      )}
    />
  );
}

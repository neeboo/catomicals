import { type HTMLAttributes } from "react";
import { cn } from "@/lib/cn";

export function Skeleton({
  className,
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "h-3 animate-blink bg-panel-3",
        className,
      )}
      {...props}
    />
  );
}

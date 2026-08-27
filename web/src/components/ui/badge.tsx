import { type HTMLAttributes } from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/cn";

export const badgeVariants = cva(
  "inline-flex items-center gap-1.5 border px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-[0.12em]",
  {
    variants: {
      variant: {
        outline: "border-line-strong bg-transparent text-paper",
        solid: "border-paper bg-paper text-ink",
        dim: "border-line bg-panel-2 text-muted",
        warn: "border-paper bg-transparent text-paper",
        muted: "border-line text-dim",
      },
    },
    defaultVariants: { variant: "outline" },
  },
);

export interface BadgeProps
  extends HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <span className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}

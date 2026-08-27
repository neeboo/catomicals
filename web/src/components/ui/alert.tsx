import { type HTMLAttributes } from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/cn";

export const alertVariants = cva(
  "border px-3 py-2 text-[11px] leading-5",
  {
    variants: {
      variant: {
        default: "border-line-strong bg-panel-2 text-paper",
        warn: "border-paper bg-transparent text-paper",
        danger:
          "border-line-strong bg-panel-2 text-paper",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

export interface AlertProps
  extends HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof alertVariants> {}

export function Alert({ className, variant, ...props }: AlertProps) {
  return (
    <div role="alert" className={cn(alertVariants({ variant }), className)} {...props} />
  );
}

export function AlertTitle({
  className,
  ...props
}: HTMLAttributes<HTMLHeadingElement>) {
  return (
    <div
      className={cn(
        "mb-0.5 text-[10px] font-semibold uppercase tracking-[0.18em] text-paper",
        className,
      )}
      {...props}
    />
  );
}

import { forwardRef, type ButtonHTMLAttributes } from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/cn";

export const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-none text-sm font-medium uppercase tracking-[0.14em] transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-paper disabled:pointer-events-none disabled:opacity-35",
  {
    variants: {
      variant: {
        default: "bg-paper text-ink hover:bg-white",
        outline:
          "border border-line-strong bg-transparent text-paper hover:border-paper",
        ghost: "bg-transparent text-muted hover:bg-panel-2 hover:text-paper",
        danger:
          "border border-line-strong bg-transparent text-paper hover:border-paper hover:bg-paper hover:text-ink",
      },
      size: {
        default: "h-10 px-4",
        sm: "h-10 px-3 text-sm",
        lg: "h-11 px-5",
      },
    },
    defaultVariants: { variant: "default", size: "default" },
  },
);

export interface ButtonProps
  extends ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, type = "button", ...props }, ref) => (
    <button
      ref={ref}
      type={type}
      className={cn(buttonVariants({ variant, size }), className)}
      {...props}
    />
  ),
);
Button.displayName = "Button";

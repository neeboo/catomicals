import { forwardRef, type InputHTMLAttributes } from "react";
import { cn } from "@/lib/cn";

export const Input = forwardRef<
  HTMLInputElement,
  InputHTMLAttributes<HTMLInputElement>
>(({ className, type, ...props }, ref) => (
  <input
    ref={ref}
    type={type}
    className={cn(
      "h-10 w-full rounded-none border border-line-strong bg-ink px-3 text-[15px] text-paper placeholder:text-dim focus-visible:border-paper focus-visible:outline-none disabled:opacity-40",
      className,
    )}
    {...props}
  />
));
Input.displayName = "Input";

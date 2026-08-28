import { lazy, Suspense } from "react";
import type { AgentUiBlockReference } from "@/lib/ui-block";

const ControlledUiBlockContent = lazy(async () => {
  const module = await import("./ControlledUiBlock");
  return { default: module.ControlledUiBlock };
});

export function ControlledUiBlock({
  block,
  onConfirmReview,
}: {
  block: AgentUiBlockReference;
  onConfirmReview?: (reviewId: string) => Promise<void>;
}) {
  return (
    <Suspense fallback={<div className="controlled-card-loading">准备受控界面</div>}>
      <ControlledUiBlockContent block={block} onConfirmReview={onConfirmReview} />
    </Suspense>
  );
}

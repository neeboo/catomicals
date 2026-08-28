import { useEffect, useState } from "react";
import { IconAlertTriangle, IconRefresh } from "@tabler/icons-react";
import { requireDesktopBridge } from "@/lib/desktop";
import {
  loadControlledUiBlock,
  type AgentUiBlockReference,
} from "@/lib/ui-block";
import {
  ControlledSpecRenderer,
  buildHealthStatusSpec,
  buildReviewSpec,
} from "./ControlledJsonUi";

interface ControlledUiBlockProps {
  block: AgentUiBlockReference;
  onConfirmReview?: (reviewId: string) => Promise<void>;
}

export function ControlledUiBlock({ block, onConfirmReview }: ControlledUiBlockProps) {
  const [loaded, setLoaded] = useState<Awaited<ReturnType<typeof loadControlledUiBlock>> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);

  useEffect(() => {
    let active = true;
    setLoaded(null);
    setError(null);
    try {
      void loadControlledUiBlock(block, requireDesktopBridge()).then(
        (value) => { if (active) setLoaded(value); },
        (cause: unknown) => { if (active) setError(cause instanceof Error ? cause.message : "无法读取权威数据"); },
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "桌面宿主不可用");
    }
    return () => { active = false; };
  }, [block]);

  if (error) return <div className="controlled-card-error"><IconAlertTriangle size={14} />{error}</div>;
  if (!loaded) return <div className="controlled-card-loading"><IconRefresh className="spin" size={14} />读取权威数据</div>;
  if (loaded.kind === "health_status") {
    return <ControlledSpecRenderer spec={buildHealthStatusSpec(loaded.block.data_bindings[0].reference_id, loaded.health)} />;
  }

  async function confirm(reviewId: string) {
    if (!onConfirmReview) return;
    setConfirming(true);
    setError(null);
    try {
      await onConfirmReview(reviewId);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "确认失败");
    } finally {
      setConfirming(false);
    }
  }

  return (
    <ControlledSpecRenderer
      spec={buildReviewSpec(loaded.review, loaded.kind, confirming, !onConfirmReview)}
      onConfirmReview={(reviewId) => { void confirm(reviewId); }}
    />
  );
}

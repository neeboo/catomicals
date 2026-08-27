import { useEffect, useState } from "react";
import { IconAlertTriangle, IconCheck, IconRefresh } from "@tabler/icons-react";
import { pluginDisplayName, type PluginSettingsReview, type SettingsReviewChange } from "@/lib/cordis";
import { requireDesktopBridge } from "@/lib/desktop";
import {
  loadControlledUiBlock,
  type ControlledUiBlockDefinition,
} from "@/lib/ui-block";

interface ControlledUiBlockProps {
  block: ControlledUiBlockDefinition;
  onConfirmReview?: (reviewId: string) => Promise<void>;
}

function displayValue(value: string | boolean | number | null): string {
  if (value === null) return "未设置";
  if (typeof value === "boolean") return value ? "开启" : "关闭";
  return String(value);
}

function ChangeRow({ change }: { change: SettingsReviewChange }) {
  return (
    <div className="controlled-diff-row">
      <div><strong>{change.label}</strong><small>{change.restart === "none" ? "立即生效" : `需重启${change.restart === "desktop" ? "桌面端" : "插件"}`}</small></div>
      {"secretState" in change ? (
        <span>密钥引用：{change.secretState === "changed" ? "已更换" : change.secretState === "set" ? "已设置" : "已清除"}</span>
      ) : (
        <span><del>{displayValue(change.before)}</del><b>{displayValue(change.after)}</b></span>
      )}
    </div>
  );
}

function ReviewBlock({
  review,
  kind,
  onConfirmReview,
}: {
  review: PluginSettingsReview;
  kind: "plugin_settings_diff" | "review_card";
  onConfirmReview?: (reviewId: string) => Promise<void>;
}) {
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const expired = Date.parse(review.expiresAt) <= Date.now();
  const canConfirm = kind === "review_card" && review.state === "current" && !expired && onConfirmReview;

  async function confirm() {
    if (!canConfirm) return;
    setConfirming(true);
    setError(null);
    try {
      await onConfirmReview(review.reviewId);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "确认失败");
    } finally {
      setConfirming(false);
    }
  }

  return (
    <section className="controlled-card" data-kind={kind}>
      <header>
        <div><strong>{pluginDisplayName(review.pluginId)}</strong><span>配置审查</span></div>
        <small>{review.state === "stale" ? "已失效" : expired ? "已过期" : "等待确认"}</small>
      </header>
      <div className="controlled-diff-list">
        {review.changes.map((change) => <ChangeRow key={change.id} change={change} />)}
      </div>
      <footer>
        <span>影响：{review.restartImpact === "none" ? "无需重启" : review.restartImpact === "desktop" ? "重启桌面端" : "重启插件"} · 权限{review.permissionDelta.added.length || review.permissionDelta.removed.length ? "有变化" : "无变化"} · {new Date(review.expiresAt).toLocaleString()} 到期</span>
        {kind === "review_card" ? (
          <button type="button" disabled={!canConfirm || confirming} onClick={() => void confirm()}>
            {confirming ? <IconRefresh className="spin" size={13} /> : <IconCheck size={13} />}
            确认更改
          </button>
        ) : null}
      </footer>
      {error ? <p className="controlled-error"><IconAlertTriangle size={13} />{error}</p> : null}
    </section>
  );
}

export function ControlledUiBlock({ block, onConfirmReview }: ControlledUiBlockProps) {
  const [loaded, setLoaded] = useState<Awaited<ReturnType<typeof loadControlledUiBlock>> | null>(null);
  const [error, setError] = useState<string | null>(null);

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
    return (
      <section className="controlled-card" data-kind="health_status">
        <header><div><strong>{pluginDisplayName(loaded.block.data_bindings[0].reference_id)}</strong><span>运行状态</span></div><small>{loaded.health.status}</small></header>
        {loaded.health.message ? <p className="controlled-health-message">{loaded.health.message}</p> : null}
        {loaded.health.checkedAt ? <footer><span>检查于 {new Date(loaded.health.checkedAt).toLocaleString()}</span></footer> : null}
      </section>
    );
  }
  return <ReviewBlock review={loaded.review} kind={loaded.kind} onConfirmReview={onConfirmReview} />;
}

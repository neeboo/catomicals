import { createContext, useContext, type ReactNode } from "react";
import { defineCatalog, type Spec } from "@json-render/core";
import { defineRegistry, JSONUIProvider, Renderer } from "@json-render/react";
import { schema } from "@json-render/react/schema";
import { IconCheck, IconRefresh } from "@tabler/icons-react";
import { z } from "zod";
import {
  pluginDisplayName,
  type PluginHealthReport,
  type PluginSettingsReview,
} from "@/lib/cordis";

// Host-authoritative catalog: every element is built here from data the host
// read through the desktop bridge (readPluginHealth / readPluginSettingsReview).
// The catalog declares no actions, so an agent spec can never bind an action.
const controlledCatalog = defineCatalog(schema, {
  components: {
    Surface: {
      props: z.object({ kind: z.string() }),
      slots: ["default", "footer"],
      description: "A host-authoritative wallet status or review surface",
    },
    Header: {
      props: z.object({ title: z.string(), subtitle: z.string(), status: z.string() }),
      description: "The title and current state of a wallet surface",
    },
    Message: {
      props: z.object({ text: z.string() }),
      description: "A short host-authoritative status message",
    },
    Change: {
      props: z.object({
        label: z.string(),
        restart: z.string(),
        before: z.string(),
        after: z.string(),
        secret: z.boolean(),
      }),
      description: "A reviewed configuration change",
    },
    Meta: {
      props: z.object({ text: z.string() }),
      description: "Expiry, permission, or freshness metadata",
    },
    Confirm: {
      props: z.object({ label: z.string(), reviewId: z.string(), disabled: z.boolean(), loading: z.boolean() }),
      description: "A host-bound confirmation action",
    },
  },
  actions: {},
});

type ConfirmHandler = (reviewId: string) => void;
const ConfirmContext = createContext<ConfirmHandler | undefined>(undefined);

const { registry } = defineRegistry(controlledCatalog, {
  components: {
    Surface: ({ props, children, slots }) => (
      <section className="controlled-card" data-kind={props.kind} data-renderer="json-render">
        {children}
        {slots?.footer ? <footer>{slots.footer}</footer> : null}
      </section>
    ),
    Header: ({ props }) => (
      <header>
        <div><strong>{props.title}</strong><span>{props.subtitle}</span></div>
        <small>{props.status}</small>
      </header>
    ),
    Message: ({ props }) => <p className="controlled-health-message">{props.text}</p>,
    Change: ({ props }) => (
      <div className="controlled-diff-row">
        <div><strong>{props.label}</strong><small>{props.restart}</small></div>
        {props.secret ? (
          <span>{props.after}</span>
        ) : (
          <span><del>{props.before}</del><b>{props.after}</b></span>
        )}
      </div>
    ),
    Meta: ({ props }) => <span>{props.text}</span>,
    Confirm: ({ props }) => {
      const confirm = useContext(ConfirmContext);
      return (
        <button
          className="controlled-confirm"
          type="button"
          disabled={props.disabled || !confirm}
          onClick={() => confirm?.(props.reviewId)}
        >
          {props.loading ? <IconRefresh className="spin" size={13} /> : <IconCheck size={13} />}
          {props.label}
        </button>
      );
    },
  },
});

function displayValue(value: string | boolean | number | null): string {
  if (value === null) return "未设置";
  if (typeof value === "boolean") return value ? "开启" : "关闭";
  return String(value);
}

function restartLabel(restart: "none" | "plugin" | "desktop"): string {
  if (restart === "none") return "立即生效";
  return `需重启${restart === "desktop" ? "桌面端" : "插件"}`;
}

function reviewStatus(review: PluginSettingsReview): string {
  if (review.state === "stale") return "已失效";
  if (Date.parse(review.expiresAt) <= Date.now()) return "已过期";
  return "等待确认";
}

export function buildHealthStatusSpec(pluginId: string, health: PluginHealthReport): Spec {
  const children = ["header"];
  const footer: string[] = [];
  const elements: Spec["elements"] = {
    surface: { type: "Surface", props: { kind: "health_status" }, children },
    header: {
      type: "Header",
      props: { title: pluginDisplayName(pluginId), subtitle: "运行状态", status: health.status },
    },
  };
  if (health.message) {
    children.push("message");
    elements.message = { type: "Message", props: { text: health.message } };
  }
  if (health.checkedAt) {
    footer.push("meta");
    elements.meta = { type: "Meta", props: { text: `检查于 ${new Date(health.checkedAt).toLocaleString()}` } };
  }
  if (footer.length > 0) {
    elements.surface = { type: "Surface", props: { kind: "health_status" }, children, slots: { footer } };
  }
  return { root: "surface", elements };
}

export function buildReviewSpec(
  review: PluginSettingsReview,
  kind: "plugin_settings_diff" | "review_card",
  confirming: boolean,
  forceDisabled: boolean,
): Spec {
  const changeIds = review.changes.map((_, index) => `change-${index}`);
  const children = ["header", ...changeIds];
  const footer = ["meta"];
  const expired = Date.parse(review.expiresAt) <= Date.now();
  const disabled = forceDisabled || review.state !== "current" || expired;
  const elements: Spec["elements"] = {
    surface: { type: "Surface", props: { kind }, children, slots: { footer } },
    header: {
      type: "Header",
      props: { title: pluginDisplayName(review.pluginId), subtitle: "配置审查", status: reviewStatus(review) },
    },
    meta: {
      type: "Meta",
      props: {
        text: `影响：${restartLabel(review.restartImpact)} · 权限${review.permissionDelta.added.length || review.permissionDelta.removed.length ? "有变化" : "无变化"} · ${new Date(review.expiresAt).toLocaleString()} 到期`,
      },
    },
  };

  review.changes.forEach((change, index) => {
    const secret = "secretState" in change;
    elements[`change-${index}`] = {
      type: "Change",
      props: {
        label: change.label,
        restart: restartLabel(change.restart),
        before: secret ? "" : displayValue(change.before),
        after: secret
          ? `密钥引用：${change.secretState === "changed" ? "已更换" : change.secretState === "set" ? "已设置" : "已清除"}`
          : displayValue(change.after),
        secret,
      },
    };
  });

  if (kind === "review_card") {
    footer.push("confirm");
    elements.confirm = {
      type: "Confirm",
      props: { label: "确认更改", reviewId: review.reviewId, disabled: disabled || confirming, loading: confirming },
    };
  }
  return { root: "surface", elements };
}

export function ControlledSpecRenderer({
  spec,
  onConfirmReview,
}: {
  spec: Spec;
  onConfirmReview?: ConfirmHandler;
}) {
  return (
    <ConfirmContext.Provider value={onConfirmReview}>
      <JSONUIProvider registry={registry}>
        <Renderer spec={spec} registry={registry} />
      </JSONUIProvider>
    </ConfirmContext.Provider>
  );
}

export function ControlledUiError({ children }: { children: ReactNode }) {
  return <p className="controlled-error">{children}</p>;
}

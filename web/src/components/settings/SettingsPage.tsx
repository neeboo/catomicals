import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "@tanstack/react-router";
import {
  IconAgentPresetOutline16,
  IconChevronLeftOutline14,
  IconDataOutline16,
  IconEnhanceOutline16,
  IconPersonalizationOutline16,
  IconRefreshOutline16,
  IconSearchOutline16,
} from "@/components/icons";
import { ControlledUiBlock } from "@/components/controlled-ui/LazyControlledUiBlock";
import {
  buildSettingsPatch,
  pluginCategories,
  pluginCategory,
  pluginDisplayName,
  settingChoiceLabel,
  settingsDraft,
  type CordisSettingValue,
  type PluginCategoryId,
  type PluginHealthReport,
  type PluginListEntry,
  type PluginSettingsFieldMetadata,
  type PluginSettingsView,
} from "@/lib/cordis";
import { requireDesktopBridge } from "@/lib/desktop";
import {
  useCredentialsQuery,
  useNodeStatusQuery,
  useSignerStatusQuery,
  useWalletStatusQuery,
} from "@/lib/hooks";
import { createReviewCardBlock } from "@/lib/ui-block";

type SettingsDraft = Record<string, CordisSettingValue | "">;

/** Per-category nav glyphs — the same assignments DeepSeek Harness' settings
    rail uses (ui-settings-general SettingsRoot navIcon). */
const categoryIcons: Record<PluginCategoryId, typeof IconDataOutline16> = {
  "wallet-security": IconAgentPresetOutline16,
  "network-data": IconDataOutline16,
  agents: IconPersonalizationOutline16,
  "interface-tools": IconEnhanceOutline16,
};

/**
 * Compact live status on the two status-bearing menu entries, per the shell
 * contract: node + CAT belong on 网络与数据, FROST + Passkey on 钱包与安全.
 * Healthy state is a quiet dot and a short count; abnormal state warns with a
 * short reason. Full details stay inside the opened panel.
 */
function CategoryStatus({ categoryId }: { categoryId: PluginCategoryId }) {
  const node = useNodeStatusQuery();
  const wallet = useWalletStatusQuery();
  const signer = useSignerStatusQuery();
  const credentials = useCredentialsQuery();

  if (categoryId === "network-data") {
    const nodeOk = node.isSuccess;
    const network = node.data?.network ?? "signet";
    const cat = wallet.data?.node?.op_cat_active;
    const warn = !nodeOk || cat !== true;
    return (
      <span className="settings-category-status" data-health={warn ? "warn" : "ok"}>
        <span className="status-dot" aria-hidden="true" />
        {!nodeOk ? "节点离线" : cat === true ? `${network} · CAT` : `${network} · CAT 未激活`}
      </span>
    );
  }
  if (categoryId === "wallet-security") {
    const configured = signer.data?.configured ?? false;
    const threshold = configured
      ? `${signer.data?.min_signers}/${wallet.data?.threshold.max_signers ?? "?"}`
      : "未配置";
    const passkeys = credentials.data?.length ?? 0;
    return (
      <span className="settings-category-status" data-health={configured ? "ok" : "warn"}>
        <span className="status-dot" aria-hidden="true" />
        {configured ? `${threshold} · ${passkeys}` : "FROST 未配置"}
      </span>
    );
  }
  return null;
}

function SettingsField({
  field,
  value,
  secretState,
  onChange,
}: {
  field: PluginSettingsFieldMetadata;
  value: CordisSettingValue | "" | undefined;
  secretState?: "unset" | "set";
  onChange: (value: CordisSettingValue | "") => void;
}) {
  if (field.type === "boolean") {
    return (
      <label className="settings-toggle-row">
        <span><strong>{field.label}</strong><small>{field.restart === "none" ? "立即生效" : "需要重启插件"}</small></span>
        <input type="checkbox" checked={value === true} onChange={(event) => onChange(event.target.checked)} />
      </label>
    );
  }

  const inputValue = typeof value === "string" || typeof value === "number" ? value : "";
  return (
    <label className="settings-field-row">
      <span><strong>{field.label}</strong><small>{field.secretReference ? `当前：${secretState === "set" ? "已设置" : "未设置"}` : field.restart === "none" ? "立即生效" : "需要重启"}</small></span>
      {field.choices ? (
        <select value={String(inputValue)} onChange={(event) => onChange(event.target.value)}>
          {field.choices.map((choice) => <option key={choice} value={choice}>{settingChoiceLabel(choice)}</option>)}
        </select>
      ) : field.control === "textarea" ? (
        <textarea
          value={String(inputValue)}
          maxLength={field.maxLength}
          rows={5}
          onChange={(event) => onChange(event.target.value)}
        />
      ) : (
        <input
          type={field.secretReference ? "password" : field.type === "integer" ? "number" : "text"}
          value={inputValue}
          min={field.minimum}
          max={field.maximum}
          placeholder={field.secretReference ? "输入新的密钥引用" : undefined}
          onChange={(event) => onChange(field.type === "integer"
            ? event.target.value === "" ? null : Number(event.target.value)
            : event.target.value)}
        />
      )}
    </label>
  );
}

export function SettingsPage() {
  const [plugins, setPlugins] = useState<PluginListEntry[]>([]);
  const [selectedPluginId, setSelectedPluginId] = useState<string | null>(null);
  const [settings, setSettings] = useState<PluginSettingsView | null>(null);
  const [health, setHealth] = useState<PluginHealthReport | null>(null);
  const [draft, setDraft] = useState<SettingsDraft>({});
  const [reviewId, setReviewId] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const loadSequence = useRef(0);

  useEffect(() => {
    let active = true;
    let bridge;
    try {
      bridge = requireDesktopBridge();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "桌面宿主不可用");
      setLoading(false);
      return () => { active = false; };
    }
    void bridge.listPlugins().then(
      (items) => {
        if (!active) return;
        setPlugins(items);
        setSelectedPluginId((current) => current ?? items[0]?.pluginId ?? null);
        setLoading(false);
      },
      (cause: unknown) => {
        if (!active) return;
        setError(cause instanceof Error ? cause.message : "无法读取插件目录");
        setLoading(false);
      },
    );
    return () => { active = false; };
  }, []);

  const loadSelected = useCallback(async (pluginId: string) => {
    const sequence = ++loadSequence.current;
    setLoading(true);
    setError(null);
    setReviewId(null);
    try {
      const bridge = requireDesktopBridge();
      const [view, report] = await Promise.all([
        bridge.readPluginSettings(pluginId),
        bridge.readPluginHealth(pluginId),
      ]);
      if (sequence !== loadSequence.current) return;
      setSettings(view);
      setDraft(settingsDraft(view));
      setHealth(report);
    } catch (cause) {
      if (sequence !== loadSequence.current) return;
      setSettings(null);
      setHealth(null);
      setError(cause instanceof Error ? cause.message : "无法读取插件设置");
    } finally {
      if (sequence === loadSequence.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!selectedPluginId) return;
    void loadSelected(selectedPluginId);
  }, [loadSelected, selectedPluginId]);

  const visiblePlugins = useMemo(() => {
    const query = search.trim().toLowerCase();
    return query
      ? plugins.filter((plugin) => `${pluginDisplayName(plugin.pluginId)} ${plugin.pluginId}`.toLowerCase().includes(query))
      : plugins;
  }, [plugins, search]);
  const visiblePluginGroups = useMemo(() => pluginCategories.map((category) => ({
    ...category,
    plugins: visiblePlugins.filter((plugin) => pluginCategory(plugin.pluginId) === category.id),
  })).filter((category) => category.plugins.length > 0), [visiblePlugins]);

  const patch = settings ? buildSettingsPatch(settings, draft) : null;
  const reviewBlock = useMemo(() => reviewId ? createReviewCardBlock(reviewId) : null, [reviewId]);

  async function createReview() {
    if (!settings || !patch || patch.changes.length === 0) return;
    setSaving(true);
    setError(null);
    try {
      const bridge = requireDesktopBridge();
      const validation = await bridge.validatePluginSettings(settings.pluginId, patch);
      if (!validation.valid) throw new Error(validation.error ?? "设置未通过检查");
      const review = await bridge.createPluginSettingsIntent(settings.pluginId, patch);
      setReviewId(review.reviewId);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "无法创建设置审查");
    } finally {
      setSaving(false);
    }
  }

  async function confirmReview(authoritativeReviewId: string) {
    const bridge = requireDesktopBridge();
    const review = await bridge.readPluginSettingsReview(authoritativeReviewId);
    if (review.state !== "current" || Date.parse(review.expiresAt) <= Date.now()) throw new Error("设置审查已经失效");
    await bridge.confirmPluginSettingsIntent(review.reviewId);
    setReviewId(null);
    if (selectedPluginId) await loadSelected(selectedPluginId);
  }

  return (
    <div className="app-frame">
      <div className="settings-shell">
        <aside className="settings-sidebar">
          <Link className="settings-back" to="/"><IconChevronLeftOutline14 size={14} />返回钱包</Link>
          <label className="settings-search"><IconSearchOutline16 size={14} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="搜索设置" /></label>
          <nav aria-label="插件设置">
            {visiblePluginGroups.map((category) => {
              const CategoryIcon = categoryIcons[category.id];
              return (
                <section className="settings-nav-group" key={category.id} aria-labelledby={`settings-group-${category.id}`}>
                  <h2 id={`settings-group-${category.id}`}><CategoryIcon size={14} aria-hidden="true" />{category.label}<CategoryStatus categoryId={category.id} /></h2>
                  {category.plugins.map((plugin) => (
                    <button key={plugin.pluginId} type="button" data-active={selectedPluginId === plugin.pluginId} onClick={() => setSelectedPluginId(plugin.pluginId)}>
                      <span>{pluginDisplayName(plugin.pluginId)}</span><small data-status={plugin.status}>{plugin.status === "ready" ? "就绪" : "隔离"}</small>
                    </button>
                  ))}
                </section>
              );
            })}
          </nav>
        </aside>
        <main className="settings-content">
          <div className="settings-content-width">
            <header className="settings-title">
              <div><h1>{selectedPluginId ? pluginDisplayName(selectedPluginId) : "设置"}</h1><p>{selectedPluginId}</p></div>
              {health ? <span data-health={health.status}>{health.status === "healthy" ? "运行正常" : health.status}</span> : null}
            </header>
            {loading ? <div className="settings-loading"><IconRefreshOutline16 className="spin" size={15} />读取配置</div> : null}
            {error ? <p className="settings-error">{error}</p> : null}
            {settings && !loading ? (
              <section className="settings-card">
                <header><div><strong>当前配置</strong><small>版本 {settings.pluginVersion}</small></div><code>{settings.settingsDigest.slice(0, 18)}…</code></header>
                <div className="settings-fields">
                  {settings.schema.fields.map((field) => (
                    <SettingsField
                      key={field.id}
                      field={field}
                      value={draft[field.id]}
                      secretState={settings.secretStates[field.id]}
                      onChange={(value) => setDraft((current) => ({ ...current, [field.id]: value }))}
                    />
                  ))}
                </div>
                <footer><span>更改会先生成审查，不会直接覆盖当前配置。</span><button type="button" disabled={saving || !patch?.changes.length || reviewId !== null} onClick={() => void createReview()}>{saving ? "检查中" : "创建审查"}</button></footer>
              </section>
            ) : null}
            {reviewBlock ? <ControlledUiBlock block={reviewBlock} onConfirmReview={confirmReview} /> : null}
          </div>
        </main>
      </div>
    </div>
  );
}

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "@tanstack/react-router";
import { IconArrowLeft, IconRefresh, IconSearch } from "@tabler/icons-react";
import { ControlledUiBlock } from "@/components/controlled-ui/ControlledUiBlock";
import {
  buildSettingsPatch,
  pluginDisplayName,
  settingsDraft,
  type CordisSettingValue,
  type PluginHealthReport,
  type PluginListEntry,
  type PluginSettingsFieldMetadata,
  type PluginSettingsView,
} from "@/lib/cordis";
import { requireDesktopBridge } from "@/lib/desktop";
import { createReviewCardBlock } from "@/lib/ui-block";

type SettingsDraft = Record<string, CordisSettingValue | "">;

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
          {field.choices.map((choice) => <option key={choice} value={choice}>{choice}</option>)}
        </select>
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
    <div className="settings-shell">
      <aside className="settings-sidebar">
        <Link className="settings-back" to="/"><IconArrowLeft size={15} />返回钱包</Link>
        <label className="settings-search"><IconSearch size={14} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="搜索设置" /></label>
        <div className="settings-nav-title">插件</div>
        <nav aria-label="插件设置">
          {visiblePlugins.map((plugin) => (
            <button key={plugin.pluginId} type="button" data-active={selectedPluginId === plugin.pluginId} onClick={() => setSelectedPluginId(plugin.pluginId)}>
              <span>{pluginDisplayName(plugin.pluginId)}</span><small data-status={plugin.status}>{plugin.status === "ready" ? "就绪" : "隔离"}</small>
            </button>
          ))}
        </nav>
      </aside>
      <main className="settings-content">
        <div className="settings-content-width">
          <header className="settings-title">
            <div><h1>{selectedPluginId ? pluginDisplayName(selectedPluginId) : "设置"}</h1><p>{selectedPluginId}</p></div>
            {health ? <span data-health={health.status}>{health.status === "healthy" ? "运行正常" : health.status}</span> : null}
          </header>
          {loading ? <div className="settings-loading"><IconRefresh className="spin" size={15} />读取配置</div> : null}
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
  );
}

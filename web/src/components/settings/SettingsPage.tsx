import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "@tanstack/react-router";
import {
  IconChevronLeftOutline14,
  IconRefreshOutline16,
  IconSearchOutline16,
} from "@/components/icons";
import { ControlledUiBlock } from "@/components/controlled-ui/LazyControlledUiBlock";
import {
  buildSettingsPatch,
  pluginCapabilitySummary,
  pluginDisplayName,
  settingChoiceLabel,
  settingsDraft,
  supportedChains,
  type CordisSettingValue,
  type CordisSettingsPatch,
  type PluginHealthReport,
  type PluginListEntry,
  type PluginSettingsFieldMetadata,
  type PluginSettingsView,
} from "@/lib/cordis";
import { requireDesktopBridge } from "@/lib/desktop";
import { createReviewCardBlock } from "@/lib/ui-block";

type SettingsDraft = Record<string, CordisSettingValue | "">;
type SettingsSectionId = "general" | "models" | "plugins" | "agent-presets";

const settingsSections: readonly {
  id: SettingsSectionId;
  label: string;
  description: string;
  pluginIds: readonly string[];
}[] = [
  {
    id: "general",
    label: "通用设置",
    description: "钱包、MCP 与桌面能力",
    pluginIds: [
      "@catomicals/plugin-walletd",
      "@catomicals/plugin-mcp",
      "@catomicals/plugin-browser",
      "@catomicals/plugin-backup",
    ],
  },
  {
    id: "models",
    label: "模型",
    description: "执行器、默认模型与推理强度",
    pluginIds: [
      "@catomicals/plugin-executor-codex",
      "@catomicals/plugin-executor-deepseek",
      "@catomicals/plugin-executor-claude-code",
    ],
  },
  {
    id: "plugins",
    label: "插件",
    description: "链与 RPC 扩展",
    pluginIds: supportedChains.map((chain) => chain.pluginId),
  },
  {
    id: "agent-presets",
    label: "Agent 预设",
    description: "生成式界面与输出规范",
    pluginIds: ["@catomicals/plugin-generative-ui"],
  },
];

const settingsPluginIds: ReadonlySet<string> = new Set(settingsSections.flatMap((section) => section.pluginIds));

const settingDescriptions: Readonly<Record<string, string>> = Object.freeze({
  "@catomicals/plugin-walletd": "钱包节点地址与进程模式",
  "@catomicals/plugin-mcp": "Agent 使用的钱包与配置工具",
  "@catomicals/plugin-browser": "内置浏览器默认页面",
  "@catomicals/plugin-backup": "备份目录、计划与保留策略",
  "@catomicals/plugin-executor-codex": "Codex 命令、模型与推理强度",
  "@catomicals/plugin-executor-deepseek": "DeepSeek Harness 命令、模型与推理强度",
  "@catomicals/plugin-executor-claude-code": "Claude Code 命令、模型与推理强度",
  "@catomicals/plugin-generative-ui": "组件输出偏好与 Agent 生成规范",
});

const manualRpcFields = new Set(["transport", "endpoint", "networkAccess", "credentialRef"]);

function visibleSettingsFields(view: PluginSettingsView, draft: SettingsDraft): readonly PluginSettingsFieldMetadata[] {
  const preset = draft.nodeSource === "preset";
  return view.schema.fields.filter((field) => field.id !== "enabled" && !(preset && manualRpcFields.has(field.id)));
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
      <span>
        <strong>{field.label}</strong>
        <small>{field.secretReference
          ? `当前：${secretState === "set" ? "已设置" : "未设置"}`
          : field.restart === "none" ? "立即生效" : "需要重启"}</small>
      </span>
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

function pluginEnabled(plugin: PluginListEntry): boolean {
  return plugin.enabled ?? true;
}

function healthPresentation(plugin: PluginListEntry, health: PluginHealthReport | undefined) {
  if (!pluginEnabled(plugin)) return { label: "已停用", state: "disabled" } as const;
  if (plugin.status === "isolated") return { label: "已隔离", state: "unhealthy" } as const;
  switch (health?.status) {
    case "healthy": return { label: "运行正常", state: "healthy" } as const;
    case "degraded": return { label: "需要检查", state: "degraded" } as const;
    case "unhealthy": return { label: "不可用", state: "unhealthy" } as const;
    case "isolated": return { label: "已隔离", state: "unhealthy" } as const;
    case "disabled": return { label: "已停用", state: "disabled" } as const;
    default: return { label: "未检查", state: "unknown" } as const;
  }
}

function checkedAtLabel(plugin: PluginListEntry, health: PluginHealthReport | undefined): string {
  if (!pluginEnabled(plugin) || !health?.checkedAt) return "最后检查 —";
  const date = new Date(health.checkedAt);
  if (Number.isNaN(date.getTime())) return "最后检查 —";
  return `最后检查 ${new Intl.DateTimeFormat("zh-CN", {
    month: "numeric",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date)}`;
}

export function SettingsPage() {
  const [plugins, setPlugins] = useState<PluginListEntry[]>([]);
  const [healthByPlugin, setHealthByPlugin] = useState<Record<string, PluginHealthReport>>({});
  const [settingsByPlugin, setSettingsByPlugin] = useState<Record<string, PluginSettingsView>>({});
  const [selectedSection, setSelectedSection] = useState<SettingsSectionId>("general");
  const [expandedPluginId, setExpandedPluginId] = useState<string | null>(null);
  const [settings, setSettings] = useState<PluginSettingsView | null>(null);
  const [draft, setDraft] = useState<SettingsDraft>({});
  const [reviewId, setReviewId] = useState<string | null>(null);
  const [reviewPluginId, setReviewPluginId] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [loadingPluginId, setLoadingPluginId] = useState<string | null>(null);
  const [savingPluginId, setSavingPluginId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const loadSequence = useRef(0);

  const loadPlugins = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const bridge = requireDesktopBridge();
      const catalog = await bridge.listPlugins();
      const byId = new Map(catalog.filter((plugin) => settingsPluginIds.has(plugin.pluginId)).map((plugin) => [plugin.pluginId, plugin]));
      const items = settingsSections.flatMap((section) => section.pluginIds.flatMap((pluginId) => {
        const plugin = byId.get(pluginId);
        return plugin ? [plugin] : [];
      }));
      const states = await Promise.all(items.map(async (plugin) => {
        const [health, pluginSettings] = await Promise.all([
          bridge.readPluginHealth(plugin.pluginId).catch(() => undefined),
          bridge.readPluginSettings(plugin.pluginId).catch(() => undefined),
        ]);
        return { pluginId: plugin.pluginId, health, settings: pluginSettings };
      }));
      setPlugins(items);
      setHealthByPlugin(Object.fromEntries(
        states.filter((entry) => Boolean(entry.health)).map((entry) => [entry.pluginId, entry.health as PluginHealthReport]),
      ));
      setSettingsByPlugin(Object.fromEntries(
        states.filter((entry) => Boolean(entry.settings)).map((entry) => [entry.pluginId, entry.settings as PluginSettingsView]),
      ));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "无法读取插件目录");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadPlugins();
  }, [loadPlugins]);

  const loadSettings = useCallback(async (pluginId: string): Promise<PluginSettingsView | null> => {
    const sequence = ++loadSequence.current;
    setLoadingPluginId(pluginId);
    setError(null);
    try {
      const view = await requireDesktopBridge().readPluginSettings(pluginId);
      if (sequence !== loadSequence.current) return null;
      setSettings(view);
      setSettingsByPlugin((current) => ({ ...current, [pluginId]: view }));
      setDraft(settingsDraft(view));
      return view;
    } catch (cause) {
      if (sequence !== loadSequence.current) return null;
      setSettings(null);
      setDraft({});
      setError(cause instanceof Error ? cause.message : "无法读取插件设置");
      return null;
    } finally {
      if (sequence === loadSequence.current) setLoadingPluginId(null);
    }
  }, []);

  const activeSection = settingsSections.find((section) => section.id === selectedSection) ?? settingsSections[0];
  const sectionPlugins = useMemo(() => {
    const byId = new Map(plugins.map((plugin) => [plugin.pluginId, plugin]));
    return activeSection.pluginIds.flatMap((pluginId) => {
      const plugin = byId.get(pluginId);
      return plugin ? [plugin] : [];
    });
  }, [activeSection, plugins]);

  const visiblePlugins = useMemo(() => {
    const query = search.trim().toLocaleLowerCase();
    return sectionPlugins.filter((plugin) => {
      if (!query) return true;
      const summary = pluginCapabilitySummary(plugin, settingsByPlugin[plugin.pluginId]);
      return [pluginDisplayName(plugin.pluginId), plugin.pluginId, settingDescriptions[plugin.pluginId], summary.chainLabel, summary.network]
        .filter(Boolean)
        .join(" ")
        .toLocaleLowerCase()
        .includes(query);
    });
  }, [search, sectionPlugins, settingsByPlugin]);

  const visiblePluginGroups = visiblePlugins.length > 0
    ? [{ id: selectedSection, label: selectedSection === "plugins" ? "链插件" : activeSection.label, plugins: visiblePlugins }]
    : [];

  const installedPluginIds = useMemo(() => new Set(plugins.map((plugin) => plugin.pluginId)), [plugins]);
  const patch = settings ? buildSettingsPatch(settings, draft) : null;
  const reviewBlock = useMemo(() => reviewId ? createReviewCardBlock(reviewId) : null, [reviewId]);

  async function toggleExpanded(pluginId: string) {
    if (expandedPluginId === pluginId) {
      setExpandedPluginId(null);
      setSettings(null);
      setDraft({});
      return;
    }
    setExpandedPluginId(pluginId);
    await loadSettings(pluginId);
  }

  function selectSection(sectionId: SettingsSectionId) {
    setSelectedSection(sectionId);
    setExpandedPluginId(null);
    setSettings(null);
    setDraft({});
    setSearch("");
    setError(null);
  }

  async function createReviewFor(pluginId: string, view: PluginSettingsView, candidatePatch: CordisSettingsPatch) {
    setSavingPluginId(pluginId);
    setError(null);
    try {
      const bridge = requireDesktopBridge();
      const validation = await bridge.validatePluginSettings(pluginId, candidatePatch);
      if (!validation.valid) throw new Error(validation.error ?? "设置未通过检查");
      const review = await bridge.createPluginSettingsIntent(pluginId, candidatePatch);
      setReviewId(review.reviewId);
      setReviewPluginId(pluginId);
      setExpandedPluginId(pluginId);
      setSettings(view);
      setDraft(settingsDraft(view));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "无法创建设置审查");
    } finally {
      setSavingPluginId(null);
    }
  }

  async function stageEnabledToggle(plugin: PluginListEntry) {
    const view = settings?.pluginId === plugin.pluginId
      ? settings
      : await loadSettings(plugin.pluginId);
    if (!view || reviewId) return;
    const enabledField = view.schema.fields.find((field) => field.id === "enabled" && field.type === "boolean");
    if (!enabledField) {
      setError(`${pluginDisplayName(plugin.pluginId)} 没有可审查的启停设置`);
      return;
    }
    const current = typeof view.settings.enabled === "boolean" ? view.settings.enabled : pluginEnabled(plugin);
    await createReviewFor(plugin.pluginId, view, {
      schemaVersion: view.settingsSchemaVersion,
      changes: [{ id: "enabled", value: !current }],
    });
  }

  async function createReview() {
    if (!settings || !patch || patch.changes.length === 0) return;
    await createReviewFor(settings.pluginId, settings, patch);
  }

  async function confirmReview(authoritativeReviewId: string) {
    const bridge = requireDesktopBridge();
    const review = await bridge.readPluginSettingsReview(authoritativeReviewId);
    if (review.state !== "current" || Date.parse(review.expiresAt) <= Date.now()) throw new Error("设置审查已经失效");
    await bridge.confirmPluginSettingsIntent(review.reviewId);
    const affectedPluginId = reviewPluginId;
    setReviewId(null);
    setReviewPluginId(null);
    await loadPlugins();
    if (affectedPluginId && expandedPluginId === affectedPluginId) await loadSettings(affectedPluginId);
  }

  return (
    <div className="app-frame">
      <div className="settings-shell">
        <aside className="settings-sidebar">
          <Link className="settings-back" to="/"><IconChevronLeftOutline14 size={14} />返回钱包</Link>
          <label className="settings-search">
            <IconSearchOutline16 size={14} />
            <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="搜索设置" />
          </label>
          <nav aria-label="设置分类">
            {settingsSections.map((section) => {
              const count = plugins.filter((plugin) => section.pluginIds.includes(plugin.pluginId)).length;
              return (
                <button
                  key={section.id}
                  type="button"
                  aria-label={section.label}
                  data-active={selectedSection === section.id}
                  onClick={() => selectSection(section.id)}
                >
                  <span>{section.label}</span><small>{count}</small>
                </button>
              );
            })}
          </nav>
        </aside>

        <main className="settings-content">
          <div className="settings-content-width settings-plugin-catalog">
            <header className="settings-title">
              <div><h1>{activeSection.label}</h1><p>{activeSection.description}</p></div>
            </header>

            {selectedSection === "plugins" ? <section className="settings-chain-overview" aria-label="支持的链">
              {supportedChains.map((chain) => (
                <span key={chain.id} data-installed={installedPluginIds.has(chain.pluginId)}>
                  <i aria-hidden="true" />{chain.label}
                </span>
              ))}
            </section> : null}

            {loading ? <div className="settings-loading"><IconRefreshOutline16 className="spin" size={15} />读取插件</div> : null}
            {error ? <p className="settings-error">{error}</p> : null}
            {reviewId ? <p className="settings-review-notice">设置变更已进入审查，确认后生效。</p> : null}
            {reviewBlock ? <ControlledUiBlock block={reviewBlock} onConfirmReview={confirmReview} /> : null}

            {!loading ? visiblePluginGroups.map((category) => (
              <section className="settings-plugin-group" key={category.id} aria-labelledby={`plugin-group-${category.id}`}>
                <header><h2 id={`plugin-group-${category.id}`}>{category.label}</h2><span>{category.plugins.length}</span></header>
                <div className="settings-plugin-list">
                  {category.plugins.map((plugin) => {
                    const name = pluginDisplayName(plugin.pluginId);
                    const enabled = pluginEnabled(plugin);
                    const summary = pluginCapabilitySummary(plugin, settingsByPlugin[plugin.pluginId]);
                    const health = healthByPlugin[plugin.pluginId];
                    const healthView = healthPresentation(plugin, health);
                    const expanded = expandedPluginId === plugin.pluginId;
                    const busy = savingPluginId === plugin.pluginId || loadingPluginId === plugin.pluginId;
                    const enabledField = settingsByPlugin[plugin.pluginId]?.schema.fields.find((field) => field.id === "enabled" && field.type === "boolean");
                    return (
                      <article className="settings-plugin-row" data-enabled={enabled} data-testid={`plugin-row-${plugin.pluginId}`} key={plugin.pluginId}>
                        <div className="settings-plugin-summary" data-kind={selectedSection === "plugins" ? "plugin" : "setting"}>
                          <div className="settings-plugin-identity">
                            <h2>{name}</h2>
                            {selectedSection === "plugins"
                              ? <code>{plugin.pluginId}</code>
                              : <p>{settingDescriptions[plugin.pluginId]}</p>}
                          </div>
                          {selectedSection === "plugins" ? <div className="settings-plugin-facts">
                            <span><small>链 / 网络</small><strong>{summary.chainLabel ?? "通用"}{summary.network ? ` · ${summary.network}` : ""}</strong></span>
                            <span><small>能力</small><strong>{summary.capabilityLabel}</strong></span>
                            <span><small>访问</small><strong>{summary.permissionLabel}{summary.networkAccessLabel ? ` · ${summary.networkAccessLabel}` : ""}</strong></span>
                            <span><small>端点</small><strong title={summary.endpoint}>{summary.endpoint ?? "本机"}</strong></span>
                            <span><small>验证</small><strong>{summary.verificationLabel}</strong></span>
                          </div> : null}
                          <div className="settings-plugin-state">
                            <span className="settings-plugin-health" data-health={healthView.state}><i aria-hidden="true" />{healthView.label}</span>
                            <small>{checkedAtLabel(plugin, health)}</small>
                          </div>
                          <div className="settings-plugin-actions">
                            {enabledField ? <button
                              type="button"
                              className="settings-plugin-toggle"
                              role="switch"
                              aria-checked={enabled}
                              aria-label={`${enabled ? "停用" : "启用"} ${name}`}
                              disabled={busy || reviewId !== null}
                              onClick={() => void stageEnabledToggle(plugin)}
                            ><span aria-hidden="true" /></button> : null}
                            <button
                              type="button"
                              className="settings-plugin-config-toggle"
                              aria-expanded={expanded}
                              aria-label={`配置 ${name}`}
                              onClick={() => void toggleExpanded(plugin.pluginId)}
                            >配置<span aria-hidden="true">›</span></button>
                          </div>
                        </div>

                        {expanded ? (
                          <div className="settings-plugin-config">
                            {loadingPluginId === plugin.pluginId ? (
                              <div className="settings-config-loading"><IconRefreshOutline16 className="spin" size={14} />读取配置</div>
                            ) : settings?.pluginId === plugin.pluginId ? (
                              <>
                                <header><code>{settings.pluginId}</code><span>版本 {settings.pluginVersion}</span></header>
                                <div className="settings-fields">
                                  {visibleSettingsFields(settings, draft).map((field) => (
                                    <SettingsField
                                      key={field.id}
                                      field={field}
                                      value={draft[field.id]}
                                      secretState={settings.secretStates[field.id]}
                                      onChange={(value) => setDraft((current) => ({ ...current, [field.id]: value }))}
                                    />
                                  ))}
                                  {visibleSettingsFields(settings, draft).length === 0
                                    ? <p className="settings-empty-config">此插件没有额外配置。</p>
                                    : null}
                                </div>
                                <footer>
                                  <span>所有改动都要先审查。</span>
                                  <button type="button" disabled={busy || !patch?.changes.length || reviewId !== null} onClick={() => void createReview()}>
                                    {savingPluginId === plugin.pluginId ? "检查中" : "创建审查"}
                                  </button>
                                </footer>
                              </>
                            ) : null}
                          </div>
                        ) : null}
                      </article>
                    );
                  })}
                </div>
              </section>
            )) : null}

            {!loading && visiblePlugins.length === 0 ? <p className="settings-empty">没有匹配的插件。</p> : null}
          </div>
        </main>
      </div>
    </div>
  );
}

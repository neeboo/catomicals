import { useCallback, useEffect, useMemo, useRef, useState, type MouseEvent } from "react";
import { createPortal } from "react-dom";
import { Link } from "@tanstack/react-router";
import {
  IconChevronLeftOutline14,
  IconCloseOutline16,
  IconRefreshOutline16,
  IconSearchOutline16,
} from "@/components/icons";
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

function walletSignerFieldLocked(pluginId: string, fieldId: string): boolean {
  return pluginId === "@catomicals/plugin-walletd" && (fieldId === "signerProtocol" || fieldId === "signingRounds");
}

function visibleSettingsFields(view: PluginSettingsView, draft: SettingsDraft): readonly PluginSettingsFieldMetadata[] {
  const preset = draft.nodeSource === "preset";
  return view.schema.fields.filter((field) => field.id !== "enabled" && !(preset && manualRpcFields.has(field.id)));
}

function SettingsField({
  pluginId,
  field,
  value,
  secretState,
  onChange,
}: {
  pluginId: string;
  field: PluginSettingsFieldMetadata;
  value: CordisSettingValue | "" | undefined;
  secretState?: "unset" | "set";
  onChange: (value: CordisSettingValue | "") => void;
}) {
  const locked = walletSignerFieldLocked(pluginId, field.id);
  if (field.type === "boolean") {
    return (
      <label className="settings-toggle-row">
        <span><strong>{field.label}</strong><small>{field.restart === "none" ? "立即生效" : "需要重启插件"}</small></span>
        <input type="checkbox" checked={value === true} disabled={locked} onChange={(event) => onChange(event.target.checked)} />
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
          : locked ? "固定值"
          : field.restart === "none" ? "立即生效" : "需要重启"}</small>
      </span>
      {field.choices ? (
        <select value={String(inputValue)} disabled={locked} onChange={(event) => onChange(event.target.value)}>
          {field.choices.map((choice) => <option key={choice} value={choice}>{settingChoiceLabel(choice)}</option>)}
        </select>
      ) : field.control === "textarea" ? (
        <textarea
          value={String(inputValue)}
          maxLength={field.maxLength}
          rows={5}
          readOnly={locked}
          onChange={(event) => onChange(event.target.value)}
        />
      ) : (
        <input
          type={field.secretReference ? "password" : field.type === "integer" ? "number" : "text"}
          value={inputValue}
          min={field.minimum}
          max={field.maximum}
          readOnly={locked}
          disabled={locked}
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

function SettingsConfigurationDialog({
  pluginId,
  settings,
  draft,
  loading,
  saving,
  error,
  canSave,
  onChange,
  onClose,
  onSave,
}: {
  pluginId: string;
  settings: PluginSettingsView | null;
  draft: SettingsDraft;
  loading: boolean;
  saving: boolean;
  error: string | null;
  canSave: boolean;
  onChange: (fieldId: string, value: CordisSettingValue | "") => void;
  onClose: () => void;
  onSave: () => void;
}) {
  const closeRef = useRef<HTMLButtonElement>(null);
  const dialogRef = useRef<HTMLElement>(null);
  const name = pluginDisplayName(pluginId);

  useEffect(() => {
    const returnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    closeRef.current?.focus();

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape" && !saving) {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== "Tab") return;
      const controls = Array.from(dialogRef.current?.querySelectorAll<HTMLElement>(
        "button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled)",
      ) ?? []);
      const first = controls[0];
      const last = controls.at(-1);
      if (!first || !last) return;
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }

    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      returnFocus?.focus();
    };
  }, [onClose, saving]);

  function closeFromBackdrop(event: MouseEvent<HTMLDivElement>) {
    if (event.target === event.currentTarget && !saving) onClose();
  }

  const fields = settings ? visibleSettingsFields(settings, draft) : [];
  return (
    <div className="settings-dialog-backdrop" onMouseDown={closeFromBackdrop}>
      <section
        ref={dialogRef}
        className="settings-dialog"
        role="dialog"
        aria-modal="true"
        aria-label={`配置 ${name}`}
      >
        <header className="settings-dialog-header">
          <div>
            <h2>{name}</h2>
            <p><code>{pluginId}</code>{settings ? <span> · {settings.pluginVersion}</span> : null}</p>
          </div>
          <button ref={closeRef} type="button" aria-label="关闭" disabled={saving} onClick={onClose}>
            <IconCloseOutline16 size={16} />
          </button>
        </header>

        <div className="settings-dialog-body">
          {loading ? (
            <div className="settings-config-loading"><IconRefreshOutline16 className="spin" size={14} />读取配置</div>
          ) : settings ? (
            <div className="settings-fields">
              {fields.map((field) => (
                <SettingsField
                  key={field.id}
                  pluginId={pluginId}
                  field={field}
                  value={draft[field.id]}
                  secretState={settings.secretStates[field.id]}
                  onChange={(value) => onChange(field.id, value)}
                />
              ))}
              {fields.length === 0 ? <p className="settings-empty-config">没有可配置项。</p> : null}
            </div>
          ) : null}
          {error ? <p className="settings-dialog-error" role="alert">{error}</p> : null}
        </div>

        <footer className="settings-dialog-footer">
          <button type="button" disabled={saving} onClick={onClose}>取消</button>
          <button type="button" className="primary" disabled={saving || loading || !settings || !canSave} onClick={onSave}>
            {saving ? "保存中" : "保存"}
          </button>
        </footer>
      </section>
    </div>
  );
}

export function SettingsPage() {
  const [plugins, setPlugins] = useState<PluginListEntry[]>([]);
  const [healthByPlugin, setHealthByPlugin] = useState<Record<string, PluginHealthReport>>({});
  const [settingsByPlugin, setSettingsByPlugin] = useState<Record<string, PluginSettingsView>>({});
  const [selectedSection, setSelectedSection] = useState<SettingsSectionId>("general");
  const [dialogPluginId, setDialogPluginId] = useState<string | null>(null);
  const [settings, setSettings] = useState<PluginSettingsView | null>(null);
  const [draft, setDraft] = useState<SettingsDraft>({});
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [loadingPluginId, setLoadingPluginId] = useState<string | null>(null);
  const [savingPluginId, setSavingPluginId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [errorPluginId, setErrorPluginId] = useState<string | null>(null);
  const loadSequence = useRef(0);

  const loadPlugins = useCallback(async () => {
    setLoading(true);
    setError(null);
    setErrorPluginId(null);
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

  const patch = settings ? buildSettingsPatch(settings, draft) : null;

  async function openConfiguration(pluginId: string) {
    setDialogPluginId(pluginId);
    setSettings(null);
    setDraft({});
    setErrorPluginId(null);
    await loadSettings(pluginId);
  }

  const closeConfiguration = useCallback(() => {
    if (savingPluginId) return;
    loadSequence.current += 1;
    setDialogPluginId(null);
    setSettings(null);
    setDraft({});
    setError(null);
    setErrorPluginId(null);
    setLoadingPluginId(null);
  }, [savingPluginId]);

  function selectSection(sectionId: SettingsSectionId) {
    setSelectedSection(sectionId);
    setDialogPluginId(null);
    setSettings(null);
    setDraft({});
    setSearch("");
    setError(null);
    setErrorPluginId(null);
  }

  async function applySettings(pluginId: string, candidatePatch: CordisSettingsPatch) {
    const bridge = requireDesktopBridge();
    const validation = await bridge.validatePluginSettings(pluginId, candidatePatch);
    if (!validation.valid) throw new Error(validation.error ?? "设置未通过检查");
    const intent = await bridge.createPluginSettingsIntent(pluginId, candidatePatch);
    await bridge.confirmPluginSettingsIntent(intent.reviewId);
  }

  async function saveConfiguration() {
    if (!settings || !patch || patch.changes.length === 0) return;
    const pluginId = settings.pluginId;
    if (pluginId === "@catomicals/plugin-walletd") {
      const roundTimeoutMs = draft.roundTimeoutMs;
      const sessionTimeoutMs = draft.sessionTimeoutMs;
      if (typeof roundTimeoutMs !== "number"
        || typeof sessionTimeoutMs !== "number"
        || sessionTimeoutMs < roundTimeoutMs * 2) {
        setError("会话超时至少要覆盖两轮签名");
        return;
      }
    }
    setSavingPluginId(pluginId);
    setError(null);
    try {
      await applySettings(pluginId, patch);
      await loadPlugins();
      setDialogPluginId(null);
      setSettings(null);
      setDraft({});
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "无法保存设置");
    } finally {
      setSavingPluginId(null);
    }
  }

  async function stageEnabledToggle(plugin: PluginListEntry) {
    setSavingPluginId(plugin.pluginId);
    setError(null);
    setErrorPluginId(null);
    try {
      const view = await requireDesktopBridge().readPluginSettings(plugin.pluginId);
      const enabledField = view.schema.fields.find((field) => field.id === "enabled" && field.type === "boolean");
      if (!enabledField) throw new Error(`${pluginDisplayName(plugin.pluginId)} 没有启停设置`);
      const current = typeof view.settings.enabled === "boolean" ? view.settings.enabled : pluginEnabled(plugin);
      await applySettings(plugin.pluginId, {
        schemaVersion: view.settingsSchemaVersion,
        changes: [{ id: "enabled", value: !current }],
      });
      await loadPlugins();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "无法更新插件状态");
      setErrorPluginId(plugin.pluginId);
    } finally {
      setSavingPluginId(null);
    }
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

            {loading ? <div className="settings-loading"><IconRefreshOutline16 className="spin" size={15} />读取插件</div> : null}
            {error && !dialogPluginId && !errorPluginId ? <p className="settings-error">{error}</p> : null}

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
                          </div> : <div className="settings-plugin-facts" aria-hidden="true" />}
                          <div className="settings-plugin-state">
                            <span className="settings-plugin-health" data-health={healthView.state}><i aria-hidden="true" />{healthView.label}</span>
                            <small>{checkedAtLabel(plugin, health)}</small>
                          </div>
                          <div className="settings-plugin-toggle-slot">
                            {enabledField ? <button
                              type="button"
                              className="settings-plugin-toggle"
                              role="switch"
                              aria-checked={enabled}
                              aria-label={`${enabled ? "停用" : "启用"} ${name}`}
                              disabled={busy}
                              onClick={() => void stageEnabledToggle(plugin)}
                            ><span aria-hidden="true" /></button> : null}
                          </div>
                          <button
                            type="button"
                            className="settings-plugin-config-toggle"
                            aria-label={`配置 ${name}`}
                            disabled={busy}
                            onClick={() => void openConfiguration(plugin.pluginId)}
                          >配置<span aria-hidden="true">›</span></button>
                        </div>
                        {errorPluginId === plugin.pluginId && error ? <p className="settings-plugin-error" role="alert">{error}</p> : null}
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
      {dialogPluginId ? createPortal(
        <SettingsConfigurationDialog
          pluginId={dialogPluginId}
          settings={settings?.pluginId === dialogPluginId ? settings : null}
          draft={draft}
          loading={loadingPluginId === dialogPluginId}
          saving={savingPluginId === dialogPluginId}
          error={error}
          onChange={(fieldId, value) => setDraft((current) => ({ ...current, [fieldId]: value }))}
          onClose={closeConfiguration}
          onSave={() => void saveConfiguration()}
          canSave={Boolean(patch?.changes.length)}
        />,
        document.body,
      ) : null}
    </div>
  );
}

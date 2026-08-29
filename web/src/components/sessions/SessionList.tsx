/**
 * Session list panel for the Catomicals chat shell, styled with the DSH/Codex
 * sidebar tokens (flat rows, quiet captions — no bordered mini-dashboard
 * boxes). It reads the desktop-backed session store and emits navigation
 * events; the visual shell owns where it mounts. Search stays collapsed
 * behind a compact icon until activated, as in Codex. No wallet state here.
 */

import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import {
  IconArchiveOutline20,
  IconCheckOutline16,
  IconCloseOutline16,
  IconEditOutline16,
  IconNewChatOutline16,
  IconSearchOutline16,
  IconTrashOutline16,
} from "@/components/icons";
import { sessionDisplayTitle, useSessionStore } from "@/lib/session";
import type { SessionSummary } from "@/lib/session";

/** One rendered session row. */
export interface SessionRowModel {
  summary: SessionSummary;
  displayTitle: string;
}

/** Props for {@link SessionList}. */
export interface SessionListProps {
  /** Called when the user selects a session (the shell owns navigation). */
  onSelectSession?: (sessionId: string) => void;
  /** Called when the user requests a brand-new session. */
  onCreateSession?: () => void;
  /** Show archived sessions too (defaults to true). */
  showArchived?: boolean;
}

/**
 * Store-bound session list: pinned new-session action, collapsed search,
 * session rows with title/provider/time, rename/archive/delete actions, and a
 * trash restore strip.
 */
export function SessionList({
  onSelectSession,
  onCreateSession,
  showArchived = true,
}: SessionListProps) {
  const store = useSessionStore();
  const [query, setQuery] = useState("");
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchResults, setSearchResults] = useState<Array<{ header: { id: string }; bestMatch: { snippet: string } }>>([]);
  const [trashVisible, setTrashVisible] = useState(false);
  const [trash, setTrash] = useState<Awaited<ReturnType<typeof store.listTrash>>>([]);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState("");
  const searchInputRef = useRef<HTMLInputElement>(null);

  const sessions = useMemo(() => {
    const list = (store.sessions ?? []).filter((summary) => showArchived || !summary.archived);
    return list.map((summary) => ({
      summary,
      displayTitle: sessionDisplayTitle(summary),
    })) as SessionRowModel[];
  }, [store.sessions, showArchived]);

  useEffect(() => {
    if (searchOpen) searchInputRef.current?.focus();
  }, [searchOpen]);

  async function runSearch(raw: FormEvent) {
    raw.preventDefault();
    const term = query.trim();
    if (!term) {
      setSearchResults([]);
      return;
    }
    try {
      const page = await store.search({ query: term, limit: 20 });
      setSearchResults(page.items as unknown as Array<{ header: { id: string }; bestMatch: { snippet: string } }>);
    } catch {
      setSearchResults([]);
    }
  }

  function closeSearch() {
    setSearchOpen(false);
    setQuery("");
    setSearchResults([]);
  }

  function selectFromSearch(id: string) {
    onSelectSession?.(id);
    closeSearch();
  }

  async function toggleTrash() {
    if (trashVisible) {
      setTrashVisible(false);
      return;
    }
    setTrash(await store.listTrash());
    setTrashVisible(true);
  }

  async function run(id: string, action: () => Promise<unknown>, refreshTrash = false) {
    setBusyId(id);
    try {
      await action();
      if (refreshTrash && trashVisible) setTrash(await store.listTrash());
    } finally {
      setBusyId(null);
    }
  }

  async function permanentlyDelete(id: string, deletedAt: number, title: string) {
    const confirmed = window.confirm(`永久删除“${title}”？此操作无法恢复。`);
    if (!confirmed) return;
    await run(id, () => store.purge(id, deletedAt), true);
  }

  function beginRename(summary: SessionSummary) {
    setRenamingId(summary.id);
    setRenameValue(summary.title ?? "");
  }

  async function submitRename(id: string) {
    const title = renameValue.trim();
    if (!title) {
      setRenamingId(null);
      return;
    }
    await run(id, () => store.rename(id, title));
    setRenamingId(null);
  }

  return (
    <section className="session-list" aria-label="会话列表">
      {searchOpen ? (
        <form className="session-search-form" onSubmit={runSearch} data-testid="session-search-form">
          <IconSearchOutline16 size={14} />
          <input
            ref={searchInputRef}
            aria-label="搜索会话内容"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="搜索全部会话…"
          />
          <button type="button" aria-label="关闭搜索" title="关闭搜索" onClick={closeSearch}>
            <IconCloseOutline16 size={14} />
          </button>
        </form>
      ) : (
        <div className="session-list-actions">
          <button className="new-session" type="button" onClick={onCreateSession}>
            <IconNewChatOutline16 size={15} />新会话
          </button>
          <button
            className="session-search-toggle"
            type="button"
            aria-label="搜索会话"
            title="搜索会话"
            onClick={() => setSearchOpen(true)}
          >
            <IconSearchOutline16 size={16} />
          </button>
        </div>
      )}

      <div className="session-scroll">
        {searchResults.length > 0 ? (
          <ul className="flex flex-col gap-1" data-testid="session-search-results">
            {searchResults.map((hit) => (
              <li key={hit.header.id}>
                <button
                  type="button"
                  className="session-row"
                  onClick={() => selectFromSearch(hit.header.id)}
                >
                  <span className="session-row-main">
                    <span>
                      <strong>{sessionDisplayTitle({ id: hit.header.id })}</strong>
                      <small>{hit.bestMatch.snippet}</small>
                    </span>
                  </span>
                </button>
              </li>
            ))}
          </ul>
        ) : (
          <ul className="flex flex-col gap-1" data-testid="session-rows">
            {sessions.map(({ summary, displayTitle }) => {
              const active = store.currentSessionId === summary.id;
              const renaming = renamingId === summary.id;
              return (
                <li
                  key={summary.id}
                  data-testid={`session-row-${summary.id}`}
                  className={`session-row ${active ? "active" : ""}`}
                  data-active={active || undefined}
                >
                  {renaming ? (
                    <form
                      className="session-rename-form"
                      onSubmit={(event) => { event.preventDefault(); void submitRename(summary.id); }}
                      onBlur={(event) => {
                        const nextTarget = event.relatedTarget;
                        if (nextTarget instanceof Node && event.currentTarget.contains(nextTarget)) return;
                        if (renamingId === summary.id) setRenamingId(null);
                      }}
                      data-testid="session-rename-form"
                    >
                      <input
                        aria-label="会话新名称"
                        value={renameValue}
                        onChange={(event) => setRenameValue(event.target.value)}
                      />
                      <button type="submit" aria-label={`保存 ${displayTitle}`} title="保存"><IconCheckOutline16 size={14} /></button>
                      <button type="button" aria-label="取消重命名" title="取消" onClick={() => setRenamingId(null)}><IconCloseOutline16 size={14} /></button>
                    </form>
                  ) : (
                    <>
                      <button
                        type="button"
                        className="session-row-main"
                        onClick={() => onSelectSession?.(summary.id)}
                      >
                        <span>
                          <strong>
                            {displayTitle}
                            {summary.archived ? <span className="session-archived-tag">已归档</span> : null}
                          </strong>
                        </span>
                      </button>
                      <div className="session-row-actions">
                        <button
                          type="button"
                          aria-label={`重命名 ${displayTitle}`}
                          title="重命名"
                          disabled={busyId === summary.id}
                          onClick={() => beginRename(summary)}
                        >
                          <IconEditOutline16 size={14} />
                        </button>
                        <button
                          type="button"
                          aria-label={`${summary.archived ? "取消归档" : "归档"} ${displayTitle}`}
                          title={summary.archived ? "取消归档" : "归档"}
                          disabled={busyId === summary.id}
                          onClick={() => void run(summary.id, () => store.setArchived(summary.id, !summary.archived))}
                        >
                          <IconArchiveOutline20 size={14} />
                        </button>
                        <button
                          type="button"
                          aria-label={`删除 ${displayTitle}`}
                          title="删除"
                          data-danger="true"
                          disabled={busyId === summary.id}
                          onClick={() => void run(summary.id, () => store.remove(summary.id), true)}
                        >
                          <IconTrashOutline16 size={14} />
                        </button>
                      </div>
                    </>
                  )}
                </li>
              );
            })}
            {sessions.length === 0 ? (
              <li className="session-list-empty">暂无会话</li>
            ) : null}
          </ul>
        )}
      </div>

      <div className="session-list-footer">
        <button className="trash-toggle" type="button" onClick={() => void toggleTrash()} data-testid="trash-toggle">
          <IconTrashOutline16 size={14} />
          <span>{trashVisible ? "关闭回收站" : "回收站"}</span>
        </button>
        {trashVisible ? (
          <div className="trash-panel" data-testid="trash-panel">
            {trash.length === 0 ? (
              <p className="trash-empty">回收站为空</p>
            ) : (
              <ul className="flex flex-col gap-1">
                {trash.map((entry) => (
                  <li key={`${entry.id}-${entry.deletedAt}`} className="trash-entry">
                    <span>{entry.title ?? sessionDisplayTitle({ id: entry.id })}</span>
                    <button
                      className="trash-entry-action"
                      type="button"
                      aria-label={`恢复 ${entry.title ?? entry.id}`}
                      title="恢复会话"
                      disabled={busyId === entry.id}
                      onClick={() => void run(entry.id, () => store.restore(entry.id, entry.deletedAt), true)}
                    >
                      恢复
                    </button>
                    <button
                      className="trash-entry-action"
                      type="button"
                      aria-label={`永久删除 ${entry.title ?? entry.id}`}
                      title="永久删除会话"
                      data-danger="true"
                      disabled={busyId === entry.id}
                      onClick={() => void permanentlyDelete(entry.id, entry.deletedAt, entry.title ?? entry.id)}
                    >
                      永久删除
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        ) : null}
      </div>
    </section>
  );
}

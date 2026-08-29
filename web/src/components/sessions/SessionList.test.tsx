// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SessionList } from "./SessionList";
import { SessionStoreProvider } from "@/lib/session";
import type { DesktopBridge, SessionBridgeApi, SessionEvent, SessionSummary } from "@/lib/desktop";

function fakeBridge(overrides: Partial<SessionBridgeApi> = {}): DesktopBridge {
  const summaries: SessionSummary[] = [
    { id: "s-1", archived: false, createdAt: 1000, updatedAt: Date.now() - 5 * 60_000, eventCount: 2, provider: "codex", title: "Fee Q&A" },
    { id: "s-2", archived: true, createdAt: 1001, updatedAt: Date.now() - 2 * 3_600_000, eventCount: 0 },
  ];
  const sessions: SessionBridgeApi = {
    create: vi.fn(async (input) => ({
      id: "s-new",
      archived: false,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      eventCount: 0,
      ...input?.title !== undefined ? { title: input.title } : {},
    })),
    append: vi.fn(async () => [] as SessionEvent[]),
    list: vi.fn(async () => summaries),
    read: vi.fn(async () => ({ meta: { version: 1, id: "s-1", createdAt: 1000 }, events: [] })),
    inspect: vi.fn(async () => ({ meta: { version: 1, id: "s-1", createdAt: 1000 }, events: [] })),
    rename: vi.fn(async (id, title) => ({ ...summaries[0], id, title })),
    setArchived: vi.fn(async (id, archived) => ({ ...summaries[0], id, archived })),
    remove: vi.fn(async (id) => ({ id, deletedAt: Date.now() })),
    restore: vi.fn(async (id) => ({ ...summaries[0], id })),
    purge: vi.fn(async () => undefined),
    listTrash: vi.fn(async () => [{ id: "s-2", deletedAt: Date.now(), title: "Old" }]),
    search: vi.fn(async () => ({
      items: [{ header: { id: "s-9" }, bestMatch: { snippet: "…fees…" } }],
    })),
    searchEvents: vi.fn(async () => ({ items: [], session: { version: 1, id: "s-1", createdAt: 1000 } })),
    readFrom: vi.fn(async () => ({ meta: { version: 1, id: "s-1", createdAt: 1000 }, events: [] })),
    navigate: vi.fn(async () => undefined),
    ...overrides,
  } as SessionBridgeApi;
  return {
    sessions,
    onSessionNavigation: vi.fn(() => () => undefined),
  } as unknown as DesktopBridge;
}

function renderList(bridge: DesktopBridge, props: Record<string, unknown> = {}) {
  return render(
    <SessionStoreProvider bridge={bridge}>
      <SessionList {...props} />
    </SessionStoreProvider>,
  );
}

describe("SessionList", () => {
  let bridge: DesktopBridge;
  beforeEach(() => { bridge = fakeBridge(); });
  afterEach(() => cleanup());

  it("renders compact session rows with titles and hover actions", async () => {
    renderList(bridge);
    await waitFor(() => expect(screen.getByText("Fee Q&A")).toBeDefined());
    expect(screen.getByText("已归档")).toBeDefined();
    const row = screen.getByTestId("session-row-s-1");
    expect(within(row).queryByText(/codex/)).toBeNull();
    expect(within(row).getByLabelText("重命名 Fee Q&A")).toBeDefined();
    expect(within(row).getByLabelText("归档 Fee Q&A")).toBeDefined();
    expect(within(row).getByLabelText("删除 Fee Q&A")).toBeDefined();
  });

  it("emits selection and creation callbacks", async () => {
    const onSelect = vi.fn();
    const onCreate = vi.fn();
    renderList(bridge, { onSelectSession: onSelect, onCreateSession: onCreate });
    await waitFor(() => expect(screen.getByText("Fee Q&A")).toBeDefined());
    fireEvent.click(screen.getByText("Fee Q&A"));
    expect(onSelect).toHaveBeenCalledWith("s-1");
    fireEvent.click(screen.getByRole("button", { name: /新会话/ }));
    expect(onCreate).toHaveBeenCalled();
  });

  it("renames, archives, and deletes through the store", async () => {
    renderList(bridge);
    await waitFor(() => expect(screen.getByText("Fee Q&A")).toBeDefined());
    const row = screen.getByTestId("session-row-s-1");

    fireEvent.click(within(row).getByLabelText("重命名 Fee Q&A"));
    const renameInput = await screen.findByLabelText("会话新名称");
    fireEvent.change(renameInput, { target: { value: "Renamed" } });
    fireEvent.submit(renameInput.closest("form") as HTMLFormElement);
    await waitFor(() => expect(bridge.sessions.rename).toHaveBeenCalledWith("s-1", "Renamed"));

    fireEvent.click(within(row).getByLabelText("归档 Fee Q&A"));
    await waitFor(() => expect(bridge.sessions.setArchived).toHaveBeenCalledWith("s-1", true));

    fireEvent.click(within(row).getByLabelText("删除 Fee Q&A"));
    await waitFor(() => expect(bridge.sessions.remove).toHaveBeenCalledWith("s-1"));
  });

  it("saves a rename through a real pointer click after the input blurs", async () => {
    const user = userEvent.setup();
    renderList(bridge);
    await screen.findByText("Fee Q&A");

    await user.click(screen.getByLabelText("重命名 Fee Q&A"));
    const input = await screen.findByLabelText("会话新名称");
    await user.clear(input);
    await user.type(input, "Pointer rename");
    await user.click(screen.getByRole("button", { name: "保存 Fee Q&A" }));

    await waitFor(() => expect(bridge.sessions.rename).toHaveBeenCalledWith("s-1", "Pointer rename"));
  });

  it("cancels a rename through a real pointer click after the input blurs", async () => {
    const user = userEvent.setup();
    renderList(bridge);
    await screen.findByText("Fee Q&A");

    await user.click(screen.getByLabelText("重命名 Fee Q&A"));
    const input = await screen.findByLabelText("会话新名称");
    await user.clear(input);
    await user.type(input, "Discard this");
    await user.click(screen.getByRole("button", { name: "取消重命名" }));

    expect(screen.queryByLabelText("会话新名称")).toBeNull();
    expect(bridge.sessions.rename).not.toHaveBeenCalled();
    expect(screen.getByText("Fee Q&A")).toBeDefined();
  });

  it("keeps search collapsed behind the icon and searches when activated", async () => {
    renderList(bridge);
    await waitFor(() => expect(screen.getByText("Fee Q&A")).toBeDefined());

    // Search is collapsed: no input until the toggle is pressed.
    expect(screen.queryByLabelText("搜索会话内容")).toBeNull();
    fireEvent.click(screen.getByLabelText("搜索会话"));
    const input = await screen.findByLabelText("搜索会话内容");
    expect(screen.queryByRole("button", { name: /新会话/ })).toBeNull();
    expect(within(input.closest("form") as HTMLFormElement).getByLabelText("关闭搜索")).toBeDefined();
    fireEvent.change(input, { target: { value: "fees" } });
    fireEvent.submit(input.closest("form") as HTMLFormElement);

    await waitFor(() => expect(bridge.sessions.search).toHaveBeenCalledWith({ query: "fees", limit: 20 }));
    expect(await screen.findByText("…fees…")).toBeDefined();
  });

  it("refreshes the open trash list after restore", async () => {
    const deletedAt = Date.now();
    const listTrash = vi.fn()
      .mockResolvedValueOnce([{ id: "s-2", deletedAt, title: "Old" }])
      .mockResolvedValueOnce([]);
    bridge = fakeBridge({ listTrash });
    renderList(bridge);
    await waitFor(() => expect(screen.getByText("Fee Q&A")).toBeDefined());
    fireEvent.click(screen.getByTestId("trash-toggle"));
    await waitFor(() => expect(screen.getByTestId("trash-panel")).toBeDefined());
    expect(screen.getByText("Old")).toBeDefined();
    fireEvent.click(screen.getByLabelText("恢复 Old"));
    await waitFor(() => expect(bridge.sessions.restore).toHaveBeenCalledWith("s-2", deletedAt));
    await waitFor(() => expect(screen.queryByText("Old")).toBeNull());
    expect(listTrash).toHaveBeenCalledTimes(2);
  });

  it("requires confirmation before permanent deletion and refreshes the trash list", async () => {
    const deletedAt = Date.now();
    const listTrash = vi.fn()
      .mockResolvedValueOnce([{ id: "s-2", deletedAt, title: "Old" }])
      .mockResolvedValueOnce([]);
    bridge = fakeBridge({ listTrash });
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    renderList(bridge);

    fireEvent.click(screen.getByTestId("trash-toggle"));
    const panel = await screen.findByTestId("trash-panel");
    const permanentDelete = within(panel).getByRole("button", { name: "永久删除 Old" });
    expect(permanentDelete.textContent).toContain("永久删除");
    fireEvent.click(permanentDelete);
    expect(bridge.sessions.purge).not.toHaveBeenCalled();

    confirm.mockReturnValue(true);
    fireEvent.click(permanentDelete);
    await waitFor(() => expect(bridge.sessions.purge).toHaveBeenCalledWith("s-2", deletedAt));
    await waitFor(() => expect(screen.queryByText("Old")).toBeNull());
    expect(listTrash).toHaveBeenCalledTimes(2);
  });

  it("refreshes an already-open trash list after a session is deleted", async () => {
    const deletedAt = Date.now();
    const listTrash = vi.fn()
      .mockResolvedValueOnce([{ id: "s-2", deletedAt, title: "Old" }])
      .mockResolvedValueOnce([
        { id: "s-2", deletedAt, title: "Old" },
        { id: "s-1", deletedAt: deletedAt + 1, title: "Fee Q&A" },
      ]);
    bridge = fakeBridge({ listTrash });
    renderList(bridge);

    fireEvent.click(screen.getByTestId("trash-toggle"));
    const panel = await screen.findByTestId("trash-panel");
    fireEvent.click(screen.getByLabelText("删除 Fee Q&A"));

    await waitFor(() => expect(bridge.sessions.remove).toHaveBeenCalledWith("s-1"));
    await waitFor(() => expect(within(panel).getByText("Fee Q&A")).toBeDefined());
    expect(listTrash).toHaveBeenCalledTimes(2);
  });
});

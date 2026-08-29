// @vitest-environment jsdom

import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { IdentityClient } from "@/lib/account";
import type { IdentitySession } from "@/lib/desktop";
import { AccountDialog } from "./AccountDialog";

afterEach(cleanup);

const localSession: IdentitySession = {
  version: 1,
  provider: "local-device",
  accountId: "a4f36bdd-66d9-4d87-a070-4e3ad531d12f",
  sessionId: "c1f66ac1-3b46-4c93-afdb-38c301a97732",
  displayName: "本机用户",
  createdAt: 1_775_000_000_000,
  authenticatedAt: 1_775_000_000_000,
};

function client(initial: IdentitySession | null = null): IdentityClient & {
  login: ReturnType<typeof vi.fn>;
  logout: ReturnType<typeof vi.fn>;
  recover: ReturnType<typeof vi.fn>;
} {
  let session = initial;
  const login = vi.fn(async () => {
    session = localSession;
    return localSession;
  });
  const logout = vi.fn(async () => {
    session = null;
  });
  const recover = vi.fn(async () => {
    session = null;
  });
  return {
    state: async () => ({ available: true, session }),
    login,
    logout,
    recover,
  };
}

describe("account login dialog", () => {
  it("creates a real local identity session while remote providers remain unavailable", async () => {
    const identity = client();
    const onSessionChange = vi.fn();
    const user = userEvent.setup();
    render(<AccountDialog client={identity} onClose={vi.fn()} onSessionChange={onSessionChange} />);

    const dialog = screen.getByRole("dialog", { name: "登录 Catomicals" });
    for (const name of ["使用 Google 登录", "使用 Apple 登录", "使用邮箱登录"]) {
      expect(within(dialog).getByRole("button", { name: new RegExp(name) }).hasAttribute("disabled")).toBe(true);
    }
    expect(within(dialog).getAllByText("OAuth 客户端未配置")).toHaveLength(2);
    expect(within(dialog).getByText("邮件验证服务未配置")).toBeTruthy();
    const local = await within(dialog).findByRole("button", { name: /使用本机身份/ });
    expect(local.hasAttribute("disabled")).toBe(false);

    await user.click(local);

    expect(identity.login).toHaveBeenCalledTimes(1);
    expect(await within(dialog).findByText("本机用户")).toBeTruthy();
    expect(within(dialog).getByRole("button", { name: "退出本机会话" })).toBeTruthy();
    expect(onSessionChange).toHaveBeenCalledWith(localSession);
    expect(within(dialog).getByText(/不会批准或签署比特币交易/)).toBeTruthy();
    expect(dialog.querySelector('a[href*="passkeys"]')).toBeNull();
  });

  it("restores the active identity and clears it on logout", async () => {
    const identity = client(localSession);
    const onSessionChange = vi.fn();
    const user = userEvent.setup();
    render(<AccountDialog client={identity} onClose={vi.fn()} onSessionChange={onSessionChange} />);

    expect(await screen.findByText("本机用户")).toBeTruthy();
    expect(screen.getByText("设备身份仍会保留，下次登录会继续使用")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "退出本机会话" }));

    expect(identity.logout).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(screen.getByRole("button", { name: /使用本机身份/ })).toBeTruthy());
    expect(onSessionChange).toHaveBeenCalledWith(null);
  });

  it("disables local login when protected storage is unavailable", async () => {
    const unavailable: IdentityClient = {
      state: async () => ({ available: false, session: null }),
      login: async () => { throw new Error("secure storage unavailable"); },
      logout: async () => undefined,
      recover: async () => undefined,
    };
    render(<AccountDialog client={unavailable} onClose={vi.fn()} />);

    const local = await screen.findByRole("button", { name: /使用本机身份，系统安全存储不可用/ });
    expect(local.hasAttribute("disabled")).toBe(true);
  });

  it("shows stable friendly copy instead of a state failure detail", async () => {
    const identity = client();
    identity.state = async () => { throw new Error("EACCES /Users/private/identity-session.json"); };
    render(<AccountDialog client={identity} onClose={vi.fn()} />);

    expect((await screen.findByRole("alert")).textContent).toContain("无法读取本机身份，请重试");
    expect(screen.queryByText(/Users\/private/)).toBeNull();
  });

  it("shows stable friendly copy instead of login and logout failure details", async () => {
    const loginIdentity = client();
    loginIdentity.login.mockRejectedValueOnce(new Error("decrypt failed /Users/private/profile"));
    const user = userEvent.setup();
    const { unmount } = render(<AccountDialog client={loginIdentity} onClose={vi.fn()} />);
    await user.click(await screen.findByRole("button", { name: /使用本机身份/ }));
    expect((await screen.findByRole("alert")).textContent).toContain("无法创建本机身份，请重试");
    expect(screen.queryByText(/Users\/private/)).toBeNull();
    unmount();

    const logoutIdentity = client(localSession);
    logoutIdentity.logout.mockRejectedValueOnce(new Error("unlink failed /Users/private/session"));
    render(<AccountDialog client={logoutIdentity} onClose={vi.fn()} />);
    await user.click(await screen.findByRole("button", { name: "退出本机会话" }));
    expect((await screen.findByRole("alert")).textContent).toContain("无法退出本机会话，请重试");
    expect(screen.queryByText(/Users\/private/)).toBeNull();
  });

  it("makes damaged local identity data explicitly recoverable", async () => {
    const identity = client();
    identity.state = async () => ({
      available: true,
      session: null,
      issue: "identity-data-corrupt",
    } as never);
    const user = userEvent.setup();
    render(<AccountDialog client={identity} onClose={vi.fn()} />);

    expect((await screen.findByRole("alert")).textContent).toContain("本机身份数据已损坏");
    await user.click(screen.getByRole("button", { name: "重置本机身份" }));

    expect(identity.recover).toHaveBeenCalledTimes(1);
    expect(await screen.findByRole("button", { name: /使用本机身份/ })).toBeTruthy();
  });

  it("closes from Escape, the close control, or the backdrop and keeps focus in the dialog", async () => {
    const onClose = vi.fn();
    const user = userEvent.setup();
    render(<AccountDialog client={client()} onClose={onClose} />);

    const close = screen.getByRole("button", { name: "关闭登录" });
    const local = await screen.findByRole("button", { name: /使用本机身份/ });
    expect(document.activeElement).toBe(close);
    await user.tab();
    expect(document.activeElement).toBe(local);
    await user.tab();
    expect(document.activeElement).toBe(close);
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledTimes(1);
    await user.click(close);
    expect(onClose).toHaveBeenCalledTimes(2);
    await user.click(screen.getByTestId("account-dialog-backdrop"));
    expect(onClose).toHaveBeenCalledTimes(3);
  });
});

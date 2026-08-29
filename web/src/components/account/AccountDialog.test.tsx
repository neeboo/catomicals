// @vitest-environment jsdom

import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AccountDialog } from "./AccountDialog";

afterEach(cleanup);

describe("account login dialog", () => {
  it("presents honest identity options without exposing wallet authorization management", () => {
    render(<AccountDialog onClose={vi.fn()} />);

    const dialog = screen.getByRole("dialog", { name: "登录 Catomicals" });
    expect(within(dialog).getByText("账户用于同步会话与设置")).toBeTruthy();

    for (const name of ["使用 Google 登录", "使用 Apple 登录", "使用邮箱登录", "使用本机 Passkey"]) {
      const option = within(dialog).getByRole("button", { name: new RegExp(name) });
      expect(option.hasAttribute("disabled")).toBe(true);
    }

    expect(within(dialog).getAllByText("即将支持")).toHaveLength(3);
    expect(within(dialog).getByText("本机身份即将支持")).toBeTruthy();
    expect(within(dialog).getByText(/只用于本地账户身份与解锁/)).toBeTruthy();
    expect(within(dialog).getByText(/不会执行比特币签名/)).toBeTruthy();
    expect(dialog.querySelector('a[href*="passkeys"]')).toBeNull();
  });

  it("closes from Escape, the close control, or the backdrop and keeps focus contained", async () => {
    const onClose = vi.fn();
    const user = userEvent.setup();
    render(<AccountDialog onClose={onClose} />);

    const close = screen.getByRole("button", { name: "关闭登录" });
    expect(document.activeElement).toBe(close);
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

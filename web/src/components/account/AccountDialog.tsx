import { useEffect, useRef, type MouseEvent } from "react";
import { createPortal } from "react-dom";
import { IconCloseOutline16 } from "@/components/icons";
import { AUTH_PROVIDERS } from "@/lib/account";

export function AccountDialog({ onClose }: { onClose: () => void }) {
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const returnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    closeRef.current?.focus();

    function onKeyDown(event: globalThis.KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key === "Tab") {
        event.preventDefault();
        closeRef.current?.focus();
      }
    }

    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      returnFocus?.focus();
    };
  }, [onClose]);

  function closeFromBackdrop(event: MouseEvent<HTMLDivElement>) {
    if (event.target === event.currentTarget) onClose();
  }

  return createPortal(
    <div
      className="account-dialog-backdrop"
      data-testid="account-dialog-backdrop"
      onMouseDown={closeFromBackdrop}
    >
      <section className="account-dialog" role="dialog" aria-modal="true" aria-labelledby="account-dialog-title">
        <header className="account-dialog-header">
          <div>
            <h2 id="account-dialog-title">登录 Catomicals</h2>
            <p>账户用于同步会话与设置</p>
          </div>
          <button ref={closeRef} type="button" aria-label="关闭登录" onClick={onClose}>
            <IconCloseOutline16 size={16} />
          </button>
        </header>

        <div className="account-provider-list" aria-label="登录方式">
          {AUTH_PROVIDERS.map((provider) => {
            const actionLabel = provider.id === "passkey"
              ? "使用本机 Passkey"
              : provider.id === "email" ? "使用邮箱登录" : `使用 ${provider.label} 登录`;
            const status = provider.id === "passkey" ? provider.statusLabel : "即将支持";
            return (
              <button key={provider.id} type="button" disabled aria-label={`${actionLabel}，${status}`}>
                <span>{actionLabel}</span>
                <small>{status}</small>
              </button>
            );
          })}
        </div>

        <p className="account-passkey-note">
          本机 Passkey 只用于本地账户身份与解锁，不会执行比特币签名。钱包授权凭证仍在安全设置中管理。
        </p>
      </section>
    </div>,
    document.body,
  );
}

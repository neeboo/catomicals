import { useEffect, useMemo, useRef, useState, type MouseEvent } from "react";
import { createPortal } from "react-dom";
import { IconCloseOutline16 } from "@/components/icons";
import { AUTH_PROVIDERS, createIdentityClient, type IdentityClient } from "@/lib/account";
import type { IdentitySession, IdentityState } from "@/lib/desktop";

export function AccountDialog({
  onClose,
  onSessionChange,
  client,
}: {
  onClose: () => void;
  onSessionChange?: (session: IdentitySession | null) => void;
  client?: IdentityClient;
}) {
  const closeRef = useRef<HTMLButtonElement>(null);
  const dialogRef = useRef<HTMLElement>(null);
  const identity = useMemo(() => client ?? createIdentityClient(), [client]);
  const [state, setState] = useState<IdentityState | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    void identity.state().then(
      (next) => { if (active) setState(next); },
      () => {
        if (!active) return;
        setState({ available: false, session: null });
        setError("无法读取本机身份，请重试");
      },
    );
    return () => { active = false; };
  }, [identity]);

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
        const controls = Array.from(dialogRef.current?.querySelectorAll<HTMLButtonElement>("button:not(:disabled)") ?? []);
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

  async function loginLocalIdentity() {
    setBusy(true);
    setError(null);
    try {
      const session = await identity.login();
      setState({ available: true, session });
      onSessionChange?.(session);
    } catch {
      setError("无法创建本机身份，请重试");
    } finally {
      setBusy(false);
    }
  }

  async function logoutLocalIdentity() {
    setBusy(true);
    setError(null);
    try {
      await identity.logout();
      setState((current) => ({ available: current?.available ?? true, session: null }));
      onSessionChange?.(null);
    } catch {
      setError("无法退出本机会话，请重试");
    } finally {
      setBusy(false);
    }
  }

  async function recoverLocalIdentity() {
    setBusy(true);
    setError(null);
    try {
      await identity.recover();
      setState({ available: true, session: null });
      onSessionChange?.(null);
    } catch {
      setError("无法重置本机身份，请重试");
    } finally {
      setBusy(false);
    }
  }

  return createPortal(
    <div
      className="account-dialog-backdrop"
      data-testid="account-dialog-backdrop"
      onMouseDown={closeFromBackdrop}
    >
      <section ref={dialogRef} className="account-dialog" role="dialog" aria-modal="true" aria-labelledby="account-dialog-title">
        <header className="account-dialog-header">
          <div>
            <h2 id="account-dialog-title">登录 Catomicals</h2>
            <p>本机身份保存会话归属与本地偏好</p>
          </div>
          <button ref={closeRef} type="button" aria-label="关闭登录" onClick={onClose}>
            <IconCloseOutline16 size={16} />
          </button>
        </header>

        {state?.issue === "identity-data-corrupt" ? (
          <div className="account-current-identity account-recovery">
            <div>
              <strong role="alert">本机身份数据已损坏</strong>
              <small>重置后会创建新的本机身份</small>
            </div>
            <button type="button" disabled={busy} onClick={() => void recoverLocalIdentity()} aria-label="重置本机身份">
              {busy ? "正在重置" : "重置本机身份"}
            </button>
          </div>
        ) : state?.session ? (
          <div className="account-current-identity">
            <div><strong>{state.session.displayName}</strong><small>设备身份仍会保留，下次登录会继续使用</small></div>
            <button type="button" disabled={busy} onClick={() => void logoutLocalIdentity()} aria-label="退出本机会话">
              {busy ? "正在退出" : "退出本机会话"}
            </button>
          </div>
        ) : (
          <div className="account-provider-list" aria-label="登录方式">
            {AUTH_PROVIDERS.map((provider) => {
              const local = provider.id === "local-device";
              const actionLabel = local
                ? "使用本机身份"
                : provider.id === "email" ? "使用邮箱登录" : `使用 ${provider.label} 登录`;
              const status = local
                ? state === null ? "正在读取" : state.available ? provider.statusLabel : "系统安全存储不可用"
                : provider.statusLabel;
              const disabled = !local || state === null || !state.available || busy;
              return (
                <button
                  key={provider.id}
                  type="button"
                  disabled={disabled}
                  aria-label={`${actionLabel}，${status}`}
                  onClick={local ? () => void loginLocalIdentity() : undefined}
                >
                  <span>{actionLabel}</span>
                  <small>{busy && local ? "正在创建" : status}</small>
                </button>
              );
            })}
          </div>
        )}

        <p className="account-passkey-note">
          本机身份会话与钱包交易授权凭证完全分开，不会批准或签署比特币交易。
        </p>
        {error ? <p className="account-error" role="alert">{error}</p> : null}
      </section>
    </div>,
    document.body,
  );
}

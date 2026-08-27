import { Link, Outlet } from "@tanstack/react-router";
import { Alert } from "@/components/ui/alert";
import { SyncIndicator } from "@/components/SyncIndicator";
import { useNodeStatusQuery, useWalletStatusQuery } from "@/lib/hooks";
import { apiBase } from "@/lib/api";
import { isWebAuthnAvailable, originMatches } from "@/lib/webauthn";
import { cn } from "@/lib/cn";

const NAV = [
  { to: "/", label: "Overview" },
  { to: "/chat", label: "Chat" },
  { to: "/transactions", label: "Transactions" },
  { to: "/intents", label: "Intents" },
  { to: "/passkeys", label: "Passkeys" },
] as const;

function GlobalBanners() {
  const wallet = useWalletStatusQuery();
  const node = useNodeStatusQuery();
  const walletOnline = wallet.isSuccess;
  const nodeSnapshot = wallet.data?.node ?? null;

  const inquisitionDown = walletOnline && nodeSnapshot === null;
  const opCatInactive = walletOnline && nodeSnapshot !== null && !nodeSnapshot.op_cat_active;
  const originBad =
    node.isSuccess && !isWebAuthnAvailable()
      ? "unsupported"
      : node.isSuccess && !originMatches(node.data.rp_origin)
        ? "mismatch"
        : null;

  return (
    <div className="flex flex-col gap-1.5">
      {wallet.isError && (
        <Alert variant="warn">
          <div className="micro-label text-paper">wallet node offline</div>
          <div className="text-muted">
            No live state is available. Cannot reach {apiBase()}.{" "}
            Start the node with{" "}
            <span className="mono-value text-paper">
              cargo run -p catomicals -- wallet serve
            </span>{" "}
            and retry.
          </div>
        </Alert>
      )}
      {inquisitionDown && (
        <Alert variant="warn">
          <div className="micro-label text-paper">inquisition node unreachable</div>
          <div className="text-muted">
            The wallet node could not reach its local Bitcoin Inquisition Signet
            RPC. Blocks, headers and OP_CAT status are unknown. Only
            non-node-dependent state is shown.
          </div>
        </Alert>
      )}
      {opCatInactive && (
        <Alert variant="warn">
          <div className="micro-label text-paper">op_cat inactive</div>
          <div className="text-muted">
            getdeploymentinfo on the connected Signet node reports BIP 347
            (OP_CAT) is not active on this chain. Covenant intents cannot be
            executed on this node.
          </div>
        </Alert>
      )}
      {originBad === "mismatch" && (
        <Alert variant="warn">
          <div className="micro-label text-paper">browser origin ≠ rp origin</div>
          <div className="text-muted">
            This page is served from <span className="mono-value text-paper">{window.location.origin}</span>{" "}
            but the wallet node accepts WebAuthn ceremonies for{" "}
            <span className="mono-value text-paper">{node.data?.rp_origin}</span>. Passkey
            registration and approval will fail until the node is started with
            a matching --rp-origin.
          </div>
        </Alert>
      )}
      {originBad === "unsupported" && (
        <Alert variant="warn">
          <div className="micro-label text-paper">webauthn unavailable</div>
          <div className="text-muted">
            This browser context cannot run WebAuthn (needs a secure context
            over localhost or HTTPS). Passkey registration and approval are
            disabled.
          </div>
        </Alert>
      )}
    </div>
  );
}

function Shell() {
  const wallet = useWalletStatusQuery();
  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b border-line">
        <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-4 py-3">
          <Link to="/" className="flex items-baseline gap-3">
            <span className="text-[13px] font-semibold uppercase tracking-[0.22em] text-paper">
              catomicals
            </span>
            <span className="micro-label">signet wallet foundation</span>
          </Link>
          <SyncIndicator
            fetching={wallet.isFetching}
            updatedAt={wallet.dataUpdatedAt}
            online={wallet.isSuccess}
          />
        </div>
      </header>
      <div className="mx-auto flex w-full max-w-6xl flex-1 gap-6 px-4 py-5">
        <aside className="w-40 shrink-0">
          <nav className="sticky top-5 flex flex-col gap-1">
            {NAV.map((item) => (
              <Link
                key={item.to}
                to={item.to}
                activeOptions={item.to === "/" ? { exact: true } : undefined}
                activeProps={{ className: "border-paper text-paper bg-panel-2" }}
                className={cn(
                  "border border-transparent px-2 py-1.5 text-[11px] uppercase tracking-[0.14em] text-muted transition-colors hover:text-paper",
                )}
              >
                {item.label}
              </Link>
            ))}
            <div className="mt-6 flex flex-col gap-1 border-t border-line pt-4">
              <span className="micro-label">api base</span>
              <span className="mono-value text-dim">{apiBase()}</span>
            </div>
          </nav>
        </aside>
        <main className="min-w-0 flex-1 pb-10">
          <GlobalBanners />
          <div className="mt-3">
            <Outlet />
          </div>
        </main>
      </div>
      <footer className="border-t border-line">
        <div className="mx-auto max-w-6xl px-4 py-2">
          <span className="micro-label">
            signet only · process-memory custody · not for real assets · no fake
            balances or signatures
          </span>
        </div>
      </footer>
    </div>
  );
}

export const rootRouteComponent = Shell;

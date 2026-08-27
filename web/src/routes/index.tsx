import { Link } from "@tanstack/react-router";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { DataRow } from "@/components/DataRow";
import { HexValue } from "@/components/HexValue";
import { IntentStatusBadge } from "@/components/IntentStatusBadge";
import { StatusDot } from "@/components/StatusDot";
import {
  useNodeStatusQuery,
  useSignerStatusQuery,
  useWalletStatusQuery,
} from "@/lib/hooks";
import { formatRelative, shortHex } from "@/lib/format";

function PanelSkeleton({ rows = 3 }: { rows?: number }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>loading</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-2 py-3">
        {Array.from({ length: rows }).map((_, i) => (
          <Skeleton key={i} className="h-4 w-full" />
        ))}
      </CardContent>
    </Card>
  );
}

function InquisitionNodePanel() {
  const q = useWalletStatusQuery();
  if (q.isPending || q.isFetching && !q.data) return <PanelSkeleton rows={4} />;
  if (q.isError) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>inquisition node</CardTitle>
        </CardHeader>
        <CardContent>
          <span className="micro-label">no live data — node offline</span>
        </CardContent>
      </Card>
    );
  }
  const node = q.data.node;
  if (!node) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>inquisition node</CardTitle>
        </CardHeader>
        <CardContent>
          <span className="micro-label">
            unreachable — rpc probe failed on the wallet node
          </span>
        </CardContent>
      </Card>
    );
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle>inquisition node</CardTitle>
        <Badge variant={node.chain === "signet" ? "solid" : "warn"}>
          {node.chain}
        </Badge>
      </CardHeader>
      <CardContent>
        <DataRow label="chain">{node.chain}</DataRow>
        <DataRow label="height">
          <span className="mono-value">
            {node.blocks.toLocaleString()}{" "}
            <span className="text-dim">
              (headers {node.headers.toLocaleString()})
            </span>
          </span>
        </DataRow>
        <DataRow label="subversion">
          <span className="mono-value">{node.subversion}</span>
        </DataRow>
        <DataRow label="op_cat / bip 347">
          <Badge variant={node.op_cat_active ? "solid" : "warn"}>
            {node.op_cat_active ? "active" : "inactive"}
          </Badge>
        </DataRow>
      </CardContent>
    </Card>
  );
}

function WalletNodePanel() {
  const q = useNodeStatusQuery();
  if (q.isPending) return <PanelSkeleton rows={4} />;
  if (q.isError || !q.data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>wallet node</CardTitle>
        </CardHeader>
        <CardContent>
          <span className="micro-label">offline — {q.error?.message ?? "unknown"}</span>
        </CardContent>
      </Card>
    );
  }
  const s = q.data;
  return (
    <Card>
      <CardHeader>
        <CardTitle>wallet node</CardTitle>
        <Badge variant="outline">{s.network}</Badge>
      </CardHeader>
      <CardContent>
        <DataRow label="network">{s.network}</DataRow>
        <DataRow label="rp id">
          <span className="mono-value">{s.rp_id}</span>
        </DataRow>
        <DataRow label="rp origin">
          <span className="mono-value">{s.rp_origin}</span>
        </DataRow>
        <DataRow label="persistence">
          <span className="mono-value text-dim">{s.persistence}</span>
        </DataRow>
        <DataRow label="secret storage">
          <span className="mono-value text-dim">{s.secret_storage}</span>
        </DataRow>
        <DataRow label="production ready">
          <Badge variant={s.production_ready ? "solid" : "dim"}>
            {s.production_ready ? "yes" : "no — signet dev only"}
          </Badge>
        </DataRow>
      </CardContent>
    </Card>
  );
}

function ThresholdPanel() {
  const q = useWalletStatusQuery();
  if (q.isPending && !q.data) return <PanelSkeleton rows={3} />;
  const t = q.data?.threshold;
  if (!t) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>threshold</CardTitle>
        </CardHeader>
        <CardContent>
          <span className="micro-label">no live data</span>
        </CardContent>
      </Card>
    );
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle>threshold</CardTitle>
        <Badge variant={t.configured ? "solid" : "warn"}>
          {t.configured ? "configured" : "unconfigured"}
        </Badge>
      </CardHeader>
      <CardContent>
        <DataRow label="requirement">
          <span className="mono-value">
            {t.configured ? `${t.min_signers} of ${t.max_signers}` : "—"}
          </span>
        </DataRow>
        <DataRow label="group pubkey x-only">
          <HexValue
            value={t.group_pubkey_xonly ?? ""}
            full={false}
            head={14}
            tail={14}
          />
        </DataRow>
        <DataRow label="taproot">
          <span className="micro-label text-muted">
            bip340 aggregated group key
          </span>
        </DataRow>
      </CardContent>
    </Card>
  );
}

function SignerPanel() {
  const wallet = useWalletStatusQuery();
  const signer = useSignerStatusQuery();
  if ((wallet.isPending && !wallet.data) || (signer.isPending && !signer.data)) {
    return <PanelSkeleton rows={4} />;
  }
  const signers = wallet.data?.signers ?? [];
  const threshold = wallet.data?.threshold;
  const online = signers.filter((s) => s.online);
  const configured = signer.data?.configured ?? false;
  const sufficient =
    !!threshold?.configured && online.length >= threshold.min_signers;

  return (
    <Card>
      <CardHeader>
        <CardTitle>signers</CardTitle>
        <StatusDot tone={configured ? "ok" : "warn"} />
      </CardHeader>
      <CardContent>
        {signers.length === 0 && (
          <span className="micro-label">no signers configured</span>
        )}
        {signers.map((s) => (
          <DataRow key={s.id} label={s.label}>
            <span className="inline-flex items-center gap-2">
              <span className="mono-value text-muted">#{s.id}</span>
              <Badge variant={s.online ? "solid" : "dim"}>
                {s.online ? "online" : "offline"}
              </Badge>
            </span>
          </DataRow>
        ))}
        <DataRow label="threshold sufficiency">
          <Badge variant={sufficient ? "solid" : "warn"}>
            {threshold?.configured
              ? `${online.length}/${threshold.min_signers} online`
              : "unconfigured"}
          </Badge>
        </DataRow>
        <DataRow label="local participant">
          <span className="mono-value">
            {signer.data?.signer_id ? `#${signer.data.signer_id}` : "none"}
          </span>
        </DataRow>
        <DataRow label="approved actions">
          <span className="mono-value">
            {signer.data?.approved_actions ?? 0}
          </span>
        </DataRow>
      </CardContent>
    </Card>
  );
}

function IntentsPanel() {
  const q = useWalletStatusQuery();
  if (q.isPending && !q.data) return <PanelSkeleton rows={4} />;
  const data = q.data;
  const pending = data?.pending_approvals ?? [];
  const recent = data?.recent_intents ?? [];
  const now = Date.now() / 1000;

  const row = (i: { id: string; status: "pending" | "approved" | "cancelled" | "expired" | "signed"; expiry: number; tx_digest_hex: string }) => {
    const stale = i.status === "pending" && i.expiry <= now;
    return (
      <div key={i.id} className="data-row">
        <div className="flex min-w-0 flex-col gap-0.5">
          <Link
            to="/intents/$intentId"
            params={{ intentId: i.id }}
            className="mono-value text-paper underline-offset-2 hover:underline"
          >
            {shortHex(i.id, 8, 6)}
          </Link>
          <span className="micro-label">
            digest {shortHex(i.tx_digest_hex, 8, 6)} ·{" "}
            {stale ? "stale" : formatRelative(i.expiry, now)}
          </span>
        </div>
        <span className="shrink-0">
          <IntentStatusBadge status={stale ? "expired" : i.status} />
        </span>
      </div>
    );
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>intents</CardTitle>
        <Link
          to="/intents"
          className="micro-label text-muted hover:text-paper"
        >
          all →
        </Link>
      </CardHeader>
      <CardContent>
        <div className="micro-label pb-1 text-dim">
          pending approvals ({pending.length})
        </div>
        {pending.length === 0 && (
          <div className="py-2">
            <span className="micro-label">none pending</span>
          </div>
        )}
        {pending.slice(0, 4).map(row)}
        <div className="micro-label pb-1 pt-2 text-dim">
          recent ({recent.length})
        </div>
        {recent.length === 0 && (
          <div className="py-2">
            <span className="micro-label">no intents yet</span>
          </div>
        )}
        {recent.slice(0, 4).map(row)}
      </CardContent>
    </Card>
  );
}

function CredentialsPanel() {
  const q = useWalletStatusQuery();
  const count = q.data?.credentials;
  return (
    <Card>
      <CardHeader>
        <CardTitle>passkeys</CardTitle>
        <Link to="/passkeys" className="micro-label text-muted hover:text-paper">
          manage →
        </Link>
      </CardHeader>
      <CardContent>
        <DataRow label="enrolled credentials">
          {q.isPending && !q.data ? (
            <Skeleton className="h-4 w-16" />
          ) : (
            <span className="mono-value">
              {typeof count === "number" ? count : "—"}
            </span>
          )}
        </DataRow>
        <DataRow label="role">
          <span className="micro-label text-muted">
            approval only — never a bitcoin signature
          </span>
        </DataRow>
        <DataRow label="enrollment">
          <span className="micro-label text-muted">
            locked after first credential
          </span>
        </DataRow>
      </CardContent>
    </Card>
  );
}

export function DashboardPage() {
  const wallet = useWalletStatusQuery();
  const node = useNodeStatusQuery();
  return (
    <div>
      <div className="mb-4 flex items-baseline justify-between gap-4">
        <h1 className="text-sm font-semibold uppercase tracking-[0.2em] text-paper">
          Overview
        </h1>
        <span className="micro-label">
          blocks {wallet.data?.node?.blocks.toLocaleString() ?? "—"} · synced{" "}
          {node.data ? "signet" : "unknown"}
        </span>
      </div>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <InquisitionNodePanel />
        <WalletNodePanel />
        <ThresholdPanel />
        <SignerPanel />
        <IntentsPanel />
        <CredentialsPanel />
      </div>
    </div>
  );
}

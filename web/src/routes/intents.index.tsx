import { useState, type FormEvent } from "react";
import { Link } from "@tanstack/react-router";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertTitle } from "@/components/ui/alert";
import { Skeleton } from "@/components/ui/skeleton";
import { IntentStatusBadge } from "@/components/IntentStatusBadge";
import { useCreateIntentMutation, useIntentsQuery, useSignerStatusQuery } from "@/lib/hooks";
import { ApiError } from "@/lib/api";
import { formatRelative, formatUnix, shortHex } from "@/lib/format";
import type { CreateIntentRequest, SigningIntent } from "@/lib/types";

const HEX64 = /^[0-9a-fA-F]{64}$/;
const UUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

function CreateIntentForm() {
  const signer = useSignerStatusQuery();
  const create = useCreateIntentMutation();
  const now = Math.floor(Date.now() / 1000);

  const [walletId, setWalletId] = useState("00000000-0000-0000-0000-000000000001");
  const [signerId, setSignerId] = useState<string>(
    signer.data?.signer_id ? String(signer.data.signer_id) : "1",
  );
  const [txDigest, setTxDigest] = useState("");
  const [sessionId, setSessionId] = useState("");
  const [ttlMinutes, setTtlMinutes] = useState("60");

  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [submitError, setSubmitError] = useState<string | null>(null);

  const ttl = Math.max(1, Math.floor(Number(ttlMinutes) || 60));
  const expiry = now + ttl * 60;

  function validate(): CreateIntentRequest | null {
    const errors: Record<string, string> = {};
    if (!UUID.test(walletId.trim())) {
      errors.walletId = "wallet id must be a uuid";
    }
    const sid = Number(signerId);
    if (!Number.isInteger(sid) || sid < 1 || sid > 65535) {
      errors.signerId = "signer id must be 1..65535";
    }
    if (!HEX64.test(txDigest.trim())) {
      errors.txDigest = "transaction digest must be 64 hex chars";
    }
    if (!HEX64.test(sessionId.trim())) {
      errors.sessionId = "session id must be 64 hex chars";
    }
    setFieldErrors(errors);
    if (Object.keys(errors).length > 0) return null;
    return {
      wallet_id: walletId.trim().toLowerCase(),
      signer_id: sid,
      tx_digest: txDigest.trim().toLowerCase(),
      session_id: sessionId.trim().toLowerCase(),
      expiry,
    };
  }

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    setSubmitError(null);
    const req = validate();
    if (!req) return;
    create.mutate(req, {
      onSuccess: () => {
        setTxDigest("");
        setSessionId("");
      },
      onError: (err) => {
        setSubmitError(
          err instanceof ApiError
            ? `${err.code}: ${err.message}`
            : (err as Error).message,
        );
      },
    });
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>create signing intent</CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={onSubmit} className="flex flex-col gap-3">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <div>
              <Label htmlFor="wallet-id">wallet id (uuid)</Label>
              <Input
                id="wallet-id"
                value={walletId}
                onChange={(e) => setWalletId(e.target.value)}
                className={fieldErrors.walletId ? "border-paper" : undefined}
              />
              {fieldErrors.walletId && (
                <span className="micro-label mt-1 block text-paper">
                  {fieldErrors.walletId}
                </span>
              )}
            </div>
            <div>
              <Label htmlFor="signer-id">signer id</Label>
              <Input
                id="signer-id"
                value={signerId}
                onChange={(e) => setSignerId(e.target.value)}
                className={fieldErrors.signerId ? "border-paper" : undefined}
              />
              <span className="micro-label mt-1 block text-dim">
                must match the node's local participant (
                {signer.data?.signer_id ? `#${signer.data.signer_id}` : "unknown"})
              </span>
              {fieldErrors.signerId && (
                <span className="micro-label mt-1 block text-paper">
                  {fieldErrors.signerId}
                </span>
              )}
            </div>
          </div>
          <div>
            <Label htmlFor="tx-digest">exact transaction digest (64 hex)</Label>
            <Input
              id="tx-digest"
              value={txDigest}
              onChange={(e) => setTxDigest(e.target.value)}
              placeholder="32 bytes being signed, hex encoded"
              spellCheck={false}
              autoCapitalize="none"
              className="font-mono"
            />
            {fieldErrors.txDigest && (
              <span className="micro-label mt-1 block text-paper">
                {fieldErrors.txDigest}
              </span>
            )}
          </div>
          <div>
            <Label htmlFor="session-id">frost session id (64 hex)</Label>
            <Input
              id="session-id"
              value={sessionId}
              onChange={(e) => setSessionId(e.target.value)}
              placeholder="opaque 32-byte FROST session"
              spellCheck={false}
              autoCapitalize="none"
              className="font-mono"
            />
            {fieldErrors.sessionId && (
              <span className="micro-label mt-1 block text-paper">
                {fieldErrors.sessionId}
              </span>
            )}
          </div>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <div>
              <Label htmlFor="ttl">expiry (minutes from now)</Label>
              <Input
                id="ttl"
                type="number"
                min={1}
                value={ttlMinutes}
                onChange={(e) => setTtlMinutes(e.target.value)}
              />
            </div>
            <div className="flex items-end pb-1">
              <span className="micro-label text-muted">
                resolves to unix {expiry} · {formatRelative(expiry, now)}
              </span>
            </div>
          </div>
          {submitError && (
            <Alert variant="danger">
              <AlertTitle>intent rejected</AlertTitle>
              <div className="text-muted">{submitError}</div>
            </Alert>
          )}
          <div className="flex items-center justify-between gap-4 border-t border-line pt-3">
            <span className="micro-label text-dim">
              agents can create the same immutable intent; approval stays
              passkey-gated
            </span>
            <Button type="submit" disabled={create.isPending}>
              {create.isPending ? "creating…" : "create intent"}
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

function IntentRow({ intent }: { intent: SigningIntent }) {
  const now = Date.now() / 1000;
  const stale = intent.status === "pending" && intent.expiry <= now;
  const displayStatus = stale && intent.status === "pending" ? "expired" : intent.status;
  return (
    <Link
      to="/intents/$intentId"
      params={{ intentId: intent.id }}
      className="block border-b border-line py-2 transition-colors last:border-b-0 hover:bg-panel-2"
    >
      <div className="flex items-center justify-between gap-4">
        <div className="flex min-w-0 flex-col gap-0.5">
          <span className="mono-value text-paper">
            {shortHex(intent.id, 8, 6)}
          </span>
          <span className="micro-label">
            digest {shortHex(intent.tx_digest, 8, 6)} · signer #{intent.signer_id} ·{" "}
            {stale ? "stale — expired" : `expires ${formatRelative(intent.expiry, now)}`}
          </span>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <span className="micro-label text-dim">
            {formatUnix(intent.created_at)}
          </span>
          <IntentStatusBadge status={displayStatus} />
        </div>
      </div>
    </Link>
  );
}

export function IntentsPage() {
  const q = useIntentsQuery();
  return (
    <div>
      <div className="mb-4">
        <h1 className="text-sm font-semibold uppercase tracking-[0.2em] text-paper">
          Intents
        </h1>
      </div>
      <div className="flex flex-col gap-3">
        <CreateIntentForm />
        <Card>
          <CardHeader>
            <CardTitle>all intents ({q.data?.length ?? 0})</CardTitle>
          </CardHeader>
          <CardContent>
            {q.isPending && (
              <div className="flex flex-col gap-2 py-1">
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-4 w-2/3" />
              </div>
            )}
            {q.isError && (
              <Alert variant="warn">
                <AlertTitle>intent list unavailable</AlertTitle>
                <div className="text-muted">{q.error.message}</div>
              </Alert>
            )}
            {q.isSuccess && q.data.length === 0 && (
              <span className="micro-label">no intents yet</span>
            )}
            {q.isSuccess &&
              q.data.map((i) => <IntentRow key={i.id} intent={i} />)}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

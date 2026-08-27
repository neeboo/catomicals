import { useState } from "react";
import { Link, useParams } from "@tanstack/react-router";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Alert, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { DataRow } from "@/components/DataRow";
import { HexValue } from "@/components/HexValue";
import { IntentStatusBadge, PhaseBadge } from "@/components/IntentStatusBadge";
import {
  useCancelIntentMutation,
  useIntentQuery,
  useSigningStatusQuery,
  useTransactionReviewQuery,
  useWalletStatusQuery,
} from "@/lib/hooks";
import { ApiError, api } from "@/lib/api";
import { formatRelative, formatUnix, shortHex } from "@/lib/format";
import { browserAssert } from "@/lib/webauthn";
import type {
  ApprovalFinishResponse,
  ApprovalStartResponse,
} from "@/lib/types";

const ACTION_LABELS: Record<string, string> = {
  sign_taproot_transaction:
    "Sign a Taproot transaction — the covenant-aware signing action authorized by this intent. The exact transaction digest is bound into the immutable intent and into the approval challenge.",
};

function actionSummary(action: string): string {
  return (
    ACTION_LABELS[action] ??
    `Signing action "${action}" (bound by protocol version, network and nonce).`
  );
}

function errorTitle(code: string | undefined, status: number): string {
  if (status === 401 || code === "webauthn_rejected") return "approval rejected";
  if (code === "ceremony_consumed_or_missing") return "approval ceremony consumed";
  if (code === "state_conflict") return "approval state conflict";
  if (code === "network_error") return "wallet node offline";
  if (code === "intent_not_found") return "intent not found";
  return "approval failed";
}

function errorGuidance(code: string | undefined): string {
  switch (code) {
    case "webauthn_rejected":
      return "The wallet node rejected the authenticator response (signature, origin, RP ID hash, user verification or counter check failed). No signer action was released.";
    case "ceremony_consumed_or_missing":
      return "The one-use ceremony was already consumed or never existed. Start a fresh approval ceremony.";
    case "state_conflict":
      return "The intent is no longer pending, has expired, or the ceremony binding no longer matches the intent. Review the intent state and retry.";
    case "network_error":
      return "The wallet node could not be reached. Reconnect and retry.";
    default:
      return "No signer action was released. Check the error code above.";
  }
}

type ApprovalState =
  | { kind: "idle" }
  | { kind: "starting" }
  | { kind: "started"; ceremony: ApprovalStartResponse }
  | { kind: "asserting" }
  | { kind: "submitting" }
  | { kind: "success"; result: ApprovalFinishResponse }
  | {
      kind: "error";
      title: string;
      message: string;
      code: string | undefined;
    };

function ApprovalPanel({ intentId }: { intentId: string }) {
  const intent = useIntentQuery(intentId);
  const signing = useSigningStatusQuery(intentId);
  const [state, setState] = useState<ApprovalState>({ kind: "idle" });
  const now = Math.floor(Date.now() / 1000);

  const data = intent.data;
  const pending = data?.status === "pending";
  const stale = pending && !!data && data.expiry <= now;

  function fail(err: unknown) {
    if (err instanceof ApiError) {
      setState({
        kind: "error",
        title: errorTitle(err.code, err.status),
        message: err.message,
        code: err.code,
      });
    } else {
      const message = (err as Error).message;
      const cancelled =
        message.toLowerCase().includes("cancel") ||
        message.toLowerCase().includes("not allowed");
      setState({
        kind: "error",
        title: cancelled ? "approval cancelled" : "approval failed",
        message,
        code: undefined,
      });
    }
  }

  async function start() {
    setState({ kind: "starting" });
    try {
      const ceremony = await api.approvalStart(intentId);
      setState({ kind: "started", ceremony });
    } catch (err) {
      fail(err);
    }
  }

  async function confirmAndApprove() {
    if (state.kind !== "started") return;
    setState({ kind: "asserting" });
    try {
      const credential = await browserAssert(state.ceremony.public_key);
      setState({ kind: "submitting" });
      const result = await api.approvalFinish(intentId, {
        ceremony_id: state.ceremony.ceremony_id,
        credential,
      });
      setState({ kind: "success", result });
    } catch (err) {
      fail(err);
    }
  }

  if (intent.isPending && !data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>passkey approval</CardTitle>
        </CardHeader>
        <CardContent>
          <Skeleton className="h-4 w-full" />
        </CardContent>
      </Card>
    );
  }

  if (!data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>passkey approval</CardTitle>
        </CardHeader>
        <CardContent>
          <span className="micro-label">{intent.error?.message ?? "unknown error"}</span>
        </CardContent>
      </Card>
    );
  }

  const binding = state.kind === "started" ? state.ceremony.binding : null;

  return (
    <Card>
      <CardHeader>
        <CardTitle>passkey approval</CardTitle>
        <PhaseBadge phase={signing.data?.phase ?? "pending_approval"} />
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {stale && (
          <Alert variant="warn">
            <AlertTitle>stale intent</AlertTitle>
            <div className="text-muted">
              This intent expired at {formatUnix(data.expiry)} and can no longer
              be approved or signed. Create a fresh intent.
            </div>
          </Alert>
        )}
        {!stale && !pending && (
          <Alert variant="default">
            <AlertTitle>not approvable</AlertTitle>
            <div className="text-muted">
              Only pending intents can be approved. Current status: {data.status}.
            </div>
          </Alert>
        )}

        {state.kind === "idle" && pending && !stale && (
          <div className="flex flex-col gap-3">
            <span className="micro-label">
              The node binds this intent's digest, signer, FROST session,
              message and expiry to a fresh WebAuthn challenge server-side.
              Nothing is released until the browser assertion fully verifies.
            </span>
            <div className="flex items-center justify-between gap-4">
              <span className="micro-label text-dim">
                one-use · user verification required · no dev override
              </span>
              <Button onClick={() => void start()}>
                start passkey approval
              </Button>
            </div>
          </div>
        )}
        {state.kind === "starting" && (
          <span className="micro-label animate-blink text-muted">
            starting ceremony…
          </span>
        )}
        {state.kind === "started" && binding && (
          <div className="flex flex-col gap-3">
            <div className="border border-line-strong bg-panel-2 px-3 py-2">
              <div className="micro-label mb-1 text-paper">
                you are approving exactly this
              </div>
              <DataRow label="intent id">
                <HexValue value={binding.intent_id} head={8} tail={6} />
              </DataRow>
              <DataRow label="bound intent digest">
                <HexValue value={binding.intent_digest_hex} head={12} tail={12} />
              </DataRow>
              <DataRow label="signer">
                <span className="mono-value">#{binding.signer_id}</span>
              </DataRow>
              <DataRow label="frost session">
                <HexValue value={binding.session_id_hex} head={10} tail={8} />
              </DataRow>
              <DataRow label="exact message">
                <HexValue value={binding.message_hex} head={12} tail={12} />
              </DataRow>
              <DataRow label="expires">
                <span className="mono-value text-muted">
                  {formatUnix(binding.expires_at)} ({formatRelative(binding.expires_at, now)})
                </span>
              </DataRow>
            </div>
            <div className="flex items-center justify-between gap-4">
              <span className="micro-label text-dim">
                the OS prompt will ask for your passkey and user verification
              </span>
              <div className="flex gap-2">
                <Button variant="ghost" onClick={() => setState({ kind: "idle" })}>
                  cancel
                </Button>
                <Button onClick={() => void confirmAndApprove()}>
                  approve with passkey
                </Button>
              </div>
            </div>
          </div>
        )}
        {(state.kind === "asserting" || state.kind === "submitting") && (
          <span className="micro-label animate-blink text-muted">
            {state.kind === "asserting"
              ? "waiting for passkey assertion…"
              : "verifying approval with the wallet node…"}
          </span>
        )}
        {state.kind === "success" && (
          <Alert variant="default">
            <AlertTitle>approved</AlertTitle>
            <div className="text-muted">
              Intent {shortHex(state.result.intent_id, 8, 6)} approved by signer #
              {state.result.signer_id}. One internal signer action was released;
              authorization expires {formatUnix(state.result.expires_at)}.
            </div>
          </Alert>
        )}
        {state.kind === "error" && (
          <Alert variant="danger">
            <AlertTitle>{state.title}</AlertTitle>
            <div className="text-muted">
              <div>{state.message}</div>
              <div className="mt-1">{errorGuidance(state.code)}</div>
            </div>
          </Alert>
        )}
      </CardContent>
    </Card>
  );
}

function ThresholdNote({ intentId }: { intentId: string }) {
  const wallet = useWalletStatusQuery();
  const signing = useSigningStatusQuery(intentId);
  const online = wallet.data?.signers.filter((s) => s.online).length ?? 0;
  const min = wallet.data?.threshold.min_signers ?? 0;
  const max = wallet.data?.threshold.max_signers ?? 0;
  const insufficient = min > 0 && online < min;

  if (signing.data?.phase !== "approved") return null;
  return (
    <Alert variant={insufficient ? "warn" : "default"}>
      <AlertTitle>threshold signing</AlertTitle>
      <div className="text-muted">
        {insufficient ? (
          <>
            This node holds only one local FROST participant and the threshold
            is {min} of {max}. Without authenticated remote signers, the
            aggregate Taproot signature cannot complete on this single-node
            deployment — an honest limitation, not a mock.
          </>
        ) : (
          <>
            The intent is approved and {online} of {min} signers are online.
            Signing phase: {signing.data.phase.replaceAll("_", " ")}.
          </>
        )}
      </div>
    </Alert>
  );
}

function ReviewedTransactionBinding({
  intentId,
  expectedDigest,
}: {
  intentId: string;
  expectedDigest: string;
}) {
  const review = useTransactionReviewQuery(intentId);
  if (!review.data) return null;
  const digestMatches = review.data.sighash_hex === expectedDigest;

  return (
    <Card>
      <CardHeader>
        <CardTitle>decoded transaction bound to this intent</CardTitle>
        <Badge variant={digestMatches ? "solid" : "warn"}>
          {digestMatches ? "digest verified" : "digest mismatch"}
        </Badge>
      </CardHeader>
      <CardContent className="flex flex-col gap-2">
        {!digestMatches && (
          <Alert variant="danger">
            <AlertTitle>do not approve</AlertTitle>
            <div className="text-muted">
              The stored transaction review no longer derives the digest shown by this intent.
            </div>
          </Alert>
        )}
        <DataRow label="transaction id">
          <HexValue value={review.data.txid} head={12} tail={12} />
        </DataRow>
        <DataRow label="amounts">
          <span className="mono-value">
            {review.data.input_total_sat.toLocaleString()} sat in · {review.data.output_total_sat.toLocaleString()} sat out
          </span>
        </DataRow>
        <DataRow label="fee">
          <span className="mono-value">
            {review.data.fee_sat.toLocaleString()} sat · {(review.data.fee_rate_milli_sat_vb / 1000).toFixed(3)} sat/vB
          </span>
        </DataRow>
        <DataRow label="replacement">
          <span className="mono-value">{review.data.signals_rbf ? "RBF signalled" : "not signalled"}</span>
        </DataRow>
        <div className="mt-1 border-t border-line pt-2">
          {review.data.outputs.map((output) => (
            <div key={output.index} className="grid grid-cols-[5rem_1fr_auto] gap-2 border-b border-line py-1 last:border-0">
              <span className="micro-label">output #{output.index}</span>
              <span className="mono-value break-all">{output.address ?? output.script_pubkey_hex}</span>
              <span className="mono-value">{output.value_sat.toLocaleString()} sat</span>
            </div>
          ))}
        </div>
        {review.data.warnings.length > 0 && (
          <Alert variant="warn">
            <AlertTitle>review warnings</AlertTitle>
            <div className="text-muted">
              {review.data.warnings.map((warning) => `${warning.code}: ${warning.message}`).join(" · ")}
            </div>
          </Alert>
        )}
      </CardContent>
    </Card>
  );
}

export function IntentDetailPage() {
  const params = useParams({ strict: false });
  const intentId = params.intentId as string;
  const q = useIntentQuery(intentId);
  const cancel = useCancelIntentMutation();
  const now = Math.floor(Date.now() / 1000);
  const intent = q.data;

  if (q.isPending && !intent) {
    return (
      <div className="flex flex-col gap-3">
        <Skeleton className="h-5 w-56" />
        <Card>
          <CardContent className="flex flex-col gap-2">
            <Skeleton className="h-4 w-full" />
            <Skeleton className="h-4 w-full" />
            <Skeleton className="h-4 w-3/4" />
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!intent) {
    return (
      <div className="flex flex-col gap-3">
        <Alert variant="warn">
          <AlertTitle>intent unavailable</AlertTitle>
          <div className="text-muted">
            {q.error instanceof ApiError
              ? q.error.message
              : (q.error?.message ?? "not found")}
          </div>
        </Alert>
        <Link to="/intents" className="micro-label text-muted hover:text-paper">
          ← back to intents
        </Link>
      </div>
    );
  }

  const pending = intent.status === "pending";
  const stale = pending && intent.expiry <= now;

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-baseline gap-3">
          <Link to="/intents" className="micro-label text-muted hover:text-paper">
            ← intents
          </Link>
          <h1 className="text-sm font-semibold uppercase tracking-[0.2em] text-paper">
            intent
          </h1>
          <span className="mono-value text-dim">{shortHex(intent.id, 10, 8)}</span>
        </div>
        <div className="flex items-center gap-2">
          <IntentStatusBadge status={stale ? "expired" : intent.status} />
          {pending && (
            <Button
              variant="ghost"
              disabled={cancel.isPending}
              onClick={() => {
                if (window.confirm("Cancel this intent? This cannot be undone.")) {
                  cancel.mutate(intent.id);
                }
              }}
            >
              {cancel.isPending ? "cancelling…" : "cancel intent"}
            </Button>
          )}
        </div>
      </div>

      {stale && (
        <Alert variant="warn">
          <AlertTitle>stale intent</AlertTitle>
          <div className="text-muted">
            This pending intent passed its expiry ({formatUnix(intent.expiry)}).
            The wallet node will refuse to approve or sign it.
          </div>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle>covenant / action summary</CardTitle>
          <Badge variant="outline">{intent.action}</Badge>
        </CardHeader>
        <CardContent>
          <p className="text-[12px] leading-5 text-paper">{actionSummary(intent.action)}</p>
          <div className="mt-2 border-t border-line pt-2">
            <DataRow label="network">
              <span className="mono-value">{intent.network}</span>
            </DataRow>
            <DataRow label="protocol version">
              <span className="mono-value">{intent.protocol_version}</span>
            </DataRow>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>immutable fields</CardTitle>
        </CardHeader>
        <CardContent>
          <DataRow label="intent id">
            <HexValue value={intent.id} full />
          </DataRow>
          <DataRow label="wallet id">
            <HexValue value={intent.wallet_id} full />
          </DataRow>
          <DataRow label="signer id">
            <span className="mono-value">#{intent.signer_id}</span>
          </DataRow>
          <DataRow label="exact transaction digest">
            <HexValue value={intent.tx_digest} full />
          </DataRow>
          <DataRow label="frost session id">
            <HexValue value={intent.session_id} full />
          </DataRow>
          <DataRow label="one-time nonce">
            <HexValue value={intent.nonce} full />
          </DataRow>
          <DataRow label="created">
            <span className="mono-value text-muted">{formatUnix(intent.created_at)}</span>
          </DataRow>
          <DataRow label="expiry">
            <span className="mono-value">
              {formatUnix(intent.expiry)}
              <span className="text-dim"> ({formatRelative(intent.expiry, now)})</span>
            </span>
          </DataRow>
        </CardContent>
      </Card>

      <ReviewedTransactionBinding
        intentId={intent.id}
        expectedDigest={intent.tx_digest}
      />

      <ApprovalPanel intentId={intent.id} />
      <ThresholdNote intentId={intent.id} />
    </div>
  );
}

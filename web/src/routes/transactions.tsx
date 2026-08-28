import { useState, type FormEvent } from "react";
import { Link } from "@tanstack/react-router";
import { Alert, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { DataRow } from "@/components/DataRow";
import { HexValue } from "@/components/HexValue";
import { ApiError } from "@/lib/api";
import {
  useCreateTransactionIntentMutation,
  useInspectTransactionMutation,
  useSignerStatusQuery,
} from "@/lib/hooks";
import type {
  CreateTransactionIntentRequest,
  SigningIntent,
  TransactionPrevout,
  TransactionReview,
  TransactionReviewRequest,
} from "@/lib/types";

const HEX64 = /^[0-9a-fA-F]{64}$/;
const UUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

function errorText(error: unknown): string {
  return error instanceof ApiError
    ? `${error.code}: ${error.message}`
    : (error as Error).message;
}

function randomSessionId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

function ReviewPanel({ review }: { review: TransactionReview }) {
  return (
    <div className="flex flex-col gap-3">
      <Card>
        <CardHeader>
          <CardTitle>decoded transaction</CardTitle>
          <Badge variant={review.signing_allowed ? "solid" : "warn"}>
            {review.signing_allowed ? "signing allowed" : "blocked"}
          </Badge>
        </CardHeader>
        <CardContent>
          <DataRow label="transaction id">
            <HexValue value={review.txid} head={12} tail={12} />
          </DataRow>
          <DataRow label="wallet-derived BIP341 digest">
            <HexValue value={review.sighash_hex} head={12} tail={12} />
          </DataRow>
          <DataRow label="signature hash type">
            <span className="mono-value">SIGHASH_{review.sighash_type.toUpperCase()}</span>
          </DataRow>
          <DataRow label="inputs / outputs">
            <span className="mono-value">{review.input_count} / {review.output_count}</span>
          </DataRow>
          <DataRow label="amounts">
            <span className="mono-value">
              {review.input_total_sat.toLocaleString()} in · {review.output_total_sat.toLocaleString()} out
            </span>
          </DataRow>
          <DataRow label="fee">
            <span className="mono-value">
              {review.fee_sat.toLocaleString()} sat · {(review.fee_rate_milli_sat_vb / 1000).toFixed(3)} sat/vB
            </span>
          </DataRow>
          <DataRow label="size">
            <span className="mono-value">{review.vsize} vB · {review.weight_wu} wu</span>
          </DataRow>
          <DataRow label="replacement">
            <span className="mono-value">{review.signals_rbf ? "RBF signalled" : "not signalled"}</span>
          </DataRow>
        </CardContent>
      </Card>

      {review.warnings.length > 0 && (
        <Alert variant="warn">
          <AlertTitle>{review.warnings.length} review warning(s)</AlertTitle>
          <div className="mt-2 flex flex-col gap-1">
            {review.warnings.map((warning, index) => (
              <div key={`${warning.code}-${index}`} className="text-muted">
                <span className="mono-value text-paper">{warning.code}</span>: {warning.message}
                {warning.input_index !== null ? ` input #${warning.input_index}` : ""}
                {warning.output_index !== null ? ` output #${warning.output_index}` : ""}
              </div>
            ))}
          </div>
        </Alert>
      )}

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
        <Card>
          <CardHeader><CardTitle>ordered prevouts</CardTitle></CardHeader>
          <CardContent className="flex flex-col gap-2">
            {review.inputs.map((input) => (
              <div key={input.index} className="border-b border-line pb-2 last:border-0 last:pb-0">
                <div className="mb-1 flex items-center justify-between gap-2">
                  <span className="micro-label">input #{input.index}</span>
                  <Badge variant={input.signing_input ? "solid" : "outline"}>
                    {input.signing_input ? "signing input" : input.script_type}
                  </Badge>
                </div>
                <DataRow label="outpoint"><HexValue value={input.outpoint} head={10} tail={8} /></DataRow>
                <DataRow label="value"><span className="mono-value">{input.value_sat.toLocaleString()} sat</span></DataRow>
                <DataRow label="address"><span className="mono-value break-all">{input.address ?? "unrecognized"}</span></DataRow>
                <DataRow label="sequence"><span className="mono-value">{input.sequence}</span></DataRow>
              </div>
            ))}
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>payments and change</CardTitle></CardHeader>
          <CardContent className="flex flex-col gap-2">
            {review.outputs.map((output) => (
              <div key={output.index} className="border-b border-line pb-2 last:border-0 last:pb-0">
                <div className="mb-1 flex items-center justify-between gap-2">
                  <span className="micro-label">output #{output.index}</span>
                  <Badge variant={output.dust ? "warn" : "outline"}>{output.script_type}</Badge>
                </div>
                <DataRow label="value"><span className="mono-value">{output.value_sat.toLocaleString()} sat</span></DataRow>
                <DataRow label="address"><span className="mono-value break-all">{output.address ?? "unrecognized"}</span></DataRow>
                <DataRow label="script"><HexValue value={output.script_pubkey_hex} head={14} tail={10} /></DataRow>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

export function TransactionsPage() {
  const signer = useSignerStatusQuery();
  const inspect = useInspectTransactionMutation();
  const create = useCreateTransactionIntentMutation();
  const [rawTxHex, setRawTxHex] = useState("");
  const [prevoutsJson, setPrevoutsJson] = useState("[]");
  const [inputIndex, setInputIndex] = useState("0");
  const [maxFeeSat, setMaxFeeSat] = useState("10000");
  const [walletId, setWalletId] = useState("00000000-0000-0000-0000-000000000001");
  const [signerId, setSignerId] = useState("1");
  const [sessionId, setSessionId] = useState("");
  const [ttlMinutes, setTtlMinutes] = useState("60");
  const [formError, setFormError] = useState<string | null>(null);
  const [createdIntent, setCreatedIntent] = useState<SigningIntent | null>(null);
  const [reviewedRequest, setReviewedRequest] = useState<string | null>(null);

  function transactionRequest(): TransactionReviewRequest | null {
    try {
      const prevouts = JSON.parse(prevoutsJson) as TransactionPrevout[];
      if (!Array.isArray(prevouts)) throw new Error("prevouts must be a JSON array");
      const index = Number(inputIndex);
      const limit = Number(maxFeeSat);
      if (!Number.isSafeInteger(index) || index < 0) throw new Error("input index must be a non-negative integer");
      if (!Number.isSafeInteger(limit) || limit < 0) throw new Error("maximum fee must be a non-negative integer");
      return {
        raw_tx_hex: rawTxHex.trim().toLowerCase(),
        prevouts,
        input_index: index,
        max_fee_sat: limit,
      };
    } catch (error) {
      setFormError((error as Error).message);
      return null;
    }
  }

  function onInspect(event: FormEvent) {
    event.preventDefault();
    setFormError(null);
    setCreatedIntent(null);
    const request = transactionRequest();
    if (!request) return;
    inspect.mutate(request, {
      onSuccess: () => setReviewedRequest(JSON.stringify(request)),
      onError: (error) => {
        setReviewedRequest(null);
        setFormError(errorText(error));
      },
    });
  }

  function onCreateIntent() {
    setFormError(null);
    const transaction = transactionRequest();
    if (!transaction) return;
    if (JSON.stringify(transaction) !== reviewedRequest) {
      return setFormError("transaction fields changed after review; inspect the current transaction again");
    }
    const sid = Number(signerId || signer.data?.signer_id);
    if (!UUID.test(walletId.trim())) return setFormError("wallet id must be a UUID");
    if (!Number.isInteger(sid) || sid < 1 || sid > 65535) return setFormError("signer id must be 1..65535");
    if (!HEX64.test(sessionId.trim())) return setFormError("FROST session id must be 64 hex characters");
    const minutes = Number(ttlMinutes);
    if (!Number.isFinite(minutes) || minutes < 1) return setFormError("expiry must be at least one minute");
    const request: CreateTransactionIntentRequest = {
      wallet_id: walletId.trim().toLowerCase(),
      signer_id: sid,
      session_id: sessionId.trim().toLowerCase(),
      expiry: Math.floor(Date.now() / 1000 + minutes * 60),
      transaction,
    };
    create.mutate(request, {
      onSuccess: setCreatedIntent,
      onError: (error) => setFormError(errorText(error)),
    });
  }

  return (
    <div className="flex flex-col gap-3">
      <Card>
        <CardHeader>
          <CardTitle>transaction review</CardTitle>
          <Badge variant="outline">unsigned Taproot · Signet</Badge>
        </CardHeader>
        <CardContent>
          <form onSubmit={onInspect} className="flex flex-col gap-3">
            <Alert variant="default">
              <AlertTitle>the wallet derives the signing digest</AlertTitle>
              <div className="text-muted">
                Supply the complete unsigned transaction and every ordered prevout. There is no editable transaction-digest field in this flow.
              </div>
            </Alert>
            <div>
              <Label htmlFor="raw-tx">unsigned transaction hex</Label>
              <textarea id="raw-tx" value={rawTxHex} onChange={(event) => setRawTxHex(event.target.value)} rows={5} spellCheck={false} className="mt-1 w-full resize-y border border-line bg-black px-2 py-1.5 font-mono text-[15px] text-paper outline-none focus:border-line-strong" />
            </div>
            <div>
              <Label htmlFor="prevouts">ordered prevouts (JSON)</Label>
              <textarea id="prevouts" value={prevoutsJson} onChange={(event) => setPrevoutsJson(event.target.value)} rows={6} spellCheck={false} className="mt-1 w-full resize-y border border-line bg-black px-2 py-1.5 font-mono text-[15px] text-paper outline-none focus:border-line-strong" />
              <span className="micro-label mt-1 block text-dim">each item: outpoint, value_sat, script_pubkey_hex · same order as transaction inputs</span>
            </div>
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <div><Label htmlFor="input-index">signing input index</Label><Input id="input-index" type="number" min={0} value={inputIndex} onChange={(event) => setInputIndex(event.target.value)} /></div>
              <div><Label htmlFor="max-fee">maximum allowed fee (sat)</Label><Input id="max-fee" type="number" min={0} value={maxFeeSat} onChange={(event) => setMaxFeeSat(event.target.value)} /></div>
            </div>
            {formError && <Alert variant="danger"><AlertTitle>transaction rejected</AlertTitle><div className="text-muted">{formError}</div></Alert>}
            <div className="flex justify-end"><Button type="submit" size="lg" disabled={inspect.isPending}>{inspect.isPending ? "checking…" : "inspect transaction"}</Button></div>
          </form>
        </CardContent>
      </Card>

      {inspect.data && (
        <>
          <ReviewPanel review={inspect.data} />
          <Card>
            <CardHeader><CardTitle>create reviewed signing intent</CardTitle></CardHeader>
            <CardContent className="flex flex-col gap-3">
              <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                <div><Label htmlFor="wallet-id">wallet id</Label><Input id="wallet-id" value={walletId} onChange={(event) => setWalletId(event.target.value)} /></div>
                <div><Label htmlFor="signer-id">signer id</Label><Input id="signer-id" value={signerId} onChange={(event) => setSignerId(event.target.value)} placeholder={signer.data?.signer_id ? String(signer.data.signer_id) : "1"} /></div>
                <div>
                  <Label htmlFor="session-id">FROST session id</Label>
                  <div className="flex gap-2"><Input id="session-id" value={sessionId} onChange={(event) => setSessionId(event.target.value)} className="font-mono" /><Button type="button" variant="ghost" onClick={() => setSessionId(randomSessionId())}>generate</Button></div>
                </div>
                <div><Label htmlFor="ttl">expiry (minutes)</Label><Input id="ttl" type="number" min={1} value={ttlMinutes} onChange={(event) => setTtlMinutes(event.target.value)} /></div>
              </div>
              <div className="flex items-center justify-between gap-4 border-t border-line pt-3">
                <span className="micro-label text-dim">the node decodes the current fields again and binds its derived digest into the intent</span>
                <Button type="button" size="lg" onClick={onCreateIntent} disabled={create.isPending}>{create.isPending ? "creating…" : "create reviewed intent"}</Button>
              </div>
              {createdIntent && (
                <Alert variant="default">
                  <AlertTitle>reviewed intent created</AlertTitle>
                  <div className="flex items-center justify-between gap-3 text-muted">
                    <HexValue value={createdIntent.id} head={10} tail={8} />
                    <Link to="/intents/$intentId" params={{ intentId: createdIntent.id }} className="micro-label text-paper underline">review and approve</Link>
                  </div>
                </Alert>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}

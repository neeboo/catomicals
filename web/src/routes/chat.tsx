import { useState, type FormEvent } from "react";
import { Link } from "@tanstack/react-router";
import { Alert, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { DataRow } from "@/components/DataRow";
import { HexValue } from "@/components/HexValue";
import { ApiError } from "@/lib/api";
import { formatRelative, formatUnix } from "@/lib/format";
import {
  useChatStateQuery,
  useCreateChatMessageMutation,
  useSignerStatusQuery,
} from "@/lib/hooks";
import type {
  ChatAuthorizationState,
  ChatIntentBinding,
  ChatMessage,
  CreateChatMessageRequest,
} from "@/lib/types";

const HEX64 = /^[0-9a-fA-F]{64}$/;
const UUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

const AUTH_LABELS: Record<ChatAuthorizationState, string> = {
  passkey_required: "passkey required",
  approved: "approved",
  cancelled: "cancelled",
  expired: "expired",
  signed: "signed",
};

function WalletActionCard({ action }: { action: ChatIntentBinding }) {
  const now = Math.floor(Date.now() / 1000);
  const approvable = action.authorization === "passkey_required";
  return (
    <div className="mt-3 border border-line-strong bg-ink">
      <div className="flex items-center justify-between gap-3 border-b border-line px-3 py-2">
        <span className="micro-label text-paper">exact bound bytes</span>
        <Badge variant={approvable ? "solid" : "dim"}>
          {AUTH_LABELS[action.authorization]}
        </Badge>
      </div>
      <div className="px-3 py-1">
        <DataRow label="action">
          <span className="mono-value">{action.action}</span>
        </DataRow>
        <DataRow label="wallet">
          <HexValue value={action.wallet_id} head={8} tail={6} />
        </DataRow>
        <DataRow label="intent">
          <HexValue value={action.intent_id} head={8} tail={6} />
        </DataRow>
        <DataRow label="intent digest">
          <HexValue value={action.intent_digest_hex} head={12} tail={10} />
        </DataRow>
        <DataRow label="transaction digest">
          <HexValue value={action.tx_digest_hex} head={12} tail={10} />
        </DataRow>
        <DataRow label="frost session">
          <HexValue value={action.session_id_hex} head={10} tail={8} />
        </DataRow>
        <DataRow label="signer / network">
          <span className="mono-value">#{action.signer_id} · {action.network}</span>
        </DataRow>
        <DataRow label="expires">
          <span className="mono-value text-muted">
            {formatUnix(action.expiry)} · {formatRelative(action.expiry, now)}
          </span>
        </DataRow>
      </div>
      <div className="flex items-center justify-between gap-4 border-t border-line px-3 py-2">
        <span className="micro-label text-dim">
          {approvable
            ? "chat created a proposal only · webauthn user verification required"
            : `intent is ${action.authorization.replaceAll("_", " ")}`}
        </span>
        <Link
          to="/intents/$intentId"
          params={{ intentId: action.intent_id }}
          className="inline-flex h-8 items-center bg-paper px-3 text-[11px] font-medium uppercase tracking-[0.14em] text-ink hover:bg-white"
        >
          {approvable ? "review + approve" : "open intent"}
        </Link>
      </div>
    </div>
  );
}

function MessageRow({ message }: { message: ChatMessage }) {
  const wallet = message.role === "wallet";
  return (
    <article
      className={wallet ? "border-l border-paper pl-4" : "ml-10 border-l border-line-strong pl-4"}
    >
      <div className="mb-1 flex items-center justify-between gap-3">
        <span className={wallet ? "micro-label text-paper" : "micro-label"}>
          {wallet ? "wallet node" : "you"} · {message.kind.replaceAll("_", " ")}
        </span>
        <time className="micro-label text-dim" dateTime={new Date(message.created_at * 1000).toISOString()}>
          {formatUnix(message.created_at)}
        </time>
      </div>
      <p className="text-[12px] leading-5 text-paper">{message.content}</p>
      {message.wallet_action ? <WalletActionCard action={message.wallet_action} /> : null}
    </article>
  );
}

function ChatComposer() {
  const signer = useSignerStatusQuery();
  const send = useCreateChatMessageMutation();
  const [content, setContent] = useState("");
  const [withAction, setWithAction] = useState(false);
  const [walletId, setWalletId] = useState("00000000-0000-0000-0000-000000000001");
  const [signerId, setSignerId] = useState("1");
  const [txDigest, setTxDigest] = useState("");
  const [sessionId, setSessionId] = useState("");
  const [ttlMinutes, setTtlMinutes] = useState("60");
  const [formError, setFormError] = useState<string | null>(null);

  function request(): CreateChatMessageRequest | null {
    const clean = content.trim();
    if (!clean || new TextEncoder().encode(clean).length > 2_000) {
      setFormError("message must contain 1–2000 bytes");
      return null;
    }
    if (!withAction) return { content: clean };
    const sid = Number(signerId);
    const ttl = Number(ttlMinutes);
    if (!UUID.test(walletId.trim())) {
      setFormError("wallet id must be a UUID");
      return null;
    }
    if (!Number.isInteger(sid) || sid < 1 || sid > 65535) {
      setFormError("signer id must be in 1..65535");
      return null;
    }
    if (!HEX64.test(txDigest.trim()) || !HEX64.test(sessionId.trim())) {
      setFormError("transaction digest and FROST session must each be 64 hex characters");
      return null;
    }
    if (!Number.isFinite(ttl) || ttl < 1) {
      setFormError("expiry must be at least one minute");
      return null;
    }
    return {
      content: clean,
      wallet_action: {
        type: "sign_taproot_transaction",
        wallet_id: walletId.trim().toLowerCase(),
        signer_id: sid,
        tx_digest: txDigest.trim().toLowerCase(),
        session_id: sessionId.trim().toLowerCase(),
        expiry: Math.floor(Date.now() / 1000) + Math.floor(ttl) * 60,
      },
    };
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    setFormError(null);
    const payload = request();
    if (!payload) return;
    send.mutate(payload, {
      onSuccess: () => {
        setContent("");
        setTxDigest("");
        setSessionId("");
      },
      onError: (error) => {
        setFormError(
          error instanceof ApiError
            ? `${error.code}: ${error.message}`
            : (error as Error).message,
        );
      },
    });
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>compose</CardTitle>
        <Button
          size="sm"
          variant={withAction ? "default" : "outline"}
          onClick={() => setWithAction((current) => !current)}
        >
          {withAction ? "wallet action attached" : "attach wallet action"}
        </Button>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} className="flex flex-col gap-3">
          <div>
            <Label htmlFor="chat-message">message</Label>
            <textarea
              id="chat-message"
              value={content}
              onChange={(event) => setContent(event.target.value)}
              placeholder="Ask about the wallet or describe the exact action you want to prepare."
              maxLength={2_000}
              rows={3}
              className="w-full resize-y rounded-none border border-line-strong bg-ink px-2 py-2 text-[12px] leading-5 text-paper placeholder:text-dim focus-visible:border-paper focus-visible:outline-none"
            />
          </div>
          {withAction ? (
            <div className="grid grid-cols-1 gap-3 border border-line bg-panel-2 p-3 md:grid-cols-2">
              <div>
                <Label htmlFor="chat-wallet-id">wallet id</Label>
                <Input id="chat-wallet-id" value={walletId} onChange={(event) => setWalletId(event.target.value)} />
              </div>
              <div>
                <Label htmlFor="chat-signer-id">signer id</Label>
                <Input id="chat-signer-id" value={signerId} onChange={(event) => setSignerId(event.target.value)} />
                <span className="micro-label mt-1 block text-dim">
                  node participant {signer.data?.signer_id ? `#${signer.data.signer_id}` : "unknown"}
                </span>
              </div>
              <div className="md:col-span-2">
                <Label htmlFor="chat-tx-digest">exact transaction digest</Label>
                <Input id="chat-tx-digest" value={txDigest} onChange={(event) => setTxDigest(event.target.value)} placeholder="64 hex characters" className="font-mono" />
              </div>
              <div className="md:col-span-2">
                <Label htmlFor="chat-session-id">frost session id</Label>
                <Input id="chat-session-id" value={sessionId} onChange={(event) => setSessionId(event.target.value)} placeholder="64 hex characters" className="font-mono" />
              </div>
              <div>
                <Label htmlFor="chat-ttl">expiry in minutes</Label>
                <Input id="chat-ttl" type="number" min={1} value={ttlMinutes} onChange={(event) => setTtlMinutes(event.target.value)} />
              </div>
              <div className="flex items-end pb-1">
                <span className="micro-label text-dim">digest-only proposal · transaction semantics are not decoded here</span>
              </div>
            </div>
          ) : null}
          {formError ? (
            <Alert variant="danger">
              <AlertTitle>message rejected</AlertTitle>
              <div className="text-muted">{formError}</div>
            </Alert>
          ) : null}
          <div className="flex items-center justify-between gap-4 border-t border-line pt-3">
            <span className="micro-label text-dim">
              no chat command can approve, sign, or inject a verifier
            </span>
            <Button type="submit" disabled={send.isPending}>
              {send.isPending ? "sending…" : withAction ? "send + create intent" : "send message"}
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

export function ChatPage() {
  const chat = useChatStateQuery();
  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-end justify-between gap-4">
        <div>
          <h1 className="text-sm font-semibold uppercase tracking-[0.2em] text-paper">Chat</h1>
          <p className="micro-label mt-1">message the self-hosted wallet node · memory-only history</p>
        </div>
        <Badge variant={chat.data?.pending_wallet_actions ? "solid" : "dim"}>
          {chat.data?.pending_wallet_actions ?? 0} awaiting passkey
        </Badge>
      </div>

      <Card className="min-h-72">
        <CardHeader>
          <CardTitle>conversation ({chat.data?.messages.length ?? 0})</CardTitle>
          <span className="micro-label text-dim">live node state</span>
        </CardHeader>
        <CardContent className="flex flex-col gap-5 py-4" aria-live="polite">
          {chat.isPending ? (
            <div className="flex flex-col gap-3">
              <Skeleton className="h-10 w-3/4" />
              <Skeleton className="ml-10 h-10 w-2/3" />
            </div>
          ) : null}
          {chat.isError ? (
            <Alert variant="warn">
              <AlertTitle>chat unavailable</AlertTitle>
              <div className="text-muted">{chat.error.message}</div>
            </Alert>
          ) : null}
          {chat.isSuccess && chat.data.messages.length === 0 ? (
            <div className="grid min-h-48 place-items-center border border-dashed border-line-strong px-6 text-center">
              <div className="max-w-md">
                <div className="text-[12px] leading-5 text-paper">No messages yet.</div>
                <div className="micro-label mt-2 leading-4">
                  Ask about capabilities, or attach an exact Taproot signing action. The wallet will create a pending intent and wait for a real Passkey assertion.
                </div>
              </div>
            </div>
          ) : null}
          {chat.data?.messages.map((message) => <MessageRow key={message.id} message={message} />)}
        </CardContent>
      </Card>

      <ChatComposer />
    </div>
  );
}

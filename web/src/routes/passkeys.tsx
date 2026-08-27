import { useState, type FormEvent } from "react";
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
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { DataRow } from "@/components/DataRow";
import { HexValue } from "@/components/HexValue";
import {
  useCredentialsQuery,
  useCredentialsInvalidation,
  useWalletStatusQuery,
} from "@/lib/hooks";
import { ApiError, api } from "@/lib/api";
import { formatUnix, shortHex } from "@/lib/format";
import { browserRegister, isWebAuthnAvailable } from "@/lib/webauthn";
import type { RegisterFinishResponse } from "@/lib/types";

type RegState =
  | { kind: "idle" }
  | { kind: "starting" }
  | { kind: "prompting" }
  | { kind: "submitting" }
  | { kind: "success"; result: RegisterFinishResponse }
  | { kind: "error"; title: string; message: string; code: string | undefined };

function regErrorTitle(code: string | undefined, status: number): string {
  if (code === "registration_locked") return "registration locked";
  if (status === 401 || code === "webauthn_rejected") return "registration rejected";
  if (code === "ceremony_consumed_or_missing") return "ceremony consumed";
  if (code === "network_error") return "wallet node offline";
  return "registration failed";
}

function RegisterPasskeyPanel() {
  const credentials = useCredentialsQuery();
  const wallet = useWalletStatusQuery();
  const invalidate = useCredentialsInvalidation();
  const [state, setState] = useState<RegState>({ kind: "idle" });
  const [label, setLabel] = useState("primary");
  const [userName, setUserName] = useState("owner");
  const [displayName, setDisplayName] = useState("Owner");
  const [fieldError, setFieldError] = useState<string | null>(null);

  const enrolledCount = wallet.data?.credentials ?? credentials.data?.length ?? 0;
  const locked = enrolledCount > 0;

  function fail(err: unknown) {
    if (err instanceof ApiError) {
      setState({
        kind: "error",
        title: regErrorTitle(err.code, err.status),
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
        title: cancelled ? "registration cancelled" : "registration failed",
        message,
        code: undefined,
      });
    }
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setFieldError(null);
    if (!label.trim() || !userName.trim() || !displayName.trim()) {
      setFieldError("label, user name and display name are all required");
      return;
    }
    setState({ kind: "starting" });
    try {
      const started = await api.registrationStart({
        label: label.trim(),
        user_name: userName.trim(),
        display_name: displayName.trim(),
      });
      setState({ kind: "prompting" });
      const credential = await browserRegister(started.public_key);
      setState({ kind: "submitting" });
      const result = await api.registrationFinish({
        ceremony_id: started.ceremony_id,
        credential,
      });
      setState({ kind: "success", result });
      invalidate();
    } catch (err) {
      fail(err);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>enroll passkey</CardTitle>
        {locked && <Badge variant="warn">locked</Badge>}
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {locked && (
          <Alert variant="warn">
            <AlertTitle>registration locked</AlertTitle>
            <div className="text-muted">
              The first successful registration claims this in-memory wallet;
              later enrollments are refused by the node, including races.
              Start the node fresh to re-bootstrap.
            </div>
          </Alert>
        )}
        {!isWebAuthnAvailable() && (
          <Alert variant="warn">
            <AlertTitle>webauthn unavailable</AlertTitle>
            <div className="text-muted">
              This context cannot create credentials. Serve over localhost or
              HTTPS with a secure context and an origin matching the node's RP.
            </div>
          </Alert>
        )}
        {!locked && isWebAuthnAvailable() && (
          <form onSubmit={onSubmit} className="flex flex-col gap-3">
            <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
              <div>
                <Label htmlFor="reg-label">label</Label>
                <Input
                  id="reg-label"
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                />
              </div>
              <div>
                <Label htmlFor="reg-user">user name</Label>
                <Input
                  id="reg-user"
                  value={userName}
                  onChange={(e) => setUserName(e.target.value)}
                  autoComplete="username webauthn"
                />
              </div>
              <div>
                <Label htmlFor="reg-display">display name</Label>
                <Input
                  id="reg-display"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                />
              </div>
            </div>
            {fieldError && (
              <span className="micro-label text-paper">{fieldError}</span>
            )}
            <div className="flex items-center justify-between gap-4 border-t border-line pt-3">
              <span className="micro-label text-dim">
                uses navigator.credentials.create with the node's challenge
              </span>
              <Button
                type="submit"
                disabled={
                  state.kind === "starting" ||
                  state.kind === "prompting" ||
                  state.kind === "submitting"
                }
              >
                {state.kind === "starting"
                  ? "starting ceremony…"
                  : state.kind === "prompting"
                    ? "waiting for authenticator…"
                    : state.kind === "submitting"
                      ? "verifying with node…"
                      : "register passkey"}
              </Button>
            </div>
          </form>
        )}
        {state.kind === "success" && (
          <Alert variant="default">
            <AlertTitle>enrolled</AlertTitle>
            <div className="text-muted">
              Credential {shortHex(state.result.credential_id, 8, 6)} registered
              as "{state.result.label}" at {formatUnix(state.result.registered_at)}.
            </div>
          </Alert>
        )}
        {state.kind === "error" && (
          <Alert variant="danger">
            <AlertTitle>{state.title}</AlertTitle>
            <div className="text-muted">{state.message}</div>
          </Alert>
        )}
      </CardContent>
    </Card>
  );
}

export function PasskeysPage() {
  const q = useCredentialsQuery();
  return (
    <div className="flex flex-col gap-3">
      <div className="mb-1">
        <h1 className="text-sm font-semibold uppercase tracking-[0.2em] text-paper">
          Passkeys
        </h1>
      </div>

      <RegisterPasskeyPanel />

      <Card>
        <CardHeader>
          <CardTitle>enrolled credentials ({q.data?.length ?? 0})</CardTitle>
        </CardHeader>
        <CardContent>
          {q.isPending && (
            <div className="flex flex-col gap-2">
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-4 w-full" />
            </div>
          )}
          {q.isError && (
            <Alert variant="warn">
              <AlertTitle>credential list unavailable</AlertTitle>
              <div className="text-muted">{q.error.message}</div>
            </Alert>
          )}
          {q.isSuccess && q.data.length === 0 && (
            <span className="micro-label">
              no credentials enrolled — the wallet claims its first passkey
            </span>
          )}
          {q.isSuccess &&
            q.data.map((c) => (
              <DataRow key={c.credential_id} label={c.label}>
                <span className="inline-flex items-center gap-2">
                  <HexValue value={c.credential_id} head={10} tail={8} />
                  <span className="micro-label text-dim">
                    {formatUnix(c.registered_at)}
                  </span>
                </span>
              </DataRow>
            ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>approval-only role</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-[12px] leading-5 text-muted">
            A passkey here proves user-intent approval; it is never used as a
            Bitcoin signature. FROST threshold signing happens separately
            through the wallet node's local participant. Credentials are stored
            in the node's process memory only.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}

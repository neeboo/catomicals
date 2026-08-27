import { Badge } from "@/components/ui/badge";
import type { IntentStatus, SigningPhase } from "@/lib/types";

const STATUS_META: Record<
  IntentStatus,
  { label: string; variant: "outline" | "solid" | "dim" | "warn" }
> = {
  pending: { label: "pending", variant: "outline" },
  approved: { label: "approved", variant: "solid" },
  cancelled: { label: "cancelled", variant: "dim" },
  expired: { label: "expired", variant: "warn" },
  signed: { label: "signed", variant: "solid" },
};

export function IntentStatusBadge({ status }: { status: IntentStatus }) {
  const meta = STATUS_META[status];
  return <Badge variant={meta.variant}>{meta.label}</Badge>;
}

const PHASE_META: Record<SigningPhase, string> = {
  pending_approval: "pending approval",
  approved: "approved",
  round_one_ready: "round one ready",
  share_produced: "share produced",
  signed: "signed",
  cancelled: "cancelled",
  expired: "expired",
};

export function PhaseBadge({ phase }: { phase: SigningPhase }) {
  return <Badge variant="outline">{PHASE_META[phase]}</Badge>;
}

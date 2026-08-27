import { formatClock } from "@/lib/format";

export function SyncIndicator({
  fetching,
  updatedAt,
  online,
}: {
  fetching: boolean;
  updatedAt: number;
  online: boolean;
}) {
  return (
    <span className="inline-flex items-center gap-2 text-[10px] uppercase tracking-[0.16em] text-dim">
      <span
        aria-hidden
        className={
          fetching
            ? "inline-block size-1.5 animate-blink bg-paper"
            : online
              ? "inline-block size-1.5 bg-paper"
              : "inline-block size-1.5 border border-dim"
        }
      />
      {fetching ? (
        <span className="text-muted">syncing…</span>
      ) : online ? (
        <span>
          last sync {formatClock(Math.floor(updatedAt / 1000))}
        </span>
      ) : (
        <span>offline</span>
      )}
    </span>
  );
}

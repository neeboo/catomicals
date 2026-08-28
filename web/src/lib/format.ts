// Presentation helpers. Pure formatting only — never fabricates wallet data.

export function formatUnix(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return "—";
  const d = new Date(seconds * 1000);
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

export function formatDuration(milliseconds: number): string {
  if (!Number.isFinite(milliseconds) || milliseconds < 0) return "—";
  const seconds = milliseconds / 1000;
  if (seconds < 60) return `${Math.round(seconds * 10) / 10}s`;
  const whole = Math.round(seconds);
  return `${Math.floor(whole / 60)}m${whole % 60}s`;
}

export function formatClock(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return "—";
  return new Date(seconds * 1000).toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

export function formatRelative(seconds: number, now: number = Date.now() / 1000): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return "—";
  const delta = seconds - now;
  const abs = Math.abs(delta);
  const span =
    abs < 60
      ? `${Math.floor(abs)}s`
      : abs < 3600
        ? `${Math.floor(abs / 60)}m ${Math.floor(abs % 60)}s`
        : abs < 86400
          ? `${Math.floor(abs / 3600)}h ${Math.floor((abs % 3600) / 60)}m`
          : `${Math.floor(abs / 86400)}d`;
  return delta >= 0 ? `in ${span}` : `${span} ago`;
}

export function shortHex(hex: string, head = 10, tail = 8): string {
  if (!hex) return "—";
  if (hex.length <= head + tail + 1) return hex;
  return `${hex.slice(0, head)}…${hex.slice(-tail)}`;
}

export function groupPubkeyShort(xonly: string | null): string {
  if (!xonly) return "—";
  return shortHex(xonly, 12, 12);
}

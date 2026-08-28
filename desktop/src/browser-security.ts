import { BlockList, isIP } from "node:net";

const blockedBrowserAddresses = new BlockList();
const browserProxyAliases = new BlockList();
browserProxyAliases.addSubnet("198.18.0.0", 15, "ipv4");
browserProxyAliases.addSubnet("fdfe:dcba:9876::", 48, "ipv6");
for (const [network, prefix] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
] as const) blockedBrowserAddresses.addSubnet(network, prefix, "ipv4");
for (const [network, prefix] of [
  ["::", 128],
  ["::1", 128],
  ["100::", 64],
  ["2001:db8::", 32],
  ["fc00::", 7],
  ["fe80::", 10],
  ["ff00::", 8],
] as const) blockedBrowserAddresses.addSubnet(network, prefix, "ipv6");

export function isPrivateBrowserHost(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  const family = isIP(normalized);
  return normalized === "localhost"
    || normalized.endsWith(".localhost")
    || normalized.endsWith(".local")
    || (family !== 0 && blockedBrowserAddresses.check(normalized, family === 4 ? "ipv4" : "ipv6"));
}

function isBrowserProxyAlias(address: string): boolean {
  const normalized = address.toLowerCase().replace(/^\[|\]$/g, "");
  const family = isIP(normalized);
  return family !== 0 && browserProxyAliases.check(normalized, family === 4 ? "ipv4" : "ipv6");
}

export function parseBrowserUrl(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048) throw new Error("browser URL required");
  const url = new URL(value);
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error("browser URL must use http or https");
  if (isPrivateBrowserHost(url.hostname) || url.port === "18787") throw new Error("private network browser URL blocked");
  return url.toString().replace(/\/$/, url.pathname === "/" && !url.search && !url.hash ? "" : "/");
}

export function shouldBlockBrowserRequest(value: string): boolean {
  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") return true;
    return isPrivateBrowserHost(url.hostname) || url.port === "18787";
  } catch {
    return true;
  }
}

interface ResolvedBrowserAddress {
  address: string;
}

export type BrowserHostLookup = (hostname: string) => Promise<readonly ResolvedBrowserAddress[]>;

export async function assertPublicBrowserUrl(
  value: unknown,
  lookup: BrowserHostLookup,
): Promise<string> {
  const normalized = parseBrowserUrl(value);
  const hostname = new URL(normalized).hostname.replace(/^\[|\]$/g, "");
  const addresses = await lookup(hostname);
  if (addresses.length === 0 || addresses.some(({ address }) => (
    isPrivateBrowserHost(address) && !isBrowserProxyAlias(address)
  ))) {
    throw new Error("private network browser URL blocked");
  }
  return normalized;
}

export function createBrowserPartitionName(sessionId: string, nonce: string): string {
  const safeSession = sessionId.replace(/[^a-zA-Z0-9_-]/g, "-").slice(0, 64) || "default";
  const safeNonce = nonce.replace(/[^a-zA-Z0-9_-]/g, "-").slice(0, 64);
  if (!safeNonce) throw new Error("browser partition nonce required");
  return `catomicals-browser:${safeSession}:${safeNonce}`;
}

interface BrowserPartitionRelease {
  close: () => void;
  clearStorageData: () => Promise<void>;
  clearCache: () => Promise<void>;
}

export async function releaseBrowserPartition(release: BrowserPartitionRelease): Promise<void> {
  try {
    release.close();
  } finally {
    await Promise.allSettled([release.clearStorageData(), release.clearCache()]);
  }
}

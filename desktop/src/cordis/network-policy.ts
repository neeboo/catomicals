import { isIP } from "node:net";
import { lookup } from "node:dns/promises";

export type RpcNetworkAccess = "local" | "private-network" | "public";
export type ResolveHostAddresses = (hostname: string) => Promise<readonly string[]>;

const metadataHostnames = new Set([
  "metadata",
  "metadata.google.internal",
  "instance-data",
]);

function ipv4Octets(address: string): readonly number[] | undefined {
  if (isIP(address) !== 4) return undefined;
  const octets = address.split(".").map(Number);
  return octets.length === 4 ? octets : undefined;
}

function isIpv4Loopback(address: string): boolean {
  return ipv4Octets(address)?.[0] === 127;
}

function isIpv4Private(address: string): boolean {
  const octets = ipv4Octets(address);
  if (!octets) return false;
  return octets[0] === 10
    || (octets[0] === 172 && octets[1]! >= 16 && octets[1]! <= 31)
    || (octets[0] === 192 && octets[1] === 168);
}

function isIpv4NonPublic(address: string): boolean {
  const octets = ipv4Octets(address);
  if (!octets) return false;
  return octets[0] === 0
    || isIpv4Loopback(address)
    || isIpv4Private(address)
    || (octets[0] === 100 && octets[1]! >= 64 && octets[1]! <= 127)
    || (octets[0] === 169 && octets[1] === 254)
    || octets[0]! >= 224;
}

function normalizedIpv6(address: string): string {
  return address.toLowerCase().split("%")[0]!;
}

function mappedIpv4(address: string): string | undefined {
  const normalized = normalizedIpv6(address);
  const mapped = normalized.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/)?.[1];
  return mapped && isIP(mapped) === 4 ? mapped : undefined;
}

function isIpv6Loopback(address: string): boolean {
  return normalizedIpv6(address) === "::1";
}

function isIpv6Private(address: string): boolean {
  const normalized = normalizedIpv6(address);
  const first = Number.parseInt(normalized.split(":")[0] || "0", 16);
  return (first & 0xfe00) === 0xfc00;
}

function isIpv6NonPublic(address: string): boolean {
  const normalized = normalizedIpv6(address);
  const mapped = mappedIpv4(normalized);
  if (mapped) return isIpv4NonPublic(mapped);
  const first = Number.parseInt(normalized.split(":")[0] || "0", 16);
  return normalized === "::"
    || isIpv6Loopback(normalized)
    || isIpv6Private(normalized)
    || (first & 0xffc0) === 0xfe80
    || (first & 0xff00) === 0xff00
    || normalized.startsWith("2001:db8:");
}

function isLoopback(address: string): boolean {
  if (isIP(address) === 4) return isIpv4Loopback(address);
  if (isIP(address) === 6) return isIpv6Loopback(address) || Boolean(mappedIpv4(address) && isIpv4Loopback(mappedIpv4(address)!));
  return false;
}

function isPrivate(address: string): boolean {
  if (isIP(address) === 4) return isIpv4Private(address);
  if (isIP(address) === 6) return isIpv6Private(address) || Boolean(mappedIpv4(address) && isIpv4Private(mappedIpv4(address)!));
  return false;
}

function isPublic(address: string): boolean {
  if (isIP(address) === 4) return !isIpv4NonPublic(address);
  if (isIP(address) === 6) return !isIpv6NonPublic(address);
  return false;
}

const defaultResolveHostAddresses: ResolveHostAddresses = async (hostname) =>
  (await lookup(hostname, { all: true, verbatim: true })).map(({ address }) => address);

export async function assertRpcEndpointAccess(
  endpointValue: string,
  access: RpcNetworkAccess,
  resolveHostAddresses: ResolveHostAddresses = defaultResolveHostAddresses,
): Promise<void> {
  const endpoint = new URL(endpointValue);
  const hostname = endpoint.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (metadataHostnames.has(hostname) || hostname.endsWith(".localhost")) throw new Error("RPC endpoint blocked by network policy");

  if (access === "local") {
    if (hostname !== "localhost" && !isLoopback(hostname)) throw new Error("RPC endpoint must be loopback");
    return;
  }
  if (access === "private-network") {
    if (!isPrivate(hostname)) throw new Error("RPC endpoint must be an explicit private address");
    return;
  }
  if (access !== "public") throw new Error("invalid RPC network access");

  const addresses = isIP(hostname) ? [hostname] : await resolveHostAddresses(hostname);
  if (addresses.length === 0 || addresses.some((address) => !isPublic(address))) {
    throw new Error("RPC endpoint resolved to a non-public address");
  }
}

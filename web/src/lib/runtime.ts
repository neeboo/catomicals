import { requireDesktopBridge, type WalletProxyRequest, type WalletProxyResponse } from "./desktop";

export type { WalletProxyRequest, WalletProxyResponse } from "./desktop";

function bridge(): NonNullable<Window["catomicalsDesktop"]> {
  return requireDesktopBridge();
}

export async function requestWallet(request: WalletProxyRequest): Promise<WalletProxyResponse> {
  return bridge().requestWallet(request);
}

export async function readMcpEnabled(): Promise<boolean> {
  return bridge().getMcpEnabled();
}

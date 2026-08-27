export interface WalletProxyRequest {
  path: string;
  method: "GET" | "POST";
  body?: string;
}

export interface WalletProxyResponse {
  status: number;
  body: string;
  contentType: string;
}

function bridge(): NonNullable<Window["catomicalsDesktop"]> {
  const bridge = window.catomicalsDesktop;
  if (!bridge) throw new Error("desktop runtime unavailable");
  return bridge;
}

export async function requestWallet(request: WalletProxyRequest): Promise<WalletProxyResponse> {
  return bridge().requestWallet(request);
}

export async function readMcpEnabled(): Promise<boolean> {
  return bridge().getMcpEnabled();
}

export interface RendererRuntimeConfig {
  walletEndpoint: string;
  mcpEnabled: boolean;
}

export async function readWalletRuntimeEndpoint(): Promise<string> {
  const bridge = window.catomicalsDesktop;
  if (!bridge) throw new Error("desktop runtime unavailable");
  const runtime = await bridge.getRuntimeConfig();
  if (typeof runtime.walletEndpoint !== "string" || runtime.walletEndpoint.length > 512) {
    throw new Error("desktop wallet endpoint unavailable");
  }
  return runtime.walletEndpoint;
}

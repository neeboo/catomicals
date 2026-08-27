/// <reference types="vite/client" />

interface Window {
  catomicalsDesktop?: {
    requestWallet(request: import("./lib/runtime").WalletProxyRequest): Promise<import("./lib/runtime").WalletProxyResponse>;
    getMcpEnabled(): Promise<boolean>;
  };
}

/// <reference types="vite/client" />

interface Window {
  catomicalsDesktop?: {
    getRuntimeConfig(): Promise<import("./lib/runtime").RendererRuntimeConfig>;
  };
}

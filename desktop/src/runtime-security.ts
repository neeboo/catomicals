const rendererOrigin = "http://localhost:5173";
const walletNodeOrigins = Object.freeze([
  "http://127.0.0.1:18787",
  "http://localhost:18787",
  "http://[::1]:18787",
] as const);
const walletRendererSources = Object.freeze([
  ...walletNodeOrigins,
  "http://127.0.0.1:*",
  "http://localhost:*",
  "http://[::1]:*",
] as const);

export const DESKTOP_ENDPOINTS = Object.freeze({
  rendererOrigin,
  devRendererOrigin: rendererOrigin,
  walletNodeUrl: walletNodeOrigins[0],
  walletNodeOrigins,
  walletCorsOrigin: rendererOrigin,
  webauthnOrigin: rendererOrigin,
});

export function rendererContentSecurityPolicy(): string {
  return `default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; connect-src 'self' ${walletRendererSources.join(" ")}; img-src 'self' data:; style-src 'self'; script-src 'self'`;
}

export function rendererSecurityHeaders(): Readonly<Record<string, string>> {
  return Object.freeze({
    "Content-Security-Policy": rendererContentSecurityPolicy(),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), geolocation=(), microphone=()",
  });
}

interface RendererUrlOptions {
  packaged: boolean;
  argv: readonly string[];
}

export function resolveRendererUrl({ packaged, argv }: RendererUrlOptions): string {
  const argument = argv.find((item) => item.startsWith("--renderer-url="));
  if (!argument || packaged) return DESKTOP_ENDPOINTS.rendererOrigin;
  const candidate = argument.slice("--renderer-url=".length);
  if (candidate !== DESKTOP_ENDPOINTS.devRendererOrigin) throw new Error("untrusted renderer URL");
  return candidate;
}

export function trustedRendererNavigation(value: string): boolean {
  try {
    return new URL(value).origin === DESKTOP_ENDPOINTS.rendererOrigin;
  } catch {
    return false;
  }
}

interface IpcFrameIdentity {
  senderId: number;
  expectedSenderId: number;
  frameUrl: string;
  isMainFrame: boolean;
  parentFramePresent: boolean;
}

export function assertTrustedIpcFrame(identity: IpcFrameIdentity): void {
  if (identity.senderId !== identity.expectedSenderId
    || !identity.isMainFrame
    || identity.parentFramePresent
    || !trustedRendererNavigation(identity.frameUrl)) {
    throw new Error("untrusted IPC sender");
  }
}

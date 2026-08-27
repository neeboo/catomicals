import { describe, expect, it } from "vitest";
import {
  DESKTOP_ENDPOINTS,
  assertTrustedIpcFrame,
  rendererContentSecurityPolicy,
  rendererSecurityHeaders,
  resolveRendererUrl,
  trustedRendererNavigation,
} from "./runtime-security";

describe("desktop renderer trust boundary", () => {
  it("uses one renderer origin for desktop navigation, CORS and WebAuthn", () => {
    expect(DESKTOP_ENDPOINTS.rendererOrigin).toBe(DESKTOP_ENDPOINTS.walletCorsOrigin);
    expect(DESKTOP_ENDPOINTS.rendererOrigin).toBe(DESKTOP_ENDPOINTS.webauthnOrigin);
  });

  it("builds renderer network policy from the shared wallet endpoint", () => {
    const policy = rendererContentSecurityPolicy();
    expect(policy).toContain(`connect-src 'self' ${DESKTOP_ENDPOINTS.walletNodeUrl}`);
    expect(policy).toContain("http://127.0.0.1:*");
    expect(policy).toContain("http://localhost:*");
    expect(policy).not.toContain("unsafe-inline");
    expect(policy).not.toContain("unsafe-eval");
  });

  it("sets the local app shell security headers", () => {
    expect(rendererSecurityHeaders()).toMatchObject({
      "Content-Security-Policy": rendererContentSecurityPolicy(),
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "no-referrer",
      "Permissions-Policy": "camera=(), geolocation=(), microphone=()",
    });
  });

  it("ignores renderer URL overrides in packaged builds", () => {
    expect(resolveRendererUrl({
      packaged: true,
      argv: ["catomicals", "--renderer-url=https://attacker.example"],
    })).toBe(DESKTOP_ENDPOINTS.rendererOrigin);
  });

  it("allows only the fixed local dev renderer override", () => {
    expect(resolveRendererUrl({
      packaged: false,
      argv: ["catomicals", `--renderer-url=${DESKTOP_ENDPOINTS.devRendererOrigin}`],
    })).toBe(DESKTOP_ENDPOINTS.devRendererOrigin);
    expect(() => resolveRendererUrl({
      packaged: false,
      argv: ["catomicals", "--renderer-url=http://127.0.0.1:3000"],
    })).toThrow("renderer URL");
  });

  it("accepts IPC only from the exact top-level renderer frame lineage", () => {
    expect(() => assertTrustedIpcFrame({
      senderId: 7,
      expectedSenderId: 7,
      frameUrl: `${DESKTOP_ENDPOINTS.rendererOrigin}/chat`,
      isMainFrame: true,
      parentFramePresent: false,
    })).not.toThrow();

    for (const candidate of [
      { senderId: 8, expectedSenderId: 7, frameUrl: DESKTOP_ENDPOINTS.rendererOrigin, isMainFrame: true, parentFramePresent: false },
      { senderId: 7, expectedSenderId: 7, frameUrl: "https://attacker.example", isMainFrame: true, parentFramePresent: false },
      { senderId: 7, expectedSenderId: 7, frameUrl: DESKTOP_ENDPOINTS.rendererOrigin, isMainFrame: false, parentFramePresent: true },
    ]) {
      expect(() => assertTrustedIpcFrame(candidate)).toThrow("untrusted IPC sender");
    }
  });

  it("allows in-app navigation only within the exact trusted origin", () => {
    expect(trustedRendererNavigation(`${DESKTOP_ENDPOINTS.rendererOrigin}/settings`)).toBe(true);
    expect(trustedRendererNavigation("https://attacker.example")).toBe(false);
    expect(trustedRendererNavigation(`${DESKTOP_ENDPOINTS.rendererOrigin}.attacker.example`)).toBe(false);
  });
});

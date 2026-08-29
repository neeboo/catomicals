import { optionalDesktopBridge, type DesktopBridge, type IdentitySession, type IdentityState } from "./desktop";

export const AUTH_PROVIDER_IDS = ["google", "apple", "email", "local-device"] as const;
export type AuthProviderId = (typeof AUTH_PROVIDER_IDS)[number];
export type AuthProviderStatus = "ready" | "unconfigured";
export type AuthCapability = "identity" | "transaction-signing";

export interface AuthProviderDefinition {
  id: AuthProviderId;
  label: string;
  status: AuthProviderStatus;
  statusLabel: string;
  capabilities: readonly AuthCapability[];
  flow: "system-oauth-pkce" | "verified-email" | "local-device";
}

export const AUTH_PROVIDERS: readonly AuthProviderDefinition[] = [
  { id: "google", label: "Google", status: "unconfigured", statusLabel: "OAuth 客户端未配置", capabilities: ["identity"], flow: "system-oauth-pkce" },
  { id: "apple", label: "Apple", status: "unconfigured", statusLabel: "OAuth 客户端未配置", capabilities: ["identity"], flow: "system-oauth-pkce" },
  { id: "email", label: "邮箱", status: "unconfigured", statusLabel: "邮件验证服务未配置", capabilities: ["identity"], flow: "verified-email" },
  { id: "local-device", label: "本机身份", status: "ready", statusLabel: "由系统安全存储保护", capabilities: ["identity"], flow: "local-device" },
] as const;

export interface IdentityClient {
  state(): Promise<IdentityState>;
  login(): Promise<IdentitySession>;
  logout(): Promise<void>;
  recover(): Promise<void>;
}

export function createIdentityClient(bridge: DesktopBridge | undefined = optionalDesktopBridge()): IdentityClient {
  if (!bridge) {
    return {
      state: async () => ({ available: false, session: null }),
      login: async () => { throw new Error("desktop identity unavailable"); },
      logout: async () => undefined,
      recover: async () => undefined,
    };
  }
  return {
    state: () => bridge.getIdentityState(),
    login: () => bridge.loginIdentity(),
    logout: () => bridge.logoutIdentity(),
    recover: () => bridge.recoverIdentity(),
  };
}

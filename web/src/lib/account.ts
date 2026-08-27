export const AUTH_PROVIDER_IDS = ["google", "apple", "email", "passkey"] as const;
export type AuthProviderId = (typeof AUTH_PROVIDER_IDS)[number];
export type AuthProviderStatus = "ready" | "unconfigured";
export type AuthCapability = "identity" | "transaction-signing";

export interface AuthProviderDefinition {
  id: AuthProviderId;
  label: string;
  status: AuthProviderStatus;
  statusLabel: string;
  capabilities: readonly AuthCapability[];
  flow: "system-oauth-pkce" | "verified-email" | "local-passkey";
}

export const AUTH_PROVIDERS: readonly AuthProviderDefinition[] = [
  { id: "google", label: "Google", status: "unconfigured", statusLabel: "OAuth 客户端未配置", capabilities: ["identity"], flow: "system-oauth-pkce" },
  { id: "apple", label: "Apple", status: "unconfigured", statusLabel: "OAuth 客户端未配置", capabilities: ["identity"], flow: "system-oauth-pkce" },
  { id: "email", label: "邮箱", status: "unconfigured", statusLabel: "邮件验证服务未配置", capabilities: ["identity"], flow: "verified-email" },
  { id: "passkey", label: "本机 Passkey", status: "ready", statusLabel: "由钱包节点管理", capabilities: ["identity"], flow: "local-passkey" },
] as const;

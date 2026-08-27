export const CORDIS_PERMISSION_SCOPES = [
  "wallet.status.read",
  "wallet.intent.read",
  "wallet.intent.create",
  "wallet.intent.cancel",
  "wallet.chat.read",
  "wallet.chat.append",
  "wallet.transaction.inspect",
  "wallet.trade.verify",
  "plugin.catalog.read",
  "plugin.manifest.read",
  "plugin.settings_schema.read",
  "plugin.health.read",
  "plugin.settings.validate",
  "plugin.settings_intent.create",
  "indexer.query.read",
  "browser.open.public",
] as const;

export type CordisPermissionScope = (typeof CORDIS_PERMISSION_SCOPES)[number];

export interface CordisAccessContext {
  readonly scopes: readonly CordisPermissionScope[];
}

const permissionScopeSet = new Set<string>(CORDIS_PERMISSION_SCOPES);

export function parsePermissionScopes(value: unknown): CordisPermissionScope[] {
  if (!Array.isArray(value)) throw new Error("invalid permission scopes");
  const result = value.map((scope) => {
    if (typeof scope !== "string" || !permissionScopeSet.has(scope)) {
      throw new Error("invalid permission scope");
    }
    return scope as CordisPermissionScope;
  });
  if (new Set(result).size !== result.length) throw new Error("duplicate permission scope");
  return result;
}

export function cordisAccess(...scopes: CordisPermissionScope[]): CordisAccessContext {
  return Object.freeze({ scopes: Object.freeze(parsePermissionScopes(scopes)) });
}

export function assertCordisPermission(access: CordisAccessContext, required: CordisPermissionScope): void {
  if (!access || !Array.isArray(access.scopes) || !access.scopes.includes(required)) {
    throw new Error(`permission denied: ${required}`);
  }
}

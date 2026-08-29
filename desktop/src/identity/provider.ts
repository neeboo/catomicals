import { randomUUID } from "node:crypto";
import type { IdentityProfile, IdentityProviderId, IdentitySession } from "./store.js";

export interface IdentityProviderAdapter {
  readonly id: IdentityProviderId;
  createSession(profile?: IdentityProfile): Promise<IdentitySession>;
}

export class LocalDeviceIdentityProvider implements IdentityProviderAdapter {
  readonly id = "local-device" as const;
  private readonly now: () => number;
  private readonly randomId: () => string;

  constructor(options: { now?: () => number; randomId?: () => string } = {}) {
    this.now = options.now ?? Date.now;
    this.randomId = options.randomId ?? randomUUID;
  }

  async createSession(profile?: IdentityProfile): Promise<IdentitySession> {
    const timestamp = this.now();
    return {
      version: 1,
      provider: this.id,
      accountId: profile?.accountId ?? this.randomId(),
      sessionId: this.randomId(),
      displayName: profile?.displayName ?? "本机用户",
      createdAt: profile?.createdAt ?? timestamp,
      authenticatedAt: timestamp,
    };
  }
}

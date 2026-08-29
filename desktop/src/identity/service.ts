import type { IdentityProviderAdapter } from "./provider.js";
import { IdentityStoreCorruptionError } from "./store.js";
import type { IdentityProfile, IdentityProviderId, IdentitySession, IdentityStore } from "./store.js";

export interface IdentityState {
  available: boolean;
  session: IdentitySession | null;
  issue?: "identity-data-corrupt";
}

export class IdentityServiceError extends Error {
  constructor(readonly code: "secure-storage-unavailable" | "identity-data-corrupt" | "identity-provider-unavailable") {
    super({
      "secure-storage-unavailable": "secure storage unavailable",
      "identity-data-corrupt": "identity data requires recovery",
      "identity-provider-unavailable": "identity provider unavailable",
    }[code]);
    this.name = "IdentityServiceError";
  }
}

export class IdentityService {
  private readonly providers: ReadonlyMap<IdentityProviderId, IdentityProviderAdapter>;
  private mutationQueue: Promise<void> = Promise.resolve();

  constructor(
    private readonly store: IdentityStore,
    providers: readonly IdentityProviderAdapter[],
  ) {
    this.providers = new Map(providers.map((provider) => [provider.id, provider]));
  }

  async state(): Promise<IdentityState> {
    if (!this.store.available) return { available: false, session: null };
    const snapshot = await this.readSnapshot();
    if (!snapshot) return { available: true, session: null, issue: "identity-data-corrupt" };
    return { available: true, session: snapshot.session };
  }

  async login(request: { provider: IdentityProviderId }): Promise<IdentitySession> {
    return this.serializeMutation(async () => {
      if (!this.store.available) throw new IdentityServiceError("secure-storage-unavailable");
      const provider = this.providers.get(request.provider);
      if (!provider) throw new IdentityServiceError("identity-provider-unavailable");
      const snapshot = await this.readSnapshot();
      if (!snapshot) throw new IdentityServiceError("identity-data-corrupt");
      const { profile } = snapshot;
      const session = await provider.createSession(profile ?? undefined);
      if (!profile) {
        await this.store.writeProfile({
          version: 1,
          provider: session.provider,
          accountId: session.accountId,
          displayName: session.displayName,
          createdAt: session.createdAt,
        });
      }
      await this.store.write(session);
      return session;
    });
  }

  async logout(): Promise<void> {
    await this.serializeMutation(() => this.store.clear());
  }

  async recover(): Promise<void> {
    await this.serializeMutation(async () => {
      if (!this.store.available) throw new IdentityServiceError("secure-storage-unavailable");
      await this.store.reset();
    });
  }

  private async readSnapshot(): Promise<{ session: IdentitySession | null; profile: IdentityProfile | null } | null> {
    try {
      const [session, profile] = await Promise.all([this.store.read(), this.store.readProfile()]);
      if (session && (!profile || session.accountId !== profile.accountId)) return null;
      return { session, profile };
    } catch (error: unknown) {
      if (error instanceof IdentityStoreCorruptionError) return null;
      throw error;
    }
  }

  private serializeMutation<T>(mutation: () => Promise<T>): Promise<T> {
    const result = this.mutationQueue.then(mutation);
    this.mutationQueue = result.then(() => undefined, () => undefined);
    return result;
  }
}

// Browser WebAuthn plumbing for the self-hosted relying party.
// The node serializes challenges and credential ids as base64url strings
// (webauthn-rs); the browser needs ArrayBuffer values for
// navigator.credentials.{create,get}, and the finish endpoints expect the
// credential in the ordinary WebAuthn JSON representation.

import type {
  CreationChallengeResponse,
  RequestChallengeResponse,
} from "./types";

export function b64urlToBuffer(value: string): ArrayBuffer {
  const pad = value.length % 4 === 0 ? "" : "=".repeat(4 - (value.length % 4));
  const b64 = value.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

export function bufferToB64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function isWebAuthnAvailable(): boolean {
  return (
    typeof window !== "undefined" &&
    window.isSecureContext &&
    typeof navigator !== "undefined" &&
    typeof navigator.credentials?.create === "function" &&
    typeof navigator.credentials?.get === "function" &&
    typeof window.PublicKeyCredential === "function"
  );
}

/** true when the browser origin equals the node's configured RP origin. */
export function originMatches(rpOrigin: string | undefined | null): boolean {
  if (!rpOrigin) return false;
  return window.location.origin === rpOrigin.replace(/\/+$/, "");
}

function prepareCreationOptions(
  start: CreationChallengeResponse,
): PublicKeyCredentialCreationOptions {
  const pk = start.publicKey;
  const options: PublicKeyCredentialCreationOptions = {
    rp: pk.rp as PublicKeyCredentialRpEntity,
    user: {
      ...pk.user,
      id: b64urlToBuffer(pk.user.id),
    } as PublicKeyCredentialUserEntity,
    challenge: b64urlToBuffer(pk.challenge),
    pubKeyCredParams: pk.pubKeyCredParams as PublicKeyCredentialParameters[],
  };
  if (typeof pk.timeout === "number") options.timeout = pk.timeout;
  if (pk.attestation) options.attestation = pk.attestation as AttestationConveyancePreference;
  if (pk.authenticatorSelection) {
    options.authenticatorSelection =
      pk.authenticatorSelection as AuthenticatorSelectionCriteria;
  }
  if (pk.excludeCredentials && pk.excludeCredentials.length > 0) {
    options.excludeCredentials = pk.excludeCredentials.map((c) => ({
      type: c.type as PublicKeyCredentialType,
      id: b64urlToBuffer(c.id),
    }));
  }
  if (pk.extensions) options.extensions = pk.extensions as AuthenticationExtensionsClientInputs;
  return options;
}

function prepareRequestOptions(
  start: RequestChallengeResponse,
): PublicKeyCredentialRequestOptions {
  const pk = start.publicKey;
  const options: PublicKeyCredentialRequestOptions = {
    challenge: b64urlToBuffer(pk.challenge),
  };
  if (typeof pk.timeout === "number") options.timeout = pk.timeout;
  if (pk.rpId) options.rpId = pk.rpId;
  if (pk.allowCredentials && pk.allowCredentials.length > 0) {
    options.allowCredentials = pk.allowCredentials.map((c) => ({
      type: c.type as PublicKeyCredentialType,
      id: b64urlToBuffer(c.id),
    }));
  }
  if (pk.userVerification) {
    options.userVerification = pk.userVerification as UserVerificationRequirement;
  }
  return options;
}

interface RegisterCredentialJSON {
  id: string;
  rawId: string;
  type: string;
  response: {
    attestationObject: string;
    clientDataJSON: string;
    transports?: string[];
  };
  clientExtensionResults: Record<string, unknown>;
}

interface AssertionCredentialJSON {
  id: string;
  rawId: string;
  type: string;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle: string | null;
  };
  clientExtensionResults: Record<string, unknown>;
}

function credentialCreateJSON(
  credential: PublicKeyCredential,
): RegisterCredentialJSON {
  const response = credential.response as AuthenticatorAttestationResponse;
  const transports =
    typeof response.getTransports === "function"
      ? response.getTransports().map(String)
      : undefined;
  return {
    id: credential.id,
    rawId: bufferToB64url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: bufferToB64url(response.attestationObject),
      clientDataJSON: bufferToB64url(response.clientDataJSON),
      transports,
    },
    clientExtensionResults: credential.getClientExtensionResults() as unknown as Record<string, unknown>,
  };
}

function credentialGetJSON(
  credential: PublicKeyCredential,
): AssertionCredentialJSON {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: bufferToB64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToB64url(response.clientDataJSON),
      authenticatorData: bufferToB64url(response.authenticatorData),
      signature: bufferToB64url(response.signature),
      userHandle: response.userHandle
        ? bufferToB64url(response.userHandle)
        : null,
    },
    clientExtensionResults: credential.getClientExtensionResults() as unknown as Record<string, unknown>,
  };
}

/** Run a browser Passkey registration ceremony against a node start response. */
export async function browserRegister(
  start: CreationChallengeResponse,
): Promise<RegisterCredentialJSON> {
  const credential = (await navigator.credentials.create({
    publicKey: prepareCreationOptions(start),
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("WebAuthn registration was cancelled");
  return credentialCreateJSON(credential);
}

/** Run a browser Passkey assertion (approval) against a node start response. */
export async function browserAssert(
  start: RequestChallengeResponse,
): Promise<AssertionCredentialJSON> {
  const credential = (await navigator.credentials.get({
    publicKey: prepareRequestOptions(start),
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("WebAuthn approval was cancelled");
  return credentialGetJSON(credential);
}

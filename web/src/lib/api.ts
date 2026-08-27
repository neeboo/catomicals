// Typed client for the self-hosted wallet node HTTP API
// (docs/wallet-node.md). All UI data is fetched live through these calls.

import type {
  ApiErrorBody,
  ApprovalFinishRequest,
  ApprovalFinishResponse,
  ApprovalStartResponse,
  ChatExchange,
  ChatMessage,
  ChatState,
  CreateChatMessageRequest,
  CreateIntentRequest,
  CreateTransactionIntentRequest,
  CredentialSummary,
  RegisterFinishRequest,
  RegisterFinishResponse,
  RegisterStartResponse,
  SigningIntent,
  ThresholdSigningStatus,
  TransactionReview,
  TransactionReviewRequest,
  WalletNodeStatus,
  WalletSignerStatus,
  WalletSnapshot,
} from "./types";
import { readWalletRuntimeEndpoint } from "./runtime";

export function apiBase(): Promise<string> {
  return readWalletRuntimeEndpoint();
}

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }

  get isNetwork(): boolean {
    return this.code === "network_error";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  const base = await apiBase();
  try {
    response = await fetch(`${base}${path}`, {
      headers: { "Content-Type": "application/json" },
      ...init,
    });
  } catch (cause) {
    throw new ApiError(
      0,
      "network_error",
      `Cannot reach the wallet node at ${base}: ${(cause as Error).message}`,
    );
  }
  const text = await response.text();
  let body: unknown = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = null;
    }
  }
  if (!response.ok) {
    const err = body as ApiErrorBody | null;
    throw new ApiError(
      response.status,
      err?.error?.code ?? "http_error",
      err?.error?.message ?? `HTTP ${response.status}`,
    );
  }
  return body as T;
}

export const api = {
  nodeStatus: () => request<WalletNodeStatus>("/api/v1/node/status"),
  walletStatus: () => request<WalletSnapshot>("/api/v1/wallet/status"),
  signerStatus: () => request<WalletSignerStatus>("/api/v1/signer/status"),
  credentials: () =>
    request<CredentialSummary[]>("/api/v1/webauthn/credentials"),
  listIntents: () => request<SigningIntent[]>("/api/v1/intents"),
  readIntent: (id: string) => request<SigningIntent>(`/api/v1/intents/${id}`),
  createIntent: (req: CreateIntentRequest) =>
    request<SigningIntent>("/api/v1/intents", {
      method: "POST",
      body: JSON.stringify(req),
    }),
  inspectTransaction: (req: TransactionReviewRequest) =>
    request<TransactionReview>("/api/v1/transactions/inspect", {
      method: "POST",
      body: JSON.stringify(req),
    }),
  createTransactionIntent: (req: CreateTransactionIntentRequest) =>
    request<SigningIntent>("/api/v1/transactions/intents", {
      method: "POST",
      body: JSON.stringify(req),
    }),
  readTransactionReview: (id: string) =>
    request<TransactionReview>(`/api/v1/transactions/intents/${id}`),
  cancelIntent: (id: string) =>
    request<SigningIntent>(`/api/v1/intents/${id}/cancel`, {
      method: "POST",
    }),
  registrationStart: (req: {
    label: string;
    user_name: string;
    display_name: string;
  }) => request<RegisterStartResponse>("/api/v1/webauthn/register/start", {
    method: "POST",
    body: JSON.stringify(req),
  }),
  registrationFinish: (req: RegisterFinishRequest) =>
    request<RegisterFinishResponse>("/api/v1/webauthn/register/finish", {
      method: "POST",
      body: JSON.stringify(req),
    }),
  approvalStart: (id: string) =>
    request<ApprovalStartResponse>(`/api/v1/intents/${id}/approve/start`, {
      method: "POST",
    }),
  approvalFinish: (id: string, req: ApprovalFinishRequest) =>
    request<ApprovalFinishResponse>(`/api/v1/intents/${id}/approve/finish`, {
      method: "POST",
      body: JSON.stringify(req),
    }),
  signingStatus: (id: string) =>
    request<ThresholdSigningStatus>(`/api/v1/signing/${id}/status`),
  chatState: () => request<ChatState>("/api/v1/chat/state"),
  readChatMessage: (id: string) =>
    request<ChatMessage>(`/api/v1/chat/messages/${id}`),
  createChatMessage: (req: CreateChatMessageRequest) =>
    request<ChatExchange>("/api/v1/chat/messages", {
      method: "POST",
      body: JSON.stringify(req),
    }),
};

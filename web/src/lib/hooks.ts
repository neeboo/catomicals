// TanStack Query hooks over the wallet-node API.

import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { api } from "./api";
import type {
  ChatState,
  CreateChatMessageRequest,
  CreateIntentRequest,
  CreateTransactionIntentRequest,
  CredentialSummary,
  SigningIntent,
  ThresholdSigningStatus,
  TransactionReview,
  TransactionReviewRequest,
  WalletNodeStatus,
  WalletSignerStatus,
  WalletSnapshot,
} from "./types";

export const queryKeys = {
  nodeStatus: ["wallet-node-status"] as const,
  walletStatus: ["wallet-status"] as const,
  signerStatus: ["signer-status"] as const,
  credentials: ["webauthn-credentials"] as const,
  intents: ["intents"] as const,
  intent: (id: string) => ["intents", id] as const,
  signingStatus: (id: string) => ["signing-status", id] as const,
  chatState: ["chat-state"] as const,
  transactionReview: (id: string) => ["transaction-review", id] as const,
};

function useLiveQuery<T>(options: {
  queryKey: readonly unknown[];
  queryFn: () => Promise<T>;
  refetchInterval?: number;
  enabled?: boolean;
}) {
  return useQuery({
    queryKey: options.queryKey,
    queryFn: options.queryFn,
    refetchInterval: options.refetchInterval,
    refetchIntervalInBackground: false,
    refetchOnWindowFocus: true,
    staleTime: 1000,
    retry: 2,
    retryDelay: 1000,
    enabled: options.enabled,
  });
}

export function useNodeStatusQuery() {
  return useLiveQuery<WalletNodeStatus>({
    queryKey: queryKeys.nodeStatus,
    queryFn: api.nodeStatus,
    refetchInterval: 15_000,
  });
}

export function useWalletStatusQuery() {
  return useLiveQuery<WalletSnapshot>({
    queryKey: queryKeys.walletStatus,
    queryFn: api.walletStatus,
    refetchInterval: 5_000,
  });
}

export function useSignerStatusQuery() {
  return useLiveQuery<WalletSignerStatus>({
    queryKey: queryKeys.signerStatus,
    queryFn: api.signerStatus,
    refetchInterval: 10_000,
  });
}

export function useCredentialsQuery() {
  return useLiveQuery<CredentialSummary[]>({
    queryKey: queryKeys.credentials,
    queryFn: api.credentials,
    refetchInterval: 10_000,
  });
}

export function useIntentsQuery() {
  return useLiveQuery<SigningIntent[]>({
    queryKey: queryKeys.intents,
    queryFn: api.listIntents,
    refetchInterval: 5_000,
  });
}

export function useIntentQuery(id: string | undefined) {
  return useLiveQuery<SigningIntent>({
    queryKey: queryKeys.intent(id ?? ""),
    queryFn: () => api.readIntent(id ?? ""),
    refetchInterval: 5_000,
    ...(id ? {} : { enabled: false }),
  });
}

export function useSigningStatusQuery(id: string | undefined) {
  return useLiveQuery<ThresholdSigningStatus>({
    queryKey: queryKeys.signingStatus(id ?? ""),
    queryFn: () => api.signingStatus(id ?? ""),
    refetchInterval: 4_000,
    ...(id ? {} : { enabled: false }),
  });
}

export function useChatStateQuery() {
  return useLiveQuery<ChatState>({
    queryKey: queryKeys.chatState,
    queryFn: api.chatState,
    refetchInterval: 4_000,
  });
}

export function useTransactionReviewQuery(id: string | undefined) {
  return useLiveQuery<TransactionReview>({
    queryKey: queryKeys.transactionReview(id ?? ""),
    queryFn: () => api.readTransactionReview(id ?? ""),
    ...(id ? {} : { enabled: false }),
  });
}

function useInvalidateWallet() {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: queryKeys.intents });
    void qc.invalidateQueries({ queryKey: queryKeys.walletStatus });
    void qc.invalidateQueries({ queryKey: queryKeys.signerStatus });
    void qc.invalidateQueries({ queryKey: ["signing-status"] });
  };
}

export function useCreateIntentMutation() {
  const invalidate = useInvalidateWallet();
  return useMutation({
    mutationFn: (req: CreateIntentRequest) => api.createIntent(req),
    onSuccess: invalidate,
  });
}

export function useInspectTransactionMutation() {
  return useMutation({
    mutationFn: (req: TransactionReviewRequest) => api.inspectTransaction(req),
  });
}

export function useCreateTransactionIntentMutation() {
  const invalidate = useInvalidateWallet();
  return useMutation({
    mutationFn: (req: CreateTransactionIntentRequest) =>
      api.createTransactionIntent(req),
    onSuccess: invalidate,
  });
}

export function useCreateChatMessageMutation() {
  const invalidateWallet = useInvalidateWallet();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: CreateChatMessageRequest) => api.createChatMessage(req),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.chatState });
      invalidateWallet();
    },
  });
}

export function useCancelIntentMutation() {
  const invalidate = useInvalidateWallet();
  return useMutation({
    mutationFn: (id: string) => api.cancelIntent(id),
    onSuccess: invalidate,
  });
}

export function useCredentialsInvalidation() {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: queryKeys.credentials });
    void qc.invalidateQueries({ queryKey: queryKeys.walletStatus });
  };
}

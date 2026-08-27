// Exact JSON shapes served by the self-hosted wallet node
// (crates/wallet-core, apps/catomicals-cli/src/wallet_serve.rs).
// Every value shown in the UI comes from these responses — nothing is
// fabricated client-side.

import type { AgentUiBlockReference, ChatReviewReference } from "./ui-block";
export type { ChatReviewReference } from "./ui-block";

export type IntentStatus =
  | "pending"
  | "approved"
  | "cancelled"
  | "expired"
  | "signed";

export type SigningPhase =
  | "pending_approval"
  | "approved"
  | "round_one_ready"
  | "share_produced"
  | "signed"
  | "cancelled"
  | "expired";

export interface NodeSnapshot {
  chain: string;
  blocks: number;
  headers: number;
  subversion: string;
  op_cat_active: boolean;
}

export interface ThresholdSnapshot {
  configured: boolean;
  min_signers: number;
  max_signers: number;
  group_pubkey_xonly: string | null;
}

export interface SignerSnapshot {
  id: number;
  label: string;
  online: boolean;
}

export interface IntentSnapshot {
  id: string;
  signer_id: number;
  tx_digest_hex: string;
  session_id_hex: string;
  status: IntentStatus;
  expiry: number;
  approved: boolean;
}

export interface WalletSnapshot {
  node: NodeSnapshot | null;
  threshold: ThresholdSnapshot;
  signers: SignerSnapshot[];
  pending_approvals: IntentSnapshot[];
  recent_intents: IntentSnapshot[];
  credentials: number;
}

export interface WalletNodeStatus {
  network: "signet";
  rp_id: string;
  rp_origin: string;
  persistence: string;
  secret_storage: string;
  production_ready: boolean;
}

export interface WalletSignerStatus {
  signer_id: number | null;
  configured: boolean;
  min_signers: number;
  group_pubkey_xonly: string | null;
  approved_actions: number;
}

export interface CredentialSummary {
  credential_id: string;
  label: string;
  registered_at: number;
}

export interface SigningIntent {
  id: string;
  network: string;
  protocol_version: number;
  action: string;
  wallet_id: string;
  signer_id: number;
  tx_digest: string;
  session_id: string;
  expiry: number;
  nonce: string;
  status: IntentStatus;
  created_at: number;
}

export interface ThresholdSigningStatus {
  intent_id: string;
  signer_id: number;
  session_id_hex: string;
  message_hex: string;
  phase: SigningPhase;
  expires_at: number;
}

export interface CreateIntentRequest {
  wallet_id: string;
  signer_id: number;
  tx_digest: string; // 64 hex chars
  session_id: string; // 64 hex chars
  expiry: number; // unix seconds
}

export interface TransactionPrevout {
  outpoint: string;
  value_sat: number;
  script_pubkey_hex: string;
}

export interface TransactionReviewRequest {
  raw_tx_hex: string;
  prevouts: TransactionPrevout[];
  input_index: number;
  max_fee_sat: number;
}

export interface ReviewedInput {
  index: number;
  outpoint: string;
  value_sat: number;
  script_pubkey_hex: string;
  script_type: string;
  address: string | null;
  sequence: number;
  signals_rbf: boolean;
  signing_input: boolean;
}

export interface ReviewedOutput {
  index: number;
  value_sat: number;
  script_pubkey_hex: string;
  script_type: string;
  address: string | null;
  dust: boolean;
}

export interface TransactionWarning {
  code: string;
  message: string;
  input_index: number | null;
  output_index: number | null;
}

export interface TransactionReview {
  network: string;
  txid: string;
  wtxid: string;
  raw_tx_hex: string;
  version: number;
  lock_time: number;
  total_size: number;
  weight_wu: number;
  vsize: number;
  input_count: number;
  output_count: number;
  input_total_sat: number;
  output_total_sat: number;
  fee_sat: number;
  fee_rate_milli_sat_vb: number;
  max_fee_sat: number;
  signals_rbf: boolean;
  input_index: number;
  sighash_type: string;
  sighash_hex: string;
  inputs: ReviewedInput[];
  outputs: ReviewedOutput[];
  warnings: TransactionWarning[];
  signing_allowed: boolean;
}

export interface CreateTransactionIntentRequest {
  wallet_id: string;
  signer_id: number;
  session_id: string;
  expiry: number;
  transaction: TransactionReviewRequest;
}

export interface ApprovalBinding {
  intent_id: string;
  intent_digest_hex: string;
  signer_id: number;
  session_id_hex: string;
  message_hex: string;
  expires_at: number;
}

// WebAuthn option envelopes as serialized by webauthn-rs (base64url strings).
export interface CreationChallengeResponse {
  publicKey: {
    rp: { name: string; id?: string };
    user: { name: string; displayName: string; id: string };
    challenge: string;
    pubKeyCredParams: Array<{ type: string; alg: number }>;
    timeout?: number;
    attestation?: string;
    authenticatorSelection?: Record<string, unknown>;
    excludeCredentials?: Array<{ type: string; id: string }>;
    extensions?: Record<string, unknown>;
  };
}

export interface RequestChallengeResponse {
  publicKey: {
    challenge: string;
    timeout?: number;
    rpId?: string;
    allowCredentials?: Array<{ type: string; id: string }>;
    userVerification?: string;
  };
}

export interface RegisterStartResponse {
  ceremony_id: string;
  public_key: CreationChallengeResponse;
  expires_at: number;
}

export interface RegisterFinishRequest {
  ceremony_id: string;
  credential: unknown; // RegisterPublicKeyCredential JSON
}

export interface RegisterFinishResponse {
  credential_id: string;
  label: string;
  registered_at: number;
}

export interface ApprovalStartResponse {
  ceremony_id: string;
  public_key: RequestChallengeResponse;
  binding: ApprovalBinding;
}

export interface ApprovalFinishRequest {
  ceremony_id: string;
  credential: unknown; // PublicKeyCredential JSON
}

export interface ApprovalFinishResponse {
  intent_id: string;
  signer_id: number;
  approved: boolean;
  expires_at: number;
}

export type ChatMessageRole = "user" | "wallet";
export type ChatMessageKind = "text" | "wallet_action";
export type ChatAuthorizationState =
  | "passkey_required"
  | "approved"
  | "cancelled"
  | "expired"
  | "signed";

export interface ChatIntentBinding {
  intent_id: string;
  intent_digest_hex: string;
  network: string;
  action: "sign_taproot_transaction";
  wallet_id: string;
  signer_id: number;
  tx_digest_hex: string;
  session_id_hex: string;
  expiry: number;
  status: IntentStatus;
  authorization: ChatAuthorizationState;
}

export interface ChatMessage {
  id: string;
  role: ChatMessageRole;
  kind: ChatMessageKind;
  content: string;
  created_at: number;
  wallet_action?: ChatIntentBinding;
  parts?: ChatMessagePart[];
}

export interface ChatTextPart {
  type: "text";
  text: string;
}

export interface ChatUiBlockPart {
  type: "ui_block";
  block: AgentUiBlockReference;
}

export type ChatToolName =
  | "get_wallet_status" | "list_signing_intents" | "read_signing_intent"
  | "cancel_signing_intent" | "get_chat_state" | "add_chat_message"
  | "inspect_transaction" | "create_transaction_intent" | "check_protected_trade"
  | "list_plugins" | "read_plugin_manifest" | "read_plugin_settings_schema"
  | "read_plugin_health" | "validate_plugin_settings_patch" | "create_plugin_settings_intent";

export type ChatPermissionScope =
  | "wallet.status.read" | "wallet.intent.read" | "wallet.intent.create"
  | "wallet.intent.cancel" | "wallet.chat.read" | "wallet.chat.append"
  | "wallet.transaction.inspect" | "wallet.trade.verify" | "plugin.catalog.read"
  | "plugin.manifest.read" | "plugin.settings_schema.read" | "plugin.health.read"
  | "plugin.settings.validate" | "plugin.settings_intent.create" | "indexer.query.read"
  | "browser.open.public";

export interface ChatToolCallPart {
  type: "tool_call";
  tool_call_id: string;
  tool_name: ChatToolName;
  request_digest: string;
  permission_scope: ChatPermissionScope;
  intent_id?: string;
  review_id?: string;
}

export interface ChatToolResultPart {
  type: "tool_result";
  tool_call_id: string;
  outcome: "succeeded" | "failed" | "cancelled";
  result_digest?: string;
  intent_id?: string;
  review_id?: string;
}

export interface ChatErrorPart {
  type: "error";
  code: string;
  message: string;
  retriable: boolean;
}

export interface ChatReviewReferencePart {
  type: "review_reference";
  reference: ChatReviewReference;
}

export type ChatMessagePart =
  | ChatTextPart
  | ChatToolCallPart
  | ChatToolResultPart
  | ChatUiBlockPart
  | ChatReviewReferencePart
  | ChatErrorPart;

export interface ChatExchange {
  user_message: ChatMessage;
  wallet_message: ChatMessage;
}

export interface ChatState {
  messages: ChatMessage[];
  pending_wallet_actions: number;
}

export interface ChatWalletActionRequest {
  type: "sign_taproot_transaction";
  wallet_id: string;
  signer_id: number;
  tx_digest: string;
  session_id: string;
  expiry: number;
}

export interface CreateChatMessageRequest {
  content: string;
  wallet_action?: ChatWalletActionRequest;
}

export interface ApiErrorBody {
  error: { code: string; message: string };
}

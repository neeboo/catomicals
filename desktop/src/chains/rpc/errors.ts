export type ChainRpcErrorCode =
  | "invalid_config"
  | "invalid_request"
  | "credential_unavailable"
  | "broadcast_disabled"
  | "unsupported_transport"
  | "timeout"
  | "redirect_rejected"
  | "response_too_large"
  | "remote_error"
  | "invalid_response";

export class ChainRpcError extends Error {
  readonly code: ChainRpcErrorCode;

  constructor(code: ChainRpcErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "ChainRpcError";
    this.code = code;
  }
}

//! CovHub bridge for the wallet HTTP/MCP/desktop surface.
//!
//! Bounded operations only:
//! - `inspect_proposal` re-verifies a `covhub.wallet-proposal/v1` and
//!   independently reproduces the local chain review. Read-only; no state
//!   change.
//! - `create_intent` repeats inspection and may create only a pending,
//!   Passkey-gated signing intent bound to the locally recomputed review and
//!   a matching local signer profile.
//!
//! There is no approval, Passkey assertion capture, secret, signing, or
//! broadcast surface here. The wallet never fetches a proposal-supplied URL;
//! the complete proposal is always supplied in the request body.

use catomicals_chain_bitcoin::BitcoinChainSuite;
use catomicals_chain_domain::{ChainId, ChainNetwork, ChainScope, ChainSuite};
use catomicals_chain_kaspa::{KaspaChainSuite, KaspaVerifier};
use catomicals_wallet::{
    SignerProfileStartupSnapshot, SigningIntent, WalletNodeService,
    covhub::{
        CovhubError, CovhubInspection, CovhubPendingIntentRequest, CovhubSigningIntent,
        CovhubWalletProposal, create_covhub_signing_intent, inspect_covhub_wallet_proposal,
    },
    signing_job::SignerProfile,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

/// HTTP route for read-only proposal inspection.
pub const COVHUB_INSPECT_ROUTE: &str = "/api/v1/covhub/proposals/inspect";
/// HTTP route for pending-intent creation.
pub const COVHUB_INTENT_ROUTE: &str = "/api/v1/covhub/proposals/intents";
/// Max request-body bytes accepted for a covhub proposal. The core allows up
/// to 1,000,000 decoded material bytes, which encodes to ~1.34 MB of base64,
/// so the transport bound must exceed the plain 1 MiB general body cap.
pub const COVHUB_MAX_REQUEST_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Bounded bridge error with a stable HTTP status and machine code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CovhubBridgeError {
    #[error("invalid session id `{0}`; expected 64 lowercase hex characters")]
    InvalidSessionId(String),
    #[error("signer profile `{profile_id}` is not configured in this wallet")]
    ProfileNotFound { profile_id: Uuid },
    #[error("no local chain suite for chain scope {scope:?}")]
    NoLocalSuite { scope: ChainScope },
    #[error("signer profile `{profile_id}` cannot back a local chain suite: {reason}")]
    ProfileSuiteUnavailable { profile_id: Uuid, reason: String },
    #[error("wallet signer inventory is unavailable: {0}")]
    ProfileInventoryUnavailable(String),
    #[error("proposal JSON could not be encoded: {0}")]
    ProposalEncoding(String),
    #[error("durable intent persistence failed: {0}")]
    Persistence(String),
    #[error(transparent)]
    Covhub(#[from] CovhubError),
}

impl CovhubBridgeError {
    /// Stable machine code for the JSON error envelope.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidSessionId(_) => "invalid_session_id",
            Self::ProfileNotFound { .. } => "signer_profile_not_found",
            Self::NoLocalSuite { .. } => "unsupported_chain_scope",
            Self::ProfileSuiteUnavailable { .. } => "signer_profile_suite_unavailable",
            Self::ProfileInventoryUnavailable(_) => "signer_inventory_unavailable",
            Self::ProposalEncoding(_) => "invalid_json",
            Self::Persistence(_) => "intent_persistence_failed",
            Self::Covhub(error) => match error {
                CovhubError::InvalidJson(_) => "invalid_json",
                CovhubError::StrictParse(_) => "proposal_rejected",
                CovhubError::UnsupportedSchema { .. } => "unsupported_schema",
                CovhubError::InvalidProposalId(_) => "invalid_proposal_id",
                CovhubError::InvalidDigest(_) => "invalid_digest",
                CovhubError::UnsupportedEncoding(_) => "unsupported_encoding",
                CovhubError::EmptyMediaType => "empty_media_type",
                CovhubError::EmptySummary => "empty_summary",
                CovhubError::AnalysisOnlyWithoutBlocker => "analysis_only_without_blocker",
                CovhubError::ReadyWithBlocker => "ready_with_blocker",
                CovhubError::ContentDigestMismatch { .. } => "content_digest_mismatch",
                CovhubError::InvalidBase64 => "invalid_base64",
                CovhubError::MaterialTooLarge { .. } => "material_too_large",
                CovhubError::TransactionHashMismatch { .. } => "transaction_hash_mismatch",
                CovhubError::UnsupportedScope { .. } => "unsupported_chain_scope",
                CovhubError::ReviewFailed(_) => "chain_review_failed",
                CovhubError::AnalysisOnly => "analysis_only",
                CovhubError::ExpiredProposal { .. } => "proposal_expired",
                CovhubError::ProfileScopeMismatch { .. } => "signer_profile_scope_mismatch",
                CovhubError::ProfileNotExecutable { .. } => "signer_profile_not_executable",
                CovhubError::InvalidTimestamp(_) => "invalid_timestamp",
            },
        }
    }

    /// HTTP status for the JSON error envelope.
    pub fn status(&self) -> u16 {
        match self {
            Self::InvalidSessionId(_) | Self::ProposalEncoding(_) => 400,
            Self::Persistence(_) => 500,
            Self::ProfileNotFound { .. } => 404,
            Self::Covhub(CovhubError::ExpiredProposal { .. }) => 409,
            Self::Covhub(_) => 422,
            Self::NoLocalSuite { .. }
            | Self::ProfileSuiteUnavailable { .. }
            | Self::ProfileInventoryUnavailable(_) => 422,
        }
    }
}

/// Complete proposal supplied by the agent. The wallet never fetches a URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectCovhubProposalRequest {
    pub proposal: Value,
}

/// Complete proposal plus the selected local signer profile and session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateCovhubIntentRequest {
    pub proposal: Value,
    pub session_id: String,
    pub profile_id: Uuid,
}

/// Independently inspect a proposal and reproduce the local chain review.
/// Read-only: no state change, no intent, no approval.
pub fn inspect_proposal(
    api: &WalletNodeService,
    raw_proposal: &str,
    now: i64,
) -> Result<Value, CovhubBridgeError> {
    let proposal = CovhubWalletProposal::parse(raw_proposal)?;
    let profile = resolve_profile_by_scope(api, &proposal.chain_scope)?;
    let suite = build_suite(&profile)?;
    let inspection = inspect_covhub_wallet_proposal(raw_proposal, suite.as_ref(), now)?;
    Ok(inspection_to_value(&inspection))
}

/// Repeat inspection and create only a pending, Passkey-gated intent bound to
/// the locally recomputed review and the selected local signer profile. The
/// pending intent is durably persisted through the wallet's existing intent
/// store, so it can be listed, read, cancelled, restored, and presented to the
/// existing human Passkey approval flow.
pub fn create_intent(
    api: &mut WalletNodeService,
    request: CreateCovhubIntentRequest,
    now: i64,
) -> Result<Value, CovhubBridgeError> {
    let session_id = parse_session_id(&request.session_id)?;
    let raw_proposal = serde_json::to_string(&request.proposal)
        .map_err(|error| CovhubBridgeError::ProposalEncoding(error.to_string()))?;
    // Strict early validation; the core repeats full inspection afterwards.
    let _ = CovhubWalletProposal::parse(&raw_proposal)?;
    let profile = resolve_profile_by_id(api, request.profile_id)?;
    let suite = build_suite(&profile)?;
    let intent = create_covhub_signing_intent(CovhubPendingIntentRequest {
        raw_proposal: &raw_proposal,
        suite: suite.as_ref(),
        profile: &profile,
        session_id,
        now,
        intent_id: None,
    })?;
    let persisted = api
        .create_covhub_intent(intent, now)
        .map_err(|error| CovhubBridgeError::Persistence(error.to_string()))?;
    Ok(intent_to_value(&persisted))
}

/// Look up a local signer profile whose chain scope matches the proposal.
/// Inspection is only possible when the wallet has a locally executable
/// chain suite/profile for the exact proposal scope (fail closed otherwise).
fn resolve_profile_by_scope(
    api: &WalletNodeService,
    scope: &ChainScope,
) -> Result<SignerProfile, CovhubBridgeError> {
    let snapshots = signer_snapshots(api)?;
    let snapshot = snapshots
        .iter()
        .find(|snapshot| &snapshot.chain_scope == scope)
        .ok_or_else(|| CovhubBridgeError::NoLocalSuite { scope: *scope })?;
    signer_profile_from_snapshot(snapshot)
}

fn resolve_profile_by_id(
    api: &WalletNodeService,
    profile_id: Uuid,
) -> Result<SignerProfile, CovhubBridgeError> {
    let snapshots = signer_snapshots(api)?;
    let snapshot = snapshots
        .iter()
        .find(|snapshot| snapshot.profile_id == profile_id)
        .ok_or_else(|| CovhubBridgeError::ProfileNotFound { profile_id })?;
    signer_profile_from_snapshot(snapshot)
}

fn signer_snapshots(
    api: &WalletNodeService,
) -> Result<Vec<SignerProfileStartupSnapshot>, CovhubBridgeError> {
    api.signer_profiles_snapshot()
        .map_err(|error| CovhubBridgeError::ProfileInventoryUnavailable(error.to_string()))
}

fn signer_profile_from_snapshot(
    snapshot: &SignerProfileStartupSnapshot,
) -> Result<SignerProfile, CovhubBridgeError> {
    let verification_key = hex::decode(&snapshot.verification_key_hex).map_err(|_| {
        CovhubBridgeError::ProfileSuiteUnavailable {
            profile_id: snapshot.profile_id,
            reason: "verification key is not hexadecimal".to_owned(),
        }
    })?;
    SignerProfile::new(
        snapshot.profile_id,
        snapshot.wallet_id,
        snapshot.chain_scope,
        snapshot.signing_suite_id,
        snapshot.backend_requirement,
        snapshot.signer_set_id.clone(),
        snapshot.authorization_signer_id.clone(),
        snapshot.signer_epoch,
        snapshot.threshold,
        snapshot.max_signers,
        verification_key,
        snapshot.secret_ref.clone(),
    )
    .map_err(|error| CovhubBridgeError::ProfileSuiteUnavailable {
        profile_id: snapshot.profile_id,
        reason: error.to_string(),
    })
}

/// Construct the real local chain suite bound to the profile's verification
/// key. Only scopes with a locally reviewable suite are supported; everything
/// else fails closed.
fn build_suite(profile: &SignerProfile) -> Result<Box<dyn ChainSuite>, CovhubBridgeError> {
    match profile.chain_scope.chain {
        ChainId::Bitcoin => {
            let key: [u8; 32] = profile
                .verification_key
                .as_slice()
                .try_into()
                .map_err(|_| CovhubBridgeError::ProfileSuiteUnavailable {
                    profile_id: profile.profile_id,
                    reason: "Bitcoin profile verification key is not 32 bytes".to_owned(),
                })?;
            let xonly = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&key).map_err(|error| {
                CovhubBridgeError::ProfileSuiteUnavailable {
                    profile_id: profile.profile_id,
                    reason: error.to_string(),
                }
            })?;
            BitcoinChainSuite::new(profile.chain_scope, xonly)
                .map(|suite| Box::new(suite) as Box<dyn ChainSuite>)
                .map_err(|error| CovhubBridgeError::ProfileSuiteUnavailable {
                    profile_id: profile.profile_id,
                    reason: error.to_string(),
                })
        }
        ChainId::Kaspa => {
            let key: [u8; 33] = profile
                .verification_key
                .as_slice()
                .try_into()
                .map_err(|_| CovhubBridgeError::ProfileSuiteUnavailable {
                    profile_id: profile.profile_id,
                    reason: "Kaspa profile verification key is not 33 bytes".to_owned(),
                })?;
            let network = match profile.chain_scope.network {
                ChainNetwork::Kaspa(network) => network,
                _ => {
                    return Err(CovhubBridgeError::ProfileSuiteUnavailable {
                        profile_id: profile.profile_id,
                        reason: "Kaspa scope has no concrete network".to_owned(),
                    });
                }
            };
            KaspaChainSuite::new(network, KaspaVerifier::EcdsaCbMpc(key))
                .map(|suite| Box::new(suite) as Box<dyn ChainSuite>)
                .map_err(|error| CovhubBridgeError::ProfileSuiteUnavailable {
                    profile_id: profile.profile_id,
                    reason: error.to_string(),
                })
        }
        _ => Err(CovhubBridgeError::NoLocalSuite {
            scope: profile.chain_scope,
        }),
    }
}

fn parse_session_id(value: &str) -> Result<[u8; 32], CovhubBridgeError> {
    // Exactly 64 lowercase hex characters. Uppercase hex fails closed so a
    // session id cannot be re-cased to collide with another session.
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CovhubBridgeError::InvalidSessionId(value.to_owned()));
    }
    let bytes =
        hex::decode(value).map_err(|_| CovhubBridgeError::InvalidSessionId(value.to_owned()))?;
    let mut session = [0u8; 32];
    session.copy_from_slice(&bytes);
    Ok(session)
}

/// Bounded inspection response. The decoded transaction material is never
/// echoed back; only its verified size and hash are reported.
fn inspection_to_value(inspection: &CovhubInspection) -> Value {
    let proposal = &inspection.proposal;
    json!({
        "schema": proposal.schema,
        "proposal_id": proposal.proposal_id,
        "canvas_digest": proposal.canvas_digest,
        "code_confirmation_digest": proposal.code_confirmation_digest,
        "chain_scope": proposal.chain_scope,
        "summary": proposal.summary,
        "created_at": proposal.created_at,
        "expires_at": proposal.expires_at,
        "readiness": proposal.readiness,
        "transaction": {
            "encoding": proposal.transaction.encoding,
            "media_type": proposal.transaction.media_type,
            "sha256": proposal.transaction.sha256,
            "decoded_material_size": inspection.decoded_material_size,
        },
        "verified_content_digest": proposal.content_digest,
        "is_expired": inspection.is_expired,
        "eligible": inspection.eligible,
        "review": {
            "schema_version": inspection.review.schema_version,
            "scope": inspection.review.scope,
            "review_digest_hex": hex::encode(inspection.review.review_digest),
            "signing_message_digest_hex": hex::encode(inspection.review.signing_message_digest),
            "summary": inspection.review.summary,
        },
    })
}

/// Bounded pending-intent response. Contains no secret, authorization, or
/// signing material; the intent itself is Passkey-gated by construction. The
/// response is reconstructed from the durably persisted wallet intent, so the
/// `intent.intent_id` is the wallet intent id that list/read/cancel/approval
/// routes operate on.
fn intent_to_value(persisted: &SigningIntent) -> Value {
    let intent = CovhubSigningIntent::from_wallet_intent(persisted);
    json!({
        "intent": intent,
        "requires_passkey_approval": true,
    })
}

/// Shorthand used by the HTTP router to build the error envelope.
pub fn bridge_error_json(error: &CovhubBridgeError) -> Value {
    json!({
        "error": {
            "code": error.code(),
            "message": error.to_string(),
        }
    })
}

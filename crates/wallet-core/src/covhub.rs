//! CovHub bridge core: strict `covhub.wallet-proposal/v1` parsing, canonical
//! RFC 8785 (JCS) content digests, and a chain-neutral pending signing intent.
//!
//! Trust boundary (see `docs/specs/covhub-catomicals-agent-v1.md`):
//! - Every CovHub digest and status is untrusted input until the wallet
//!   recomputes the digest and re-runs the selected local `ChainSuite` over
//!   the complete transaction material.
//! - A `ready_for_wallet_review` proposal is only eligible to become a pending
//!   intent. It is **not** approved and is **not** ready for signing.
//! - This module adds no approval, signing, secret, broadcast, or transport
//!   surface. The pending intent is Passkey-gated by construction: creating
//!   it never produces a [`crate::signing_job::SigningJob`], and no
//!   signing capability exists until a separate Passkey approval flow binds
//!   the intent digest.
//! - The proposal deliberately has no trusted signing-message field. The
//!   wallet derives `ReviewArtifact::review_digest` and
//!   `ReviewArtifact::signing_message_digest` through its local chain suite.

use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use catomicals_chain_domain::{
    ChainId, ChainNetwork, ChainScope, ChainSuite, MAX_REVIEW_MATERIAL_BYTES, ReviewArtifact,
    RpcPresetId,
};
use catomicals_signing_domain::require_executable_suite;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use uuid::Uuid;

/// The only proposal contract schema accepted by this parser.
pub const COVHUB_WALLET_PROPOSAL_SCHEMA: &str = "covhub.wallet-proposal/v1";
/// Proposal identifiers are stable ids prefixed with `proposal:`.
pub const COVHUB_PROPOSAL_ID_PREFIX: &str = "proposal:";
/// Decoded transaction material is limited to one megabyte (spec).
pub const COVHUB_MAX_DECODED_MATERIAL_BYTES: usize = MAX_REVIEW_MATERIAL_BYTES;
/// Canonical signing-intent protocol version for the chain-neutral intent.
pub const COVHUB_SIGNING_INTENT_VERSION: u16 = 1;

/// Errors from the CovHub wallet-proposal bridge.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CovhubError {
    #[error("proposal is not valid UTF-8 JSON: {0}")]
    InvalidJson(String),
    #[error("strict proposal parse failed: {0}")]
    StrictParse(String),
    #[error("proposal schema `{actual}` is not `covhub.wallet-proposal/v1`")]
    UnsupportedSchema { actual: String },
    #[error("proposal id `{0}` is not a stable `proposal:<id>` identifier")]
    InvalidProposalId(String),
    #[error("invalid `sha256:<64 lowercase hex>` digest `{0}`")]
    InvalidDigest(String),
    #[error("unsupported transaction encoding `{0}`; expected `base64`")]
    UnsupportedEncoding(String),
    #[error("transaction media type must not be empty")]
    EmptyMediaType,
    #[error("proposal summary must not be empty")]
    EmptySummary,
    #[error("analysis_only readiness requires at least one blocker")]
    AnalysisOnlyWithoutBlocker,
    #[error("ready_for_wallet_review readiness must not declare blockers")]
    ReadyWithBlocker,
    #[error("content digest mismatch: declared {declared}, computed {computed}")]
    ContentDigestMismatch { declared: String, computed: String },
    #[error("transaction material must be standard padded base64")]
    InvalidBase64,
    #[error("decoded transaction material is {actual_bytes} bytes; maximum is {max_bytes} bytes")]
    MaterialTooLarge {
        actual_bytes: usize,
        max_bytes: usize,
    },
    #[error("transaction sha256 mismatch: declared {declared}, computed {computed}")]
    TransactionHashMismatch { declared: String, computed: String },
    #[error("chain scope {scope:?} is not supported by the local chain suite")]
    UnsupportedScope { scope: ChainScope },
    #[error("local chain review failed: {0}")]
    ReviewFailed(String),
    #[error("proposal is analysis-only and cannot create a signing intent")]
    AnalysisOnly,
    #[error("proposal has expired (expires_at {expires_at})")]
    ExpiredProposal { expires_at: String },
    #[error(
        "signer profile chain scope {profile_scope:?} does not match proposal scope {proposal_scope:?}"
    )]
    ProfileScopeMismatch {
        profile_scope: ChainScope,
        proposal_scope: ChainScope,
    },
    #[error("signer profile {profile_id} is not executable for its chain scope: {reason}")]
    ProfileNotExecutable { profile_id: Uuid, reason: String },
    #[error("invalid RFC3339 timestamp `{0}`")]
    InvalidTimestamp(String),
}

/// Transaction material inside a wallet proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CovhubTransactionMaterial {
    pub encoding: String,
    pub media_type: String,
    pub material_base64: String,
    pub sha256: String,
}

/// Proposal readiness. `ready_for_wallet_review` may become a pending intent;
/// `analysis_only` requires at least one blocker and cannot create an intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CovhubReadinessStatus {
    ReadyForWalletReview,
    AnalysisOnly,
}

/// Proposal readiness block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CovhubReadiness {
    pub status: CovhubReadinessStatus,
    pub blockers: Vec<String>,
}

/// A strictly parsed `covhub.wallet-proposal/v1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CovhubWalletProposal {
    pub schema: String,
    pub proposal_id: String,
    pub canvas_digest: String,
    pub code_confirmation_digest: String,
    pub chain_scope: ChainScope,
    pub transaction: CovhubTransactionMaterial,
    pub summary: String,
    pub created_at: String,
    pub expires_at: String,
    pub readiness: CovhubReadiness,
    pub content_digest: String,
}

/// Wire form used for strict `deny_unknown_fields` parsing. `chain_scope` is
/// held as loose strings because the contract admits both the spec network
/// names (`kaspa-testnet-11`) and the wallet's canonical names
/// (`kaspa.testnet11`).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CovhubWalletProposalWire {
    schema: String,
    proposal_id: String,
    canvas_digest: String,
    code_confirmation_digest: String,
    chain_scope: CovhubChainScopeWire,
    transaction: CovhubTransactionMaterial,
    summary: String,
    created_at: String,
    expires_at: String,
    readiness: CovhubReadiness,
    content_digest: String,
}

/// Loose chain-scope wire form accepted by the CovHub contract.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CovhubChainScopeWire {
    schema_version: u16,
    chain: ChainId,
    network: String,
}

impl CovhubChainScopeWire {
    fn to_chain_scope(&self) -> Result<ChainScope, CovhubError> {
        if self.schema_version != 1 {
            return Err(CovhubError::StrictParse(format!(
                "unsupported chain scope schema version {}; expected 1",
                self.schema_version
            )));
        }
        let network = match ChainNetwork::from_str(&self.network) {
            Ok(network) => network,
            Err(_) => match RpcPresetId::from_str(&self.network) {
                Ok(preset) => preset.chain_network(),
                Err(_) => {
                    return Err(CovhubError::StrictParse(format!(
                        "unsupported concrete chain network `{}`",
                        self.network
                    )));
                }
            },
        };
        ChainScope::new(self.chain, network)
            .map_err(|error| CovhubError::StrictParse(error.to_string()))
    }
}

impl CovhubWalletProposal {
    /// Strictly parse a raw proposal. Unknown fields, malformed identifiers,
    /// invalid digest strings, and inconsistent readiness are rejected here.
    /// The canonical content digest is verified separately by
    /// [`verify_content_digest`].
    pub fn parse(raw: &str) -> Result<Self, CovhubError> {
        let value: Value = serde_json::from_str(raw)
            .map_err(|error| CovhubError::InvalidJson(error.to_string()))?;
        let wire: CovhubWalletProposalWire = serde_json::from_value(value)
            .map_err(|error| CovhubError::StrictParse(error.to_string()))?;
        let chain_scope = wire.chain_scope.to_chain_scope()?;

        if wire.schema != COVHUB_WALLET_PROPOSAL_SCHEMA {
            return Err(CovhubError::UnsupportedSchema {
                actual: wire.schema,
            });
        }
        if !wire.proposal_id.starts_with(COVHUB_PROPOSAL_ID_PREFIX)
            || wire.proposal_id.len() <= COVHUB_PROPOSAL_ID_PREFIX.len()
        {
            return Err(CovhubError::InvalidProposalId(wire.proposal_id));
        }
        for (label, digest) in [
            ("canvas_digest", &wire.canvas_digest),
            ("code_confirmation_digest", &wire.code_confirmation_digest),
            ("content_digest", &wire.content_digest),
        ] {
            if !valid_sha256_digest(digest) {
                return Err(CovhubError::InvalidDigest(format!("{label} `{digest}`")));
            }
        }
        if wire.transaction.encoding != "base64" {
            return Err(CovhubError::UnsupportedEncoding(wire.transaction.encoding));
        }
        if wire.transaction.media_type.trim().is_empty() {
            return Err(CovhubError::EmptyMediaType);
        }
        if !valid_sha256_digest(&wire.transaction.sha256) {
            return Err(CovhubError::InvalidDigest(format!(
                "transaction.sha256 `{}`",
                wire.transaction.sha256
            )));
        }
        if wire.summary.trim().is_empty() {
            return Err(CovhubError::EmptySummary);
        }
        match wire.readiness.status {
            CovhubReadinessStatus::ReadyForWalletReview => {
                if !wire.readiness.blockers.is_empty() {
                    return Err(CovhubError::ReadyWithBlocker);
                }
            }
            CovhubReadinessStatus::AnalysisOnly => {
                if wire.readiness.blockers.is_empty() {
                    return Err(CovhubError::AnalysisOnlyWithoutBlocker);
                }
            }
        }

        // Both timestamps must be valid RFC 3339. Parsing is total and
        // panic-free; malformed or truncated values fail closed here so no
        // later stage can observe an unvalidated timestamp.
        let _ = parse_rfc3339_seconds(&wire.created_at)?;
        let _ = parse_rfc3339_seconds(&wire.expires_at)?;

        Ok(Self {
            schema: wire.schema,
            proposal_id: wire.proposal_id,
            canvas_digest: wire.canvas_digest,
            code_confirmation_digest: wire.code_confirmation_digest,
            chain_scope,
            transaction: wire.transaction,
            summary: wire.summary,
            created_at: wire.created_at,
            expires_at: wire.expires_at,
            readiness: wire.readiness,
            content_digest: wire.content_digest,
        })
    }
}

fn valid_sha256_digest(value: &str) -> bool {
    let Some(hex_part) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex_part.len() == 64
        && hex_part
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// RFC 8785 (JCS) canonical digest of a proposal JSON object with its
/// `content_digest` field omitted: `sha256:<64 lowercase hex>`.
pub fn compute_content_digest(raw: &str) -> Result<String, CovhubError> {
    let mut value: Value =
        serde_json::from_str(raw).map_err(|error| CovhubError::InvalidJson(error.to_string()))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| CovhubError::InvalidJson("proposal root must be an object".to_owned()))?;
    object.remove("content_digest");
    let canonical = serde_jcs::to_string(&value)
        .map_err(|error| CovhubError::InvalidJson(error.to_string()))?;
    Ok(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(canonical.as_bytes()))
    ))
}

/// Verify the proposal's declared `content_digest` against the locally
/// recomputed RFC 8785 canonical digest. Returns the computed digest.
pub fn verify_content_digest(raw: &str) -> Result<String, CovhubError> {
    let proposal = CovhubWalletProposal::parse(raw)?;
    let computed = compute_content_digest(raw)?;
    if proposal.content_digest != computed {
        return Err(CovhubError::ContentDigestMismatch {
            declared: proposal.content_digest,
            computed,
        });
    }
    Ok(computed)
}

/// Decode the proposal's base64 material and verify size and sha256 bounds.
pub fn decode_transaction_material(
    proposal: &CovhubWalletProposal,
) -> Result<Vec<u8>, CovhubError> {
    let decoded = BASE64_STANDARD
        .decode(&proposal.transaction.material_base64)
        .map_err(|_| CovhubError::InvalidBase64)?;
    if decoded.len() > COVHUB_MAX_DECODED_MATERIAL_BYTES {
        return Err(CovhubError::MaterialTooLarge {
            actual_bytes: decoded.len(),
            max_bytes: COVHUB_MAX_DECODED_MATERIAL_BYTES,
        });
    }
    let computed = format!("sha256:{}", hex::encode(Sha256::digest(&decoded)));
    if computed != proposal.transaction.sha256 {
        return Err(CovhubError::TransactionHashMismatch {
            declared: proposal.transaction.sha256.clone(),
            computed,
        });
    }
    Ok(decoded)
}

/// Result of an independent, read-only wallet inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CovhubInspection {
    pub proposal: CovhubWalletProposal,
    pub decoded_material_size: usize,
    pub review: ReviewArtifact,
    pub is_expired: bool,
    pub eligible: bool,
}

/// Strict parse + canonical digest verification + independent local
/// chain-suite review. Read-only: no state change.
pub fn inspect_covhub_wallet_proposal(
    raw: &str,
    suite: &dyn ChainSuite,
    now: i64,
) -> Result<CovhubInspection, CovhubError> {
    let proposal = CovhubWalletProposal::parse(raw)?;
    verify_content_digest(raw)?;
    let decoded = decode_transaction_material(&proposal)?;
    if suite.scope() != proposal.chain_scope {
        return Err(CovhubError::UnsupportedScope {
            scope: proposal.chain_scope,
        });
    }
    let review = suite
        .review_transaction(&decoded)
        .map_err(|error| CovhubError::ReviewFailed(error.to_string()))?;
    let expires_seconds = parse_rfc3339_seconds(&proposal.expires_at)?;
    let is_expired = now > expires_seconds;
    let eligible =
        proposal.readiness.status == CovhubReadinessStatus::ReadyForWalletReview && !is_expired;
    Ok(CovhubInspection {
        decoded_material_size: decoded.len(),
        review,
        is_expired,
        eligible,
        proposal,
    })
}

/// Lifecycle of a chain-neutral CovHub signing intent. Only `pending` intents
/// exist from this bridge; the type itself is Passkey-gated and never produces
/// a [`crate::signing_job::SigningJob`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CovhubIntentStatus {
    Pending,
    Approved,
    Cancelled,
    Expired,
    Signed,
}

/// Chain-neutral pending signing intent bound to the locally recomputed
/// review and the selected local signer profile.
///
/// `chain_scope` replaces any chain-specific network enum: a Kaspa proposal
/// is stored as Kaspa, never encoded as Bitcoin Signet. The intent binds the
/// exact ChainScope, review digest, signing-message digest, session, expiry,
/// and profile into an immutable digest for a future Passkey approval gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CovhubSigningIntent {
    pub version: u16,
    pub intent_id: Uuid,
    pub proposal_id: String,
    pub proposal_digest: String,
    pub canvas_digest: String,
    pub code_confirmation_digest: String,
    pub chain_scope: ChainScope,
    #[serde(with = "crate::api::hex_array32")]
    pub review_digest: [u8; 32],
    #[serde(with = "crate::api::hex_array32")]
    pub signing_message_digest: [u8; 32],
    #[serde(with = "crate::api::hex_array32")]
    pub session_id: [u8; 32],
    pub profile_id: Uuid,
    /// Unix seconds after which the intent may not be approved.
    pub expires_at: i64,
    pub created_at: i64,
    pub status: CovhubIntentStatus,
}

impl CovhubSigningIntent {
    /// Canonical encoding of the immutable intent fields (lifecycle metadata
    /// `status`/`created_at` are excluded, matching the wallet intent model).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        covhub_canonical_bytes(
            self.version,
            &self.intent_id,
            &self.proposal_id,
            &self.proposal_digest,
            &self.canvas_digest,
            &self.code_confirmation_digest,
            &self.chain_scope,
            &self.review_digest,
            &self.signing_message_digest,
            &self.session_id,
            &self.profile_id,
            self.expires_at,
        )
    }

    /// Reconstruct the chain-neutral CovHub intent view of a durable wallet
    /// intent that carries a [`CovhubBinding`]. Returns `None` for wallet
    /// intents that are not CovHub-backed. The lifecycle status is translated
    /// from the authoritative wallet `SigningIntent` status.
    pub fn from_wallet_intent(intent: &crate::intent::SigningIntent) -> Option<Self> {
        use crate::intent::IntentStatus;
        let binding = intent.covhub.as_ref()?;
        Some(Self {
            version: binding.version,
            intent_id: intent.id,
            proposal_id: binding.proposal_id.clone(),
            proposal_digest: binding.proposal_digest.clone(),
            canvas_digest: binding.canvas_digest.clone(),
            code_confirmation_digest: binding.code_confirmation_digest.clone(),
            chain_scope: binding.chain_scope,
            review_digest: binding.review_digest,
            signing_message_digest: binding.signing_message_digest,
            session_id: intent.session_id,
            profile_id: binding.profile_id,
            expires_at: intent.expiry,
            created_at: intent.created_at,
            status: match intent.status {
                IntentStatus::Pending => CovhubIntentStatus::Pending,
                IntentStatus::Approved => CovhubIntentStatus::Approved,
                IntentStatus::Cancelled => CovhubIntentStatus::Cancelled,
                IntentStatus::Expired => CovhubIntentStatus::Expired,
                IntentStatus::Signing | IntentStatus::Signed => CovhubIntentStatus::Signed,
            },
        })
    }

    /// SHA-256 of the immutable intent. This is the future Passkey approval
    /// challenge; nothing about the signing request can be swapped after it is
    /// issued.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }

    /// A CovHub intent is always Passkey-gated: approval is mandatory before
    /// any signing job can exist.
    pub fn requires_passkey_approval(&self) -> bool {
        true
    }

    pub fn is_expired(&self, now: i64) -> bool {
        now > self.expires_at
    }
}

pub(crate) fn append_field(output: &mut Vec<u8>, field: &[u8]) {
    let length = u32::try_from(field.len()).expect("bounded contract field fits in u32");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(field);
}

/// Immutable CovHub binding attached to a wallet [`crate::intent::SigningIntent`].
///
/// This is the narrow, versioned, chain-neutral intent binding. A CovHub
/// pending intent is persisted through the existing durable wallet intent
/// store as a `SigningIntent` carrying this binding, so it can be listed,
/// read, cancelled, restored, and presented to the existing human Passkey
/// approval flow without ever encoding a Kaspa scope as Bitcoin Signet.
///
/// The binding deliberately carries **no** lifecycle field: `status`,
/// `created_at`, and `expires_at` live on the wallet `SigningIntent`, which is
/// the durable record and the authority on lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CovhubBinding {
    pub version: u16,
    pub proposal_id: String,
    pub proposal_digest: String,
    pub canvas_digest: String,
    pub code_confirmation_digest: String,
    pub chain_scope: ChainScope,
    #[serde(with = "crate::api::hex_array32")]
    pub review_digest: [u8; 32],
    #[serde(with = "crate::api::hex_array32")]
    pub signing_message_digest: [u8; 32],
    pub profile_id: Uuid,
}

impl CovhubBinding {
    /// Build the durable wallet-intent binding from the chain-neutral pending
    /// intent produced by [`create_covhub_signing_intent`].
    pub fn from_covhub_intent(intent: &CovhubSigningIntent) -> Self {
        Self {
            version: intent.version,
            proposal_id: intent.proposal_id.clone(),
            proposal_digest: intent.proposal_digest.clone(),
            canvas_digest: intent.canvas_digest.clone(),
            code_confirmation_digest: intent.code_confirmation_digest.clone(),
            chain_scope: intent.chain_scope,
            review_digest: intent.review_digest,
            signing_message_digest: intent.signing_message_digest,
            profile_id: intent.profile_id,
        }
    }
}

/// Whether a new chain signing job request matches the immutable CovHub
/// binding carried by the wallet intent in every field the approved intent is
/// authority over: exact native chain scope, review digest, signing message
/// digest, selected signer profile, and the executable signing suite/profile
/// relationship, plus the intent session and expiry.
///
/// `profile_scope` and `profile_suite` are the wallet-stored signer profile
/// fields for `binding.profile_id`; they prove the exact selected executable
/// signing suite/profile relationship (the profile must be executable for the
/// bound chain scope and the job must select exactly that suite).
///
/// The legacy `network`/`action` placeholder fields on the wallet intent are
/// never consulted: for a CovHub-backed intent the chain-neutral
/// [`CovhubBinding::chain_scope`] is the sole chain authority. A Kaspa
/// Testnet11 intent must never route through the Signet placeholder.
pub(crate) fn covhub_job_matches_binding(
    intent: &crate::intent::SigningIntent,
    job: &crate::signing_job::SigningJob,
    profile_scope: ChainScope,
    profile_suite: catomicals_signing_domain::SigningSuiteId,
) -> bool {
    let Some(binding) = &intent.covhub else {
        return true;
    };
    if job.chain_scope != binding.chain_scope
        || job.review.review_digest != binding.review_digest
        || job.review.signing_message_digest != binding.signing_message_digest
        || job.profile_id != binding.profile_id
        || job.session_id != intent.session_id
        || job.expires_at != intent.expiry
    {
        return false;
    }
    if profile_scope != binding.chain_scope
        || profile_suite != job.signing_suite_id
        || require_executable_suite(&binding.chain_scope, profile_suite).is_err()
    {
        return false;
    }
    true
}

/// Canonical approval bytes for a CovHub-bound wallet intent. Reproduces
/// [`CovhubSigningIntent::canonical_bytes`] exactly so the Passkey challenge
/// for a durable CovHub intent equals the chain-neutral CovHub intent digest.
pub(crate) fn covhub_canonical_bytes(
    version: u16,
    intent_id: &Uuid,
    proposal_id: &str,
    proposal_digest: &str,
    canvas_digest: &str,
    code_confirmation_digest: &str,
    chain_scope: &ChainScope,
    review_digest: &[u8; 32],
    signing_message_digest: &[u8; 32],
    session_id: &[u8; 32],
    profile_id: &Uuid,
    expires_at: i64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(320);
    out.extend_from_slice(b"catomicals/covhub-signing-intent\0");
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(intent_id.as_bytes());
    append_field(&mut out, proposal_id.as_bytes());
    append_field(&mut out, proposal_digest.as_bytes());
    append_field(&mut out, canvas_digest.as_bytes());
    append_field(&mut out, code_confirmation_digest.as_bytes());
    append_field(&mut out, chain_scope.chain.as_str().as_bytes());
    append_field(&mut out, chain_scope.network.as_str().as_bytes());
    out.extend_from_slice(review_digest);
    out.extend_from_slice(signing_message_digest);
    out.extend_from_slice(session_id);
    out.extend_from_slice(profile_id.as_bytes());
    out.extend_from_slice(&expires_at.to_be_bytes());
    out
}

/// Request to create a chain-neutral pending CovHub signing intent.
pub struct CovhubPendingIntentRequest<'a> {
    pub raw_proposal: &'a str,
    pub suite: &'a dyn ChainSuite,
    pub profile: &'a crate::signing_job::SignerProfile,
    pub session_id: [u8; 32],
    pub now: i64,
    pub intent_id: Option<Uuid>,
}

/// Repeat inspection and, only when the proposal is eligible and a matching
/// local executable signer profile is available, create a **pending** intent
/// bound to the locally recomputed review and selected profile.
///
/// Fails closed when the proposal is analysis-only, expired, oversized, has a
/// digest mismatch, selects an unsupported scope, lacks a locally executable
/// suite/profile, or cannot reproduce the review. It never accepts a
/// CovHub-provided authorization, signature, signer secret, or broadcast
/// instruction, and it never creates a [`crate::signing_job::SigningJob`].
pub fn create_covhub_signing_intent(
    request: CovhubPendingIntentRequest<'_>,
) -> Result<CovhubSigningIntent, CovhubError> {
    let inspection =
        inspect_covhub_wallet_proposal(request.raw_proposal, request.suite, request.now)?;
    if !inspection.eligible {
        if inspection.proposal.readiness.status == CovhubReadinessStatus::AnalysisOnly {
            return Err(CovhubError::AnalysisOnly);
        }
        return Err(CovhubError::ExpiredProposal {
            expires_at: inspection.proposal.expires_at.clone(),
        });
    }
    if request.profile.chain_scope != inspection.proposal.chain_scope {
        return Err(CovhubError::ProfileScopeMismatch {
            profile_scope: request.profile.chain_scope,
            proposal_scope: inspection.proposal.chain_scope,
        });
    }
    require_executable_suite(
        &request.profile.chain_scope,
        request.profile.signing_suite_id,
    )
    .map_err(|error| CovhubError::ProfileNotExecutable {
        profile_id: request.profile.profile_id,
        reason: error.to_string(),
    })?;
    let expires_seconds = parse_rfc3339_seconds(&inspection.proposal.expires_at)?;

    Ok(CovhubSigningIntent {
        version: COVHUB_SIGNING_INTENT_VERSION,
        intent_id: request.intent_id.unwrap_or_else(Uuid::new_v4),
        proposal_id: inspection.proposal.proposal_id.clone(),
        proposal_digest: inspection.proposal.content_digest.clone(),
        canvas_digest: inspection.proposal.canvas_digest.clone(),
        code_confirmation_digest: inspection.proposal.code_confirmation_digest.clone(),
        chain_scope: inspection.proposal.chain_scope,
        review_digest: inspection.review.review_digest,
        signing_message_digest: inspection.review.signing_message_digest,
        session_id: request.session_id,
        profile_id: request.profile.profile_id,
        expires_at: expires_seconds,
        created_at: request.now,
        status: CovhubIntentStatus::Pending,
    })
}

/// Parse an RFC 3339 timestamp to Unix seconds. Accepts `YYYY-MM-DDTHH:MM:SS`,
/// optional fractional seconds, and `Z` or `±HH:MM` timezone offsets.
///
/// This function is total: short, truncated, or malformed inputs return
/// `Err(CovhubError::InvalidTimestamp)` and never panic.
pub fn parse_rfc3339_seconds(input: &str) -> Result<i64, CovhubError> {
    let bytes = input.as_bytes();
    let invalid = || CovhubError::InvalidTimestamp(input.to_owned());
    let four = |range: std::ops::Range<usize>| {
        parse_four_digits(
            bytes
                .get(range)
                .ok_or_else(invalid)?
                .try_into()
                .ok()
                .ok_or_else(invalid)?,
        )
        .ok_or_else(invalid)
    };
    let two = |range: std::ops::Range<usize>| {
        parse_two_digits(
            bytes
                .get(range)
                .ok_or_else(invalid)?
                .try_into()
                .ok()
                .ok_or_else(invalid)?,
        )
        .ok_or_else(invalid)
    };

    let year = four(0..4)?;
    if bytes.get(4) != Some(&b'-') {
        return Err(invalid());
    }
    let month = two(5..7)?;
    if bytes.get(7) != Some(&b'-') {
        return Err(invalid());
    }
    let day = two(8..10)?;
    if !matches!(bytes.get(10), Some(&b'T') | Some(&b't')) {
        return Err(invalid());
    }
    let hour = two(11..13)?;
    if bytes.get(13) != Some(&b':') {
        return Err(invalid());
    }
    let minute = two(14..16)?;
    if bytes.get(16) != Some(&b':') {
        return Err(invalid());
    }
    let second = two(17..19)?;

    if !(1..=12).contains(&month)
        || !(1..=days_in_month(year, month)).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(invalid());
    }

    let mut index = 19usize;
    if matches!(bytes.get(index), Some(&b'.') | Some(&b',')) {
        index += 1;
        let start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        if index == start {
            return Err(invalid());
        }
        let fraction = &input[start..index];
        let mut nanos: u32 = fraction
            .parse()
            .map_err(|_| CovhubError::InvalidTimestamp(input.to_owned()))?;
        for _ in fraction.len()..9 {
            nanos *= 10;
        }
        if nanos > 999_999_999 {
            return Err(invalid());
        }
    }

    let mut offset_seconds = 0i64;
    match bytes.get(index) {
        Some(&b'Z') | Some(&b'z') => {
            index += 1;
        }
        Some(&b'+') | Some(&b'-') => {
            let sign = if bytes[index] == b'-' { -1 } else { 1 };
            let offset_hour = parse_two_digits(
                &bytes
                    .get(index + 1..index + 3)
                    .ok_or_else(invalid)?
                    .try_into()
                    .ok()
                    .ok_or_else(invalid)?,
            )
            .ok_or_else(invalid)?;
            if bytes.get(index + 3) != Some(&b':') {
                return Err(invalid());
            }
            let offset_minute = parse_two_digits(
                &bytes
                    .get(index + 4..index + 6)
                    .ok_or_else(invalid)?
                    .try_into()
                    .ok()
                    .ok_or_else(invalid)?,
            )
            .ok_or_else(invalid)?;
            if offset_hour > 23 || offset_minute > 59 {
                return Err(invalid());
            }
            offset_seconds = sign * (i64::from(offset_hour) * 3600 + i64::from(offset_minute) * 60);
            index += 6;
        }
        _ => return Err(invalid()),
    }
    if index != bytes.len() {
        return Err(invalid());
    }

    let days = days_from_civil(i64::from(year), i64::from(month), i64::from(day));
    let seconds =
        days * 86_400 + i64::from(hour) * 3_600 + i64::from(minute) * 60 + i64::from(second)
            - offset_seconds;
    Ok(seconds)
}

fn parse_four_digits(bytes: &[u8; 4]) -> Option<i64> {
    if bytes.iter().all(|byte| byte.is_ascii_digit()) {
        Some(
            i64::from(bytes[0] - b'0') * 1000
                + i64::from(bytes[1] - b'0') * 100
                + i64::from(bytes[2] - b'0') * 10
                + i64::from(bytes[3] - b'0'),
        )
    } else {
        None
    }
}

fn parse_two_digits(bytes: &[u8; 2]) -> Option<u16> {
    if bytes.iter().all(|byte| byte.is_ascii_digit()) {
        Some(u16::from(bytes[0] - b'0') * 10 + u16::from(bytes[1] - b'0'))
    } else {
        None
    }
}

fn days_in_month(year: i64, month: u16) -> u16 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31u16,
        4 | 6 | 9 | 11 => 30u16,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Days from civil epoch (1970-01-01). Howard Hinnant's `days_from_civil`.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Helper used by tests and fixtures to build a proposal JSON with a valid
/// canonical `content_digest`.
#[cfg(test)]
pub(crate) fn with_content_digest(mut value: Value) -> Value {
    use serde_json::json;
    let digest =
        crate::covhub::compute_content_digest(&serde_json::to_string(&value).unwrap()).unwrap();
    if let Some(object) = value.as_object_mut() {
        object.insert("content_digest".to_owned(), json!(digest));
    }
    value
}

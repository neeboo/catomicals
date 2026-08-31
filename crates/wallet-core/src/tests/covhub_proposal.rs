//! CovHub wallet-proposal bridge tests.
//!
//! Covers strict `covhub.wallet-proposal/v1` parsing, RFC 8785 canonical
//! digests, independent local chain-suite review (including a real Kaspa
//! Testnet11 fixture), expiry/readiness/size rejection, one-byte mutation
//! rejection, and a chain-neutral Passkey-gated pending intent.

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use catomicals_chain_domain::{
    BitcoinNetwork, ChainCapabilities, ChainNetwork, ChainScope, ChainSuite, KaspaNetwork,
    ReviewArtifact, ReviewContractError,
};
use catomicals_signing_domain::{SignerBackendRequirement, SigningSuiteId};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::AddressBinding;
use crate::api::WalletApi;
use crate::covhub::{
    COVHUB_SIGNING_INTENT_VERSION, COVHUB_WALLET_PROPOSAL_SCHEMA, CovhubBinding, CovhubError,
    CovhubIntentStatus, CovhubPendingIntentRequest, CovhubReadinessStatus, CovhubSigningIntent,
    CovhubWalletProposal, create_covhub_signing_intent, inspect_covhub_wallet_proposal,
    parse_rfc3339_seconds, verify_content_digest, with_content_digest,
};
use crate::intent::{IntentStatus, SigningIntent};
use crate::signing_job::SignerProfile;
use crate::store::{
    ApprovalStartState, AuthorizationState, FrostNonceClaimState, InMemoryWalletStore,
    PasskeyState, StorageDescriptor, WalletStore, WalletStoreError, WebauthnProfileState,
};

const NOW: i64 = 1_788_220_000; // 2026-09-01T01:46:40Z
const FUTURE_EXPIRES: &str = "2026-09-01T02:00:00.000Z"; // 1788228000
const PAST_EXPIRES: &str = "2025-06-15T00:00:00Z"; // 1749945600

fn scope_signet() -> ChainScope {
    ChainScope::for_network(ChainNetwork::Bitcoin(BitcoinNetwork::Signet))
}

fn scope_kaspa_testnet11() -> ChainScope {
    ChainScope::for_network(ChainNetwork::Kaspa(KaspaNetwork::Testnet11))
}

#[cfg(feature = "seven-chain-addresses")]
fn scope_kaspa_testnet10() -> ChainScope {
    ChainScope::for_network(ChainNetwork::Kaspa(KaspaNetwork::Testnet10))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

/// Deterministic test-only chain suite: review digests are derived from the
/// complete decoded material, so any material mutation changes the review.
#[derive(Debug, Clone)]
struct Sha256Suite {
    scope: ChainScope,
}

impl catomicals_chain_domain::ChainSuite for Sha256Suite {
    fn scope(&self) -> ChainScope {
        self.scope
    }

    fn capabilities(&self) -> ChainCapabilities {
        ChainCapabilities {
            address_derivation: true,
            transaction_review: true,
            final_signature_verification: true,
            broadcast: false,
        }
    }

    fn review_transaction(&self, material: &[u8]) -> Result<ReviewArtifact, ReviewContractError> {
        let mut review_input = Vec::with_capacity(material.len() + 32);
        review_input.extend_from_slice(b"catomicals.test.sha256\0");
        review_input.extend_from_slice(material);
        let review_digest = Sha256::digest(&review_input).into();
        let mut message_input = Vec::with_capacity(material.len() + 32);
        message_input.extend_from_slice(b"catomicals.test.msg\0");
        message_input.extend_from_slice(material);
        let signing_message_digest = Sha256::digest(&message_input).into();
        ReviewArtifact::new(
            self.scope,
            review_digest,
            signing_message_digest,
            format!("sha256 review of {} bytes", material.len()),
            material.to_vec(),
        )
    }

    fn verify_finalized_signature(
        &self,
        _review: &ReviewArtifact,
        _finalized_signature: &[u8],
    ) -> Result<(), ReviewContractError> {
        Ok(())
    }
}

/// Test-only suite whose review always fails.
#[derive(Debug, Clone)]
struct FailingSuite {
    scope: ChainScope,
}

impl catomicals_chain_domain::ChainSuite for FailingSuite {
    fn scope(&self) -> ChainScope {
        self.scope
    }

    fn capabilities(&self) -> ChainCapabilities {
        ChainCapabilities {
            address_derivation: false,
            transaction_review: true,
            final_signature_verification: false,
            broadcast: false,
        }
    }

    fn review_transaction(&self, _material: &[u8]) -> Result<ReviewArtifact, ReviewContractError> {
        Err(ReviewContractError::UnsupportedOperation {
            operation: "test failure",
        })
    }

    fn verify_finalized_signature(
        &self,
        _review: &ReviewArtifact,
        _finalized_signature: &[u8],
    ) -> Result<(), ReviewContractError> {
        Ok(())
    }
}

fn build_proposal(
    material: &[u8],
    scope: ChainScope,
    expires_at: &str,
    readiness_status: &str,
    blockers: Vec<String>,
) -> Value {
    let value = json!({
        "schema": "covhub.wallet-proposal/v1",
        "proposal_id": format!("proposal:test-{}", &hex::encode(Sha256::digest(material))[..16]),
        "canvas_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "code_confirmation_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "chain_scope": {
            "schema_version": 1,
            "chain": scope.chain.as_str(),
            "network": scope.network.as_str(),
        },
        "transaction": {
            "encoding": "base64",
            "media_type": "application/vnd.kaspa.transaction-review+binary",
            "material_base64": b64(material),
            "sha256": sha256_hex(material),
        },
        "summary": "Unsigned transaction material for independent wallet review.",
        "created_at": "2026-09-01T00:00:00.000Z",
        "expires_at": expires_at,
        "readiness": { "status": readiness_status, "blockers": blockers },
    });
    with_content_digest(value)
}

fn profile(
    scope: ChainScope,
    suite_id: SigningSuiteId,
    backend: SignerBackendRequirement,
    verification_key: Vec<u8>,
) -> SignerProfile {
    SignerProfile::new(
        Uuid::from_bytes([0x51; 16]),
        Uuid::from_bytes([0x52; 16]),
        scope,
        suite_id,
        backend,
        "signer-set-1".to_owned(),
        "signer-1".to_owned(),
        1,
        2,
        3,
        verification_key,
        "opaque-handle-placeholder".to_owned(),
    )
    .unwrap()
}

fn signet_profile() -> SignerProfile {
    profile(
        scope_signet(),
        SigningSuiteId::BITCOIN_BIP340_FROST_V1,
        SignerBackendRequirement::FrostSecp256k1Tr,
        vec![7u8; 33],
    )
}

#[test]
fn parses_ready_proposal_verifies_digest_and_reproduces_review() {
    let scope = scope_signet();
    let material = b"unsigned taproot transaction material";
    let raw = serde_json::to_string(&build_proposal(
        material,
        scope,
        FUTURE_EXPIRES,
        "ready_for_wallet_review",
        vec![],
    ))
    .unwrap();
    let suite = Sha256Suite { scope };

    let inspection = inspect_covhub_wallet_proposal(&raw, &suite, NOW).unwrap();

    assert_eq!(inspection.proposal.schema, COVHUB_WALLET_PROPOSAL_SCHEMA);
    assert_eq!(inspection.decoded_material_size, material.len());
    assert!(!inspection.is_expired);
    assert!(inspection.eligible);
    assert_eq!(inspection.review.scope, scope);
    // The wallet independently reproduces the review over the decoded bytes.
    let fresh = suite.review_transaction(material).unwrap();
    assert_eq!(inspection.review, fresh);
    // The signing-message digest is locally derived, never proposal-supplied.
    assert_eq!(
        inspection.review.signing_message_digest,
        fresh.signing_message_digest
    );
}

#[test]
fn rejects_unknown_fields() {
    let mut value = build_proposal(
        b"x",
        scope_signet(),
        FUTURE_EXPIRES,
        "ready_for_wallet_review",
        vec![],
    );
    value
        .as_object_mut()
        .unwrap()
        .insert("mystery_field".to_owned(), json!(1));
    let raw = serde_json::to_string(&value).unwrap();
    let error = inspect_covhub_wallet_proposal(
        &raw,
        &Sha256Suite {
            scope: scope_signet(),
        },
        NOW,
    )
    .unwrap_err();
    assert!(matches!(error, CovhubError::StrictParse(_)));
}

#[test]
fn rejects_malformed_base64() {
    let mut value = build_proposal(
        b"x",
        scope_signet(),
        FUTURE_EXPIRES,
        "ready_for_wallet_review",
        vec![],
    );
    value["transaction"]["material_base64"] = json!("@@not-base64@@");
    let value = with_content_digest(value);
    let raw = serde_json::to_string(&value).unwrap();
    let error = inspect_covhub_wallet_proposal(
        &raw,
        &Sha256Suite {
            scope: scope_signet(),
        },
        NOW,
    )
    .unwrap_err();
    assert!(matches!(error, CovhubError::InvalidBase64));
}

#[test]
fn rejects_decoded_material_over_one_million_bytes() {
    let material = vec![0xabu8; 1_000_001];
    let value = build_proposal(
        &material,
        scope_signet(),
        FUTURE_EXPIRES,
        "ready_for_wallet_review",
        vec![],
    );
    let raw = serde_json::to_string(&value).unwrap();
    let error = inspect_covhub_wallet_proposal(
        &raw,
        &Sha256Suite {
            scope: scope_signet(),
        },
        NOW,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        CovhubError::MaterialTooLarge {
            actual_bytes: 1_000_001,
            max_bytes: 1_000_000
        }
    ));
}

#[test]
fn rejects_canonical_digest_mismatch_after_mutation() {
    let mut value = build_proposal(
        b"x",
        scope_signet(),
        FUTURE_EXPIRES,
        "ready_for_wallet_review",
        vec![],
    );
    value["summary"] = json!("tampered summary that changes the canonical digest");
    // Deliberately do NOT recompute content_digest.
    let raw = serde_json::to_string(&value).unwrap();
    let error = inspect_covhub_wallet_proposal(
        &raw,
        &Sha256Suite {
            scope: scope_signet(),
        },
        NOW,
    )
    .unwrap_err();
    assert!(matches!(error, CovhubError::ContentDigestMismatch { .. }));
}

#[test]
fn rejects_transaction_sha256_mismatch() {
    let mut value = build_proposal(
        b"x",
        scope_signet(),
        FUTURE_EXPIRES,
        "ready_for_wallet_review",
        vec![],
    );
    value["transaction"]["sha256"] =
        json!("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    let value = with_content_digest(value); // digest consistent; only tx hash is wrong
    let raw = serde_json::to_string(&value).unwrap();
    let error = inspect_covhub_wallet_proposal(
        &raw,
        &Sha256Suite {
            scope: scope_signet(),
        },
        NOW,
    )
    .unwrap_err();
    assert!(matches!(error, CovhubError::TransactionHashMismatch { .. }));
}

#[test]
fn rejects_one_byte_transaction_mutation() {
    let mut value = build_proposal(
        b"covhub-golden-transaction-material",
        scope_signet(),
        FUTURE_EXPIRES,
        "ready_for_wallet_review",
        vec![],
    );
    // Flip one character of the base64 material without updating any digest.
    let encoded = value["transaction"]["material_base64"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut bytes: Vec<u8> = encoded.into_bytes();
    let index = bytes.len() / 2;
    bytes[index] = if bytes[index] == b'A' { b'B' } else { b'A' };
    value["transaction"]["material_base64"] = json!(String::from_utf8(bytes).unwrap());
    let raw = serde_json::to_string(&value).unwrap();
    let error = inspect_covhub_wallet_proposal(
        &raw,
        &Sha256Suite {
            scope: scope_signet(),
        },
        NOW,
    )
    .unwrap_err();
    assert!(matches!(error, CovhubError::ContentDigestMismatch { .. }));
}

#[test]
fn inspection_reports_analysis_only_as_ineligible_but_still_reviews() {
    let value = build_proposal(
        b"x",
        scope_signet(),
        FUTURE_EXPIRES,
        "analysis_only",
        vec!["missing artifact".to_owned()],
    );
    let raw = serde_json::to_string(&value).unwrap();
    let suite = Sha256Suite {
        scope: scope_signet(),
    };
    let inspection = inspect_covhub_wallet_proposal(&raw, &suite, NOW).unwrap();
    assert_eq!(
        inspection.proposal.readiness.status,
        CovhubReadinessStatus::AnalysisOnly
    );
    assert!(!inspection.eligible);
    assert_eq!(
        inspection.review.review_digest,
        suite.review_transaction(b"x").unwrap().review_digest
    );
}

#[test]
fn inspection_reports_expiry_but_still_reviews() {
    let value = build_proposal(
        b"x",
        scope_signet(),
        PAST_EXPIRES,
        "ready_for_wallet_review",
        vec![],
    );
    let raw = serde_json::to_string(&value).unwrap();
    let suite = Sha256Suite {
        scope: scope_signet(),
    };
    let inspection = inspect_covhub_wallet_proposal(&raw, &suite, NOW).unwrap();
    assert!(inspection.is_expired);
    assert!(!inspection.eligible);
    assert_eq!(
        inspection.review.review_digest,
        suite.review_transaction(b"x").unwrap().review_digest
    );
}

#[test]
fn rejects_unsupported_scope() {
    let value = build_proposal(
        b"x",
        scope_kaspa_testnet11(),
        FUTURE_EXPIRES,
        "ready_for_wallet_review",
        vec![],
    );
    let raw = serde_json::to_string(&value).unwrap();
    // Local suite only supports Bitcoin Signet.
    let error = inspect_covhub_wallet_proposal(
        &raw,
        &Sha256Suite {
            scope: scope_signet(),
        },
        NOW,
    )
    .unwrap_err();
    assert!(matches!(error, CovhubError::UnsupportedScope { .. }));
}

#[test]
fn rejects_scope_with_unsupported_network_name() {
    let mut value = build_proposal(
        b"x",
        scope_kaspa_testnet11(),
        FUTURE_EXPIRES,
        "ready_for_wallet_review",
        vec![],
    );
    value["chain_scope"]["network"] = json!("kaspa.testnet-99");
    let value = with_content_digest(value);
    let raw = serde_json::to_string(&value).unwrap();
    let error = inspect_covhub_wallet_proposal(
        &raw,
        &Sha256Suite {
            scope: scope_signet(),
        },
        NOW,
    )
    .unwrap_err();
    // ChainScope parsing fails inside strict parse.
    assert!(matches!(error, CovhubError::StrictParse(_)));
}

#[test]
fn rejects_wrong_schema() {
    let mut value = build_proposal(
        b"x",
        scope_signet(),
        FUTURE_EXPIRES,
        "ready_for_wallet_review",
        vec![],
    );
    value["schema"] = json!("covhub.wallet-proposal/v2");
    let value = with_content_digest(value);
    let raw = serde_json::to_string(&value).unwrap();
    let error = inspect_covhub_wallet_proposal(
        &raw,
        &Sha256Suite {
            scope: scope_signet(),
        },
        NOW,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        CovhubError::UnsupportedSchema { ref actual } if actual == "covhub.wallet-proposal/v2"
    ));
}

#[test]
fn rejects_analysis_only_readiness_without_blocker() {
    let value = build_proposal(
        b"x",
        scope_signet(),
        FUTURE_EXPIRES,
        "analysis_only",
        vec![],
    );
    let raw = serde_json::to_string(&value).unwrap();
    let error = inspect_covhub_wallet_proposal(
        &raw,
        &Sha256Suite {
            scope: scope_signet(),
        },
        NOW,
    )
    .unwrap_err();
    assert!(matches!(error, CovhubError::AnalysisOnlyWithoutBlocker));
}

#[test]
fn rejects_ready_readiness_with_blockers() {
    let value = build_proposal(
        b"x",
        scope_signet(),
        FUTURE_EXPIRES,
        "ready_for_wallet_review",
        vec!["unexpected".to_owned()],
    );
    let raw = serde_json::to_string(&value).unwrap();
    let error = inspect_covhub_wallet_proposal(
        &raw,
        &Sha256Suite {
            scope: scope_signet(),
        },
        NOW,
    )
    .unwrap_err();
    assert!(matches!(error, CovhubError::ReadyWithBlocker));
}

// ---------------------------------------------------------------------------
// Pending intent binding
// ---------------------------------------------------------------------------

fn pending_intent_request<'a>(
    raw: &'a str,
    suite: &'a dyn catomicals_chain_domain::ChainSuite,
    profile: &'a SignerProfile,
) -> CovhubPendingIntentRequest<'a> {
    CovhubPendingIntentRequest {
        raw_proposal: raw,
        suite,
        profile,
        session_id: [0x33; 32],
        now: NOW,
        intent_id: Some(Uuid::from_bytes([0x44; 16])),
    }
}

#[test]
fn creates_pending_intent_bound_to_scope_review_session_expiry_and_profile() {
    let scope = scope_signet();
    let material = b"unsigned taproot transaction material";
    let raw = serde_json::to_string(&build_proposal(
        material,
        scope,
        FUTURE_EXPIRES,
        "ready_for_wallet_review",
        vec![],
    ))
    .unwrap();
    let suite = Sha256Suite { scope };
    let profile = signet_profile();

    let intent =
        create_covhub_signing_intent(pending_intent_request(&raw, &suite, &profile)).unwrap();

    assert_eq!(intent.version, COVHUB_SIGNING_INTENT_VERSION);
    assert_eq!(intent.status, CovhubIntentStatus::Pending);
    assert_eq!(intent.chain_scope, scope);
    assert_eq!(intent.intent_id, Uuid::from_bytes([0x44; 16]));
    assert_eq!(intent.profile_id, profile.profile_id);
    assert_eq!(intent.session_id, [0x33; 32]);
    assert_eq!(intent.expires_at, 1_788_228_000);
    assert_eq!(intent.created_at, NOW);
    // Bound to the wallet-derived review, never to a proposal-supplied digest.
    let review = suite.review_transaction(material).unwrap();
    assert_eq!(intent.review_digest, review.review_digest);
    assert_eq!(intent.signing_message_digest, review.signing_message_digest);
    assert!(intent.requires_passkey_approval());
}

#[test]
fn pending_intent_digest_binds_every_immutable_field() {
    let scope = scope_signet();
    let material = b"unsigned taproot transaction material";
    let raw = serde_json::to_string(&build_proposal(
        material,
        scope,
        FUTURE_EXPIRES,
        "ready_for_wallet_review",
        vec![],
    ))
    .unwrap();
    let suite = Sha256Suite { scope };
    let profile = signet_profile();
    let base =
        create_covhub_signing_intent(pending_intent_request(&raw, &suite, &profile)).unwrap();
    let digest = base.digest();

    let mut changed = base.clone();
    changed.review_digest[0] ^= 1;
    assert_ne!(changed.digest(), digest);
    let mut changed = base.clone();
    changed.signing_message_digest[0] ^= 1;
    assert_ne!(changed.digest(), digest);
    let mut changed = base.clone();
    changed.session_id[0] ^= 1;
    assert_ne!(changed.digest(), digest);
    let mut changed = base.clone();
    changed.expires_at += 1;
    assert_ne!(changed.digest(), digest);
    let mut changed = base.clone();
    changed.profile_id = Uuid::from_bytes([0x55; 16]);
    assert_ne!(changed.digest(), digest);
    let mut changed = base.clone();
    changed.chain_scope = scope_kaspa_testnet11();
    assert_ne!(changed.digest(), digest);
    let mut changed = base.clone();
    changed.proposal_digest =
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned();
    assert_ne!(changed.digest(), digest);
    // Lifecycle metadata is intentionally not part of the approval digest.
    let mut approved = base.clone();
    approved.status = CovhubIntentStatus::Approved;
    assert_eq!(approved.digest(), digest);
}

#[test]
fn no_intent_for_analysis_only_proposal() {
    let value = build_proposal(
        b"x",
        scope_signet(),
        FUTURE_EXPIRES,
        "analysis_only",
        vec!["missing artifact".to_owned()],
    );
    let raw = serde_json::to_string(&value).unwrap();
    let error = create_covhub_signing_intent(pending_intent_request(
        &raw,
        &Sha256Suite {
            scope: scope_signet(),
        },
        &signet_profile(),
    ))
    .unwrap_err();
    assert!(matches!(error, CovhubError::AnalysisOnly));
}

#[test]
fn no_intent_for_expired_proposal() {
    let value = build_proposal(
        b"x",
        scope_signet(),
        PAST_EXPIRES,
        "ready_for_wallet_review",
        vec![],
    );
    let raw = serde_json::to_string(&value).unwrap();
    let error = create_covhub_signing_intent(pending_intent_request(
        &raw,
        &Sha256Suite {
            scope: scope_signet(),
        },
        &signet_profile(),
    ))
    .unwrap_err();
    assert!(matches!(error, CovhubError::ExpiredProposal { .. }));
}

#[test]
fn no_intent_for_profile_scope_drift() {
    let value = build_proposal(
        b"x",
        scope_kaspa_testnet11(),
        FUTURE_EXPIRES,
        "ready_for_wallet_review",
        vec![],
    );
    let raw = serde_json::to_string(&value).unwrap();
    // Suite matches the proposal but the profile is bound to Bitcoin Signet.
    let error = create_covhub_signing_intent(pending_intent_request(
        &raw,
        &Sha256Suite {
            scope: scope_kaspa_testnet11(),
        },
        &signet_profile(),
    ))
    .unwrap_err();
    assert!(matches!(error, CovhubError::ProfileScopeMismatch { .. }));
}

#[test]
fn no_intent_for_digest_mismatch() {
    let mut value = build_proposal(
        b"x",
        scope_signet(),
        FUTURE_EXPIRES,
        "ready_for_wallet_review",
        vec![],
    );
    value["summary"] = json!("tampered");
    let raw = serde_json::to_string(&value).unwrap();
    let error = create_covhub_signing_intent(pending_intent_request(
        &raw,
        &Sha256Suite {
            scope: scope_signet(),
        },
        &signet_profile(),
    ))
    .unwrap_err();
    assert!(matches!(error, CovhubError::ContentDigestMismatch { .. }));
}

#[test]
fn no_intent_when_review_cannot_be_reproduced() {
    let value = build_proposal(
        b"x",
        scope_signet(),
        FUTURE_EXPIRES,
        "ready_for_wallet_review",
        vec![],
    );
    let raw = serde_json::to_string(&value).unwrap();
    let error = create_covhub_signing_intent(pending_intent_request(
        &raw,
        &FailingSuite {
            scope: scope_signet(),
        },
        &signet_profile(),
    ))
    .unwrap_err();
    assert!(matches!(error, CovhubError::ReviewFailed(_)));
}

// ---------------------------------------------------------------------------
// Cross-repository golden fixtures
// ---------------------------------------------------------------------------

#[test]
fn cross_repo_wallet_proposal_fixture_digest_is_reproduced() {
    let fixture = include_str!("fixtures/covhub-wallet-proposal-v1.json");
    let computed = verify_content_digest(fixture).unwrap();
    let proposal = crate::covhub::CovhubWalletProposal::parse(fixture).unwrap();
    assert_eq!(proposal.content_digest, computed);
    assert_eq!(
        proposal.content_digest,
        "sha256:4de3cf2c70f22601d0399b50c7b82f128525099c9886f76989df07f3084d9ec5"
    );
    assert_eq!(
        proposal.canvas_digest,
        "sha256:d70b55dd2d76d51b834c73c3709efa1cc4b35f323c1057867fce33ce0495bdcc"
    );
    assert_eq!(
        proposal.code_confirmation_digest,
        "sha256:734f728ea975f45be8468598701223ec74793d3603a7440065abe6641a4b9025"
    );
    assert_eq!(
        proposal.transaction.sha256,
        "sha256:0d4444ffd470eef55102e241053784edab89cc82a18883085a139540395486da"
    );
    assert_eq!(proposal.chain_scope.chain.as_str(), "kaspa");
    assert_eq!(proposal.chain_scope.network.as_str(), "kaspa.testnet11");
}

#[test]
fn cross_repo_canvas_and_confirmation_digests_are_reproduced() {
    let canvas = include_str!("fixtures/covhub-canvas-v1.json");
    let mut value: Value = serde_json::from_str(canvas).unwrap();
    value.as_object_mut().unwrap().remove("semantic_digest");
    let canonical = serde_jcs::to_string(&value).unwrap();
    let computed = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(canonical.as_bytes()))
    );
    assert_eq!(
        computed,
        "sha256:d70b55dd2d76d51b834c73c3709efa1cc4b35f323c1057867fce33ce0495bdcc"
    );

    let confirmation = include_str!("fixtures/covhub-code-confirmation-v1.json");
    let mut value: Value = serde_json::from_str(confirmation).unwrap();
    value.as_object_mut().unwrap().remove("content_digest");
    let canonical = serde_jcs::to_string(&value).unwrap();
    let computed = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(canonical.as_bytes()))
    );
    assert_eq!(
        computed,
        "sha256:734f728ea975f45be8468598701223ec74793d3603a7440065abe6641a4b9025"
    );
}

// ---------------------------------------------------------------------------
// Real Kaspa Testnet11 chain-suite review (requires seven-chain-addresses)
// ---------------------------------------------------------------------------

#[cfg(feature = "seven-chain-addresses")]
fn kaspa_group_key() -> Vec<u8> {
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
    let secret = SecretKey::from_slice(&[7u8; 32]).unwrap();
    PublicKey::from_secret_key(&Secp256k1::new(), &secret)
        .serialize()
        .to_vec()
}

#[cfg(feature = "seven-chain-addresses")]
fn kaspa_review_material(network: KaspaNetwork) -> Vec<u8> {
    use catomicals_chain_kaspa::{KaspaReviewMaterial, KaspaVerifier};
    use kaspa_addresses::{Address, Prefix, Version};
    use kaspa_consensus_core::{
        hashing::sighash_type::SIG_HASH_ALL,
        subnets::SUBNETWORK_ID_NATIVE,
        tx::{Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry},
    };
    use kaspa_hashes::Hash;
    use kaspa_txscript::pay_to_address_script;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    let group_key: [u8; 33] = kaspa_group_key().try_into().unwrap();
    let input_script = pay_to_address_script(&Address::new(
        Prefix::Testnet,
        Version::PubKeyECDSA,
        &group_key,
    ));
    let output_secret = SecretKey::from_slice(&[9u8; 32]).unwrap();
    let output_key = PublicKey::from_secret_key(&Secp256k1::new(), &output_secret).serialize();
    let output_script = pay_to_address_script(&Address::new(
        Prefix::Testnet,
        Version::PubKeyECDSA,
        &output_key,
    ));
    let transaction = Transaction::new(
        0,
        vec![TransactionInput::new(
            TransactionOutpoint::new(Hash::from_bytes([0x11; 32]), 7),
            vec![],
            1,
            1,
        )],
        vec![TransactionOutput::new(900, output_script)],
        42,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    KaspaReviewMaterial::new(
        network,
        transaction,
        vec![UtxoEntry::new(1_000, input_script, 8, false, None)],
        0,
        SIG_HASH_ALL,
    )
    .unwrap()
    .encode()
    .unwrap()
}

#[cfg(feature = "seven-chain-addresses")]
fn kaspa_profile(network: KaspaNetwork) -> SignerProfile {
    profile(
        ChainScope::for_network(ChainNetwork::Kaspa(network)),
        SigningSuiteId::KASPA_ECDSA_CB_MPC_V1,
        SignerBackendRequirement::CbMpcThresholdEcdsa,
        kaspa_group_key(),
    )
}

#[cfg(feature = "seven-chain-addresses")]
#[test]
fn kaspa_testnet11_review_uses_the_real_chain_suite() {
    use catomicals_chain_kaspa::{KaspaChainSuite, KaspaVerifier};

    let network = KaspaNetwork::Testnet11;
    let scope = scope_kaspa_testnet11();
    let material = kaspa_review_material(network);
    let suite = KaspaChainSuite::new(
        network,
        KaspaVerifier::EcdsaCbMpc(kaspa_group_key().try_into().unwrap()),
    )
    .unwrap();
    let raw = serde_json::to_string(&build_proposal(
        &material,
        scope,
        FUTURE_EXPIRES,
        "ready_for_wallet_review",
        vec![],
    ))
    .unwrap();

    let inspection = inspect_covhub_wallet_proposal(&raw, &suite, NOW).unwrap();
    assert_eq!(inspection.review.scope, scope);
    assert!(inspection.review.summary.contains("Testnet11"));
    // Reproduced locally over the complete decoded material.
    let fresh = suite.review_transaction(&material).unwrap();
    assert_eq!(inspection.review, fresh);
    assert_eq!(
        inspection.review.signing_message_digest,
        fresh.signing_message_digest
    );
    assert!(inspection.eligible);
}

#[cfg(feature = "seven-chain-addresses")]
#[test]
fn kaspa_testnet11_proposal_is_not_reviewed_as_bitcoin_signet() {
    use catomicals_chain_kaspa::{KaspaChainSuite, KaspaVerifier};

    let network = KaspaNetwork::Testnet11;
    let material = kaspa_review_material(network);
    let suite = KaspaChainSuite::new(
        network,
        KaspaVerifier::EcdsaCbMpc(kaspa_group_key().try_into().unwrap()),
    )
    .unwrap();
    // Proposal claims Testnet10 while the local suite is Testnet11.
    let raw = serde_json::to_string(&build_proposal(
        &material,
        scope_kaspa_testnet10(),
        FUTURE_EXPIRES,
        "ready_for_wallet_review",
        vec![],
    ))
    .unwrap();
    let error = inspect_covhub_wallet_proposal(&raw, &suite, NOW).unwrap_err();
    assert!(matches!(error, CovhubError::UnsupportedScope { .. }));
}

#[cfg(feature = "seven-chain-addresses")]
#[test]
fn kaspa_testnet11_pending_intent_binds_kaspa_scope_never_signet() {
    use catomicals_chain_kaspa::{KaspaChainSuite, KaspaVerifier};

    let network = KaspaNetwork::Testnet11;
    let scope = scope_kaspa_testnet11();
    let material = kaspa_review_material(network);
    let suite = KaspaChainSuite::new(
        network,
        KaspaVerifier::EcdsaCbMpc(kaspa_group_key().try_into().unwrap()),
    )
    .unwrap();
    let profile = kaspa_profile(network);
    let raw = serde_json::to_string(&build_proposal(
        &material,
        scope,
        FUTURE_EXPIRES,
        "ready_for_wallet_review",
        vec![],
    ))
    .unwrap();

    let intent =
        create_covhub_signing_intent(pending_intent_request(&raw, &suite, &profile)).unwrap();
    assert_eq!(intent.chain_scope.chain.as_str(), "kaspa");
    assert_eq!(intent.chain_scope.network.as_str(), "kaspa.testnet11");
    assert_eq!(intent.status, CovhubIntentStatus::Pending);
    assert!(intent.requires_passkey_approval());
    // The canonical intent binding never names Bitcoin Signet.
    let bytes = intent.canonical_bytes();
    assert!(!bytes.windows(6).any(|window| window == b"signet"));
    let review = suite.review_transaction(&material).unwrap();
    assert_eq!(intent.review_digest, review.review_digest);
    assert_eq!(intent.signing_message_digest, review.signing_message_digest);
}

// ---------------------------------------------------------------------
// Durable persistence through the existing wallet intent store
// ---------------------------------------------------------------------

/// In-memory store wrapper that reports one signer profile so the wallet can
/// persist a CovHub pending intent through `WalletApi`.
#[derive(Debug, Default)]
struct ProfileStore {
    inner: InMemoryWalletStore,
    profile: Option<SignerProfile>,
}

impl ProfileStore {
    fn new(profile: SignerProfile) -> Self {
        Self {
            inner: InMemoryWalletStore::new(),
            profile: Some(profile),
        }
    }
}

impl WalletStore for ProfileStore {
    fn descriptor(&self) -> StorageDescriptor {
        self.inner.descriptor()
    }
    fn wallet_id(&self) -> Option<Uuid> {
        self.profile.as_ref().map(|profile| profile.wallet_id)
    }
    fn insert_intent(&mut self, intent: SigningIntent) -> Result<(), WalletStoreError> {
        self.inner.insert_intent(intent)
    }
    fn get_intent(&self, id: &Uuid) -> Option<SigningIntent> {
        self.inner.get_intent(id)
    }
    fn list_intents(&self) -> Vec<SigningIntent> {
        self.inner.list_intents()
    }
    fn update_intent(&mut self, intent: SigningIntent, now: i64) -> Result<(), WalletStoreError> {
        self.inner.update_intent(intent, now)
    }
    fn webauthn_profile(&self) -> Result<Option<WebauthnProfileState>, WalletStoreError> {
        self.inner.webauthn_profile()
    }
    fn set_webauthn_profile(
        &mut self,
        profile: WebauthnProfileState,
    ) -> Result<(), WalletStoreError> {
        self.inner.set_webauthn_profile(profile)
    }
    fn insert_passkey(&mut self, passkey: PasskeyState) -> Result<(), WalletStoreError> {
        self.inner.insert_passkey(passkey)
    }
    fn list_passkeys(&self) -> Result<Vec<PasskeyState>, WalletStoreError> {
        self.inner.list_passkeys()
    }
    fn begin_approval(&mut self, state: ApprovalStartState) -> Result<(), WalletStoreError> {
        self.inner.begin_approval(state)
    }
    fn complete_approval(
        &mut self,
        state: crate::store::ApprovalCompletionState,
    ) -> Result<AuthorizationState, WalletStoreError> {
        self.inner.complete_approval(state)
    }
    fn available_authorizations(
        &self,
        now: i64,
    ) -> Result<Vec<AuthorizationState>, WalletStoreError> {
        self.inner.available_authorizations(now)
    }
    fn claim_frost_nonce(&mut self, claim: FrostNonceClaimState) -> Result<(), WalletStoreError> {
        self.inner.claim_frost_nonce(claim)
    }
    fn signer_profiles(
        &self,
    ) -> Result<Vec<(SignerProfile, Vec<AddressBinding>)>, WalletStoreError> {
        Ok(self
            .profile
            .clone()
            .map(|profile| (profile, Vec::new()))
            .into_iter()
            .collect())
    }
}

/// Build a chain-neutral pending CovHub intent directly (all fields public).
fn pending_covhub_intent(profile: &SignerProfile) -> CovhubSigningIntent {
    CovhubSigningIntent {
        version: COVHUB_SIGNING_INTENT_VERSION,
        intent_id: Uuid::from_bytes([0x71; 16]),
        proposal_id: "proposal:test-persistence".to_owned(),
        proposal_digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            .to_owned(),
        canvas_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_owned(),
        code_confirmation_digest:
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        chain_scope: profile.chain_scope,
        review_digest: [0x81; 32],
        signing_message_digest: [0x82; 32],
        session_id: [0x83; 32],
        profile_id: profile.profile_id,
        expires_at: 1_788_228_000,
        created_at: NOW,
        status: CovhubIntentStatus::Pending,
    }
}

#[test]
fn wallet_api_persists_a_covhub_pending_intent_that_is_listable_readable_and_cancellable() {
    let profile = signet_profile();
    let mut api = WalletApi::with_store(Box::new(ProfileStore::new(profile.clone())));
    let covhub = pending_covhub_intent(&profile);

    let persisted = api.create_covhub_intent(covhub.clone(), NOW).unwrap();
    assert_eq!(persisted.id, covhub.intent_id);
    assert_eq!(persisted.status, IntentStatus::Pending);
    let binding = persisted.covhub.as_ref().unwrap();
    assert_eq!(binding.chain_scope, profile.chain_scope);
    assert_eq!(binding.profile_id, profile.profile_id);
    assert_eq!(binding.proposal_id, "proposal:test-persistence");
    // The durable wallet record stores the signing-message digest in the
    // legacy column while the exact chain-neutral scope lives in the binding.
    assert_eq!(persisted.tx_digest, covhub.signing_message_digest);
    // The Passkey approval challenge is exactly the chain-neutral CovHub
    // intent digest.
    assert_eq!(persisted.digest(), covhub.digest());

    assert_eq!(api.list_intents(), vec![persisted.clone()]);
    assert_eq!(api.read_intent(&covhub.intent_id).unwrap(), persisted);

    let cancelled = api.cancel_intent(&covhub.intent_id, NOW).unwrap();
    assert_eq!(cancelled.status, IntentStatus::Cancelled);
    let after = api.list_intents();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].status, IntentStatus::Cancelled);
    // Cancellation is not approval: no authorization exists.
    assert!(api.available_authorizations(NOW).unwrap().is_empty());
}

#[test]
fn covhub_bound_wallet_intent_digest_is_the_chain_neutral_covhub_digest() {
    let profile = signet_profile();
    let covhub = pending_covhub_intent(&profile);
    let wallet_intent = SigningIntent {
        id: covhub.intent_id,
        network: crate::intent::BitcoinNetwork::CovhubDelegated,
        protocol_version: crate::intent::SIGNING_PROTOCOL_VERSION,
        action: crate::intent::SigningAction::CovhubDelegated,
        wallet_id: profile.wallet_id,
        signer_id: 1,
        personal_signing_policy: None,
        tx_digest: covhub.signing_message_digest,
        session_id: covhub.session_id,
        expiry: covhub.expires_at,
        nonce: [0x99; 32],
        covhub: Some(CovhubBinding::from_covhub_intent(&covhub)),
        status: IntentStatus::Pending,
        created_at: covhub.created_at,
    };
    assert_eq!(wallet_intent.canonical_bytes(), covhub.canonical_bytes());
    assert_eq!(wallet_intent.digest(), covhub.digest());
    let reconstructed = CovhubSigningIntent::from_wallet_intent(&wallet_intent).unwrap();
    assert_eq!(reconstructed, covhub);
}

#[test]
fn covhub_wallet_intent_round_trip_preserves_binding_and_lifecycle() {
    let profile = signet_profile();
    let covhub = pending_covhub_intent(&profile);
    let wallet_intent = SigningIntent {
        id: covhub.intent_id,
        network: crate::intent::BitcoinNetwork::CovhubDelegated,
        protocol_version: crate::intent::SIGNING_PROTOCOL_VERSION,
        action: crate::intent::SigningAction::CovhubDelegated,
        wallet_id: profile.wallet_id,
        signer_id: 1,
        personal_signing_policy: None,
        tx_digest: covhub.signing_message_digest,
        session_id: covhub.session_id,
        expiry: covhub.expires_at,
        nonce: [0x9a; 32],
        covhub: Some(CovhubBinding::from_covhub_intent(&covhub)),
        status: IntentStatus::Cancelled,
        created_at: covhub.created_at,
    };
    // Lifecycle is authoritative on the wallet intent and maps onto the
    // chain-neutral view.
    let back = CovhubSigningIntent::from_wallet_intent(&wallet_intent).unwrap();
    assert_eq!(back.status, CovhubIntentStatus::Cancelled);
    let json = serde_json::to_string(&wallet_intent).unwrap();
    let decoded: SigningIntent = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, wallet_intent);
}

#[test]
fn rfc3339_parsing_is_total_and_panic_free_for_short_or_malformed_inputs() {
    for bad in [
        "",
        "x",
        "2026",
        "2026-09-01",
        "2026-09-01T00:00:00",
        "2026-09-01T00:00:00+",
        "2026-09-01T00:00:00+5",
        "2026-09-01T00:00:00+05",
        "2026-09-01T00:00:00Zextra",
        "999-01-01T00:00:00Z",
        "2026-09-01T25:00:00Z",
        "2026-13-01T00:00:00Z",
        "2026-02-30T00:00:00Z",
    ] {
        assert!(
            parse_rfc3339_seconds(bad).is_err(),
            "{bad:?} must fail closed without panicking"
        );
    }
    assert_eq!(
        parse_rfc3339_seconds("2026-09-01T02:00:00.000Z").unwrap(),
        1_788_228_000
    );
    assert_eq!(
        parse_rfc3339_seconds("2026-09-01T00:00:00-02:00").unwrap(),
        parse_rfc3339_seconds("2026-09-01T02:00:00Z").unwrap()
    );
}

#[test]
fn malformed_created_at_or_expires_at_fails_closed_during_parse() {
    let scope = scope_signet();
    let material = b"unsigned transaction material for timestamp tests";
    for field in ["created_at", "expires_at"] {
        for bad in ["", "x", "2026-09-01T00:00:00", "2026-13-01T00:00:00Z"] {
            let mut proposal = build_proposal(
                material,
                scope,
                FUTURE_EXPIRES,
                "ready_for_wallet_review",
                vec![],
            );
            proposal[field] = json!(bad);
            let raw = serde_json::to_string(&proposal).unwrap();
            let error = CovhubWalletProposal::parse(&raw).unwrap_err();
            assert!(
                matches!(error, CovhubError::InvalidTimestamp(_)),
                "{field} {bad:?} -> {error:?}"
            );
        }
    }
}

use std::time::Duration;

#[cfg(not(feature = "native-cbmpc"))]
use std::sync::Arc;

#[cfg(not(feature = "native-cbmpc"))]
use catomicals_cb_mpc_signer::CbMpcRuntime;
#[cfg(not(feature = "native-cbmpc"))]
use catomicals_cb_mpc_signer::DurableSessionClaimStore;
use catomicals_cb_mpc_signer::{
    ApprovedCbMpcSignRequest, ApprovedCbMpcSignRequestParts, CB_MPC_ECDSA_SIGN_STAGES, CbMpcError,
    CbMpcProfile, CbMpcRuntimeLimits, CbMpcSignerSet, PartyId,
};
use catomicals_chain_domain::{
    BitcoinCashNetwork, BsvNetwork, ChainNetwork, ChainScope, KaspaNetwork, ReviewArtifact,
};
use catomicals_signing_domain::{ReviewBinding, SigningSuiteId};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

const NOW: i64 = 1_800_000_000;

fn group_public_key() -> [u8; 33] {
    PublicKey::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[7; 32]).expect("valid secret key"),
    )
    .serialize()
}

fn parties() -> Vec<PartyId> {
    ["desktop", "mobile-backup", "onepassword"]
        .map(|name| PartyId::new(name).expect("valid party"))
        .to_vec()
}

fn request_for(profile: CbMpcProfile) -> ApprovedCbMpcSignRequest {
    let scope = match profile {
        CbMpcProfile::BitcoinCashEcdsaV1 => {
            ChainScope::for_network(ChainNetwork::BitcoinCash(BitcoinCashNetwork::Mainnet))
        }
        CbMpcProfile::BsvEcdsaV1 => ChainScope::for_network(ChainNetwork::Bsv(BsvNetwork::Mainnet)),
        CbMpcProfile::KaspaEcdsaV1 => {
            ChainScope::for_network(ChainNetwork::Kaspa(KaspaNetwork::Testnet11))
        }
    };
    let review = ReviewArtifact::new(scope, [11; 32], [12; 32], "review".to_owned(), vec![0x51])
        .expect("valid review");
    let binding = ReviewBinding::new(
        scope,
        profile.signing_suite_id(),
        "personal-wallet",
        4,
        review.schema_version,
        review.review_digest,
    )
    .expect("valid binding");
    let signer_set =
        CbMpcSignerSet::new("personal-wallet", 4, 2, parties()).expect("valid signer set");

    ApprovedCbMpcSignRequest::new(
        ApprovedCbMpcSignRequestParts {
            profile,
            review,
            review_binding: binding,
            signer_set,
            group_public_key: group_public_key(),
            policy_snapshot_digest: [21; 32],
            chain_snapshot_digest: [22; 32],
            online_parties: parties()[..2].to_vec(),
            receiver: PartyId::new("desktop").unwrap(),
            session_id: [31; 32],
            expires_at: NOW + 120,
        },
        NOW,
    )
    .expect("valid approved request")
}

#[test]
fn profile_and_stage_count_are_fixed() {
    assert_eq!(CB_MPC_ECDSA_SIGN_STAGES, 9);
    assert_eq!(
        CbMpcProfile::BitcoinCashEcdsaV1.signing_suite_id(),
        SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1
    );
    assert_eq!(
        CbMpcProfile::BsvEcdsaV1.signing_suite_id(),
        SigningSuiteId::BSV_ECDSA_CB_MPC_V1
    );
    assert_eq!(
        CbMpcProfile::KaspaEcdsaV1.signing_suite_id(),
        SigningSuiteId::KASPA_ECDSA_CB_MPC_V1
    );
}

#[test]
fn approved_request_binds_every_security_snapshot() {
    let baseline = request_for(CbMpcProfile::BitcoinCashEcdsaV1);
    let baseline_digest = baseline.binding_digest();

    let mut changed_policy = request_for(CbMpcProfile::BitcoinCashEcdsaV1).into_parts();
    changed_policy.policy_snapshot_digest = [99; 32];
    let changed_policy = ApprovedCbMpcSignRequest::new(changed_policy, NOW).unwrap();
    assert_ne!(baseline_digest, changed_policy.binding_digest());

    let mut changed_chain = request_for(CbMpcProfile::BitcoinCashEcdsaV1).into_parts();
    changed_chain.chain_snapshot_digest = [98; 32];
    let changed_chain = ApprovedCbMpcSignRequest::new(changed_chain, NOW).unwrap();
    assert_ne!(baseline_digest, changed_chain.binding_digest());

    let mut changed_session = request_for(CbMpcProfile::BitcoinCashEcdsaV1).into_parts();
    changed_session.session_id = [97; 32];
    let changed_session = ApprovedCbMpcSignRequest::new(changed_session, NOW).unwrap();
    assert_ne!(baseline_digest, changed_session.binding_digest());
}

#[test]
fn constructor_rejects_noncanonical_or_drifted_requests() {
    let mut wrong_review = request_for(CbMpcProfile::BitcoinCashEcdsaV1).into_parts();
    wrong_review.review.review_digest = [55; 32];
    assert_eq!(
        ApprovedCbMpcSignRequest::new(wrong_review, NOW),
        Err(CbMpcError::ReviewBindingMismatch)
    );

    let mut wrong_suite = request_for(CbMpcProfile::BitcoinCashEcdsaV1).into_parts();
    wrong_suite.review_binding.signing_suite_id = SigningSuiteId::BSV_ECDSA_CB_MPC_V1;
    assert_eq!(
        ApprovedCbMpcSignRequest::new(wrong_suite, NOW),
        Err(CbMpcError::ProfileMismatch)
    );

    assert_eq!(
        CbMpcSignerSet::new(
            "personal-wallet",
            4,
            2,
            vec![
                parties()[1].clone(),
                parties()[0].clone(),
                parties()[2].clone()
            ],
        ),
        Err(CbMpcError::NonCanonicalPartyOrder)
    );

    let mut expired = request_for(CbMpcProfile::BsvEcdsaV1).into_parts();
    expired.expires_at = NOW;
    assert_eq!(
        ApprovedCbMpcSignRequest::new(expired, NOW),
        Err(CbMpcError::Expired)
    );
}

#[test]
fn runtime_has_only_bounded_transport_settings() {
    let limits =
        CbMpcRuntimeLimits::new(Duration::from_secs(5), Duration::from_secs(30), 1024 * 1024)
            .unwrap();
    assert_eq!(limits.receive_timeout(), Duration::from_secs(5));
    assert_eq!(limits.session_timeout(), Duration::from_secs(30));
    assert_eq!(limits.max_frame_bytes(), 1024 * 1024);

    assert_eq!(
        CbMpcRuntimeLimits::new(Duration::ZERO, Duration::from_secs(1), 1024),
        Err(CbMpcError::InvalidRuntimeLimits)
    );
    assert_eq!(
        CbMpcRuntimeLimits::new(Duration::from_secs(2), Duration::from_secs(1), 1024),
        Err(CbMpcError::InvalidRuntimeLimits)
    );
}

#[cfg(not(feature = "native-cbmpc"))]
#[test]
fn native_selection_fails_closed_without_feature() {
    let limits =
        CbMpcRuntimeLimits::new(Duration::from_secs(5), Duration::from_secs(30), 1024 * 1024)
            .unwrap();
    let root = tempfile::Builder::new()
        .prefix("cb-mpc-contract-")
        .tempdir()
        .unwrap();
    let root_path = root.path().canonicalize().unwrap();
    let store = Arc::new(DurableSessionClaimStore::open(&root_path.join("claims")).unwrap());
    assert!(matches!(
        CbMpcRuntime::new_native(limits, store),
        Err(CbMpcError::BackendUnavailable)
    ));
}

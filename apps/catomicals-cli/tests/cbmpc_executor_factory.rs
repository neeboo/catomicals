#![allow(dead_code)]

#[path = "../src/cbmpc_executor_factory.rs"]
mod cbmpc_executor_factory;

use catomicals_chain_domain::{BsvNetwork, ChainNetwork, ChainScope};
use catomicals_signing_domain::{SignerBackendRequirement, SigningSuiteId};
use catomicals_wallet::SignerProfileStartupSnapshot;
use cbmpc_executor_factory::{
    CB_MPC_MANIFEST_VERSION, CB_MPC_PROTOCOL_STAGES, CbMpcExecutorManifestV1, CbMpcFactoryError,
    CbMpcRecoverySignerRefV1, CbMpcSignerRefV1,
};
use uuid::Uuid;

fn snapshot() -> SignerProfileStartupSnapshot {
    SignerProfileStartupSnapshot {
        profile_id: Uuid::from_bytes([0x11; 16]),
        wallet_id: Uuid::from_bytes([0x22; 16]),
        chain_scope: ChainScope::for_network(ChainNetwork::Bsv(BsvNetwork::Regtest)),
        signing_suite_id: SigningSuiteId::BSV_ECDSA_CB_MPC_V1,
        backend_requirement: SignerBackendRequirement::CbMpcThresholdEcdsa,
        signer_set_id: "personal-wallet".to_owned(),
        authorization_signer_id: "passkey:primary".to_owned(),
        signer_epoch: 7,
        threshold: 2,
        max_signers: 3,
        verification_key_hex: format!("02{}", "11".repeat(32)),
        secret_ref: "op://Private/cbmpc/manifest".to_owned(),
        address_bindings: vec![],
    }
}

fn signer(party_id: &str, suffix: &str) -> CbMpcSignerRefV1 {
    CbMpcSignerRefV1 {
        party_id: party_id.to_owned(),
        device_ref: format!("device://cbmpc/{suffix}"),
        sealed_share_ref: format!("op://Private/cbmpc/share-{suffix}"),
        protector_key_ref: format!("op://Private/cbmpc/key-{suffix}"),
        endpoint_ref: format!("unix://cbmpc/{suffix}"),
        tls_identity_ref: format!("op://Private/cbmpc/tls-{suffix}"),
    }
}

fn manifest(snapshot: &SignerProfileStartupSnapshot) -> CbMpcExecutorManifestV1 {
    CbMpcExecutorManifestV1 {
        format_version: CB_MPC_MANIFEST_VERSION,
        wallet_id: snapshot.wallet_id,
        profile_id: snapshot.profile_id,
        chain_scope: snapshot.chain_scope,
        signing_suite_id: snapshot.signing_suite_id,
        signer_set_id: snapshot.signer_set_id.clone(),
        signer_epoch: snapshot.signer_epoch,
        protocol_stages: CB_MPC_PROTOCOL_STAGES,
        all_parties: [
            "desktop".to_owned(),
            "mobile".to_owned(),
            "onepassword".to_owned(),
        ],
        active_signers: [signer("desktop", "desktop"), signer("onepassword", "op")],
        recovery_signer: Some(CbMpcRecoverySignerRefV1 {
            party_id: "mobile".to_owned(),
            device_ref: "device://cbmpc/mobile".to_owned(),
            sealed_share_ref: "op://Private/cbmpc/share-mobile".to_owned(),
            protector_key_ref: "op://Private/cbmpc/key-mobile".to_owned(),
        }),
        receiver: "desktop".to_owned(),
    }
}

#[test]
fn manifest_rejects_wallet_profile_network_suite_and_round_drift() {
    let snapshot = snapshot();
    let valid = manifest(&snapshot);
    valid.validate_for(&snapshot).expect("valid manifest");

    let mut wrong_backend = snapshot.clone();
    wrong_backend.backend_requirement = SignerBackendRequirement::FrostSecp256k1Tr;
    assert_eq!(
        valid.validate_for(&wrong_backend),
        Err(CbMpcFactoryError::ManifestBindingMismatch)
    );

    let cases = [
        {
            let mut value = valid.clone();
            value.wallet_id = Uuid::new_v4();
            value
        },
        {
            let mut value = valid.clone();
            value.profile_id = Uuid::new_v4();
            value
        },
        {
            let mut value = valid.clone();
            value.chain_scope = ChainScope::for_network(ChainNetwork::Bsv(BsvNetwork::Testnet));
            value
        },
        {
            let mut value = valid.clone();
            value.signing_suite_id = SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1;
            value
        },
        {
            let mut value = valid;
            value.protocol_stages -= 1;
            value
        },
    ];

    for drifted in cases {
        assert_eq!(
            drifted.validate_for(&snapshot),
            Err(CbMpcFactoryError::ManifestBindingMismatch)
        );
    }
}

#[test]
fn manifest_contains_references_without_private_material() {
    let encoded = serde_json::to_string(&manifest(&snapshot())).expect("manifest JSON");
    assert!(encoded.contains("sealed_share_ref"));
    assert!(encoded.contains("tls_identity_ref"));
    assert!(!encoded.contains("private_key"));
    assert!(!encoded.contains("ciphertext"));
    assert!(!encoded.contains("secret_share"));
}

#[test]
fn recovery_signer_must_be_the_distinct_third_party() {
    let snapshot = snapshot();
    let mut value = manifest(&snapshot);
    value.recovery_signer.as_mut().unwrap().party_id = "desktop".to_owned();
    assert_eq!(
        value.validate_for(&snapshot),
        Err(CbMpcFactoryError::ManifestInvalid)
    );
}

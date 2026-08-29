use std::str::FromStr;

use catomicals_chain_domain::{
    BitcoinCashNetwork, BitcoinNetwork, BsvNetwork, ChainNetwork, ChainScope, ChiaNetwork,
    ErgoNetwork,
};
use catomicals_signing_domain::{
    Capabilities, ReviewBinding, SignerBackendRequirement, SigningAlgorithm, SigningContractError,
    SigningExecutionMode, SigningSuite, SigningSuiteId, resolve_builtin_suite,
};

fn accepts_object_safe_signing_suite(_: &dyn SigningSuite) {}

#[test]
fn signing_suite_contract_is_object_safe() {
    let _ = accepts_object_safe_signing_suite;
}

#[test]
fn signing_algorithms_and_execution_modes_have_stable_semantic_ids() {
    assert_eq!(
        SigningAlgorithm::ALL.map(|value| value.as_str()),
        [
            "bip340-taproot-schnorr",
            "secp256k1-schnorr",
            "bitcoin-cash-schnorr",
            "secp256k1-ecdsa",
            "bls12-381-aug-scheme",
            "ergo-sigma",
        ]
    );
    assert_eq!(
        SigningExecutionMode::ALL.map(|value| value.as_str()),
        [
            "threshold-interactive",
            "single-signer-isolated",
            "native-chain-coordinator",
        ]
    );

    for algorithm in SigningAlgorithm::ALL {
        let encoded = serde_json::to_string(&algorithm).unwrap();
        assert_eq!(
            serde_json::from_str::<SigningAlgorithm>(&encoded).unwrap(),
            algorithm
        );
    }

    assert_eq!(
        SignerBackendRequirement::ALL.map(|value| value.as_str()),
        [
            "frost-secp256k1-tr",
            "frost-secp256k1-kaspa",
            "cb-mpc-threshold-ecdsa",
            "isolated-bip340",
            "isolated-secp256k1-ecdsa",
            "isolated-bitcoin-cash-schnorr",
            "chia-bls-aug",
            "ergo-sigma",
        ]
    );
}

#[test]
fn builtin_suites_declare_algorithm_execution_and_capabilities() {
    let bitcoin = ChainScope::for_network(ChainNetwork::Bitcoin(BitcoinNetwork::Signet));
    let suite = resolve_builtin_suite(&bitcoin, SigningSuiteId::BITCOIN_BIP340_FROST_V1)
        .expect("Bitcoin Signet supports the BIP340 FROST suite");
    assert_eq!(suite.algorithm, SigningAlgorithm::Bip340TaprootSchnorr);
    assert_eq!(
        suite.backend_requirement,
        SignerBackendRequirement::FrostSecp256k1Tr
    );
    assert_eq!(
        suite.execution_mode,
        SigningExecutionMode::ThresholdInteractive
    );
    assert_eq!(
        suite.capabilities,
        Capabilities {
            produces_consensus_signature: true,
            independently_verifiable: true,
            interactive_threshold: true,
        }
    );

    let bch = ChainScope::for_network(ChainNetwork::BitcoinCash(BitcoinCashNetwork::Chipnet));
    assert_eq!(
        resolve_builtin_suite(&bch, SigningSuiteId::BITCOIN_CASH_SCHNORR_ISOLATED_V1)
            .unwrap()
            .algorithm,
        SigningAlgorithm::BitcoinCashSchnorr
    );

    let bch_threshold =
        resolve_builtin_suite(&bch, SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1).unwrap();
    assert_eq!(
        bch_threshold.backend_requirement,
        SignerBackendRequirement::CbMpcThresholdEcdsa
    );
    assert!(bch_threshold.capabilities.interactive_threshold);

    let bsv = ChainScope::for_network(ChainNetwork::Bsv(BsvNetwork::Stn));
    let bsv_threshold = resolve_builtin_suite(&bsv, SigningSuiteId::BSV_ECDSA_CB_MPC_V1).unwrap();
    assert_eq!(
        bsv_threshold.backend_requirement,
        SignerBackendRequirement::CbMpcThresholdEcdsa
    );
    assert!(bsv_threshold.capabilities.interactive_threshold);

    let chia = ChainScope::for_network(ChainNetwork::Chia(ChiaNetwork::Testnet11));
    assert_eq!(
        resolve_builtin_suite(&chia, SigningSuiteId::CHIA_BLS12381_AUG_NATIVE_V1)
            .unwrap()
            .algorithm,
        SigningAlgorithm::Bls12381AugScheme
    );

    let ergo = ChainScope::for_network(ChainNetwork::Ergo(ErgoNetwork::Testnet));
    assert_eq!(
        resolve_builtin_suite(&ergo, SigningSuiteId::ERGO_SIGMA_NATIVE_V1)
            .unwrap()
            .algorithm,
        SigningAlgorithm::ErgoSigma
    );
}

#[test]
fn unsupported_chain_suite_combinations_fail_closed() {
    let bitcoin = ChainScope::for_network(ChainNetwork::Bitcoin(BitcoinNetwork::Mainnet));
    assert_eq!(
        resolve_builtin_suite(&bitcoin, SigningSuiteId::CHIA_BLS12381_AUG_NATIVE_V1),
        Err(SigningContractError::UnsupportedCombination {
            chain_scope: bitcoin,
            suite_id: SigningSuiteId::CHIA_BLS12381_AUG_NATIVE_V1,
        })
    );

    assert!(SigningSuiteId::from_str("unknown.v1").is_err());
    assert!(SigningSuiteId::from_str("btc.bip340.frost-secp256k1-tr").is_err());
}

#[test]
fn review_binding_domain_separates_every_signing_authority_dimension() {
    let scope = ChainScope::for_network(ChainNetwork::Bitcoin(BitcoinNetwork::Signet));
    let baseline = ReviewBinding::new(
        scope,
        SigningSuiteId::BITCOIN_BIP340_FROST_V1,
        "wallet-primary-2-of-3",
        7,
        1,
        [0x42; 32],
    )
    .unwrap();
    let baseline_domain = baseline.domain_separator();

    let variants = [
        ReviewBinding::new(
            ChainScope::for_network(ChainNetwork::Bitcoin(BitcoinNetwork::Testnet4)),
            SigningSuiteId::BITCOIN_BIP340_FROST_V1,
            "wallet-primary-2-of-3",
            7,
            1,
            [0x42; 32],
        )
        .unwrap(),
        ReviewBinding::new(
            scope,
            SigningSuiteId::BITCOIN_BIP340_ISOLATED_V1,
            "wallet-primary-2-of-3",
            7,
            1,
            [0x42; 32],
        )
        .unwrap(),
        ReviewBinding::new(
            scope,
            SigningSuiteId::BITCOIN_BIP340_FROST_V1,
            "wallet-recovery-2-of-3",
            7,
            1,
            [0x42; 32],
        )
        .unwrap(),
        ReviewBinding::new(
            scope,
            SigningSuiteId::BITCOIN_BIP340_FROST_V1,
            "wallet-primary-2-of-3",
            8,
            1,
            [0x42; 32],
        )
        .unwrap(),
        ReviewBinding::new(
            scope,
            SigningSuiteId::BITCOIN_BIP340_FROST_V1,
            "wallet-primary-2-of-3",
            7,
            2,
            [0x42; 32],
        )
        .unwrap(),
        ReviewBinding::new(
            scope,
            SigningSuiteId::BITCOIN_BIP340_FROST_V1,
            "wallet-primary-2-of-3",
            7,
            1,
            [0x43; 32],
        )
        .unwrap(),
    ];

    for variant in variants {
        assert_ne!(baseline_domain, variant.domain_separator());
    }
}

#[test]
fn review_binding_serialization_is_versioned_and_stable() {
    let binding = ReviewBinding::new(
        ChainScope::for_network(ChainNetwork::Bitcoin(BitcoinNetwork::Testnet4)),
        SigningSuiteId::BITCOIN_BIP340_FROST_V1,
        "wallet-primary-2-of-3",
        7,
        1,
        [0xab; 32],
    )
    .unwrap();

    let value = serde_json::to_value(binding).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["chain_scope"]["chain"], "bitcoin");
    assert_eq!(value["chain_scope"]["network"], "bitcoin.testnet4");
    assert_eq!(
        value["signing_suite_id"],
        "btc.bip340.frost-secp256k1-tr.v1"
    );
    assert_eq!(value["signer_set_id"], "wallet-primary-2-of-3");
    assert_eq!(value["signer_set_epoch"], 7);
    assert_eq!(value["review_schema_version"], 1);
}

#[test]
fn review_binding_deserialization_revalidates_all_invariants() {
    let binding = ReviewBinding::new(
        ChainScope::for_network(ChainNetwork::Bitcoin(BitcoinNetwork::Testnet4)),
        SigningSuiteId::BITCOIN_BIP340_FROST_V1,
        "wallet-primary-2-of-3",
        7,
        1,
        [0xab; 32],
    )
    .unwrap();
    let valid = serde_json::to_value(binding).unwrap();

    let mut wrong_version = valid.clone();
    wrong_version["schema_version"] = 2.into();
    assert!(serde_json::from_value::<ReviewBinding>(wrong_version).is_err());

    let mut wrong_suite = valid.clone();
    wrong_suite["signing_suite_id"] = "chia.bls12-381.aug.native.v1".into();
    assert!(serde_json::from_value::<ReviewBinding>(wrong_suite).is_err());

    let mut oversized_signer_set = valid.clone();
    oversized_signer_set["signer_set_id"] = "x".repeat(129).into();
    assert!(serde_json::from_value::<ReviewBinding>(oversized_signer_set).is_err());

    let mut unversioned_review = valid;
    unversioned_review["review_schema_version"] = 0.into();
    assert!(serde_json::from_value::<ReviewBinding>(unversioned_review).is_err());
}

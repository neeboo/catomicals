use std::str::FromStr;

use catomicals_chain_domain::{
    BitcoinCashNetwork, BitcoinNetwork, BsvNetwork, ChainNetwork, ChainScope, ChiaNetwork,
    ErgoNetwork, FractalBitcoinNetwork, KaspaNetwork,
};
use catomicals_signing_domain::{
    Capabilities, ReviewBinding, SignerBackendRequirement, SigningAlgorithm, SigningAvailability,
    SigningContractError, SigningExecutionMode, SigningSuite, SigningSuiteDescriptor,
    SigningSuiteId, require_executable_suite, resolve_builtin_suite,
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
            "threshold-non-interactive",
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
            "chia-bls-aug-threshold-2of3",
            "ergo-sigma",
            "ergo-sigma-p2pk",
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
    assert_eq!(suite.availability, SigningAvailability::Executable);
    assert_eq!(
        suite.capabilities,
        Capabilities {
            produces_consensus_signature: true,
            independently_verifiable: true,
            interactive_threshold: true,
            non_interactive_threshold: false,
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
    let ergo = resolve_builtin_suite(&ergo, SigningSuiteId::ERGO_SIGMA_NATIVE_V1).unwrap();
    assert_eq!(ergo.algorithm, SigningAlgorithm::ErgoSigma);
    assert_eq!(
        ergo.capabilities,
        Capabilities {
            produces_consensus_signature: false,
            independently_verifiable: false,
            interactive_threshold: false,
            non_interactive_threshold: false,
        }
    );
}

#[test]
fn builtin_capability_matrix_marks_declaration_only_suites_unavailable() {
    let consensus_single = Capabilities {
        produces_consensus_signature: true,
        independently_verifiable: true,
        interactive_threshold: false,
        non_interactive_threshold: false,
    };
    let consensus_threshold = Capabilities {
        interactive_threshold: true,
        ..consensus_single
    };
    let declaration_only = Capabilities {
        produces_consensus_signature: false,
        independently_verifiable: false,
        interactive_threshold: false,
        non_interactive_threshold: false,
    };
    let bitcoin = ChainScope::for_network(ChainNetwork::Bitcoin(BitcoinNetwork::Signet));
    let fractal =
        ChainScope::for_network(ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Signet));
    let bch = ChainScope::for_network(ChainNetwork::BitcoinCash(BitcoinCashNetwork::Chipnet));
    let bsv = ChainScope::for_network(ChainNetwork::Bsv(BsvNetwork::Stn));
    let kaspa = ChainScope::for_network(ChainNetwork::Kaspa(KaspaNetwork::Testnet11));
    let chia = ChainScope::for_network(ChainNetwork::Chia(ChiaNetwork::Testnet11));
    let ergo = ChainScope::for_network(ChainNetwork::Ergo(ErgoNetwork::Testnet));
    let cases = [
        (
            bitcoin,
            SigningSuiteId::BITCOIN_BIP340_FROST_V1,
            consensus_threshold,
        ),
        (
            bitcoin,
            SigningSuiteId::BITCOIN_BIP340_ISOLATED_V1,
            consensus_single,
        ),
        (
            fractal,
            SigningSuiteId::FRACTAL_BITCOIN_BIP340_FROST_V1,
            consensus_threshold,
        ),
        (
            bch,
            SigningSuiteId::BITCOIN_CASH_SCHNORR_ISOLATED_V1,
            consensus_single,
        ),
        (
            bch,
            SigningSuiteId::BITCOIN_CASH_ECDSA_ISOLATED_V1,
            consensus_single,
        ),
        (
            bch,
            SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1,
            consensus_threshold,
        ),
        (bsv, SigningSuiteId::BSV_ECDSA_ISOLATED_V1, consensus_single),
        (
            bsv,
            SigningSuiteId::BSV_ECDSA_CB_MPC_V1,
            consensus_threshold,
        ),
        (
            kaspa,
            SigningSuiteId::KASPA_SCHNORR_FROST_V1,
            consensus_threshold,
        ),
        (
            kaspa,
            SigningSuiteId::KASPA_ECDSA_ISOLATED_V1,
            consensus_single,
        ),
        (
            chia,
            SigningSuiteId::CHIA_BLS12381_AUG_NATIVE_V1,
            consensus_single,
        ),
        (
            chia,
            SigningSuiteId::CHIA_BLS12381_AUG_THRESHOLD_2OF3_V1,
            Capabilities {
                produces_consensus_signature: true,
                independently_verifiable: true,
                interactive_threshold: false,
                non_interactive_threshold: true,
            },
        ),
        (ergo, SigningSuiteId::ERGO_SIGMA_NATIVE_V1, declaration_only),
        (
            ergo,
            SigningSuiteId::ERGO_SIGMA_P2PK_ISOLATED_V1,
            consensus_single,
        ),
    ];

    for (scope, suite_id, expected) in cases {
        assert_eq!(
            resolve_builtin_suite(&scope, suite_id)
                .unwrap()
                .capabilities,
            expected,
            "unexpected capability declaration for {suite_id}",
        );
    }
}

#[test]
fn execution_entry_rejects_declaration_only_suites() {
    let fractal =
        ChainScope::for_network(ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Signet));
    let kaspa = ChainScope::for_network(ChainNetwork::Kaspa(KaspaNetwork::Testnet11));
    let chia = ChainScope::for_network(ChainNetwork::Chia(ChiaNetwork::Testnet11));
    let ergo = ChainScope::for_network(ChainNetwork::Ergo(ErgoNetwork::Testnet));

    for (scope, suite_id) in [
        (fractal, SigningSuiteId::FRACTAL_BITCOIN_BIP340_FROST_V1),
        (kaspa, SigningSuiteId::KASPA_SCHNORR_FROST_V1),
        (chia, SigningSuiteId::CHIA_BLS12381_AUG_NATIVE_V1),
        (chia, SigningSuiteId::CHIA_BLS12381_AUG_THRESHOLD_2OF3_V1),
        (ergo, SigningSuiteId::ERGO_SIGMA_NATIVE_V1),
    ] {
        let descriptor = resolve_builtin_suite(&scope, suite_id).unwrap();
        assert_eq!(
            descriptor.availability,
            SigningAvailability::DeclarationOnly
        );
        assert_eq!(
            require_executable_suite(&scope, suite_id),
            Err(SigningContractError::SuiteNotExecutable { suite_id })
        );
    }
}

#[test]
fn execution_entry_accepts_only_proven_transaction_level_suites() {
    let bitcoin = ChainScope::for_network(ChainNetwork::Bitcoin(BitcoinNetwork::Signet));
    let bch = ChainScope::for_network(ChainNetwork::BitcoinCash(BitcoinCashNetwork::Chipnet));
    let bsv = ChainScope::for_network(ChainNetwork::Bsv(BsvNetwork::Stn));
    let kaspa = ChainScope::for_network(ChainNetwork::Kaspa(KaspaNetwork::Testnet11));
    let ergo = ChainScope::for_network(ChainNetwork::Ergo(ErgoNetwork::Testnet));

    for (scope, suite_id) in [
        (bitcoin, SigningSuiteId::BITCOIN_BIP340_FROST_V1),
        (bch, SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1),
        (bsv, SigningSuiteId::BSV_ECDSA_CB_MPC_V1),
        (kaspa, SigningSuiteId::KASPA_ECDSA_CB_MPC_V1),
        (ergo, SigningSuiteId::ERGO_SIGMA_P2PK_ISOLATED_V1),
    ] {
        let descriptor = require_executable_suite(&scope, suite_id).unwrap();
        assert_eq!(descriptor.availability, SigningAvailability::Executable);
        assert!(descriptor.capabilities.produces_consensus_signature);
        assert!(descriptor.capabilities.independently_verifiable);
    }
}

#[test]
fn descriptor_schema_v2_expresses_non_interactive_threshold_capability() {
    assert_eq!(
        SigningExecutionMode::ThresholdNonInteractive.as_str(),
        "threshold-non-interactive"
    );
    let capabilities = Capabilities {
        produces_consensus_signature: true,
        independently_verifiable: true,
        interactive_threshold: false,
        non_interactive_threshold: true,
    };
    assert!(capabilities.non_interactive_threshold);

    let bitcoin = ChainScope::for_network(ChainNetwork::Bitcoin(BitcoinNetwork::Signet));
    let descriptor =
        resolve_builtin_suite(&bitcoin, SigningSuiteId::BITCOIN_BIP340_FROST_V1).unwrap();
    let value = serde_json::to_value(descriptor).unwrap();
    assert_eq!(value["schema_version"], 2);
    assert_eq!(value["availability"], "executable");
    assert_eq!(value["capabilities"]["non_interactive_threshold"], false);

    assert_eq!(
        serde_json::from_value::<SigningSuiteDescriptor>(value.clone()).unwrap(),
        descriptor
    );
    let mut obsolete = value;
    obsolete["schema_version"] = 1.into();
    assert!(serde_json::from_value::<SigningSuiteDescriptor>(obsolete).is_err());
}

#[test]
fn kaspa_cb_mpc_suite_is_executable_after_transaction_engine_validation_lands() {
    let suite_id = SigningSuiteId::from_str("kaspa.ecdsa.cb-mpc.v1").unwrap();
    assert_eq!(suite_id, SigningSuiteId::KASPA_ECDSA_CB_MPC_V1);
    assert_eq!(
        serde_json::to_string(&suite_id).unwrap(),
        "\"kaspa.ecdsa.cb-mpc.v1\""
    );

    let kaspa = ChainScope::for_network(ChainNetwork::Kaspa(KaspaNetwork::Testnet11));
    let descriptor = resolve_builtin_suite(&kaspa, suite_id).unwrap();
    assert_eq!(descriptor.algorithm, SigningAlgorithm::Secp256k1Ecdsa);
    assert_eq!(
        descriptor.execution_mode,
        SigningExecutionMode::ThresholdInteractive
    );
    assert_eq!(
        descriptor.backend_requirement,
        SignerBackendRequirement::CbMpcThresholdEcdsa
    );
    assert!(descriptor.capabilities.interactive_threshold);
    assert_eq!(descriptor.availability, SigningAvailability::Executable);
    assert_eq!(
        require_executable_suite(&kaspa, suite_id).unwrap(),
        descriptor
    );
}

#[test]
fn chia_threshold_suite_exposes_crypto_capability_without_transaction_execution() {
    let suite_id = SigningSuiteId::from_str("chia.bls12-381.aug.threshold-2of3.v1").unwrap();
    assert_eq!(
        suite_id,
        SigningSuiteId::CHIA_BLS12381_AUG_THRESHOLD_2OF3_V1
    );
    assert_eq!(
        serde_json::to_string(&suite_id).unwrap(),
        "\"chia.bls12-381.aug.threshold-2of3.v1\""
    );

    let chia = ChainScope::for_network(ChainNetwork::Chia(ChiaNetwork::Testnet11));
    let descriptor = resolve_builtin_suite(&chia, suite_id).unwrap();
    assert_eq!(descriptor.algorithm, SigningAlgorithm::Bls12381AugScheme);
    assert_eq!(
        descriptor.execution_mode,
        SigningExecutionMode::ThresholdNonInteractive
    );
    assert_eq!(
        descriptor.backend_requirement,
        SignerBackendRequirement::ChiaBlsAugThreshold2of3
    );
    assert_eq!(
        descriptor.capabilities,
        Capabilities {
            produces_consensus_signature: true,
            independently_verifiable: true,
            interactive_threshold: false,
            non_interactive_threshold: true,
        }
    );
    assert_eq!(
        descriptor.availability,
        SigningAvailability::DeclarationOnly
    );
    assert_eq!(
        require_executable_suite(&chia, suite_id),
        Err(SigningContractError::SuiteNotExecutable { suite_id })
    );
}

#[test]
fn ergo_p2pk_isolated_suite_is_executable_while_generic_sigma_stays_declaration_only() {
    let suite_id = SigningSuiteId::from_str("ergo.sigma.p2pk.isolated.v1").unwrap();
    assert_eq!(suite_id, SigningSuiteId::ERGO_SIGMA_P2PK_ISOLATED_V1);
    assert_eq!(
        serde_json::to_string(&suite_id).unwrap(),
        "\"ergo.sigma.p2pk.isolated.v1\""
    );

    let ergo = ChainScope::for_network(ChainNetwork::Ergo(ErgoNetwork::Testnet));
    let descriptor = require_executable_suite(&ergo, suite_id).unwrap();
    assert_eq!(descriptor.algorithm, SigningAlgorithm::ErgoSigma);
    assert_eq!(
        descriptor.execution_mode,
        SigningExecutionMode::SingleSignerIsolated
    );
    assert_eq!(
        descriptor.backend_requirement,
        SignerBackendRequirement::ErgoSigmaP2pk
    );
    assert_eq!(descriptor.availability, SigningAvailability::Executable);

    let generic = resolve_builtin_suite(&ergo, SigningSuiteId::ERGO_SIGMA_NATIVE_V1).unwrap();
    assert_eq!(generic.availability, SigningAvailability::DeclarationOnly);
    assert_eq!(
        require_executable_suite(&ergo, SigningSuiteId::ERGO_SIGMA_NATIVE_V1),
        Err(SigningContractError::SuiteNotExecutable {
            suite_id: SigningSuiteId::ERGO_SIGMA_NATIVE_V1,
        })
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
    assert!(matches!(
        resolve_builtin_suite(
            &bitcoin,
            SigningSuiteId::CHIA_BLS12381_AUG_THRESHOLD_2OF3_V1,
        ),
        Err(SigningContractError::UnsupportedCombination { .. })
    ));

    let chia = ChainScope::for_network(ChainNetwork::Chia(ChiaNetwork::Testnet11));
    assert!(matches!(
        resolve_builtin_suite(&chia, SigningSuiteId::ERGO_SIGMA_P2PK_ISOLATED_V1),
        Err(SigningContractError::UnsupportedCombination { .. })
    ));

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

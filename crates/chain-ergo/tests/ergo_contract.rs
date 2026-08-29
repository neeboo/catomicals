use catomicals_chain_domain::{ChainCapabilities, ChainId, ChainNetwork, ChainSuite, ErgoNetwork};
use catomicals_chain_ergo::{
    ERGO_COIN_TYPE, ErgoAdapterError, ErgoAddressKind, ErgoChainSuite, ErgoSignerBackend,
    ErgoSignerMode, ErgoSigningSuite, ErgoThresholdP2pkRuntimeDescriptor, derive_eip3_path,
    p2pk_address, parse_address, pay_to_script_address,
};
use catomicals_signing_domain::{
    Capabilities, SignerBackendRequirement, SigningAlgorithm, SigningExecutionMode, SigningSuite,
    SigningSuiteId,
};

#[test]
fn upstream_address_vectors_parse_on_their_declared_network() {
    // sigma-rust/ergotree-ir address module fixtures.
    let mainnet_p2pk = parse_address(
        ErgoNetwork::Mainnet,
        "9fRAWhdxEsTcdb8PhGNrZfwqa65zfkuYHAMmkQLcic1gdLSV5vA",
    )
    .unwrap();
    assert_eq!(mainnet_p2pk.kind(), ErgoAddressKind::P2Pk);
    assert_eq!(mainnet_p2pk.network(), ErgoNetwork::Mainnet);
    assert_eq!(
        mainnet_p2pk.to_string(),
        "9fRAWhdxEsTcdb8PhGNrZfwqa65zfkuYHAMmkQLcic1gdLSV5vA"
    );

    let testnet_p2pk = parse_address(
        ErgoNetwork::Testnet,
        "3WvsT2Gm4EpsM9Pg18PdY6XyhNNMqXDsvJTbbf6ihLvAmSb7u5RN",
    )
    .unwrap();
    assert_eq!(testnet_p2pk.kind(), ErgoAddressKind::P2Pk);
    assert_eq!(testnet_p2pk.network(), ErgoNetwork::Testnet);

    let mainnet_p2s = parse_address(ErgoNetwork::Mainnet, "4MQyML64GnzMxZgm").unwrap();
    assert_eq!(mainnet_p2s.kind(), ErgoAddressKind::PayToScript);
    assert!(!mainnet_p2s.ergo_tree_bytes().unwrap().is_empty());

    let testnet_p2s = parse_address(ErgoNetwork::Testnet, "Ms7smJwLGbUAjuWQ").unwrap();
    assert_eq!(testnet_p2s.kind(), ErgoAddressKind::PayToScript);
    assert!(!testnet_p2s.ergo_tree_bytes().unwrap().is_empty());
}

#[test]
fn address_validation_rejects_wrong_network_checksum_and_unsupported_p2sh() {
    let mainnet_p2pk = "9fRAWhdxEsTcdb8PhGNrZfwqa65zfkuYHAMmkQLcic1gdLSV5vA";
    assert!(matches!(
        parse_address(ErgoNetwork::Testnet, mainnet_p2pk),
        Err(ErgoAdapterError::InvalidAddressNetwork { .. })
    ));

    let mut bad_checksum = mainnet_p2pk.to_owned();
    bad_checksum.pop();
    bad_checksum.push('B');
    assert!(matches!(
        parse_address(ErgoNetwork::Mainnet, &bad_checksum),
        Err(ErgoAdapterError::InvalidAddress(_))
    ));

    // sigma-rust's upstream mainnet P2SH fixture. This adapter deliberately supports P2PK/P2S only.
    assert!(matches!(
        parse_address(
            ErgoNetwork::Mainnet,
            "8UApt8czfFVuTgQmMwtsRBZ4nfWquNiSwCWUjMg"
        ),
        Err(ErgoAdapterError::UnsupportedAddressKind)
    ));
}

#[test]
fn upstream_address_payloads_encode_back_to_the_same_network_address() {
    let mainnet_p2pk = parse_address(
        ErgoNetwork::Mainnet,
        "9fRAWhdxEsTcdb8PhGNrZfwqa65zfkuYHAMmkQLcic1gdLSV5vA",
    )
    .unwrap();
    assert_eq!(
        p2pk_address(ErgoNetwork::Mainnet, &mainnet_p2pk.content_bytes())
            .unwrap()
            .to_string(),
        mainnet_p2pk.to_string()
    );

    let testnet_p2s = parse_address(ErgoNetwork::Testnet, "Ms7smJwLGbUAjuWQ").unwrap();
    assert_eq!(
        pay_to_script_address(ErgoNetwork::Testnet, &testnet_p2s.content_bytes())
            .unwrap()
            .to_string(),
        testnet_p2s.to_string()
    );

    assert!(matches!(
        pay_to_script_address(ErgoNetwork::Mainnet, &[0xff]),
        Err(ErgoAdapterError::InvalidAddress(_))
    ));
}

#[test]
fn eip3_derivation_contract_has_fixed_coin_type_and_external_branch() {
    assert_eq!(ERGO_COIN_TYPE, 429);
    assert_eq!(
        derive_eip3_path(0, 0).unwrap().to_string(),
        "m/44'/429'/0'/0/0"
    );
    assert_eq!(
        derive_eip3_path(7, 19).unwrap().to_string(),
        "m/44'/429'/7'/0/19"
    );
}

#[test]
fn eip3_indices_cannot_cross_into_the_hardened_range() {
    const HARDENED: u32 = 1 << 31;
    assert!(matches!(
        derive_eip3_path(HARDENED, 0),
        Err(ErgoAdapterError::InvalidDerivationIndex {
            field: "account",
            ..
        })
    ));
    assert!(matches!(
        derive_eip3_path(0, HARDENED),
        Err(ErgoAdapterError::InvalidDerivationIndex {
            field: "address_index",
            ..
        })
    ));
}

#[test]
fn chain_and_signing_suites_declare_the_shared_ergo_contract() {
    let chain = ErgoChainSuite::new(ErgoNetwork::Testnet);
    assert_eq!(chain.scope().chain, ChainId::Ergo);
    assert_eq!(
        chain.scope().network,
        ChainNetwork::Ergo(ErgoNetwork::Testnet)
    );
    assert_eq!(
        chain.capabilities(),
        ChainCapabilities {
            address_derivation: true,
            transaction_review: true,
            final_signature_verification: true,
            broadcast: false,
        }
    );
    assert!(chain.review_transaction(&[]).is_err());

    let signing = ErgoSigningSuite::new(ErgoNetwork::Testnet).unwrap();
    let descriptor = signing.descriptor();
    assert_eq!(descriptor.id, SigningSuiteId::ERGO_SIGMA_P2PK_ISOLATED_V1);
    assert_eq!(descriptor.algorithm, SigningAlgorithm::ErgoSigma);
    assert_eq!(
        descriptor.execution_mode,
        SigningExecutionMode::SingleSignerIsolated
    );
    assert_eq!(
        descriptor.backend_requirement,
        SignerBackendRequirement::ErgoSigmaP2pk
    );
    assert_eq!(
        descriptor.capabilities,
        Capabilities {
            produces_consensus_signature: true,
            independently_verifiable: true,
            interactive_threshold: false,
            non_interactive_threshold: false,
        }
    );
    assert!(signing.supports(&chain.scope()));
}

#[test]
fn threshold_runtime_uses_the_registered_executable_suite_without_rewriting_it() {
    let signing = ErgoSigningSuite::new(ErgoNetwork::Testnet).unwrap();

    assert_eq!(
        signing
            .required_backend(ErgoSignerMode::SingleProver)
            .unwrap(),
        ErgoSignerBackend::NativeSigma
    );
    assert!(matches!(
        signing.required_backend(ErgoSignerMode::MultiParty),
        Err(ErgoAdapterError::SigmaMultisigUnavailable)
    ));
    let threshold = ErgoThresholdP2pkRuntimeDescriptor::new(ErgoNetwork::Testnet).unwrap();
    assert_eq!((threshold.threshold, threshold.max_signers), (2, 3));
    assert!(threshold.produces_native_p2pk_proof);
    assert_eq!(
        threshold.signing_suite.id,
        SigningSuiteId::ERGO_SIGMA_P2PK_THRESHOLD_2OF3_V1
    );
    assert_eq!(
        threshold.signing_suite.execution_mode,
        SigningExecutionMode::ThresholdInteractive
    );
    assert_eq!(
        threshold.signing_suite.backend_requirement,
        SignerBackendRequirement::ErgoSigmaP2pkThreshold2of3
    );
    assert_eq!(
        threshold.signing_suite.availability,
        catomicals_signing_domain::SigningAvailability::Executable
    );
    assert!(matches!(
        signing.validate_backend(
            ErgoSignerMode::SingleProver,
            ErgoSignerBackend::Secp256k1Ecdsa
        ),
        Err(ErgoAdapterError::IncompatibleSignerBackend { .. })
    ));
    assert!(matches!(
        signing.validate_backend(
            ErgoSignerMode::SingleProver,
            ErgoSignerBackend::Secp256k1Frost
        ),
        Err(ErgoAdapterError::IncompatibleSignerBackend { .. })
    ));
}

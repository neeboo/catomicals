use std::str::FromStr;

use catomicals_chain_bitcoin::{
    AddressKind, BitcoinAdapterError, BitcoinChainSuite, BitcoinSigningSuite, derivation_path,
};
use catomicals_chain_domain::{
    BitcoinNetwork, ChainId, ChainNetwork, ChainScope, FractalBitcoinNetwork,
};
use catomicals_signing_domain::{SignerBackendRequirement, SigningSuite, SigningSuiteId};

fn bitcoin(network: BitcoinNetwork) -> ChainScope {
    ChainScope::for_network(ChainNetwork::Bitcoin(network))
}

fn fractal_scope(network: FractalBitcoinNetwork) -> ChainScope {
    ChainScope::for_network(ChainNetwork::FractalBitcoin(network))
}

#[test]
fn bip84_and_bip86_paths_use_bip44_network_class_coin_types() {
    let mainnet = derivation_path(
        bitcoin(BitcoinNetwork::Mainnet),
        AddressKind::P2wpkh,
        0,
        0,
        0,
    )
    .expect("Bitcoin mainnet address derivation remains read-only available");
    assert_eq!(mainnet.path().to_string(), "84'/0'/0'/0/0");

    let testnet = derivation_path(
        bitcoin(BitcoinNetwork::Testnet4),
        AddressKind::P2tr,
        7,
        1,
        42,
    )
    .expect("testnet derivation");
    assert_eq!(testnet.path().to_string(), "86'/1'/7'/1/42");
}

#[test]
fn fractal_uses_standard_coin_types_but_keeps_a_separate_chain_binding() {
    let bitcoin_path = derivation_path(
        bitcoin(BitcoinNetwork::Testnet3),
        AddressKind::P2tr,
        0,
        0,
        0,
    )
    .expect("Bitcoin testnet path");
    let fractal_path = derivation_path(
        fractal_scope(FractalBitcoinNetwork::Testnet3),
        AddressKind::P2tr,
        0,
        0,
        0,
    )
    .expect("Fractal testnet path");

    assert_eq!(bitcoin_path.path(), fractal_path.path());
    assert_ne!(bitcoin_path.scope(), fractal_path.scope());
    assert_eq!(fractal_path.path().to_string(), "86'/1'/0'/0/0");
}

#[test]
fn derivation_rejects_non_bitcoin_family_and_unhardened_overflow() {
    let forged_scope = ChainScope {
        schema_version: 1,
        chain: ChainId::FractalBitcoin,
        network: ChainNetwork::Bitcoin(BitcoinNetwork::Signet),
    };
    assert!(matches!(
        derivation_path(forged_scope, AddressKind::P2tr, 0, 0, 0),
        Err(BitcoinAdapterError::MismatchedChainNetwork { .. })
    ));

    assert!(matches!(
        derivation_path(
            bitcoin(BitcoinNetwork::Signet),
            AddressKind::P2tr,
            1 << 31,
            0,
            0
        ),
        Err(BitcoinAdapterError::InvalidDerivationIndex {
            field: "account",
            ..
        })
    ));

    let stale_scope = ChainScope {
        schema_version: 0,
        chain: ChainId::Bitcoin,
        network: ChainNetwork::Bitcoin(BitcoinNetwork::Signet),
    };
    assert!(matches!(
        derivation_path(stale_scope, AddressKind::P2tr, 0, 0, 0),
        Err(BitcoinAdapterError::UnsupportedScopeSchemaVersion { .. })
    ));
}

#[test]
fn signing_suites_declare_frost_without_owning_a_frost_implementation() {
    let bitcoin = BitcoinSigningSuite::new(bitcoin(BitcoinNetwork::Signet)).expect("test suite");
    assert_eq!(
        bitcoin.descriptor().id,
        SigningSuiteId::BITCOIN_BIP340_FROST_V1
    );
    assert_eq!(
        bitcoin.descriptor().backend_requirement,
        SignerBackendRequirement::FrostSecp256k1Tr
    );

    let fractal = BitcoinSigningSuite::new(fractal_scope(FractalBitcoinNetwork::Signet))
        .expect("Fractal test suite");
    assert_eq!(
        fractal.descriptor().id,
        SigningSuiteId::FRACTAL_BITCOIN_BIP340_FROST_V1
    );
    assert_eq!(
        fractal.descriptor().backend_requirement,
        SignerBackendRequirement::FrostSecp256k1Tr
    );
    assert!(!bitcoin.supports(&fractal_for_bitcoin_network(BitcoinNetwork::Signet)));
}

#[test]
fn mainnet_chain_and_signing_suites_are_not_activated() {
    let key = bitcoin::XOnlyPublicKey::from_str(
        "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
    )
    .expect("BIP86 output key");

    assert!(matches!(
        BitcoinChainSuite::new(bitcoin(BitcoinNetwork::Mainnet), key),
        Err(BitcoinAdapterError::MainnetNotActivated { .. })
    ));
    assert!(matches!(
        BitcoinSigningSuite::new(fractal_scope(FractalBitcoinNetwork::Mainnet)),
        Err(BitcoinAdapterError::MainnetNotActivated { .. })
    ));
}

// Keep this helper separate so the test above catches accidental cross-family API coercion.
fn fractal_for_bitcoin_network(network: BitcoinNetwork) -> ChainScope {
    let network = match network {
        BitcoinNetwork::Mainnet => FractalBitcoinNetwork::Mainnet,
        BitcoinNetwork::Testnet3 => FractalBitcoinNetwork::Testnet3,
        BitcoinNetwork::Testnet4 => FractalBitcoinNetwork::Testnet4,
        BitcoinNetwork::Signet => FractalBitcoinNetwork::Signet,
        BitcoinNetwork::Regtest => FractalBitcoinNetwork::Regtest,
    };
    ChainScope::for_network(ChainNetwork::FractalBitcoin(network))
}

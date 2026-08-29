use std::str::FromStr;

use bitcoin::{CompressedPublicKey, XOnlyPublicKey};
use catomicals_chain_bitcoin::{
    AddressKind, BitcoinAdapterError, derive_p2tr_address, derive_p2wpkh_address, parse_address,
};
use catomicals_chain_domain::{BitcoinNetwork, ChainNetwork, ChainScope, FractalBitcoinNetwork};

fn bitcoin(network: BitcoinNetwork) -> ChainScope {
    ChainScope::for_network(ChainNetwork::Bitcoin(network))
}

fn fractal(network: FractalBitcoinNetwork) -> ChainScope {
    ChainScope::for_network(ChainNetwork::FractalBitcoin(network))
}

fn bip84_pubkey() -> CompressedPublicKey {
    CompressedPublicKey::from_str(
        "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c",
    )
    .expect("BIP84 vector key")
}

fn bip86_internal_key() -> XOnlyPublicKey {
    XOnlyPublicKey::from_str("cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115")
        .expect("BIP86 vector key")
}

#[test]
fn matches_official_bip84_and_bip86_mainnet_vectors() {
    let p2wpkh = derive_p2wpkh_address(bitcoin(BitcoinNetwork::Mainnet), &bip84_pubkey())
        .expect("BIP84 address");
    assert_eq!(
        p2wpkh.to_string(),
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
    );

    let p2tr = derive_p2tr_address(bitcoin(BitcoinNetwork::Mainnet), bip86_internal_key())
        .expect("BIP86 address");
    assert_eq!(
        p2tr.to_string(),
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
    );
    assert_eq!(
        hex::encode(p2tr.script_pubkey().as_bytes()),
        "5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
    );
}

#[test]
fn covers_every_bitcoin_network_hrp_without_signet_hardcoding() {
    let cases = [
        (BitcoinNetwork::Mainnet, "bc1p"),
        (BitcoinNetwork::Testnet3, "tb1p"),
        (BitcoinNetwork::Testnet4, "tb1p"),
        (BitcoinNetwork::Signet, "tb1p"),
        (BitcoinNetwork::Regtest, "bcrt1p"),
    ];

    for (network, prefix) in cases {
        let address = derive_p2tr_address(bitcoin(network), bip86_internal_key())
            .expect("supported Bitcoin network");
        assert!(address.to_string().starts_with(prefix), "{network:?}");
        assert_eq!(address.scope(), bitcoin(network));
    }
}

#[test]
fn fractal_prefixes_match_the_official_node_profiles() {
    // Official source pinned at fractal-bitcoin/fractal
    // 8c22167f04250c7dd03afe46af4158bd08001183, src/kernel/chainparams.cpp.
    let cases = [
        (FractalBitcoinNetwork::Mainnet, "bc1q"),
        // Fractal's official node deliberately uses mainnet prefixes on testnet3.
        (FractalBitcoinNetwork::Testnet3, "bc1q"),
        (FractalBitcoinNetwork::Testnet4, "tb1q"),
        (FractalBitcoinNetwork::Signet, "tb1q"),
        (FractalBitcoinNetwork::Regtest, "bcrt1q"),
    ];

    for (network, prefix) in cases {
        let address = derive_p2wpkh_address(fractal(network), &bip84_pubkey())
            .expect("supported Fractal network");
        assert!(address.to_string().starts_with(prefix), "{network:?}");
        if network == FractalBitcoinNetwork::Testnet3 {
            assert_eq!(
                address.to_string(),
                "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
            );
        }
    }
}

#[test]
fn identical_address_text_remains_bound_to_chain_and_concrete_network() {
    let bitcoin_address =
        derive_p2tr_address(bitcoin(BitcoinNetwork::Signet), bip86_internal_key())
            .expect("Bitcoin address");
    let fractal_address =
        derive_p2tr_address(fractal(FractalBitcoinNetwork::Signet), bip86_internal_key())
            .expect("Fractal address");
    assert_eq!(bitcoin_address.to_string(), fractal_address.to_string());
    assert_ne!(bitcoin_address.scope(), fractal_address.scope());

    assert!(matches!(
        bitcoin_address.require_scope(fractal(FractalBitcoinNetwork::Signet)),
        Err(BitcoinAdapterError::ScopeMismatch { .. })
    ));
    assert!(matches!(
        bitcoin_address.require_scope(bitcoin(BitcoinNetwork::Testnet4)),
        Err(BitcoinAdapterError::ScopeMismatch { .. })
    ));
}

#[test]
fn strict_parser_rejects_wrong_hrp_and_wrong_address_kind() {
    let mainnet = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
    assert!(matches!(
        parse_address(
            bitcoin(BitcoinNetwork::Testnet4),
            AddressKind::P2wpkh,
            mainnet
        ),
        Err(BitcoinAdapterError::InvalidAddressNetwork { .. })
    ));
    assert!(matches!(
        parse_address(bitcoin(BitcoinNetwork::Mainnet), AddressKind::P2tr, mainnet),
        Err(BitcoinAdapterError::UnexpectedAddressKind { .. })
    ));
}

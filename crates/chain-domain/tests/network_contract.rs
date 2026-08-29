use std::str::FromStr;

use catomicals_chain_domain::{
    BitcoinCashNetwork, BitcoinNetwork, BsvNetwork, ChainId, ChainNetwork, ChainScope, ChiaNetwork,
    ErgoNetwork, FractalBitcoinNetwork, KaspaNetwork, RpcPresetId,
};

#[test]
fn chain_ids_are_the_seven_stable_product_ids() {
    let ids = ChainId::ALL.map(|chain| chain.to_string());
    assert_eq!(
        ids,
        [
            "bitcoin",
            "bitcoin-cash",
            "bsv",
            "fractal-bitcoin",
            "kaspa",
            "chia",
            "ergo",
        ]
    );

    for chain in ChainId::ALL {
        let json = serde_json::to_string(&chain).unwrap();
        assert_eq!(serde_json::from_str::<ChainId>(&json).unwrap(), chain);
        assert_eq!(ChainId::from_str(chain.as_str()).unwrap(), chain);
    }
}

#[test]
fn concrete_networks_keep_consensus_identity() {
    let networks = [
        ChainNetwork::Bitcoin(BitcoinNetwork::Testnet3),
        ChainNetwork::Bitcoin(BitcoinNetwork::Testnet4),
        ChainNetwork::BitcoinCash(BitcoinCashNetwork::Testnet3),
        ChainNetwork::BitcoinCash(BitcoinCashNetwork::Testnet4),
        ChainNetwork::BitcoinCash(BitcoinCashNetwork::Scalenet),
        ChainNetwork::Bsv(BsvNetwork::Stn),
        ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Testnet3),
        ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Testnet4),
        ChainNetwork::Kaspa(KaspaNetwork::Testnet10),
        ChainNetwork::Kaspa(KaspaNetwork::Testnet11),
        ChainNetwork::Kaspa(KaspaNetwork::Simnet),
        ChainNetwork::Kaspa(KaspaNetwork::Devnet),
        ChainNetwork::Chia(ChiaNetwork::Testnet11),
    ];

    let names = networks.map(|network| network.to_string());
    assert_eq!(
        names,
        [
            "bitcoin.testnet3",
            "bitcoin.testnet4",
            "bitcoin-cash.testnet3",
            "bitcoin-cash.testnet4",
            "bitcoin-cash.scalenet",
            "bsv.stn",
            "fractal-bitcoin.testnet3",
            "fractal-bitcoin.testnet4",
            "kaspa.testnet10",
            "kaspa.testnet11",
            "kaspa.simnet",
            "kaspa.devnet",
            "chia.testnet11",
        ]
    );

    for network in networks {
        let json = serde_json::to_string(&network).unwrap();
        assert_eq!(
            serde_json::from_str::<ChainNetwork>(&json).unwrap(),
            network
        );
        assert_eq!(ChainNetwork::from_str(network.as_str()).unwrap(), network);
    }
}

#[test]
fn generic_network_names_and_rpc_preset_ids_are_not_chain_networks() {
    for invalid in [
        "mainnet",
        "testnet",
        "signet",
        "regtest",
        "bitcoin-testnet3",
        "bitcoin-inquisition",
        "kaspa-testnet-11",
        "chia-testnet11",
    ] {
        assert!(
            ChainNetwork::from_str(invalid).is_err(),
            "{invalid} must not be accepted as a consensus network identity"
        );
    }

    assert_eq!(
        RpcPresetId::from_str("bitcoin-testnet3").unwrap(),
        RpcPresetId::BitcoinTestnet3
    );
    assert_eq!(
        RpcPresetId::from_str("kaspa-testnet-11").unwrap(),
        RpcPresetId::KaspaTestnet11
    );
}

#[test]
fn every_rpc_preset_maps_to_one_concrete_network() {
    for preset in RpcPresetId::ALL {
        let network = preset.chain_network();
        assert_eq!(preset.chain_id(), network.chain_id());
        assert_eq!(RpcPresetId::from_str(preset.as_str()).unwrap(), preset);
    }

    assert_eq!(
        RpcPresetId::BitcoinInquisition.chain_network(),
        ChainNetwork::Bitcoin(BitcoinNetwork::Signet)
    );
    assert_eq!(
        RpcPresetId::BitcoinCashChipnet.chain_network(),
        ChainNetwork::BitcoinCash(BitcoinCashNetwork::Chipnet)
    );
    assert_eq!(
        RpcPresetId::BitcoinCashScalenet.chain_network(),
        ChainNetwork::BitcoinCash(BitcoinCashNetwork::Scalenet)
    );
    assert_eq!(
        RpcPresetId::BsvTestnet.chain_network(),
        ChainNetwork::Bsv(BsvNetwork::Testnet)
    );
    assert_eq!(
        RpcPresetId::BsvStn.chain_network(),
        ChainNetwork::Bsv(BsvNetwork::Stn)
    );
    assert_eq!(
        RpcPresetId::KaspaSimnet.chain_network(),
        ChainNetwork::Kaspa(KaspaNetwork::Simnet)
    );
    assert_eq!(
        RpcPresetId::KaspaDevnet.chain_network(),
        ChainNetwork::Kaspa(KaspaNetwork::Devnet)
    );
    assert_eq!(
        RpcPresetId::ErgoTestnet.chain_network(),
        ChainNetwork::Ergo(ErgoNetwork::Testnet)
    );
}

#[test]
fn chain_scope_rejects_a_mismatched_chain_and_never_falls_back_to_bitcoin() {
    let network = ChainNetwork::Chia(ChiaNetwork::Testnet11);
    assert!(ChainScope::new(ChainId::Bitcoin, network).is_err());

    let scope = ChainScope::for_network(network);
    assert_eq!(scope.chain, ChainId::Chia);
    assert_eq!(scope.network, network);
    assert_eq!(scope.schema_version, 1);
}

#[test]
fn chain_scope_deserialization_revalidates_version_and_chain_network_match() {
    assert!(
        serde_json::from_str::<ChainScope>(
            r#"{"schema_version":1,"chain":"bitcoin","network":"chia.testnet11"}"#
        )
        .is_err()
    );
    assert!(
        serde_json::from_str::<ChainScope>(
            r#"{"schema_version":2,"chain":"bitcoin","network":"bitcoin.signet"}"#
        )
        .is_err()
    );
}

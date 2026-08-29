use std::str::FromStr;

use catomicals_chain_bitcoin_cash::{
    Address, AddressKind, AddressNetwork, Bip44Path, BitcoinCashNetwork, Error,
};

const HASH: [u8; 20] = [
    0xf5, 0xbf, 0x48, 0xb3, 0x97, 0xda, 0xe7, 0x0b, 0xe8, 0x2b, 0x3c, 0xca, 0x47, 0x93, 0xf8, 0xeb,
    0x2b, 0x6c, 0xda, 0xc9,
];

const NETWORKS: [BitcoinCashNetwork; 6] = [
    BitcoinCashNetwork::Mainnet,
    BitcoinCashNetwork::Testnet3,
    BitcoinCashNetwork::Testnet4,
    BitcoinCashNetwork::Scalenet,
    BitcoinCashNetwork::Chipnet,
    BitcoinCashNetwork::Regtest,
];

#[test]
fn cashaddr_matches_bitcoincash_org_vectors() {
    let mainnet = Address::new(BitcoinCashNetwork::Mainnet, AddressKind::P2pkh, HASH);
    assert_eq!(
        mainnet.to_cashaddr().unwrap(),
        "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2"
    );

    let testnet = Address::new(BitcoinCashNetwork::Testnet3, AddressKind::P2sh, HASH);
    assert_eq!(
        testnet.to_cashaddr().unwrap(),
        "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t"
    );
}

#[test]
fn cashaddr_round_trips_every_supported_network() {
    for network in NETWORKS {
        for kind in [AddressKind::P2pkh, AddressKind::P2sh] {
            let address = Address::new(network, kind, HASH);
            let encoded = address.to_cashaddr().unwrap();
            assert_eq!(Address::parse_cashaddr(network, &encoded), Ok(address));
        }
    }
}

#[test]
fn cashaddr_parses_prefixless_and_uniform_uppercase_forms() {
    let address = Address::new(BitcoinCashNetwork::Mainnet, AddressKind::P2pkh, HASH);
    let encoded = address.to_cashaddr().unwrap();
    let prefixless = encoded.split_once(':').unwrap().1;
    assert_eq!(
        Address::parse_cashaddr(BitcoinCashNetwork::Mainnet, prefixless),
        Ok(address)
    );
    assert_eq!(
        Address::parse_cashaddr(BitcoinCashNetwork::Mainnet, &encoded.to_ascii_uppercase()),
        Ok(address)
    );
}

#[test]
fn cashaddr_rejects_wrong_prefix_mixed_case_and_bad_checksum() {
    let mainnet = Address::new(BitcoinCashNetwork::Mainnet, AddressKind::P2pkh, HASH);
    let encoded = mainnet.to_cashaddr().unwrap();

    assert!(matches!(
        Address::parse_cashaddr(BitcoinCashNetwork::Testnet4, &encoded),
        Err(Error::WrongNetwork { .. })
    ));
    assert!(matches!(
        Address::parse_cashaddr(
            BitcoinCashNetwork::Mainnet,
            "bitcoincash:Qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2"
        ),
        Err(Error::MixedCaseAddress)
    ));
    let mut damaged = encoded.into_bytes();
    *damaged.last_mut().unwrap() = b'q';
    assert!(matches!(
        Address::parse_cashaddr(
            BitcoinCashNetwork::Mainnet,
            std::str::from_utf8(&damaged).unwrap()
        ),
        Err(Error::InvalidChecksum)
    ));
}

#[test]
fn legacy_round_trips_and_rejects_mainnet_testnet_confusion() {
    for network in NETWORKS {
        for kind in [AddressKind::P2pkh, AddressKind::P2sh] {
            let address = Address::new(network, kind, HASH);
            let encoded = address.to_legacy();
            let parsed = Address::parse_legacy(network, &encoded).unwrap();
            assert_eq!(parsed.kind, address.kind);
            assert_eq!(parsed.hash, address.hash);
            assert_eq!(parsed.to_legacy(), encoded);
        }
    }

    let mainnet = Address::new(BitcoinCashNetwork::Mainnet, AddressKind::P2sh, HASH);
    assert!(matches!(
        Address::parse_legacy(BitcoinCashNetwork::Chipnet, &mainnet.to_legacy()),
        Err(Error::WrongNetwork { .. })
    ));
}

#[test]
fn test_family_addresses_do_not_claim_an_exact_network_identity() {
    let encoded = Address::new(BitcoinCashNetwork::Testnet3, AddressKind::P2pkh, HASH)
        .to_cashaddr()
        .unwrap();
    let parsed = Address::parse_cashaddr(BitcoinCashNetwork::Chipnet, &encoded).unwrap();

    assert_eq!(parsed.network, AddressNetwork::TestFamily);
    assert!(matches!(
        parsed.require_exact_network(BitcoinCashNetwork::Chipnet),
        Err(Error::AmbiguousAddressNetwork)
    ));
}

#[test]
fn legacy_non_mainnet_addresses_are_explicitly_ambiguous_with_regtest() {
    let encoded = Address::new(BitcoinCashNetwork::Regtest, AddressKind::P2pkh, HASH).to_legacy();
    let parsed = Address::parse_legacy(BitcoinCashNetwork::Regtest, &encoded).unwrap();

    assert_eq!(parsed.network, AddressNetwork::LegacyNonMainnet);
    assert!(matches!(
        parsed.require_exact_network(BitcoinCashNetwork::Regtest),
        Err(Error::AmbiguousAddressNetwork)
    ));
    assert!(matches!(
        parsed.to_cashaddr(),
        Err(Error::AmbiguousAddressNetwork)
    ));
}

#[test]
fn p2pkh_from_compressed_public_key_uses_hash160() {
    let public_key =
        hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
    let address = Address::p2pkh_from_public_key(BitcoinCashNetwork::Mainnet, &public_key).unwrap();
    assert_eq!(address.to_legacy(), "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
}

#[test]
fn p2sh_from_redeem_script_uses_hash160() {
    let address = Address::p2sh_from_redeem_script(BitcoinCashNetwork::Mainnet, &[0x51]);
    let expected: [u8; 20] = hex::decode("da1745e9b549bd0bfa1a569971c77eba30cd5a4b")
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(address.hash, expected);
    assert_eq!(address.kind, AddressKind::P2sh);
}

#[test]
fn bip44_path_fixes_coin_type_145_and_validates_indices() {
    let path = Bip44Path::new(7, 1, 99).unwrap();
    assert_eq!(path.to_string(), "m/44'/145'/7'/1/99");
    assert_eq!(Bip44Path::from_str(&path.to_string()), Ok(path));
    assert_eq!(Bip44Path::COIN_TYPE, 145);

    assert!(matches!(
        Bip44Path::new(0, 2, 0),
        Err(Error::InvalidChange(2))
    ));
    assert!(Bip44Path::new(1 << 31, 0, 0).is_err());
    assert!(Bip44Path::new(0, 0, 1 << 31).is_err());
    assert!(Bip44Path::from_str("m/44'/0'/0'/0/0").is_err());
}

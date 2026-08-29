use catomicals_chain_domain::KaspaNetwork;
use catomicals_chain_kaspa::{
    AddressKind, DerivationBranch, KASPA_COIN_TYPE, derive_multisig_path, derive_single_sig_path,
    encode_address, parse_address,
};

const X_ONLY_VECTOR: [u8; 32] = [
    0x5f, 0xff, 0x3c, 0x4d, 0xa1, 0x8f, 0x45, 0xad, 0xcd, 0xd4, 0x99, 0xe4, 0x46, 0x11, 0xe9, 0xff,
    0xf1, 0x48, 0xba, 0x69, 0xdb, 0x3c, 0x4e, 0xa2, 0xdd, 0xd9, 0x55, 0xfc, 0x46, 0xa5, 0x95, 0x22,
];

const ECDSA_VECTOR: [u8; 33] = [
    0xba, 0x01, 0xfc, 0x5f, 0x4e, 0x9d, 0x98, 0x79, 0x59, 0x9c, 0x69, 0xa3, 0xda, 0xfd, 0xb8, 0x35,
    0xa7, 0x25, 0x5e, 0x5f, 0x2e, 0x93, 0x4e, 0x93, 0x22, 0xec, 0xd3, 0xaf, 0x19, 0x0a, 0xb0, 0xf6,
    0x0e,
];

#[test]
fn official_pubkey_vectors_round_trip() {
    let mainnet = encode_address(
        KaspaNetwork::Mainnet,
        AddressKind::PubKeyXOnly,
        &X_ONLY_VECTOR,
    )
    .expect("official mainnet x-only vector");
    assert_eq!(
        mainnet,
        "kaspa:qp0l70zd5x85ttwd6jv7g3s3a8llzj96d8dncn4zmhv4tlzx5k2jyqh70xmfj"
    );
    assert_eq!(
        parse_address(KaspaNetwork::Mainnet, &mainnet)
            .unwrap()
            .payload(),
        X_ONLY_VECTOR
    );

    let testnet = encode_address(
        KaspaNetwork::Testnet10,
        AddressKind::PubKeyEcdsa,
        &ECDSA_VECTOR,
    )
    .expect("official testnet ECDSA vector");
    assert_eq!(
        testnet,
        "kaspatest:qxaqrlzlf6wes72en3568khahq66wf27tuhfxn5nytkd8tcep2c0vrse6gdmpks"
    );
    assert_eq!(
        parse_address(KaspaNetwork::Testnet11, &testnet)
            .unwrap()
            .kind(),
        AddressKind::PubKeyEcdsa
    );
}

#[test]
fn every_supported_network_uses_the_official_prefix() {
    let cases = [
        (KaspaNetwork::Mainnet, "kaspa:"),
        (KaspaNetwork::Testnet10, "kaspatest:"),
        (KaspaNetwork::Testnet11, "kaspatest:"),
        (KaspaNetwork::Simnet, "kaspasim:"),
        (KaspaNetwork::Devnet, "kaspadev:"),
    ];

    for (network, prefix) in cases {
        for (kind, payload) in [
            (AddressKind::PubKeyXOnly, vec![0x11; 32]),
            (AddressKind::PubKeyEcdsa, vec![0x02; 33]),
            (AddressKind::ScriptHash, vec![0x22; 32]),
        ] {
            let encoded = encode_address(network, kind, &payload).unwrap();
            assert!(encoded.starts_with(prefix), "{network:?} {kind:?}");
            let parsed = parse_address(network, &encoded).unwrap();
            assert_eq!(parsed.network(), network);
            assert_eq!(parsed.kind(), kind);
            assert_eq!(parsed.payload(), payload.as_slice());
        }
    }
}

#[test]
fn parsing_rejects_a_different_network_prefix_and_invalid_payload_lengths() {
    let mainnet =
        encode_address(KaspaNetwork::Mainnet, AddressKind::PubKeyXOnly, &[0x33; 32]).unwrap();
    assert!(parse_address(KaspaNetwork::Simnet, &mainnet).is_err());

    assert!(encode_address(KaspaNetwork::Mainnet, AddressKind::PubKeyXOnly, &[0; 31]).is_err());
    assert!(encode_address(KaspaNetwork::Mainnet, AddressKind::PubKeyEcdsa, &[0; 32]).is_err());
    assert!(encode_address(KaspaNetwork::Mainnet, AddressKind::ScriptHash, &[0; 33]).is_err());
}

#[test]
fn official_coin_type_and_paths_are_explicit() {
    assert_eq!(KASPA_COIN_TYPE, 111_111);
    assert_eq!(
        derive_single_sig_path(0, DerivationBranch::Receive, 0).unwrap(),
        "m/44'/111111'/0'/0/0"
    );
    assert_eq!(
        derive_single_sig_path(7, DerivationBranch::Change, 19).unwrap(),
        "m/44'/111111'/7'/1/19"
    );
    assert_eq!(
        derive_multisig_path(2, 5, DerivationBranch::Receive, 9).unwrap(),
        "m/45'/111111'/2'/5/0/9"
    );
}

#[test]
fn derivation_indices_cannot_cross_into_the_hardened_range() {
    const HARDENED: u32 = 1 << 31;
    assert!(derive_single_sig_path(HARDENED, DerivationBranch::Receive, 0).is_err());
    assert!(derive_single_sig_path(0, DerivationBranch::Receive, HARDENED).is_err());
    assert!(derive_multisig_path(0, HARDENED, DerivationBranch::Receive, 0).is_err());
}

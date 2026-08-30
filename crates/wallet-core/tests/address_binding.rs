use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use catomicals_chain_bitcoin::{derive_p2tr_output_key_address, derive_p2wpkh_address};
use catomicals_chain_chia::{
    ThresholdBlsDealerKeyKind, dealer_split_threshold_secret_2_of_3, encode_puzzle_hash,
    standard_threshold_puzzle_hash,
};
use catomicals_chain_domain::{
    BitcoinCashNetwork, BitcoinNetwork, BsvNetwork, ChainNetwork, ChainScope, ChiaNetwork,
    ErgoNetwork, FractalBitcoinNetwork, KaspaNetwork,
};
#[cfg(feature = "seven-chain-addresses")]
use catomicals_chain_kaspa::AddressKind as KaspaAddressKind;
use catomicals_signing_domain::{SignerBackendRequirement, SigningSuiteId};
use catomicals_wallet::{AddressBinding, SignerProfile};
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn compressed_key(seed: u8) -> [u8; 33] {
    let secret = SecretKey::from_slice(&[seed; 32]).unwrap();
    PublicKey::from_secret_key(&Secp256k1::new(), &secret).serialize()
}

fn x_only_key(seed: u8) -> [u8; 32] {
    let secret = SecretKey::from_slice(&[seed; 32]).unwrap();
    let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
    XOnlyPublicKey::from_keypair(&keypair).0.serialize()
}

fn chia_group_key(seed: u8) -> [u8; 48] {
    dealer_split_threshold_secret_2_of_3(
        ThresholdBlsDealerKeyKind::FinalSigningKey,
        [seed; 32],
        [seed + 1; 32],
    )
    .unwrap()
    .commitment()
    .group_public_key()
}

fn profile(
    network: ChainNetwork,
    suite: SigningSuiteId,
    backend: SignerBackendRequirement,
    verification_key: Vec<u8>,
) -> SignerProfile {
    SignerProfile::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        ChainScope::for_network(network),
        suite,
        backend,
        "address-binding-vectors".to_owned(),
        "participant-1".to_owned(),
        1,
        2,
        3,
        verification_key,
        "encrypted-file://address-binding/share-1".to_owned(),
    )
    .unwrap()
}

fn binding(profile: &SignerProfile, address: &str) -> Result<AddressBinding, String> {
    AddressBinding::new(Uuid::new_v4(), profile, address.to_owned())
        .map_err(|error| error.to_string())
}

#[test]
fn bitcoin_frost_binds_the_profile_output_key_and_network() {
    let profile = profile(
        ChainNetwork::Bitcoin(BitcoinNetwork::Signet),
        SigningSuiteId::BITCOIN_BIP340_FROST_V1,
        SignerBackendRequirement::FrostSecp256k1Tr,
        x_only_key(1).to_vec(),
    );
    let expected = derive_p2tr_output_key_address(
        profile.chain_scope,
        XOnlyPublicKey::from_slice(&profile.verification_key).unwrap(),
    )
    .unwrap()
    .to_string();
    let other_key = derive_p2tr_output_key_address(
        profile.chain_scope,
        XOnlyPublicKey::from_slice(&x_only_key(2)).unwrap(),
    )
    .unwrap()
    .to_string();
    let wrong_network = derive_p2tr_output_key_address(
        ChainScope::for_network(ChainNetwork::Bitcoin(BitcoinNetwork::Mainnet)),
        XOnlyPublicKey::from_slice(&profile.verification_key).unwrap(),
    )
    .unwrap()
    .to_string();

    let bound = binding(&profile, &expected).unwrap();
    let expected_digest: [u8; 32] = Sha256::digest(&profile.verification_key).into();
    assert_eq!(bound.verification_key_digest(), expected_digest);
    assert!(binding(&profile, &other_key).is_err());
    assert!(binding(&profile, &wrong_network).is_err());

    let compressed =
        bitcoin::CompressedPublicKey(PublicKey::from_slice(compressed_key(1).as_slice()).unwrap());
    let wrong_kind = derive_p2wpkh_address(profile.chain_scope, &compressed)
        .unwrap()
        .to_string();
    assert!(binding(&profile, &wrong_kind).is_err());
}

#[test]
fn fractal_frost_binds_the_profile_output_key_and_network() {
    let profile = profile(
        ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Signet),
        SigningSuiteId::FRACTAL_BITCOIN_BIP340_FROST_V1,
        SignerBackendRequirement::FrostSecp256k1Tr,
        x_only_key(3).to_vec(),
    );
    let address_for = |scope, key: &[u8]| {
        derive_p2tr_output_key_address(scope, XOnlyPublicKey::from_slice(key).unwrap())
            .unwrap()
            .to_string()
    };
    let expected = address_for(profile.chain_scope, &profile.verification_key);
    let other_key = address_for(profile.chain_scope, &x_only_key(4));
    let wrong_network = address_for(
        ChainScope::for_network(ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Mainnet)),
        &profile.verification_key,
    );

    assert!(binding(&profile, &expected).is_ok());
    assert!(binding(&profile, &other_key).is_err());
    assert!(binding(&profile, &wrong_network).is_err());
}

#[cfg(not(feature = "seven-chain-addresses"))]
#[test]
fn optional_chain_address_binding_fails_closed_without_validators() {
    let cases = [
        (
            profile(
                ChainNetwork::BitcoinCash(BitcoinCashNetwork::Mainnet),
                SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1,
                SignerBackendRequirement::CbMpcThresholdEcdsa,
                compressed_key(5).to_vec(),
            ),
            "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",
        ),
        (
            profile(
                ChainNetwork::Bsv(BsvNetwork::Mainnet),
                SigningSuiteId::BSV_ECDSA_CB_MPC_V1,
                SignerBackendRequirement::CbMpcThresholdEcdsa,
                compressed_key(7).to_vec(),
            ),
            "1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i",
        ),
        (
            profile(
                ChainNetwork::Kaspa(KaspaNetwork::Mainnet),
                SigningSuiteId::KASPA_ECDSA_CB_MPC_V1,
                SignerBackendRequirement::CbMpcThresholdEcdsa,
                compressed_key(9).to_vec(),
            ),
            "kaspa:qp0l70zd5x85ttwd6jv7g3s3a8llzj96d8dncn4zmhv4tlzx5k2jyqh70xmfj",
        ),
    ];

    for (profile, address) in cases {
        assert!(binding(&profile, address).is_err());
    }
}

#[cfg(feature = "seven-chain-addresses")]
#[test]
fn bitcoin_cash_binds_the_profile_key_with_explicit_test_family_scope() {
    let profile = profile(
        ChainNetwork::BitcoinCash(BitcoinCashNetwork::Chipnet),
        SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1,
        SignerBackendRequirement::CbMpcThresholdEcdsa,
        compressed_key(5).to_vec(),
    );
    let address_for = |network, key: &[u8]| {
        catomicals_chain_bitcoin_cash::Address::p2pkh_from_public_key(network, key)
            .unwrap()
            .to_cashaddr()
            .unwrap()
    };
    let expected = address_for(BitcoinCashNetwork::Chipnet, &profile.verification_key);
    let other_key = address_for(BitcoinCashNetwork::Chipnet, &compressed_key(6));
    let wrong_network = address_for(BitcoinCashNetwork::Mainnet, &profile.verification_key);

    assert!(binding(&profile, &expected).is_ok());
    assert!(binding(&profile, &other_key).is_err());
    assert!(binding(&profile, &wrong_network).is_err());
}

#[cfg(feature = "seven-chain-addresses")]
#[test]
fn bsv_binds_the_profile_key_with_explicit_test_family_scope() {
    let profile = profile(
        ChainNetwork::Bsv(BsvNetwork::Testnet),
        SigningSuiteId::BSV_ECDSA_CB_MPC_V1,
        SignerBackendRequirement::CbMpcThresholdEcdsa,
        compressed_key(7).to_vec(),
    );
    let address_for = |network, key: &[u8]| {
        catomicals_chain_bsv::Address::p2pkh_from_public_key(network, key)
            .unwrap()
            .to_string()
    };
    let expected = address_for(BsvNetwork::Testnet, &profile.verification_key);
    let other_key = address_for(BsvNetwork::Testnet, &compressed_key(8));
    let wrong_network = address_for(BsvNetwork::Mainnet, &profile.verification_key);

    assert!(binding(&profile, &expected).is_ok());
    assert!(binding(&profile, &other_key).is_err());
    assert!(binding(&profile, &wrong_network).is_err());
}

#[cfg(feature = "seven-chain-addresses")]
#[test]
fn kaspa_ecdsa_binds_the_profile_key_kind_and_network() {
    let profile = profile(
        ChainNetwork::Kaspa(KaspaNetwork::Testnet11),
        SigningSuiteId::KASPA_ECDSA_CB_MPC_V1,
        SignerBackendRequirement::CbMpcThresholdEcdsa,
        compressed_key(9).to_vec(),
    );
    let address_for = |network, key: &[u8]| {
        catomicals_chain_kaspa::encode_address(network, KaspaAddressKind::PubKeyEcdsa, key).unwrap()
    };
    let expected = address_for(KaspaNetwork::Testnet11, &profile.verification_key);
    let other_key = address_for(KaspaNetwork::Testnet11, &compressed_key(10));
    let wrong_network = address_for(KaspaNetwork::Mainnet, &profile.verification_key);

    assert!(binding(&profile, &expected).is_ok());
    assert!(binding(&profile, &other_key).is_err());
    assert!(binding(&profile, &wrong_network).is_err());
}

#[test]
fn chia_threshold_binds_the_profile_group_key_and_network() {
    let profile = profile(
        ChainNetwork::Chia(ChiaNetwork::Testnet11),
        SigningSuiteId::CHIA_BLS12381_AUG_THRESHOLD_2OF3_V1,
        SignerBackendRequirement::ChiaBlsAugThreshold2of3,
        chia_group_key(11).to_vec(),
    );
    let address_for = |scope, key: &[u8]| {
        let group_key: [u8; 48] = key.try_into().unwrap();
        encode_puzzle_hash(scope, standard_threshold_puzzle_hash(group_key).unwrap()).unwrap()
    };
    let expected = address_for(profile.chain_scope, &profile.verification_key);
    let other_key = address_for(profile.chain_scope, &chia_group_key(13));
    let wrong_network = address_for(
        ChainScope::for_network(ChainNetwork::Chia(ChiaNetwork::Mainnet)),
        &profile.verification_key,
    );

    assert!(binding(&profile, &expected).is_ok());
    assert!(binding(&profile, &other_key).is_err());
    assert!(binding(&profile, &wrong_network).is_err());
}

#[test]
fn ergo_threshold_binds_the_profile_p2pk_and_network() {
    let profile = profile(
        ChainNetwork::Ergo(ErgoNetwork::Testnet),
        SigningSuiteId::ERGO_SIGMA_P2PK_THRESHOLD_2OF3_V1,
        SignerBackendRequirement::ErgoSigmaP2pkThreshold2of3,
        compressed_key(15).to_vec(),
    );
    let address_for = |network, key: &[u8]| {
        catomicals_chain_ergo::p2pk_address(network, key)
            .unwrap()
            .to_string()
    };
    let expected = address_for(ErgoNetwork::Testnet, &profile.verification_key);
    let other_key = address_for(ErgoNetwork::Testnet, &compressed_key(16));
    let wrong_network = address_for(ErgoNetwork::Mainnet, &profile.verification_key);

    assert!(binding(&profile, &expected).is_ok());
    assert!(binding(&profile, &other_key).is_err());
    assert!(binding(&profile, &wrong_network).is_err());
}

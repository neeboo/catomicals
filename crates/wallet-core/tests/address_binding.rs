use std::str::FromStr;

use bitcoin::XOnlyPublicKey;
use catomicals_chain_bitcoin::derive_p2tr_address;
use catomicals_chain_domain::{
    BitcoinCashNetwork, BitcoinNetwork, BsvNetwork, ChainNetwork, ChainScope, ChiaNetwork,
    ErgoNetwork, FractalBitcoinNetwork, KaspaNetwork,
};
use catomicals_signing_domain::{SignerBackendRequirement, SigningSuiteId};
use catomicals_wallet::{AddressBinding, SignerProfile};
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn profile(
    network: ChainNetwork,
    suite: SigningSuiteId,
    backend: SignerBackendRequirement,
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
        vec![0x02; 33],
        "encrypted-file://address-binding/share-1".to_owned(),
    )
    .unwrap()
}

fn binding(profile: &SignerProfile, address: &str) -> Result<AddressBinding, String> {
    AddressBinding::new(Uuid::new_v4(), profile, address.to_owned())
        .map_err(|error| error.to_string())
}

#[test]
fn bitcoin_frost_accepts_only_p2tr_on_the_profile_network() {
    let profile = profile(
        ChainNetwork::Bitcoin(BitcoinNetwork::Signet),
        SigningSuiteId::BITCOIN_BIP340_FROST_V1,
        SignerBackendRequirement::FrostSecp256k1Tr,
    );
    let key = XOnlyPublicKey::from_str(
        "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
    )
    .unwrap();
    let valid = derive_p2tr_address(profile.chain_scope, key)
        .unwrap()
        .to_string();

    let bound = binding(&profile, &valid).unwrap();
    assert_eq!(
        bound.verification_key_digest,
        Sha256::digest(&profile.verification_key).as_slice()
    );
    assert!(
        binding(
            &profile,
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        )
        .is_err()
    );
    assert!(binding(&profile, "tb1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu").is_err());
}

#[test]
fn fractal_frost_accepts_only_p2tr_on_the_profile_network() {
    let profile = profile(
        ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Signet),
        SigningSuiteId::FRACTAL_BITCOIN_BIP340_FROST_V1,
        SignerBackendRequirement::FrostSecp256k1Tr,
    );
    let key = XOnlyPublicKey::from_str(
        "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
    )
    .unwrap();
    let valid = derive_p2tr_address(profile.chain_scope, key)
        .unwrap()
        .to_string();

    assert!(binding(&profile, &valid).is_ok());
    assert!(
        binding(
            &profile,
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        )
        .is_err()
    );
}

#[test]
fn bitcoin_cash_accepts_the_test_family_but_rejects_mainnet() {
    let profile = profile(
        ChainNetwork::BitcoinCash(BitcoinCashNetwork::Chipnet),
        SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1,
        SignerBackendRequirement::CbMpcThresholdEcdsa,
    );

    assert!(
        binding(
            &profile,
            "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t"
        )
        .is_ok()
    );
    assert!(
        binding(
            &profile,
            "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2"
        )
        .is_err()
    );
}

#[test]
fn bsv_accepts_the_non_mainnet_family_but_rejects_mainnet() {
    let profile = profile(
        ChainNetwork::Bsv(BsvNetwork::Testnet),
        SigningSuiteId::BSV_ECDSA_CB_MPC_V1,
        SignerBackendRequirement::CbMpcThresholdEcdsa,
    );

    assert!(binding(&profile, "mo9ncXisMeAoXwqcV5EWuyncbmCcQN4rVs").is_ok());
    assert!(binding(&profile, "1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i").is_err());
}

#[test]
fn kaspa_ecdsa_accepts_the_profile_prefix_and_key_kind() {
    let profile = profile(
        ChainNetwork::Kaspa(KaspaNetwork::Testnet11),
        SigningSuiteId::KASPA_ECDSA_CB_MPC_V1,
        SignerBackendRequirement::CbMpcThresholdEcdsa,
    );

    assert!(
        binding(
            &profile,
            "kaspatest:qxaqrlzlf6wes72en3568khahq66wf27tuhfxn5nytkd8tcep2c0vrse6gdmpks"
        )
        .is_ok()
    );
    assert!(
        binding(
            &profile,
            "kaspa:qp0l70zd5x85ttwd6jv7g3s3a8llzj96d8dncn4zmhv4tlzx5k2jyqh70xmfj"
        )
        .is_err()
    );
}

#[test]
fn chia_threshold_accepts_only_the_profile_hrp() {
    let profile = profile(
        ChainNetwork::Chia(ChiaNetwork::Testnet11),
        SigningSuiteId::CHIA_BLS12381_AUG_THRESHOLD_2OF3_V1,
        SignerBackendRequirement::ChiaBlsAugThreshold2of3,
    );

    assert!(
        binding(
            &profile,
            "txch1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqm6ksh7qddh"
        )
        .is_ok()
    );
    assert!(
        binding(
            &profile,
            "xch1pwrzyy35qxk0rz76jl0648fvt6ql905vwd7zs0scjqant5sf25lql4hz3z"
        )
        .is_err()
    );
}

#[test]
fn ergo_threshold_accepts_only_p2pk_on_the_profile_network() {
    let profile = profile(
        ChainNetwork::Ergo(ErgoNetwork::Testnet),
        SigningSuiteId::ERGO_SIGMA_P2PK_THRESHOLD_2OF3_V1,
        SignerBackendRequirement::ErgoSigmaP2pkThreshold2of3,
    );

    assert!(
        binding(
            &profile,
            "3WvsT2Gm4EpsM9Pg18PdY6XyhNNMqXDsvJTbbf6ihLvAmSb7u5RN"
        )
        .is_ok()
    );
    assert!(
        binding(
            &profile,
            "9fRAWhdxEsTcdb8PhGNrZfwqa65zfkuYHAMmkQLcic1gdLSV5vA"
        )
        .is_err()
    );
    assert!(binding(&profile, "Ms7smJwLGbUAjuWQ").is_err());
}

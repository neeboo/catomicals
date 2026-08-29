use std::str::FromStr;

use catomicals_chain_bsv::{
    Address, AddressNetworkResolution, AddressType, Bip44Path, BsvChainSuite, BsvError, BsvNetwork,
    BsvSigningRequest, ForkIdSighashType, Transaction, TxInput, TxOutput, append_sighash_byte,
    fork_id_sighash, sign_digest, verify_transaction_signature,
};
use catomicals_chain_domain::{ChainId, ChainSuite, ReviewArtifact};
use catomicals_signing_domain::{SignerBackendRequirement, SigningAlgorithm, SigningExecutionMode};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

fn sample_transaction() -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![
            TxInput {
                previous_txid_le: [0x11; 32],
                previous_output_index: 1,
                script_sig: vec![],
                sequence: 0xffff_fffe,
            },
            TxInput {
                previous_txid_le: [0x22; 32],
                previous_output_index: 0,
                script_sig: vec![],
                sequence: 0xffff_fffd,
            },
        ],
        outputs: vec![
            TxOutput {
                value_satoshis: 40_000,
                script_pubkey: decode_hex("76a91465a16059864a2fdbc7c99a4723a8395bc6f188eb88ac"),
            },
            TxOutput {
                value_satoshis: 9_000,
                script_pubkey: decode_hex("a91474f209f6ea907e2ea48f74fae05782ae8a66525787"),
            },
        ],
        lock_time: 42,
    }
}

#[test]
fn official_node_base58_vectors_cover_p2pkh_p2sh_and_all_networks() {
    // bitcoin-sv/bitcoin-sv src/test/data/base58_keys_valid.json.
    let main_p2pkh_payload = decode_hex("65a16059864a2fdbc7c99a4723a8395bc6f188eb");
    let main_p2sh_payload = decode_hex("74f209f6ea907e2ea48f74fae05782ae8a665257");
    let test_p2pkh_payload = decode_hex("53c0307d6851aa0ce7825ba883c6bd9ad242b486");
    let test_p2sh_payload = decode_hex("6349a418fc4578d10a372b54b45c280cc8c4382f");

    assert_eq!(
        Address::from_payload(BsvNetwork::Mainnet, AddressType::P2pkh, &main_p2pkh_payload)
            .unwrap()
            .to_string(),
        "1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i"
    );
    assert_eq!(
        Address::from_payload(BsvNetwork::Mainnet, AddressType::P2sh, &main_p2sh_payload)
            .unwrap()
            .to_string(),
        "3CMNFxN1oHBc4R1EpboAL5yzHGgE611Xou"
    );

    for network in [BsvNetwork::Testnet, BsvNetwork::Stn, BsvNetwork::Regtest] {
        assert_eq!(
            Address::from_payload(network, AddressType::P2pkh, &test_p2pkh_payload)
                .unwrap()
                .to_string(),
            "mo9ncXisMeAoXwqcV5EWuyncbmCcQN4rVs"
        );
        assert_eq!(
            Address::from_payload(network, AddressType::P2sh, &test_p2sh_payload)
                .unwrap()
                .to_string(),
            "2N2JD6wb56AfK4tfmM6PwdVmoYk2dCKf4Br"
        );
    }
}

#[test]
fn address_parsing_validates_the_declared_network_and_checksum() {
    let address =
        Address::parse_for_network("1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i", BsvNetwork::Mainnet)
            .unwrap();
    assert_eq!(address.address_type(), AddressType::P2pkh);
    assert_eq!(address.network(), BsvNetwork::Mainnet);

    assert!(
        Address::parse_for_network("1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i", BsvNetwork::Testnet)
            .is_err()
    );
    assert!(
        Address::parse_for_network("mo9ncXisMeAoXwqcV5EWuyncbmCcQN4rVs", BsvNetwork::Mainnet)
            .is_err()
    );
    assert!(
        Address::parse_for_network("1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62j", BsvNetwork::Mainnet)
            .is_err()
    );
}

#[test]
fn test_family_addresses_report_ambiguity_and_exact_network_checks_fail_closed() {
    let encoded = "mo9ncXisMeAoXwqcV5EWuyncbmCcQN4rVs";
    assert_eq!(
        Address::resolve_network(encoded).unwrap(),
        AddressNetworkResolution::Ambiguous {
            compatible_networks: [BsvNetwork::Testnet, BsvNetwork::Stn, BsvNetwork::Regtest,],
        }
    );

    for requested in [BsvNetwork::Testnet, BsvNetwork::Stn, BsvNetwork::Regtest] {
        assert!(matches!(
            Address::parse_for_network(encoded, requested),
            Err(BsvError::AmbiguousAddressNetwork {
                requested: actual,
                compatible_networks: [
                    BsvNetwork::Testnet,
                    BsvNetwork::Stn,
                    BsvNetwork::Regtest,
                ],
            }) if actual == requested
        ));
    }
}

#[test]
fn addresses_are_generated_from_secp256k1_keys_and_redeem_scripts() {
    let secret_key = SecretKey::from_slice(&[1; 32]).unwrap();
    let public_key = PublicKey::from_secret_key(&Secp256k1::new(), &secret_key);
    assert_eq!(
        Address::p2pkh_from_public_key(BsvNetwork::Mainnet, &public_key.serialize())
            .unwrap()
            .to_string(),
        "1C6Rc3w25VHud3dLDamutaqfKWqhrLRTaD"
    );
    assert_eq!(
        Address::p2sh_from_redeem_script(BsvNetwork::Mainnet, &[0x51])
            .unwrap()
            .to_string(),
        "3MaB7QVq3k4pQx3BhsvEADgzQonLSBwMdj"
    );
    assert!(Address::p2pkh_from_public_key(BsvNetwork::Mainnet, &[2; 32]).is_err());
}

#[test]
fn bip44_path_uses_registered_bsv_coin_type_236() {
    let path = Bip44Path::new(7, false, 19).unwrap();
    assert_eq!(Bip44Path::COIN_TYPE, 236);
    assert_eq!(
        path.components(),
        [0x8000_002c, 0x8000_00ec, 0x8000_0007, 0, 19]
    );
    assert_eq!(path.to_string(), "m/44'/236'/7'/0/19");
    assert_eq!(Bip44Path::from_str("m/44'/236'/7'/0/19").unwrap(), path);

    assert!(Bip44Path::from_str("m/44'/0'/7'/0/19").is_err());
    assert!(Bip44Path::new(1 << 31, false, 0).is_err());
    assert!(Bip44Path::new(0, false, 1 << 31).is_err());
}

#[test]
fn forkid_payload_signing_and_der_assembly_are_independently_verifiable() {
    let transaction = sample_transaction();
    let script_code = decode_hex("76a91465a16059864a2fdbc7c99a4723a8395bc6f188eb88ac");
    let sighash_type = ForkIdSighashType::ALL;
    let digest = fork_id_sighash(&transaction, 0, &script_code, 50_000, sighash_type).unwrap();

    // Fixed regression value produced from the BSV replay-protected-sighash serialization.
    assert_eq!(
        digest,
        <[u8; 32]>::try_from(decode_hex(
            "f47c713be2aa6aad092adccf369930d225e21fc786d6a17b72f1e6b43d0a0cf5"
        ))
        .unwrap()
    );

    let secret_key = SecretKey::from_slice(&[7; 32]).unwrap();
    let public_key = PublicKey::from_secret_key(&Secp256k1::new(), &secret_key);
    let signature = sign_digest(&secret_key, digest, sighash_type).unwrap();

    assert_eq!(signature.last().copied(), Some(0x41));
    verify_transaction_signature(&public_key, digest, &signature, sighash_type).unwrap();

    let mut wrong_digest = digest;
    wrong_digest[0] ^= 1;
    assert!(
        verify_transaction_signature(&public_key, wrong_digest, &signature, sighash_type).is_err()
    );

    let mut wrong_algorithm = signature.clone();
    *wrong_algorithm.last_mut().unwrap() = 0x01;
    assert!(
        verify_transaction_signature(&public_key, digest, &wrong_algorithm, sighash_type).is_err()
    );
}

#[test]
fn deserialization_rejects_non_forkid_and_unknown_sighash_algorithms() {
    assert!(serde_json::from_str::<ForkIdSighashType>("1").is_err());
    assert!(serde_json::from_str::<ForkIdSighashType>("64").is_err());
    assert!(serde_json::from_str::<ForkIdSighashType>("68").is_err());
    assert_eq!(
        serde_json::from_str::<ForkIdSighashType>("65").unwrap(),
        ForkIdSighashType::ALL
    );
}

#[test]
fn official_node_der_signature_keeps_its_forkid_byte() {
    // bitcoin-sv/bitcoin-sv src/test/data/script_tests.json, "P2PK FORKID".
    let der = decode_hex(
        "30440220368d68340dfbebf99d5ec87d77fba899763e466c0a7ab2fa0221fb868ab0f3ef0220266c1a52a8e5b7b597613b80cf53814d3925dfb6715dce712c8e7a25e63a0440",
    );
    let encoded = append_sighash_byte(&der, ForkIdSighashType::ALL).unwrap();
    assert_eq!(encoded.last().copied(), Some(0x41));
    assert_eq!(&encoded[..encoded.len() - 1], der);
}

#[test]
fn threshold_mode_requires_cb_mpc_ecdsa_and_rejects_frost() {
    let suite = BsvChainSuite::new(BsvNetwork::Mainnet, [2; 33]).unwrap();
    let threshold = suite
        .signing_descriptor(SigningExecutionMode::ThresholdInteractive)
        .unwrap();
    assert_eq!(threshold.algorithm, SigningAlgorithm::Secp256k1Ecdsa);
    assert_eq!(
        threshold.backend_requirement,
        SignerBackendRequirement::CbMpcThresholdEcdsa
    );
    let isolated = suite
        .signing_descriptor(SigningExecutionMode::SingleSignerIsolated)
        .unwrap();
    assert_eq!(
        isolated.backend_requirement,
        SignerBackendRequirement::IsolatedSecp256k1Ecdsa
    );
    assert!(
        suite
            .validate_backend_requirement(
                SigningExecutionMode::ThresholdInteractive,
                SignerBackendRequirement::FrostSecp256k1Tr,
            )
            .is_err()
    );
}

#[test]
fn chain_suite_reviews_and_verifies_only_bsv_forkid_transactions() {
    let secret_key = SecretKey::from_slice(&[7; 32]).unwrap();
    let public_key = PublicKey::from_secret_key(&Secp256k1::new(), &secret_key);
    let suite = BsvChainSuite::new(BsvNetwork::Stn, public_key.serialize()).unwrap();
    let request = BsvSigningRequest {
        network: BsvNetwork::Stn,
        transaction: sample_transaction(),
        input_index: 0,
        script_code: decode_hex("76a91465a16059864a2fdbc7c99a4723a8395bc6f188eb88ac"),
        input_value_satoshis: 50_000,
        sighash_type: ForkIdSighashType::ALL,
    };
    let material = request.encode().unwrap();
    let review = suite.review_transaction(&material).unwrap();
    assert_eq!(review.scope.chain, ChainId::Bsv);
    assert_eq!(review.reviewed_material, material);
    assert!(!review.summary.contains("canonical request sha256"));
    assert_eq!(
        review.signing_message_digest,
        request.signing_digest().unwrap()
    );

    let signature = sign_digest(
        &secret_key,
        review.signing_message_digest,
        ForkIdSighashType::ALL,
    )
    .unwrap();
    suite
        .verify_finalized_signature(&review, &signature)
        .unwrap();

    let wrong_network = BsvSigningRequest {
        network: BsvNetwork::Testnet,
        ..request
    };
    assert!(
        suite
            .review_transaction(&wrong_network.encode().unwrap())
            .is_err()
    );

    let mut wrong_algorithm = signature;
    *wrong_algorithm.last_mut().unwrap() = 0x01;
    assert!(
        suite
            .verify_finalized_signature(&review, &wrong_algorithm)
            .is_err()
    );
}

#[test]
fn final_verification_rejects_forged_review_artifacts() {
    let secret_key = SecretKey::from_slice(&[7; 32]).unwrap();
    let public_key = PublicKey::from_secret_key(&Secp256k1::new(), &secret_key);
    let suite = BsvChainSuite::new(BsvNetwork::Mainnet, public_key.serialize()).unwrap();
    let request = BsvSigningRequest {
        network: BsvNetwork::Mainnet,
        transaction: sample_transaction(),
        input_index: 0,
        script_code: decode_hex("76a91465a16059864a2fdbc7c99a4723a8395bc6f188eb88ac"),
        input_value_satoshis: 50_000,
        sighash_type: ForkIdSighashType::ALL,
    };
    let review = suite
        .review_transaction(&request.encode().unwrap())
        .unwrap();

    let forged_digest = [0x44; 32];
    let forged_digest_review = ReviewArtifact::new(
        review.scope,
        review.review_digest,
        forged_digest,
        review.summary.clone(),
        review.reviewed_material.clone(),
    )
    .unwrap();
    let forged_digest_signature =
        sign_digest(&secret_key, forged_digest, ForkIdSighashType::ALL).unwrap();
    assert!(
        suite
            .verify_finalized_signature(&forged_digest_review, &forged_digest_signature)
            .is_err()
    );

    let forged_summary_review = ReviewArtifact::new(
        review.scope,
        review.review_digest,
        review.signing_message_digest,
        "BSV mainnet: send everything to the attacker".to_owned(),
        review.reviewed_material.clone(),
    )
    .unwrap();
    let original_signature = sign_digest(
        &secret_key,
        review.signing_message_digest,
        ForkIdSighashType::ALL,
    )
    .unwrap();
    assert!(
        suite
            .verify_finalized_signature(&forged_summary_review, &original_signature)
            .is_err()
    );

    let forged_from_scratch = ReviewArtifact::new(
        review.scope,
        [0x55; 32],
        forged_digest,
        "internally consistent attacker review".to_owned(),
        b"not a canonical BSV request".to_vec(),
    )
    .unwrap();
    assert!(
        suite
            .verify_finalized_signature(&forged_from_scratch, &forged_digest_signature)
            .is_err()
    );
}

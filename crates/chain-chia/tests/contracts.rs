use catomicals_chain_chia::{
    AggSigMe, AugmentedVerification, BlsSignatureShare, ChiaAdapterError, ChiaChainSuite,
    ChiaSigningSuite, ThresholdBlsDealerKeyKind, WalletDerivationKind, aggregate_signatures,
    dealer_split_threshold_secret_2_of_3, decode_address, derive_synthetic_public_key,
    derive_synthetic_secret_key, derive_wallet_public_key, derive_wallet_secret_key,
    encode_puzzle_hash, interpolate_threshold_signature_2_of_3, sign_augmented,
    sign_threshold_share_2_of_3, verify_aggregate_augmented, verify_augmented,
    wallet_derivation_path,
};
use catomicals_chain_domain::{
    BitcoinNetwork, ChainCapabilities, ChainId, ChainNetwork, ChainScope, ChainSuite, ChiaNetwork,
};
use catomicals_signing_domain::{
    SignerBackendRequirement, SigningExecutionMode, SigningSuite, SigningSuiteId,
};
use chia_bls::SecretKey;

fn mainnet_scope() -> ChainScope {
    ChainScope::for_network(ChainNetwork::Chia(ChiaNetwork::Mainnet))
}

fn testnet11_scope() -> ChainScope {
    ChainScope::for_network(ChainNetwork::Chia(ChiaNetwork::Testnet11))
}

fn bytes32(hex_value: &str) -> [u8; 32] {
    hex::decode(hex_value).unwrap().try_into().unwrap()
}

fn bytes96(hex_value: &str) -> [u8; 96] {
    hex::decode(hex_value).unwrap().try_into().unwrap()
}

#[test]
fn official_address_vector_round_trips_with_network_hrp() {
    // https://docs.chia.net/chia-blockchain/coin-set-model/addresses/
    let puzzle_hash = bytes32("0b8622123401acf18bda97dfaa9d2c5e81f2be8c737c283e18903b35d209553e");
    let address = encode_puzzle_hash(mainnet_scope(), puzzle_hash).unwrap();
    assert_eq!(
        address,
        "xch1pwrzyy35qxk0rz76jl0648fvt6ql905vwd7zs0scjqant5sf25lql4hz3z"
    );
    assert_eq!(
        decode_address(mainnet_scope(), &address).unwrap(),
        puzzle_hash
    );

    // Official Chia burn-address vector uses the testnet `txch` HRP.
    let burn_hash = bytes32("000000000000000000000000000000000000000000000000000000000000dead");
    let testnet_address = encode_puzzle_hash(testnet11_scope(), burn_hash).unwrap();
    assert_eq!(
        testnet_address,
        "txch1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqm6ksh7qddh"
    );
    assert_eq!(
        decode_address(testnet11_scope(), &testnet_address).unwrap(),
        burn_hash
    );
}

#[test]
fn address_decoder_rejects_wrong_network_and_non_bech32m() {
    let puzzle_hash = [42; 32];
    let mainnet_address = encode_puzzle_hash(mainnet_scope(), puzzle_hash).unwrap();
    assert!(matches!(
        decode_address(testnet11_scope(), &mainnet_address),
        Err(ChiaAdapterError::WrongAddressPrefix { .. })
    ));

    let legacy_bech32 =
        bech32::encode::<bech32::Bech32>(bech32::Hrp::parse("xch").unwrap(), &puzzle_hash).unwrap();
    assert!(matches!(
        decode_address(mainnet_scope(), &legacy_bech32),
        Err(ChiaAdapterError::InvalidAddress(_))
    ));
}

#[test]
fn wallet_paths_are_the_official_chia_path() {
    let hardened = wallet_derivation_path(7, WalletDerivationKind::Hardened);
    assert_eq!(hardened.components(), [12381, 8444, 2, 7]);
    assert_eq!(hardened.to_string(), "m/12381/8444/2/7 (hardened)");

    let unhardened = wallet_derivation_path(7, WalletDerivationKind::Unhardened);
    assert_eq!(unhardened.components(), [12381, 8444, 2, 7]);
    assert_eq!(unhardened.to_string(), "m/12381/8444/2/7");
}

#[test]
fn official_synthetic_key_vectors_match() {
    // Vectors copied from Chia-Network/chia_rs chia-puzzle-types tests.
    let master = SecretKey::from_bytes(&bytes32(
        "6bb19282e27bc6e7e397fb19efc2627a412410fdfd13bf14f4ce5bfdce084c71",
    ))
    .unwrap();
    let wallet_sk = derive_wallet_secret_key(&master, 0, WalletDerivationKind::Unhardened);
    let wallet_pk = derive_wallet_public_key(&master.public_key(), 0);
    assert_eq!(wallet_sk.public_key(), wallet_pk);

    let synthetic_sk = derive_synthetic_secret_key(&wallet_sk);
    let synthetic_pk = derive_synthetic_public_key(&wallet_pk);
    assert_eq!(
        hex::encode(synthetic_sk.to_bytes()),
        "64c91fe4534fc21c36096be012e0e14de484180a1a510783367bcd5ccecaad0c"
    );
    assert_eq!(
        hex::encode(synthetic_pk.to_bytes()),
        "b0c8cf08fdbe7fdb7bb1795740153b944c32364b100c372a05833554cb97794563b096cb5f57bfa09f38d7aebb48704e"
    );
    assert_eq!(synthetic_sk.public_key(), synthetic_pk);
}

#[test]
fn official_augmented_bls_aggregate_vector_matches() {
    // Chia-Network/bls-signatures "Chia test vector 2".
    let sk1 = SecretKey::from_seed(&[2; 32]);
    let sk2 = SecretKey::from_seed(&[3; 32]);
    let messages: [&[u8]; 6] = [
        &[1, 2, 3, 40],
        &[5, 6, 70, 201],
        &[1, 2, 3, 40],
        &[9, 10, 11, 12, 13],
        &[1, 2, 3, 40],
        &[15, 63, 244, 92, 0, 1],
    ];
    let keys = [&sk1, &sk2, &sk2, &sk1, &sk1, &sk1];
    let signatures = keys
        .iter()
        .zip(messages)
        .map(|(key, message)| sign_augmented(key, message).unwrap())
        .collect::<Vec<_>>();
    assert!(signatures.iter().all(|signature| signature.len() == 96));
    let aggregate = aggregate_signatures(&signatures).unwrap();
    assert_eq!(
        hex::encode(aggregate),
        "a1d5360dcb418d33b29b90b912b4accde535cf0e52caf467a005dc632d9f7af44b6c4e9acd46eac218b28cdb07a3e3bc087df1cd1e3213aa4e11322a3ff3847bbba0b2fd19ddc25ca964871997b9bceeab37a4c2565876da19382ea32a962200"
    );

    let verification = keys
        .iter()
        .zip(messages)
        .map(|(key, message)| AugmentedVerification::new(key.public_key().to_bytes(), message))
        .collect::<Vec<_>>();
    assert!(verify_aggregate_augmented(&verification, aggregate).unwrap());

    let mut wrong_messages = verification;
    wrong_messages[0] = AugmentedVerification::new(sk1.public_key().to_bytes(), b"wrong");
    assert!(!verify_aggregate_augmented(&wrong_messages, aggregate).unwrap());
}

#[test]
fn agg_sig_me_binds_message_coin_and_network_additional_data() {
    let key = SecretKey::from_seed(&[9; 32]);
    let coin_id = [0x22; 32];
    let condition_message = b"delegated puzzle hash";

    let mainnet = AggSigMe::new(mainnet_scope(), condition_message, coin_id).unwrap();
    let mut expected = condition_message.to_vec();
    expected.extend_from_slice(&coin_id);
    expected.extend_from_slice(&bytes32(
        "ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb",
    ));
    assert_eq!(mainnet.final_message(), expected);

    let signature = mainnet.sign(&key).unwrap();
    let public_key = key.public_key().to_bytes();
    assert_eq!(public_key.len(), 48);
    assert_eq!(signature.len(), 96);
    assert!(mainnet.verify(public_key, signature).unwrap());

    let testnet = AggSigMe::new(testnet11_scope(), condition_message, coin_id).unwrap();
    assert_eq!(
        &testnet.final_message()[condition_message.len() + coin_id.len()..],
        &bytes32("37a90eb5185a9c4439a91ddc98bbadce7b4feba060d50116a067de66bf236615")
    );
    assert!(!testnet.verify(public_key, signature).unwrap());

    let mut tampered = mainnet.final_message().to_vec();
    tampered[0] ^= 1;
    assert!(!verify_augmented(public_key, &tampered, signature).unwrap());
}

#[test]
fn identity_keys_and_signatures_are_rejected() {
    let zero_key = SecretKey::from_bytes(&[0; 32]).unwrap();
    assert_eq!(
        sign_augmented(&zero_key, b"message"),
        Err(ChiaAdapterError::InvalidSecretKey)
    );

    let infinity_public_key = {
        let mut bytes = [0; 48];
        bytes[0] = 0xc0;
        bytes
    };
    let infinity_signature = {
        let mut bytes = [0; 96];
        bytes[0] = 0xc0;
        bytes
    };
    assert_eq!(
        verify_augmented(infinity_public_key, b"message", infinity_signature),
        Err(ChiaAdapterError::IdentityPublicKey)
    );
}

#[test]
fn suites_bind_to_chia_and_advertise_real_capabilities() {
    let chain_suite = ChiaChainSuite::new(testnet11_scope()).unwrap();
    assert_eq!(chain_suite.scope(), testnet11_scope());
    assert_eq!(
        chain_suite.capabilities(),
        ChainCapabilities {
            address_derivation: true,
            transaction_review: false,
            final_signature_verification: false,
            broadcast: false,
        }
    );

    let signing_suite = ChiaSigningSuite::new(testnet11_scope()).unwrap();
    let descriptor = signing_suite.descriptor();
    assert_eq!(descriptor.id, SigningSuiteId::CHIA_BLS12381_AUG_NATIVE_V1);
    assert_eq!(
        descriptor.execution_mode,
        SigningExecutionMode::NativeChainCoordinator
    );
    assert_eq!(
        descriptor.backend_requirement,
        SignerBackendRequirement::ChiaBlsAug
    );
    assert!(!descriptor.capabilities.interactive_threshold);

    let bitcoin = ChainScope::for_network(ChainNetwork::Bitcoin(BitcoinNetwork::Regtest));
    assert!(matches!(
        ChiaChainSuite::new(bitcoin),
        Err(ChiaAdapterError::UnsupportedChainScope(_))
    ));
    let mismatched = ChainScope {
        schema_version: 1,
        chain: ChainId::Bitcoin,
        network: ChainNetwork::Chia(ChiaNetwork::Testnet11),
    };
    assert!(matches!(
        ChiaSigningSuite::new(mismatched),
        Err(ChiaAdapterError::MismatchedChainNetwork { .. })
    ));
}

#[test]
fn threshold_quorums_match_chia_augmented_signature_byte_for_byte() {
    // Fixed vector copied from Chia-Network/chia_rs
    // crates/chia-bls/src/signature.rs::test_sign.
    let group_secret = SecretKey::from_bytes(&bytes32(
        "52d75c4707e39595b27314547f9723e5530c01198af3fc5849d9a7af65631efb",
    ))
    .unwrap();
    let coefficient = SecretKey::from_bytes(&[2; 32]).unwrap();
    let dealer = dealer_split_threshold_secret_2_of_3(
        ThresholdBlsDealerKeyKind::FinalSigningKey,
        group_secret.to_bytes(),
        coefficient.to_bytes(),
    )
    .unwrap();
    let message = *b"foobar";
    let expected = bytes96(
        "b45825c0ee7759945c0189b4c38b7e54231ebadc83a851bec3bb7cf954a124ae0cc8e8e5146558332ea152f63bf8846e04826185ef60e817f271f8d500126561319203f9acb95809ed20c193757233454be1562a5870570941a84605bd2c9c9a",
    );
    assert_eq!(sign_augmented(&group_secret, &message).unwrap(), expected);

    let partials = dealer
        .shares()
        .iter()
        .map(|share| sign_threshold_share_2_of_3(dealer.commitment(), share, &message).unwrap())
        .collect::<Vec<_>>();

    for quorum in [[0, 1], [0, 2], [1, 2]] {
        let actual = interpolate_threshold_signature_2_of_3(
            dealer.commitment(),
            &message,
            &[partials[quorum[0]].clone(), partials[quorum[1]].clone()],
        )
        .unwrap();
        assert_eq!(actual, expected);
        assert!(
            verify_augmented(dealer.commitment().group_public_key(), &message, actual).unwrap()
        );
    }
}

#[test]
fn threshold_partials_use_the_group_key_as_the_single_augmentation() {
    let group_secret = SecretKey::from_seed(&[0x51; 32]);
    let coefficient = SecretKey::from_seed(&[0x15; 32]);
    let dealer = dealer_split_threshold_secret_2_of_3(
        ThresholdBlsDealerKeyKind::FinalSigningKey,
        group_secret.to_bytes(),
        coefficient.to_bytes(),
    )
    .unwrap();
    let message = b"same hash-to-curve point for every partial";
    let valid =
        sign_threshold_share_2_of_3(dealer.commitment(), &dealer.shares()[0], message).unwrap();
    assert_eq!(valid.participant_id, 1);

    // A common AugSchemeMPL mistake is using each share public key as the
    // augmentation. Such a partial is individually valid under that key, but
    // must be rejected by the threshold aggregator.
    let share_secret =
        SecretKey::from_bytes(&dealer.shares()[1].export_for_provisioning()).unwrap();
    let wrong = sign_augmented(&share_secret, message).unwrap();
    let wrong = BlsSignatureShare::new(2, wrong);
    assert_eq!(
        interpolate_threshold_signature_2_of_3(dealer.commitment(), message, &[valid, wrong]),
        Err(ChiaAdapterError::InvalidThresholdPartial { participant_id: 2 })
    );

    let full_signature = sign_augmented(&group_secret, message).unwrap();
    assert!(matches!(
        interpolate_threshold_signature_2_of_3(
            dealer.commitment(),
            message,
            &[
                BlsSignatureShare::new(1, full_signature),
                BlsSignatureShare::new(3, full_signature),
            ],
        ),
        Err(ChiaAdapterError::InvalidThresholdPartial { .. })
    ));

    let mismatched_share = catomicals_chain_chia::ThresholdBlsSecretShare::import_for_signing(
        1,
        dealer.shares()[1].export_for_provisioning(),
    )
    .unwrap();
    assert_eq!(
        sign_threshold_share_2_of_3(dealer.commitment(), &mismatched_share, message),
        Err(ChiaAdapterError::ThresholdShareCommitmentMismatch { participant_id: 1 })
    );
}

#[test]
fn threshold_rejects_bad_quorums_commitments_messages_and_group_keys() {
    let group_secret = SecretKey::from_seed(&[0x61; 32]);
    let coefficient = SecretKey::from_seed(&[0x16; 32]);
    let dealer = dealer_split_threshold_secret_2_of_3(
        ThresholdBlsDealerKeyKind::FinalSigningKey,
        group_secret.to_bytes(),
        coefficient.to_bytes(),
    )
    .unwrap();
    let other = dealer_split_threshold_secret_2_of_3(
        ThresholdBlsDealerKeyKind::FinalSigningKey,
        SecretKey::from_seed(&[0x62; 32]).to_bytes(),
        SecretKey::from_seed(&[0x26; 32]).to_bytes(),
    )
    .unwrap();
    let message = b"reviewed spend";
    let partial1 =
        sign_threshold_share_2_of_3(dealer.commitment(), &dealer.shares()[0], message).unwrap();
    let partial2 =
        sign_threshold_share_2_of_3(dealer.commitment(), &dealer.shares()[1], message).unwrap();

    assert_eq!(
        interpolate_threshold_signature_2_of_3(
            dealer.commitment(),
            message,
            std::slice::from_ref(&partial1)
        ),
        Err(ChiaAdapterError::InsufficientThresholdShares { actual: 1 })
    );
    assert_eq!(
        interpolate_threshold_signature_2_of_3(
            dealer.commitment(),
            message,
            &[partial1.clone(), partial1.clone()]
        ),
        Err(ChiaAdapterError::DuplicateThresholdParticipant(1))
    );
    assert!(matches!(
        interpolate_threshold_signature_2_of_3(
            dealer.commitment(),
            b"different message",
            &[partial1.clone(), partial2.clone()]
        ),
        Err(ChiaAdapterError::InvalidThresholdPartial { .. })
    ));
    assert!(matches!(
        interpolate_threshold_signature_2_of_3(other.commitment(), message, &[partial1, partial2]),
        Err(ChiaAdapterError::InvalidThresholdPartial { .. })
    ));

    let wrong_coefficient = catomicals_chain_chia::ThresholdBlsCommitment::import(
        dealer.commitment().group_public_key(),
        other.commitment().coefficient_public_key(),
    )
    .unwrap();
    let partial1 =
        sign_threshold_share_2_of_3(dealer.commitment(), &dealer.shares()[0], message).unwrap();
    let partial2 =
        sign_threshold_share_2_of_3(dealer.commitment(), &dealer.shares()[1], message).unwrap();
    assert!(matches!(
        interpolate_threshold_signature_2_of_3(&wrong_coefficient, message, &[partial1, partial2]),
        Err(ChiaAdapterError::InvalidThresholdPartial { .. })
    ));

    let mut corrupt =
        sign_threshold_share_2_of_3(dealer.commitment(), &dealer.shares()[0], message).unwrap();
    corrupt.signature[0] ^= 0xff;
    let valid =
        sign_threshold_share_2_of_3(dealer.commitment(), &dealer.shares()[2], message).unwrap();
    assert_eq!(
        interpolate_threshold_signature_2_of_3(dealer.commitment(), message, &[corrupt, valid]),
        Err(ChiaAdapterError::InvalidThresholdPartial { participant_id: 1 })
    );

    let mut bad_coefficient = dealer.commitment().coefficient_public_key();
    bad_coefficient[0] ^= 1;
    assert!(
        catomicals_chain_chia::ThresholdBlsCommitment::import(
            dealer.commitment().group_public_key(),
            bad_coefficient
        )
        .is_err()
    );
}

#[test]
fn threshold_agg_sig_me_is_bound_to_chia_network_additional_data() {
    let group_secret = SecretKey::from_seed(&[0x71; 32]);
    let dealer = dealer_split_threshold_secret_2_of_3(
        ThresholdBlsDealerKeyKind::FinalSigningKey,
        group_secret.to_bytes(),
        SecretKey::from_seed(&[0x17; 32]).to_bytes(),
    )
    .unwrap();
    let coin_id = [0x33; 32];
    let mainnet = AggSigMe::new(mainnet_scope(), b"condition", coin_id).unwrap();
    let testnet = AggSigMe::new(testnet11_scope(), b"condition", coin_id).unwrap();
    let p1 = sign_threshold_share_2_of_3(
        dealer.commitment(),
        &dealer.shares()[0],
        mainnet.final_message(),
    )
    .unwrap();
    let p2 = sign_threshold_share_2_of_3(
        dealer.commitment(),
        &dealer.shares()[2],
        mainnet.final_message(),
    )
    .unwrap();
    let signature = interpolate_threshold_signature_2_of_3(
        dealer.commitment(),
        mainnet.final_message(),
        &[p1, p2],
    )
    .unwrap();
    assert!(
        mainnet
            .verify(dealer.commitment().group_public_key(), signature)
            .unwrap()
    );
    assert!(
        !testnet
            .verify(dealer.commitment().group_public_key(), signature)
            .unwrap()
    );
}

#[test]
fn threshold_v1_rejects_unprepared_hardened_and_unsynthesized_keys() {
    let secret = SecretKey::from_seed(&[0x81; 32]).to_bytes();
    let coefficient = SecretKey::from_seed(&[0x18; 32]).to_bytes();
    for kind in [
        ThresholdBlsDealerKeyKind::HardenedWalletMaster,
        ThresholdBlsDealerKeyKind::UnsynthesizedWalletKey,
    ] {
        assert!(matches!(
            dealer_split_threshold_secret_2_of_3(kind, secret, coefficient),
            Err(ChiaAdapterError::ThresholdKeyMustBeFinalSigningKey)
        ));
    }
}

#[test]
fn threshold_secret_share_export_is_explicit_zeroizing_and_debug_is_redacted() {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<catomicals_chain_chia::ThresholdBlsSecretShare>();

    let dealer = dealer_split_threshold_secret_2_of_3(
        ThresholdBlsDealerKeyKind::FinalSigningKey,
        SecretKey::from_seed(&[0x91; 32]).to_bytes(),
        SecretKey::from_seed(&[0x19; 32]).to_bytes(),
    )
    .unwrap();
    let share = &dealer.shares()[0];
    let debug = format!("{share:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains(&hex::encode(share.export_for_provisioning().as_ref())));

    let mut exported = share.export_for_provisioning();
    assert_ne!(*exported, [0; 32]);
    let imported = catomicals_chain_chia::ThresholdBlsSecretShare::import_for_signing(
        share.participant_id(),
        exported.clone(),
    )
    .unwrap();
    let imported_partial =
        sign_threshold_share_2_of_3(dealer.commitment(), &imported, b"imported share").unwrap();
    assert_eq!(imported_partial.participant_id, share.participant_id());
    zeroize::Zeroize::zeroize(&mut exported);
    assert_eq!(*exported, [0; 32]);

    assert!(matches!(
        catomicals_chain_chia::ThresholdBlsSecretShare::import_for_signing(
            0,
            zeroize::Zeroizing::new([1; 32])
        ),
        Err(ChiaAdapterError::InvalidThresholdParticipant(0))
    ));
    assert!(matches!(
        catomicals_chain_chia::ThresholdBlsSecretShare::import_for_signing(
            4,
            zeroize::Zeroizing::new([1; 32])
        ),
        Err(ChiaAdapterError::InvalidThresholdParticipant(4))
    ));
}

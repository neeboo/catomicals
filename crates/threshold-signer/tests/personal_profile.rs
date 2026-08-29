use std::collections::BTreeMap;

use catomicals_threshold::{
    AuthorizationError, FrostCoordinator, NonceGuard, PERSONAL_PROFILE_FORMAT_VERSION,
    PERSONAL_PROFILE_MAX_BYTES, PERSONAL_SECRET_PACKAGE_FORMAT_VERSION,
    PERSONAL_SECRET_PACKAGE_MAX_BYTES, PersonalProfileError, PersonalSignerProfile,
    SigningAuthorization, participant_identifier, run_local_dkg,
};
use serde_json::Value;
use uuid::Uuid;

const PROFILE_ID: Uuid = Uuid::from_u128(0x11111111_2222_3333_4444_555555555555);
const WALLET_ID: Uuid = Uuid::from_u128(0xaaaaaaaa_bbbb_cccc_dddd_eeeeeeeeeeee);
const SIGNER_SET_ID: Uuid = Uuid::from_u128(0x01234567_89ab_cdef_0123_456789abcdef);

fn make_bootstrap() -> catomicals_threshold::PersonalSignerBootstrap {
    PersonalSignerProfile::bootstrap(
        PROFILE_ID,
        WALLET_ID,
        SIGNER_SET_ID,
        7,
        run_local_dkg(3, 2).expect("dkg"),
    )
    .expect("personal profile")
}

#[test]
fn profile_and_secret_packages_are_versioned_deterministic_and_bounded() {
    let bootstrap = make_bootstrap();
    let profile = &bootstrap.profile;

    assert_eq!(profile.profile_id(), PROFILE_ID);
    assert_eq!(profile.wallet_id(), WALLET_ID);
    assert_eq!(profile.signer_set_id(), SIGNER_SET_ID);
    assert_eq!(profile.signer_epoch(), 7);
    assert_eq!(profile.min_signers(), 2);
    assert_eq!(profile.max_signers(), 3);
    assert_eq!(profile.participants().len(), 3);

    let first = profile.to_bytes().expect("encode profile");
    let second = profile.to_bytes().expect("encode profile again");
    assert_eq!(first, second);
    assert!(first.len() <= PERSONAL_PROFILE_MAX_BYTES);
    let decoded = PersonalSignerProfile::from_bytes(&first).expect("decode profile");
    assert_eq!(decoded.binding_digest(), profile.binding_digest());

    for (signer_id, package) in &bootstrap.secret_packages {
        assert_eq!(*signer_id, package.signer_id());
        package.validate(profile).expect("bound package");
        let first = package.to_bytes().expect("encode package");
        let second = package.to_bytes().expect("encode package again");
        assert_eq!(first.as_slice(), second.as_slice());
        assert!(first.len() <= PERSONAL_SECRET_PACKAGE_MAX_BYTES);
        let decoded =
            catomicals_threshold::PersonalParticipantSecretPackage::from_bytes(&first, profile)
                .expect("decode bound package");
        decoded.validate(profile).expect("decoded package binding");
    }
}

#[test]
fn secret_package_rejects_profile_and_key_material_drift() {
    let bootstrap = make_bootstrap();
    let package = bootstrap.secret_packages.get(&1).expect("share one");

    let other = make_bootstrap();
    assert_eq!(
        package.validate(&other.profile),
        Err(PersonalProfileError::ProfileBindingMismatch)
    );

    for (field, replacement) in [
        ("signer_epoch", Value::from(8_u64)),
        ("min_signers", Value::from(3_u64)),
        ("max_signers", Value::from(4_u64)),
    ] {
        let mut value: Value = serde_json::from_slice(&profile_bytes(&bootstrap)).unwrap();
        value[field] = replacement;
        let altered = serde_json::to_vec(&value).unwrap();
        match PersonalSignerProfile::from_bytes(&altered) {
            Ok(profile) => assert_eq!(
                package.validate(&profile),
                Err(PersonalProfileError::ProfileBindingMismatch)
            ),
            Err(error) => assert!(matches!(
                error,
                PersonalProfileError::InvalidThreshold
                    | PersonalProfileError::InvalidPublicPackage
                    | PersonalProfileError::InvalidParticipantInventory
            )),
        }
    }

    let mut group_drift: Value = serde_json::from_slice(&profile_bytes(&bootstrap)).unwrap();
    let first_group_byte = group_drift["group_pubkey_xonly"][0].as_u64().unwrap() as u8;
    group_drift["group_pubkey_xonly"][0] = Value::from(first_group_byte ^ 1);
    assert_eq!(
        PersonalSignerProfile::from_bytes(&serde_json::to_vec(&group_drift).unwrap()),
        Err(PersonalProfileError::InvalidPublicPackage)
    );

    let mut participant_drift: Value = serde_json::from_slice(&profile_bytes(&bootstrap)).unwrap();
    participant_drift["participants"][0]["signer_id"] = Value::from(2_u64);
    assert_eq!(
        PersonalSignerProfile::from_bytes(&serde_json::to_vec(&participant_drift).unwrap()),
        Err(PersonalProfileError::InvalidParticipantInventory)
    );

    let mut secret: Value = serde_json::from_slice(
        bootstrap
            .secret_packages
            .get(&1)
            .unwrap()
            .to_bytes()
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    secret["signer_id"] = Value::from(2_u64);
    let changed = serde_json::to_vec(&secret).unwrap();
    assert!(matches!(
        catomicals_threshold::PersonalParticipantSecretPackage::from_bytes(
            &changed,
            &bootstrap.profile,
        ),
        Err(PersonalProfileError::ParticipantMismatch)
            | Err(PersonalProfileError::KeyPackageMismatch)
    ));

    let mut secret: Value = serde_json::from_slice(
        bootstrap
            .secret_packages
            .get(&1)
            .unwrap()
            .to_bytes()
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let other_secret: Value = serde_json::from_slice(
        other
            .secret_packages
            .get(&1)
            .unwrap()
            .to_bytes()
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    secret["key_package"] = other_secret["key_package"].clone();
    let changed = serde_json::to_vec(&secret).unwrap();
    assert_eq!(
        catomicals_threshold::PersonalParticipantSecretPackage::from_bytes(
            &changed,
            &bootstrap.profile,
        )
        .map(|_| ()),
        Err(PersonalProfileError::KeyPackageMismatch)
    );
}

#[test]
fn secret_debug_output_is_redacted() {
    let bootstrap = make_bootstrap();
    let package = bootstrap.secret_packages.get(&2).unwrap();
    let encoded = package.to_bytes().unwrap();
    let key_bytes = serde_json::from_slice::<Value>(&encoded).unwrap()["key_package"]
        .as_array()
        .unwrap()
        .iter()
        .map(|byte| byte.as_u64().unwrap() as u8)
        .collect::<Vec<_>>();
    let debug = format!("{package:?}");

    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains(&format!("{key_bytes:?}")));
    assert!(!debug.contains("key_package: ["));

    let opened = package.open(&bootstrap.profile).unwrap();
    let opened_debug = format!("{opened:?}");
    assert!(opened_debug.contains("<redacted>"));
    assert!(!opened_debug.contains(&format!("{key_bytes:?}")));
}

#[test]
fn schema_fields_and_versions_are_locked_without_random_key_bytes() {
    // Local DKG uses OS randomness, so full encoded key bytes cannot be a
    // stable vector. Lock the version and exact field inventory instead.
    let bootstrap = make_bootstrap();
    let profile: Value = serde_json::from_slice(&profile_bytes(&bootstrap)).unwrap();
    assert_eq!(
        profile["format_version"],
        Value::from(PERSONAL_PROFILE_FORMAT_VERSION)
    );
    let profile_fields = profile
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        profile_fields,
        [
            "format_version",
            "group_pubkey_xonly",
            "max_signers",
            "min_signers",
            "participants",
            "profile_id",
            "public_key_package",
            "signer_epoch",
            "signer_set_id",
            "wallet_id",
        ]
        .into_iter()
        .collect()
    );

    let secret: Value = serde_json::from_slice(
        &bootstrap
            .secret_packages
            .get(&2)
            .unwrap()
            .to_bytes()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        secret["format_version"],
        Value::from(PERSONAL_SECRET_PACKAGE_FORMAT_VERSION)
    );
    let secret_fields = secret
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        secret_fields,
        [
            "format_version",
            "group_pubkey_xonly",
            "key_package",
            "max_signers",
            "min_signers",
            "profile_binding_digest",
            "profile_id",
            "signer_epoch",
            "signer_id",
            "signer_set_id",
            "wallet_id",
        ]
        .into_iter()
        .collect()
    );
}

#[test]
fn decoders_reject_oversized_and_unknown_input() {
    assert_eq!(
        PersonalSignerProfile::from_bytes(&vec![b' '; PERSONAL_PROFILE_MAX_BYTES + 1]),
        Err(PersonalProfileError::PackageTooLarge)
    );
    assert!(matches!(
        catomicals_threshold::PersonalParticipantSecretPackage::from_bytes(
            &vec![b' '; PERSONAL_SECRET_PACKAGE_MAX_BYTES + 1],
            &make_bootstrap().profile,
        ),
        Err(PersonalProfileError::PackageTooLarge)
    ));

    let bootstrap = make_bootstrap();
    let mut profile: Value = serde_json::from_slice(&profile_bytes(&bootstrap)).unwrap();
    profile["unexpected"] = Value::Bool(true);
    assert_eq!(
        PersonalSignerProfile::from_bytes(&serde_json::to_vec(&profile).unwrap()),
        Err(PersonalProfileError::Encoding)
    );

    let package = bootstrap.secret_packages.get(&2).unwrap();
    let mut secret: Value = serde_json::from_slice(&package.to_bytes().unwrap()).unwrap();
    secret["unexpected"] = Value::Bool(true);
    assert!(matches!(
        catomicals_threshold::PersonalParticipantSecretPackage::from_bytes(
            &serde_json::to_vec(&secret).unwrap(),
            &bootstrap.profile,
        ),
        Err(PersonalProfileError::Encoding)
    ));
}

#[test]
fn every_two_package_pair_signs_the_same_message() {
    let bootstrap = make_bootstrap();
    for pair in [[1_u16, 2_u16], [1, 3], [2, 3]] {
        let mut participants = BTreeMap::new();
        for signer_id in pair {
            let opened = bootstrap.secret_packages[&signer_id]
                .open(&bootstrap.profile)
                .expect("open bound package");
            assert_eq!(opened.signer_id(), signer_id);
            participants.insert(
                signer_id,
                opened
                    .into_participant(NonceGuard::new())
                    .expect("consume opened package into participant"),
            );
        }

        let session_id = [pair[0] as u8; 32];
        let message = [0x77; 32];
        let mut coordinator = FrostCoordinator::new(
            session_id,
            message,
            bootstrap.profile.min_signers(),
            bootstrap.profile.public_key_package().unwrap(),
        );
        for signer_id in pair {
            let commitment = participants
                .get_mut(&signer_id)
                .unwrap()
                .round1(session_id, message)
                .unwrap();
            coordinator.add_commitment(signer_id, commitment).unwrap();
        }
        let session = coordinator.signing_session().unwrap();
        for signer_id in pair {
            let mut authorization = ExactAuthorization {
                session: session_id,
                message,
                signer: signer_id,
                used: false,
            };
            let share = participants
                .get_mut(&signer_id)
                .unwrap()
                .round2(&session, &mut authorization, 1)
                .unwrap();
            coordinator.add_signature_share(signer_id, share).unwrap();
        }
        coordinator.finalize().expect("valid aggregate signature");
    }
}

fn profile_bytes(bootstrap: &catomicals_threshold::PersonalSignerBootstrap) -> Vec<u8> {
    bootstrap.profile.to_bytes().unwrap()
}

struct ExactAuthorization {
    session: [u8; 32],
    message: [u8; 32],
    signer: u16,
    used: bool,
}

impl SigningAuthorization for ExactAuthorization {
    fn authorize(
        &mut self,
        session_id: &[u8; 32],
        message: &[u8; 32],
        signer_id: u16,
        _now: i64,
    ) -> Result<(), AuthorizationError> {
        if self.used {
            return Err(AuthorizationError::AlreadyConsumed);
        }
        if session_id != &self.session {
            return Err(AuthorizationError::WrongSession);
        }
        if message != &self.message {
            return Err(AuthorizationError::WrongMessage);
        }
        if signer_id != self.signer {
            return Err(AuthorizationError::WrongSigner);
        }
        self.used = true;
        Ok(())
    }
}

#[test]
fn participant_identifiers_remain_the_expected_one_based_set() {
    let bootstrap = make_bootstrap();
    for signer_id in 1..=3 {
        let descriptor = &bootstrap.profile.participants()[usize::from(signer_id - 1)];
        assert_eq!(descriptor.signer_id, signer_id);
        assert_eq!(
            descriptor.identifier_hex,
            hex::encode(participant_identifier(signer_id).unwrap().serialize())
        );
    }
}

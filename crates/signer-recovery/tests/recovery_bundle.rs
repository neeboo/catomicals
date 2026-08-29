use std::collections::BTreeMap;

use catomicals_signer_recovery::{
    RECOVERY_BUNDLE_FORMAT_VERSION, RECOVERY_BUNDLE_MAX_BYTES, RECOVERY_KDF_LANES,
    RECOVERY_KDF_MEMORY_KIB, RECOVERY_KDF_OUTPUT_LEN, RECOVERY_KDF_PASSES, RecoveryBundle,
    RecoveryBundleError, RecoveryKey,
};
use catomicals_threshold::{
    FrostCoordinator, NonceGuard, PersonalParticipantSecretPackage, PersonalSignerBootstrap,
    PersonalSignerProfile, SigningAuthorization, run_local_dkg,
};
use serde_json::Value;
use uuid::Uuid;

fn bootstrap(epoch: u64) -> PersonalSignerBootstrap {
    PersonalSignerProfile::bootstrap(
        Uuid::from_u128(0x11111111_2222_3333_4444_555555555555),
        Uuid::from_u128(0xaaaaaaaa_bbbb_cccc_dddd_eeeeeeeeeeee),
        Uuid::from_u128(0x01234567_89ab_cdef_0123_456789abcdef),
        epoch,
        run_local_dkg(3, 2).expect("dkg"),
    )
    .expect("profile")
}

#[test]
fn exports_and_opens_only_phone_recovery_participant() {
    let mut bootstrap = bootstrap(7);
    let participant3 = bootstrap.secret_packages.remove(&3).unwrap();

    let (bundle, recovery_key) =
        RecoveryBundle::seal(participant3, &bootstrap.profile).expect("seal participant 3");
    let bytes = bundle.to_bytes().expect("serialize bundle");
    assert_eq!(bytes, bundle.to_bytes().expect("serialize bundle again"));
    assert!(bytes.len() <= RECOVERY_BUNDLE_MAX_BYTES);
    assert_eq!(bundle.format_version(), RECOVERY_BUNDLE_FORMAT_VERSION);
    assert_eq!(bundle.participant_id(), 3);
    assert_eq!(bundle.profile_id(), bootstrap.profile.profile_id());
    assert_eq!(bundle.wallet_id(), bootstrap.profile.wallet_id());
    assert_eq!(bundle.signer_set_id(), bootstrap.profile.signer_set_id());
    assert_eq!(bundle.signer_epoch(), bootstrap.profile.signer_epoch());
    assert_eq!(
        bundle.group_pubkey_xonly(),
        bootstrap.profile.group_pubkey_xonly()
    );
    assert_eq!(
        bundle.profile_binding_digest(),
        bootstrap.profile.binding_digest()
    );
    assert_eq!(bundle.kdf_memory_kib(), RECOVERY_KDF_MEMORY_KIB);
    assert_eq!(bundle.kdf_passes(), RECOVERY_KDF_PASSES);
    assert_eq!(bundle.kdf_lanes(), RECOVERY_KDF_LANES);
    assert_eq!(bundle.kdf_output_len(), RECOVERY_KDF_OUTPUT_LEN);
    bundle.verify_checksum().expect("copy checksum");

    let decoded = RecoveryBundle::from_bytes(&bytes).expect("decode bundle");
    let recovered = decoded
        .open(&recovery_key, &bootstrap.profile)
        .expect("authenticated restore");
    assert_eq!(recovered.signer_id(), 3);
    recovered
        .validate(&bootstrap.profile)
        .expect("profile binding");

    for signer_id in [1_u16, 2] {
        assert!(matches!(
            RecoveryBundle::seal(
                bootstrap.secret_packages.remove(&signer_id).unwrap(),
                &bootstrap.profile,
            ),
            Err(RecoveryBundleError::WrongParticipant),
        ));
    }
}

#[test]
fn recovered_participant_completes_one_plus_three_and_two_plus_three_bip340() {
    let mut bootstrap = bootstrap(7);
    let participant3 = bootstrap.secret_packages.remove(&3).unwrap();
    let (bundle, recovery_key) = RecoveryBundle::seal(participant3, &bootstrap.profile).unwrap();

    for peer in [1_u16, 2] {
        let recovered = bundle.open(&recovery_key, &bootstrap.profile).unwrap();
        sign_pair(&bootstrap, peer, recovered, [peer as u8; 32], [0x77; 32]);
    }
}

#[test]
fn wrong_key_and_ciphertext_or_metadata_tampering_are_rejected() {
    let mut bootstrap = bootstrap(7);
    let participant3 = bootstrap.secret_packages.remove(&3).unwrap();
    let (bundle, key) = RecoveryBundle::seal(participant3, &bootstrap.profile).unwrap();
    let mut wrong_key_bytes = *key.to_bytes();
    wrong_key_bytes[0] ^= 1;
    let wrong_key = RecoveryKey::from_bytes(wrong_key_bytes);
    assert!(matches!(
        bundle.open(&wrong_key, &bootstrap.profile),
        Err(RecoveryBundleError::AuthenticationFailed)
    ));
    bundle.open(&key, &bootstrap.profile).unwrap();

    for field in [
        "payload_ciphertext",
        "wrapped_dek",
        "payload_nonce",
        "wrapped_dek_nonce",
        "profile_binding_digest",
        "group_pubkey_xonly",
        "signer_epoch",
        "participant_id",
        "checksum",
    ] {
        let mut wire: Value = serde_json::from_slice(&bundle.to_bytes().unwrap()).unwrap();
        tamper_json_field(&mut wire[field]);
        let bytes = serde_json::to_vec(&wire).unwrap();
        let decoded = RecoveryBundle::from_bytes(&bytes);
        assert!(decoded.is_err(), "tampered {field} must be rejected");
    }
}

#[test]
fn rejects_corrupt_checksum_wrong_profile_and_weak_or_unsupported_wire() {
    let mut signer_bootstrap = bootstrap(7);
    let participant3 = signer_bootstrap.secret_packages.remove(&3).unwrap();
    let (bundle, key) = RecoveryBundle::seal(participant3, &signer_bootstrap.profile).unwrap();
    let other_profile = bootstrap(8).profile;
    assert!(matches!(
        bundle.open(&key, &other_profile),
        Err(RecoveryBundleError::ProfileMismatch)
    ));

    let original: Value = serde_json::from_slice(&bundle.to_bytes().unwrap()).unwrap();
    for (path, replacement, expected) in [
        (
            &["kdf", "memory_kib"][..],
            Value::from(RECOVERY_KDF_MEMORY_KIB - 1),
            RecoveryBundleError::WeakKdfParameters,
        ),
        (
            &["kdf", "passes"][..],
            Value::from(RECOVERY_KDF_PASSES - 1),
            RecoveryBundleError::WeakKdfParameters,
        ),
        (
            &["kdf", "lanes"][..],
            Value::from(RECOVERY_KDF_LANES - 1),
            RecoveryBundleError::WeakKdfParameters,
        ),
        (
            &["kdf", "output_len"][..],
            Value::from(RECOVERY_KDF_OUTPUT_LEN - 1),
            RecoveryBundleError::WeakKdfParameters,
        ),
        (
            &["kdf", "memory_kib"][..],
            Value::from(RECOVERY_KDF_MEMORY_KIB + 1),
            RecoveryBundleError::WeakKdfParameters,
        ),
        (
            &["format_version"][..],
            Value::from(RECOVERY_BUNDLE_FORMAT_VERSION - 1),
            RecoveryBundleError::UnsupportedVersion,
        ),
    ] {
        let mut wire = original.clone();
        set_path(&mut wire, path, replacement);
        let result = RecoveryBundle::from_bytes(&serde_json::to_vec(&wire).unwrap());
        assert_eq!(result.unwrap_err(), expected);
    }

    let mut unknown = original.clone();
    unknown["unexpected"] = Value::Bool(true);
    assert_eq!(
        RecoveryBundle::from_bytes(&serde_json::to_vec(&unknown).unwrap()).unwrap_err(),
        RecoveryBundleError::InvalidEncoding
    );
    assert!(matches!(
        RecoveryBundle::from_bytes(&vec![b' '; RECOVERY_BUNDLE_MAX_BYTES + 1]),
        Err(RecoveryBundleError::BundleTooLarge)
    ));
}

#[test]
fn debug_output_redacts_recovery_key_and_ciphertexts() {
    let mut bootstrap = bootstrap(7);
    let participant3 = bootstrap.secret_packages.remove(&3).unwrap();
    let (bundle, generated_key) = RecoveryBundle::seal(participant3, &bootstrap.profile).unwrap();
    let imported_key = RecoveryKey::from_bytes(*generated_key.to_bytes());

    let key_debug = format!("{imported_key:?}");
    assert!(key_debug.contains("redacted"));
    assert!(!key_debug.contains("66"));
    let bundle_debug = format!("{bundle:?}");
    assert!(bundle_debug.contains("redacted"));
    let wire = String::from_utf8(bundle.to_bytes().unwrap()).unwrap();
    let encoded: Value = serde_json::from_str(&wire).unwrap();
    let ciphertext = serde_json::to_string(&encoded["payload_ciphertext"]).unwrap();
    assert!(!bundle_debug.contains(&ciphertext));
}

fn sign_pair(
    bootstrap: &PersonalSignerBootstrap,
    peer: u16,
    recovered: PersonalParticipantSecretPackage,
    session_id: [u8; 32],
    message: [u8; 32],
) {
    let mut participants = BTreeMap::new();
    for (signer_id, package) in [(peer, &bootstrap.secret_packages[&peer]), (3, &recovered)] {
        let participant = package
            .open(&bootstrap.profile)
            .unwrap()
            .into_participant(NonceGuard::new())
            .unwrap();
        participants.insert(signer_id, participant);
    }
    let mut coordinator = FrostCoordinator::new(
        session_id,
        message,
        bootstrap.profile.min_signers(),
        bootstrap.profile.public_key_package().unwrap(),
    );
    for signer_id in [peer, 3] {
        let commitment = participants
            .get_mut(&signer_id)
            .unwrap()
            .round1(session_id, message)
            .unwrap();
        coordinator.add_commitment(signer_id, commitment).unwrap();
    }
    let session = coordinator.signing_session().unwrap();
    for signer_id in [peer, 3] {
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
    ) -> Result<(), catomicals_threshold::AuthorizationError> {
        if self.used {
            return Err(catomicals_threshold::AuthorizationError::AlreadyConsumed);
        }
        if session_id != &self.session {
            return Err(catomicals_threshold::AuthorizationError::WrongSession);
        }
        if message != &self.message {
            return Err(catomicals_threshold::AuthorizationError::WrongMessage);
        }
        if signer_id != self.signer {
            return Err(catomicals_threshold::AuthorizationError::WrongSigner);
        }
        self.used = true;
        Ok(())
    }
}

fn tamper_json_field(value: &mut Value) {
    match value {
        Value::Array(values) => {
            values[0] = Value::from(values[0].as_u64().unwrap() ^ 1);
        }
        Value::Number(number) => {
            *value = Value::from(number.as_u64().unwrap() ^ 1);
        }
        _ => panic!("unsupported tamper field"),
    }
}

fn set_path(root: &mut Value, path: &[&str], replacement: Value) {
    let mut current = root;
    for segment in &path[..path.len() - 1] {
        current = &mut current[*segment];
    }
    current[path[path.len() - 1]] = replacement;
}

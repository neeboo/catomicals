use std::collections::BTreeMap;

use catomicals_threshold::{
    AuthorizationError, CoordinatorError, FrostCoordinator, LocalFrostParticipant, NonceGuard,
    SigningAuthorization, SigningError, group_pubkey_xonly, participant_identifier, run_local_dkg,
};

struct ExactAuthorization {
    session: [u8; 32],
    message: [u8; 32],
    signer: u16,
    expires: i64,
    used: bool,
}

impl SigningAuthorization for ExactAuthorization {
    fn authorize(
        &mut self,
        session_id: &[u8; 32],
        message: &[u8; 32],
        signer_id: u16,
        now: i64,
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
        if now > self.expires {
            return Err(AuthorizationError::Expired);
        }
        self.used = true;
        Ok(())
    }
}

fn authorization(session: [u8; 32], message: [u8; 32], signer: u16) -> ExactAuthorization {
    ExactAuthorization {
        session,
        message,
        signer,
        expires: 200,
        used: false,
    }
}

#[test]
fn local_dkg_drives_two_of_three_signing_through_explicit_rounds() {
    let generated = run_local_dkg(3, 2).expect("distributed key generation");
    assert_eq!(generated.key_packages.len(), 3);
    assert_eq!(generated.min_signers, 2);
    assert_eq!(generated.max_signers, 3);
    assert_ne!(
        group_pubkey_xonly(&generated.public_key_package).expect("public key"),
        [0; 32]
    );

    let session_id = [0x31; 32];
    let message = [0x42; 32];
    let mut participants: BTreeMap<_, _> = generated
        .key_packages
        .into_iter()
        .map(|(id, package)| {
            let signer_id = if id == 1u16.try_into().unwrap() {
                1
            } else if id == 2u16.try_into().unwrap() {
                2
            } else {
                3
            };
            (
                signer_id,
                LocalFrostParticipant::new(signer_id, package, NonceGuard::new())
                    .expect("participant"),
            )
        })
        .collect();
    let mut coordinator =
        FrostCoordinator::new(session_id, message, 2, generated.public_key_package);

    for signer_id in [1, 2] {
        let commitment = participants
            .get_mut(&signer_id)
            .unwrap()
            .round1(session_id, message)
            .expect("round one");
        coordinator
            .add_commitment(signer_id, commitment)
            .expect("commitment");
    }
    let session = coordinator.signing_session().expect("session");
    for signer_id in [1, 2] {
        let share = participants
            .get_mut(&signer_id)
            .unwrap()
            .round2(
                &session,
                &mut authorization(session_id, message, signer_id),
                100,
            )
            .expect("round two");
        coordinator.add_signature_share(signer_id, share).unwrap();
    }
    let signature = coordinator.finalize().expect("aggregate signature");
    assert_eq!(
        catomicals_threshold::signature_to_bytes(&signature)
            .unwrap()
            .len(),
        64
    );
}

#[test]
fn participant_rejects_session_message_and_round_replay_substitution() {
    let generated = run_local_dkg(3, 2).unwrap();
    let key = generated.key_packages[&1u16.try_into().unwrap()].clone();
    let mut participant = LocalFrostParticipant::new(1, key, NonceGuard::new()).unwrap();
    let session_id = [7; 32];
    let message = [8; 32];
    let own = participant.round1(session_id, message).unwrap();
    let other_key = generated.key_packages[&2u16.try_into().unwrap()].clone();
    let mut other = LocalFrostParticipant::new(2, other_key, NonceGuard::new()).unwrap();
    let other_commitment = other.round1(session_id, message).unwrap();

    let mut coordinator =
        FrostCoordinator::new(session_id, message, 2, generated.public_key_package.clone());
    coordinator.add_commitment(1, own).unwrap();
    coordinator.add_commitment(2, other_commitment).unwrap();
    let exact = coordinator.signing_session().unwrap();

    let wrong_session = catomicals_threshold::build_session(
        [9; 32],
        message,
        2,
        exact.signing_package.signing_commitments().clone(),
        generated.public_key_package.clone(),
    );
    let error = participant
        .round2(
            &wrong_session,
            &mut authorization(session_id, message, 1),
            100,
        )
        .unwrap_err();
    assert!(matches!(error, SigningError::RoundOneNotFound));

    let wrong_message = catomicals_threshold::build_session(
        session_id,
        [10; 32],
        2,
        exact.signing_package.signing_commitments().clone(),
        generated.public_key_package,
    );
    let error = participant
        .round2(
            &wrong_message,
            &mut authorization(session_id, message, 1),
            100,
        )
        .unwrap_err();
    assert!(matches!(error, SigningError::RoundBindingMismatch));

    participant
        .round2(&exact, &mut authorization(session_id, message, 1), 100)
        .unwrap();
    let replay = participant
        .round2(&exact, &mut authorization(session_id, message, 1), 100)
        .unwrap_err();
    assert!(matches!(replay, SigningError::RoundOneNotFound));
}

#[test]
fn coordinator_rejects_duplicate_participant_and_under_threshold_finalize() {
    let generated = run_local_dkg(3, 2).unwrap();
    let mut participant = LocalFrostParticipant::new(
        1,
        generated.key_packages[&1u16.try_into().unwrap()].clone(),
        NonceGuard::new(),
    )
    .unwrap();
    let commitment = participant.round1([1; 32], [2; 32]).unwrap();
    let mut other = LocalFrostParticipant::new(
        2,
        generated.key_packages[&2u16.try_into().unwrap()].clone(),
        NonceGuard::new(),
    )
    .unwrap();
    let other_commitment = other.round1([1; 32], [2; 32]).unwrap();
    let mut coordinator = FrostCoordinator::new([1; 32], [2; 32], 2, generated.public_key_package);
    coordinator.add_commitment(1, commitment).unwrap();
    assert!(matches!(
        coordinator.add_commitment(1, other_commitment),
        Err(CoordinatorError::DuplicateParticipant(1))
    ));
    assert!(matches!(
        coordinator.signing_session(),
        Err(CoordinatorError::InsufficientCommitments { .. })
    ));
    coordinator.add_commitment(2, other_commitment).unwrap();
    let session = coordinator.signing_session().unwrap();
    assert_eq!(
        session
            .signing_package
            .signing_commitments()
            .get(&participant_identifier(1).unwrap()),
        Some(&commitment),
        "a rejected duplicate must not replace the first commitment"
    );
}

#[test]
fn participant_exposes_only_a_stable_pending_nonce_fingerprint() {
    let mut generated = run_local_dkg(3, 2).unwrap();
    let identifier = participant_identifier(1).unwrap();
    let key_package = generated.key_packages.remove(&identifier).unwrap();
    let mut participant = LocalFrostParticipant::new(1, key_package, NonceGuard::new()).unwrap();
    let session_id = [0x41; 32];
    let message = [0x42; 32];

    participant.round1(session_id, message).unwrap();
    let first = participant
        .pending_nonce_fingerprint(&session_id, &message)
        .unwrap();
    let second = participant
        .pending_nonce_fingerprint(&session_id, &message)
        .unwrap();
    assert_eq!(first, second);
    assert_ne!(first, [0; 32]);
    assert!(
        participant
            .pending_nonce_fingerprint(&session_id, &[0x43; 32])
            .is_err()
    );
}

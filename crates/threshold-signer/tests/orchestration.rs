use std::collections::BTreeMap;

use catomicals_threshold::{
    AuthorizationError, BoundParticipant, LocalFrostParticipant, NonceGuard, OrchestrationError,
    SessionPhase, SigningAuthorization, ThresholdSessionMachine, participant_identifier,
    run_local_dkg, signature_to_bytes,
};
use frost_secp256k1_tr::round2::SignatureShare;
use uuid::Uuid;

struct ExactAuthorization {
    session: [u8; 32],
    message: [u8; 32],
    signer_id: u16,
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
        if signer_id != self.signer_id {
            return Err(AuthorizationError::WrongSigner);
        }
        self.used = true;
        Ok(())
    }
}

fn authorization(session: [u8; 32], message: [u8; 32], signer_id: u16) -> ExactAuthorization {
    ExactAuthorization {
        session,
        message,
        signer_id,
        used: false,
    }
}

fn bindings() -> Vec<BoundParticipant> {
    (1..=3)
        .map(|signer_id| BoundParticipant {
            signer_id,
            device_id: Uuid::from_bytes([signer_id as u8; 16]),
            device_generation: 1,
            request_binding_digest: [signer_id as u8 + 10; 32],
        })
        .collect()
}

#[test]
fn valid_two_of_three_flow_verifies_each_share_and_final_signature() {
    let generated = run_local_dkg(3, 2).unwrap();
    let mut signers: BTreeMap<_, _> = (1..=3)
        .map(|signer_id| {
            let key = generated.key_packages[&participant_identifier(signer_id).unwrap()].clone();
            (
                signer_id,
                LocalFrostParticipant::new(signer_id, key, NonceGuard::new()).unwrap(),
            )
        })
        .collect();
    let session_id = [0x31; 32];
    let message = [0x32; 32];
    let expected = bindings();
    let mut machine = ThresholdSessionMachine::new(
        session_id,
        message,
        [0x33; 32],
        2,
        200,
        expected.clone(),
        generated.public_key_package,
        100,
    )
    .unwrap();

    for signer_id in [1, 2] {
        let commitment = signers
            .get_mut(&signer_id)
            .unwrap()
            .round1(session_id, message)
            .unwrap();
        machine
            .add_commitment(&expected[usize::from(signer_id - 1)], commitment, 101)
            .unwrap();
    }
    let session = machine.freeze_commitments(102).unwrap().clone();
    for signer_id in [1, 2] {
        let share = signers
            .get_mut(&signer_id)
            .unwrap()
            .round2(
                &session,
                &mut authorization(session_id, message, signer_id),
                103,
            )
            .unwrap();
        machine
            .add_signature_share(&expected[usize::from(signer_id - 1)], share, 104)
            .unwrap();
    }
    let signature = machine.finalize(105).unwrap();
    assert_eq!(signature_to_bytes(&signature).unwrap().len(), 64);
    assert_eq!(machine.phase(), SessionPhase::Finalized);
    assert!(machine.verify_audit_chain());
    assert_eq!(machine.audit().last().unwrap().sequence, 7);
}

#[test]
fn identity_drift_is_terminal_and_is_audited() {
    let generated = run_local_dkg(3, 2).unwrap();
    let expected = bindings();
    let mut signer = LocalFrostParticipant::new(
        1,
        generated.key_packages[&participant_identifier(1).unwrap()].clone(),
        NonceGuard::new(),
    )
    .unwrap();
    let mut machine = ThresholdSessionMachine::new(
        [1; 32],
        [2; 32],
        [3; 32],
        2,
        200,
        expected.clone(),
        generated.public_key_package,
        100,
    )
    .unwrap();
    let commitment = signer.round1([1; 32], [2; 32]).unwrap();
    let mut drifted = expected[0].clone();
    drifted.device_generation += 1;

    assert_eq!(
        machine.add_commitment(&drifted, commitment, 101),
        Err(OrchestrationError::IdentityDrift)
    );
    assert_eq!(machine.phase(), SessionPhase::Failed);
    assert_eq!(
        machine.audit().last().unwrap().code.as_deref(),
        Some("identity_drift")
    );
    assert!(machine.verify_audit_chain());
}

#[test]
fn invalid_share_is_verified_before_storage_and_fails_closed() {
    let generated = run_local_dkg(3, 2).unwrap();
    let mut signers: BTreeMap<_, _> = (1..=2)
        .map(|signer_id| {
            let key = generated.key_packages[&participant_identifier(signer_id).unwrap()].clone();
            (
                signer_id,
                LocalFrostParticipant::new(signer_id, key, NonceGuard::new()).unwrap(),
            )
        })
        .collect();
    let expected = bindings();
    let mut machine = ThresholdSessionMachine::new(
        [4; 32],
        [5; 32],
        [6; 32],
        2,
        200,
        expected.clone(),
        generated.public_key_package,
        100,
    )
    .unwrap();
    for signer_id in [1, 2] {
        let commitment = signers
            .get_mut(&signer_id)
            .unwrap()
            .round1([4; 32], [5; 32])
            .unwrap();
        machine
            .add_commitment(&expected[usize::from(signer_id - 1)], commitment, 101)
            .unwrap();
    }
    let session = machine.freeze_commitments(102).unwrap().clone();
    let valid_share = signers
        .get_mut(&1)
        .unwrap()
        .round2(&session, &mut authorization([4; 32], [5; 32], 1), 103)
        .unwrap();
    let mut corrupted = valid_share.serialize();
    corrupted[0] ^= 1;
    let corrupted = SignatureShare::deserialize(&corrupted).unwrap();

    assert_eq!(
        machine.add_signature_share(&expected[0], corrupted, 104),
        Err(OrchestrationError::InvalidSignatureShare)
    );
    assert_eq!(machine.phase(), SessionPhase::Failed);
    assert_eq!(
        machine.audit().last().unwrap().code.as_deref(),
        Some("invalid_signature_share")
    );
}

#[test]
fn timeout_and_operator_abort_are_terminal() {
    let generated = run_local_dkg(3, 2).unwrap();
    let expected = bindings();
    let mut expired = ThresholdSessionMachine::new(
        [7; 32],
        [8; 32],
        [9; 32],
        2,
        110,
        expected.clone(),
        generated.public_key_package.clone(),
        100,
    )
    .unwrap();
    assert!(expired.expire(111));
    assert_eq!(expired.phase(), SessionPhase::Expired);
    assert!(expired.verify_audit_chain());

    let mut aborted = ThresholdSessionMachine::new(
        [10; 32],
        [11; 32],
        [12; 32],
        2,
        200,
        expected,
        generated.public_key_package,
        100,
    )
    .unwrap();
    aborted.abort("operator_cancelled", 101).unwrap();
    assert_eq!(aborted.phase(), SessionPhase::Aborted);
    assert_eq!(
        aborted.audit().last().unwrap().code.as_deref(),
        Some("operator_cancelled")
    );
    assert!(aborted.verify_audit_chain());
}

use catomicals_chain_domain::{ChainNetwork, ChainScope, ErgoNetwork};
use catomicals_chain_ergo::{
    ErgoAdapterError, ErgoThresholdNonceReplayGuard, ErgoThresholdNonceReservation,
    ErgoThresholdSigningPackage, aggregate_threshold_p2pk_proof_2_of_3,
    dealer_split_threshold_secret_2_of_3, generate_threshold_nonces_2_of_3,
    sign_threshold_share_2_of_3,
};
use catomicals_signing_domain::{ReviewBinding, SigningSuiteId};
use ergo_lib::{
    ergotree_interpreter::sigma_protocol::verifier::verify_signature,
    ergotree_ir::sigma_protocol::sigma_boolean::{
        ProveDlog, SigmaBoolean, SigmaProofOfKnowledgeTree,
    },
};
use sigma_ser::ScorexSerializable;
use std::collections::BTreeMap;

#[derive(Default)]
struct MemoryReplayGuard(BTreeMap<[u8; 32], bool>);

struct RejectConsumeGuard;

impl ErgoThresholdNonceReplayGuard for RejectConsumeGuard {
    fn reserve(
        &mut self,
        _reservation: &ErgoThresholdNonceReservation,
    ) -> Result<(), ErgoAdapterError> {
        Ok(())
    }

    fn consume(
        &mut self,
        _reservation: &ErgoThresholdNonceReservation,
        _transcript_digest: [u8; 32],
    ) -> Result<(), ErgoAdapterError> {
        Err(ErgoAdapterError::ThresholdNonceReplay(
            "durable nonce record is already consumed".into(),
        ))
    }
}

impl ErgoThresholdNonceReplayGuard for MemoryReplayGuard {
    fn reserve(
        &mut self,
        reservation: &ErgoThresholdNonceReservation,
    ) -> Result<(), ErgoAdapterError> {
        if self
            .0
            .insert(reservation.nonce_fingerprint, false)
            .is_some()
        {
            return Err(ErgoAdapterError::ThresholdNonceReplay(
                "duplicate reservation".into(),
            ));
        }
        Ok(())
    }

    fn consume(
        &mut self,
        reservation: &ErgoThresholdNonceReservation,
        _transcript_digest: [u8; 32],
    ) -> Result<(), ErgoAdapterError> {
        match self.0.get_mut(&reservation.nonce_fingerprint) {
            Some(consumed @ false) => {
                *consumed = true;
                Ok(())
            }
            _ => Err(ErgoAdapterError::ThresholdNonceReplay(
                "nonce already consumed".into(),
            )),
        }
    }
}

fn review_binding(tag: u8) -> ReviewBinding {
    ReviewBinding::new(
        ChainScope::for_network(ChainNetwork::Ergo(ErgoNetwork::Testnet)),
        SigningSuiteId::ERGO_SIGMA_P2PK_THRESHOLD_2OF3_V1,
        "ergo-threshold-test",
        1,
        1,
        [tag; 32],
    )
    .unwrap()
}

fn proposition(public_key: [u8; 33]) -> SigmaBoolean {
    let point = ergo_lib::ergo_chain_types::EcPoint::scorex_parse_bytes(&public_key).unwrap();
    SigmaBoolean::ProofOfKnowledge(SigmaProofOfKnowledgeTree::ProveDlog(ProveDlog::new(point)))
}

#[test]
fn every_two_of_three_quorum_produces_a_native_ergo_p2pk_proof() {
    let dealer = dealer_split_threshold_secret_2_of_3([0x11; 32], [0x22; 32]).unwrap();
    let message = b"reviewed Ergo transaction bytes";
    let binding = review_binding(0x91);

    for quorum in [[0, 1], [0, 2], [1, 2]] {
        let session_id = [u8::try_from(quorum[0] * 3 + quorum[1] + 1).unwrap(); 32];
        let mut replay_guard = MemoryReplayGuard::default();
        let first = &dealer.shares()[quorum[0]];
        let second = &dealer.shares()[quorum[1]];
        let first_nonces =
            generate_threshold_nonces_2_of_3(first, session_id, &mut replay_guard).unwrap();
        let second_nonces =
            generate_threshold_nonces_2_of_3(second, session_id, &mut replay_guard).unwrap();
        let package = ErgoThresholdSigningPackage::new(
            dealer.commitment(),
            &binding,
            session_id,
            message,
            &[first_nonces.commitments(), second_nonces.commitments()],
        )
        .unwrap();
        let partials = [
            sign_threshold_share_2_of_3(
                dealer.commitment(),
                first,
                first_nonces,
                &binding,
                &package,
                &mut replay_guard,
            )
            .unwrap(),
            sign_threshold_share_2_of_3(
                dealer.commitment(),
                second,
                second_nonces,
                &binding,
                &package,
                &mut replay_guard,
            )
            .unwrap(),
        ];
        let proof = aggregate_threshold_p2pk_proof_2_of_3(dealer.commitment(), &package, &partials)
            .unwrap();

        assert_eq!(proof.as_bytes().len(), 56);
        assert!(
            verify_signature(
                proposition(dealer.commitment().group_public_key()),
                message,
                proof.as_bytes(),
            )
            .unwrap()
        );
    }
}

#[test]
fn threshold_signing_rejects_mixed_transcripts_and_invalid_partials() {
    let dealer = dealer_split_threshold_secret_2_of_3([0x31; 32], [0x12; 32]).unwrap();
    let binding = review_binding(0x92);
    let session_id = [0x32; 32];
    let mut replay_guard = MemoryReplayGuard::default();
    let first_nonces =
        generate_threshold_nonces_2_of_3(&dealer.shares()[0], session_id, &mut replay_guard)
            .unwrap();
    let second_nonces =
        generate_threshold_nonces_2_of_3(&dealer.shares()[1], session_id, &mut replay_guard)
            .unwrap();
    let package = ErgoThresholdSigningPackage::new(
        dealer.commitment(),
        &binding,
        session_id,
        b"approved transaction",
        &[first_nonces.commitments(), second_nonces.commitments()],
    )
    .unwrap();
    let first = sign_threshold_share_2_of_3(
        dealer.commitment(),
        &dealer.shares()[0],
        first_nonces,
        &binding,
        &package,
        &mut replay_guard,
    )
    .unwrap();
    let mut second = sign_threshold_share_2_of_3(
        dealer.commitment(),
        &dealer.shares()[1],
        second_nonces,
        &binding,
        &package,
        &mut replay_guard,
    )
    .unwrap();

    second.response[0] ^= 1;
    assert!(
        aggregate_threshold_p2pk_proof_2_of_3(dealer.commitment(), &package, &[first, second],)
            .is_err()
    );
}

#[test]
fn threshold_secrets_and_nonces_are_redacted() {
    let dealer = dealer_split_threshold_secret_2_of_3([0x41; 32], [0x13; 32]).unwrap();
    let mut replay_guard = MemoryReplayGuard::default();
    let nonces =
        generate_threshold_nonces_2_of_3(&dealer.shares()[0], [0x41; 32], &mut replay_guard)
            .unwrap();

    assert!(format!("{:?}", dealer.shares()[0]).contains("[REDACTED]"));
    assert!(format!("{nonces:?}").contains("[REDACTED]"));
}

#[test]
fn signing_package_cannot_be_reused_with_another_feldman_commitment() {
    let first_dealer = dealer_split_threshold_secret_2_of_3([0x51; 32], [0x14; 32]).unwrap();
    let second_dealer = dealer_split_threshold_secret_2_of_3([0x51; 32], [0x15; 32]).unwrap();
    let binding = review_binding(0x93);
    let session_id = [0x51; 32];
    let mut replay_guard = MemoryReplayGuard::default();
    let first_nonces =
        generate_threshold_nonces_2_of_3(&second_dealer.shares()[0], session_id, &mut replay_guard)
            .unwrap();
    let second_nonces =
        generate_threshold_nonces_2_of_3(&second_dealer.shares()[1], session_id, &mut replay_guard)
            .unwrap();
    let package = ErgoThresholdSigningPackage::new(
        first_dealer.commitment(),
        &binding,
        session_id,
        b"same group key and message",
        &[first_nonces.commitments(), second_nonces.commitments()],
    )
    .unwrap();

    assert!(matches!(
        sign_threshold_share_2_of_3(
            second_dealer.commitment(),
            &second_dealer.shares()[0],
            first_nonces,
            &binding,
            &package,
            &mut replay_guard,
        ),
        Err(ErgoAdapterError::ThresholdSigningPackageMismatch)
    ));
}

#[test]
fn signer_rejects_a_package_for_another_review_binding() {
    let dealer = dealer_split_threshold_secret_2_of_3([0x61; 32], [0x16; 32]).unwrap();
    let approved = review_binding(0xa1);
    let substituted = review_binding(0xa2);
    let session_id = [0x61; 32];
    let mut replay_guard = MemoryReplayGuard::default();
    let first_nonces =
        generate_threshold_nonces_2_of_3(&dealer.shares()[0], session_id, &mut replay_guard)
            .unwrap();
    let second_nonces =
        generate_threshold_nonces_2_of_3(&dealer.shares()[1], session_id, &mut replay_guard)
            .unwrap();
    let package = ErgoThresholdSigningPackage::new(
        dealer.commitment(),
        &substituted,
        session_id,
        b"same native Ergo message",
        &[first_nonces.commitments(), second_nonces.commitments()],
    )
    .unwrap();

    assert!(matches!(
        sign_threshold_share_2_of_3(
            dealer.commitment(),
            &dealer.shares()[0],
            first_nonces,
            &approved,
            &package,
            &mut replay_guard,
        ),
        Err(ErgoAdapterError::ThresholdReviewBindingMismatch)
    ));
}

#[test]
fn signer_fails_closed_when_the_durable_nonce_guard_rejects_consumption() {
    let dealer = dealer_split_threshold_secret_2_of_3([0x71; 32], [0x17; 32]).unwrap();
    let binding = review_binding(0xb1);
    let session_id = [0x71; 32];
    let mut guard = RejectConsumeGuard;
    let first_nonces =
        generate_threshold_nonces_2_of_3(&dealer.shares()[0], session_id, &mut guard).unwrap();
    let second_nonces =
        generate_threshold_nonces_2_of_3(&dealer.shares()[1], session_id, &mut guard).unwrap();
    let package = ErgoThresholdSigningPackage::new(
        dealer.commitment(),
        &binding,
        session_id,
        b"approved transaction",
        &[first_nonces.commitments(), second_nonces.commitments()],
    )
    .unwrap();

    assert!(matches!(
        sign_threshold_share_2_of_3(
            dealer.commitment(),
            &dealer.shares()[0],
            first_nonces,
            &binding,
            &package,
            &mut guard,
        ),
        Err(ErgoAdapterError::ThresholdNonceReplay(_))
    ));
}

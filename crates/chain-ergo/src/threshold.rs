//! Two-round 2-of-3 threshold Schnorr for native Ergo P2PK proofs.
//!
//! Ergo P2PK verifies a ProveDlog Sigma proof encoded as a 24-byte Fiat-Shamir
//! challenge followed by a 32-byte response. This module distributes the
//! witness for that exact public key. The resulting 56-byte proof is verified
//! by sigma-rust and does not require a different on-chain script.

use core::fmt;

use blake2::{Blake2b, Digest, digest::consts::U32};
use ergo_lib::{
    chain::transaction::{Transaction, reduced::reduce_tx},
    ergo_chain_types::{EcPoint, ec_point::is_identity},
    ergotree_interpreter::sigma_protocol::{prover::ProofBytes, verifier::verify_signature},
    ergotree_ir::{
        ergo_tree::{ErgoTree, ErgoTreeHeader},
        mir::{constant::Constant, expr::Expr},
        serialization::SigmaSerializable,
        sigma_protocol::sigma_boolean::{
            ProveDlog, SigmaBoolean, SigmaProofOfKnowledgeTree, SigmaProp,
        },
    },
};
use k256::elliptic_curve::{Field, Group, PrimeField, ops::Reduce};
use k256::{ProjectivePoint, Scalar, U256};
use rand_core::OsRng;
use sigma_ser::ScorexSerializable;
use zeroize::{Zeroize, Zeroizing};

use catomicals_chain_domain::{ChainNetwork, ChainScope, ChainSuite, ErgoNetwork, ReviewArtifact};
use catomicals_signing_domain::{
    ReviewBinding, SignerBackendRequirement, SigningAvailability, SigningExecutionMode,
    SigningSuiteDescriptor, SigningSuiteId, resolve_builtin_suite,
};

use crate::{ErgoAdapterError, ErgoChainSuite, ErgoReviewMaterialV1};

const PARTICIPANTS: core::ops::RangeInclusive<u16> = 1..=3;
const THRESHOLD: usize = 2;
const CHALLENGE_BYTES: usize = 24;
const RESPONSE_BYTES: usize = 32;
const PROOF_BYTES: usize = CHALLENGE_BYTES + RESPONSE_BYTES;
const BINDING_DOMAIN: &[u8] = b"catomicals/ergo-p2pk-threshold/binding/v1";
const TRANSCRIPT_DOMAIN: &[u8] = b"catomicals/ergo-p2pk-threshold/transcript/v1";
const NONCE_FINGERPRINT_DOMAIN: &[u8] = b"catomicals/ergo-p2pk-threshold/nonce/v1";

type Blake2b256 = Blake2b<U32>;

/// Runtime view of the registered executable Ergo threshold suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErgoThresholdP2pkRuntimeDescriptor {
    pub signing_suite: SigningSuiteDescriptor,
    pub threshold: u16,
    pub max_signers: u16,
    pub produces_native_p2pk_proof: bool,
}

impl ErgoThresholdP2pkRuntimeDescriptor {
    pub fn new(network: ErgoNetwork) -> Result<Self, ErgoAdapterError> {
        let scope = ChainScope::for_network(ChainNetwork::Ergo(network));
        let signing_suite =
            resolve_builtin_suite(&scope, SigningSuiteId::ERGO_SIGMA_P2PK_THRESHOLD_2OF3_V1)?;
        if signing_suite.execution_mode != SigningExecutionMode::ThresholdInteractive
            || signing_suite.backend_requirement
                != SignerBackendRequirement::ErgoSigmaP2pkThreshold2of3
            || signing_suite.availability != SigningAvailability::Executable
            || !signing_suite.capabilities.produces_consensus_signature
            || !signing_suite.capabilities.independently_verifiable
            || !signing_suite.capabilities.interactive_threshold
            || signing_suite.capabilities.non_interactive_threshold
        {
            return Err(ErgoAdapterError::ThresholdSuiteContractMismatch);
        }
        Ok(Self {
            signing_suite,
            threshold: 2,
            max_signers: 3,
            produces_native_p2pk_proof: true,
        })
    }
}

/// Public Feldman commitments for `f(x) = secret + coefficient*x`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErgoThresholdCommitment {
    group_public_key: [u8; 33],
    coefficient_public_key: [u8; 33],
}

impl ErgoThresholdCommitment {
    /// Imports and validates both curve points.
    pub fn import(
        group_public_key: [u8; 33],
        coefficient_public_key: [u8; 33],
    ) -> Result<Self, ErgoAdapterError> {
        let group = parse_point(&group_public_key)?;
        let coefficient = parse_point(&coefficient_public_key)?;
        if bool::from(group.is_identity()) || bool::from(coefficient.is_identity()) {
            return Err(ErgoAdapterError::InvalidThresholdCommitment(
                "identity public coefficients are forbidden".into(),
            ));
        }
        Ok(Self {
            group_public_key,
            coefficient_public_key,
        })
    }

    pub const fn group_public_key(&self) -> [u8; 33] {
        self.group_public_key
    }

    pub const fn coefficient_public_key(&self) -> [u8; 33] {
        self.coefficient_public_key
    }

    pub fn share_public_key(&self, participant_id: u16) -> Result<[u8; 33], ErgoAdapterError> {
        validate_participant(participant_id)?;
        let group = parse_point(&self.group_public_key)?;
        let coefficient = parse_point(&self.coefficient_public_key)?;
        point_bytes(group + coefficient * scalar_from_participant(participant_id))
    }

    fn group_point(&self) -> Result<ProjectivePoint, ErgoAdapterError> {
        parse_point(&self.group_public_key)
    }
}

/// One participant's secret Shamir share.
///
/// It is intentionally non-cloneable and non-serializable. Export is an
/// explicit provisioning boundary and returns a zeroizing buffer.
pub struct ErgoThresholdSecretShare {
    participant_id: u16,
    scalar: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for ErgoThresholdSecretShare {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ErgoThresholdSecretShare")
            .field("participant_id", &self.participant_id)
            .field("scalar", &"[REDACTED]")
            .finish()
    }
}

impl ErgoThresholdSecretShare {
    pub fn import_for_signing(
        participant_id: u16,
        scalar: Zeroizing<[u8; 32]>,
    ) -> Result<Self, ErgoAdapterError> {
        validate_participant(participant_id)?;
        parse_nonzero_scalar(&scalar, "secret share")?;
        Ok(Self {
            participant_id,
            scalar,
        })
    }

    pub const fn participant_id(&self) -> u16 {
        self.participant_id
    }

    pub fn export_for_provisioning(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.scalar)
    }

    fn scalar(&self) -> Result<Scalar, ErgoAdapterError> {
        parse_nonzero_scalar(&self.scalar, "secret share")
    }
}

/// Output of a trusted offline dealer split. This is not DKG.
#[derive(Debug)]
pub struct ErgoThresholdDealerOutput {
    commitment: ErgoThresholdCommitment,
    shares: [ErgoThresholdSecretShare; 3],
}

impl ErgoThresholdDealerOutput {
    pub const fn commitment(&self) -> &ErgoThresholdCommitment {
        &self.commitment
    }

    pub const fn shares(&self) -> &[ErgoThresholdSecretShare; 3] {
        &self.shares
    }
}

/// Splits one final Ergo P2PK scalar into three shares with threshold two.
///
/// The caller must deliver shares independently and destroy the dealer input.
pub fn dealer_split_threshold_secret_2_of_3(
    mut group_secret: [u8; 32],
    mut coefficient: [u8; 32],
) -> Result<ErgoThresholdDealerOutput, ErgoAdapterError> {
    let group_secret_owned = Zeroizing::new(group_secret);
    let coefficient_owned = Zeroizing::new(coefficient);
    group_secret.zeroize();
    coefficient.zeroize();
    let group_secret = parse_nonzero_scalar(&group_secret_owned, "group secret")?;
    let coefficient = parse_nonzero_scalar(&coefficient_owned, "dealer coefficient")?;
    let commitment = ErgoThresholdCommitment::import(
        point_bytes(ProjectivePoint::GENERATOR * group_secret)?,
        point_bytes(ProjectivePoint::GENERATOR * coefficient)?,
    )?;

    let make_share = |participant_id: u16| -> Result<ErgoThresholdSecretShare, ErgoAdapterError> {
        let share = group_secret + coefficient * scalar_from_participant(participant_id);
        if bool::from(share.is_zero()) {
            return Err(ErgoAdapterError::InvalidThresholdScalar(
                "zero secret share",
            ));
        }
        ErgoThresholdSecretShare::import_for_signing(
            participant_id,
            Zeroizing::new(share.to_bytes().into()),
        )
    };
    let shares = [make_share(1)?, make_share(2)?, make_share(3)?];
    Ok(ErgoThresholdDealerOutput { commitment, shares })
}

/// Public two-nonce commitment sent in round one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErgoThresholdCommitments {
    pub participant_id: u16,
    pub session_id: [u8; 32],
    pub hiding: [u8; 33],
    pub binding: [u8; 33],
}

/// Public record persisted before round-one commitments leave the signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErgoThresholdNonceReservation {
    pub session_id: [u8; 32],
    pub participant_id: u16,
    pub nonce_fingerprint: [u8; 32],
    pub commitments: ErgoThresholdCommitments,
}

/// Durable replay boundary supplied by wallet storage, a remote signer, or an HSM sidecar.
///
/// `reserve` must commit before round-one material is published. `consume` must be atomic and
/// reject a second call for the same fingerprint, including after process restart.
pub trait ErgoThresholdNonceReplayGuard {
    fn reserve(
        &mut self,
        reservation: &ErgoThresholdNonceReservation,
    ) -> Result<(), ErgoAdapterError>;

    fn consume(
        &mut self,
        reservation: &ErgoThresholdNonceReservation,
        transcript_digest: [u8; 32],
    ) -> Result<(), ErgoAdapterError>;
}

/// Secret nonces for one signing attempt. Consumed by partial signing.
pub struct ErgoThresholdSigningNonces {
    participant_id: u16,
    hiding: Zeroizing<[u8; 32]>,
    binding: Zeroizing<[u8; 32]>,
    commitments: ErgoThresholdCommitments,
    reservation: ErgoThresholdNonceReservation,
}

impl fmt::Debug for ErgoThresholdSigningNonces {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ErgoThresholdSigningNonces")
            .field("participant_id", &self.participant_id)
            .field("nonces", &"[REDACTED]")
            .field("commitments", &self.commitments)
            .finish()
    }
}

impl ErgoThresholdSigningNonces {
    pub fn commitments(&self) -> ErgoThresholdCommitments {
        self.commitments.clone()
    }
}

/// Generates fresh two-nonce FROST-style round-one material.
pub fn generate_threshold_nonces_2_of_3(
    share: &ErgoThresholdSecretShare,
    session_id: [u8; 32],
    replay_guard: &mut impl ErgoThresholdNonceReplayGuard,
) -> Result<ErgoThresholdSigningNonces, ErgoAdapterError> {
    validate_participant(share.participant_id)?;
    validate_session_id(session_id)?;
    let hiding = random_nonzero_scalar();
    let binding = random_nonzero_scalar();
    let commitments = ErgoThresholdCommitments {
        participant_id: share.participant_id,
        session_id,
        hiding: point_bytes(ProjectivePoint::GENERATOR * hiding)?,
        binding: point_bytes(ProjectivePoint::GENERATOR * binding)?,
    };
    let reservation = ErgoThresholdNonceReservation {
        session_id,
        participant_id: share.participant_id,
        nonce_fingerprint: nonce_fingerprint(&commitments),
        commitments: commitments.clone(),
    };
    replay_guard.reserve(&reservation)?;
    Ok(ErgoThresholdSigningNonces {
        participant_id: share.participant_id,
        hiding: Zeroizing::new(hiding.to_bytes().into()),
        binding: Zeroizing::new(binding.to_bytes().into()),
        commitments,
        reservation,
    })
}

/// Wallet-facing, fully reviewed threshold request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErgoThresholdSigningRequest {
    review: ReviewArtifact,
    review_binding: ReviewBinding,
    session_id: [u8; 32],
    message: Vec<u8>,
    runtime: ErgoThresholdP2pkRuntimeDescriptor,
}

impl ErgoThresholdSigningRequest {
    pub fn new(
        review: &ReviewArtifact,
        review_binding: &ReviewBinding,
        session_id: [u8; 32],
    ) -> Result<Self, ErgoAdapterError> {
        validate_session_id(session_id)?;
        let network = match review.scope.network {
            ChainNetwork::Ergo(network) => network,
            _ => return Err(ErgoAdapterError::ThresholdSuiteContractMismatch),
        };
        let runtime = ErgoThresholdP2pkRuntimeDescriptor::new(network)?;
        if review_binding.signing_suite_id != runtime.signing_suite.id {
            return Err(ErgoAdapterError::ThresholdSuiteContractMismatch);
        }
        validate_review_binding(review, review_binding)?;
        let material = ErgoReviewMaterialV1::decode(&review.reviewed_material)?;
        let expected = ErgoChainSuite::new(material.network)
            .review_transaction(&review.reviewed_material)
            .map_err(|error| ErgoAdapterError::InvalidSignedTransaction(error.to_string()))?;
        if expected != *review {
            return Err(ErgoAdapterError::ThresholdReviewBindingMismatch);
        }
        Ok(Self {
            review: review.clone(),
            review_binding: review_binding.clone(),
            session_id,
            message: material.bytes_to_sign,
            runtime,
        })
    }

    pub const fn review(&self) -> &ReviewArtifact {
        &self.review
    }

    pub const fn review_binding(&self) -> &ReviewBinding {
        &self.review_binding
    }

    pub const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }

    pub const fn runtime(&self) -> &ErgoThresholdP2pkRuntimeDescriptor {
        &self.runtime
    }
}

/// Canonical round-two transcript. Commitments are sorted by participant id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErgoThresholdSigningPackage {
    message: Vec<u8>,
    review_binding: ReviewBinding,
    session_id: [u8; 32],
    commitments: [ErgoThresholdCommitments; THRESHOLD],
    transcript_digest: [u8; 32],
    aggregate_commitment: [u8; 33],
    challenge: [u8; CHALLENGE_BYTES],
}

impl ErgoThresholdSigningPackage {
    pub fn new(
        commitment: &ErgoThresholdCommitment,
        review_binding: &ReviewBinding,
        session_id: [u8; 32],
        message: &[u8],
        commitments: &[ErgoThresholdCommitments],
    ) -> Result<Self, ErgoAdapterError> {
        validate_session_id(session_id)?;
        if commitments.len() != THRESHOLD {
            return Err(ErgoAdapterError::InvalidThresholdQuorum {
                actual: commitments.len(),
            });
        }
        let mut ordered = [commitments[0].clone(), commitments[1].clone()];
        ordered.sort_by_key(|item| item.participant_id);
        validate_participant(ordered[0].participant_id)?;
        validate_participant(ordered[1].participant_id)?;
        if ordered[0].participant_id == ordered[1].participant_id {
            return Err(ErgoAdapterError::DuplicateThresholdParticipant(
                ordered[0].participant_id,
            ));
        }
        for item in &ordered {
            if item.session_id != session_id {
                return Err(ErgoAdapterError::ThresholdSessionMismatch);
            }
            parse_nonidentity_point(&item.hiding, "hiding nonce commitment")?;
            parse_nonidentity_point(&item.binding, "binding nonce commitment")?;
        }
        let transcript_digest =
            transcript_digest(commitment, review_binding, session_id, message, &ordered);
        let mut aggregate = ProjectivePoint::IDENTITY;
        for item in &ordered {
            let rho = binding_factor(&transcript_digest, item.participant_id);
            aggregate += parse_point(&item.hiding)? + parse_point(&item.binding)? * rho;
        }
        if bool::from(aggregate.is_identity()) {
            return Err(ErgoAdapterError::InvalidThresholdCommitment(
                "aggregate nonce commitment is identity".into(),
            ));
        }
        let aggregate_commitment = point_bytes(aggregate)?;
        let challenge = ergo_challenge(commitment.group_public_key, aggregate_commitment, message)?;
        Ok(Self {
            message: message.to_vec(),
            review_binding: review_binding.clone(),
            session_id,
            commitments: ordered,
            transcript_digest,
            aggregate_commitment,
            challenge,
        })
    }

    pub fn for_review(
        commitment: &ErgoThresholdCommitment,
        request: &ErgoThresholdSigningRequest,
        commitments: &[ErgoThresholdCommitments],
    ) -> Result<Self, ErgoAdapterError> {
        Self::new(
            commitment,
            &request.review_binding,
            request.session_id,
            &request.message,
            commitments,
        )
    }

    pub fn message(&self) -> &[u8] {
        &self.message
    }

    pub const fn transcript_digest(&self) -> [u8; 32] {
        self.transcript_digest
    }

    pub const fn review_binding(&self) -> &ReviewBinding {
        &self.review_binding
    }

    pub const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }

    fn commitment_for(&self, participant_id: u16) -> Option<&ErgoThresholdCommitments> {
        self.commitments
            .iter()
            .find(|item| item.participant_id == participant_id)
    }

    fn signer_ids(&self) -> [u16; THRESHOLD] {
        [
            self.commitments[0].participant_id,
            self.commitments[1].participant_id,
        ]
    }

    fn validate_commitment(
        &self,
        commitment: &ErgoThresholdCommitment,
    ) -> Result<(), ErgoAdapterError> {
        if transcript_digest(
            commitment,
            &self.review_binding,
            self.session_id,
            &self.message,
            &self.commitments,
        ) == self.transcript_digest
        {
            Ok(())
        } else {
            Err(ErgoAdapterError::ThresholdSigningPackageMismatch)
        }
    }
}

/// One transcript-bound and publicly verifiable response share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErgoThresholdSignatureShare {
    pub participant_id: u16,
    pub transcript_digest: [u8; 32],
    pub response: [u8; 32],
}

/// Consumes fresh nonces and produces one response share.
pub fn sign_threshold_share_2_of_3(
    commitment: &ErgoThresholdCommitment,
    share: &ErgoThresholdSecretShare,
    nonces: ErgoThresholdSigningNonces,
    expected_review_binding: &ReviewBinding,
    package: &ErgoThresholdSigningPackage,
    replay_guard: &mut impl ErgoThresholdNonceReplayGuard,
) -> Result<ErgoThresholdSignatureShare, ErgoAdapterError> {
    package.validate_commitment(commitment)?;
    if &package.review_binding != expected_review_binding {
        return Err(ErgoAdapterError::ThresholdReviewBindingMismatch);
    }
    if package.session_id != nonces.commitments.session_id {
        return Err(ErgoAdapterError::ThresholdSessionMismatch);
    }
    let participant_id = share.participant_id;
    if participant_id != nonces.participant_id {
        return Err(ErgoAdapterError::ThresholdNonceCommitmentMismatch { participant_id });
    }
    validate_threshold_secret_share(commitment, share)?;
    let expected_nonces = package
        .commitment_for(participant_id)
        .ok_or(ErgoAdapterError::ThresholdNonceCommitmentMismatch { participant_id })?;
    if expected_nonces != &nonces.commitments {
        return Err(ErgoAdapterError::ThresholdNonceCommitmentMismatch { participant_id });
    }
    replay_guard.consume(&nonces.reservation, package.transcript_digest)?;
    let hiding = parse_nonzero_scalar(&nonces.hiding, "hiding nonce")?;
    let binding = parse_nonzero_scalar(&nonces.binding, "binding nonce")?;
    let rho = binding_factor(&package.transcript_digest, participant_id);
    let challenge = challenge_scalar(&package.challenge);
    let lambda = lagrange_coefficient(participant_id, package.signer_ids())?;
    let response = hiding + rho * binding + challenge * lambda * share.scalar()?;
    Ok(ErgoThresholdSignatureShare {
        participant_id,
        transcript_digest: package.transcript_digest,
        response: response.to_bytes().into(),
    })
}

/// Verifies an imported scalar against the corresponding Feldman commitment.
pub fn validate_threshold_secret_share(
    commitment: &ErgoThresholdCommitment,
    share: &ErgoThresholdSecretShare,
) -> Result<(), ErgoAdapterError> {
    let participant_id = share.participant_id;
    let expected_share = commitment.share_public_key(participant_id)?;
    let actual_share = point_bytes(ProjectivePoint::GENERATOR * share.scalar()?)?;
    if expected_share != actual_share {
        return Err(ErgoAdapterError::ThresholdShareCommitmentMismatch { participant_id });
    }
    Ok(())
}

/// Native Ergo P2PK proof bytes: 24-byte challenge plus 32-byte response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErgoP2pkProof {
    bytes: [u8; PROOF_BYTES],
    review_binding: ReviewBinding,
}

impl ErgoP2pkProof {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Verifies two partials and aggregates them into one native Ergo proof.
pub fn aggregate_threshold_p2pk_proof_2_of_3(
    commitment: &ErgoThresholdCommitment,
    package: &ErgoThresholdSigningPackage,
    partials: &[ErgoThresholdSignatureShare],
) -> Result<ErgoP2pkProof, ErgoAdapterError> {
    package.validate_commitment(commitment)?;
    if partials.len() != THRESHOLD {
        return Err(ErgoAdapterError::InvalidThresholdQuorum {
            actual: partials.len(),
        });
    }
    let mut seen = Vec::with_capacity(THRESHOLD);
    let challenge = challenge_scalar(&package.challenge);
    let signer_ids = package.signer_ids();
    let mut response = Scalar::ZERO;
    for partial in partials {
        validate_participant(partial.participant_id)?;
        if seen.contains(&partial.participant_id) {
            return Err(ErgoAdapterError::DuplicateThresholdParticipant(
                partial.participant_id,
            ));
        }
        seen.push(partial.participant_id);
        if partial.transcript_digest != package.transcript_digest {
            return Err(ErgoAdapterError::ThresholdTranscriptMismatch {
                participant_id: partial.participant_id,
            });
        }
        let round_one = package.commitment_for(partial.participant_id).ok_or(
            ErgoAdapterError::InvalidThresholdPartial {
                participant_id: partial.participant_id,
            },
        )?;
        let z = parse_scalar(&partial.response, "partial response")?;
        let rho = binding_factor(&package.transcript_digest, partial.participant_id);
        let lambda = lagrange_coefficient(partial.participant_id, signer_ids)?;
        let verifying_share = parse_point(&commitment.share_public_key(partial.participant_id)?)?;
        let expected = parse_point(&round_one.hiding)?
            + parse_point(&round_one.binding)? * rho
            + verifying_share * (challenge * lambda);
        if ProjectivePoint::GENERATOR * z != expected {
            return Err(ErgoAdapterError::InvalidThresholdPartial {
                participant_id: partial.participant_id,
            });
        }
        response += z;
    }

    let mut bytes = [0_u8; PROOF_BYTES];
    bytes[..CHALLENGE_BYTES].copy_from_slice(&package.challenge);
    bytes[CHALLENGE_BYTES..].copy_from_slice(response.to_bytes().as_slice());
    let proof = ErgoP2pkProof {
        bytes,
        review_binding: package.review_binding.clone(),
    };
    if !verify_signature(
        p2pk_proposition(commitment.group_point()?),
        &package.message,
        proof.as_bytes(),
    )
    .map_err(|error| ErgoAdapterError::InvalidThresholdCommitment(error.to_string()))?
    {
        return Err(ErgoAdapterError::InvalidThresholdFinalProof);
    }
    Ok(proof)
}

/// Installs one native threshold proof per reviewed input and returns the
/// canonical full transaction encoding accepted by Ergo nodes.
pub fn assemble_threshold_p2pk_transaction(
    review: &ReviewArtifact,
    review_binding: &ReviewBinding,
    commitment: &ErgoThresholdCommitment,
    proofs: &[ErgoP2pkProof],
) -> Result<Vec<u8>, ErgoAdapterError> {
    validate_review_binding(review, review_binding)?;
    if proofs
        .iter()
        .any(|proof| &proof.review_binding != review_binding)
    {
        return Err(ErgoAdapterError::ThresholdReviewBindingMismatch);
    }
    let material = ErgoReviewMaterialV1::decode(&review.reviewed_material)?;
    let expected_review = ErgoChainSuite::new(material.network)
        .review_transaction(&review.reviewed_material)
        .map_err(|error| ErgoAdapterError::InvalidSignedTransaction(error.to_string()))?;
    if expected_review != *review {
        return Err(ErgoAdapterError::InvalidSignedTransaction(
            "review artifact binding mismatch".into(),
        ));
    }
    if proofs.len() != material.unsigned_tx.inputs.len() {
        return Err(ErgoAdapterError::ThresholdProofCount {
            expected: material.unsigned_tx.inputs.len(),
            actual: proofs.len(),
        });
    }
    if material.bytes_to_sign
        != material
            .unsigned_tx
            .bytes_to_sign()
            .map_err(|error| ErgoAdapterError::InvalidSignedTransaction(error.to_string()))?
    {
        return Err(ErgoAdapterError::InvalidSignedTransaction(
            "reviewed bytes_to_sign do not match the unsigned transaction".into(),
        ));
    }

    let tx_context = ergo_lib::wallet::signing::TransactionContext::new(
        material.unsigned_tx.clone(),
        material.input_boxes.clone(),
        material.data_boxes.clone(),
    )
    .map_err(|error| ErgoAdapterError::InvalidSignedTransaction(error.to_string()))?;
    let reduced = reduce_tx(tx_context, &material.state_context())
        .map_err(|error| ErgoAdapterError::InvalidSignedTransaction(error.to_string()))?;
    for (input_index, (reduced_input, proof)) in
        reduced.reduced_inputs().iter().zip(proofs).enumerate()
    {
        let SigmaBoolean::ProofOfKnowledge(SigmaProofOfKnowledgeTree::ProveDlog(prove_dlog)) =
            &reduced_input.sigma_prop
        else {
            return Err(ErgoAdapterError::UnsupportedInputScript { input_index });
        };
        let input_key = prove_dlog
            .h
            .scorex_serialize_bytes()
            .map_err(|error| ErgoAdapterError::InvalidSignedTransaction(error.to_string()))?;
        if input_key.as_slice() != commitment.group_public_key {
            return Err(ErgoAdapterError::ThresholdInputKeyMismatch { input_index });
        }
        if !verify_signature(
            reduced_input.sigma_prop.clone(),
            &material.bytes_to_sign,
            proof.as_bytes(),
        )
        .map_err(|error| ErgoAdapterError::InvalidSignedTransaction(error.to_string()))?
        {
            return Err(ErgoAdapterError::InvalidThresholdFinalProof);
        }
    }

    Transaction::from_unsigned_tx(
        material.unsigned_tx,
        proofs
            .iter()
            .map(|proof| ProofBytes::Some(proof.as_bytes().to_vec()))
            .collect(),
    )
    .map_err(|error| ErgoAdapterError::InvalidSignedTransaction(error.to_string()))?
    .sigma_serialize_bytes()
    .map_err(|error| ErgoAdapterError::InvalidSignedTransaction(error.to_string()))
}

fn validate_participant(participant_id: u16) -> Result<(), ErgoAdapterError> {
    if PARTICIPANTS.contains(&participant_id) {
        Ok(())
    } else {
        Err(ErgoAdapterError::InvalidThresholdParticipant(
            participant_id,
        ))
    }
}

fn parse_scalar(bytes: &[u8; 32], field: &'static str) -> Result<Scalar, ErgoAdapterError> {
    Option::<Scalar>::from(Scalar::from_repr((*bytes).into()))
        .ok_or(ErgoAdapterError::InvalidThresholdScalar(field))
}

fn parse_nonzero_scalar(bytes: &[u8; 32], field: &'static str) -> Result<Scalar, ErgoAdapterError> {
    let scalar = parse_scalar(bytes, field)?;
    if bool::from(scalar.is_zero()) {
        Err(ErgoAdapterError::InvalidThresholdScalar(field))
    } else {
        Ok(scalar)
    }
}

fn scalar_from_participant(participant_id: u16) -> Scalar {
    Scalar::from(u64::from(participant_id))
}

fn random_nonzero_scalar() -> Scalar {
    loop {
        let scalar = Scalar::random(&mut OsRng);
        if !bool::from(scalar.is_zero()) {
            return scalar;
        }
    }
}

fn parse_point(bytes: &[u8; 33]) -> Result<ProjectivePoint, ErgoAdapterError> {
    let point = EcPoint::scorex_parse_bytes(bytes)
        .map_err(|error| ErgoAdapterError::InvalidThresholdCommitment(error.to_string()))?;
    Ok(point.into())
}

fn parse_nonidentity_point(
    bytes: &[u8; 33],
    field: &'static str,
) -> Result<ProjectivePoint, ErgoAdapterError> {
    let point = parse_point(bytes)?;
    let ergo_point: EcPoint = point.into();
    if is_identity(&ergo_point) {
        Err(ErgoAdapterError::InvalidThresholdCommitment(format!(
            "{field} is identity"
        )))
    } else {
        Ok(point)
    }
}

fn point_bytes(point: ProjectivePoint) -> Result<[u8; 33], ErgoAdapterError> {
    let point: EcPoint = point.into();
    point
        .scorex_serialize_bytes()
        .map_err(|error| ErgoAdapterError::InvalidThresholdCommitment(error.to_string()))?
        .try_into()
        .map_err(|_| ErgoAdapterError::InvalidThresholdCommitment("invalid point size".into()))
}

fn reduce_hash(hash: [u8; 32]) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(&hash.into())
}

fn transcript_digest(
    commitment: &ErgoThresholdCommitment,
    review_binding: &ReviewBinding,
    session_id: [u8; 32],
    message: &[u8],
    commitments: &[ErgoThresholdCommitments; THRESHOLD],
) -> [u8; 32] {
    let mut hash = Blake2b256::new();
    hash.update(TRANSCRIPT_DOMAIN);
    let review_domain = review_binding.domain_separator();
    hash.update((review_domain.len() as u64).to_be_bytes());
    hash.update(review_domain);
    hash.update(session_id);
    hash.update(commitment.group_public_key);
    hash.update(commitment.coefficient_public_key);
    hash.update((message.len() as u64).to_be_bytes());
    hash.update(message);
    for item in commitments {
        hash.update(item.participant_id.to_be_bytes());
        hash.update(item.hiding);
        hash.update(item.binding);
    }
    hash.finalize().into()
}

fn validate_session_id(session_id: [u8; 32]) -> Result<(), ErgoAdapterError> {
    if session_id == [0; 32] {
        Err(ErgoAdapterError::InvalidThresholdSession)
    } else {
        Ok(())
    }
}

fn nonce_fingerprint(commitments: &ErgoThresholdCommitments) -> [u8; 32] {
    let mut hash = Blake2b256::new();
    hash.update(NONCE_FINGERPRINT_DOMAIN);
    hash.update(commitments.session_id);
    hash.update(commitments.participant_id.to_be_bytes());
    hash.update(commitments.hiding);
    hash.update(commitments.binding);
    hash.finalize().into()
}

fn validate_review_binding(
    review: &ReviewArtifact,
    review_binding: &ReviewBinding,
) -> Result<(), ErgoAdapterError> {
    if review_binding.signing_suite_id != SigningSuiteId::ERGO_SIGMA_P2PK_THRESHOLD_2OF3_V1
        || review_binding.chain_scope != review.scope
        || review_binding.review_schema_version != review.schema_version
        || review_binding.review_digest != review.review_digest
    {
        return Err(ErgoAdapterError::ThresholdReviewBindingMismatch);
    }
    Ok(())
}

fn binding_factor(transcript_digest: &[u8; 32], participant_id: u16) -> Scalar {
    let mut hash = Blake2b256::new();
    hash.update(BINDING_DOMAIN);
    hash.update(transcript_digest);
    hash.update(participant_id.to_be_bytes());
    reduce_hash(hash.finalize().into())
}

fn lagrange_coefficient(
    participant_id: u16,
    signer_ids: [u16; THRESHOLD],
) -> Result<Scalar, ErgoAdapterError> {
    if !signer_ids.contains(&participant_id) {
        return Err(ErgoAdapterError::InvalidThresholdParticipant(
            participant_id,
        ));
    }
    let other = if signer_ids[0] == participant_id {
        signer_ids[1]
    } else {
        signer_ids[0]
    };
    let x_i = scalar_from_participant(participant_id);
    let x_j = scalar_from_participant(other);
    let inverse = Option::<Scalar>::from((x_j - x_i).invert()).ok_or(
        ErgoAdapterError::DuplicateThresholdParticipant(participant_id),
    )?;
    Ok(x_j * inverse)
}

fn p2pk_proposition(group_public_key: ProjectivePoint) -> SigmaBoolean {
    let point: EcPoint = group_public_key.into();
    SigmaBoolean::ProofOfKnowledge(SigmaProofOfKnowledgeTree::ProveDlog(ProveDlog::new(point)))
}

fn ergo_challenge(
    group_public_key: [u8; 33],
    aggregate_commitment: [u8; 33],
    message: &[u8],
) -> Result<[u8; CHALLENGE_BYTES], ErgoAdapterError> {
    let proposition = p2pk_proposition(parse_point(&group_public_key)?);
    let prop_tree = ErgoTree::new(
        ErgoTreeHeader::v0(true),
        &Expr::Const(Constant::from(SigmaProp::new(proposition))),
    )
    .map_err(|error| ErgoAdapterError::InvalidThresholdCommitment(error.to_string()))?;
    let prop_bytes = prop_tree
        .sigma_serialize_bytes()
        .map_err(|error| ErgoAdapterError::InvalidThresholdCommitment(error.to_string()))?;
    let commitment_point: EcPoint = parse_point(&aggregate_commitment)?.into();
    let commitment_bytes = commitment_point
        .sigma_serialize_bytes()
        .map_err(|error| ErgoAdapterError::InvalidThresholdCommitment(error.to_string()))?;
    let mut transcript =
        Vec::with_capacity(5 + prop_bytes.len() + commitment_bytes.len() + message.len());
    transcript.push(1);
    transcript.extend_from_slice(&(prop_bytes.len() as i16).to_be_bytes());
    transcript.extend_from_slice(&prop_bytes);
    transcript.extend_from_slice(&(commitment_bytes.len() as i16).to_be_bytes());
    transcript.extend_from_slice(&commitment_bytes);
    transcript.extend_from_slice(message);
    let digest: [u8; 32] = Blake2b256::digest(&transcript).into();
    let mut challenge = [0_u8; CHALLENGE_BYTES];
    challenge.copy_from_slice(&digest[..CHALLENGE_BYTES]);
    Ok(challenge)
}

fn challenge_scalar(challenge: &[u8; CHALLENGE_BYTES]) -> Scalar {
    let mut bytes = [0_u8; 32];
    bytes[32 - CHALLENGE_BYTES..].copy_from_slice(challenge);
    <Scalar as Reduce<U256>>::reduce_bytes(&bytes.into())
}

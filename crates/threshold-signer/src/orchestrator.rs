//! Audited FROST coordinator state machine for local and remote signers.
//!
//! The machine holds public commitments, public verifying shares, signature
//! shares, and device bindings. It never holds a participant key package or
//! secret nonce. Every transition is deadline checked and recorded in a
//! hash-chained audit stream.

use std::collections::BTreeMap;

use frost_secp256k1_tr::{
    Identifier, Signature, keys::PublicKeyPackage, round1::SigningCommitments,
    round2::SignatureShare,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{FrostSession, aggregate_and_verify, build_session, participant_identifier};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionPhase {
    CollectingCommitments,
    CollectingShares,
    Finalized,
    Aborted,
    Expired,
    Failed,
}

impl SessionPhase {
    fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Finalized | Self::Aborted | Self::Expired | Self::Failed
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundParticipant {
    pub signer_id: u16,
    pub device_id: Uuid,
    pub device_generation: u64,
    #[serde(with = "hex32")]
    pub request_binding_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventKind {
    SessionStarted,
    CommitmentAccepted,
    CommitmentsFrozen,
    ShareAccepted,
    SessionFinalized,
    SessionAborted,
    SessionExpired,
    SessionFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub sequence: u64,
    pub at: i64,
    pub kind: AuditEventKind,
    pub signer_id: Option<u16>,
    pub code: Option<String>,
    #[serde(with = "hex32")]
    pub previous_digest: [u8; 32],
    #[serde(with = "hex32")]
    pub event_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OrchestrationError {
    #[error("invalid threshold signer set")]
    InvalidSignerSet,
    #[error("participant is not part of this signing session")]
    UnknownParticipant,
    #[error("participant device identity or request binding drifted")]
    IdentityDrift,
    #[error("participant already submitted this round")]
    DuplicateParticipant,
    #[error("operation is not valid during phase {0:?}")]
    WrongPhase(SessionPhase),
    #[error("threshold session expired")]
    Expired,
    #[error("need {required} participants, have {actual}")]
    InsufficientParticipants { required: u16, actual: usize },
    #[error("signature share failed cryptographic verification")]
    InvalidSignatureShare,
    #[error("threshold signature failed: {0}")]
    Signing(String),
}

/// Coordinator state for an exact signer set, message, policy and device set.
pub struct ThresholdSessionMachine {
    session_id: [u8; 32],
    message: [u8; 32],
    policy_digest: [u8; 32],
    min_signers: u16,
    deadline: i64,
    phase: SessionPhase,
    public_key_package: PublicKeyPackage,
    participants: BTreeMap<u16, BoundParticipant>,
    commitments: BTreeMap<Identifier, SigningCommitments>,
    frozen_session: Option<FrostSession>,
    shares: BTreeMap<Identifier, SignatureShare>,
    audit: Vec<AuditEvent>,
}

impl core::fmt::Debug for ThresholdSessionMachine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ThresholdSessionMachine")
            .field("session_id", &hex::encode(self.session_id))
            .field("message", &hex::encode(self.message))
            .field("policy_digest", &hex::encode(self.policy_digest))
            .field("min_signers", &self.min_signers)
            .field("deadline", &self.deadline)
            .field("phase", &self.phase)
            .field("participants", &self.participants.len())
            .field("commitments", &self.commitments.len())
            .field("shares", &self.shares.len())
            .finish_non_exhaustive()
    }
}

impl ThresholdSessionMachine {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: [u8; 32],
        message: [u8; 32],
        policy_digest: [u8; 32],
        min_signers: u16,
        deadline: i64,
        participants: Vec<BoundParticipant>,
        public_key_package: PublicKeyPackage,
        now: i64,
    ) -> Result<Self, OrchestrationError> {
        let participant_map: BTreeMap<_, _> = participants
            .into_iter()
            .map(|participant| (participant.signer_id, participant))
            .collect();
        if min_signers == 0
            || participant_map.len() < usize::from(min_signers)
            || deadline <= now
            || participant_map.iter().any(|(signer_id, participant)| {
                signer_id != &participant.signer_id
                    || participant_identifier(*signer_id)
                        .ok()
                        .is_none_or(|id| !public_key_package.verifying_shares().contains_key(&id))
            })
        {
            return Err(OrchestrationError::InvalidSignerSet);
        }
        let mut machine = Self {
            session_id,
            message,
            policy_digest,
            min_signers,
            deadline,
            phase: SessionPhase::CollectingCommitments,
            public_key_package,
            participants: participant_map,
            commitments: BTreeMap::new(),
            frozen_session: None,
            shares: BTreeMap::new(),
            audit: Vec::new(),
        };
        machine.record(now, AuditEventKind::SessionStarted, None, None);
        Ok(machine)
    }

    pub fn phase(&self) -> SessionPhase {
        self.phase
    }

    pub fn deadline(&self) -> i64 {
        self.deadline
    }

    pub fn audit(&self) -> &[AuditEvent] {
        &self.audit
    }

    pub fn audit_head(&self) -> [u8; 32] {
        self.audit
            .last()
            .map(|event| event.event_digest)
            .unwrap_or([0; 32])
    }

    pub fn add_commitment(
        &mut self,
        participant: &BoundParticipant,
        commitment: SigningCommitments,
        now: i64,
    ) -> Result<(), OrchestrationError> {
        self.require_phase(SessionPhase::CollectingCommitments, now)?;
        self.require_identity(participant, now)?;
        let identifier = participant_identifier(participant.signer_id)
            .map_err(|_| OrchestrationError::UnknownParticipant)?;
        if self.commitments.contains_key(&identifier) {
            return Err(OrchestrationError::DuplicateParticipant);
        }
        self.commitments.insert(identifier, commitment);
        self.record(
            now,
            AuditEventKind::CommitmentAccepted,
            Some(participant.signer_id),
            None,
        );
        Ok(())
    }

    /// Freeze the exact participant set used by round two. Commitments cannot
    /// be added after this transition.
    pub fn freeze_commitments(&mut self, now: i64) -> Result<&FrostSession, OrchestrationError> {
        self.require_phase(SessionPhase::CollectingCommitments, now)?;
        if self.commitments.len() < usize::from(self.min_signers) {
            return Err(OrchestrationError::InsufficientParticipants {
                required: self.min_signers,
                actual: self.commitments.len(),
            });
        }
        self.frozen_session = Some(build_session(
            self.session_id,
            self.message,
            self.min_signers,
            self.commitments.clone(),
            self.public_key_package.clone(),
        ));
        self.phase = SessionPhase::CollectingShares;
        self.record(now, AuditEventKind::CommitmentsFrozen, None, None);
        Ok(self
            .frozen_session
            .as_ref()
            .expect("frozen session is inserted before it is returned"))
    }

    pub fn signing_session(&self) -> Result<&FrostSession, OrchestrationError> {
        self.frozen_session
            .as_ref()
            .ok_or(OrchestrationError::WrongPhase(self.phase))
    }

    pub fn add_signature_share(
        &mut self,
        participant: &BoundParticipant,
        share: SignatureShare,
        now: i64,
    ) -> Result<(), OrchestrationError> {
        self.require_phase(SessionPhase::CollectingShares, now)?;
        self.require_identity(participant, now)?;
        let identifier = participant_identifier(participant.signer_id)
            .map_err(|_| OrchestrationError::UnknownParticipant)?;
        let session = self
            .frozen_session
            .as_ref()
            .ok_or(OrchestrationError::WrongPhase(self.phase))?;
        if !session
            .signing_package
            .signing_commitments()
            .contains_key(&identifier)
        {
            self.fail(
                now,
                Some(participant.signer_id),
                "participant_not_in_frozen_package",
            );
            return Err(OrchestrationError::UnknownParticipant);
        }
        if self.shares.contains_key(&identifier) {
            return Err(OrchestrationError::DuplicateParticipant);
        }
        let verifying_share = self
            .public_key_package
            .verifying_shares()
            .get(&identifier)
            .ok_or(OrchestrationError::UnknownParticipant)?;
        if frost_core::verify_signature_share(
            identifier,
            verifying_share,
            &share,
            &session.signing_package,
            self.public_key_package.verifying_key(),
        )
        .is_err()
        {
            self.fail(now, Some(participant.signer_id), "invalid_signature_share");
            return Err(OrchestrationError::InvalidSignatureShare);
        }
        self.shares.insert(identifier, share);
        self.record(
            now,
            AuditEventKind::ShareAccepted,
            Some(participant.signer_id),
            None,
        );
        Ok(())
    }

    pub fn finalize(&mut self, now: i64) -> Result<Signature, OrchestrationError> {
        self.require_phase(SessionPhase::CollectingShares, now)?;
        if self.shares.len() < usize::from(self.min_signers) {
            return Err(OrchestrationError::InsufficientParticipants {
                required: self.min_signers,
                actual: self.shares.len(),
            });
        }
        let session = self
            .frozen_session
            .as_ref()
            .ok_or(OrchestrationError::WrongPhase(self.phase))?;
        match aggregate_and_verify(session, &self.shares) {
            Ok(signature) => {
                self.phase = SessionPhase::Finalized;
                self.record(now, AuditEventKind::SessionFinalized, None, None);
                Ok(signature)
            }
            Err(error) => {
                self.fail(now, None, "aggregate_verification_failed");
                Err(OrchestrationError::Signing(error.to_string()))
            }
        }
    }

    pub fn abort(&mut self, reason_code: &str, now: i64) -> Result<(), OrchestrationError> {
        self.check_deadline(now)?;
        if self.phase.is_terminal() {
            return Err(OrchestrationError::WrongPhase(self.phase));
        }
        self.phase = SessionPhase::Aborted;
        self.record(now, AuditEventKind::SessionAborted, None, Some(reason_code));
        Ok(())
    }

    pub fn expire(&mut self, now: i64) -> bool {
        if now <= self.deadline || self.phase.is_terminal() {
            return false;
        }
        self.phase = SessionPhase::Expired;
        self.record(now, AuditEventKind::SessionExpired, None, Some("deadline"));
        true
    }

    pub fn verify_audit_chain(&self) -> bool {
        let mut previous = [0u8; 32];
        for event in &self.audit {
            if event.previous_digest != previous
                || event.event_digest
                    != audit_digest(
                        event.sequence,
                        event.at,
                        event.kind,
                        event.signer_id,
                        event.code.as_deref(),
                        previous,
                    )
            {
                return false;
            }
            previous = event.event_digest;
        }
        true
    }

    fn require_phase(
        &mut self,
        expected: SessionPhase,
        now: i64,
    ) -> Result<(), OrchestrationError> {
        self.check_deadline(now)?;
        if self.phase != expected {
            return Err(OrchestrationError::WrongPhase(self.phase));
        }
        Ok(())
    }

    fn check_deadline(&mut self, now: i64) -> Result<(), OrchestrationError> {
        if self.expire(now) || self.phase == SessionPhase::Expired {
            return Err(OrchestrationError::Expired);
        }
        Ok(())
    }

    fn require_identity(
        &mut self,
        participant: &BoundParticipant,
        now: i64,
    ) -> Result<(), OrchestrationError> {
        if self.participants.get(&participant.signer_id) != Some(participant) {
            self.fail(now, Some(participant.signer_id), "identity_drift");
            return Err(OrchestrationError::IdentityDrift);
        }
        Ok(())
    }

    fn fail(&mut self, now: i64, signer_id: Option<u16>, code: &str) {
        self.phase = SessionPhase::Failed;
        self.record(now, AuditEventKind::SessionFailed, signer_id, Some(code));
    }

    fn record(
        &mut self,
        at: i64,
        kind: AuditEventKind,
        signer_id: Option<u16>,
        code: Option<&str>,
    ) {
        let sequence = self.audit.len() as u64 + 1;
        let previous_digest = self.audit_head();
        let event_digest = audit_digest(sequence, at, kind, signer_id, code, previous_digest);
        self.audit.push(AuditEvent {
            sequence,
            at,
            kind,
            signer_id,
            code: code.map(str::to_owned),
            previous_digest,
            event_digest,
        });
    }
}

fn audit_digest(
    sequence: u64,
    at: i64,
    kind: AuditEventKind,
    signer_id: Option<u16>,
    code: Option<&str>,
    previous_digest: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"catomicals/frost-audit/v1\0");
    hasher.update(previous_digest);
    hasher.update(sequence.to_be_bytes());
    hasher.update(at.to_be_bytes());
    hasher.update([kind as u8]);
    hasher.update(signer_id.unwrap_or_default().to_be_bytes());
    let code = code.unwrap_or_default().as_bytes();
    hasher.update((code.len() as u32).to_be_bytes());
    hasher.update(code);
    hasher.finalize().into()
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let value = String::deserialize(deserializer)?;
        hex::decode(&value)
            .map_err(serde::de::Error::custom)?
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32-byte hexadecimal value"))
    }
}

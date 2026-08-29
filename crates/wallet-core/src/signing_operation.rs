//! Personal 2-of-3 signing coordination.
//!
//! Provider I/O is deliberately absent from this module. Each transition first
//! commits public operation state and then returns a typed provider request for
//! the caller to execute after releasing wallet and SQLite locks.

use std::collections::{BTreeMap, HashMap};

use catomicals_threshold::{
    BoundParticipant, PersonalSignerProfile, ProviderIdentity, SIGNER_PROVIDER_PROTOCOL_VERSION,
    SignatureShare, SignerAbortRequest, SignerRequestContext, SignerRoundOneRequest,
    SignerRoundOneResponse, SignerRoundTwoRequest, SignerRoundTwoResponse, SigningCommitments,
    ThresholdSessionMachine, signature_to_bytes,
};
use catomicals_wallet_storage::{
    NewPersonalSigningOperation, PersonalSigningOperation, PersonalSigningOperationStatus,
    PersonalSigningReceipt, PersonalSigningRound, WalletStorage,
};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginPersonalSigningOperation {
    pub operation_id: Uuid,
    pub intent_id: Uuid,
    pub session_id: [u8; 32],
    pub taproot_sighash: [u8; 32],
    pub policy_digest: [u8; 32],
    pub chain_snapshot_digest: [u8; 32],
    pub selected_participants: [u16; 2],
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonalRoundOneDispatch {
    pub signer_id: u16,
    pub request: SignerRoundOneRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonalRoundTwoDispatch {
    pub signer_id: u16,
    pub request: SignerRoundTwoRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonalAbortDispatch {
    pub signer_id: u16,
    pub request: SignerAbortRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonalSigningTermination {
    pub status: PersonalSigningOperationStatus,
    pub aborts: Vec<PersonalAbortDispatch>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersonalSigningRecovery {
    ReadyToFinalize,
    ResumeRoundTwo(Vec<PersonalRoundTwoDispatch>),
    Finalized([u8; 64]),
    TerminatedInterruptedCommitmentRound,
    Terminal(PersonalSigningOperationStatus),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PersonalSigningError {
    #[error("provider identity does not match the personal signer profile")]
    ProviderIdentityDrift,
    #[error("personal signer selection must be one of [1,2], [1,3], or [2,3]")]
    InvalidParticipantPair,
    #[error("personal signing operation has expired")]
    Expired,
    #[error("personal signing operation does not exist")]
    OperationNotFound,
    #[error("personal signing operation is already active")]
    OperationAlreadyActive,
    #[error("personal signing operation is not authorized: {0}")]
    Authorization(String),
    #[error("provider response does not match the dispatched request")]
    ResponseBindingMismatch,
    #[error("personal signing operation is in the wrong phase")]
    WrongPhase,
    #[error("personal signing operation storage failed: {0}")]
    Storage(String),
    #[error("personal signing operation failed: {0}")]
    Signing(String),
}

pub trait PersonalSigningStore: Send {
    fn create_operation(
        &mut self,
        operation: NewPersonalSigningOperation,
    ) -> Result<PersonalSigningOperation, PersonalSigningError>;
    fn operation(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<PersonalSigningOperation>, PersonalSigningError>;
    fn receipts(
        &self,
        operation_id: Uuid,
    ) -> Result<Vec<PersonalSigningReceipt>, PersonalSigningError>;
    fn record_receipt(
        &mut self,
        receipt: PersonalSigningReceipt,
    ) -> Result<(), PersonalSigningError>;
    fn freeze(
        &mut self,
        operation_id: Uuid,
        binding: [u8; 32],
        signing_package: Vec<u8>,
        now: i64,
    ) -> Result<(), PersonalSigningError>;
    fn complete(
        &mut self,
        operation_id: Uuid,
        binding: [u8; 32],
        signature: [u8; 64],
        now: i64,
    ) -> Result<(), PersonalSigningError>;
    fn terminate(
        &mut self,
        operation_id: Uuid,
        binding: [u8; 32],
        status: PersonalSigningOperationStatus,
        reason: &str,
        now: i64,
    ) -> Result<(), PersonalSigningError>;
}

impl PersonalSigningStore for WalletStorage {
    fn create_operation(
        &mut self,
        operation: NewPersonalSigningOperation,
    ) -> Result<PersonalSigningOperation, PersonalSigningError> {
        self.create_personal_signing_operation(operation)
            .map_err(storage_error)
    }

    fn operation(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<PersonalSigningOperation>, PersonalSigningError> {
        self.personal_signing_operation(operation_id)
            .map_err(storage_error)
    }

    fn receipts(
        &self,
        operation_id: Uuid,
    ) -> Result<Vec<PersonalSigningReceipt>, PersonalSigningError> {
        self.personal_signing_receipts(operation_id)
            .map_err(storage_error)
    }

    fn record_receipt(
        &mut self,
        receipt: PersonalSigningReceipt,
    ) -> Result<(), PersonalSigningError> {
        self.record_personal_signing_receipt(receipt)
            .map_err(storage_error)
    }

    fn freeze(
        &mut self,
        operation_id: Uuid,
        binding: [u8; 32],
        signing_package: Vec<u8>,
        now: i64,
    ) -> Result<(), PersonalSigningError> {
        self.freeze_personal_signing_operation(operation_id, binding, signing_package, now)
            .map_err(storage_error)
    }

    fn complete(
        &mut self,
        operation_id: Uuid,
        binding: [u8; 32],
        signature: [u8; 64],
        now: i64,
    ) -> Result<(), PersonalSigningError> {
        self.complete_personal_signing_operation(operation_id, binding, signature, now)
            .map_err(storage_error)
    }

    fn terminate(
        &mut self,
        operation_id: Uuid,
        binding: [u8; 32],
        status: PersonalSigningOperationStatus,
        reason: &str,
        now: i64,
    ) -> Result<(), PersonalSigningError> {
        self.terminate_personal_signing_operation(operation_id, binding, status, reason, now)
            .map_err(storage_error)
    }
}

struct LiveOperation {
    record: PersonalSigningOperation,
    machine: ThresholdSessionMachine,
    participants: BTreeMap<u16, BoundParticipant>,
    round_one_contexts: BTreeMap<u16, SignerRequestContext>,
    round_two_contexts: BTreeMap<u16, SignerRequestContext>,
}

pub struct PersonalSigningCoordinator<S> {
    profile: PersonalSignerProfile,
    identities: BTreeMap<u16, ProviderIdentity>,
    store: S,
    operations: HashMap<Uuid, LiveOperation>,
    rng: OsRng,
}

impl<S: PersonalSigningStore> PersonalSigningCoordinator<S> {
    pub fn new(
        profile: PersonalSignerProfile,
        identities: Vec<ProviderIdentity>,
        store: S,
    ) -> Result<Self, PersonalSigningError> {
        let identities: BTreeMap<_, _> = identities
            .into_iter()
            .map(|identity| (identity.signer_id, identity))
            .collect();
        if identities.len() != 3 || !identities_match_profile(&profile, &identities) {
            return Err(PersonalSigningError::ProviderIdentityDrift);
        }
        Ok(Self {
            profile,
            identities,
            store,
            operations: HashMap::new(),
            rng: OsRng,
        })
    }

    fn begin_mechanism(
        &mut self,
        request: BeginPersonalSigningOperation,
        now: i64,
    ) -> Result<Vec<PersonalRoundOneDispatch>, PersonalSigningError> {
        if self.operations.contains_key(&request.operation_id) {
            return Err(PersonalSigningError::OperationAlreadyActive);
        }
        if self.store.operation(request.operation_id)?.is_some() {
            return Err(PersonalSigningError::OperationAlreadyActive);
        }
        validate_pair(request.selected_participants)?;
        if request.expires_at <= now {
            return Err(PersonalSigningError::Expired);
        }
        let binding = personal_operation_binding_digest(&self.profile, &request);
        let record = NewPersonalSigningOperation {
            operation_id: request.operation_id,
            wallet_id: self.profile.wallet_id(),
            profile_id: self.profile.profile_id(),
            signer_set_id: self.profile.signer_set_id(),
            signer_epoch: self.profile.signer_epoch(),
            intent_id: request.intent_id,
            session_id: request.session_id,
            taproot_sighash: request.taproot_sighash,
            policy_digest: request.policy_digest,
            chain_snapshot_digest: request.chain_snapshot_digest,
            group_pubkey_xonly: self.profile.group_pubkey_xonly(),
            profile_binding_digest: self.profile.binding_digest(),
            operation_binding_digest: binding,
            allowed_participants: [1, 2, 3],
            selected_participants: request.selected_participants,
            threshold: self.profile.min_signers(),
            max_signers: self.profile.max_signers(),
            expires_at: request.expires_at,
            created_at: now,
        };
        let bound = self.bound_participants(&request.selected_participants, binding)?;
        let machine = ThresholdSessionMachine::new(
            request.session_id,
            request.taproot_sighash,
            request.policy_digest,
            self.profile.min_signers(),
            request.expires_at,
            bound.values().cloned().collect(),
            self.profile
                .public_key_package()
                .map_err(|error| PersonalSigningError::Signing(error.to_string()))?,
            now,
        )
        .map_err(signing_error)?;
        let durable = self.store.create_operation(record)?;
        if durable.operation_binding_digest != binding
            || durable.status != PersonalSigningOperationStatus::CollectingCommitments
        {
            return Err(PersonalSigningError::ResponseBindingMismatch);
        }
        let mut contexts = BTreeMap::new();
        for signer_id in request.selected_participants {
            let request_nonce = random_nonce(&mut self.rng);
            contexts.insert(
                signer_id,
                self.request_context(&durable, signer_id, request_nonce)?,
            );
        }
        let dispatches = contexts
            .iter()
            .map(|(signer_id, context)| PersonalRoundOneDispatch {
                signer_id: *signer_id,
                request: SignerRoundOneRequest {
                    context: context.clone(),
                },
            })
            .collect();
        self.operations.insert(
            request.operation_id,
            LiveOperation {
                record: durable,
                machine,
                participants: bound,
                round_one_contexts: contexts,
                round_two_contexts: BTreeMap::new(),
            },
        );
        Ok(dispatches)
    }

    /// Passkey-gated entry point. The authorization binds the whole signer
    /// group and allowed set; the operation then selects one approved pair.
    pub fn begin_authorized(
        &mut self,
        request: BeginPersonalSigningOperation,
        authorization: &mut crate::gate::PersonalOperationAuthorization,
        now: i64,
    ) -> Result<Vec<PersonalRoundOneDispatch>, PersonalSigningError> {
        let binding = personal_operation_binding_digest(&self.profile, &request);
        authorization
            .consume(binding)
            .map_err(|error| PersonalSigningError::Authorization(error.to_string()))?;
        self.begin_mechanism(request, now)
    }

    pub fn accept_round_one(
        &mut self,
        operation_id: Uuid,
        signer_id: u16,
        response: SignerRoundOneResponse,
        now: i64,
    ) -> Result<(), PersonalSigningError> {
        let operation = self
            .operations
            .get_mut(&operation_id)
            .ok_or(PersonalSigningError::OperationNotFound)?;
        let context = operation
            .round_one_contexts
            .get(&signer_id)
            .cloned()
            .ok_or(PersonalSigningError::ResponseBindingMismatch)?;
        if response.request_binding_digest != context.binding_digest() {
            return Err(PersonalSigningError::ResponseBindingMismatch);
        }
        let payload = hex::decode(response.commitment_hex)
            .map_err(|_| PersonalSigningError::ResponseBindingMismatch)?;
        let commitment = SigningCommitments::deserialize(&payload)
            .map_err(|_| PersonalSigningError::ResponseBindingMismatch)?;
        let participant = operation
            .participants
            .get(&signer_id)
            .ok_or(PersonalSigningError::ProviderIdentityDrift)?;
        operation
            .machine
            .add_commitment(participant, commitment, now)
            .map_err(signing_error)?;
        self.store.record_receipt(PersonalSigningReceipt {
            operation_id,
            signer_id,
            round: PersonalSigningRound::Commitment,
            device_id: context.device_id,
            device_generation: context.device_generation,
            request_binding_digest: response.request_binding_digest,
            payload,
            received_at: now,
        })?;
        operation.round_one_contexts.remove(&signer_id);
        Ok(())
    }

    pub fn freeze_commitments(
        &mut self,
        operation_id: Uuid,
        now: i64,
    ) -> Result<Vec<PersonalRoundTwoDispatch>, PersonalSigningError> {
        let (identities, rng) = (&self.identities, &mut self.rng);
        let operation = self
            .operations
            .get_mut(&operation_id)
            .ok_or(PersonalSigningError::OperationNotFound)?;
        if !operation.round_one_contexts.is_empty() {
            return Err(PersonalSigningError::WrongPhase);
        }
        let session = operation
            .machine
            .freeze_commitments(now)
            .map_err(signing_error)?
            .clone();
        let signing_package = session
            .signing_package
            .serialize()
            .map_err(|error| PersonalSigningError::Signing(error.to_string()))?;
        self.store.freeze(
            operation_id,
            operation.record.operation_binding_digest,
            signing_package.clone(),
            now,
        )?;
        operation.record.status = PersonalSigningOperationStatus::CollectingShares;
        operation.record.signing_package = Some(signing_package.clone());
        operation.record.updated_at = now;
        let mut contexts = BTreeMap::new();
        for signer_id in operation.record.selected_participants {
            let identity = identities
                .get(&signer_id)
                .ok_or(PersonalSigningError::ProviderIdentityDrift)?;
            contexts.insert(
                signer_id,
                request_context(&operation.record, identity, random_nonce(rng)),
            );
        }
        let dispatches = contexts
            .iter()
            .map(|(signer_id, context)| PersonalRoundTwoDispatch {
                signer_id: *signer_id,
                request: SignerRoundTwoRequest {
                    context: context.clone(),
                    signing_package_hex: hex::encode(&signing_package),
                },
            })
            .collect();
        operation.round_two_contexts = contexts;
        Ok(dispatches)
    }

    pub fn accept_round_two(
        &mut self,
        operation_id: Uuid,
        signer_id: u16,
        response: SignerRoundTwoResponse,
        now: i64,
    ) -> Result<(), PersonalSigningError> {
        let operation = self
            .operations
            .get_mut(&operation_id)
            .ok_or(PersonalSigningError::OperationNotFound)?;
        let context = operation
            .round_two_contexts
            .get(&signer_id)
            .cloned()
            .ok_or(PersonalSigningError::ResponseBindingMismatch)?;
        if response.request_binding_digest != context.binding_digest() {
            return Err(PersonalSigningError::ResponseBindingMismatch);
        }
        let payload = hex::decode(response.signature_share_hex)
            .map_err(|_| PersonalSigningError::ResponseBindingMismatch)?;
        let share = SignatureShare::deserialize(&payload)
            .map_err(|_| PersonalSigningError::ResponseBindingMismatch)?;
        let participant = operation
            .participants
            .get(&signer_id)
            .ok_or(PersonalSigningError::ProviderIdentityDrift)?;
        operation
            .machine
            .add_signature_share(participant, share, now)
            .map_err(signing_error)?;
        self.store.record_receipt(PersonalSigningReceipt {
            operation_id,
            signer_id,
            round: PersonalSigningRound::SignatureShare,
            device_id: context.device_id,
            device_generation: context.device_generation,
            request_binding_digest: response.request_binding_digest,
            payload,
            received_at: now,
        })?;
        operation.round_two_contexts.remove(&signer_id);
        Ok(())
    }

    pub fn finalize(
        &mut self,
        operation_id: Uuid,
        now: i64,
    ) -> Result<[u8; 64], PersonalSigningError> {
        let operation = self
            .operations
            .get_mut(&operation_id)
            .ok_or(PersonalSigningError::OperationNotFound)?;
        if !operation.round_two_contexts.is_empty() {
            return Err(PersonalSigningError::WrongPhase);
        }
        let signature = operation.machine.finalize(now).map_err(signing_error)?;
        let signature = signature_to_bytes(&signature).map_err(signing_error)?;
        self.store.complete(
            operation_id,
            operation.record.operation_binding_digest,
            signature,
            now,
        )?;
        operation.record.status = PersonalSigningOperationStatus::Finalized;
        operation.record.final_signature = Some(signature);
        operation.record.updated_at = now;
        Ok(signature)
    }

    pub fn expire(
        &mut self,
        operation_id: Uuid,
        now: i64,
    ) -> Result<Option<PersonalSigningTermination>, PersonalSigningError> {
        let operation = self
            .operations
            .get_mut(&operation_id)
            .ok_or(PersonalSigningError::OperationNotFound)?;
        if !operation.machine.expire(now) {
            return Ok(None);
        }
        self.store.terminate(
            operation_id,
            operation.record.operation_binding_digest,
            PersonalSigningOperationStatus::Expired,
            "deadline",
            now,
        )?;
        operation.record.status = PersonalSigningOperationStatus::Expired;
        operation.record.terminal_reason = Some("deadline".to_owned());
        operation.record.updated_at = now;
        let mut aborts = Vec::new();
        for signer_id in operation.record.selected_participants {
            let identity = self
                .identities
                .get(&signer_id)
                .ok_or(PersonalSigningError::ProviderIdentityDrift)?;
            aborts.push(PersonalAbortDispatch {
                signer_id,
                request: SignerAbortRequest {
                    context: request_context(
                        &operation.record,
                        identity,
                        random_nonce(&mut self.rng),
                    ),
                    reason_code: "deadline".to_owned(),
                },
            });
        }
        Ok(Some(PersonalSigningTermination {
            status: PersonalSigningOperationStatus::Expired,
            aborts,
        }))
    }

    pub fn recover_operation(
        &mut self,
        operation_id: Uuid,
        now: i64,
    ) -> Result<PersonalSigningRecovery, PersonalSigningError> {
        let record = self
            .store
            .operation(operation_id)?
            .ok_or(PersonalSigningError::OperationNotFound)?;
        if record.wallet_id != self.profile.wallet_id()
            || record.profile_id != self.profile.profile_id()
            || record.signer_set_id != self.profile.signer_set_id()
            || record.signer_epoch != self.profile.signer_epoch()
            || record.group_pubkey_xonly != self.profile.group_pubkey_xonly()
            || record.profile_binding_digest != self.profile.binding_digest()
        {
            return Err(PersonalSigningError::ProviderIdentityDrift);
        }
        match record.status {
            PersonalSigningOperationStatus::Finalized => {
                return record
                    .final_signature
                    .map(PersonalSigningRecovery::Finalized)
                    .ok_or(PersonalSigningError::ResponseBindingMismatch);
            }
            PersonalSigningOperationStatus::Aborted
            | PersonalSigningOperationStatus::Expired
            | PersonalSigningOperationStatus::Failed => {
                return Ok(PersonalSigningRecovery::Terminal(record.status));
            }
            PersonalSigningOperationStatus::CollectingCommitments => {
                self.store.terminate(
                    operation_id,
                    record.operation_binding_digest,
                    PersonalSigningOperationStatus::Aborted,
                    "restart_interrupted",
                    now,
                )?;
                return Ok(PersonalSigningRecovery::TerminatedInterruptedCommitmentRound);
            }
            PersonalSigningOperationStatus::CollectingShares => {}
        }
        if now > record.expires_at {
            self.store.terminate(
                operation_id,
                record.operation_binding_digest,
                PersonalSigningOperationStatus::Expired,
                "deadline",
                now,
            )?;
            return Ok(PersonalSigningRecovery::Terminal(
                PersonalSigningOperationStatus::Expired,
            ));
        }

        let participants = self.bound_participants(
            &record.selected_participants,
            record.operation_binding_digest,
        )?;
        let mut machine = ThresholdSessionMachine::new(
            record.session_id,
            record.taproot_sighash,
            record.policy_digest,
            record.threshold,
            record.expires_at,
            participants.values().cloned().collect(),
            self.profile
                .public_key_package()
                .map_err(|error| PersonalSigningError::Signing(error.to_string()))?,
            now,
        )
        .map_err(signing_error)?;
        let receipts = self.store.receipts(operation_id)?;
        for receipt in receipts
            .iter()
            .filter(|receipt| receipt.round == PersonalSigningRound::Commitment)
        {
            validate_recovered_receipt(&record, &self.identities, receipt)?;
            let commitment = SigningCommitments::deserialize(&receipt.payload)
                .map_err(|_| PersonalSigningError::ResponseBindingMismatch)?;
            machine
                .add_commitment(
                    participants
                        .get(&receipt.signer_id)
                        .ok_or(PersonalSigningError::ProviderIdentityDrift)?,
                    commitment,
                    now,
                )
                .map_err(signing_error)?;
        }
        let session = machine
            .freeze_commitments(now)
            .map_err(signing_error)?
            .clone();
        let signing_package = session
            .signing_package
            .serialize()
            .map_err(|error| PersonalSigningError::Signing(error.to_string()))?;
        if record.signing_package.as_deref() != Some(signing_package.as_slice()) {
            return Err(PersonalSigningError::ResponseBindingMismatch);
        }
        for receipt in receipts
            .iter()
            .filter(|receipt| receipt.round == PersonalSigningRound::SignatureShare)
        {
            validate_recovered_receipt(&record, &self.identities, receipt)?;
            let share = SignatureShare::deserialize(&receipt.payload)
                .map_err(|_| PersonalSigningError::ResponseBindingMismatch)?;
            machine
                .add_signature_share(
                    participants
                        .get(&receipt.signer_id)
                        .ok_or(PersonalSigningError::ProviderIdentityDrift)?,
                    share,
                    now,
                )
                .map_err(signing_error)?;
        }
        let completed: std::collections::BTreeSet<_> = receipts
            .iter()
            .filter(|receipt| receipt.round == PersonalSigningRound::SignatureShare)
            .map(|receipt| receipt.signer_id)
            .collect();
        let mut contexts = BTreeMap::new();
        for signer_id in record.selected_participants {
            if !completed.contains(&signer_id) {
                let identity = self
                    .identities
                    .get(&signer_id)
                    .ok_or(PersonalSigningError::ProviderIdentityDrift)?;
                contexts.insert(
                    signer_id,
                    request_context(&record, identity, random_nonce(&mut self.rng)),
                );
            }
        }
        let dispatches: Vec<_> = contexts
            .iter()
            .map(|(signer_id, context)| PersonalRoundTwoDispatch {
                signer_id: *signer_id,
                request: SignerRoundTwoRequest {
                    context: context.clone(),
                    signing_package_hex: hex::encode(&signing_package),
                },
            })
            .collect();
        self.operations.insert(
            operation_id,
            LiveOperation {
                record,
                machine,
                participants,
                round_one_contexts: BTreeMap::new(),
                round_two_contexts: contexts,
            },
        );
        if dispatches.is_empty() {
            Ok(PersonalSigningRecovery::ReadyToFinalize)
        } else {
            Ok(PersonalSigningRecovery::ResumeRoundTwo(dispatches))
        }
    }

    pub fn operation(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<PersonalSigningOperation>, PersonalSigningError> {
        self.store.operation(operation_id)
    }

    pub fn receipts(
        &self,
        operation_id: Uuid,
    ) -> Result<Vec<PersonalSigningReceipt>, PersonalSigningError> {
        self.store.receipts(operation_id)
    }

    pub fn into_store(self) -> S {
        self.store
    }

    fn bound_participants(
        &self,
        selected: &[u16; 2],
        operation_binding: [u8; 32],
    ) -> Result<BTreeMap<u16, BoundParticipant>, PersonalSigningError> {
        selected
            .iter()
            .map(|signer_id| {
                let identity = self
                    .identities
                    .get(signer_id)
                    .ok_or(PersonalSigningError::ProviderIdentityDrift)?;
                Ok((
                    *signer_id,
                    BoundParticipant {
                        signer_id: *signer_id,
                        device_id: identity.device_id,
                        device_generation: identity.device_generation,
                        request_binding_digest: operation_binding,
                    },
                ))
            })
            .collect()
    }

    fn request_context(
        &self,
        operation: &PersonalSigningOperation,
        signer_id: u16,
        request_nonce: [u8; 32],
    ) -> Result<SignerRequestContext, PersonalSigningError> {
        let identity = self
            .identities
            .get(&signer_id)
            .ok_or(PersonalSigningError::ProviderIdentityDrift)?;
        Ok(request_context(operation, identity, request_nonce))
    }
}

fn request_context(
    operation: &PersonalSigningOperation,
    identity: &ProviderIdentity,
    request_nonce: [u8; 32],
) -> SignerRequestContext {
    SignerRequestContext {
        protocol_version: SIGNER_PROVIDER_PROTOCOL_VERSION,
        wallet_id: operation.wallet_id,
        signer_set_id: operation.signer_set_id,
        signer_epoch: operation.signer_epoch,
        signer_id: identity.signer_id,
        device_id: identity.device_id,
        device_generation: identity.device_generation,
        operation_id: operation.operation_id,
        intent_id: operation.intent_id,
        session_id: operation.session_id,
        taproot_sighash: operation.taproot_sighash,
        policy_digest: operation.policy_digest,
        group_pubkey_xonly: operation.group_pubkey_xonly,
        verifying_share_digest: identity.verifying_share_digest,
        min_signers: operation.threshold,
        max_signers: operation.max_signers,
        chain_snapshot_digest: operation.chain_snapshot_digest,
        request_nonce,
        expires_at: operation.expires_at,
    }
}

fn identities_match_profile(
    profile: &PersonalSignerProfile,
    identities: &BTreeMap<u16, ProviderIdentity>,
) -> bool {
    profile.participants().iter().all(|participant| {
        identities
            .get(&participant.signer_id)
            .is_some_and(|identity| {
                identity.wallet_id == profile.wallet_id()
                    && identity.signer_set_id == profile.signer_set_id()
                    && identity.signer_epoch == profile.signer_epoch()
                    && identity.group_pubkey_xonly == profile.group_pubkey_xonly()
                    && identity.verifying_share_digest == participant.verifying_share_digest
            })
    })
}

fn validate_recovered_receipt(
    operation: &PersonalSigningOperation,
    identities: &BTreeMap<u16, ProviderIdentity>,
    receipt: &PersonalSigningReceipt,
) -> Result<(), PersonalSigningError> {
    let identity = identities
        .get(&receipt.signer_id)
        .ok_or(PersonalSigningError::ProviderIdentityDrift)?;
    if !operation.selected_participants.contains(&receipt.signer_id)
        || receipt.device_id != identity.device_id
        || receipt.device_generation != identity.device_generation
        || receipt.received_at > operation.expires_at
    {
        return Err(PersonalSigningError::ProviderIdentityDrift);
    }
    Ok(())
}

fn validate_pair(pair: [u16; 2]) -> Result<(), PersonalSigningError> {
    if matches!(pair, [1, 2] | [1, 3] | [2, 3]) {
        Ok(())
    } else {
        Err(PersonalSigningError::InvalidParticipantPair)
    }
}

pub(crate) fn personal_operation_binding_digest(
    profile: &PersonalSignerProfile,
    request: &BeginPersonalSigningOperation,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"catomicals/personal-signing-operation/v1\0");
    hasher.update(profile.binding_digest());
    hasher.update(profile.wallet_id().as_bytes());
    hasher.update(profile.profile_id().as_bytes());
    hasher.update(profile.signer_set_id().as_bytes());
    hasher.update(profile.signer_epoch().to_be_bytes());
    hasher.update(profile.group_pubkey_xonly());
    hasher.update(request.operation_id.as_bytes());
    hasher.update(request.intent_id.as_bytes());
    hasher.update(request.session_id);
    hasher.update(request.taproot_sighash);
    hasher.update(request.policy_digest);
    hasher.update(request.chain_snapshot_digest);
    for signer_id in [1_u16, 2, 3] {
        hasher.update(signer_id.to_be_bytes());
    }
    for signer_id in request.selected_participants {
        hasher.update(signer_id.to_be_bytes());
    }
    hasher.update(profile.min_signers().to_be_bytes());
    hasher.update(profile.max_signers().to_be_bytes());
    hasher.update(request.expires_at.to_be_bytes());
    hasher.finalize().into()
}

fn random_nonce(rng: &mut OsRng) -> [u8; 32] {
    let mut nonce = [0_u8; 32];
    rng.fill_bytes(&mut nonce);
    nonce
}

fn storage_error(error: impl std::fmt::Display) -> PersonalSigningError {
    PersonalSigningError::Storage(error.to_string())
}

fn signing_error(error: impl std::fmt::Display) -> PersonalSigningError {
    PersonalSigningError::Signing(error.to_string())
}

#[cfg(test)]
mod tests {
    include!("../tests/personal_signing_operation.rs");
}

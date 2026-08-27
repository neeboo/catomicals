//! Explicit FROST participant and coordinator round interfaces.

use std::collections::BTreeMap;

use frost_secp256k1_tr::{
    Identifier, Signature,
    keys::{KeyPackage, PublicKeyPackage},
    round1::{SigningCommitments, SigningNonces, commit},
    round2::SignatureShare,
};
use rand::rngs::OsRng;

use crate::{
    FrostSession, NonceGuard, SigningAuthorization, SigningError, aggregate_and_verify,
    build_session, participant_identifier, sign_share,
};

struct PendingRoundOne {
    message: [u8; 32],
    nonces: SigningNonces,
    commitments: SigningCommitments,
}

/// One isolated FROST participant. Its key and nonces are private and cannot
/// be serialized through the wallet API.
pub struct LocalFrostParticipant {
    signer_id: u16,
    key_package: KeyPackage,
    nonce_guard: NonceGuard,
    pending: BTreeMap<[u8; 32], PendingRoundOne>,
}

impl core::fmt::Debug for LocalFrostParticipant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LocalFrostParticipant")
            .field("signer_id", &self.signer_id)
            .field("key_package", &"<redacted>")
            .field("pending_rounds", &self.pending.len())
            .finish()
    }
}

impl LocalFrostParticipant {
    pub fn new(
        signer_id: u16,
        key_package: KeyPackage,
        nonce_guard: NonceGuard,
    ) -> Result<Self, SigningError> {
        if key_package.identifier() != &participant_identifier(signer_id)? {
            return Err(SigningError::KeyPackageSignerMismatch);
        }
        Ok(Self {
            signer_id,
            key_package,
            nonce_guard,
            pending: BTreeMap::new(),
        })
    }

    pub fn signer_id(&self) -> u16 {
        self.signer_id
    }

    /// Generate secret nonces and return only public commitments.
    pub fn round1(
        &mut self,
        session_id: [u8; 32],
        message: [u8; 32],
    ) -> Result<SigningCommitments, SigningError> {
        if self.pending.contains_key(&session_id) {
            return Err(SigningError::RoundOneAlreadyExists);
        }
        let (nonces, commitments) = commit(self.key_package.signing_share(), &mut OsRng);
        self.pending.insert(
            session_id,
            PendingRoundOne {
                message,
                nonces,
                commitments,
            },
        );
        Ok(commitments)
    }

    /// Return a one-way fingerprint for the secret nonces held by an exact
    /// pending round. This lets wallet authority storage claim the nonce before
    /// round two without exposing the nonce or the signing share.
    pub fn pending_nonce_fingerprint(
        &self,
        session_id: &[u8; 32],
        message: &[u8; 32],
    ) -> Result<[u8; 32], SigningError> {
        let pending = self
            .pending
            .get(session_id)
            .ok_or(SigningError::RoundOneNotFound)?;
        if &pending.message != message {
            return Err(SigningError::RoundBindingMismatch);
        }
        Ok(NonceGuard::fingerprint(self.signer_id, &pending.nonces))
    }

    /// Consume matching round-one state and exact-bound authorization to
    /// produce one signature share.
    pub fn round2(
        &mut self,
        session: &FrostSession,
        authorization: &mut dyn SigningAuthorization,
        now: i64,
    ) -> Result<SignatureShare, SigningError> {
        let pending = self
            .pending
            .get(&session.id)
            .ok_or(SigningError::RoundOneNotFound)?;
        let identifier = participant_identifier(self.signer_id)?;
        if pending.message != session.message
            || session
                .signing_package
                .signing_commitments()
                .get(&identifier)
                != Some(&pending.commitments)
        {
            return Err(SigningError::RoundBindingMismatch);
        }

        let pending = self
            .pending
            .remove(&session.id)
            .ok_or(SigningError::RoundOneNotFound)?;
        sign_share(
            session,
            self.signer_id,
            &pending.nonces,
            &self.key_package,
            &mut self.nonce_guard,
            authorization,
            now,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CoordinatorError {
    #[error("participant {0} already submitted this round")]
    DuplicateParticipant(u16),
    #[error("need {required} commitments, have {actual}")]
    InsufficientCommitments { required: u16, actual: usize },
    #[error("need {required} signature shares, have {actual}")]
    InsufficientShares { required: u16, actual: usize },
    #[error("invalid participant identifier")]
    InvalidParticipant,
    #[error("threshold signing failed: {0}")]
    Signing(String),
}

/// Coordinator state for one immutable session and message.
pub struct FrostCoordinator {
    session_id: [u8; 32],
    message: [u8; 32],
    min_signers: u16,
    public_key_package: PublicKeyPackage,
    commitments: BTreeMap<Identifier, SigningCommitments>,
    shares: BTreeMap<Identifier, SignatureShare>,
}

impl FrostCoordinator {
    pub fn new(
        session_id: [u8; 32],
        message: [u8; 32],
        min_signers: u16,
        public_key_package: PublicKeyPackage,
    ) -> Self {
        Self {
            session_id,
            message,
            min_signers,
            public_key_package,
            commitments: BTreeMap::new(),
            shares: BTreeMap::new(),
        }
    }

    pub fn add_commitment(
        &mut self,
        signer_id: u16,
        commitment: SigningCommitments,
    ) -> Result<(), CoordinatorError> {
        let id =
            Identifier::try_from(signer_id).map_err(|_| CoordinatorError::InvalidParticipant)?;
        match self.commitments.entry(id) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(commitment);
                Ok(())
            }
            std::collections::btree_map::Entry::Occupied(_) => {
                Err(CoordinatorError::DuplicateParticipant(signer_id))
            }
        }
    }

    pub fn signing_session(&self) -> Result<FrostSession, CoordinatorError> {
        if self.commitments.len() < usize::from(self.min_signers) {
            return Err(CoordinatorError::InsufficientCommitments {
                required: self.min_signers,
                actual: self.commitments.len(),
            });
        }
        Ok(build_session(
            self.session_id,
            self.message,
            self.min_signers,
            self.commitments.clone(),
            self.public_key_package.clone(),
        ))
    }

    pub fn add_signature_share(
        &mut self,
        signer_id: u16,
        share: SignatureShare,
    ) -> Result<(), CoordinatorError> {
        let id =
            Identifier::try_from(signer_id).map_err(|_| CoordinatorError::InvalidParticipant)?;
        match self.shares.entry(id) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(share);
                Ok(())
            }
            std::collections::btree_map::Entry::Occupied(_) => {
                Err(CoordinatorError::DuplicateParticipant(signer_id))
            }
        }
    }

    pub fn finalize(&self) -> Result<Signature, CoordinatorError> {
        if self.shares.len() < usize::from(self.min_signers) {
            return Err(CoordinatorError::InsufficientShares {
                required: self.min_signers,
                actual: self.shares.len(),
            });
        }
        let session = self.signing_session()?;
        aggregate_and_verify(&session, &self.shares)
            .map_err(|error| CoordinatorError::Signing(error.to_string()))
    }
}

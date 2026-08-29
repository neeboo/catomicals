use std::{
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use cb_mpc::{EcdsaKeyShare, ThresholdPolicy, Transport, TransportError};
use secp256k1::{Message, PublicKey, Secp256k1, ecdsa::Signature};
use zeroize::Zeroizing;

use crate::{
    ApprovedCbMpcSignRequest, CbMpcError, CbMpcRuntime, CbMpcRuntimeLimits, CbMpcSignerSet,
    PartyId, SessionClaimError, SessionTransport, TransportFailure,
};

const CB_MPC_TRANSPORT_ERROR: i32 = 0xff03_0001_u32 as i32;

pub struct SecretShareMaterial(Zeroizing<Vec<u8>>);

impl SecretShareMaterial {
    pub fn new(bytes: Vec<u8>) -> Result<Self, CbMpcError> {
        if bytes.is_empty() {
            return Err(CbMpcError::ShareMismatch);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Explicitly exposes share bytes to an encrypted persistence boundary.
    /// The returned slice must never be logged or serialized as ordinary JSON.
    pub fn expose_secret(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretShareMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "SecretShareMaterial(REDACTED, len={})",
            self.0.len()
        )
    }
}

pub struct CbMpcShare {
    party: PartyId,
    group_public_key: [u8; 33],
    native: EcdsaKeyShare,
    busy: AtomicBool,
}

impl CbMpcShare {
    pub fn from_serialized(
        party: PartyId,
        secret: SecretShareMaterial,
    ) -> Result<Self, CbMpcError> {
        let native = EcdsaKeyShare::from_bytes(secret.expose_secret()).map_err(native_error)?;
        Self::from_native(party, native)
    }

    fn from_native(party: PartyId, native: EcdsaKeyShare) -> Result<Self, CbMpcError> {
        let group_public_key =
            <[u8; 33]>::try_from(native.public_key_compressed().map_err(native_error)?)
                .map_err(|_| CbMpcError::InvalidGroupPublicKey)?;
        PublicKey::from_slice(&group_public_key).map_err(|_| CbMpcError::InvalidGroupPublicKey)?;
        Ok(Self {
            party,
            group_public_key,
            native,
            busy: AtomicBool::new(false),
        })
    }

    pub fn party(&self) -> &PartyId {
        &self.party
    }

    pub const fn group_public_key(&self) -> [u8; 33] {
        self.group_public_key
    }

    pub fn export_secret(&self) -> Result<SecretShareMaterial, CbMpcError> {
        let secret = self.native.to_bytes();
        SecretShareMaterial::new(secret.expose_secret().to_vec())
    }

    fn reserve(&self) -> Result<ShareReservation<'_>, CbMpcError> {
        self.busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| CbMpcError::ShareBusy)?;
        Ok(ShareReservation { share: self })
    }
}

impl fmt::Debug for CbMpcShare {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CbMpcShare")
            .field("party", &self.party)
            .field("group_public_key", &self.group_public_key)
            .field("secret", &"REDACTED")
            .finish()
    }
}

struct ShareReservation<'a> {
    share: &'a CbMpcShare,
}

impl Drop for ShareReservation<'_> {
    fn drop(&mut self) {
        self.share.busy.store(false, Ordering::Release);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalEcdsaSignature {
    der: Vec<u8>,
}

impl CanonicalEcdsaSignature {
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// Returns the canonical low-S signature in Kaspa's compact wire form.
    pub fn compact_low_s(&self) -> [u8; 64] {
        Signature::from_der(&self.der)
            .expect("canonical signature is constructed from strict DER")
            .serialize_compact()
    }

    fn from_native(
        native_der: &[u8],
        digest: [u8; 32],
        group_public_key: [u8; 33],
    ) -> Result<Self, CbMpcError> {
        let signature =
            Signature::from_der(native_der).map_err(|_| CbMpcError::InvalidSignature)?;
        let mut normalized = signature;
        normalized.normalize_s();
        let der = normalized.serialize_der().to_vec();
        if Signature::from_der(&der)
            .map_err(|_| CbMpcError::InvalidSignature)?
            .serialize_der()
            .as_ref()
            != der
        {
            return Err(CbMpcError::InvalidSignature);
        }
        let public_key = PublicKey::from_slice(&group_public_key)
            .map_err(|_| CbMpcError::InvalidGroupPublicKey)?;
        Secp256k1::verification_only()
            .verify_ecdsa(&Message::from_digest(digest), &normalized, &public_key)
            .map_err(|_| CbMpcError::InvalidSignature)?;
        Ok(Self { der })
    }
}

pub fn generate_native_2_of_3(
    signer_set: &CbMpcSignerSet,
    transports: [&dyn SessionTransport; 3],
    limits: CbMpcRuntimeLimits,
) -> Result<[CbMpcShare; 3], CbMpcError> {
    let policy = native_policy(signer_set)?;
    let quorum = signer_set.parties()[..2]
        .iter()
        .map(PartyId::as_str)
        .collect::<Vec<_>>();
    let deadline = Instant::now()
        .checked_add(limits.session_timeout())
        .ok_or(CbMpcError::InvalidRuntimeLimits)?;
    let failures = (0..3)
        .map(|_| Arc::new(Mutex::new(None)))
        .collect::<Vec<_>>();
    let results = std::thread::scope(|scope| {
        let mut threads = Vec::with_capacity(3);
        for index in 0..3 {
            let adapter = BoundedTransport {
                inner: transports[index],
                limits,
                deadline,
                failure: Arc::clone(&failures[index]),
            };
            let policy = &policy;
            let quorum = &quorum;
            threads.push(scope.spawn(move || cb_mpc::dkg(index, policy, quorum, &adapter)));
        }
        threads
            .into_iter()
            .map(|thread| thread.join().map_err(|_| CbMpcError::TransportTerminated))
            .collect::<Result<Vec<_>, _>>()
    })?;
    let mut native_shares = Vec::with_capacity(3);
    let mut session = None;
    for (index, result) in results.into_iter().enumerate() {
        let (share, current_session) =
            result.map_err(|error| captured_or_native(&failures[index], &error))?;
        if session
            .as_ref()
            .is_some_and(|expected| expected != &current_session)
        {
            return Err(CbMpcError::NativeFailure(None));
        }
        session = Some(current_session);
        native_shares.push(CbMpcShare::from_native(
            signer_set.parties()[index].clone(),
            share,
        )?);
    }
    native_shares
        .try_into()
        .map_err(|_| CbMpcError::NativeFailure(None))
}

impl CbMpcRuntime {
    pub fn sign(
        &self,
        request: &ApprovedCbMpcSignRequest,
        shares: [&CbMpcShare; 2],
        transports: [&dyn SessionTransport; 2],
        now: i64,
    ) -> Result<CanonicalEcdsaSignature, CbMpcError> {
        let parts = request.parts();
        if parts.expires_at <= now {
            return Err(CbMpcError::Expired);
        }
        self.session_claims
            .claim(parts.session_id)
            .map_err(map_claim_error)?;
        self.sign_started(request, shares, transports, now)
    }

    fn sign_started(
        &self,
        request: &ApprovedCbMpcSignRequest,
        shares: [&CbMpcShare; 2],
        transports: [&dyn SessionTransport; 2],
        now: i64,
    ) -> Result<CanonicalEcdsaSignature, CbMpcError> {
        let parts = request.parts();
        for (index, share) in shares.iter().enumerate() {
            if share.party() != &parts.online_parties[index]
                || share.group_public_key() != parts.group_public_key
            {
                return Err(CbMpcError::ShareMismatch);
            }
        }
        let _reservations = [shares[0].reserve()?, shares[1].reserve()?];
        let policy = native_policy(&parts.signer_set)?;
        let online = parts
            .online_parties
            .iter()
            .map(|party| party.as_str().to_owned())
            .collect::<Vec<_>>();
        let receiver = parts
            .online_parties
            .iter()
            .position(|party| party == &parts.receiver)
            .ok_or(CbMpcError::InvalidReceiver)?;
        let absolute_remaining = u64::try_from(parts.expires_at - now)
            .map(Duration::from_secs)
            .map_err(|_| CbMpcError::Expired)?;
        let deadline = Instant::now()
            .checked_add(self.limits.session_timeout().min(absolute_remaining))
            .ok_or(CbMpcError::InvalidRuntimeLimits)?;
        let failures = [Arc::new(Mutex::new(None)), Arc::new(Mutex::new(None))];
        let digest = parts.review.signing_message_digest;
        let results = std::thread::scope(|scope| {
            let mut threads = Vec::with_capacity(2);
            for index in 0..2 {
                let adapter = BoundedTransport {
                    inner: transports[index],
                    limits: self.limits,
                    deadline,
                    failure: Arc::clone(&failures[index]),
                };
                let policy = &policy;
                let online = &online;
                threads.push(scope.spawn(move || {
                    cb_mpc::sign(
                        index,
                        online,
                        policy,
                        &shares[index].native,
                        &digest,
                        receiver,
                        &adapter,
                    )
                }));
            }
            threads
                .into_iter()
                .map(|thread| thread.join().map_err(|_| CbMpcError::TransportTerminated))
                .collect::<Result<Vec<_>, _>>()
        })?;

        let mut receiver_signature = None;
        for (index, result) in results.into_iter().enumerate() {
            let signature = result.map_err(|error| captured_or_native(&failures[index], &error))?;
            if index == receiver {
                receiver_signature = signature;
            } else if signature.is_some() {
                return Err(CbMpcError::InvalidSignature);
            }
        }
        CanonicalEcdsaSignature::from_native(
            receiver_signature
                .as_deref()
                .ok_or(CbMpcError::InvalidSignature)?,
            digest,
            parts.group_public_key,
        )
    }
}

fn map_claim_error(error: SessionClaimError) -> CbMpcError {
    match error {
        SessionClaimError::AlreadyClaimed => CbMpcError::SessionTerminal,
        SessionClaimError::StoreFull => CbMpcError::ReplayCacheFull,
        SessionClaimError::StoreBusy
        | SessionClaimError::CorruptStore
        | SessionClaimError::UnsafePath
        | SessionClaimError::UnsafePermissions
        | SessionClaimError::InvalidSession
        | SessionClaimError::FailedClosed
        | SessionClaimError::Io => CbMpcError::ReplayStoreUnavailable,
    }
}

fn native_policy(signer_set: &CbMpcSignerSet) -> Result<ThresholdPolicy, CbMpcError> {
    ThresholdPolicy::new(
        usize::from(signer_set.threshold()),
        signer_set
            .parties()
            .iter()
            .map(|party| party.as_str().to_owned())
            .collect(),
    )
    .map_err(native_error)
}

struct BoundedTransport<'a> {
    inner: &'a dyn SessionTransport,
    limits: CbMpcRuntimeLimits,
    deadline: Instant,
    failure: Arc<Mutex<Option<TransportFailure>>>,
}

impl BoundedTransport<'_> {
    fn operation_deadline(&self) -> Instant {
        Instant::now()
            .checked_add(self.limits.receive_timeout())
            .unwrap_or(self.deadline)
            .min(self.deadline)
    }

    fn fail(&self, failure: TransportFailure) -> TransportError {
        if let Ok(mut captured) = self.failure.lock() {
            *captured = Some(failure);
        }
        TransportError::new(CB_MPC_TRANSPORT_ERROR)
    }
}

impl Transport for BoundedTransport<'_> {
    fn send(&self, receiver: i32, data: &[u8]) -> Result<(), TransportError> {
        if data.len() > self.limits.max_frame_bytes() {
            return Err(self.fail(TransportFailure::FrameTooLarge));
        }
        if Instant::now() >= self.deadline {
            return Err(self.fail(TransportFailure::Timeout));
        }
        let receiver =
            usize::try_from(receiver).map_err(|_| self.fail(TransportFailure::Terminated))?;
        self.inner
            .send(receiver, data, self.operation_deadline())
            .map_err(|failure| self.fail(failure))
    }

    fn receive(&self, sender: i32) -> Result<Vec<u8>, TransportError> {
        let sender =
            usize::try_from(sender).map_err(|_| self.fail(TransportFailure::Terminated))?;
        let frame = self
            .inner
            .receive(sender, self.operation_deadline())
            .map_err(|failure| self.fail(failure))?;
        if frame.len() > self.limits.max_frame_bytes() {
            return Err(self.fail(TransportFailure::FrameTooLarge));
        }
        Ok(frame)
    }

    fn receive_all(&self, senders: &[i32]) -> Result<Vec<Vec<u8>>, TransportError> {
        senders.iter().map(|sender| self.receive(*sender)).collect()
    }
}

fn captured_or_native(
    failure: &Mutex<Option<TransportFailure>>,
    error: &cb_mpc::Error,
) -> CbMpcError {
    match failure.lock().ok().and_then(|captured| *captured) {
        Some(TransportFailure::Timeout) => CbMpcError::TransportTimeout,
        Some(TransportFailure::Terminated) => CbMpcError::TransportTerminated,
        Some(TransportFailure::FrameTooLarge) => CbMpcError::FrameTooLarge,
        Some(TransportFailure::Failed) => CbMpcError::TransportFailed,
        None => native_error_ref(error),
    }
}

fn native_error(error: cb_mpc::Error) -> CbMpcError {
    native_error_ref(&error)
}

fn native_error_ref(error: &cb_mpc::Error) -> CbMpcError {
    CbMpcError::NativeFailure(error.native_code())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoopTransport;

    impl SessionTransport for NoopTransport {
        fn send(
            &self,
            _receiver: usize,
            _frame: &[u8],
            _deadline: Instant,
        ) -> Result<(), TransportFailure> {
            Ok(())
        }

        fn receive(&self, _sender: usize, _deadline: Instant) -> Result<Vec<u8>, TransportFailure> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn bounded_transport_rejects_oversized_frames_before_io() {
        let limits =
            CbMpcRuntimeLimits::new(Duration::from_secs(1), Duration::from_secs(2), 4).unwrap();
        let failure = Arc::new(Mutex::new(None));
        let adapter = BoundedTransport {
            inner: &NoopTransport,
            limits,
            deadline: Instant::now() + Duration::from_secs(2),
            failure: Arc::clone(&failure),
        };

        assert!(adapter.send(0, &[0; 5]).is_err());
        assert_eq!(
            *failure.lock().unwrap(),
            Some(TransportFailure::FrameTooLarge)
        );
    }
}

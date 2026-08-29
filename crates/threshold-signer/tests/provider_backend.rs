use std::{collections::BTreeMap, time::Duration};

use catomicals_threshold::{
    FrostSignerBackend, GuardedSignerProvider, HsmSignerAdapter, LocalEncryptedFrostBackend,
    LocalFrostParticipant, NonceGuard, ProviderError, ProviderIdentity, ProviderRequestAuthorizer,
    ProviderRound, SIGNER_PROVIDER_PROTOCOL_VERSION, SignerProvider, SignerProviderKind,
    SignerRequestContext, SignerRoundOneRequest, SignerRoundTwoRequest, build_session,
    group_pubkey_xonly, participant_identifier, run_local_dkg,
};
use frost_secp256k1_tr::{SigningPackage, round1::SigningCommitments, round2::SignatureShare};
use sha2::{Digest, Sha256};
use uuid::Uuid;

struct ExactPolicy;

impl ProviderRequestAuthorizer for ExactPolicy {
    fn authorize(
        &mut self,
        context: &SignerRequestContext,
        _round: ProviderRound,
    ) -> Result<(), ProviderError> {
        (context.policy_digest == [9; 32])
            .then_some(())
            .ok_or(ProviderError::IdentityDrift)
    }
}

fn context(identity: &ProviderIdentity, request_nonce: [u8; 32]) -> SignerRequestContext {
    SignerRequestContext {
        protocol_version: SIGNER_PROVIDER_PROTOCOL_VERSION,
        wallet_id: identity.wallet_id,
        signer_set_id: identity.signer_set_id,
        signer_epoch: identity.signer_epoch,
        signer_id: identity.signer_id,
        device_id: identity.device_id,
        device_generation: identity.device_generation,
        operation_id: Uuid::from_bytes([7; 16]),
        intent_id: Uuid::from_bytes([8; 16]),
        session_id: [4; 32],
        taproot_sighash: [5; 32],
        policy_digest: [9; 32],
        group_pubkey_xonly: identity.group_pubkey_xonly,
        verifying_share_digest: identity.verifying_share_digest,
        min_signers: 2,
        max_signers: 3,
        chain_snapshot_digest: [10; 32],
        request_nonce,
        expires_at: 200,
    }
}

#[test]
fn local_encrypted_provider_keeps_keys_private_and_returns_a_verified_share() {
    let generated = run_local_dkg(3, 2).unwrap();
    let signer_id = 1;
    let identifier = participant_identifier(signer_id).unwrap();
    let participant = LocalFrostParticipant::new(
        signer_id,
        generated.key_packages[&identifier].clone(),
        NonceGuard::new(),
    )
    .unwrap();
    let verifying_share = generated.public_key_package.verifying_shares()[&identifier]
        .serialize()
        .unwrap();
    let identity = ProviderIdentity {
        wallet_id: Uuid::from_bytes([1; 16]),
        signer_set_id: Uuid::from_bytes([2; 16]),
        signer_epoch: 3,
        signer_id,
        device_id: Uuid::from_bytes([3; 16]),
        device_generation: 1,
        group_pubkey_xonly: group_pubkey_xonly(&generated.public_key_package).unwrap(),
        verifying_share_digest: Sha256::digest(verifying_share).into(),
    };
    let backend = LocalEncryptedFrostBackend::new(
        participant,
        generated.public_key_package.clone(),
        ExactPolicy,
    );
    let mut provider = GuardedSignerProvider::new(identity.clone(), backend);

    let round_one_context = context(&identity, [11; 32]);
    let response = provider
        .round_one(
            SignerRoundOneRequest {
                context: round_one_context.clone(),
            },
            100,
        )
        .unwrap();
    assert_eq!(
        response.request_binding_digest,
        round_one_context.binding_digest()
    );
    let own_commitment =
        SigningCommitments::deserialize(&hex::decode(response.commitment_hex).unwrap()).unwrap();

    let mut other = LocalFrostParticipant::new(
        2,
        generated.key_packages[&participant_identifier(2).unwrap()].clone(),
        NonceGuard::new(),
    )
    .unwrap();
    let other_commitment = other.round1([4; 32], [5; 32]).unwrap();
    let session = build_session(
        [4; 32],
        [5; 32],
        2,
        BTreeMap::from([
            (identifier, own_commitment),
            (participant_identifier(2).unwrap(), other_commitment),
        ]),
        generated.public_key_package.clone(),
    );
    let mut drifted_round_two_context = context(&identity, [12; 32]);
    drifted_round_two_context.chain_snapshot_digest = [42; 32];
    assert_eq!(
        provider.round_two(
            SignerRoundTwoRequest {
                context: drifted_round_two_context,
                signing_package_hex: hex::encode(session.signing_package.serialize().unwrap()),
            },
            101,
        ),
        Err(ProviderError::RoundBindingMismatch)
    );

    let round_two_context = context(&identity, [13; 32]);
    let response = provider
        .round_two(
            SignerRoundTwoRequest {
                context: round_two_context.clone(),
                signing_package_hex: hex::encode(session.signing_package.serialize().unwrap()),
            },
            101,
        )
        .unwrap();
    assert_eq!(
        response.request_binding_digest,
        round_two_context.binding_digest()
    );
    let share =
        SignatureShare::deserialize(&hex::decode(response.signature_share_hex).unwrap()).unwrap();
    frost_core::verify_signature_share(
        identifier,
        &generated.public_key_package.verifying_shares()[&identifier],
        &share,
        &session.signing_package,
        generated.public_key_package.verifying_key(),
    )
    .unwrap();

    assert_eq!(
        provider.round_two(
            SignerRoundTwoRequest {
                context: round_two_context,
                signing_package_hex: hex::encode(session.signing_package.serialize().unwrap()),
            },
            102,
        ),
        Err(ProviderError::Replay)
    );
}

#[test]
fn signer_rejects_a_session_beyond_its_configured_lifetime() {
    let generated = run_local_dkg(3, 2).unwrap();
    let signer_id = 1;
    let identifier = participant_identifier(signer_id).unwrap();
    let participant = LocalFrostParticipant::new(
        signer_id,
        generated.key_packages[&identifier].clone(),
        NonceGuard::new(),
    )
    .unwrap();
    let identity = ProviderIdentity {
        wallet_id: Uuid::from_bytes([1; 16]),
        signer_set_id: Uuid::from_bytes([2; 16]),
        signer_epoch: 3,
        signer_id,
        device_id: Uuid::from_bytes([3; 16]),
        device_generation: 1,
        group_pubkey_xonly: group_pubkey_xonly(&generated.public_key_package).unwrap(),
        verifying_share_digest: Sha256::digest(
            generated.public_key_package.verifying_shares()[&identifier]
                .serialize()
                .unwrap(),
        )
        .into(),
    };
    let backend =
        LocalEncryptedFrostBackend::new(participant, generated.public_key_package, ExactPolicy);
    let mut provider = GuardedSignerProvider::new_with_session_timeout(
        identity.clone(),
        backend,
        Duration::from_secs(30),
    )
    .unwrap();
    let mut request_context = context(&identity, [21; 32]);
    request_context.expires_at = 131;

    assert_eq!(
        provider.round_one(
            SignerRoundOneRequest {
                context: request_context,
            },
            100,
        ),
        Err(ProviderError::SessionLifetimeExceeded)
    );
}

struct WrongKindBackend;

impl FrostSignerBackend for WrongKindBackend {
    fn provider_kind(&self) -> SignerProviderKind {
        SignerProviderKind::LocalEncrypted
    }

    fn health(&mut self, _now: i64) -> catomicals_threshold::DeviceHealth {
        unreachable!()
    }

    fn reserve_nonce_and_commit(
        &mut self,
        _context: &SignerRequestContext,
    ) -> Result<SigningCommitments, ProviderError> {
        unreachable!()
    }

    fn sign_reserved_share(
        &mut self,
        _context: &SignerRequestContext,
        _signing_package: &SigningPackage,
    ) -> Result<SignatureShare, ProviderError> {
        unreachable!()
    }

    fn burn_reservation(
        &mut self,
        _operation_id: Uuid,
        _session_id: [u8; 32],
        _reason_code: &str,
    ) -> Result<(), ProviderError> {
        unreachable!()
    }
}

#[test]
fn hsm_adapter_refuses_to_label_a_local_backend_as_hardware() {
    let identity = ProviderIdentity {
        wallet_id: Uuid::from_bytes([1; 16]),
        signer_set_id: Uuid::from_bytes([2; 16]),
        signer_epoch: 1,
        signer_id: 2,
        device_id: Uuid::from_bytes([3; 16]),
        device_generation: 1,
        group_pubkey_xonly: [4; 32],
        verifying_share_digest: [5; 32],
    };
    assert!(matches!(
        HsmSignerAdapter::new(identity, WrongKindBackend),
        Err(ProviderError::InvalidProvider)
    ));
}

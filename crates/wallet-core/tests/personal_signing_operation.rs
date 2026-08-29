use std::collections::BTreeMap;

use catomicals_threshold::{
    GuardedSignerProvider, LocalEncryptedFrostBackend, NonceGuard, PersonalSignerProfile,
    ProviderError, ProviderIdentity, ProviderRequestAuthorizer, ProviderRound, SignerProvider,
    run_local_dkg,
};
use catomicals_wallet::{
    BeginPersonalSigningOperation, PersonalSigningCoordinator, PersonalSigningError,
    PersonalSigningRecovery,
};
use catomicals_wallet_storage::{PersonalSigningOperationStatus, WalletStorage};
use tempfile::tempdir;
use uuid::Uuid;

struct ApprovedPolicy;

impl ProviderRequestAuthorizer for ApprovedPolicy {
    fn authorize(
        &mut self,
        context: &catomicals_threshold::SignerRequestContext,
        _round: ProviderRound,
    ) -> Result<(), ProviderError> {
        (context.policy_digest == [8; 32])
            .then_some(())
            .ok_or(ProviderError::IdentityDrift)
    }
}

fn fixture() -> (
    PersonalSignerProfile,
    Vec<ProviderIdentity>,
    BTreeMap<u16, Box<dyn SignerProvider>>,
) {
    let wallet_id = Uuid::from_bytes([1; 16]);
    let bootstrap = PersonalSignerProfile::bootstrap(
        Uuid::from_bytes([2; 16]),
        wallet_id,
        Uuid::from_bytes([3; 16]),
        1,
        run_local_dkg(3, 2).unwrap(),
    )
    .unwrap();
    let profile = bootstrap.profile;
    let public = profile.public_key_package().unwrap();
    let identities: Vec<_> = profile
        .participants()
        .iter()
        .map(|participant| ProviderIdentity {
            wallet_id,
            signer_set_id: profile.signer_set_id(),
            signer_epoch: profile.signer_epoch(),
            signer_id: participant.signer_id,
            device_id: Uuid::from_bytes([participant.signer_id as u8; 16]),
            device_generation: 1,
            group_pubkey_xonly: profile.group_pubkey_xonly(),
            verifying_share_digest: participant.verifying_share_digest,
        })
        .collect();
    let providers = bootstrap
        .secret_packages
        .into_iter()
        .map(|(signer_id, package)| {
            let participant = package
                .open(&profile)
                .unwrap()
                .into_participant(NonceGuard::new())
                .unwrap();
            let identity = identities
                .iter()
                .find(|identity| identity.signer_id == signer_id)
                .unwrap()
                .clone();
            let backend =
                LocalEncryptedFrostBackend::new(participant, public.clone(), ApprovedPolicy);
            (
                signer_id,
                Box::new(GuardedSignerProvider::new(identity, backend)) as Box<dyn SignerProvider>,
            )
        })
        .collect();
    (profile, identities, providers)
}

fn request(selected_participants: [u16; 2]) -> BeginPersonalSigningOperation {
    BeginPersonalSigningOperation {
        operation_id: Uuid::new_v4(),
        intent_id: Uuid::new_v4(),
        session_id: [6; 32],
        taproot_sighash: [7; 32],
        policy_digest: [8; 32],
        chain_snapshot_digest: [9; 32],
        selected_participants,
        expires_at: 200,
    }
}

fn run_pair(selected: [u16; 2]) {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let (profile, identities, mut providers) = fixture();
    let storage = WalletStorage::initialize(&database, profile.wallet_id(), 100).unwrap();
    let mut coordinator = PersonalSigningCoordinator::new(profile, identities, storage).unwrap();
    let request = request(selected);

    let round_one = coordinator.begin(request.clone(), 100).unwrap();
    assert_eq!(round_one.len(), 2);
    for dispatch in round_one {
        let signer_id = dispatch.signer_id;
        let response = providers
            .get_mut(&signer_id)
            .unwrap()
            .round_one(dispatch.request, 101)
            .unwrap();
        coordinator
            .accept_round_one(request.operation_id, signer_id, response, 102)
            .unwrap();
    }

    let round_two = coordinator
        .freeze_commitments(request.operation_id, 103)
        .unwrap();
    assert_eq!(round_two.len(), 2);
    for dispatch in round_two {
        let signer_id = dispatch.signer_id;
        let response = providers
            .get_mut(&signer_id)
            .unwrap()
            .round_two(dispatch.request, 104)
            .unwrap();
        coordinator
            .accept_round_two(request.operation_id, signer_id, response, 105)
            .unwrap();
    }
    let signature = coordinator.finalize(request.operation_id, 106).unwrap();
    assert_ne!(signature, [0; 64]);
    let durable = coordinator
        .operation(request.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(durable.status, PersonalSigningOperationStatus::Finalized);
    assert_eq!(durable.final_signature, Some(signature));
}

#[test]
fn daily_and_both_recovery_pairs_complete_a_verified_signature() {
    run_pair([1, 2]);
    run_pair([1, 3]);
    run_pair([2, 3]);
}

#[test]
fn provider_inventory_and_pair_selection_are_profile_bound() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let (profile, mut identities, _providers) = fixture();
    identities[1].signer_epoch += 1;
    let storage = WalletStorage::initialize(&database, profile.wallet_id(), 100).unwrap();
    assert!(matches!(
        PersonalSigningCoordinator::new(profile, identities, storage),
        Err(PersonalSigningError::ProviderIdentityDrift)
    ));

    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let (profile, identities, _providers) = fixture();
    let storage = WalletStorage::initialize(&database, profile.wallet_id(), 100).unwrap();
    let mut coordinator = PersonalSigningCoordinator::new(profile, identities, storage).unwrap();
    assert!(matches!(
        coordinator.begin(request([2, 1]), 100),
        Err(PersonalSigningError::InvalidParticipantPair)
    ));
}

#[test]
fn request_is_persisted_before_provider_dispatch_and_expiry_is_terminal() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let (profile, identities, _providers) = fixture();
    let storage = WalletStorage::initialize(&database, profile.wallet_id(), 100).unwrap();
    let mut coordinator = PersonalSigningCoordinator::new(profile, identities, storage).unwrap();
    let request = request([1, 2]);
    let dispatches = coordinator.begin(request.clone(), 100).unwrap();
    assert_eq!(dispatches.len(), 2);
    assert_eq!(
        coordinator
            .operation(request.operation_id)
            .unwrap()
            .unwrap()
            .status,
        PersonalSigningOperationStatus::CollectingCommitments
    );

    let termination = coordinator
        .expire(request.operation_id, 201)
        .unwrap()
        .unwrap();
    assert_eq!(termination.aborts.len(), 2);
    assert_eq!(
        coordinator
            .operation(request.operation_id)
            .unwrap()
            .unwrap()
            .status,
        PersonalSigningOperationStatus::Expired
    );
}

#[test]
fn persisted_signature_shares_finalize_after_coordinator_restart() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let (profile, identities, mut providers) = fixture();
    let storage = WalletStorage::initialize(&database, profile.wallet_id(), 100).unwrap();
    let mut coordinator =
        PersonalSigningCoordinator::new(profile.clone(), identities.clone(), storage).unwrap();
    let request = request([1, 2]);
    for dispatch in coordinator.begin(request.clone(), 100).unwrap() {
        let signer_id = dispatch.signer_id;
        let response = providers
            .get_mut(&signer_id)
            .unwrap()
            .round_one(dispatch.request, 101)
            .unwrap();
        coordinator
            .accept_round_one(request.operation_id, signer_id, response, 102)
            .unwrap();
    }
    for dispatch in coordinator
        .freeze_commitments(request.operation_id, 103)
        .unwrap()
    {
        let signer_id = dispatch.signer_id;
        let response = providers
            .get_mut(&signer_id)
            .unwrap()
            .round_two(dispatch.request, 104)
            .unwrap();
        coordinator
            .accept_round_two(request.operation_id, signer_id, response, 105)
            .unwrap();
    }
    drop(coordinator.into_store());

    let storage = WalletStorage::open(&database).unwrap();
    let mut restarted = PersonalSigningCoordinator::new(profile, identities, storage).unwrap();
    assert_eq!(
        restarted
            .recover_operation(request.operation_id, 106)
            .unwrap(),
        PersonalSigningRecovery::ReadyToFinalize
    );
    let signature = restarted.finalize(request.operation_id, 107).unwrap();
    assert_ne!(signature, [0; 64]);
}

#[test]
fn restart_during_commitment_collection_is_explicitly_terminated() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let (profile, identities, _providers) = fixture();
    let storage = WalletStorage::initialize(&database, profile.wallet_id(), 100).unwrap();
    let mut coordinator =
        PersonalSigningCoordinator::new(profile.clone(), identities.clone(), storage).unwrap();
    let request = request([1, 2]);
    coordinator.begin(request.clone(), 100).unwrap();
    drop(coordinator.into_store());

    let storage = WalletStorage::open(&database).unwrap();
    let mut restarted = PersonalSigningCoordinator::new(profile, identities, storage).unwrap();
    assert_eq!(
        restarted
            .recover_operation(request.operation_id, 110)
            .unwrap(),
        PersonalSigningRecovery::TerminatedInterruptedCommitmentRound
    );
    let durable = restarted.operation(request.operation_id).unwrap().unwrap();
    assert_eq!(durable.status, PersonalSigningOperationStatus::Aborted);
    assert_eq!(
        durable.terminal_reason.as_deref(),
        Some("restart_interrupted")
    );
}

#[test]
fn malformed_provider_response_does_not_consume_the_retry_context() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let (profile, identities, mut providers) = fixture();
    let storage = WalletStorage::initialize(&database, profile.wallet_id(), 100).unwrap();
    let mut coordinator = PersonalSigningCoordinator::new(profile, identities, storage).unwrap();
    let request = request([1, 2]);
    let dispatch = coordinator.begin(request.clone(), 100).unwrap().remove(0);
    let signer_id = dispatch.signer_id;
    let mut response = providers
        .get_mut(&signer_id)
        .unwrap()
        .round_one(dispatch.request, 101)
        .unwrap();
    let valid_response = response.clone();
    response.request_binding_digest[0] ^= 1;

    assert_eq!(
        coordinator.accept_round_one(request.operation_id, signer_id, response, 102),
        Err(PersonalSigningError::ResponseBindingMismatch)
    );
    coordinator
        .accept_round_one(request.operation_id, signer_id, valid_response, 103)
        .unwrap();
}

#[test]
fn live_operation_id_cannot_be_dispatched_twice() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let (profile, identities, _providers) = fixture();
    let storage = WalletStorage::initialize(&database, profile.wallet_id(), 100).unwrap();
    let mut coordinator = PersonalSigningCoordinator::new(profile, identities, storage).unwrap();
    let request = request([1, 2]);

    coordinator.begin(request.clone(), 100).unwrap();
    assert_eq!(
        coordinator.begin(request, 101),
        Err(PersonalSigningError::OperationAlreadyActive)
    );
}

#[test]
fn durable_operation_id_requires_recovery_instead_of_redispatch() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let (profile, identities, _providers) = fixture();
    let storage = WalletStorage::initialize(&database, profile.wallet_id(), 100).unwrap();
    let request = request([1, 2]);
    let mut coordinator =
        PersonalSigningCoordinator::new(profile.clone(), identities.clone(), storage).unwrap();
    coordinator.begin(request.clone(), 100).unwrap();
    drop(coordinator.into_store());

    let storage = WalletStorage::open(&database).unwrap();
    let mut restarted = PersonalSigningCoordinator::new(profile, identities, storage).unwrap();
    assert_eq!(
        restarted.begin(request, 101),
        Err(PersonalSigningError::OperationAlreadyActive)
    );
}

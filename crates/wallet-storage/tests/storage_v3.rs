use catomicals_policy_registry::{
    ActivationProposal, ActivationProposalInput, MAX_BUNDLE_BYTES, compile_policy_json,
};
use catomicals_wallet_storage::{
    ActivationStatus, CURRENT_SCHEMA_VERSION, PolicyStoreOutcome, StorageError, WalletStorage,
};
use rusqlite::Connection;
use tempfile::tempdir;
use uuid::Uuid;

const ISSUANCE: &str = r#"{
  "schema_version":1,
  "canonicalization":"catomicals-policy-jcs-v1",
  "digest_algorithm":"sha256",
  "network":{"bitcoin_network":"signet","deployment_profile":"bitcoin-inquisition-signet-v29.4-op-cat","op_cat":"required"},
  "policy_kind":"catomicals-issuance-v1",
  "name":"stored issuance",
  "input":{"item_id":"4242424242424242424242424242424242424242424242424242424242424242","target_prefix":1,"total_supply":4,"successor_rule":"recursive_issuer","lane_count":1,"salt":"7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a","metadata_base64":"Y2F0b21pY2FscyBkZW1vIGl0ZW0="}
}"#;

fn proposal(
    bundle: &catomicals_policy_registry::PolicyBundle,
    wallet_id: Uuid,
    wallet_epoch: u64,
) -> ActivationProposal {
    ActivationProposal::new(ActivationProposalInput {
        activation_id: Uuid::from_bytes([0x31; 16]),
        binding_id: Uuid::from_bytes([0x32; 16]),
        policy_hash: bundle.policy_hash.clone(),
        wallet_id,
        wallet_epoch,
        signer_set_id: Uuid::from_bytes([0x33; 16]),
        signer_epoch: 7,
        chain_profile: "bitcoin-inquisition-signet-v29.4-op-cat".to_owned(),
        artifact_set_digest: bundle.artifact_set_digest.clone(),
        validation_run_digest: bundle.validation_run.run_digest.clone(),
        expires_at: 1_900_000_000,
        created_at: 1_800_000_100,
    })
    .unwrap()
}

#[test]
fn fresh_v3_stores_complete_registry_and_requires_byte_identical_idempotency() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([0x21; 16]);
    let mut storage = WalletStorage::initialize(&database, wallet_id, 1_800_000_000).unwrap();
    assert_eq!(CURRENT_SCHEMA_VERSION, 4);
    assert_eq!(storage.schema_version().unwrap(), 4);

    let bundle = compile_policy_json(ISSUANCE.as_bytes()).unwrap();
    let bytes = bundle.to_bytes().unwrap();
    assert_eq!(
        storage
            .store_policy_bundle_bytes(&bundle.policy_hash, &bytes, 1_800_000_001)
            .unwrap(),
        PolicyStoreOutcome::Inserted
    );
    assert_eq!(
        storage
            .store_policy_bundle_bytes(&bundle.policy_hash, &bytes, 1_800_000_002)
            .unwrap(),
        PolicyStoreOutcome::AlreadyPresent
    );
    assert_eq!(
        storage.policy_bundle_bytes(&bundle.policy_hash).unwrap(),
        Some(bytes.clone())
    );

    let mut different = bytes;
    *different.last_mut().unwrap() ^= 1;
    assert!(matches!(
        storage.store_policy_bundle_bytes(&bundle.policy_hash, &different, 1_800_000_003),
        Err(StorageError::ImmutableConflict("policy_documents"))
    ));
}

#[test]
fn storage_rejects_an_oversized_bundle_before_immutable_hash_lookup() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([0x26; 16]);
    let mut storage = WalletStorage::initialize(&database, wallet_id, 1_800_000_000).unwrap();
    let bundle = compile_policy_json(ISSUANCE.as_bytes()).unwrap();
    storage
        .store_policy_bundle_bytes(
            &bundle.policy_hash,
            &bundle.to_bytes().unwrap(),
            1_800_000_001,
        )
        .unwrap();

    let oversized = vec![b' '; MAX_BUNDLE_BYTES + 1];
    assert!(matches!(
        storage.store_policy_bundle_bytes(&bundle.policy_hash, &oversized, 1_800_000_002),
        Err(StorageError::InvalidStoredValue(message)) if message.contains("policy bundle")
    ));
}

#[test]
fn v2_database_upgrades_in_order_to_v3() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([0x22; 16]);
    let storage = WalletStorage::initialize(&database, wallet_id, 1_800_000_000).unwrap();
    drop(storage);

    let raw = Connection::open(&database).unwrap();
    raw.execute_batch(
        "DROP TRIGGER policy_documents_no_update;
         DROP TRIGGER signer_request_nonces_no_update;
         DROP TRIGGER signer_request_nonces_no_delete;
         DROP TRIGGER signer_request_nonces_operation_binding;
         DROP TRIGGER signer_device_events_no_update;
         DROP TRIGGER signer_device_events_no_delete;
         DROP INDEX signer_request_nonces_operation;
         DROP INDEX signer_device_events_latest;
         DROP TABLE signer_request_nonces;
         DROP TABLE signer_device_events;
         DROP TRIGGER policy_documents_no_delete;
         DROP TRIGGER policy_artifacts_no_update;
         DROP TRIGGER policy_artifacts_no_delete;
         DROP TRIGGER policy_test_vectors_no_update;
         DROP TRIGGER policy_test_vectors_no_delete;
         DROP TRIGGER policy_validation_runs_no_update;
         DROP TRIGGER policy_validation_runs_no_delete;
         DROP TRIGGER policy_bindings_no_update;
         DROP TRIGGER policy_bindings_no_delete;
         DROP TRIGGER policy_activations_no_update;
         DROP TRIGGER policy_activations_no_delete;
         DROP TABLE policy_activations;
         DROP TABLE policy_bindings;
         DROP TABLE policy_validation_runs;
         DROP TABLE policy_test_vectors;
         DROP TABLE policy_artifacts;
         DROP TABLE policy_documents;
         DELETE FROM schema_migrations WHERE version = 4;
         DELETE FROM schema_migrations WHERE version = 3;
         PRAGMA user_version = 2;",
    )
    .unwrap();
    drop(raw);

    let upgraded = WalletStorage::open(&database).unwrap();
    assert_eq!(upgraded.schema_version().unwrap(), 4);
}

#[test]
fn tampered_v3_append_only_trigger_fails_on_reopen() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([0x23; 16]);
    let storage = WalletStorage::initialize(&database, wallet_id, 1_800_000_000).unwrap();
    drop(storage);
    let raw = Connection::open(&database).unwrap();
    raw.execute_batch(
        "DROP TRIGGER policy_activations_no_update;
         CREATE TRIGGER policy_activations_no_update BEFORE UPDATE ON policy_activations BEGIN SELECT 1; END;",
    )
    .unwrap();
    drop(raw);
    assert!(matches!(
        WalletStorage::open(&database),
        Err(StorageError::SchemaIntegrity { .. })
    ));
}

#[test]
fn dead_code_append_only_trigger_fails_on_reopen() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([0x27; 16]);
    let storage = WalletStorage::initialize(&database, wallet_id, 1_800_000_000).unwrap();
    drop(storage);
    let raw = Connection::open(&database).unwrap();
    raw.execute_batch(
        "DROP TRIGGER policy_activations_no_update;
         CREATE TRIGGER policy_activations_no_update
         BEFORE UPDATE ON policy_activations WHEN 0
         BEGIN SELECT RAISE(ABORT, 'dead append-only trigger'); END;",
    )
    .unwrap();
    drop(raw);
    assert!(matches!(
        WalletStorage::open(&database),
        Err(StorageError::SchemaIntegrity { .. })
    ));
}

#[test]
fn weakened_policy_table_ddl_fails_on_reopen() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([0x28; 16]);
    let storage = WalletStorage::initialize(&database, wallet_id, 1_800_000_000).unwrap();
    drop(storage);
    let raw = Connection::open(&database).unwrap();
    raw.execute_batch(
        "DROP TRIGGER policy_artifacts_no_update;
         DROP TRIGGER policy_artifacts_no_delete;
         DROP INDEX policy_artifacts_policy;
         DROP TABLE policy_artifacts;
         CREATE TABLE policy_artifacts (
             policy_hash TEXT NOT NULL REFERENCES policy_documents(policy_hash),
             artifact_id TEXT NOT NULL,
             wallet_id TEXT NOT NULL REFERENCES wallet_metadata(wallet_id),
             wallet_epoch INTEGER NOT NULL CHECK (wallet_epoch > 0),
             kind TEXT NOT NULL CHECK (length(kind) > 0),
             lane INTEGER,
             media_type TEXT NOT NULL CHECK (length(media_type) > 0),
             content BLOB NOT NULL,
             content_digest TEXT NOT NULL,
             created_at INTEGER NOT NULL,
             PRIMARY KEY (policy_hash, artifact_id)
         ) STRICT;
         CREATE INDEX policy_artifacts_policy
         ON policy_artifacts(policy_hash, artifact_id);
         CREATE TRIGGER policy_artifacts_no_update BEFORE UPDATE ON policy_artifacts
         BEGIN SELECT RAISE(ABORT, 'policy artifacts are immutable'); END;
         CREATE TRIGGER policy_artifacts_no_delete BEFORE DELETE ON policy_artifacts
         BEGIN SELECT RAISE(ABORT, 'policy artifacts are append-only'); END;",
    )
    .unwrap();
    drop(raw);
    assert!(matches!(
        WalletStorage::open(&database),
        Err(StorageError::SchemaIntegrity { .. })
    ));
}

#[test]
fn every_v3_digest_column_has_full_lowercase_sha256_check() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([0x29; 16]);
    let storage = WalletStorage::initialize(&database, wallet_id, 1_800_000_000).unwrap();
    drop(storage);
    let raw = Connection::open(&database).unwrap();

    for (table, columns) in [
        (
            "policy_documents",
            &[
                "policy_hash",
                "artifact_set_digest",
                "vector_set_digest",
                "validation_run_digest",
            ][..],
        ),
        ("policy_artifacts", &["content_digest"][..]),
        ("policy_test_vectors", &["input_digest"][..]),
        (
            "policy_validation_runs",
            &["run_digest", "artifact_set_digest", "vector_set_digest"][..],
        ),
        (
            "policy_bindings",
            &["artifact_set_digest", "validation_run_digest"][..],
        ),
        (
            "policy_activations",
            &[
                "artifact_set_digest",
                "validation_run_digest",
                "approval_digest",
            ][..],
        ),
    ] {
        let sql: String = raw
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        let compact: String = sql
            .to_ascii_lowercase()
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        for column in columns {
            assert!(compact.contains(&format!("length({column})=71")));
            assert!(compact.contains(&format!("substr({column},1,7)='sha256:'")));
            assert!(compact.contains(&format!("substr({column},8)notglob'*[^0-9a-f]*'")));
        }
    }
}

#[test]
fn only_validated_current_epoch_policy_can_create_a_pending_activation() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([0x24; 16]);
    let mut storage = WalletStorage::initialize(&database, wallet_id, 1_800_000_000).unwrap();
    let bundle = compile_policy_json(ISSUANCE.as_bytes()).unwrap();
    let pending = proposal(&bundle, wallet_id, 1);

    assert!(matches!(
        storage.propose_policy_activation(&pending),
        Err(StorageError::PolicyNotValidated)
    ));
    storage
        .store_policy_bundle_bytes(
            &bundle.policy_hash,
            &bundle.to_bytes().unwrap(),
            1_800_000_001,
        )
        .unwrap();

    let wrong = ActivationProposal::new(ActivationProposalInput {
        activation_id: Uuid::from_bytes([0x41; 16]),
        binding_id: Uuid::from_bytes([0x42; 16]),
        policy_hash: bundle.policy_hash.clone(),
        wallet_id,
        wallet_epoch: 1,
        signer_set_id: Uuid::from_bytes([0x43; 16]),
        signer_epoch: 7,
        chain_profile: "bitcoin-inquisition-signet-v29.4-op-cat".to_owned(),
        artifact_set_digest: bundle.artifact_set_digest.clone(),
        validation_run_digest:
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned(),
        expires_at: 1_900_000_000,
        created_at: 1_800_000_100,
    })
    .unwrap();
    assert!(matches!(
        storage.propose_policy_activation(&wrong),
        Err(StorageError::PolicyNotValidated)
    ));

    storage.propose_policy_activation(&pending).unwrap();
    assert_eq!(
        storage
            .policy_activation_status(pending.activation_id)
            .unwrap(),
        Some(ActivationStatus::Pending)
    );
    assert!(
        !storage
            .policy_binding_usable_for_signing(pending.binding_id)
            .unwrap()
    );
}

#[test]
fn recovery_epoch_invalidates_pending_activation_without_mutating_history() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([0x25; 16]);
    let mut storage = WalletStorage::initialize(&database, wallet_id, 1_800_000_000).unwrap();
    let bundle = compile_policy_json(ISSUANCE.as_bytes()).unwrap();
    storage
        .store_policy_bundle_bytes(
            &bundle.policy_hash,
            &bundle.to_bytes().unwrap(),
            1_800_000_001,
        )
        .unwrap();
    let pending = proposal(&bundle, wallet_id, 1);
    storage.propose_policy_activation(&pending).unwrap();

    storage.begin_restore_precheck(1_800_000_200).unwrap();
    storage.cutover_restore(1_800_000_201).unwrap();
    assert_eq!(
        storage
            .policy_activation_status(pending.activation_id)
            .unwrap(),
        Some(ActivationStatus::InvalidatedByRecovery)
    );
    assert!(
        !storage
            .policy_binding_usable_for_signing(pending.binding_id)
            .unwrap()
    );
}

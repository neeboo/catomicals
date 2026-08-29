use catomicals_chain_domain::{BitcoinNetwork, ChainNetwork, ChainScope};
use catomicals_signing_domain::{SignerBackendRequirement, SigningSuiteId};
use catomicals_wallet_storage::{ChainExecutorClaim, StorageError, WalletStorage};
use rusqlite::{Connection, params};
use tempfile::tempdir;
use uuid::Uuid;

const NOW: i64 = 1_900_000_000;

fn scope() -> ChainScope {
    ChainScope::for_network(ChainNetwork::Bitcoin(BitcoinNetwork::Signet))
}

fn fixture() -> (tempfile::TempDir, std::path::PathBuf, ChainExecutorClaim) {
    let root = tempdir().unwrap();
    let path = root.path().join("wallet.sqlite3");
    let wallet_id = Uuid::new_v4();
    let profile_id = Uuid::new_v4();
    let job_id = Uuid::new_v4();
    WalletStorage::initialize(&path, wallet_id, NOW).unwrap();

    // The claim contract is intentionally tested independently of the intent
    // setup ceremony. The production method still matches this row's complete
    // immutable execution binding before inserting its one-time ledger entry.
    let raw = Connection::open(&path).unwrap();
    raw.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
    raw.execute(
        "INSERT INTO signer_profiles
         (profile_id, wallet_id, chain_scope_json, signing_suite_id,
          backend_requirement, signer_set_id, authorization_signer_id,
          signer_epoch, threshold, max_signers, verification_key,
          secret_ref_id, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, 'set-1', 'participant-1', 1, 2, 3,
                 ?6, ?7, ?8)",
        params![
            profile_id.to_string(),
            wallet_id.to_string(),
            serde_json::to_string(&scope()).unwrap(),
            SigningSuiteId::BITCOIN_BIP340_FROST_V1.as_str(),
            SignerBackendRequirement::FrostSecp256k1Tr.as_str(),
            [2_u8; 32].as_slice(),
            Uuid::new_v4().to_string(),
            NOW,
        ],
    )
    .unwrap();
    raw.execute(
        "INSERT INTO signing_jobs
         (job_id, wallet_id, profile_id, intent_id, chain_scope_json,
          signing_suite_id, backend_requirement, review_schema_version,
          review_artifact_json, review_digest, signing_message_digest,
          policy_snapshot_digest, chain_snapshot_digest, session_id,
          selected_parties_json, receiver, operation_binding_digest, status,
          final_signature, terminal_reason, expires_at, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?9, ?10, ?11, ?12,
                 ?13, ?14, 'desktop', ?15, 'signing', NULL, NULL, ?16, ?17, ?17)",
        params![
            job_id.to_string(),
            wallet_id.to_string(),
            profile_id.to_string(),
            Uuid::new_v4().to_string(),
            serde_json::to_string(&scope()).unwrap(),
            SigningSuiteId::BITCOIN_BIP340_FROST_V1.as_str(),
            SignerBackendRequirement::FrostSecp256k1Tr.as_str(),
            serde_json::json!({"test": true}).to_string(),
            [1_u8; 32].as_slice(),
            [2_u8; 32].as_slice(),
            [3_u8; 32].as_slice(),
            [4_u8; 32].as_slice(),
            [5_u8; 32].as_slice(),
            serde_json::json!(["wallet", "phone"]).to_string(),
            [6_u8; 32].as_slice(),
            NOW + 120,
            NOW,
        ],
    )
    .unwrap();
    drop(raw);

    (
        root,
        path,
        ChainExecutorClaim {
            wallet_id,
            profile_id,
            signing_suite_id: SigningSuiteId::BITCOIN_BIP340_FROST_V1,
            backend_requirement: SignerBackendRequirement::FrostSecp256k1Tr,
            session_id: [5; 32],
            review_domain_digest: [7; 32],
            signing_message_digest: [2; 32],
            operation_binding_digest: [6; 32],
            claimed_at: NOW + 1,
        },
    )
}

#[test]
fn executor_claim_is_one_time_across_restart() {
    let (_root, path, claim) = fixture();
    let mut first = WalletStorage::open(&path).unwrap();
    first.claim_chain_executor(claim.clone()).unwrap();
    drop(first);

    let mut restarted = WalletStorage::open(&path).unwrap();
    assert!(matches!(
        restarted.claim_chain_executor(claim),
        Err(StorageError::SigningJobConflict)
    ));
}

#[test]
fn executor_claim_rejects_profile_epoch_or_operation_drift_before_insert() {
    let (_root, path, claim) = fixture();
    let mut storage = WalletStorage::open(&path).unwrap();

    let mut drifted = claim.clone();
    drifted.operation_binding_digest = [9; 32];
    assert!(matches!(
        storage.claim_chain_executor(drifted),
        Err(StorageError::SigningJobBindingDrift)
    ));

    storage.claim_chain_executor(claim).unwrap();
}

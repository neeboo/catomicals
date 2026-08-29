#![cfg(unix)]

use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::PathBuf,
    process::Command,
    sync::{Arc, Barrier},
};

use catomicals_cb_mpc_signer::{
    DurableSessionClaimStore, LEGACY_SESSION_CLAIM_LOG_FILE, MAX_RETAINED_SESSION_IDS,
    SESSION_CLAIM_LOG_FILE, SessionClaimError, SessionClaimNamespace,
};
use catomicals_signing_domain::{SignerBackendRequirement, SigningSuiteId};
use sha2::{Digest, Sha256};

const LOCK_CHILD_DIRECTORY: &str = "CATOMICALS_CLAIM_LOCK_CHILD_DIRECTORY";

fn private_tempdir() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let canonical_path = directory.path().canonicalize().unwrap();
    (directory, canonical_path)
}

fn session(sequence: u64) -> [u8; 32] {
    let mut session = [0_u8; 32];
    session[..8].copy_from_slice(&sequence.to_be_bytes());
    session[31] = 1;
    session
}

fn namespace(wallet: u8, profile: u8) -> SessionClaimNamespace {
    SessionClaimNamespace::new(
        [wallet; 16],
        [profile; 16],
        SigningSuiteId::BSV_ECDSA_CB_MPC_V1,
        SignerBackendRequirement::CbMpcThresholdEcdsa,
    )
    .unwrap()
}

#[test]
fn scoped_claims_survive_restart_and_allow_same_session_in_another_profile() {
    let (_root, root_path) = private_tempdir();
    let directory = root_path.join("claims");
    let store = DurableSessionClaimStore::open(&directory).unwrap();
    store.claim_scoped(&namespace(1, 2), session(77)).unwrap();
    store.claim_scoped(&namespace(1, 3), session(77)).unwrap();
    drop(store);

    let reopened = DurableSessionClaimStore::open(&directory).unwrap();
    assert_eq!(
        reopened.claim_scoped(&namespace(1, 2), session(77)),
        Err(SessionClaimError::AlreadyClaimed)
    );
    assert_eq!(
        reopened.claim_scoped(&namespace(1, 3), session(77)),
        Err(SessionClaimError::AlreadyClaimed)
    );
    reopened
        .claim_scoped(&namespace(2, 2), session(77))
        .unwrap();
}

#[test]
fn legacy_unscoped_claims_remain_a_fail_closed_global_blocklist() {
    const LEGACY_HEADER: &[u8; 32] = b"CATOMICALS-CBMPC-CLAIMS-V1\0\0\0\0\0\0";
    const LEGACY_RECORD_DOMAIN: &[u8] = b"catomicals.cb-mpc.session-claim.v1\0";

    let (_root, root_path) = private_tempdir();
    let directory = root_path.join("claims");
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let legacy_path = directory.join(LEGACY_SESSION_CLAIM_LOG_FILE);
    let legacy_session = session(91);
    let mut legacy_log = Vec::from(LEGACY_HEADER.as_slice());
    legacy_log.extend_from_slice(&legacy_session);
    let mut checksum = Sha256::new();
    checksum.update(LEGACY_RECORD_DOMAIN);
    checksum.update(legacy_session);
    legacy_log.extend_from_slice(&checksum.finalize());
    fs::write(&legacy_path, legacy_log).unwrap();
    fs::set_permissions(&legacy_path, fs::Permissions::from_mode(0o600)).unwrap();

    let store = DurableSessionClaimStore::open(&directory).unwrap();
    for identity in [namespace(1, 1), namespace(2, 2)] {
        assert_eq!(
            store.claim_scoped(&identity, legacy_session),
            Err(SessionClaimError::AlreadyClaimed)
        );
    }
    store.claim_scoped(&namespace(1, 1), session(92)).unwrap();
}

#[test]
fn claims_survive_restart_and_duplicate_claims_are_rejected() {
    let (_root, root_path) = private_tempdir();
    let directory = root_path.join("claims");
    let store = DurableSessionClaimStore::open(&directory).unwrap();
    let directory_metadata = fs::metadata(&directory).unwrap();
    let log_metadata = fs::metadata(directory.join(SESSION_CLAIM_LOG_FILE)).unwrap();
    assert_eq!(directory_metadata.permissions().mode() & 0o7777, 0o700);
    assert_eq!(log_metadata.permissions().mode() & 0o7777, 0o600);
    assert_eq!(
        directory_metadata.uid(),
        rustix::process::geteuid().as_raw()
    );
    assert_eq!(log_metadata.uid(), rustix::process::geteuid().as_raw());
    store.claim(session(1)).unwrap();
    drop(store);

    let reopened = DurableSessionClaimStore::open(&directory).unwrap();
    assert_eq!(
        reopened.claim(session(1)),
        Err(SessionClaimError::AlreadyClaimed)
    );
    reopened.claim(session(2)).unwrap();
}

#[test]
fn claims_are_serialized_across_threads_and_store_instances() {
    let (_root, root_path) = private_tempdir();
    let directory = root_path.join("claims");
    let store = Arc::new(DurableSessionClaimStore::open(&directory).unwrap());
    assert!(matches!(
        DurableSessionClaimStore::open(&directory),
        Err(SessionClaimError::StoreBusy)
    ));
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "durable_store_lock_is_held_across_processes_child",
            "--nocapture",
        ])
        .env(LOCK_CHILD_DIRECTORY, &directory)
        .status()
        .unwrap();
    assert!(child.success());

    let barrier = Arc::new(Barrier::new(17));
    let mut threads = Vec::new();
    for _ in 0..16 {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            store.claim(session(9))
        }));
    }
    barrier.wait();
    let results = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(SessionClaimError::AlreadyClaimed))
            .count(),
        15
    );
}

#[test]
fn durable_store_lock_is_held_across_processes_child() {
    let Some(directory) = std::env::var_os(LOCK_CHILD_DIRECTORY) else {
        return;
    };
    assert!(matches!(
        DurableSessionClaimStore::open(PathBuf::from(directory).as_path()),
        Err(SessionClaimError::StoreBusy)
    ));
}

#[test]
fn fixed_capacity_fails_closed_without_eviction() {
    let (_root, root_path) = private_tempdir();
    let directory = root_path.join("claims");
    let store = DurableSessionClaimStore::open(&directory).unwrap();
    for sequence in 0..MAX_RETAINED_SESSION_IDS {
        store.claim(session(sequence as u64)).unwrap();
    }
    assert_eq!(
        store.claim(session(MAX_RETAINED_SESSION_IDS as u64)),
        Err(SessionClaimError::StoreFull)
    );
    drop(store);

    let reopened = DurableSessionClaimStore::open(&directory).unwrap();
    assert_eq!(
        reopened.claim(session(0)),
        Err(SessionClaimError::AlreadyClaimed)
    );
    assert_eq!(
        reopened.claim(session((MAX_RETAINED_SESSION_IDS + 1) as u64)),
        Err(SessionClaimError::StoreFull)
    );
}

#[test]
fn truncated_corrupt_and_duplicate_logs_fail_closed() {
    for mutation in ["truncate", "corrupt", "duplicate"] {
        let (_root, root_path) = private_tempdir();
        let directory = root_path.join("claims");
        let store = DurableSessionClaimStore::open(&directory).unwrap();
        store.claim(session(1)).unwrap();
        drop(store);
        let log = directory.join(SESSION_CLAIM_LOG_FILE);
        let original = fs::read(&log).unwrap();
        match mutation {
            "truncate" => fs::write(&log, &original[..original.len() - 1]).unwrap(),
            "corrupt" => {
                let mut bytes = original;
                let last = bytes.len() - 1;
                bytes[last] ^= 1;
                fs::write(&log, bytes).unwrap();
            }
            "duplicate" => {
                let record = &original[original.len() - 64..];
                OpenOptions::new()
                    .append(true)
                    .open(&log)
                    .unwrap()
                    .write_all(record)
                    .unwrap();
            }
            _ => unreachable!(),
        }
        assert!(matches!(
            DurableSessionClaimStore::open(&directory),
            Err(SessionClaimError::CorruptStore)
        ));
    }
}

#[test]
fn symlinks_and_unsafe_permissions_are_rejected() {
    let (_root, root_path) = private_tempdir();
    let real = root_path.join("real");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
    let linked = root_path.join("linked");
    symlink(&real, &linked).unwrap();
    assert!(matches!(
        DurableSessionClaimStore::open(&linked),
        Err(SessionClaimError::UnsafePath)
    ));

    let unsafe_directory = root_path.join("unsafe-directory");
    fs::create_dir(&unsafe_directory).unwrap();
    fs::set_permissions(&unsafe_directory, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        DurableSessionClaimStore::open(&unsafe_directory),
        Err(SessionClaimError::UnsafePermissions)
    ));

    let file_link_directory = root_path.join("file-link");
    fs::create_dir(&file_link_directory).unwrap();
    fs::set_permissions(&file_link_directory, fs::Permissions::from_mode(0o700)).unwrap();
    let target = root_path.join("target");
    fs::write(&target, []).unwrap();
    symlink(&target, file_link_directory.join(SESSION_CLAIM_LOG_FILE)).unwrap();
    assert!(matches!(
        DurableSessionClaimStore::open(&file_link_directory),
        Err(SessionClaimError::UnsafePath)
    ));
}

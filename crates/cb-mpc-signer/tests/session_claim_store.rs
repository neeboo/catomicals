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
    DurableSessionClaimStore, MAX_RETAINED_SESSION_IDS, SESSION_CLAIM_LOG_FILE, SessionClaimError,
};

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

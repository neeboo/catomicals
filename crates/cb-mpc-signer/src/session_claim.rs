use std::{
    collections::HashSet,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path},
    sync::Mutex,
};

use rustix::{
    fs::{self, FlockOperation, Mode, OFlags},
    io::Errno,
};
use sha2::{Digest, Sha256};

use crate::MAX_RETAINED_SESSION_IDS;

pub const SESSION_CLAIM_LOG_FILE: &str = "session-claims.v1";

const HEADER: &[u8; 32] = b"CATOMICALS-CBMPC-CLAIMS-V1\0\0\0\0\0\0";
const RECORD_DOMAIN: &[u8] = b"catomicals.cb-mpc.session-claim.v1\0";
const RECORD_BYTES: usize = 64;
const PRIVATE_DIRECTORY_MODE: u16 = 0o700;
const PRIVATE_FILE_MODE: u16 = 0o600;

/// A durable, bounded claim log for cb-mpc session identifiers.
///
/// The store takes a process-wide advisory lock for its entire lifetime. A
/// session is appended and synchronized before signing starts; entries are
/// never removed or evicted. Corrupt stores fail closed and require an
/// operator to replace the store only after preserving the old replay set.
pub struct DurableSessionClaimStore {
    state: Mutex<ClaimState>,
}

struct ClaimState {
    file: File,
    claimed: HashSet<[u8; 32]>,
    failed_closed: bool,
}

impl DurableSessionClaimStore {
    pub fn open(directory: &Path) -> Result<Self, SessionClaimError> {
        let directory_fd = open_private_directory(directory)?;
        let descriptor = fs::openat(
            &directory_fd,
            SESSION_CLAIM_LOG_FILE,
            OFlags::RDWR | OFlags::APPEND | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(PRIVATE_FILE_MODE),
        )
        .map_err(map_path_error)?;
        validate_private_file(&descriptor)?;
        fs::flock(&descriptor, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            match error {
                Errno::AGAIN => SessionClaimError::StoreBusy,
                _ => SessionClaimError::Io,
            }
        })?;

        let mut file = File::from(descriptor);
        let claimed = load_or_initialize(&mut file, &directory_fd)?;
        Ok(Self {
            state: Mutex::new(ClaimState {
                file,
                claimed,
                failed_closed: false,
            }),
        })
    }

    /// Atomically consumes one session identifier for all future attempts.
    pub fn claim(&self, session_id: [u8; 32]) -> Result<(), SessionClaimError> {
        if session_id == [0; 32] {
            return Err(SessionClaimError::InvalidSession);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| SessionClaimError::FailedClosed)?;
        if state.failed_closed {
            return Err(SessionClaimError::FailedClosed);
        }
        if state.claimed.contains(&session_id) {
            return Err(SessionClaimError::AlreadyClaimed);
        }
        if state.claimed.len() >= MAX_RETAINED_SESSION_IDS {
            return Err(SessionClaimError::StoreFull);
        }

        let record = encode_record(session_id);
        if state
            .file
            .write_all(&record)
            .and_then(|()| state.file.sync_all())
            .is_err()
        {
            state.failed_closed = true;
            return Err(SessionClaimError::FailedClosed);
        }
        state.claimed.insert(session_id);
        Ok(())
    }
}

impl std::fmt::Debug for DurableSessionClaimStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableSessionClaimStore")
            .field("contents", &"REDACTED")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SessionClaimError {
    #[error("session identifier has already been claimed")]
    AlreadyClaimed,
    #[error("session claim store is at its fixed capacity")]
    StoreFull,
    #[error("session claim store is locked by another process")]
    StoreBusy,
    #[error("session claim store is corrupt")]
    CorruptStore,
    #[error("session claim path is unsafe")]
    UnsafePath,
    #[error("session claim path has unsafe ownership or permissions")]
    UnsafePermissions,
    #[error("session identifier is invalid")]
    InvalidSession,
    #[error("session claim store failed closed")]
    FailedClosed,
    #[error("session claim store I/O failed")]
    Io,
}

fn open_private_directory(path: &Path) -> Result<std::os::fd::OwnedFd, SessionClaimError> {
    if !path.is_absolute() {
        return Err(SessionClaimError::UnsafePath);
    }
    let components = path.components().collect::<Vec<_>>();
    if components.len() < 2
        || !matches!(components.first(), Some(Component::RootDir))
        || components
            .iter()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(SessionClaimError::UnsafePath);
    }

    let mut current = fs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| SessionClaimError::Io)?;
    for (index, component) in components.iter().enumerate().skip(1) {
        let Component::Normal(name) = component else {
            return Err(SessionClaimError::UnsafePath);
        };
        let is_final = index + 1 == components.len();
        if is_final {
            match fs::mkdirat(&current, *name, Mode::from_raw_mode(PRIVATE_DIRECTORY_MODE)) {
                Ok(()) => fs::fsync(&current).map_err(|_| SessionClaimError::Io)?,
                Err(Errno::EXIST) => {}
                Err(error) => return Err(map_path_error(error)),
            }
        }
        current = fs::openat(
            &current,
            *name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(map_path_error)?;
    }
    validate_private_directory(&current)?;
    Ok(current)
}

fn validate_private_directory(descriptor: &std::os::fd::OwnedFd) -> Result<(), SessionClaimError> {
    let stat = fs::fstat(descriptor).map_err(|_| SessionClaimError::Io)?;
    if fs::FileType::from_raw_mode(stat.st_mode) != fs::FileType::Directory {
        return Err(SessionClaimError::UnsafePath);
    }
    if fs::Mode::from_raw_mode(stat.st_mode).bits() != PRIVATE_DIRECTORY_MODE
        || stat.st_uid != rustix::process::geteuid().as_raw()
    {
        return Err(SessionClaimError::UnsafePermissions);
    }
    Ok(())
}

fn validate_private_file(descriptor: &std::os::fd::OwnedFd) -> Result<(), SessionClaimError> {
    let stat = fs::fstat(descriptor).map_err(|_| SessionClaimError::Io)?;
    if fs::FileType::from_raw_mode(stat.st_mode) != fs::FileType::RegularFile || stat.st_nlink != 1
    {
        return Err(SessionClaimError::UnsafePath);
    }
    if fs::Mode::from_raw_mode(stat.st_mode).bits() != PRIVATE_FILE_MODE
        || stat.st_uid != rustix::process::geteuid().as_raw()
    {
        return Err(SessionClaimError::UnsafePermissions);
    }
    Ok(())
}

fn load_or_initialize(
    file: &mut File,
    directory_fd: &std::os::fd::OwnedFd,
) -> Result<HashSet<[u8; 32]>, SessionClaimError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| SessionClaimError::Io)?;
    let mut contents = Vec::new();
    file.take((HEADER.len() + RECORD_BYTES * MAX_RETAINED_SESSION_IDS + 1) as u64)
        .read_to_end(&mut contents)
        .map_err(|_| SessionClaimError::Io)?;
    if contents.is_empty() {
        file.write_all(HEADER).map_err(|_| SessionClaimError::Io)?;
        file.sync_all().map_err(|_| SessionClaimError::Io)?;
        fs::fsync(directory_fd).map_err(|_| SessionClaimError::Io)?;
        return Ok(HashSet::new());
    }
    if contents.len() < HEADER.len()
        || &contents[..HEADER.len()] != HEADER
        || !(contents.len() - HEADER.len()).is_multiple_of(RECORD_BYTES)
        || contents.len() > HEADER.len() + RECORD_BYTES * MAX_RETAINED_SESSION_IDS
    {
        return Err(SessionClaimError::CorruptStore);
    }

    let mut claimed = HashSet::new();
    for record in contents[HEADER.len()..].chunks_exact(RECORD_BYTES) {
        let session_id: [u8; 32] = record[..32]
            .try_into()
            .map_err(|_| SessionClaimError::CorruptStore)?;
        if session_id == [0; 32]
            || record[32..] != record_checksum(session_id)
            || !claimed.insert(session_id)
        {
            return Err(SessionClaimError::CorruptStore);
        }
    }
    Ok(claimed)
}

fn encode_record(session_id: [u8; 32]) -> [u8; RECORD_BYTES] {
    let mut record = [0; RECORD_BYTES];
    record[..32].copy_from_slice(&session_id);
    record[32..].copy_from_slice(&record_checksum(session_id));
    record
}

fn record_checksum(session_id: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RECORD_DOMAIN);
    hasher.update(session_id);
    hasher.finalize().into()
}

fn map_path_error(error: Errno) -> SessionClaimError {
    match error {
        Errno::LOOP | Errno::NOTDIR => SessionClaimError::UnsafePath,
        _ => SessionClaimError::Io,
    }
}

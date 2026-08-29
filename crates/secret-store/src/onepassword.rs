use std::{
    env,
    ffi::OsString,
    fmt, fs,
    io::{self, Read},
    path::PathBuf,
    process::{Command, Stdio},
    sync::mpsc::{self, TryRecvError},
    thread,
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use thiserror::Error;
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::process::CommandExt as _;

use crate::SecretValue;

pub const ONEPASSWORD_MAX_STDOUT_BYTES: usize = 64 * 1024;

const CHILD_ENV_ALLOWLIST: &[&str] = &[
    "HOME",
    "USER",
    "LOGNAME",
    "TMPDIR",
    "XDG_CONFIG_HOME",
    "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "LANG",
    "LC_ALL",
];

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum OnePasswordLoadError {
    #[error("the 1Password executable configuration is invalid")]
    InvalidExecutable,
    #[error("the 1Password secret reference is invalid")]
    InvalidReference,
    #[error("the 1Password command timeout is invalid")]
    InvalidTimeout,
    #[error("non-interactive 1Password token environments are forbidden")]
    TokenEnvironmentForbidden,
    #[error("the 1Password command could not be started")]
    StartFailed,
    #[error("the 1Password command timed out")]
    TimedOut,
    #[error("the 1Password command returned too much data")]
    OutputTooLarge,
    #[error("the 1Password command failed")]
    CommandFailed,
    #[error("the 1Password command output is invalid")]
    MalformedPayload,
    #[error("the 1Password command pipe failed")]
    PipeFailed,
}

pub type OnePasswordResult<T> = Result<T, OnePasswordLoadError>;

/// Loads a device-wrapped package from an interactive 1Password desktop
/// session. This is deliberately a read-only loader, not a [`crate::SecretBackend`]:
/// it cannot create, replace, or delete vault items.
///
/// The referenced field contains standard-base64 encoded wrapped bytes. The
/// bytes still require the signer's computer-bound unwrap key before they can
/// become a participant package.
pub struct OnePasswordWrappedPackageLoader {
    executable: PathBuf,
    reference: String,
    timeout: Duration,
}

impl OnePasswordWrappedPackageLoader {
    pub fn new(
        executable: PathBuf,
        reference: impl Into<String>,
        timeout: Duration,
    ) -> OnePasswordResult<Self> {
        let executable = canonical_executable(executable)?;
        let reference = reference.into();
        if !valid_secret_reference(&reference) {
            return Err(OnePasswordLoadError::InvalidReference);
        }
        if timeout.is_zero() {
            return Err(OnePasswordLoadError::InvalidTimeout);
        }
        Ok(Self {
            executable,
            reference,
            timeout,
        })
    }

    pub fn load(&self) -> OnePasswordResult<SecretValue> {
        reject_token_environment()?;

        let inherited_environment = allowed_environment();
        let mut command = Command::new(&self.executable);
        command
            .arg("read")
            .arg(&self.reference)
            .env_clear()
            .envs(inherited_environment)
            .env("OP_BIOMETRIC_UNLOCK_ENABLED", "true")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        command.process_group(0);

        let mut child = command
            .spawn()
            .map_err(|_| OnePasswordLoadError::StartFailed)?;
        let stdout = child
            .stdout
            .take()
            .ok_or(OnePasswordLoadError::PipeFailed)?;
        let stderr = child
            .stderr
            .take()
            .ok_or(OnePasswordLoadError::PipeFailed)?;

        let (stdout_sender, stdout_receiver) = mpsc::sync_channel(1);
        let stdout_thread = thread::spawn(move || {
            let result = read_bounded(stdout);
            match result {
                StdoutResult::TooLarge => {
                    let _ = stdout_sender.send(StdoutSignal::TooLarge);
                }
                StdoutResult::Failed => {
                    let _ = stdout_sender.send(StdoutSignal::Failed);
                }
                StdoutResult::Complete(_) => {}
            }
            result
        });
        let stderr_thread = thread::spawn(move || {
            let mut stderr = stderr;
            let _ = io::copy(&mut stderr, &mut io::sink());
        });

        let started = Instant::now();
        loop {
            match stdout_receiver.try_recv() {
                Ok(StdoutSignal::TooLarge) => {
                    terminate(&mut child);
                    let _ = stdout_thread.join();
                    drop(stderr_thread);
                    return Err(OnePasswordLoadError::OutputTooLarge);
                }
                Ok(StdoutSignal::Failed) => {
                    terminate(&mut child);
                    let _ = stdout_thread.join();
                    drop(stderr_thread);
                    return Err(OnePasswordLoadError::PipeFailed);
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => {}
            }

            match child.try_wait() {
                Ok(Some(status)) => {
                    let bytes = match stdout_thread
                        .join()
                        .map_err(|_| OnePasswordLoadError::PipeFailed)?
                    {
                        StdoutResult::Complete(bytes) => bytes,
                        StdoutResult::TooLarge => {
                            drop(stderr_thread);
                            return Err(OnePasswordLoadError::OutputTooLarge);
                        }
                        StdoutResult::Failed => {
                            drop(stderr_thread);
                            return Err(OnePasswordLoadError::PipeFailed);
                        }
                    };
                    let _ = stderr_thread.join();
                    if !status.success() {
                        return Err(OnePasswordLoadError::CommandFailed);
                    }
                    return decode_wrapped_package(bytes);
                }
                Ok(None) => {}
                Err(_) => {
                    terminate(&mut child);
                    drop(stdout_thread);
                    drop(stderr_thread);
                    return Err(OnePasswordLoadError::CommandFailed);
                }
            }

            if started.elapsed() >= self.timeout {
                terminate(&mut child);
                drop(stdout_thread);
                drop(stderr_thread);
                return Err(OnePasswordLoadError::TimedOut);
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}

impl fmt::Debug for OnePasswordWrappedPackageLoader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OnePasswordWrappedPackageLoader")
            .field("executable", &"[REDACTED]")
            .field("reference", &"[REDACTED]")
            .field("timeout", &self.timeout)
            .finish()
    }
}

enum StdoutResult {
    Complete(Zeroizing<Vec<u8>>),
    TooLarge,
    Failed,
}

enum StdoutSignal {
    TooLarge,
    Failed,
}

fn read_bounded(stdout: impl Read) -> StdoutResult {
    let mut bytes = Zeroizing::new(Vec::with_capacity(ONEPASSWORD_MAX_STDOUT_BYTES));
    let mut bounded = stdout.take((ONEPASSWORD_MAX_STDOUT_BYTES + 1) as u64);
    if bounded.read_to_end(&mut bytes).is_err() {
        return StdoutResult::Failed;
    }
    if bytes.len() > ONEPASSWORD_MAX_STDOUT_BYTES {
        return StdoutResult::TooLarge;
    }
    StdoutResult::Complete(bytes)
}

fn decode_wrapped_package(mut encoded: Zeroizing<Vec<u8>>) -> OnePasswordResult<SecretValue> {
    while encoded.last().is_some_and(u8::is_ascii_whitespace) {
        encoded.pop();
    }
    let first_non_whitespace = encoded
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .ok_or(OnePasswordLoadError::MalformedPayload)?;
    if first_non_whitespace > 0 {
        encoded.drain(..first_non_whitespace);
    }
    if encoded.iter().any(u8::is_ascii_whitespace) {
        return Err(OnePasswordLoadError::MalformedPayload);
    }
    let mut decoded = Zeroizing::new(Vec::with_capacity(
        encoded.len().saturating_mul(3).saturating_div(4) + 3,
    ));
    STANDARD
        .decode_vec(encoded.as_slice(), &mut decoded)
        .map_err(|_| OnePasswordLoadError::MalformedPayload)?;
    if decoded.is_empty() {
        return Err(OnePasswordLoadError::MalformedPayload);
    }
    Ok(SecretValue::new(std::mem::take(&mut *decoded)))
}

fn canonical_executable(path: PathBuf) -> OnePasswordResult<PathBuf> {
    if !path.is_absolute() {
        return Err(OnePasswordLoadError::InvalidExecutable);
    }
    let path = fs::canonicalize(path).map_err(|_| OnePasswordLoadError::InvalidExecutable)?;
    let metadata = fs::metadata(&path).map_err(|_| OnePasswordLoadError::InvalidExecutable)?;
    if !metadata.is_file()
        || !matches!(
            path.file_name().and_then(|name| name.to_str()),
            Some("op" | "op.exe")
        )
    {
        return Err(OnePasswordLoadError::InvalidExecutable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(OnePasswordLoadError::InvalidExecutable);
        }
    }
    Ok(path)
}

fn valid_secret_reference(reference: &str) -> bool {
    if reference.len() > 2_048 || !reference.is_ascii() {
        return false;
    }
    let Some(path) = reference.strip_prefix("op://") else {
        return false;
    };
    let segments = path.split('/').collect::<Vec<_>>();
    if !(3..=4).contains(&segments.len()) {
        return false;
    }
    segments.into_iter().all(valid_reference_segment)
}

fn valid_reference_segment(segment: &str) -> bool {
    if segment.is_empty() {
        return false;
    }
    let bytes = segment.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
            index += 1;
            continue;
        }
        if byte == b'%'
            && index + 2 < bytes.len()
            && bytes[index + 1].is_ascii_hexdigit()
            && bytes[index + 2].is_ascii_hexdigit()
        {
            index += 3;
            continue;
        }
        return false;
    }
    true
}

fn reject_token_environment() -> OnePasswordResult<()> {
    let forbidden = env::vars_os().any(|(key, _)| {
        let key = key.to_string_lossy();
        key == "OP_SERVICE_ACCOUNT_TOKEN"
            || key == "OP_CONNECT_TOKEN"
            || key.starts_with("OP_SESSION_")
    });
    if forbidden {
        return Err(OnePasswordLoadError::TokenEnvironmentForbidden);
    }
    Ok(())
}

fn allowed_environment() -> Vec<(OsString, OsString)> {
    CHILD_ENV_ALLOWLIST
        .iter()
        .filter_map(|key| env::var_os(key).map(|value| (OsString::from(key), value)))
        .collect()
}

fn terminate(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        use rustix::process::{Pid, Signal, kill_process_group};

        if let Some(pid) = Pid::from_raw(child.id() as i32) {
            let _ = kill_process_group(pid, Signal::KILL);
        }
    }
    #[cfg(not(unix))]
    let _ = child.kill();
    let _ = child.wait();
}

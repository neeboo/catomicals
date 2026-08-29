#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

use catomicals_secret_store::{OnePasswordLoadError, OnePasswordWrappedPackageLoader};
use tempfile::TempDir;

const REFERENCE: &str = "op://vault/item/wrapped-package";
const FIXTURE_SECRET: &str = "wrapped-participant-package-fixture-secret";

fn fake_op(directory: &Path, body: &str) -> PathBuf {
    let path = directory.join("op");
    fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write fake op executable");
    let mut permissions = fs::metadata(&path).expect("fake op metadata").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).expect("make fake op executable");
    path
}

fn loader(executable: PathBuf, timeout: Duration) -> OnePasswordWrappedPackageLoader {
    OnePasswordWrappedPackageLoader::new(executable, REFERENCE, timeout)
        .expect("valid loader configuration")
}

fn assert_redacted(error: &OnePasswordLoadError) {
    let display = error.to_string();
    let debug = format!("{error:?}");
    assert!(!display.contains(FIXTURE_SECRET), "Display leaked secret");
    assert!(!debug.contains(FIXTURE_SECRET), "Debug leaked secret");
}

#[test]
fn restricted_onepassword_loader_contract() {
    let temporary = TempDir::new().expect("temporary directory");

    unsafe { std::env::set_var("CATOMICALS_TEST_SECRET", FIXTURE_SECRET) };
    let success = fake_op(
        temporary.path(),
        "[ \"$1\" = read ] && [ \"$2\" = 'op://vault/item/wrapped-package' ] || exit 9\n[ \"$OP_BIOMETRIC_UNLOCK_ENABLED\" = true ] || exit 10\n[ -z \"$CATOMICALS_TEST_SECRET\" ] || exit 11\nprintf 'd3JhcHBlZC1wYWNrYWdl'",
    );
    let loaded = loader(success, Duration::from_secs(3))
        .load()
        .expect("load wrapped package");
    unsafe { std::env::remove_var("CATOMICALS_TEST_SECRET") };
    assert_eq!(loaded.expose(), b"wrapped-package");
    assert_eq!(format!("{loaded:?}"), "SecretValue([REDACTED])");

    let malformed = fake_op(temporary.path(), "printf 'not-base64!' ");
    let error = loader(malformed, Duration::from_secs(3))
        .load()
        .expect_err("reject malformed wrapped package");
    assert_eq!(error, OnePasswordLoadError::MalformedPayload);
    assert_redacted(&error);

    let partial_decode_payload = format!("{}!", "QUJD".repeat(2_048));
    let partial_decode = fake_op(
        temporary.path(),
        &format!("printf '{partial_decode_payload}'"),
    );
    let error = loader(partial_decode, Duration::from_secs(3))
        .load()
        .expect_err("reject invalid tail after a long valid base64 prefix");
    assert_eq!(error, OnePasswordLoadError::MalformedPayload);
    assert_redacted(&error);

    let non_zero = fake_op(
        temporary.path(),
        &format!("printf '{FIXTURE_SECRET}' >&2\nexit 23"),
    );
    let error = loader(non_zero, Duration::from_secs(3))
        .load()
        .expect_err("reject failed op command");
    assert_eq!(error, OnePasswordLoadError::CommandFailed);
    assert_redacted(&error);

    let oversized = fake_op(
        temporary.path(),
        "i=0\nwhile [ $i -lt 66000 ]; do printf A; i=$((i + 1)); done",
    );
    let error = loader(oversized, Duration::from_secs(2))
        .load()
        .expect_err("reject oversized stdout");
    assert_eq!(error, OnePasswordLoadError::OutputTooLarge);
    assert_redacted(&error);

    let slow = fake_op(temporary.path(), "sleep 3\nprintf 'd3JhcHBlZC1wYWNrYWdl'");
    let error = loader(slow, Duration::from_millis(40))
        .load()
        .expect_err("time out slow op command");
    assert_eq!(error, OnePasswordLoadError::TimedOut);
    assert_redacted(&error);

    let relative = OnePasswordWrappedPackageLoader::new(
        PathBuf::from("op"),
        REFERENCE,
        Duration::from_secs(3),
    )
    .expect_err("reject relative executable");
    assert_eq!(relative, OnePasswordLoadError::InvalidExecutable);

    let invalid_reference = OnePasswordWrappedPackageLoader::new(
        temporary.path().join("op"),
        "op://vault//field",
        Duration::from_secs(3),
    )
    .expect_err("reject invalid reference");
    assert_eq!(invalid_reference, OnePasswordLoadError::InvalidReference);

    // This test is intentionally one serial contract so the process-wide
    // environment mutation cannot race another loader test in this binary.
    unsafe { std::env::set_var("OP_SERVICE_ACCOUNT_TOKEN", FIXTURE_SECRET) };
    let token_error = loader(temporary.path().join("op"), Duration::from_secs(3))
        .load()
        .expect_err("reject service account environment");
    unsafe { std::env::remove_var("OP_SERVICE_ACCOUNT_TOKEN") };
    assert_eq!(token_error, OnePasswordLoadError::TokenEnvironmentForbidden);
    assert_redacted(&token_error);

    unsafe { std::env::set_var("OP_CONNECT_TOKEN", FIXTURE_SECRET) };
    let connect_error = loader(temporary.path().join("op"), Duration::from_secs(3))
        .load()
        .expect_err("reject Connect token environment");
    unsafe { std::env::remove_var("OP_CONNECT_TOKEN") };
    assert_eq!(
        connect_error,
        OnePasswordLoadError::TokenEnvironmentForbidden
    );
    assert_redacted(&connect_error);

    unsafe { std::env::set_var("OP_SESSION_personal", FIXTURE_SECRET) };
    let session_error = loader(temporary.path().join("op"), Duration::from_secs(3))
        .load()
        .expect_err("reject session token environment");
    unsafe { std::env::remove_var("OP_SESSION_personal") };
    assert_eq!(
        session_error,
        OnePasswordLoadError::TokenEnvironmentForbidden
    );
    assert_redacted(&session_error);
}

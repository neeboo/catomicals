#![cfg(unix)]

use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::net::UnixStream,
    os::{fd::AsRawFd as _, unix::fs::OpenOptionsExt as _},
    path::{Path, PathBuf},
    process::{Command, Output},
};

use catomicals_signer_recovery::RecoveryBundle;
use catomicals_threshold::{PersonalSignerProfile, run_local_dkg};
use rustix::io::{FdFlags, fcntl_setfd};
use tempfile::tempdir;
use uuid::Uuid;

#[test]
fn personal_commands_are_exposed_under_wallet_signer() {
    let output = cli()
        .args(["wallet", "signer", "personal", "--help"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("bootstrap"));
    assert!(stdout.contains("verify-recovery"));
}

#[test]
fn verify_recovery_reads_key_only_from_inherited_pipe_and_prints_public_identity() {
    let fixture = recovery_fixture();
    let output = verify(&fixture.profile, &fixture.bundle, fixture.key);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["participant_id"], 3);
    assert_eq!(summary["profile_id"], fixture.profile_id.to_string());
    assert_eq!(summary["wallet_id"], fixture.wallet_id.to_string());
    assert_eq!(summary["signer_set_id"], fixture.signer_set_id.to_string());
    assert_eq!(summary["signer_epoch"], 7);
    assert_eq!(summary["status"], "verified");
    let all_output = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!all_output.contains(&hex::encode(fixture.key)));
    assert!(!all_output.contains("key_package"));
    assert!(!all_output.contains("signing_share"));
}

#[test]
fn verify_recovery_rejects_wrong_key_and_regular_file_descriptor() {
    let fixture = recovery_fixture();
    let wrong_key = verify(&fixture.profile, &fixture.bundle, [0x99; 32]);
    assert!(!wrong_key.status.success());
    assert!(String::from_utf8_lossy(&wrong_key.stderr).contains("authentication failed"));

    let key_file = fixture.root.join("key.bin");
    private_write(&key_file, &fixture.key);
    let file = fs::File::open(&key_file).unwrap();
    fcntl_setfd(&file, FdFlags::empty()).unwrap();
    let output = cli()
        .args([
            "wallet",
            "signer",
            "personal",
            "verify-recovery",
            "--profile",
            path(&fixture.profile),
            "--bundle",
            path(&fixture.bundle),
            "--recovery-key-fd",
            &file.as_raw_fd().to_string(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("pipe or socket"));
}

#[test]
fn verify_recovery_rejects_truncated_or_oversized_key_material() {
    let fixture = recovery_fixture();
    for key in [vec![0x34; 31], vec![0x34; 33]] {
        let output = verify_bytes(&fixture.profile, &fixture.bundle, &key);
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("exactly 32 bytes"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn verify_recovery_rejects_public_permissions_and_symlink_inputs() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let fixture = recovery_fixture();
    fs::set_permissions(&fixture.profile, fs::Permissions::from_mode(0o644)).unwrap();
    let public = verify(&fixture.profile, &fixture.bundle, fixture.key);
    assert!(!public.status.success());
    assert!(String::from_utf8_lossy(&public.stderr).contains("mode 0600"));

    fs::set_permissions(&fixture.profile, fs::Permissions::from_mode(0o600)).unwrap();
    let linked = fixture.root.join("linked-profile.json");
    symlink(&fixture.profile, &linked).unwrap();
    let linked_input = verify(&linked, &fixture.bundle, fixture.key);
    assert!(!linked_input.status.success());
    assert!(String::from_utf8_lossy(&linked_input.stderr).contains("personal signer profile"));
}

#[test]
fn verify_recovery_rejects_a_profile_from_another_signer_set() {
    let fixture = recovery_fixture();
    let mut other = PersonalSignerProfile::bootstrap(
        Uuid::new_v4(),
        fixture.wallet_id,
        Uuid::new_v4(),
        7,
        run_local_dkg(3, 2).unwrap(),
    )
    .unwrap();
    other.secret_packages.clear();
    private_write(
        &fixture.root.join("other-profile.json"),
        &other.profile.to_bytes().unwrap(),
    );
    let output = verify(
        &fixture.root.join("other-profile.json"),
        &fixture.bundle,
        fixture.key,
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("does not match"));
}

#[cfg(target_os = "macos")]
#[test]
fn bootstrap_rejects_a_regular_recovery_key_descriptor_before_touching_signer_state() {
    let directory = tempdir().unwrap();
    let data_dir = directory.path().join("wallet");
    let output_dir = directory.path().join("provisioning");
    let key_file = directory.path().join("key.bin");
    private_write(&key_file, b"");
    let file = OpenOptions::new().write(true).open(&key_file).unwrap();
    fcntl_setfd(&file, FdFlags::empty()).unwrap();
    let output = cli()
        .args([
            "wallet",
            "signer",
            "personal",
            "bootstrap",
            "--data-dir",
            path(&data_dir),
            "--output-dir",
            path(&output_dir),
            "--recovery-key-fd",
            &file.as_raw_fd().to_string(),
            "--device-key-id",
            "catomicals.test.must-not-be-created",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("pipe or socket"));
    assert!(!output_dir.exists());
    assert!(!data_dir.join("signer.json").exists());
}

#[cfg(target_os = "macos")]
#[test]
fn bootstrap_never_overwrites_an_existing_signer() {
    let directory = tempdir().unwrap();
    let data_dir = directory.path().join("wallet");
    fs::create_dir(&data_dir).unwrap();
    let manifest = data_dir.join("signer.json");
    private_write(&manifest, b"existing-signer-marker");
    let output_dir = directory.path().join("provisioning");
    let (sink, _reader) = UnixStream::pair().unwrap();
    fcntl_setfd(&sink, FdFlags::empty()).unwrap();
    let output = cli()
        .args([
            "wallet",
            "signer",
            "personal",
            "bootstrap",
            "--data-dir",
            path(&data_dir),
            "--output-dir",
            path(&output_dir),
            "--recovery-key-fd",
            &sink.as_raw_fd().to_string(),
            "--device-key-id",
            "catomicals.test.must-not-be-created-existing",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("already initialized"));
    assert_eq!(fs::read(&manifest).unwrap(), b"existing-signer-marker");
    assert!(!output_dir.exists());
}

struct RecoveryFixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    profile: PathBuf,
    bundle: PathBuf,
    key: [u8; 32],
    profile_id: Uuid,
    wallet_id: Uuid,
    signer_set_id: Uuid,
}

fn recovery_fixture() -> RecoveryFixture {
    let directory = tempdir().unwrap();
    let root = directory.path().to_path_buf();
    let profile_path = root.join("profile.json");
    let bundle_path = root.join("participant-3.recovery");
    let profile_id = Uuid::from_bytes([0x31; 16]);
    let wallet_id = Uuid::from_bytes([0x32; 16]);
    let signer_set_id = Uuid::from_bytes([0x33; 16]);
    let mut bootstrap = PersonalSignerProfile::bootstrap(
        profile_id,
        wallet_id,
        signer_set_id,
        7,
        run_local_dkg(3, 2).unwrap(),
    )
    .unwrap();
    let profile = bootstrap.profile;
    let (bundle, recovery_key) =
        RecoveryBundle::seal(bootstrap.secret_packages.remove(&3).unwrap(), &profile).unwrap();
    let key = *recovery_key.to_bytes();
    private_write(&profile_path, &profile.to_bytes().unwrap());
    private_write(&bundle_path, &bundle.to_bytes().unwrap());
    RecoveryFixture {
        _directory: directory,
        root,
        profile: profile_path,
        bundle: bundle_path,
        key,
        profile_id,
        wallet_id,
        signer_set_id,
    }
}

fn verify(profile: &Path, bundle: &Path, key: [u8; 32]) -> Output {
    verify_bytes(profile, bundle, &key)
}

fn verify_bytes(profile: &Path, bundle: &Path, key: &[u8]) -> Output {
    let (reader, mut writer) = UnixStream::pair().unwrap();
    fcntl_setfd(&reader, FdFlags::empty()).unwrap();
    writer.write_all(key).unwrap();
    drop(writer);
    cli()
        .args([
            "wallet",
            "signer",
            "personal",
            "verify-recovery",
            "--profile",
            path(profile),
            "--bundle",
            path(bundle),
            "--recovery-key-fd",
            &reader.as_raw_fd().to_string(),
        ])
        .output()
        .unwrap()
}

fn private_write(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_catomicals"))
}

fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}

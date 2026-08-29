//! `wallet ...` — provider-neutral wallet primitives from the CLI.
//!
//! Everything here uses the same `WalletApi` surface the HTTP server and the
//! frontend use, so human UI, Codex and DeepSeek adapters achieve identical
//! outcomes (see `docs/adapters.md`).

use std::{path::PathBuf, str::FromStr};

use anyhow::{Context, bail};
use catomicals_wallet::{
    ApprovalChallenge, ApprovalState, CreateIntentRequest, SigningIntent, WalletApi, WalletError,
    WalletStore,
};
use clap::{Args, Subcommand};
use uuid::Uuid;

use crate::{NodeArgs, wallet_serve};

#[derive(Subcommand)]
pub enum WalletCommand {
    /// Show wallet status (node, threshold, signers, pending approvals).
    Status(StatusArgs),
    /// Localhost-only HTTP server for the wallet API (frontend/agent surface).
    Serve(ServeArgs),
    Intent {
        #[command(subcommand)]
        cmd: IntentCommand,
    },
    Approval {
        #[command(subcommand)]
        cmd: ApprovalCommand,
    },
    /// Initialize or inspect the durable signer without exposing key material.
    Signer {
        #[command(subcommand)]
        cmd: SignerCommand,
    },
    /// Explain how production Passkey approval must be configured.
    Approve(ApproveArgs),
    /// Explain why mock Passkey authorization is disabled.
    Demo(DemoArgs),
}

#[derive(Args)]
pub struct StatusArgs {
    #[command(flatten)]
    pub node: NodeArgs,
    /// How many pending approvals to show.
    #[arg(long, default_value_t = 10)]
    pub limit: usize,
}

#[derive(Args)]
pub struct ServeArgs {
    /// Bind address. Non-loopback requires an explicit deployment opt-in.
    #[arg(long, default_value = "127.0.0.1:18787")]
    pub addr: String,
    /// Allowed CORS origin (frontend dev server).
    #[arg(long, default_value = "http://localhost:5173")]
    pub cors_origin: String,
    /// WebAuthn relying-party identifier. It cannot change after enrollment.
    #[arg(long, default_value = "localhost")]
    pub rp_id: String,
    /// Exact browser origin; remote deployments must use HTTPS.
    #[arg(long, default_value = "http://localhost:5173")]
    pub rp_origin: String,
    /// Human-readable relying-party name shown by authenticators.
    #[arg(long, default_value = "Catomicals local wallet")]
    pub rp_name: String,
    /// Lifetime of server-side WebAuthn ceremony state.
    #[arg(long, default_value_t = 300)]
    pub ceremony_ttl_seconds: i64,
    /// Local FROST participant ID. Durable mode binds this id permanently to
    /// the encrypted signer manifest on first initialization.
    #[arg(long, default_value_t = 1)]
    pub signer_id: u16,
    /// Permit a public bind behind an operator-managed HTTPS reverse proxy.
    #[arg(long)]
    pub allow_non_loopback_bind: bool,
    /// Enable durable authority state in this directory. Omit for the
    /// process-memory compatibility server.
    #[arg(long, value_name = "DIR")]
    pub data_dir: Option<std::path::PathBuf>,
    /// Explicitly use the encrypted local file backend for a self-hosted
    /// development wallet. Production startup otherwise fails closed until a
    /// reviewed OS keychain, HSM, or remote secret backend is injected.
    #[arg(long)]
    pub allow_self_hosted_development_secrets: bool,
    /// Wallet id used only when initializing a new durable data directory.
    #[arg(long, default_value = "00000000-0000-0000-0000-000000000001")]
    pub wallet_id: String,
    #[command(flatten)]
    pub node: NodeArgs,
}

#[derive(Subcommand)]
pub enum IntentCommand {
    New(NewIntentArgs),
    List,
    Show(IntentIdArg),
    Cancel(IntentIdArg),
}

#[derive(Subcommand)]
pub enum ApprovalCommand {
    /// Issue the approval challenge (the exact intent digest).
    Challenge(IntentIdArg),
    /// Read approval state for an intent.
    State(IntentIdArg),
}

#[derive(Subcommand)]
pub enum SignerCommand {
    /// Initialize the encrypted local signer once, or verify an existing one.
    Init(SignerInitArgs),
    /// Print the versioned public signer audit list. This never opens the key package.
    Audit(SignerAuditArgs),
    /// Provision or verify the personal 2-of-3 signer set.
    Personal {
        #[command(subcommand)]
        cmd: PersonalSignerCommand,
    },
}

#[derive(Subcommand)]
pub enum PersonalSignerCommand {
    /// Create one 2-of-3 profile and three independently protected participant shares.
    Bootstrap(PersonalBootstrapArgs),
    /// Authenticate and validate the offline participant-3 recovery package.
    VerifyRecovery(VerifyRecoveryArgs),
}

#[derive(Args)]
pub struct PersonalBootstrapArgs {
    /// Durable wallet directory where participant 1 will be installed.
    #[arg(long, value_name = "DIR")]
    data_dir: PathBuf,
    /// New private directory that receives only the public profile and encrypted packages.
    #[arg(long, value_name = "DIR")]
    output_dir: PathBuf,
    #[arg(long, default_value = "00000000-0000-0000-0000-000000000001")]
    wallet_id: String,
    #[arg(long, default_value_t = 1)]
    signer_epoch: u64,
    /// Secure Enclave key label for participant 2.
    #[arg(long, default_value = "catomicals.personal.desktop.1")]
    device_key_id: String,
    #[arg(long, default_value_t = 1)]
    device_generation: u64,
    /// Inherited pipe or socket that receives the generated 32-byte recovery key.
    #[arg(long, value_name = "FD")]
    recovery_key_fd: i32,
}

#[derive(Args)]
pub struct VerifyRecoveryArgs {
    #[arg(long, value_name = "FILE")]
    profile: PathBuf,
    #[arg(long, value_name = "FILE")]
    bundle: PathBuf,
    /// Inherited pipe or socket containing exactly the 32-byte recovery key.
    #[arg(long, value_name = "FD")]
    recovery_key_fd: i32,
}

#[derive(Args)]
pub struct SignerInitArgs {
    #[arg(long, value_name = "DIR")]
    data_dir: std::path::PathBuf,
    #[arg(long, default_value = "00000000-0000-0000-0000-000000000001")]
    wallet_id: String,
    #[arg(long, default_value_t = 1)]
    signer_id: u16,
}

#[derive(Args)]
pub struct SignerAuditArgs {
    #[arg(long, value_name = "DIR")]
    data_dir: std::path::PathBuf,
}

#[derive(Args)]
pub struct NewIntentArgs {
    #[arg(long, default_value = "00000000-0000-0000-0000-000000000001")]
    wallet_id: String,
    #[arg(long)]
    signer_id: u16,
    #[arg(long)]
    tx_digest_hex: String,
    #[arg(long)]
    session_id_hex: String,
    /// Unix seconds at which the intent expires.
    #[arg(long)]
    expiry: i64,
}

#[derive(Args)]
pub struct IntentIdArg {
    #[arg(value_name = "INTENT_ID")]
    pub id: String,
}

#[derive(Args)]
pub struct DemoArgs {
    /// Message to sign (hashed to a BIP340 digest).
    #[arg(long, default_value = "catomicals demo transaction v1")]
    message: String,
}

#[derive(Args)]
pub struct ApproveArgs {
    #[arg(value_name = "INTENT_ID")]
    pub id: String,
    /// Credential id to attach to the mock assertion.
    #[arg(long, default_value = "dev-credential")]
    pub credential_id: String,
}

pub fn run(cmd: WalletCommand) -> anyhow::Result<()> {
    match cmd {
        WalletCommand::Status(args) => status(args),
        WalletCommand::Serve(args) => wallet_serve::serve(args),
        WalletCommand::Intent { cmd } => intent(cmd),
        WalletCommand::Approval { cmd } => approval(cmd),
        WalletCommand::Signer { cmd } => signer(cmd),
        WalletCommand::Approve(args) => approve(args),
        WalletCommand::Demo(args) => demo_flow(args),
    }
}

fn signer(command: SignerCommand) -> anyhow::Result<()> {
    let audit = match command {
        SignerCommand::Init(args) => {
            let requested_wallet_id = Uuid::parse_str(&args.wallet_id)
                .with_context(|| format!("invalid wallet id `{}`", args.wallet_id))?;
            let authority =
                crate::walletd::open_authority(&args.data_dir, requested_wallet_id, now())?;
            let wallet_id = authority
                .wallet_id()
                .context("durable wallet authority is not initialized")?;
            let signer = crate::persistent_signer::PersistentSigner::open_or_initialize(
                &args.data_dir,
                wallet_id,
                args.signer_id,
                now(),
            )?;
            signer.audit_manifest()
        }
        SignerCommand::Audit(args) => {
            crate::persistent_signer::read_audit_manifest(&args.data_dir)?
        }
        SignerCommand::Personal { cmd } => return personal_signer(cmd),
    };
    println!("{}", serde_json::to_string_pretty(&audit)?);
    Ok(())
}

fn personal_signer(command: PersonalSignerCommand) -> anyhow::Result<()> {
    match command {
        PersonalSignerCommand::Bootstrap(args) => bootstrap_personal_signer(args),
        PersonalSignerCommand::VerifyRecovery(args) => verify_personal_recovery(args),
    }
}

fn bootstrap_personal_signer(_args: PersonalBootstrapArgs) -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        use catomicals_secret_store::MacosSecureEnclaveProtector;

        validate_bootstrap_paths(&_args)?;
        let mut recovery_key_sink = open_recovery_key_sink(_args.recovery_key_fd)?;
        let protector = MacosSecureEnclaveProtector::create(&_args.device_key_id)
            .context("creating the Secure Enclave key for personal participant 2")?;
        let summary = bootstrap_personal_signer_with_protector(
            _args,
            &protector,
            &mut recovery_key_sink,
            now(),
        )?;
        println!("{}", serde_json::to_string_pretty(&summary)?);
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = _args;
        bail!("personal signer bootstrap requires macOS Secure Enclave")
    }
}

const PERSONAL_PROFILE_FILE: &str = "profile.json";
const PERSONAL_DEVICE_PACKAGE_FILE: &str = "participant-2.device-wrapped.json";
const PERSONAL_RECOVERY_BUNDLE_FILE: &str = "participant-3.recovery.json";

#[derive(Debug, serde::Serialize)]
struct PersonalBootstrapSummary {
    status: &'static str,
    profile_id: Uuid,
    wallet_id: Uuid,
    signer_set_id: Uuid,
    signer_epoch: u64,
    group_pubkey_xonly: String,
    wallet_participant_id: u16,
    desktop_participant_id: u16,
    recovery_participant_id: u16,
    profile_path: PathBuf,
    device_wrapped_package_path: PathBuf,
    recovery_bundle_path: PathBuf,
    device_package_state: &'static str,
}

fn bootstrap_personal_signer_with_protector(
    args: PersonalBootstrapArgs,
    protector: &dyn catomicals_secret_store::DeviceKeyProtector,
    recovery_key_sink: &mut dyn std::io::Write,
    created_at: i64,
) -> anyhow::Result<PersonalBootstrapSummary> {
    use catomicals_secret_store::{DeviceWrapBinding, DeviceWrappedPackageV1, SecretValue};
    use catomicals_signer_recovery::RecoveryBundle;
    use catomicals_threshold::{PersonalSignerProfile, run_local_dkg};

    let paths = validate_bootstrap_paths(&args)?;
    let wallet_id = Uuid::parse_str(&args.wallet_id)
        .with_context(|| format!("invalid wallet id `{}`", args.wallet_id))?;
    if args.signer_epoch == 0 || args.device_generation == 0 {
        bail!("signer epoch and device generation must be positive");
    }
    if protector.key_id() != args.device_key_id {
        bail!("device key protector does not match the requested key id");
    }

    let mut bootstrap = PersonalSignerProfile::bootstrap(
        Uuid::new_v4(),
        wallet_id,
        Uuid::new_v4(),
        args.signer_epoch,
        run_local_dkg(3, 2).context("personal 2-of-3 distributed key generation failed")?,
    )
    .context("creating personal signer profile")?;
    let package3 = bootstrap
        .secret_packages
        .remove(&3)
        .ok_or_else(|| anyhow::anyhow!("personal DKG omitted recovery participant 3"))?;
    let profile = bootstrap.profile;
    // Consume and protect the offline share first. No later provisioning step
    // can retain or accidentally route participant 3 into wallet or desktop
    // storage.
    let (recovery_bundle, recovery_key) = RecoveryBundle::seal(package3, &profile)
        .context("protecting recovery participant package")?;

    let package2 = bootstrap
        .secret_packages
        .remove(&2)
        .ok_or_else(|| anyhow::anyhow!("personal DKG omitted desktop participant 2"))?;
    let device_binding = DeviceWrapBinding::new(
        protector.provider(),
        protector.algorithm(),
        protector.key_id(),
        profile.binding_digest(),
        2,
        profile.signer_epoch(),
        args.device_generation,
    )
    .context("binding desktop participant package")?;
    let package2_bytes = package2
        .to_bytes()
        .context("encoding desktop participant package")?;
    let device_package = DeviceWrappedPackageV1::seal(
        SecretValue::new(package2_bytes.to_vec()),
        device_binding,
        protector,
    )
    .context("protecting desktop participant package")?;
    let package1 = bootstrap
        .secret_packages
        .remove(&1)
        .ok_or_else(|| anyhow::anyhow!("personal DKG omitted wallet participant 1"))?;
    if !bootstrap.secret_packages.is_empty() {
        bail!("personal DKG returned an unexpected participant inventory");
    }
    let profile_bytes = profile
        .to_bytes()
        .context("encoding personal signer profile")?;
    let device_package_bytes = device_package
        .to_bytes()
        .context("encoding device-wrapped participant package")?;
    let recovery_bundle_bytes = recovery_bundle
        .to_bytes()
        .context("encoding recovery participant package")?;

    create_private_output_directory(&paths.output_dir)?;
    let result = (|| {
        write_private_output_atomic(&paths.profile, &profile_bytes)?;
        write_private_output_atomic(&paths.device_package, &device_package_bytes)?;
        write_private_output_atomic(&paths.recovery_bundle, &recovery_bundle_bytes)?;
        let key_bytes = recovery_key.to_bytes();
        recovery_key_sink
            .write_all(key_bytes.as_ref())
            .context("writing recovery key to inherited descriptor")?;
        recovery_key_sink
            .flush()
            .context("flushing recovery key to inherited descriptor")?;
        crate::persistent_signer::install_personal_wallet_share(
            &paths.data_dir,
            &profile,
            package1,
            created_at,
        )?;
        Ok::<(), anyhow::Error>(())
    })();
    if let Err(error) = result {
        cleanup_private_outputs(&paths);
        return Err(error);
    }

    Ok(PersonalBootstrapSummary {
        status: "provisioned",
        profile_id: profile.profile_id(),
        wallet_id: profile.wallet_id(),
        signer_set_id: profile.signer_set_id(),
        signer_epoch: profile.signer_epoch(),
        group_pubkey_xonly: hex::encode(profile.group_pubkey_xonly()),
        wallet_participant_id: 1,
        desktop_participant_id: 2,
        recovery_participant_id: 3,
        profile_path: paths.profile,
        device_wrapped_package_path: paths.device_package,
        recovery_bundle_path: paths.recovery_bundle,
        device_package_state: "encrypted_pending_1password_import",
    })
}

fn cleanup_private_outputs(paths: &PersonalBootstrapPaths) {
    for path in [
        &paths.profile,
        &paths.device_package,
        &paths.recovery_bundle,
    ] {
        let _ = std::fs::remove_file(path);
    }
    let _ = std::fs::remove_dir(&paths.output_dir);
}

struct PersonalBootstrapPaths {
    data_dir: PathBuf,
    output_dir: PathBuf,
    profile: PathBuf,
    device_package: PathBuf,
    recovery_bundle: PathBuf,
}

fn validate_bootstrap_paths(
    args: &PersonalBootstrapArgs,
) -> anyhow::Result<PersonalBootstrapPaths> {
    reject_direct_symlink(&args.data_dir, "wallet data directory")?;
    reject_direct_symlink(&args.output_dir, "provisioning output directory")?;
    if args.output_dir.exists() {
        bail!("provisioning output directory already exists");
    }
    if args.data_dir.join("signer.json").exists() || args.data_dir.join("signer-secrets").exists() {
        bail!("durable signer is already initialized");
    }
    let data_dir = canonicalize_missing_leaf(&args.data_dir, "wallet data directory")?;
    let output_dir = canonicalize_missing_leaf(&args.output_dir, "provisioning output directory")?;
    if data_dir == output_dir
        || data_dir.starts_with(&output_dir)
        || output_dir.starts_with(&data_dir)
    {
        bail!("wallet data and provisioning output paths overlap");
    }
    for ancestor in output_dir.ancestors().skip(1) {
        if ancestor.join("manifest.json").is_file() && ancestor.join("wallet.sqlite3.enc").is_file()
        {
            bail!("provisioning output cannot be placed inside an existing wallet backup");
        }
    }
    Ok(PersonalBootstrapPaths {
        profile: output_dir.join(PERSONAL_PROFILE_FILE),
        device_package: output_dir.join(PERSONAL_DEVICE_PACKAGE_FILE),
        recovery_bundle: output_dir.join(PERSONAL_RECOVERY_BUNDLE_FILE),
        data_dir,
        output_dir,
    })
}

fn reject_direct_symlink(path: &std::path::Path, label: &str) -> anyhow::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => bail!("{label} cannot be a symlink"),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspecting {label}")),
    }
}

fn canonicalize_missing_leaf(path: &std::path::Path, label: &str) -> anyhow::Result<PathBuf> {
    if path.exists() {
        return std::fs::canonicalize(path).with_context(|| format!("resolving {label}"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{label} has no parent directory"))?;
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{label} has no final component"))?;
    Ok(std::fs::canonicalize(parent)
        .with_context(|| format!("resolving parent of {label}"))?
        .join(name))
}

#[cfg(unix)]
fn create_private_output_directory(path: &std::path::Path) -> anyhow::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;

    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .context("creating private provisioning output directory")
}

#[cfg(not(unix))]
fn create_private_output_directory(_path: &std::path::Path) -> anyhow::Result<()> {
    bail!("personal signer provisioning requires Unix permission semantics")
}

#[cfg(unix)]
fn write_private_output_atomic(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::{
        fs::{File, OpenOptions},
        io::Write as _,
        os::unix::fs::OpenOptionsExt as _,
    };

    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("private provisioning output has no parent"))?;
    let temporary = parent.join(format!(".provisioning-{}.tmp", Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .context("creating private provisioning output")?;
    let result = (|| {
        file.write_all(bytes)
            .context("writing private provisioning output")?;
        file.sync_all()
            .context("syncing private provisioning output")?;
        std::fs::rename(&temporary, path).context("installing private provisioning output")?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .context("syncing provisioning output directory")
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[cfg(not(unix))]
fn write_private_output_atomic(_path: &std::path::Path, _bytes: &[u8]) -> anyhow::Result<()> {
    bail!("personal signer provisioning requires Unix permission semantics")
}

#[cfg(unix)]
fn open_recovery_key_sink(fd: i32) -> anyhow::Result<std::fs::File> {
    use std::{fs::OpenOptions, os::unix::fs::FileTypeExt as _};

    if fd < 3 {
        bail!("recovery key descriptor must be an inherited pipe or socket");
    }
    let sink = OpenOptions::new()
        .write(true)
        .open(format!("/dev/fd/{fd}"))
        .context("opening inherited recovery key descriptor")?;
    let file_type = sink.metadata()?.file_type();
    if !file_type.is_fifo() && !file_type.is_socket() {
        bail!("recovery key descriptor must be an inherited pipe or socket");
    }
    Ok(sink)
}

#[derive(serde::Serialize)]
struct RecoveryVerificationSummary {
    status: &'static str,
    profile_id: Uuid,
    wallet_id: Uuid,
    signer_set_id: Uuid,
    signer_epoch: u64,
    participant_id: u16,
    group_pubkey_xonly: String,
}

fn verify_personal_recovery(args: VerifyRecoveryArgs) -> anyhow::Result<()> {
    use catomicals_signer_recovery::{RecoveryBundle, RecoveryKey};
    use catomicals_threshold::PersonalSignerProfile;

    let profile_bytes = read_private_bounded(&args.profile, 64 * 1024, "personal signer profile")?;
    let profile = PersonalSignerProfile::from_bytes(&profile_bytes)
        .context("personal signer profile is invalid")?;
    let bundle_bytes = read_private_bounded(&args.bundle, 128 * 1024, "recovery bundle")?;
    let bundle = RecoveryBundle::from_bytes(&bundle_bytes).context("recovery bundle is invalid")?;
    let key_bytes = read_recovery_key_fd(args.recovery_key_fd)?;
    let key = RecoveryKey::from_bytes(key_bytes);
    let participant = bundle
        .open(&key, &profile)
        .context("recovery bundle authentication failed")?;
    let summary = RecoveryVerificationSummary {
        status: "verified",
        profile_id: profile.profile_id(),
        wallet_id: profile.wallet_id(),
        signer_set_id: profile.signer_set_id(),
        signer_epoch: profile.signer_epoch(),
        participant_id: participant.signer_id(),
        group_pubkey_xonly: hex::encode(profile.group_pubkey_xonly()),
    };
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

#[cfg(unix)]
fn read_private_bounded(
    path: &std::path::Path,
    limit: u64,
    label: &str,
) -> anyhow::Result<Vec<u8>> {
    use rustix::{
        fs::{FileType, Mode, OFlags, fstat, open},
        process::geteuid,
    };
    use std::{fs::File, io::Read as _};

    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .with_context(|| format!("opening {label}"))?;
    let metadata = fstat(&descriptor).with_context(|| format!("reading {label} metadata"))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || Mode::from_raw_mode(metadata.st_mode).bits() != 0o600
        || metadata.st_uid != geteuid().as_raw()
        || metadata.st_nlink != 1
    {
        bail!("{label} must be a private regular file with mode 0600");
    }
    let mut bytes = Vec::new();
    File::from(descriptor)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {label}"))?;
    if bytes.len() as u64 > limit {
        bail!("{label} exceeds its size limit");
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_private_bounded(
    _path: &std::path::Path,
    _limit: u64,
    _label: &str,
) -> anyhow::Result<Vec<u8>> {
    bail!("personal signer files require Unix permission semantics")
}

#[cfg(unix)]
fn read_recovery_key_fd(fd: i32) -> anyhow::Result<[u8; 32]> {
    use std::{fs::OpenOptions, io::Read as _, os::unix::fs::FileTypeExt as _};

    if fd < 3 {
        bail!("recovery key descriptor must be an inherited pipe or socket");
    }
    let source = OpenOptions::new()
        .read(true)
        .open(format!("/dev/fd/{fd}"))
        .context("opening inherited recovery key descriptor")?;
    let file_type = source.metadata()?.file_type();
    if !file_type.is_fifo() && !file_type.is_socket() {
        bail!("recovery key descriptor must be an inherited pipe or socket");
    }
    let mut bytes = Vec::with_capacity(33);
    source
        .take(33)
        .read_to_end(&mut bytes)
        .context("reading inherited recovery key descriptor")?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("recovery key descriptor must contain exactly 32 bytes"))?;
    Ok(key)
}

#[cfg(not(unix))]
fn read_recovery_key_fd(_fd: i32) -> anyhow::Result<[u8; 32]> {
    bail!("recovery key descriptors require Unix")
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn intent_id(s: &str) -> anyhow::Result<Uuid> {
    Uuid::from_str(s).with_context(|| format!("invalid intent id `{s}`"))
}

fn new_api() -> WalletApi {
    WalletApi::new()
}

fn status(args: StatusArgs) -> anyhow::Result<()> {
    let mut api = new_api();
    if let Some(snapshot) = probe_node_public(&args.node) {
        api.set_node_snapshot(Some(snapshot));
    }
    let s = api.status();
    println!("wallet status");
    match &s.node {
        Some(n) => {
            println!(
                "  node           {} (blocks {}, op_cat={})",
                n.chain, n.blocks, n.op_cat_active
            );
        }
        None => println!("  node           unreachable"),
    }
    println!(
        "  threshold      {}/{} configured={} pubkey={}",
        s.threshold.min_signers,
        s.threshold.max_signers,
        s.threshold.configured,
        s.threshold
            .group_pubkey_xonly
            .clone()
            .unwrap_or_else(|| "-".into())
    );
    println!("  signers        {}", s.signers.len());
    for sg in &s.signers {
        println!(
            "    #{} {} {}",
            sg.id,
            sg.label,
            if sg.online { "online" } else { "offline" }
        );
    }
    println!("  pending        {}", s.pending_approvals.len());
    for p in s.pending_approvals.iter().take(args.limit) {
        println!("    {} signer={} expiry={}", p.id, p.signer_id, p.expiry);
    }
    println!("  credentials    {}", s.credentials);
    Ok(())
}

fn intent(cmd: IntentCommand) -> anyhow::Result<()> {
    let mut api = new_api();
    match cmd {
        IntentCommand::New(args) => {
            let tx_digest =
                hex::decode(&args.tx_digest_hex).context("tx_digest_hex must be 32-byte hex")?;
            let session_id =
                hex::decode(&args.session_id_hex).context("session_id_hex must be 32-byte hex")?;
            if tx_digest.len() != 32 || session_id.len() != 32 {
                bail!("digests must be exactly 32 bytes (64 hex chars)");
            }
            let mut td = [0u8; 32];
            let mut sd = [0u8; 32];
            td.copy_from_slice(&tx_digest);
            sd.copy_from_slice(&session_id);
            let intent = api.create_intent(
                CreateIntentRequest {
                    wallet_id: Uuid::from_str(&args.wallet_id)?,
                    signer_id: args.signer_id,
                    tx_digest: td,
                    session_id: sd,
                    expiry: args.expiry,
                },
                now(),
            )?;
            print_intent(&intent);
        }
        IntentCommand::List => {
            for i in api.list_intents() {
                print_intent(&i);
            }
        }
        IntentCommand::Show(arg) => {
            let i = api.read_intent(&intent_id(&arg.id)?)?;
            print_intent(&i);
        }
        IntentCommand::Cancel(arg) => {
            let i = api.cancel_intent(&intent_id(&arg.id)?, now())?;
            print_intent(&i);
        }
    }
    Ok(())
}

fn approval(cmd: ApprovalCommand) -> anyhow::Result<()> {
    let api = new_api();
    match cmd {
        ApprovalCommand::Challenge(arg) => {
            let c: ApprovalChallenge = api.approval_challenge(&intent_id(&arg.id)?, now())?;
            println!("approval challenge");
            println!("  intent        {}", c.intent_id);
            println!("  challenge     {} (hex)", hex::encode(c.challenge));
            println!("  challenge_b64 {}", c.challenge_b64url);
            println!("  expires_at    {}", c.expires_at);
        }
        ApprovalCommand::State(arg) => {
            let s: ApprovalState = api.read_approval(&intent_id(&arg.id)?)?;
            println!(
                "intent {} status={:?} approved={}",
                s.intent_id, s.status, s.approved
            );
        }
    }
    Ok(())
}

fn approve(args: ApproveArgs) -> anyhow::Result<()> {
    let _ = intent_id(&args.id)?;
    bail!(
        "mock Passkey approval is disabled; configure a cryptographic WebAuthn RP verifier for credential `{}`",
        args.credential_id
    )
}

fn demo_flow(args: DemoArgs) -> anyhow::Result<()> {
    bail!(
        "mock Passkey wallet demo is disabled for `{}`; use `catomicals frost demo` for the dev-only threshold proof",
        args.message
    )
}

fn print_intent(i: &SigningIntent) {
    println!(
        "intent {} wallet={} signer={} status={:?}",
        i.id, i.wallet_id, i.signer_id, i.status
    );
    println!("  tx_digest   {}", hex::encode(i.tx_digest));
    println!("  session_id  {}", hex::encode(i.session_id));
    println!("  nonce       {}", hex::encode(i.nonce));
    println!("  expiry      {} created_at {}", i.expiry, i.created_at);
}

/// Probe the node and build a wallet `NodeSnapshot` (non-fatal).
pub fn probe_node_public(args: &NodeArgs) -> Option<catomicals_wallet::NodeSnapshot> {
    let config = catomicals_node_client::rpc::NodeRpcConfig {
        rpc_url: args.rpc_url.clone(),
        cookie_path: args.cookie.clone(),
        data_dir: args.datadir.clone(),
        allow_non_loopback: args.allow_non_loopback,
    };
    let connection = catomicals_node_client::rpc::connect(&config).ok()?;
    let report = catomicals_node_client::rpc::check_node_health(&connection).ok()?;
    Some(catomicals_wallet::NodeSnapshot {
        chain: report.chain,
        blocks: report.blocks,
        headers: report.headers,
        subversion: report.subversion,
        op_cat_active: report.op_cat.active,
    })
}

// keep WalletError import referenced for downstream docs
#[allow(dead_code)]
fn _err_type(_: WalletError) {}

#[cfg(all(test, unix))]
mod personal_provisioning_tests {
    use std::{fs, io, os::unix::fs::PermissionsExt as _, path::PathBuf};

    use catomicals_secret_store::{
        DeviceKeyProtectionError, DeviceKeyProtector, DeviceKeyProvider, DeviceKeyWrapAlgorithm,
        DeviceWrappedPackageV1, FileSecretBackend, RuntimeProfile, SecretValue,
    };
    use catomicals_signer_recovery::{RecoveryBundle, RecoveryKey};
    use catomicals_threshold::PersonalSignerProfile;
    use tempfile::tempdir;
    use uuid::Uuid;

    use super::*;

    struct TestProtector {
        key_id: String,
    }

    impl DeviceKeyProtector for TestProtector {
        fn provider(&self) -> DeviceKeyProvider {
            DeviceKeyProvider::MacosSecureEnclaveP256
        }

        fn algorithm(&self) -> DeviceKeyWrapAlgorithm {
            DeviceKeyWrapAlgorithm::AppleEciesCofactorX963Sha256AesGcm
        }

        fn key_id(&self) -> &str {
            &self.key_id
        }

        fn wrap_dek(&self, dek: SecretValue) -> Result<Vec<u8>, DeviceKeyProtectionError> {
            Ok(dek.expose().iter().map(|byte| byte ^ 0xa5).collect())
        }

        fn unwrap_dek(&self, wrapped_dek: &[u8]) -> Result<SecretValue, DeviceKeyProtectionError> {
            Ok(SecretValue::new(
                wrapped_dek.iter().map(|byte| byte ^ 0xa5).collect(),
            ))
        }
    }

    #[test]
    fn bootstrap_installs_one_share_and_emits_two_independent_ciphertexts() {
        let root = tempdir().unwrap();
        let data_dir = root.path().join("wallet");
        let output_dir = root.path().join("provisioning");
        let wallet_id = Uuid::from_bytes([0x41; 16]);
        let args = args(data_dir.clone(), output_dir.clone(), wallet_id);
        let protector = TestProtector {
            key_id: args.device_key_id.clone(),
        };
        let mut recovery_key = Vec::new();

        let summary = bootstrap_personal_signer_with_protector(
            args,
            &protector,
            &mut recovery_key,
            1_800_000_000,
        )
        .unwrap();

        assert_eq!(recovery_key.len(), 32);
        assert_eq!(
            fs::metadata(&output_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for name in [
            "profile.json",
            "participant-2.device-wrapped.json",
            "participant-3.recovery.json",
        ] {
            assert_eq!(
                fs::metadata(output_dir.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let profile =
            PersonalSignerProfile::from_bytes(&fs::read(output_dir.join("profile.json")).unwrap())
                .unwrap();
        let wrapped = DeviceWrappedPackageV1::from_bytes(
            &fs::read(output_dir.join("participant-2.device-wrapped.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(wrapped.binding().signer_id(), 2);
        assert_eq!(wrapped.binding().profile_digest(), profile.binding_digest());
        let bundle = RecoveryBundle::from_bytes(
            &fs::read(output_dir.join("participant-3.recovery.json")).unwrap(),
        )
        .unwrap();
        let key = RecoveryKey::from_bytes(recovery_key.try_into().unwrap());
        let participant3 = bundle.open(&key, &profile).unwrap();
        assert_eq!(participant3.signer_id(), 3);
        assert_eq!(summary.profile_id, profile.profile_id());
        assert_eq!(summary.wallet_id, wallet_id);
        let audit = crate::persistent_signer::read_audit_manifest(&data_dir).unwrap();
        assert_eq!(audit.signer_id, 1);
        assert_eq!(audit.signer_set_id, profile.signer_set_id());
        assert_eq!(
            audit.group_pubkey_xonly,
            hex::encode(profile.group_pubkey_xonly())
        );
    }

    #[test]
    fn recovery_bundle_is_isolated_from_wallet_backup_and_desktop_share_output() {
        let root = tempdir().unwrap();
        let data_dir = root.path().join("wallet");
        let output_dir = root.path().join("provisioning");
        let backup_dir = root.path().join("wallet-backup");
        let protector = TestProtector {
            key_id: "catomicals.test.desktop".to_owned(),
        };
        bootstrap_personal_signer_with_protector(
            args(
                data_dir.clone(),
                output_dir.clone(),
                Uuid::from_bytes([0x45; 16]),
            ),
            &protector,
            &mut Vec::new(),
            1_800_000_004,
        )
        .unwrap();

        let device_path = output_dir.join(PERSONAL_DEVICE_PACKAGE_FILE);
        let recovery_path = output_dir.join(PERSONAL_RECOVERY_BUNDLE_FILE);
        let device_bytes = fs::read(&device_path).unwrap();
        let recovery_bytes = fs::read(&recovery_path).unwrap();
        assert!(DeviceWrappedPackageV1::from_bytes(&device_bytes).is_ok());
        assert!(RecoveryBundle::from_bytes(&recovery_bytes).is_ok());
        assert!(DeviceWrappedPackageV1::from_bytes(&recovery_bytes).is_err());
        assert!(RecoveryBundle::from_bytes(&device_bytes).is_err());
        assert!(!recovery_path.starts_with(&data_dir));
        assert!(!device_path.starts_with(&data_dir));

        fs::create_dir(&backup_dir).unwrap();
        let backup_backend = FileSecretBackend::open(
            root.path().join("backup-secrets"),
            RuntimeProfile::Development,
        )
        .unwrap();
        crate::persistent_signer::export_backup_attachment(&data_dir, &backup_dir, &backup_backend)
            .unwrap()
            .expect("share1 backup attachment");
        assert!(!backup_dir.join(PERSONAL_RECOVERY_BUNDLE_FILE).exists());
        assert!(!backup_dir.join(PERSONAL_DEVICE_PACKAGE_FILE).exists());
        assert_directory_does_not_contain(&data_dir, &recovery_bytes);
        assert_directory_does_not_contain(&data_dir, &device_bytes);
        assert_directory_does_not_contain(&backup_dir, &recovery_bytes);
        assert_directory_does_not_contain(&backup_dir, &device_bytes);
    }

    #[test]
    fn bootstrap_rejects_overlap_and_existing_signer_before_creating_outputs() {
        let root = tempdir().unwrap();
        let data_dir = root.path().join("wallet");
        fs::create_dir(&data_dir).unwrap();
        let overlap = data_dir.join("exports");
        let protector = TestProtector {
            key_id: "catomicals.test.desktop".to_owned(),
        };
        let mut sink = Vec::new();
        let error = bootstrap_personal_signer_with_protector(
            args(
                data_dir.clone(),
                overlap.clone(),
                Uuid::from_bytes([0x42; 16]),
            ),
            &protector,
            &mut sink,
            1_800_000_001,
        )
        .unwrap_err();
        assert!(error.to_string().contains("overlap"));
        assert!(!overlap.exists());
        assert!(sink.is_empty());

        fs::write(data_dir.join("signer.json"), b"existing").unwrap();
        let output_dir = root.path().join("second");
        let error = bootstrap_personal_signer_with_protector(
            args(data_dir, output_dir.clone(), Uuid::from_bytes([0x43; 16])),
            &protector,
            &mut sink,
            1_800_000_002,
        )
        .unwrap_err();
        assert!(error.to_string().contains("already initialized"));
        assert!(!output_dir.exists());
    }

    #[test]
    fn bootstrap_rolls_back_outputs_when_recovery_key_delivery_fails() {
        struct FailingWriter;
        impl io::Write for FailingWriter {
            fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let root = tempdir().unwrap();
        let data_dir = root.path().join("wallet");
        let output_dir = root.path().join("provisioning");
        let protector = TestProtector {
            key_id: "catomicals.test.desktop".to_owned(),
        };
        let error = bootstrap_personal_signer_with_protector(
            args(
                data_dir.clone(),
                output_dir.clone(),
                Uuid::from_bytes([0x44; 16]),
            ),
            &protector,
            &mut FailingWriter,
            1_800_000_003,
        )
        .unwrap_err();
        assert!(error.to_string().contains("recovery key"));
        assert!(!output_dir.exists());
        assert!(!data_dir.join("signer.json").exists());
    }

    fn args(data_dir: PathBuf, output_dir: PathBuf, wallet_id: Uuid) -> PersonalBootstrapArgs {
        PersonalBootstrapArgs {
            data_dir,
            output_dir,
            wallet_id: wallet_id.to_string(),
            signer_epoch: 3,
            device_key_id: "catomicals.test.desktop".to_owned(),
            device_generation: 1,
            recovery_key_fd: 9,
        }
    }

    fn assert_directory_does_not_contain(directory: &std::path::Path, needle: &[u8]) {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                assert_directory_does_not_contain(&path, needle);
            } else {
                let bytes = fs::read(&path).unwrap();
                assert!(
                    !bytes.windows(needle.len()).any(|window| window == needle),
                    "isolated package was copied to {}",
                    path.display()
                );
            }
        }
    }
}

use std::path::PathBuf;

use anyhow::bail;
use clap::{Args, Subcommand};

#[cfg(target_os = "macos")]
use std::{
    fs::File,
    io::{Read as _, Take},
    net::SocketAddr,
    os::fd::FromRawFd as _,
    path::Path,
    time::Duration,
};

#[cfg(target_os = "macos")]
use catomicals_secret_store::{
    DeviceKeyProtector, DeviceKeyProvider, DeviceKeyWrapAlgorithm, DeviceWrapBinding,
    DeviceWrappedPackageV1, MacosSecureEnclaveProtector, OnePasswordWrappedPackageLoader,
};
#[cfg(target_os = "macos")]
use catomicals_signer_transport::{MtlsSignerServer, TransportLimits, private_ca_server_config};
#[cfg(target_os = "macos")]
use catomicals_threshold::{
    GuardedSignerProvider, LocalEncryptedFrostBackend, NonceGuard, PersonalParticipantRole,
    PersonalParticipantSecretPackage, PersonalSignerProfile, ProviderError, ProviderIdentity,
    ProviderRequestAuthorizer, ProviderRound,
};
#[cfg(target_os = "macos")]
use rustix::{
    fs::{FileType, Mode, OFlags, fstat, open},
    process::geteuid,
};
#[cfg(target_os = "macos")]
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
#[cfg(target_os = "macos")]
use serde::{Deserialize, Serialize};
#[cfg(target_os = "macos")]
use tokio::{net::TcpListener, runtime::Builder, sync::watch};
#[cfg(target_os = "macos")]
use uuid::Uuid;

#[cfg(target_os = "macos")]
const CONFIG_FORMAT_VERSION: u16 = 2;
#[cfg(target_os = "macos")]
const FROST_SIGNING_ROUNDS: u8 = 2;
#[cfg(target_os = "macos")]
const DESKTOP_SIGNER_ID: u16 = 2;
#[cfg(target_os = "macos")]
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
#[cfg(target_os = "macos")]
const MAX_PROFILE_BYTES: u64 = 64 * 1024;
#[cfg(target_os = "macos")]
const MAX_CERTIFICATE_BYTES: u64 = 64 * 1024;
#[cfg(target_os = "macos")]
const MAX_PRIVATE_KEY_BYTES: u64 = 16 * 1024;
#[cfg(target_os = "macos")]
const SERIAL_PROVIDER_MAX_CONNECTIONS: usize = 1;
#[cfg(target_os = "macos")]
const MIN_ROUND_TIMEOUT_MS: u64 = 100;
#[cfg(target_os = "macos")]
const MAX_ROUND_TIMEOUT_MS: u64 = 120_000;
#[cfg(target_os = "macos")]
const MAX_SESSION_TIMEOUT_MS: u64 = 15 * 60 * 1_000;

#[cfg(all(test, target_os = "macos"))]
const TEST_PROTECTOR_ENV: &str = "CATOMICALS_TEST_ONLY_DEVICE_PROTECTOR";
#[cfg(all(test, target_os = "macos"))]
const TEST_PROTECTOR_VALUE: &str = "explicit-unit-test-only";

#[derive(Debug, Subcommand)]
pub enum SignerCommand {
    Serve(ServeArgs),
}

#[derive(Debug, Args)]
pub struct ServeArgs {
    /// Private signer configuration file. It must be owned by the current user and mode 0600.
    #[arg(
        long,
        value_name = "FILE",
        required_unless_present = "config_fd",
        conflicts_with = "config_fd"
    )]
    config: Option<PathBuf>,

    /// Inherited descriptor containing the private signer configuration.
    #[arg(
        long,
        value_name = "FD",
        required_unless_present = "config",
        conflicts_with = "config"
    )]
    config_fd: Option<i32>,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum SignerProtocolProfile {
    FrostSecp256k1TrV1,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignerServeConfig {
    format_version: u16,
    protocol_profile: SignerProtocolProfile,
    listen_addr: SocketAddr,
    profile_path: PathBuf,
    onepassword_executable: PathBuf,
    wrapped_package_reference: String,
    device_key_id: String,
    server_cert_path: PathBuf,
    server_key_path: PathBuf,
    client_ca_cert_path: PathBuf,
    coordinator_spki_sha256_hex: String,
    device_id: Uuid,
    device_generation: u64,
    round_timeout_ms: u64,
    session_timeout_ms: u64,
    max_frame_bytes: usize,
    max_connections: usize,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Serialize)]
struct ReadyStatus {
    event: &'static str,
    state: &'static str,
    signer_id: u16,
    signer_set_id: Uuid,
    epoch: u64,
    device_generation: u64,
    online: bool,
    protocol_profile: SignerProtocolProfile,
    signing_rounds: u8,
}

pub fn run(command: SignerCommand) -> anyhow::Result<()> {
    match command {
        SignerCommand::Serve(args) => serve(args),
    }
}

#[cfg(not(target_os = "macos"))]
fn serve(_args: ServeArgs) -> anyhow::Result<()> {
    bail!("the production personal signer is unsupported on this platform")
}

#[cfg(target_os = "macos")]
fn serve(args: ServeArgs) -> anyhow::Result<()> {
    #[cfg(test)]
    if std::env::var(TEST_PROTECTOR_ENV).as_deref() == Ok(TEST_PROTECTOR_VALUE) {
        return serve_with_protector(args, tests::open_test_protector);
    }
    serve_with_protector(args, |key_id| {
        MacosSecureEnclaveProtector::open(key_id.to_owned())
            .map(|protector| Box::new(protector) as Box<dyn DeviceKeyProtector>)
            .map_err(|_| {
                anyhow::anyhow!(
                    "Secure Enclave signer key is unavailable; a signed helper with the required Keychain entitlement is required"
                )
            })
    })
}

#[cfg(target_os = "macos")]
fn serve_with_protector<F>(args: ServeArgs, open_protector: F) -> anyhow::Result<()>
where
    F: FnOnce(&str) -> anyhow::Result<Box<dyn DeviceKeyProtector>>,
{
    let config = read_config_source(args)?;
    let profile = read_profile(&config.profile_path)?;
    let participant = load_desktop_participant(&config, &profile, open_protector)?;
    let identity = signer_identity(&profile, config.device_id, config.device_generation)?;
    let backend = LocalEncryptedFrostBackend::new(
        participant,
        profile
            .public_key_package()
            .map_err(|_| anyhow::anyhow!("personal signer profile is invalid"))?,
        PersonalSignerAuthorizer,
    );
    let provider = GuardedSignerProvider::new_with_session_timeout(
        identity,
        backend,
        Duration::from_millis(config.session_timeout_ms),
    )
    .map_err(|_| anyhow::anyhow!("signer session configuration is invalid"))?;

    let server_cert = read_public_file(&config.server_cert_path, MAX_CERTIFICATE_BYTES)
        .map(CertificateDer::from)?;
    let server_key = read_private_file(&config.server_key_path, MAX_PRIVATE_KEY_BYTES)
        .map(PrivatePkcs8KeyDer::from)
        .map(PrivateKeyDer::from)?;
    let client_ca = read_public_file(&config.client_ca_cert_path, MAX_CERTIFICATE_BYTES)
        .map(CertificateDer::from)?;
    let server_config = private_ca_server_config(client_ca, vec![server_cert], server_key)
        .map_err(|_| anyhow::anyhow!("signer transport configuration is invalid"))?;
    let coordinator_spki = decode_spki_pin(&config.coordinator_spki_sha256_hex)?;
    let server = MtlsSignerServer::new(
        provider,
        server_config,
        coordinator_spki,
        TransportLimits {
            io_timeout: Duration::from_millis(config.round_timeout_ms),
            max_frame_bytes: config.max_frame_bytes,
            max_connections: config.max_connections,
        },
    );

    let runtime = Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async move {
        let listener = TcpListener::bind(config.listen_addr)
            .await
            .map_err(|_| anyhow::anyhow!("signer listener could not start"))?;
        let status = ReadyStatus {
            event: "personal_signer_status",
            state: "ready",
            signer_id: DESKTOP_SIGNER_ID,
            signer_set_id: profile.signer_set_id(),
            epoch: profile.signer_epoch(),
            device_generation: config.device_generation,
            online: true,
            protocol_profile: config.protocol_profile,
            signing_rounds: FROST_SIGNING_ROUNDS,
        };
        println!(
            "{}",
            serde_json::to_string(&status)
                .map_err(|_| anyhow::anyhow!("signer status could not be encoded"))?
        );
        std::io::Write::flush(&mut std::io::stdout())
            .map_err(|_| anyhow::anyhow!("signer status could not be emitted"))?;
        let (_shutdown, receiver) = watch::channel(false);
        server
            .serve(listener, receiver)
            .await
            .map_err(|_| anyhow::anyhow!("signer transport stopped"))
    })
}

#[cfg(target_os = "macos")]
fn load_desktop_participant<F>(
    config: &SignerServeConfig,
    profile: &PersonalSignerProfile,
    open_protector: F,
) -> anyhow::Result<catomicals_threshold::LocalFrostParticipant>
where
    F: FnOnce(&str) -> anyhow::Result<Box<dyn DeviceKeyProtector>>,
{
    let loaded = OnePasswordWrappedPackageLoader::new(
        config.onepassword_executable.clone(),
        config.wrapped_package_reference.clone(),
        Duration::from_millis(config.round_timeout_ms),
    )
    .map_err(|_| anyhow::anyhow!("1Password signer configuration is invalid"))?
    .load()
    .map_err(|_| anyhow::anyhow!("1Password signer package is unavailable"))?;
    let wrapped = DeviceWrappedPackageV1::from_bytes(loaded.expose())
        .map_err(|_| anyhow::anyhow!("1Password signer package is invalid"))?;
    let expected_binding = DeviceWrapBinding::new(
        DeviceKeyProvider::MacosSecureEnclaveP256,
        DeviceKeyWrapAlgorithm::AppleEciesCofactorX963Sha256AesGcm,
        config.device_key_id.clone(),
        profile.binding_digest(),
        DESKTOP_SIGNER_ID,
        profile.signer_epoch(),
        config.device_generation,
    )
    .map_err(|_| anyhow::anyhow!("device signer binding is invalid"))?;
    if wrapped.binding() != &expected_binding {
        bail!("device signer binding does not match the configured profile");
    }
    let protector = open_protector(&config.device_key_id)?;
    let package_bytes = wrapped
        .open(&expected_binding, protector.as_ref())
        .map_err(|_| anyhow::anyhow!("device signer package could not be opened"))?;
    let package = PersonalParticipantSecretPackage::from_bytes(package_bytes.expose(), profile)
        .map_err(|_| anyhow::anyhow!("participant signer package is invalid"))?;
    if package.signer_id() != DESKTOP_SIGNER_ID
        || profile.participants().iter().all(|descriptor| {
            descriptor.signer_id != DESKTOP_SIGNER_ID
                || descriptor.role != PersonalParticipantRole::DesktopOnePassword
        })
    {
        bail!("participant signer package has the wrong role");
    }
    package
        .open(profile)
        .map_err(|_| anyhow::anyhow!("participant signer package is invalid"))?
        .into_participant(NonceGuard::new())
        .map_err(|_| anyhow::anyhow!("participant signer package is invalid"))
}

#[cfg(target_os = "macos")]
fn signer_identity(
    profile: &PersonalSignerProfile,
    device_id: Uuid,
    device_generation: u64,
) -> anyhow::Result<ProviderIdentity> {
    let descriptor = profile
        .participants()
        .iter()
        .find(|participant| participant.signer_id == DESKTOP_SIGNER_ID)
        .ok_or_else(|| anyhow::anyhow!("personal signer profile is invalid"))?;
    Ok(ProviderIdentity {
        wallet_id: profile.wallet_id(),
        signer_set_id: profile.signer_set_id(),
        signer_epoch: profile.signer_epoch(),
        signer_id: DESKTOP_SIGNER_ID,
        device_id,
        device_generation,
        group_pubkey_xonly: profile.group_pubkey_xonly(),
        verifying_share_digest: descriptor.verifying_share_digest,
    })
}

#[cfg(target_os = "macos")]
struct PersonalSignerAuthorizer;

#[cfg(target_os = "macos")]
impl ProviderRequestAuthorizer for PersonalSignerAuthorizer {
    fn authorize(
        &mut self,
        context: &catomicals_threshold::SignerRequestContext,
        _round: ProviderRound,
    ) -> Result<(), ProviderError> {
        if context.min_signers != 2 || context.max_signers != 3 {
            return Err(ProviderError::IdentityDrift);
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn read_config(path: &Path) -> anyhow::Result<SignerServeConfig> {
    let bytes = read_private_file(path, MAX_CONFIG_BYTES)?;
    parse_config(&bytes)
}

#[cfg(target_os = "macos")]
fn read_config_source(args: ServeArgs) -> anyhow::Result<SignerServeConfig> {
    match (args.config, args.config_fd) {
        (Some(path), None) => read_config(&path),
        (None, Some(fd)) if fd >= 0 => {
            // Ownership of the inherited descriptor is transferred by the CLI
            // contract. File closes it after the bounded read, including errors.
            let file = unsafe { File::from_raw_fd(fd) };
            let bytes = read_private_file_handle(file, MAX_CONFIG_BYTES)?;
            parse_config(&bytes)
        }
        _ => bail!("exactly one signer configuration source is required"),
    }
}

#[cfg(target_os = "macos")]
fn parse_config(bytes: &[u8]) -> anyhow::Result<SignerServeConfig> {
    let config: SignerServeConfig = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("signer configuration is invalid"))?;
    if config.max_connections != SERIAL_PROVIDER_MAX_CONNECTIONS {
        bail!("signer max_connections must be 1 because the FROST provider is serialized");
    }
    if config.format_version != CONFIG_FORMAT_VERSION
        || !config.listen_addr.ip().is_loopback()
        || config.device_generation == 0
        || config.protocol_profile != SignerProtocolProfile::FrostSecp256k1TrV1
        || !(MIN_ROUND_TIMEOUT_MS..=MAX_ROUND_TIMEOUT_MS).contains(&config.round_timeout_ms)
        || config.session_timeout_ms > MAX_SESSION_TIMEOUT_MS
        || config.session_timeout_ms
            < config
                .round_timeout_ms
                .checked_mul(u64::from(FROST_SIGNING_ROUNDS))
                .ok_or_else(|| anyhow::anyhow!("signer configuration is invalid"))?
        || config.max_frame_bytes == 0
        || config.max_frame_bytes > 64 * 1024
    {
        bail!("signer configuration is invalid");
    }
    for path in [
        &config.profile_path,
        &config.onepassword_executable,
        &config.server_cert_path,
        &config.server_key_path,
        &config.client_ca_cert_path,
    ] {
        if !path.is_absolute() {
            bail!("signer configuration is invalid");
        }
    }
    decode_spki_pin(&config.coordinator_spki_sha256_hex)?;
    Ok(config)
}

#[cfg(all(test, target_os = "macos"))]
mod tests;

#[cfg(target_os = "macos")]
fn read_profile(path: &Path) -> anyhow::Result<PersonalSignerProfile> {
    let bytes = read_private_file(path, MAX_PROFILE_BYTES)?;
    PersonalSignerProfile::from_bytes(&bytes)
        .map_err(|_| anyhow::anyhow!("personal signer profile is invalid"))
}

#[cfg(target_os = "macos")]
fn decode_spki_pin(encoded: &str) -> anyhow::Result<[u8; 32]> {
    if encoded.len() != 64 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("signer transport pin is invalid");
    }
    hex::decode(encoded)
        .map_err(|_| anyhow::anyhow!("signer transport pin is invalid"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("signer transport pin is invalid"))
}

#[cfg(target_os = "macos")]
fn read_private_file(path: &Path, max_bytes: u64) -> anyhow::Result<Vec<u8>> {
    let file = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| anyhow::anyhow!("private signer file is unavailable"))?;
    read_private_file_handle(File::from(file), max_bytes)
}

#[cfg(target_os = "macos")]
fn read_private_file_handle(file: File, max_bytes: u64) -> anyhow::Result<Vec<u8>> {
    let metadata =
        fstat(&file).map_err(|_| anyhow::anyhow!("private signer file is unavailable"))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_mode & 0o777 != 0o600
        || metadata.st_uid != geteuid().as_raw()
    {
        bail!("private signer file permissions are unsafe");
    }
    read_bounded(file, max_bytes, "private signer file is invalid")
}

#[cfg(target_os = "macos")]
fn read_public_file(path: &Path, max_bytes: u64) -> anyhow::Result<Vec<u8>> {
    let file = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| anyhow::anyhow!("signer certificate is unavailable"))?;
    let metadata =
        fstat(&file).map_err(|_| anyhow::anyhow!("signer certificate is unavailable"))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile {
        bail!("signer certificate is invalid");
    }
    read_bounded(File::from(file), max_bytes, "signer certificate is invalid")
}

#[cfg(target_os = "macos")]
fn read_bounded(file: File, max_bytes: u64, error: &'static str) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(usize::try_from(max_bytes).unwrap_or(0));
    let mut reader: Take<File> = file.take(max_bytes.saturating_add(1));
    reader
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!(error))?;
    if bytes.is_empty() || bytes.len() as u64 > max_bytes {
        bail!(error);
    }
    Ok(bytes)
}

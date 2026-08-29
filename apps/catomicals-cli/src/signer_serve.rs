use std::path::PathBuf;

use anyhow::bail;
use clap::{Args, Subcommand};

#[cfg(target_os = "macos")]
use std::{
    fs::File,
    io::{Read as _, Take},
    net::SocketAddr,
    path::Path,
    time::Duration,
};

#[cfg(target_os = "macos")]
use catomicals_secret_store::{
    DeviceKeyProvider, DeviceKeyWrapAlgorithm, DeviceWrapBinding, DeviceWrappedPackageV1,
    MacosSecureEnclaveProtector, OnePasswordWrappedPackageLoader,
};
#[cfg(target_os = "macos")]
use catomicals_signer_transport::{MtlsSignerServer, TransportLimits, private_ca_server_config};
#[cfg(target_os = "macos")]
use catomicals_threshold::{
    GuardedSignerProvider, LocalEncryptedFrostBackend, NonceGuard, PersonalParticipantRole,
    PersonalParticipantSecretPackage, PersonalSignerProfile, ProviderError, ProviderIdentity,
    ProviderRequestAuthorizer, ProviderRound, SIGNER_PROVIDER_PROTOCOL_VERSION,
};
#[cfg(target_os = "macos")]
use rustix::{
    fs::{FileType, Mode, OFlags, fstat, open},
    process::geteuid,
};
#[cfg(target_os = "macos")]
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
#[cfg(target_os = "macos")]
use serde::Deserialize;
#[cfg(target_os = "macos")]
use tokio::{net::TcpListener, runtime::Builder, sync::watch};
#[cfg(target_os = "macos")]
use uuid::Uuid;

#[cfg(target_os = "macos")]
const CONFIG_FORMAT_VERSION: u16 = 1;
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

#[derive(Debug, Subcommand)]
pub enum SignerCommand {
    Serve(ServeArgs),
}

#[derive(Debug, Args)]
pub struct ServeArgs {
    /// Private signer configuration file. It must be owned by the current user and mode 0600.
    #[arg(long, value_name = "FILE")]
    config: PathBuf,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignerServeConfig {
    format_version: u16,
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
    io_timeout_ms: u64,
    max_frame_bytes: usize,
    max_connections: usize,
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
    let config = read_config(&args.config)?;
    let profile = read_profile(&config.profile_path)?;
    let participant = load_desktop_participant(&config, &profile)?;
    let identity = signer_identity(&profile, config.device_id, config.device_generation)?;
    let backend = LocalEncryptedFrostBackend::new(
        participant,
        profile
            .public_key_package()
            .map_err(|_| anyhow::anyhow!("personal signer profile is invalid"))?,
        PersonalSignerAuthorizer {
            identity: identity.clone(),
        },
    );
    let provider = GuardedSignerProvider::new(identity, backend);

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
            io_timeout: Duration::from_millis(config.io_timeout_ms),
            max_frame_bytes: config.max_frame_bytes,
            max_connections: config.max_connections,
        },
    );

    let runtime = Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async move {
        let listener = TcpListener::bind(config.listen_addr)
            .await
            .map_err(|_| anyhow::anyhow!("signer listener could not start"))?;
        let bound = listener
            .local_addr()
            .map_err(|_| anyhow::anyhow!("signer listener could not start"))?;
        println!("personal signer ready on {bound}");
        let (_shutdown, receiver) = watch::channel(false);
        server
            .serve(listener, receiver)
            .await
            .map_err(|_| anyhow::anyhow!("signer transport stopped"))
    })
}

#[cfg(target_os = "macos")]
fn load_desktop_participant(
    config: &SignerServeConfig,
    profile: &PersonalSignerProfile,
) -> anyhow::Result<catomicals_threshold::LocalFrostParticipant> {
    let loaded = OnePasswordWrappedPackageLoader::new(
        config.onepassword_executable.clone(),
        config.wrapped_package_reference.clone(),
        Duration::from_millis(config.io_timeout_ms),
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
    let protector = MacosSecureEnclaveProtector::open(config.device_key_id.clone())
        .map_err(|_| {
            anyhow::anyhow!(
                "Secure Enclave signer key is unavailable; a signed helper with the required Keychain entitlement is required"
            )
        })?;
    let package_bytes = wrapped
        .open(&expected_binding, &protector)
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
struct PersonalSignerAuthorizer {
    identity: ProviderIdentity,
}

#[cfg(target_os = "macos")]
impl ProviderRequestAuthorizer for PersonalSignerAuthorizer {
    fn authorize(
        &mut self,
        context: &catomicals_threshold::SignerRequestContext,
        _round: ProviderRound,
    ) -> Result<(), ProviderError> {
        if context.protocol_version != SIGNER_PROVIDER_PROTOCOL_VERSION
            || context.wallet_id != self.identity.wallet_id
            || context.signer_set_id != self.identity.signer_set_id
            || context.signer_epoch != self.identity.signer_epoch
            || context.signer_id != self.identity.signer_id
            || context.device_id != self.identity.device_id
            || context.device_generation != self.identity.device_generation
            || context.group_pubkey_xonly != self.identity.group_pubkey_xonly
            || context.verifying_share_digest != self.identity.verifying_share_digest
            || context.min_signers != 2
            || context.max_signers != 3
        {
            return Err(ProviderError::IdentityDrift);
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn read_config(path: &Path) -> anyhow::Result<SignerServeConfig> {
    let bytes = read_private_file(path, MAX_CONFIG_BYTES)?;
    let config: SignerServeConfig = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("signer configuration is invalid"))?;
    if config.format_version != CONFIG_FORMAT_VERSION
        || !config.listen_addr.ip().is_loopback()
        || config.device_generation == 0
        || config.io_timeout_ms == 0
        || config.max_frame_bytes == 0
        || config.max_frame_bytes > 64 * 1024
        || config.max_connections == 0
        || config.max_connections > 64
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
    let metadata =
        fstat(&file).map_err(|_| anyhow::anyhow!("private signer file is unavailable"))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_mode & 0o777 != 0o600
        || metadata.st_uid != geteuid().as_raw()
    {
        bail!("private signer file permissions are unsafe");
    }
    read_bounded(
        File::from(file),
        max_bytes,
        "private signer file is invalid",
    )
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

use std::path::PathBuf;

use anyhow::Context;
use catomicals_secret_store::{FileSecretBackend, RuntimeProfile};
use catomicals_wallet_storage::WalletStorage;
use clap::{Args, Subcommand, ValueEnum};
use uuid::Uuid;

use crate::walletd::WALLET_DATABASE;

#[derive(Subcommand)]
pub enum BackupCommand {
    /// Export an encrypted SQLite snapshot and manifest.
    Export(ExportArgs),
    /// Authenticate, decrypt, checksum, and inspect a backup without restoring it.
    Verify(VerifyArgs),
    /// Atomically replace one wallet database and leave it in recovering state.
    Restore(RestoreArgs),
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum SecretProfile {
    Development,
    Production,
}

impl From<SecretProfile> for RuntimeProfile {
    fn from(profile: SecretProfile) -> Self {
        match profile {
            SecretProfile::Development => Self::Development,
            SecretProfile::Production => Self::Production,
        }
    }
}

#[derive(Args)]
pub struct SecretBackendArgs {
    /// Directory for the development-only encrypted file secret backend.
    #[arg(long, value_name = "DIR")]
    secret_dir: PathBuf,
    /// Runtime profile. The file backend deliberately rejects production.
    #[arg(long, value_enum)]
    profile: SecretProfile,
}

impl SecretBackendArgs {
    fn open(&self) -> anyhow::Result<FileSecretBackend> {
        FileSecretBackend::open(&self.secret_dir, self.profile.into()).map_err(Into::into)
    }
}

#[derive(Args)]
pub struct ExportArgs {
    /// Durable wallet data directory containing wallet.sqlite3.
    #[arg(long, value_name = "DIR")]
    data_dir: PathBuf,
    /// New output directory for this backup bundle.
    #[arg(long, value_name = "DIR")]
    out: PathBuf,
    #[command(flatten)]
    secrets: SecretBackendArgs,
}

#[derive(Args)]
pub struct VerifyArgs {
    /// Backup bundle containing manifest.json.
    #[arg(value_name = "BUNDLE")]
    bundle: PathBuf,
    #[command(flatten)]
    secrets: SecretBackendArgs,
}

#[derive(Args)]
pub struct RestoreArgs {
    /// Backup bundle containing manifest.json.
    #[arg(value_name = "BUNDLE")]
    bundle: PathBuf,
    /// Durable wallet data directory containing wallet.sqlite3.
    #[arg(long, value_name = "DIR")]
    data_dir: PathBuf,
    /// Wallet identity expected in both the live database and backup.
    #[arg(long)]
    wallet_id: Uuid,
    #[command(flatten)]
    secrets: SecretBackendArgs,
}

pub fn run(command: BackupCommand) -> anyhow::Result<()> {
    match command {
        BackupCommand::Export(args) => export(args),
        BackupCommand::Verify(args) => verify(args),
        BackupCommand::Restore(args) => restore(args),
    }
}

fn export(args: ExportArgs) -> anyhow::Result<()> {
    let backend = args.secrets.open()?;
    let database = args.data_dir.join(WALLET_DATABASE);
    let mut storage = WalletStorage::open(&database)
        .with_context(|| format!("cannot open durable wallet at {}", database.display()))?;
    let manifest = storage.export_encrypted_backup(&args.out, Some(&backend), now())?;
    println!("encrypted wallet backup exported");
    println!("  wallet_id       {}", manifest.wallet_id);
    println!("  recovery_epoch  {}", manifest.recovery_epoch);
    println!("  schema_version  {}", manifest.schema_version);
    println!("  bundle          {}", args.out.display());
    Ok(())
}

fn verify(args: VerifyArgs) -> anyhow::Result<()> {
    let backend = args.secrets.open()?;
    let manifest = WalletStorage::verify_encrypted_backup(&args.bundle, Some(&backend))?;
    println!("encrypted wallet backup verified");
    println!("  wallet_id       {}", manifest.wallet_id);
    println!("  recovery_epoch  {}", manifest.recovery_epoch);
    println!("  schema_version  {}", manifest.schema_version);
    Ok(())
}

fn restore(args: RestoreArgs) -> anyhow::Result<()> {
    let backend = args.secrets.open()?;
    let database = args.data_dir.join(WALLET_DATABASE);
    let storage = WalletStorage::restore_encrypted_backup(
        &database,
        &args.bundle,
        Some(&backend),
        args.wallet_id,
        now(),
    )?;
    let metadata = storage.wallet_metadata()?;
    println!("wallet backup cut over");
    println!("  wallet_id       {}", metadata.wallet_id);
    println!("  recovery_epoch  {}", metadata.epoch);
    println!("  state           recovering");
    println!("  next            complete node snapshot and signer availability checks");
    Ok(())
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

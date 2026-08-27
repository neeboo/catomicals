use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, bail};
use catomicals_policy_registry::{
    ActivationProposal, ActivationProposalInput, MAX_BUNDLE_BYTES, compile_policy_json,
    inspect_bundle,
};
use catomicals_wallet_storage::WalletStorage;
use clap::{Args, Subcommand};
use serde::Serialize;
use uuid::Uuid;

use crate::walletd::WALLET_DATABASE;

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Compile and execute vectors for a strict policy document.
    Compile(CompileArgs),
    /// Inspect a canonical bundle without opening wallet storage.
    Inspect(InspectArgs),
    /// Create a pending activation proposal. This never activates a policy.
    Activate(ActivateArgs),
}

#[derive(Debug, Args)]
pub struct CompileArgs {
    #[arg(value_name = "POLICY_JSON")]
    file: PathBuf,
    /// Existing durable wallet directory. When present, the exact bundle is
    /// stored atomically with its artifacts, vectors, validation and audit.
    #[arg(long, value_name = "DIR")]
    data_dir: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct InspectArgs {
    #[arg(value_name = "BUNDLE_JSON")]
    bundle: PathBuf,
}

#[derive(Debug, Args)]
pub struct ActivateArgs {
    #[arg(long, value_name = "DIR")]
    data_dir: PathBuf,
    #[arg(long)]
    policy_hash: String,
    #[arg(long)]
    signer_set_id: Uuid,
    #[arg(long)]
    signer_epoch: u64,
    #[arg(long)]
    expires_at: i64,
    /// Deterministic test/audit override; normally generated locally.
    #[arg(long)]
    activation_id: Option<Uuid>,
    /// Deterministic test/audit override; normally generated locally.
    #[arg(long)]
    binding_id: Option<Uuid>,
}

pub fn run(command: PolicyCommand) -> anyhow::Result<()> {
    match command {
        PolicyCommand::Compile(args) => compile(args),
        PolicyCommand::Inspect(args) => inspect(args),
        PolicyCommand::Activate(args) => activate(args),
    }
}

fn compile(args: CompileArgs) -> anyhow::Result<()> {
    let source = read_limited(&args.file, 64 * 1024)?;
    let bundle = compile_policy_json(&source)?;
    let bytes = bundle.to_bytes()?;
    if let Some(data_dir) = args.data_dir {
        let mut storage = WalletStorage::open(data_dir.join(WALLET_DATABASE))?;
        storage.store_policy_bundle_bytes(&bundle.policy_hash, &bytes, now())?;
    }
    io::stdout().lock().write_all(&bytes)?;
    Ok(())
}

fn inspect(args: InspectArgs) -> anyhow::Result<()> {
    let bytes = read_limited(&args.bundle, MAX_BUNDLE_BYTES)?;
    let bundle = inspect_bundle(&bytes)?;
    println!(
        "policy {} verified: {} artifacts, {} vectors, all vectors passed",
        bundle.policy_hash,
        bundle.artifacts.len(),
        bundle.test_vectors.len()
    );
    Ok(())
}

fn activate(args: ActivateArgs) -> anyhow::Result<()> {
    let mut storage = WalletStorage::open(args.data_dir.join(WALLET_DATABASE))?;
    let metadata = storage.wallet_metadata()?;
    let bytes = storage
        .policy_bundle_bytes(&args.policy_hash)?
        .with_context(|| {
            format!(
                "policy {} has not completed exact compiler and vector validation in this wallet",
                args.policy_hash
            )
        })?;
    let bundle = inspect_bundle(&bytes)?;
    if !bundle.validation_run.all_passed {
        bail!("policy has not completed exact compiler and vector validation");
    }
    let created_at = now();
    let proposal = ActivationProposal::new(ActivationProposalInput {
        activation_id: args.activation_id.unwrap_or_else(Uuid::new_v4),
        binding_id: args.binding_id.unwrap_or_else(Uuid::new_v4),
        policy_hash: bundle.policy_hash,
        wallet_id: metadata.wallet_id,
        wallet_epoch: metadata.epoch,
        signer_set_id: args.signer_set_id,
        signer_epoch: args.signer_epoch,
        chain_profile: catomicals_policy_registry::INQUISITION_SIGNET_PROFILE.to_owned(),
        artifact_set_digest: bundle.artifact_set_digest,
        validation_run_digest: bundle.validation_run.run_digest,
        expires_at: args.expires_at,
        created_at,
    })?;
    storage.propose_policy_activation(&proposal)?;
    let output = PendingActivationOutput {
        activation_id: proposal.activation_id,
        approval_digest: &proposal.approval_digest,
        authority_requirement: "Formal activation requires a future independent AuthorityIntent + Passkey atomic authorization chain. This pending proposal grants no signing authority, is not a transaction signature, and consumes no FROST nonce.",
        binding_id: proposal.binding_id,
        policy_hash: &proposal.policy_hash,
        state: "pending",
        wallet_epoch: proposal.wallet_epoch,
    };
    io::stdout()
        .lock()
        .write_all(&serde_jcs::to_vec(&output)?)?;
    Ok(())
}

#[derive(Serialize)]
struct PendingActivationOutput<'a> {
    activation_id: Uuid,
    approval_digest: &'a str,
    authority_requirement: &'static str,
    binding_id: Uuid,
    policy_hash: &'a str,
    state: &'static str,
    wallet_epoch: u64,
}

fn read_limited(path: &PathBuf, max: usize) -> anyhow::Result<Vec<u8>> {
    let metadata =
        fs::metadata(path).with_context(|| format!("failed to read {}", path.display()))?;
    if metadata.len() > max as u64 {
        bail!("{} exceeds the {} byte input limit", path.display(), max);
    }
    fs::read(path).with_context(|| format!("failed to read {}", path.display()))
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

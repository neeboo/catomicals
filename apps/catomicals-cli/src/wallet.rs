//! `wallet ...` — provider-neutral wallet primitives from the CLI.
//!
//! Everything here uses the same `WalletApi` surface the HTTP server and the
//! frontend use, so human UI, Codex and DeepSeek adapters achieve identical
//! outcomes (see `docs/adapters.md`).

use std::str::FromStr;

use anyhow::{Context, bail};
use catomicals_wallet::{
    ApprovalChallenge, ApprovalState, CreateIntentRequest, SigningIntent, WalletApi, WalletError,
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
    /// Local FROST participant ID in the ephemeral development DKG set.
    #[arg(long, default_value_t = 1)]
    pub signer_id: u16,
    /// Permit a public bind behind an operator-managed HTTPS reverse proxy.
    #[arg(long)]
    pub allow_non_loopback_bind: bool,
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
        WalletCommand::Approve(args) => approve(args),
        WalletCommand::Demo(args) => demo_flow(args),
    }
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
    let client = catomicals_node_client::rpc::connect(&config).ok()?;
    let report = catomicals_node_client::rpc::check_node_health(&client).ok()?;
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

//! catomicals — Catomicals wallet foundation CLI.
//!
//! Subcommands:
//! - `node health`   — validate a local Inquisition Signet node (cookie auth).
//! - `wallet ...`    — provider-neutral wallet intent API (status/intent/approval).
//! - `wallet serve`  — localhost-only HTTP surface for the wallet API.
//! - `frost demo`    — run the threshold BIP340 demo end-to-end.
//! - `signer ...`    — host a personal 1Password-backed FROST signer service.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

mod backup;
mod cordis_mcp;
mod frost_demo;
mod mcp;
mod node;
mod persistent_signer;
mod policy;
mod signer_serve;
mod wallet;
mod wallet_serve;
mod walletd;

#[derive(Parser)]
#[command(name = "catomicals", version, about = "Catomicals wallet foundation")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Node identity / health checks against Bitcoin Inquisition Signet.
    Node {
        #[command(subcommand)]
        cmd: node::NodeCommand,
    },
    /// Provider-neutral wallet intent API.
    Wallet {
        #[command(subcommand)]
        cmd: wallet::WalletCommand,
    },
    /// Run the FROST threshold BIP340 demo.
    Frost {
        #[command(subcommand)]
        cmd: frost_demo::FrostCommand,
    },
    /// Expose non-custodial wallet tools to Codex, DeepSeek, or another MCP client.
    Mcp {
        #[command(subcommand)]
        cmd: mcp::McpCommand,
    },
    /// Export, verify, or restore an encrypted single-wallet backup.
    Backup {
        #[command(subcommand)]
        cmd: backup::BackupCommand,
    },
    /// Compile, inspect, and propose activation of immutable policies.
    Policy {
        #[command(subcommand)]
        cmd: policy::PolicyCommand,
    },
    /// Serve a personal 1Password-backed FROST signer over pinned mTLS.
    Signer {
        #[command(subcommand)]
        cmd: signer_serve::SignerCommand,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Node { cmd } => node::run(cmd),
        Command::Wallet { cmd } => wallet::run(cmd),
        Command::Frost { cmd } => frost_demo::run(cmd),
        Command::Mcp { cmd } => mcp::run(cmd),
        Command::Backup { cmd } => backup::run(cmd),
        Command::Policy { cmd } => policy::run(cmd),
        Command::Signer { cmd } => signer_serve::run(cmd),
    }
}

/// Shared CLI args for anything that talks to a node.
#[derive(Debug, clap::Args, Clone)]
pub struct NodeArgs {
    /// Inquisition RPC URL (loopback only unless --allow-non-loopback).
    #[arg(long, env = "CATOMICALS_RPC_URL", default_value = catomicals_node_client::rpc::DEFAULT_SIGNET_RPC_URL)]
    pub rpc_url: String,
    /// Cookie file. Default: <datadir>/signet/.cookie, else ~/.bitcoin/signet/.cookie.
    #[arg(long)]
    pub cookie: Option<PathBuf>,
    /// Bitcoin datadir used to locate the cookie.
    #[arg(long)]
    pub datadir: Option<PathBuf>,
    /// Allow connecting to a non-loopback RPC host (tunnels only).
    #[arg(long)]
    pub allow_non_loopback: bool,
}

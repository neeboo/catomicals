//! `node health`: connect to a local Bitcoin Inquisition Signet node, verify
//! chain and OP_CAT activation, and print an honest report.

use std::path::Path;

use anyhow::{Context, bail};
use clap::{Args, Subcommand};

use crate::NodeArgs;
use catomicals_node_client::rpc::{self, NodeHealthReport, NodeRpcConfig};

#[derive(Subcommand)]
pub enum NodeCommand {
    /// Verify chain=signet and OP_CAT active against a local node.
    Health(HealthArgs),
}

#[derive(Args)]
pub struct HealthArgs {
    #[command(flatten)]
    pub node: NodeArgs,
    /// Emit the report as JSON instead of a human table.
    #[arg(long)]
    pub json: bool,
}

pub fn run(cmd: NodeCommand) -> anyhow::Result<()> {
    match cmd {
        NodeCommand::Health(args) => health(args),
    }
}

fn health(args: HealthArgs) -> anyhow::Result<()> {
    let config = NodeRpcConfig {
        rpc_url: args.node.rpc_url.clone(),
        cookie_path: args.node.cookie.clone(),
        data_dir: args.node.datadir.clone(),
        allow_non_loopback: args.node.allow_non_loopback,
    };

    // RPC must stay on loopback unless the operator opted into a tunnel.
    if let Err(e) = config.check_loopback() {
        bail!("refusing to dial a non-loopback node RPC: {e}");
    }

    // Resolve the cookie path *before* connecting so errors are actionable.
    let cookie_path = config.resolve_cookie_path();
    if !cookie_path.exists() {
        bail!(
            "cookie file not found at {} (start bitcoind, or pass --cookie/--datadir)",
            cookie_path.display()
        );
    }

    let client =
        rpc::connect(&config).with_context(|| format!("connecting to {}", config.rpc_url))?;
    let report = rpc::check_node_health(&client)
        .with_context(|| format!("health check against {}", config.rpc_url))?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_report(&report, &cookie_path);
    }

    if !report.identity_valid {
        bail!("node identity is not valid for the Catomicals wallet foundation");
    }
    Ok(())
}

fn print_report(r: &NodeHealthReport, cookie: &Path) {
    println!("bitcoin node health");
    println!("  chain        {}", r.chain);
    println!("  blocks       {} (headers {})", r.blocks, r.headers);
    println!("  subversion   {}", r.subversion);
    println!("  inquisition  {}", r.inquisition);
    println!(
        "  op_cat (BIP347) {} (kind={}{})",
        if r.op_cat.active {
            "ACTIVE"
        } else {
            "INACTIVE"
        },
        r.op_cat.kind,
        r.op_cat
            .height
            .map(|h| format!(", height={h}"))
            .unwrap_or_default()
    );
    println!(
        "  identity     {}",
        if r.identity_valid { "OK" } else { "INVALID" }
    );
    println!("  cookie       {}", cookie.display());
}

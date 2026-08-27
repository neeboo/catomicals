//! Outbound-only RPC health checks against a local Bitcoin Inquisition node.
//!
//! Connection policy:
//! - Default endpoint is loopback (`127.0.0.1:38332`, the default Signet RPC
//!   port). The wallet foundation never binds or listens.
//! - Authentication is exclusively cookie-based (`Auth::CookieFile`), matching
//!   Core's default `-server=1` setup. No passwords in process arguments.
//! - Non-loopback RPC URLs are rejected unless the operator opts in, and always
//!   warned about: the node config must keep RPC on loopback.

use std::path::{Path, PathBuf};

use bitcoincore_rpc::{Auth, Client, RpcApi};
use serde_json::Value;

use crate::deployment::{self, DeploymentStatus, OP_CAT_DEPLOYMENT_NAME};
use crate::{NodeIdentity, NodeIdentityError, is_inquisition_subversion};

/// Default Signet RPC endpoint on a local node.
pub const DEFAULT_SIGNET_RPC_URL: &str = "http://127.0.0.1:38332";
/// Default cookie location for the `signet` chain datadir.
pub const DEFAULT_COOKIE_REL: &str = "signet/.cookie";

#[derive(Debug, thiserror::Error)]
pub enum NodeRpcError {
    #[error("rpc transport error: {0}")]
    Rpc(#[from] bitcoincore_rpc::Error),
    #[error("could not read cookie file {path}: {source}")]
    Cookie {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cookie file {path} is empty")]
    EmptyCookie { path: PathBuf },
    #[error("identity validation failed: {0}")]
    Identity(#[from] NodeIdentityError),
    #[error("deployment check failed: {0}")]
    Deployment(#[from] deployment::DeploymentError),
    #[error("rpc url must use http or https, got `{0}`")]
    UnsupportedScheme(String),
    #[error("rpc url host is not loopback: `{0}`")]
    NonLoopback(String),
}

/// Connection configuration for the health check.
#[derive(Debug, Clone)]
pub struct NodeRpcConfig {
    pub rpc_url: String,
    pub cookie_path: Option<PathBuf>,
    pub data_dir: Option<PathBuf>,
    /// Allow connecting to a non-loopback host (advanced/tunneled setups).
    pub allow_non_loopback: bool,
}

impl Default for NodeRpcConfig {
    fn default() -> Self {
        Self {
            rpc_url: DEFAULT_SIGNET_RPC_URL.to_owned(),
            cookie_path: None,
            data_dir: None,
            allow_non_loopback: false,
        }
    }
}

impl NodeRpcConfig {
    /// Resolve the cookie file path: explicit override, else
    /// `<datadir>/signet/.cookie`, else `~/.bitcoin/signet/.cookie`.
    pub fn resolve_cookie_path(&self) -> PathBuf {
        if let Some(cp) = &self.cookie_path {
            return cp.clone();
        }
        let base = self
            .data_dir
            .as_deref()
            .map(Path::to_path_buf)
            .unwrap_or_else(default_bitcoin_dir);
        base.join(DEFAULT_COOKIE_REL)
    }

    /// Guard: RPC must never be dialed on a non-loopback address unless the
    /// operator explicitly opts in (tunnels). Public exposure of the node RPC
    /// is prevented by the node config (`rpcallowip=127.0.0.1`).
    pub fn check_loopback(&self) -> Result<(), NodeRpcError> {
        if self.allow_non_loopback {
            return Ok(());
        }
        let authority = self
            .rpc_url
            .strip_prefix("http://")
            .or_else(|| self.rpc_url.strip_prefix("https://"))
            .ok_or_else(|| NodeRpcError::UnsupportedScheme(self.rpc_url.clone()))?
            .split('/')
            .next()
            .unwrap_or("");
        let host = if let Some(bracketed) = authority.strip_prefix('[') {
            bracketed.split(']').next().unwrap_or("")
        } else {
            authority.split(':').next().unwrap_or("")
        };
        let loopback = host == "127.0.0.1" || host == "localhost" || host == "::1";
        if loopback {
            Ok(())
        } else {
            Err(NodeRpcError::NonLoopback(self.rpc_url.clone()))
        }
    }
}

fn default_bitcoin_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".bitcoin")
}

/// Open an RPC client using cookie authentication.
pub fn connect(config: &NodeRpcConfig) -> Result<Client, NodeRpcError> {
    config.check_loopback()?;
    if !config.rpc_url.starts_with("http://") && !config.rpc_url.starts_with("https://") {
        return Err(NodeRpcError::UnsupportedScheme(config.rpc_url.clone()));
    }
    let cookie_path = config.resolve_cookie_path();
    let cookie = std::fs::read(&cookie_path).map_err(|source| NodeRpcError::Cookie {
        path: cookie_path.clone(),
        source,
    })?;
    if cookie.is_empty() {
        return Err(NodeRpcError::EmptyCookie { path: cookie_path });
    }
    Ok(Client::new(&config.rpc_url, Auth::CookieFile(cookie_path))?)
}

/// A consolidated, honest health report.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NodeHealthReport {
    pub chain: String,
    pub blocks: u64,
    pub headers: u64,
    pub subversion: String,
    pub inquisition: bool,
    pub op_cat: DeploymentStatus,
    pub identity_valid: bool,
}

/// Query a node and validate that it is an Inquisition Signet node with
/// OP_CAT active. Reads only; never exposes RPC.
pub fn check_node_health(client: &Client) -> Result<NodeHealthReport, NodeRpcError> {
    let blockchain = client.get_blockchain_info()?;
    let network = client.get_network_info()?;
    let deployments: Value = client.call("getdeploymentinfo", &[])?;
    let op_cat = deployment::deployment_status(&deployments, OP_CAT_DEPLOYMENT_NAME)?;

    let chain = blockchain.chain.to_string();
    let identity = NodeIdentity {
        chain: chain.clone(),
        subversion: network.subversion.clone(),
        cat_active: op_cat.active,
    };
    let identity_valid = crate::validate_node_identity(&identity).is_ok();

    Ok(NodeHealthReport {
        chain,
        blocks: blockchain.blocks,
        headers: blockchain.headers,
        subversion: network.subversion.clone(),
        inquisition: is_inquisition_subversion(&network.subversion),
        op_cat,
        identity_valid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_loopback() {
        let cfg = NodeRpcConfig::default();
        assert!(cfg.check_loopback().is_ok());
    }

    #[test]
    fn non_loopback_rejected_by_default() {
        let cfg = NodeRpcConfig {
            rpc_url: "http://0.0.0.0:38332".into(),
            allow_non_loopback: false,
            ..Default::default()
        };
        assert!(cfg.check_loopback().is_err());
    }

    #[test]
    fn non_loopback_allowed_with_opt_in() {
        let cfg = NodeRpcConfig {
            rpc_url: "http://0.0.0.0:38332".into(),
            allow_non_loopback: true,
            ..Default::default()
        };
        assert!(cfg.check_loopback().is_ok());
    }

    #[test]
    fn cookie_path_resolution() {
        let cfg = NodeRpcConfig::default();
        let cfg = NodeRpcConfig {
            data_dir: Some(PathBuf::from("/tmp/datadir")),
            ..cfg
        };
        let p = cfg.resolve_cookie_path();
        assert_eq!(p, PathBuf::from("/tmp/datadir/signet/.cookie"));
        let overridden = NodeRpcConfig {
            cookie_path: Some(PathBuf::from("/custom/cookie")),
            ..Default::default()
        };
        assert_eq!(
            overridden.resolve_cookie_path(),
            PathBuf::from("/custom/cookie")
        );
    }

    #[test]
    fn configured_datadir_is_used_for_connection_cookie() {
        let cfg = NodeRpcConfig {
            data_dir: Some(PathBuf::from("/srv/bitcoin-inquisition")),
            ..Default::default()
        };
        assert_eq!(
            cfg.resolve_cookie_path(),
            PathBuf::from("/srv/bitcoin-inquisition/signet/.cookie")
        );
    }

    #[test]
    fn ipv6_loopback_is_accepted_but_near_matches_are_rejected() {
        let ipv6 = NodeRpcConfig {
            rpc_url: "http://[::1]:38332".into(),
            ..Default::default()
        };
        assert!(ipv6.check_loopback().is_ok());

        let near_match = NodeRpcConfig {
            rpc_url: "http://127.0.0.1.example:38332".into(),
            ..Default::default()
        };
        assert!(near_match.check_loopback().is_err());
    }
}

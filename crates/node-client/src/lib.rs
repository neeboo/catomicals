//! Catomicals node client: identify a Bitcoin Inquisition node on Signet with
//! OP_CAT (BIP 347) active.
//!
//! The client only ever connects *outbound* to the node's RPC; it never binds a
//! listener. The node itself must be configured with `rpcbind=127.0.0.1` and
//! `rpcallowip=127.0.0.1` (see `config/bitcoin-signet.conf`) so RPC is never
//! exposed publicly.

pub mod deployment;
pub mod rpc;

use serde::{Deserialize, Serialize};

/// The only chain Catomicals wallet foundations run on.
pub const EXPECTED_CHAIN: &str = "signet";

/// Identity facts used to accept/reject a node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeIdentity {
    /// Chain name reported by `getblockchaininfo` (`signet`).
    pub chain: String,
    /// `subversion` string reported by `getnetworkinfo`.
    pub subversion: String,
    /// Whether the OP_CAT (BIP 347) deployment is active.
    pub cat_active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NodeIdentityError {
    #[error("node reports chain `{0}`, expected `signet`")]
    WrongChain(String),
    #[error("OP_CAT (BIP 347) is not active on this node")]
    CatInactive,
}

/// Validate the identity facts. Deliberately independent of any RPC client so
/// it can be unit-tested without a node.
pub fn validate_node_identity(identity: &NodeIdentity) -> Result<(), NodeIdentityError> {
    if identity.chain != EXPECTED_CHAIN {
        return Err(NodeIdentityError::WrongChain(identity.chain.clone()));
    }
    if !identity.cat_active {
        return Err(NodeIdentityError::CatInactive);
    }
    Ok(())
}

/// Does this `subversion` string look like a Bitcoin Inquisition build?
///
/// Inquisition advertises itself with an `inq` marker in `-version`/subversion
/// (e.g. `/Satoshi:29.4.0(bitcoin-inquisition)/`). This is informational: the
/// hard requirements are chain and OP_CAT activation.
pub fn is_inquisition_subversion(subversion: &str) -> bool {
    subversion.to_ascii_lowercase().contains("inq")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(chain: &str, subversion: &str, cat_active: bool) -> NodeIdentity {
        NodeIdentity {
            chain: chain.to_owned(),
            subversion: subversion.to_owned(),
            cat_active,
        }
    }

    #[test]
    fn accepts_inquisition_on_signet_with_active_cat() {
        let identity = identity("signet", "/Satoshi:29.4.0(bitcoin-inquisition)/", true);
        assert_eq!(validate_node_identity(&identity), Ok(()));
        assert!(is_inquisition_subversion(&identity.subversion));
    }

    #[test]
    fn rejects_a_node_on_the_wrong_chain() {
        let identity = identity("main", "/Satoshi:29.4.0(bitcoin-inquisition)/", true);
        assert_eq!(
            validate_node_identity(&identity),
            Err(NodeIdentityError::WrongChain("main".to_owned()))
        );
    }

    #[test]
    fn rejects_signet_before_cat_activation() {
        let identity = identity("signet", "/Satoshi:29.4.0(bitcoin-inquisition)/", false);
        assert_eq!(
            validate_node_identity(&identity),
            Err(NodeIdentityError::CatInactive)
        );
    }

    #[test]
    fn inquisition_marker_detection() {
        assert!(is_inquisition_subversion(
            "/Satoshi:29.4.0(bitcoin-inquisition)/"
        ));
        assert!(!is_inquisition_subversion("/Satoshi:29.4.0/"));
        assert!(is_inquisition_subversion("/Satoshi:29.4.0(inq)/"));
    }
}

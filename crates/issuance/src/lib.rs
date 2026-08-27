//! Catomicals proof-of-work issuance gate on Bitcoin Inquisition.
//!
//! A creator defines issuance terms (item identity, PoW target, total supply,
//! successor rule). The issuer tapscript commits one state and enforces only
//! its proof-of-work challenge plus `remaining != 0`. OP_CAT cannot inspect
//! transaction outputs, so item ownership and successor-state transitions are
//! wallet policy, not OP_CAT-only consensus rules. The indexer only discovers
//! issuer-leaf reveals and unclassified P2TR candidates.
//!
//! Nothing here is a CAT20 token, a bridge, a platform token, or off-chain
//! settlement. This crate is Signet research code, not a production asset
//! protocol.

pub mod indexer;
pub mod models;
pub mod pow;
pub mod script;
pub mod state;
pub mod terms;
pub mod verify;

/// Protocol version of this implementation.
pub const PROTOCOL_VERSION: u32 = 1;
/// Signet is the only network this foundation runs on.
pub const EXPECTED_NETWORK: &str = "signet";

/// Convenience re-export of the issuer tapscript builder.
pub use script::issuer_script;

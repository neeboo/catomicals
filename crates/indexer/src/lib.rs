//! Rebuildable covenant discovery index.
//!
//! This crate is a query accelerator over raw Bitcoin blocks. Its records are
//! observations, never consensus truth, and wallet authorization or signing
//! must not depend on this database.

mod store;
mod types;

pub use store::{IndexError, Indexer, IndexerConfig};
pub use types::{
    ApplyStats, BlockRecord, CheckpointManifest, ConfirmationStatus, IssuanceTransitionRecord,
    ObservationKind, Provenance, RawEvidenceRef, Tip, TransactionRecord, UtxoRecord,
};

//! Stable signing identities, execution topology, and review bindings.

mod operation;
mod suite;

pub use operation::{MAX_SIGNER_SET_ID_BYTES, ReviewBinding};
pub use suite::{
    Capabilities, SignerBackendRequirement, SigningAlgorithm, SigningAvailability,
    SigningContractError, SigningExecutionMode, SigningSuite, SigningSuiteDescriptor,
    SigningSuiteId, require_executable_suite, resolve_builtin_suite,
};

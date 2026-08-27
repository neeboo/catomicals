// These package-internal tests need access to the crate-private legacy seam.
// Cargo runs the same source through `src/lib.rs` as `authorization_seam_tests`.
include!("../src/tests/authorization_seam.rs");

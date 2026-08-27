// These package-internal tests need access to crate-private authorization
// construction. Cargo runs this source through `src/lib.rs`.
include!("../src/tests/security_requirements.rs");

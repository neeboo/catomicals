use catomicals_policy_registry::{compile_policy_json, inspect_bundle};

const ISSUANCE: &[u8] = include_bytes!("../../../docs/policies/examples/issuance-v1.json");
const LISTING: &[u8] =
    include_bytes!("../../../docs/policies/examples/fixed-price-listing-v1.json");
const SCHEMA: &str = include_str!("../../../schemas/agent/policy-object.schema.json");

#[test]
fn documented_examples_compile_and_round_trip_through_the_rust_contract() {
    for document in [ISSUANCE, LISTING] {
        let bundle = compile_policy_json(document).unwrap();
        inspect_bundle(&bundle.to_bytes().unwrap()).unwrap();
    }
}

#[test]
fn public_schema_keeps_lifecycle_outside_the_hashed_document_and_locks_v1_hashing() {
    let schema: serde_json::Value = serde_json::from_str(SCHEMA).unwrap();
    let encoded = serde_json::to_string(&schema).unwrap();
    assert!(!encoded.contains("lifecycle_state"));
    assert_eq!(
        schema["$defs"]["digestAlgorithm"]["const"],
        serde_json::json!("sha256")
    );
    assert_eq!(
        schema["$defs"]["canonicalization"]["const"],
        serde_json::json!("catomicals-policy-jcs-v1")
    );
    assert!(encoded.contains("content_ref"));
    assert!(encoded.contains("compile_document"));
    assert!(encoded.contains("verify_policy_hash"));
    assert!(encoded.contains("verify_artifact"));
}

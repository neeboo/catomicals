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
fn draft_2020_12_schema_accepts_both_real_compiler_bundles_without_errors() {
    let schema: serde_json::Value = serde_json::from_str(SCHEMA).unwrap();
    let validator = jsonschema::draft202012::options().build(&schema).unwrap();

    for document in [ISSUANCE, LISTING] {
        let instance = serde_json::to_value(compile_policy_json(document).unwrap()).unwrap();
        let errors: Vec<_> = validator
            .iter_errors(&instance)
            .map(|error| error.to_string())
            .collect();
        assert!(errors.is_empty(), "schema validation errors: {errors:#?}");
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

#[test]
fn candidate_document_allows_runner_rejected_business_values_only() {
    let schema: serde_json::Value = serde_json::from_str(SCHEMA).unwrap();
    let validator = jsonschema::draft202012::options().build(&schema).unwrap();
    let instance = serde_json::to_value(compile_policy_json(ISSUANCE).unwrap()).unwrap();
    let vector_index = instance["test_vectors"]
        .as_array()
        .unwrap()
        .iter()
        .position(|vector| vector["vector_id"] == "negative.zero_supply")
        .unwrap();

    assert_eq!(
        instance["test_vectors"][vector_index]["input"]["document"]["input"]["total_supply"],
        serde_json::json!(0)
    );
    assert!(validator.is_valid(&instance));

    let mut wrong_profile = instance.clone();
    wrong_profile["test_vectors"][vector_index]["input"]["document"]["network"]["deployment_profile"] =
        serde_json::json!("unapproved-profile");
    assert!(!validator.is_valid(&wrong_profile));

    let mut unknown_field = instance;
    unknown_field["test_vectors"][vector_index]["input"]["document"]["unknown"] =
        serde_json::json!(true);
    assert!(!validator.is_valid(&unknown_field));
}

#[test]
fn bundle_root_document_keeps_full_business_validation() {
    let schema: serde_json::Value = serde_json::from_str(SCHEMA).unwrap();
    let validator = jsonschema::draft202012::options().build(&schema).unwrap();
    let mut instance = serde_json::to_value(compile_policy_json(ISSUANCE).unwrap()).unwrap();
    instance["document"]["input"]["total_supply"] = serde_json::json!(0);

    assert!(!validator.is_valid(&instance));
}

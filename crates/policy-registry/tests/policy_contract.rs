use catomicals_policy_registry::{
    CompileError, MAX_BUNDLE_BYTES, POLICY_CANONICALIZATION, POLICY_COMPILER_VERSION, PolicyBundle,
    compile_policy_json, inspect_bundle,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

const ISSUANCE: &str = r#"{
  "schema_version": 1,
  "canonicalization": "catomicals-policy-jcs-v1",
  "digest_algorithm": "sha256",
  "network": {
    "bitcoin_network": "signet",
    "deployment_profile": "bitcoin-inquisition-signet-v29.4-op-cat",
    "op_cat": "required"
  },
  "policy_kind": "catomicals-issuance-v1",
  "name": "demo issuance",
  "input": {
    "item_id": "4242424242424242424242424242424242424242424242424242424242424242",
    "target_prefix": 1,
    "total_supply": 4,
    "successor_rule": "recursive_issuer",
    "lane_count": 1,
    "salt": "7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a",
    "metadata_base64": "Y2F0b21pY2FscyBkZW1vIGl0ZW0="
  }
}"#;

const LISTING: &str = r#"{
  "schema_version": 1,
  "canonicalization": "catomicals-policy-jcs-v1",
  "digest_algorithm": "sha256",
  "network": {
    "bitcoin_network": "signet",
    "deployment_profile": "bitcoin-inquisition-signet-v29.4-op-cat",
    "op_cat": "required"
  },
  "policy_kind": "catomicals-fixed-price-listing-v1",
  "name": "one concrete fixed price order",
  "input": {
    "receipt": {
      "txid": "1111111111111111111111111111111111111111111111111111111111111111",
      "vout": 2,
      "script_pubkey_hex": "5120531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337",
      "item_sat_amount": 10000,
      "terms_hash": "2222222222222222222222222222222222222222222222222222222222222222",
      "item_id": "3333333333333333333333333333333333333333333333333333333333333333",
      "item_commitment": "4444444444444444444444444444444444444444444444444444444444444444",
      "lane": 0,
      "sequence": 7
    },
    "seller_key": "531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337",
    "seller_payout_script_hex": "512062c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f7",
    "price_sat": 60000,
    "creator_fee_script_hex": "5120f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a",
    "creator_fee_sat": 3000,
    "cancel_script_hex": "5120531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337",
    "expiry_height": 240144,
    "max_network_fee_sat": 2000
  }
}"#;

#[test]
fn jcs_hash_is_fixed_and_ignores_object_key_order() {
    let compiled = compile_policy_json(ISSUANCE.as_bytes()).unwrap();
    assert_eq!(
        compiled.document.canonicalization(),
        POLICY_CANONICALIZATION
    );
    assert_eq!(
        compiled.policy_hash,
        "sha256:98d886619311839462ec3c3f713cf9d92acb3254eebce5736153c061d88242ae"
    );

    let value: serde_json::Value = serde_json::from_str(ISSUANCE).unwrap();
    let reordered = serde_json::to_vec(&value).unwrap();
    assert_eq!(
        compile_policy_json(&reordered).unwrap().policy_hash,
        compiled.policy_hash
    );

    let changed = ISSUANCE.replace("demo issuance", "demo issuance changed");
    assert_ne!(
        compile_policy_json(changed.as_bytes()).unwrap().policy_hash,
        compiled.policy_hash
    );
}

#[test]
fn duplicate_unknown_and_lifecycle_fields_are_rejected_before_hashing() {
    let duplicate = ISSUANCE.replacen(
        "\"schema_version\": 1,",
        "\"schema_version\": 1, \"schema_version\": 1,",
        1,
    );
    assert!(matches!(
        compile_policy_json(duplicate.as_bytes()),
        Err(CompileError::InvalidJson(_))
    ));

    let lifecycle = ISSUANCE.replacen(
        "\"name\": \"demo issuance\",",
        "\"name\": \"demo issuance\", \"lifecycle_state\": \"active\",",
        1,
    );
    assert!(matches!(
        compile_policy_json(lifecycle.as_bytes()),
        Err(CompileError::InvalidJson(_))
    ));
}

#[test]
fn issuance_compilation_locks_protocol_bytes_and_runs_executable_vectors() {
    let bundle = compile_policy_json(ISSUANCE.as_bytes()).unwrap();
    assert_eq!(bundle.compiler_version, POLICY_COMPILER_VERSION);
    assert!(bundle.validation_run.all_passed);
    assert_eq!(bundle.artifacts.len(), 4);
    assert!(
        bundle
            .artifacts
            .iter()
            .all(|artifact| artifact.content_ref == format!("inline:{}", artifact.artifact_id))
    );

    let artifact = |kind: &str| {
        bundle
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == kind)
            .unwrap()
    };
    assert_eq!(
        artifact("issuance_terms").content_digest,
        "sha256:0e20e3afc134a12293cb1dde901e0abdd7d8359be17a5b842bb6241b03ccfd2a"
    );
    assert_eq!(
        artifact("issuer_tapscript").content_hex,
        "200e20e3afc134a12293cb1dde901e0abdd7d8359be17a5b842bb6241b03ccfd2a0501000000000501040000000201010201005479517955795b795d797e7e7e7ea85159797e876952790501000000008791697575757575757575757551"
    );
    assert!(
        bundle
            .test_vectors
            .iter()
            .any(|vector| vector.expected_accept)
    );
    assert!(
        bundle
            .test_vectors
            .iter()
            .any(|vector| !vector.expected_accept)
    );
    inspect_bundle(&bundle.to_bytes().unwrap()).unwrap();
}

#[test]
fn issuance_rejects_zero_supply_bad_lanes_and_oversized_metadata() {
    let zero = ISSUANCE.replace("\"total_supply\": 4", "\"total_supply\": 0");
    assert!(matches!(
        compile_policy_json(zero.as_bytes()),
        Err(CompileError::InvalidIssuance(_))
    ));

    let lanes = ISSUANCE.replace("\"lane_count\": 1", "\"lane_count\": 2");
    assert!(matches!(
        compile_policy_json(lanes.as_bytes()),
        Err(CompileError::InvalidIssuance(_))
    ));

    let oversized = ISSUANCE.replace(
        "Y2F0b21pY2FscyBkZW1vIGl0ZW0=",
        &base64::Engine::encode(&base64::engine::general_purpose::STANDARD, vec![0u8; 4097]),
    );
    assert!(matches!(
        compile_policy_json(oversized.as_bytes()),
        Err(CompileError::InvalidIssuance(_))
    ));
}

#[test]
fn bundle_inspection_rejects_document_and_artifact_tampering() {
    let bundle = compile_policy_json(ISSUANCE.as_bytes()).unwrap();
    let mut body: serde_json::Value = serde_json::from_slice(&bundle.to_bytes().unwrap()).unwrap();
    body["document"]["name"] = serde_json::json!("tampered");
    assert!(inspect_bundle(&serde_jcs::to_vec(&body).unwrap()).is_err());

    let mut artifact: PolicyBundle = serde_json::from_slice(&bundle.to_bytes().unwrap()).unwrap();
    artifact.artifacts[0].content_hex.push_str("00");
    assert!(inspect_bundle(&serde_jcs::to_vec(&artifact).unwrap()).is_err());
}

#[test]
fn inspection_rejects_an_oversized_bundle_before_json_parsing() {
    let oversized = vec![b' '; MAX_BUNDLE_BYTES + 1];
    assert!(matches!(
        inspect_bundle(&oversized),
        Err(CompileError::LimitExceeded("policy bundle"))
    ));
}

#[test]
fn inspection_rejects_rehashed_artifacts_that_were_not_compiler_outputs() {
    let mut bundle = compile_policy_json(ISSUANCE.as_bytes()).unwrap();
    let artifact = &mut bundle.artifacts[0];
    artifact.content_hex.push_str("00");
    artifact.content_digest = sha256(&hex::decode(&artifact.content_hex).unwrap());
    artifact.artifact_id = format!(
        "{}:{}:{}",
        artifact.kind,
        artifact
            .lane
            .map_or_else(|| "global".to_owned(), |lane| lane.to_string()),
        artifact.content_digest
    );
    artifact.content_ref = format!("inline:{}", artifact.artifact_id);
    bundle.artifact_set_digest = sha256(&serde_jcs::to_vec(&bundle.artifacts).unwrap());
    bundle.validation_run.artifact_set_digest = bundle.artifact_set_digest.clone();
    bundle.validation_run.run_digest = validation_run_digest(&bundle);

    assert!(inspect_bundle(&bundle.to_bytes().unwrap()).is_err());
}

#[test]
fn compile_output_is_byte_for_byte_deterministic() {
    assert_eq!(
        compile_policy_json(ISSUANCE.as_bytes())
            .unwrap()
            .to_bytes()
            .unwrap(),
        compile_policy_json(ISSUANCE.as_bytes())
            .unwrap()
            .to_bytes()
            .unwrap()
    );
}

#[test]
fn fixed_price_listing_compiles_the_exact_existing_order_instance() {
    let bundle = compile_policy_json(LISTING.as_bytes()).unwrap();
    let artifact = |kind: &str| {
        bundle
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == kind)
            .unwrap()
    };
    assert_eq!(bundle.artifacts.len(), 6);
    assert_eq!(
        artifact("listing_commitment").content_hex,
        "4c96ce2192aa3bd8e30ab95ba84e1d0f88fb947e4e677a43e81f2624b4bce904"
    );
    assert_eq!(
        artifact("buy_leaf").content_hex,
        "204c96ce2192aa3bd8e30ab95ba84e1d0f88fb947e4e677a43e81f2624b4bce9047520531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337ac"
    );
    assert_eq!(
        artifact("cancel_leaf").content_hex,
        "0310aa03b175204c96ce2192aa3bd8e30ab95ba84e1d0f88fb947e4e677a43e81f2624b4bce9047520531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337ac"
    );
    assert_eq!(
        artifact("listing_output").content_hex,
        "5120f6cf2eddf0d2f7333ae887867e72d1dee7962d868e51c78aded22514ca9c0a94"
    );
    assert!(bundle.validation_run.all_passed);
    inspect_bundle(&bundle.to_bytes().unwrap()).unwrap();
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn validation_run_digest(bundle: &PolicyBundle) -> String {
    #[derive(Serialize)]
    struct DigestInput<'a> {
        compiler_version: &'a str,
        policy_hash: &'a str,
        artifact_set_digest: &'a str,
        vector_set_digest: &'a str,
        results: &'a [catomicals_policy_registry::VectorResult],
        all_passed: bool,
    }

    sha256(
        &serde_jcs::to_vec(&DigestInput {
            compiler_version: &bundle.validation_run.compiler_version,
            policy_hash: &bundle.validation_run.policy_hash,
            artifact_set_digest: &bundle.validation_run.artifact_set_digest,
            vector_set_digest: &bundle.validation_run.vector_set_digest,
            results: &bundle.validation_run.results,
            all_passed: bundle.validation_run.all_passed,
        })
        .unwrap(),
    )
}

use catomicals_chain_domain::{
    ChainCapabilities, ChainId, ChainNetwork, ChainScope, ChainSuite, ReviewArtifact,
    ReviewContractError,
};

fn accepts_object_safe_chain_suite(_: &dyn ChainSuite) {}

#[test]
fn chain_suite_contract_is_object_safe() {
    let _ = accepts_object_safe_chain_suite;
}

#[test]
fn review_artifact_is_versioned_bounded_and_secret_free() {
    let scope = ChainScope::for_network(ChainNetwork::Bitcoin(
        catomicals_chain_domain::BitcoinNetwork::Signet,
    ));
    let artifact = ReviewArtifact::new(
        scope,
        [0x11; 32],
        [0x22; 32],
        "send 12 sats to tb1p…".to_owned(),
    )
    .unwrap();

    assert_eq!(artifact.schema_version, 1);
    assert_eq!(artifact.scope.chain, ChainId::Bitcoin);
    assert_eq!(artifact.review_digest, [0x11; 32]);
    assert_eq!(artifact.signing_message_digest, [0x22; 32]);
    assert!(!serde_json::to_string(&artifact).unwrap().contains("secret"));

    assert_eq!(
        ReviewArtifact::new(scope, [0; 32], [0; 32], "x".repeat(4097)),
        Err(ReviewContractError::SummaryTooLong { max_bytes: 4096 })
    );
}

#[test]
fn review_artifact_deserialization_revalidates_version_and_bounds() {
    let valid = ReviewArtifact::new(
        ChainScope::for_network(ChainNetwork::Bitcoin(
            catomicals_chain_domain::BitcoinNetwork::Signet,
        )),
        [0x11; 32],
        [0x22; 32],
        "summary".to_owned(),
    )
    .unwrap();
    let mut value = serde_json::to_value(valid).unwrap();

    value["schema_version"] = 2.into();
    assert!(serde_json::from_value::<ReviewArtifact>(value.clone()).is_err());

    value["schema_version"] = 1.into();
    value["summary"] = "x".repeat(4097).into();
    assert!(serde_json::from_value::<ReviewArtifact>(value).is_err());
}

#[test]
fn chain_capabilities_are_explicit_and_stably_serialized() {
    let capabilities = ChainCapabilities {
        address_derivation: true,
        transaction_review: true,
        final_signature_verification: true,
        broadcast: false,
    };

    assert_eq!(
        serde_json::to_string(&capabilities).unwrap(),
        r#"{"address_derivation":true,"transaction_review":true,"final_signature_verification":true,"broadcast":false}"#
    );
}

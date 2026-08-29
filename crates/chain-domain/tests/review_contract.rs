use catomicals_chain_domain::{
    ChainCapabilities, ChainId, ChainNetwork, ChainScope, ChainSuite, MAX_REVIEW_MATERIAL_BYTES,
    ReviewArtifact, ReviewContractError,
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
        vec![0x33; 128],
    )
    .unwrap();

    assert_eq!(artifact.schema_version, 2);
    assert_eq!(artifact.scope.chain, ChainId::Bitcoin);
    assert_eq!(artifact.review_digest, [0x11; 32]);
    assert_eq!(artifact.signing_message_digest, [0x22; 32]);
    assert_eq!(artifact.reviewed_material, vec![0x33; 128]);
    assert!(!serde_json::to_string(&artifact).unwrap().contains("secret"));

    assert_eq!(
        ReviewArtifact::new(scope, [0; 32], [0; 32], "x".repeat(4097), vec![1]),
        Err(ReviewContractError::SummaryTooLong { max_bytes: 4096 })
    );
    assert_eq!(
        ReviewArtifact::new(scope, [0; 32], [0; 32], "ok".to_owned(), vec![]),
        Err(ReviewContractError::MissingReviewedMaterial)
    );
    assert_eq!(
        ReviewArtifact::new(
            scope,
            [0; 32],
            [0; 32],
            "ok".to_owned(),
            vec![0; MAX_REVIEW_MATERIAL_BYTES + 1],
        ),
        Err(ReviewContractError::ReviewedMaterialTooLong {
            max_bytes: MAX_REVIEW_MATERIAL_BYTES,
        })
    );
}

#[test]
fn review_artifact_deserialization_revalidates_version_and_bounds() {
    let scope = ChainScope::for_network(ChainNetwork::Bitcoin(
        catomicals_chain_domain::BitcoinNetwork::Signet,
    ));
    let valid = ReviewArtifact::new(
        scope,
        [0x11; 32],
        [0x22; 32],
        "summary".to_owned(),
        vec![1, 2, 3],
    )
    .unwrap();
    let mut value = serde_json::to_value(&valid).unwrap();
    assert!(serde_json::from_value::<ReviewArtifact>(value.clone()).is_ok());

    let mut missing_material = serde_json::to_value(&valid).unwrap();
    missing_material
        .as_object_mut()
        .unwrap()
        .remove("reviewed_material");
    assert!(serde_json::from_value::<ReviewArtifact>(missing_material).is_err());

    value["schema_version"] = 1.into();
    assert!(serde_json::from_value::<ReviewArtifact>(value.clone()).is_err());

    value["schema_version"] = 2.into();
    value["summary"] = "x".repeat(4097).into();
    assert!(serde_json::from_value::<ReviewArtifact>(value).is_err());

    let mut oversized = serde_json::json!({
        "schema_version": 2,
        "scope": scope,
        "review_digest": vec![0; 32],
        "signing_message_digest": vec![0; 32],
        "summary": "summary",
        "reviewed_material": vec![0; MAX_REVIEW_MATERIAL_BYTES + 1],
    });
    assert!(serde_json::from_value::<ReviewArtifact>(oversized.clone()).is_err());
    oversized["reviewed_material"] = serde_json::json!([]);
    assert!(serde_json::from_value::<ReviewArtifact>(oversized).is_err());
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

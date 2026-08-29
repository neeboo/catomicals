use catomicals_chain_domain::{ChainCapabilities, ChainSuite, ErgoNetwork};
use catomicals_chain_ergo::{
    ErgoAdapterError, ErgoChainSuite, ErgoReviewMaterialV1, ErgoSigningSuite,
    ErgoThresholdNonceReplayGuard, ErgoThresholdNonceReservation, ErgoThresholdSigningPackage,
    ErgoThresholdSigningRequest, aggregate_threshold_p2pk_proof_2_of_3,
    assemble_threshold_p2pk_transaction, dealer_split_threshold_secret_2_of_3,
    generate_threshold_nonces_2_of_3, sign_threshold_share_2_of_3,
};
use catomicals_signing_domain::{ReviewBinding, SigningSuiteId};
use ergo_lib::chain::{
    ergo_box::box_builder::ErgoBoxCandidateBuilder,
    parameters::Parameters,
    transaction::{DataInput, Transaction, UnsignedInput, unsigned::UnsignedTransaction},
};
use ergo_lib::ergo_chain_types::{Header, PreHeader};
use ergo_lib::ergotree_ir::{
    chain::{
        address::Address,
        context_extension::ContextExtension,
        ergo_box::{ErgoBox, box_value::BoxValue},
        tx_id::TxId,
    },
    ergo_tree::{ErgoTree, ErgoTreeHeader},
    mir::{constant::Constant, expr::Expr},
    serialization::SigmaSerializable,
};
use ergo_lib::wallet::secret_key::SecretKey;
use std::collections::BTreeMap;

#[derive(Default)]
struct MemoryReplayGuard(BTreeMap<[u8; 32], bool>);

impl ErgoThresholdNonceReplayGuard for MemoryReplayGuard {
    fn reserve(
        &mut self,
        reservation: &ErgoThresholdNonceReservation,
    ) -> Result<(), ErgoAdapterError> {
        if self
            .0
            .insert(reservation.nonce_fingerprint, false)
            .is_some()
        {
            return Err(ErgoAdapterError::ThresholdNonceReplay(
                "duplicate reservation".into(),
            ));
        }
        Ok(())
    }

    fn consume(
        &mut self,
        reservation: &ErgoThresholdNonceReservation,
        _transcript_digest: [u8; 32],
    ) -> Result<(), ErgoAdapterError> {
        match self.0.get_mut(&reservation.nonce_fingerprint) {
            Some(consumed @ false) => {
                *consumed = true;
                Ok(())
            }
            _ => Err(ErgoAdapterError::ThresholdNonceReplay(
                "nonce already consumed".into(),
            )),
        }
    }
}

const UPSTREAM_MAINNET_HEADER: &str = r#"{
  "extensionId":"a1c5a5f409fce4d16a501371b11aaaf0e0a44609d8436958c383e12f9c14528c",
  "difficulty":"1371769604669440",
  "votes":"000000",
  "timestamp":1627249021284,
  "size":221,
  "stateRoot":"1d3d031ba060245d8184948c6f726a8bb98a1bc621affc4a1dcf0e20226eb27716",
  "height":540000,
  "nBits":117759902,
  "version":2,
  "id":"96911575efdceb082b974aa3042263be07632de48031aa2204d77d8d5a8240b8",
  "adProofsRoot":"aa0d212ec398d9558b2b2f24239963bdd8d2d22f70b6e8b5cfff3474609bcdde",
  "transactionsRoot":"235a6e8f28f54fef5fbcd17d2638eb03ef9cfb331f4b5a50fbb74df4a524dcb4",
  "extensionHash":"badffc4d646e1c2babcf1ce8422b4f2430b6262c947c964671e97486d8bdb601",
  "powSolutions":{
    "pk":"02b3a06d6eaa8671431ba1db4dd427a77f75a5c2acbd71bfb725d38adc2b55f669",
    "w":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "n":"0537288a2c246648",
    "d":0
  },
  "adProofsId":"13856ec4123971268ff0d7493bfa520021c6328ceba648bf39484b45761f4edf",
  "transactionsId":"5871d44565a08892d03f3e4f53a3d98a7f21e549738fff0864bce205916a5bfb",
  "parentId":"c55f05c91fea37f95eff73dfa62e8745f54db6dff5e9f257e39b9c0cfbfd8133"
}"#;

fn fixture(network: ErgoNetwork) -> (ErgoReviewMaterialV1, [u8; 32]) {
    // Scorex/SigmaState SigningSpecification ProveDlog scalar.
    let secret_bytes = [
        0xf2, 0xa3, 0xd9, 0x63, 0xdf, 0x15, 0x91, 0x97, 0x1c, 0xd4, 0x45, 0x5b, 0x41, 0xcc, 0xa9,
        0x24, 0x5b, 0xf6, 0x84, 0xe1, 0xdc, 0x66, 0x80, 0x49, 0xc4, 0xca, 0x84, 0x68, 0x98, 0x07,
        0xc6, 0xb2,
    ];
    let secret = SecretKey::dlog_from_bytes(&secret_bytes).expect("valid upstream scalar");
    let input_candidate = ErgoBoxCandidateBuilder::new(
        BoxValue::SAFE_USER_MIN,
        secret
            .get_address_from_public_image()
            .script()
            .expect("P2PK script"),
        1_000,
    )
    .build()
    .expect("input candidate");
    let input_box =
        ErgoBox::from_box_candidate(&input_candidate, TxId::zero(), 0).expect("input box");
    let output = ErgoBoxCandidateBuilder::new(
        BoxValue::SAFE_USER_MIN,
        secret
            .get_address_from_public_image()
            .script()
            .expect("P2PK script"),
        1_000,
    )
    .build()
    .expect("output candidate");
    let data_candidate = ErgoBoxCandidateBuilder::new(BoxValue::SAFE_USER_MIN, tree_true(), 900)
        .build()
        .expect("data candidate");
    let data_box = ErgoBox::from_box_candidate(&data_candidate, TxId::zero(), 1).expect("data box");
    let unsigned_tx = UnsignedTransaction::new_from_vec(
        vec![UnsignedInput::new(
            input_box.box_id(),
            ContextExtension::empty(),
        )],
        vec![DataInput::from(data_box.box_id())],
        vec![output],
    )
    .expect("unsigned tx");
    let header: Header = serde_json::from_str(UPSTREAM_MAINNET_HEADER).expect("upstream header");
    let pre_header = PreHeader::from(header.clone());
    let headers = std::array::from_fn(|_| header.clone());
    (
        ErgoReviewMaterialV1::new(
            network,
            pre_header,
            unsigned_tx,
            vec![input_box],
            vec![data_box],
            headers,
            Parameters::default(),
        )
        .expect("review material"),
        secret_bytes,
    )
}

fn tree_true() -> ErgoTree {
    ErgoTree::new(ErgoTreeHeader::v0(true), &Expr::Const(Constant::from(true))).unwrap()
}

#[test]
fn p2pk_review_sign_and_final_validation_use_full_ergo_transaction() {
    let (material, secret) = fixture(ErgoNetwork::Mainnet);
    let upstream_secret = SecretKey::dlog_from_bytes(&secret).unwrap();
    let Address::P2Pk(upstream_public_key) = upstream_secret.get_address_from_public_image() else {
        panic!("the upstream ProveDlog scalar must produce a P2PK key");
    };
    assert_eq!(
        upstream_public_key.sigma_serialize_bytes().unwrap(),
        vec![
            0x03, 0xcb, 0x0d, 0x49, 0xe4, 0xea, 0xe7, 0xe5, 0x70, 0x59, 0xa3, 0xda, 0x8a, 0xc5,
            0x26, 0x26, 0xd2, 0x6f, 0xc1, 0x13, 0x30, 0xaf, 0x8f, 0xb0, 0x93, 0xfa, 0x59, 0x7d,
            0x8b, 0x93, 0xde, 0xb7, 0xb1,
        ]
    );
    let encoded = material.encode().expect("canonical encoding");
    assert_eq!(ErgoReviewMaterialV1::decode(&encoded).unwrap(), material);

    let chain = ErgoChainSuite::new(ErgoNetwork::Mainnet);
    assert_eq!(
        chain.capabilities(),
        ChainCapabilities {
            address_derivation: true,
            transaction_review: true,
            final_signature_verification: true,
            broadcast: false,
        }
    );
    let review = chain.review_transaction(&encoded).expect("review");
    let signed = ErgoSigningSuite::new(ErgoNetwork::Mainnet)
        .unwrap()
        .sign_p2pk(&review, &secret)
        .expect("signed transaction");
    chain
        .verify_finalized_signature(&review, &signed)
        .expect("consensus-valid transaction");
}

#[test]
fn review_is_network_bound_and_rejects_non_p2pk_input_trees() {
    let (material, _) = fixture(ErgoNetwork::Testnet);
    let encoded = material.encode().unwrap();
    assert!(
        ErgoChainSuite::new(ErgoNetwork::Mainnet)
            .review_transaction(&encoded)
            .is_err()
    );

    let (mut p2s, _) = fixture(ErgoNetwork::Testnet);
    p2s.input_boxes[0].ergo_tree = tree_true();
    let encoded = p2s.encode().unwrap();
    assert!(
        ErgoChainSuite::new(ErgoNetwork::Testnet)
            .review_transaction(&encoded)
            .is_err()
    );

    let (mut p2sh, _) = fixture(ErgoNetwork::Testnet);
    p2sh.input_boxes[0].ergo_tree = Address::P2SH([7_u8; 24]).script().unwrap();
    assert!(
        ErgoChainSuite::new(ErgoNetwork::Testnet)
            .review_transaction(&p2sh.encode().unwrap())
            .is_err()
    );
}

#[test]
fn review_artifact_rejects_every_consensus_context_tamper() {
    let (material, secret) = fixture(ErgoNetwork::Mainnet);
    let chain = ErgoChainSuite::new(ErgoNetwork::Mainnet);
    let review = chain
        .review_transaction(&material.encode().unwrap())
        .unwrap();
    let signed = ErgoSigningSuite::new(ErgoNetwork::Mainnet)
        .unwrap()
        .sign_p2pk(&review, &secret)
        .unwrap();

    let mut variants = Vec::new();

    let mut signing_bytes = material.clone();
    signing_bytes.bytes_to_sign[0] ^= 1;
    variants.push(signing_bytes);

    let mut input_box = material.clone();
    input_box.input_boxes[0].creation_height += 1;
    variants.push(input_box);

    let mut data_box = material.clone();
    data_box.data_boxes[0].creation_height += 1;
    variants.push(data_box);

    let mut output = material.clone();
    output
        .unsigned_tx
        .output_candidates
        .iter_mut()
        .next()
        .unwrap()
        .creation_height += 1;
    variants.push(output);

    let mut context = material.clone();
    context
        .unsigned_tx
        .inputs
        .iter_mut()
        .next()
        .unwrap()
        .extension
        .values
        .insert(1, Constant::from(7_i32));
    variants.push(context);

    let mut header = material.clone();
    header.headers[0].timestamp += 1;
    variants.push(header);

    let mut pre_header = material.clone();
    pre_header.pre_header.timestamp += 1;
    variants.push(pre_header);

    let mut parameters = material.clone();
    use ergo_lib::chain::parameters::Parameter;
    parameters
        .parameters
        .parameters_table
        .insert(Parameter::InputCost, 2_001);
    variants.push(parameters);

    for tampered_material in variants {
        let mut tampered_review = review.clone();
        tampered_review.reviewed_material = tampered_material.encode().unwrap();
        assert!(
            chain
                .verify_finalized_signature(&tampered_review, &signed)
                .is_err()
        );
    }

    let mut wrong_network = material;
    wrong_network.network = ErgoNetwork::Testnet;
    let mut tampered_review = review.clone();
    tampered_review.reviewed_material = wrong_network.encode().unwrap();
    assert!(
        chain
            .verify_finalized_signature(&tampered_review, &signed)
            .is_err()
    );
}

#[test]
fn finalized_transaction_rejects_output_and_context_extension_tampering() {
    let (material, secret) = fixture(ErgoNetwork::Testnet);
    let chain = ErgoChainSuite::new(ErgoNetwork::Testnet);
    let review = chain
        .review_transaction(&material.encode().unwrap())
        .unwrap();
    let signed_bytes = ErgoSigningSuite::new(ErgoNetwork::Testnet)
        .unwrap()
        .sign_p2pk(&review, &secret)
        .unwrap();
    let signed = Transaction::sigma_parse_bytes(&signed_bytes).unwrap();

    let mut changed_output = signed.clone();
    changed_output
        .output_candidates
        .iter_mut()
        .next()
        .unwrap()
        .creation_height += 1;
    assert!(
        chain
            .verify_finalized_signature(&review, &changed_output.sigma_serialize_bytes().unwrap())
            .is_err()
    );

    let mut changed_context = signed;
    changed_context
        .inputs
        .iter_mut()
        .next()
        .unwrap()
        .spending_proof
        .extension
        .values
        .insert(1, Constant::from(9_i32));
    assert!(
        chain
            .verify_finalized_signature(&review, &changed_context.sigma_serialize_bytes().unwrap())
            .is_err()
    );
}

#[test]
fn canonical_material_rejects_trailing_and_oversized_encodings() {
    let (material, _) = fixture(ErgoNetwork::Testnet);
    let mut trailing = material.encode().unwrap();
    trailing.push(0);
    assert!(ErgoReviewMaterialV1::decode(&trailing).is_err());

    let oversized = vec![0_u8; catomicals_chain_domain::MAX_REVIEW_MATERIAL_BYTES + 1];
    assert!(ErgoReviewMaterialV1::decode(&oversized).is_err());
}

#[test]
fn p2pk_signing_rejects_wrong_secret_and_tampered_artifacts() {
    let (material, _) = fixture(ErgoNetwork::Testnet);
    let chain = ErgoChainSuite::new(ErgoNetwork::Testnet);
    let review = chain
        .review_transaction(&material.encode().unwrap())
        .unwrap();
    let wrong_secret = [2_u8; 32];
    assert!(matches!(
        ErgoSigningSuite::new(ErgoNetwork::Testnet)
            .unwrap()
            .sign_p2pk(&review, &wrong_secret),
        Err(ErgoAdapterError::SigmaSigning(_))
    ));

    let mut forged = review.clone();
    forged.signing_message_digest[0] ^= 1;
    assert!(
        chain
            .verify_finalized_signature(&forged, &[0_u8; 16])
            .is_err()
    );
}

#[test]
fn threshold_proof_is_assembled_into_and_validates_as_a_full_ergo_transaction() {
    let (material, group_secret) = fixture(ErgoNetwork::Testnet);
    let chain = ErgoChainSuite::new(ErgoNetwork::Testnet);
    let review = chain
        .review_transaction(&material.encode().unwrap())
        .unwrap();
    let binding = ReviewBinding::new(
        review.scope,
        SigningSuiteId::ERGO_SIGMA_P2PK_THRESHOLD_2OF3_V1,
        "ergo-threshold-fixture",
        1,
        review.schema_version,
        review.review_digest,
    )
    .unwrap();
    let session_id = [0x73; 32];
    let request = ErgoThresholdSigningRequest::new(&review, &binding, session_id).unwrap();
    assert_eq!(
        request.runtime().signing_suite.id,
        SigningSuiteId::ERGO_SIGMA_P2PK_THRESHOLD_2OF3_V1
    );
    let dealer = dealer_split_threshold_secret_2_of_3(group_secret, [0x23; 32]).unwrap();
    let mut replay_guard = MemoryReplayGuard::default();
    let first_nonces =
        generate_threshold_nonces_2_of_3(&dealer.shares()[0], session_id, &mut replay_guard)
            .unwrap();
    let third_nonces =
        generate_threshold_nonces_2_of_3(&dealer.shares()[2], session_id, &mut replay_guard)
            .unwrap();
    let package = ErgoThresholdSigningPackage::for_review(
        dealer.commitment(),
        &request,
        &[first_nonces.commitments(), third_nonces.commitments()],
    )
    .unwrap();
    let proof = aggregate_threshold_p2pk_proof_2_of_3(
        dealer.commitment(),
        &package,
        &[
            sign_threshold_share_2_of_3(
                dealer.commitment(),
                &dealer.shares()[0],
                first_nonces,
                &binding,
                &package,
                &mut replay_guard,
            )
            .unwrap(),
            sign_threshold_share_2_of_3(
                dealer.commitment(),
                &dealer.shares()[2],
                third_nonces,
                &binding,
                &package,
                &mut replay_guard,
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let mut forged_review = review.clone();
    forged_review.review_digest[0] ^= 1;
    assert!(
        assemble_threshold_p2pk_transaction(
            &forged_review,
            &binding,
            dealer.commitment(),
            std::slice::from_ref(&proof),
        )
        .is_err()
    );
    let signed = assemble_threshold_p2pk_transaction(
        &review,
        &binding,
        dealer.commitment(),
        std::slice::from_ref(&proof),
    )
    .unwrap();

    chain.verify_finalized_signature(&review, &signed).unwrap();
}

#[test]
fn threshold_request_rejects_single_signer_profile_drift() {
    let (material, _) = fixture(ErgoNetwork::Testnet);
    let review = ErgoChainSuite::new(ErgoNetwork::Testnet)
        .review_transaction(&material.encode().unwrap())
        .unwrap();
    let isolated_binding = ReviewBinding::new(
        review.scope,
        SigningSuiteId::ERGO_SIGMA_P2PK_ISOLATED_V1,
        "wrong-ergo-profile",
        1,
        review.schema_version,
        review.review_digest,
    )
    .unwrap();

    assert!(matches!(
        ErgoThresholdSigningRequest::new(&review, &isolated_binding, [0x81; 32]),
        Err(ErgoAdapterError::ThresholdSuiteContractMismatch)
    ));
}

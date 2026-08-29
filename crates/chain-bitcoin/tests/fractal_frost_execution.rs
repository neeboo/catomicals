use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, absolute,
    hashes::Hash, sighash::TapSighashType, transaction,
};
use catomicals_chain_bitcoin::{
    BitcoinAdapterError, BitcoinChainSuite, FractalExecutionError, FractalFrostExecutionAdapter,
    FractalFrostSessionContext, FractalFrostSigner, FractalNodeRpc, FractalNodeRpcTransport,
    TaprootKeySpendRequest, TaprootReviewMaterial, derive_p2tr_address,
    derive_p2tr_output_key_address,
};
use catomicals_chain_domain::{
    ChainNetwork, ChainScope, ChainSuite, FractalBitcoinNetwork, ReviewContractError,
};
use catomicals_threshold::{
    AuthorizationError, FrostCoordinator, LocalDkgOutput, LocalFrostParticipant, NonceGuard,
    SigningAuthorization, group_pubkey_xonly, participant_identifier, run_local_dkg,
    signature_to_bytes,
};

const SIGNER_SET_ID: &str = "fractal-primary-2-of-3";
const SIGNER_SET_EPOCH: u64 = 7;

fn fractal(network: FractalBitcoinNetwork) -> ChainScope {
    ChainScope::for_network(ChainNetwork::FractalBitcoin(network))
}

#[derive(Debug)]
struct ExactAuthorization {
    session_id: [u8; 32],
    message: [u8; 32],
    signer_id: u16,
    consumed: bool,
}

impl SigningAuthorization for ExactAuthorization {
    fn authorize(
        &mut self,
        session_id: &[u8; 32],
        message: &[u8; 32],
        signer_id: u16,
        _now: i64,
    ) -> Result<(), AuthorizationError> {
        if self.consumed {
            return Err(AuthorizationError::AlreadyConsumed);
        }
        if session_id != &self.session_id {
            return Err(AuthorizationError::WrongSession);
        }
        if message != &self.message {
            return Err(AuthorizationError::WrongMessage);
        }
        if signer_id != self.signer_id {
            return Err(AuthorizationError::WrongSigner);
        }
        self.consumed = true;
        Ok(())
    }
}

fn unsigned_transaction() -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([42; 32]), 1),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: ScriptBuf::new_op_return([]),
        }],
    }
}

fn frost_fixture() -> ([u8; 32], LocalDkgOutput) {
    let dkg = run_local_dkg(3, 2).expect("2-of-3 DKG");
    let group_key = group_pubkey_xonly(&dkg.public_key_package).expect("group key");
    (group_key, dkg)
}

fn frost_signature_for(dkg: LocalDkgOutput, payload: [u8; 32]) -> [u8; 64] {
    frost_signature_for_session(dkg, [91; 32], payload)
}

fn frost_signature_for_session(
    mut dkg: LocalDkgOutput,
    session_id: [u8; 32],
    payload: [u8; 32],
) -> [u8; 64] {
    let mut coordinator =
        FrostCoordinator::new(session_id, payload, 2, dkg.public_key_package.clone());
    let mut participants = BTreeMap::new();
    for signer_id in [1_u16, 2] {
        let key = dkg
            .key_packages
            .remove(&participant_identifier(signer_id).expect("identifier"))
            .expect("participant key");
        let mut participant =
            LocalFrostParticipant::new(signer_id, key, NonceGuard::new()).expect("participant");
        let commitment = participant.round1(session_id, payload).expect("round one");
        coordinator
            .add_commitment(signer_id, commitment)
            .expect("commitment");
        participants.insert(signer_id, participant);
    }
    let session = coordinator.signing_session().expect("signing session");
    for (signer_id, participant) in &mut participants {
        let mut authorization = ExactAuthorization {
            session_id,
            message: payload,
            signer_id: *signer_id,
            consumed: false,
        };
        let share = participant
            .round2(&session, &mut authorization, 1_800_000_000)
            .expect("round two");
        coordinator
            .add_signature_share(*signer_id, share)
            .expect("signature share");
    }
    let signature = coordinator.finalize().expect("aggregate signature");
    signature_to_bytes(&signature).expect("BIP340 signature")
}

#[test]
fn fractal_networks_finalize_a_real_frost_key_spend() {
    for network in [
        FractalBitcoinNetwork::Testnet3,
        FractalBitcoinNetwork::Testnet4,
        FractalBitcoinNetwork::Signet,
        FractalBitcoinNetwork::Regtest,
    ] {
        let scope = fractal(network);

        // The FROST group key is already the BIP341 output key. It must not be
        // silently TapTweak'ed a second time by an internal-key address helper.
        let (group_key, dkg) = frost_fixture();
        let output_key = bitcoin::XOnlyPublicKey::from_slice(&group_key).expect("x-only key");
        let address = derive_p2tr_output_key_address(scope, output_key).expect("Fractal address");
        assert_eq!(address.scope(), scope);
        assert_ne!(
            address.script_pubkey(),
            derive_p2tr_address(scope, output_key)
                .expect("internal-key address")
                .script_pubkey(),
            "FROST output key must not receive a second TapTweak"
        );
        let expected_prefix = match network {
            FractalBitcoinNetwork::Testnet3 => "bc1p",
            FractalBitcoinNetwork::Testnet4 | FractalBitcoinNetwork::Signet => "tb1p",
            FractalBitcoinNetwork::Regtest => "bcrt1p",
            FractalBitcoinNetwork::Mainnet => unreachable!(),
        };
        assert!(address.to_string().starts_with(expected_prefix));

        let request = TaprootKeySpendRequest::new(
            scope,
            unsigned_transaction(),
            vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: address.script_pubkey(),
            }],
            0,
            TapSighashType::Default,
        )
        .expect("Fractal key-spend request");
        let suite = BitcoinChainSuite::new(scope, output_key).expect("Fractal chain suite");
        let material = TaprootReviewMaterial::from_request(&request)
            .expect("review material")
            .encode()
            .expect("canonical review material");
        let review = suite.review_transaction(&material).expect("review");

        let signature = frost_signature_for(dkg, review.signing_message_digest);

        let finalized = suite
            .finalize_reviewed_key_spend(&review, signature)
            .expect("review-bound aggregate signature finalizes");
        assert_eq!(finalized.scope(), scope);
        assert_eq!(finalized.input_index(), 0);
        assert_eq!(finalized.transaction().input[0].witness.len(), 1);
        suite
            .verify_finalized_key_spend(&review, &finalized)
            .expect("the actual signed transaction verifies");
        suite
            .verify_finalized_transaction(&review, finalized.transaction())
            .expect("serialized transaction witness verifies");
    }
}

#[test]
fn finalization_rejects_scope_and_review_drift() {
    let scope = fractal(FractalBitcoinNetwork::Signet);
    let (group_key, dkg) = frost_fixture();
    let output_key = bitcoin::XOnlyPublicKey::from_slice(&group_key).expect("x-only key");
    let address = derive_p2tr_output_key_address(scope, output_key).expect("address");
    let request = TaprootKeySpendRequest::new(
        scope,
        unsigned_transaction(),
        vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: address.script_pubkey(),
        }],
        0,
        TapSighashType::Default,
    )
    .unwrap();
    let suite = BitcoinChainSuite::new(scope, output_key).unwrap();
    let review = suite
        .review_transaction(
            &TaprootReviewMaterial::from_request(&request)
                .unwrap()
                .encode()
                .unwrap(),
        )
        .unwrap();
    let signature = frost_signature_for(dkg, review.signing_message_digest);

    let wrong_scope =
        BitcoinChainSuite::new(fractal(FractalBitcoinNetwork::Regtest), output_key).unwrap();
    assert!(matches!(
        wrong_scope.finalize_reviewed_key_spend(&review, signature),
        Err(ReviewContractError::InvalidFinalizedSignature(_))
    ));

    let mut drifted = review.clone();
    drifted.signing_message_digest[0] ^= 1;
    assert!(matches!(
        suite.finalize_reviewed_key_spend(&drifted, signature),
        Err(ReviewContractError::InvalidFinalizedSignature(_))
    ));

    let finalized = suite
        .finalize_reviewed_key_spend(&review, signature)
        .expect("original review and signature");
    let mut transaction_drift = finalized.transaction().clone();
    transaction_drift.output[0].value = Amount::from_sat(89_999);
    assert!(matches!(
        suite.verify_finalized_transaction(&review, &transaction_drift),
        Err(ReviewContractError::InvalidFinalizedSignature(_))
    ));

    let mut witness_drift = finalized.transaction().clone();
    witness_drift.input[0].witness.push([0_u8; 64]);
    assert!(matches!(
        suite.verify_finalized_transaction(&review, &witness_drift),
        Err(ReviewContractError::InvalidFinalizedSignature(_))
    ));
}

#[test]
fn fractal_mainnet_signing_remains_fail_closed() {
    let key = bitcoin::XOnlyPublicKey::from_slice(&[
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98,
    ])
    .unwrap();
    let address =
        derive_p2tr_output_key_address(fractal(FractalBitcoinNetwork::Mainnet), key).unwrap();
    assert!(address.to_string().starts_with("bc1p"));
    assert!(matches!(
        BitcoinChainSuite::new(fractal(FractalBitcoinNetwork::Mainnet), key),
        Err(BitcoinAdapterError::MainnetNotActivated { .. })
    ));
}

fn fractal_material(scope: ChainScope, output_key: bitcoin::XOnlyPublicKey) -> Vec<u8> {
    let address = derive_p2tr_output_key_address(scope, output_key).unwrap();
    let request = TaprootKeySpendRequest::new(
        scope,
        unsigned_transaction(),
        vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: address.script_pubkey(),
        }],
        0,
        TapSighashType::Default,
    )
    .unwrap();
    TaprootReviewMaterial::from_request(&request)
        .unwrap()
        .encode()
        .unwrap()
}

#[test]
fn wallet_adapter_reproduces_review_binding_before_returning_the_final_witness() {
    let scope = fractal(FractalBitcoinNetwork::Signet);
    let (group_key, dkg) = frost_fixture();
    let output_key = bitcoin::XOnlyPublicKey::from_slice(&group_key).unwrap();
    let adapter =
        FractalFrostExecutionAdapter::new(scope, output_key, SIGNER_SET_ID, SIGNER_SET_EPOCH)
            .unwrap();
    let material = fractal_material(scope, output_key);

    let signing_session_id = [77; 32];
    let signing = adapter
        .prepare(&material, signing_session_id)
        .expect("wallet signing request");
    assert_eq!(signing.scope(), scope);
    assert_eq!(signing.review_binding().chain_scope, scope);
    assert_eq!(
        signing.review_binding().signing_suite_id,
        catomicals_signing_domain::SigningSuiteId::FractalBitcoinBip340FrostV1
    );
    assert_eq!(signing.review_binding().signer_set_id, SIGNER_SET_ID);
    assert_eq!(signing.review_binding().signer_set_epoch, SIGNER_SET_EPOCH);
    assert_eq!(
        signing.review_binding().review_schema_version,
        signing.review().schema_version
    );
    assert_eq!(
        signing.review_binding().review_digest,
        signing.review().review_digest
    );
    let binding_json = serde_json::to_value(signing.review_binding()).unwrap();
    let binding_round_trip: catomicals_signing_domain::ReviewBinding =
        serde_json::from_value(binding_json).unwrap();
    assert_eq!(&binding_round_trip, signing.review_binding());
    assert_eq!(
        signing.signing_message(),
        signing.review().signing_message_digest
    );

    let expected_binding = signing.review_binding().clone();
    let mut signer = FixtureFractalSigner {
        dkg: Some(dkg),
        observed_session: None,
    };
    let finalized = adapter
        .finalize_with_signer(signing, &mut signer)
        .expect("review-bound finalization");
    assert_eq!(finalized.scope(), scope);
    assert_eq!(finalized.review_binding(), &expected_binding);
    assert_eq!(finalized.witness().len(), 64);
    let observed = signer.observed_session.expect("signer saw the session");
    assert_eq!(observed.0, signing_session_id);
    assert_eq!(observed.1, expected_binding.domain_separator());

    assert!(matches!(
        FractalFrostExecutionAdapter::new(
            ChainScope::for_network(ChainNetwork::Bitcoin(
                catomicals_chain_domain::BitcoinNetwork::Signet
            )),
            output_key,
            SIGNER_SET_ID,
            SIGNER_SET_EPOCH,
        ),
        Err(FractalExecutionError::WrongChain(_))
    ));
}

struct FixtureFractalSigner {
    dkg: Option<LocalDkgOutput>,
    observed_session: Option<([u8; 32], Vec<u8>)>,
}

impl FractalFrostSigner for FixtureFractalSigner {
    fn sign(&mut self, session: &FractalFrostSessionContext<'_>) -> Result<[u8; 64], String> {
        self.observed_session = Some((
            session.signing_session_id(),
            session.review_binding().domain_separator(),
        ));
        Ok(frost_signature_for_session(
            self.dkg.take().expect("one signing attempt"),
            session.signing_session_id(),
            session.signing_message(),
        ))
    }
}

#[test]
fn wallet_adapter_rejects_partial_taproot_sighash_modes() {
    let scope = fractal(FractalBitcoinNetwork::Signet);
    let (group_key, _) = frost_fixture();
    let output_key = bitcoin::XOnlyPublicKey::from_slice(&group_key).unwrap();
    let address = derive_p2tr_output_key_address(scope, output_key).unwrap();
    let request = TaprootKeySpendRequest::new(
        scope,
        unsigned_transaction(),
        vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: address.script_pubkey(),
        }],
        0,
        TapSighashType::Single,
    )
    .unwrap();
    let material = TaprootReviewMaterial::from_request(&request)
        .unwrap()
        .encode()
        .unwrap();
    let adapter =
        FractalFrostExecutionAdapter::new(scope, output_key, SIGNER_SET_ID, SIGNER_SET_EPOCH)
            .unwrap();
    assert!(matches!(
        adapter.prepare(&material, [42; 32]),
        Err(FractalExecutionError::UnsupportedSighash { .. })
    ));
}

#[derive(Debug)]
struct StrictMockRpc {
    state: Rc<RefCell<StrictMockRpcState>>,
}

#[derive(Debug)]
struct StrictMockRpcState {
    calls: RefCell<Vec<(String, serde_json::Value)>>,
    responses: RefCell<Vec<Result<serde_json::Value, String>>>,
}

impl StrictMockRpc {
    fn new(
        responses: Vec<Result<serde_json::Value, String>>,
    ) -> (Self, Rc<RefCell<StrictMockRpcState>>) {
        let state = Rc::new(RefCell::new(StrictMockRpcState {
            calls: RefCell::new(Vec::new()),
            responses: RefCell::new(responses.into_iter().rev().collect()),
        }));
        (
            Self {
                state: Rc::clone(&state),
            },
            state,
        )
    }
}

impl FractalNodeRpcTransport for StrictMockRpc {
    fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
        let state = self.state.borrow();
        state.calls.borrow_mut().push((method.to_owned(), params));
        state
            .responses
            .borrow_mut()
            .pop()
            .expect("strict mock requires one response per call")
    }
}

fn finalized_fixture() -> catomicals_chain_bitcoin::FractalFinalizedKeySpend {
    let scope = fractal(FractalBitcoinNetwork::Regtest);
    let (group_key, dkg) = frost_fixture();
    let output_key = bitcoin::XOnlyPublicKey::from_slice(&group_key).unwrap();
    let adapter =
        FractalFrostExecutionAdapter::new(scope, output_key, SIGNER_SET_ID, SIGNER_SET_EPOCH)
            .unwrap();
    let material = fractal_material(scope, output_key);
    let signing = adapter.prepare(&material, [19; 32]).unwrap();
    let mut signer = FixtureFractalSigner {
        dkg: Some(dkg),
        observed_session: None,
    };
    adapter.finalize_with_signer(signing, &mut signer).unwrap()
}

fn verified_regtest_responses(
    responses: impl IntoIterator<Item = Result<serde_json::Value, String>>,
) -> Vec<Result<serde_json::Value, String>> {
    vec![
        Ok(serde_json::json!({ "chain": "regtest" })),
        Ok(serde_json::Value::String(
            "createindexerblock \"address\"\nSubmit via submitindexerblock".to_owned(),
        )),
    ]
    .into_iter()
    .chain(responses)
    .collect()
}

#[test]
fn node_rpc_requires_testmempoolaccept_before_sendrawtransaction() {
    let finalized = finalized_fixture();
    let txid = finalized.txid().to_string();
    let (transport, state) = StrictMockRpc::new(verified_regtest_responses([
        Ok(serde_json::json!([{
            "txid": txid,
            "wtxid": finalized.wtxid().to_string(),
            "allowed": true
        }])),
        Ok(serde_json::Value::String(txid.clone())),
    ]));
    let rpc = FractalNodeRpc::connect(fractal(FractalBitcoinNetwork::Regtest), transport).unwrap();

    assert_eq!(
        rpc.preflight_and_broadcast(&finalized)
            .expect("preflight then broadcast")
            .to_string(),
        txid
    );

    let state = state.borrow();
    let calls = state.calls.borrow();
    assert_eq!(calls.len(), 4);
    assert_eq!(
        calls[0],
        ("getblockchaininfo".to_owned(), serde_json::json!([]))
    );
    assert_eq!(
        calls[1],
        ("help".to_owned(), serde_json::json!(["createindexerblock"]))
    );
    assert_eq!(calls[2].0, "testmempoolaccept");
    assert_eq!(calls[3].0, "sendrawtransaction");
    assert_eq!(calls[2].1[0][0], calls[3].1[0]);
}

#[test]
fn node_rpc_never_broadcasts_rejected_or_mismatched_transactions() {
    let finalized = finalized_fixture();
    let txid = finalized.txid().to_string();
    let (rejected, rejected_state) =
        StrictMockRpc::new(verified_regtest_responses([Ok(serde_json::json!([{
            "txid": txid,
            "wtxid": finalized.wtxid().to_string(),
            "allowed": false,
            "reject-reason": "mandatory-script-verify-flag-failed"
        }]))]));
    let rpc = FractalNodeRpc::connect(fractal(FractalBitcoinNetwork::Regtest), rejected).unwrap();
    assert!(matches!(
        rpc.test_mempool_accept(&finalized),
        Err(FractalExecutionError::MempoolRejected { .. })
    ));
    assert_eq!(rejected_state.borrow().calls.borrow().len(), 3);

    let (mismatched, mismatched_state) =
        StrictMockRpc::new(verified_regtest_responses([Ok(serde_json::json!([{
            "txid": Txid::from_byte_array([99; 32]).to_string(),
            "wtxid": finalized.wtxid().to_string(),
            "allowed": true
        }]))]));
    let rpc = FractalNodeRpc::connect(fractal(FractalBitcoinNetwork::Regtest), mismatched).unwrap();
    assert!(matches!(
        rpc.test_mempool_accept(&finalized),
        Err(FractalExecutionError::RpcTransactionMismatch { .. })
    ));
    assert_eq!(mismatched_state.borrow().calls.borrow().len(), 3);

    let (wrong_network, wrong_network_state) = StrictMockRpc::new(verified_regtest_responses([]));
    assert!(matches!(
        FractalNodeRpc::connect(fractal(FractalBitcoinNetwork::Signet), wrong_network),
        Err(FractalExecutionError::NodeNetworkMismatch { .. })
    ));
    assert_eq!(wrong_network_state.borrow().calls.borrow().len(), 1);
}

#[test]
fn node_rpc_rejects_non_fractal_nodes_and_missing_or_wrong_wtxid() {
    let (bitcoin_core, bitcoin_core_state) = StrictMockRpc::new(vec![
        Ok(serde_json::json!({ "chain": "regtest" })),
        Err("Method not found".to_owned()),
    ]);
    assert!(matches!(
        FractalNodeRpc::connect(fractal(FractalBitcoinNetwork::Regtest), bitcoin_core),
        Err(FractalExecutionError::NodeIdentityMismatch { .. })
    ));
    assert_eq!(bitcoin_core_state.borrow().calls.borrow().len(), 2);

    let finalized = finalized_fixture();
    let txid = finalized.txid().to_string();
    for entry in [
        serde_json::json!({ "txid": txid, "allowed": true }),
        serde_json::json!({
            "txid": txid,
            "wtxid": bitcoin::Wtxid::from_byte_array([88; 32]).to_string(),
            "allowed": true
        }),
    ] {
        let (transport, state) =
            StrictMockRpc::new(verified_regtest_responses([Ok(serde_json::json!([entry]))]));
        let rpc =
            FractalNodeRpc::connect(fractal(FractalBitcoinNetwork::Regtest), transport).unwrap();
        assert!(matches!(
            rpc.test_mempool_accept(&finalized),
            Err(FractalExecutionError::InvalidRpcResponse(_))
                | Err(FractalExecutionError::RpcWitnessTransactionMismatch { .. })
        ));
        assert_eq!(state.borrow().calls.borrow().len(), 3);
    }
}

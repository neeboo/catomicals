use bitcoin::{
    Amount, ScriptBuf, Transaction, TxOut, XOnlyPublicKey, consensus::deserialize,
    sighash::TapSighashType,
};
use catomicals_chain_bitcoin::{
    BitcoinAdapterError, BitcoinChainSuite, TaprootKeySpendRequest, TaprootReviewMaterial,
    assemble_taproot_key_spend_signature, taproot_key_spend_payload,
    verify_taproot_key_spend_signature,
};
use catomicals_chain_domain::{
    BitcoinNetwork, ChainNetwork, ChainScope, ChainSuite, FractalBitcoinNetwork, ReviewArtifact,
    ReviewContractError,
};
use sha2::{Digest, Sha256};

const RAW_UNSIGNED_TX: &str = "02000000097de20cbff686da83a54981d2b9bab3586f4ca7e48f57f5b55963115f3b334e9c010000000000000000d7b7cab57b1393ace2d064f4d4a2cb8af6def61273e127517d44759b6dafdd990000000000fffffffff8e1f583384333689228c5d28eac13366be082dc57441760d957275419a418420000000000fffffffff0689180aa63b30cb162a73c6d2a38b7eeda2a83ece74310fda0843ad604853b0100000000feffffffaa5202bdf6d8ccd2ee0f0202afbbb7461d9264a25e5bfd3c5a52ee1239e0ba6c0000000000feffffff956149bdc66faa968eb2be2d2faa29718acbfe3941215893a2a3446d32acd050000000000000000000e664b9773b88c09c32cb70a2a3e4da0ced63b7ba3b22f848531bbb1d5d5f4c94010000000000000000e9aa6b8e6c9de67619e6a3924ae25696bb7b694bb677a632a74ef7eadfd4eabf0000000000ffffffffa778eb6a263dc090464cd125c466b5a99667720b1c110468831d058aa1b82af10100000000ffffffff0200ca9a3b000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac807840cb0000000020ac9a87f5594be208f8532db38cff670c450ed2fea8fcdefcc9a663f78bab962b0065cd1d";

const PREVOUTS: [(&str, u64); 9] = [
    (
        "512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343",
        420_000_000,
    ),
    (
        "5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3",
        462_000_000,
    ),
    (
        "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac",
        294_000_000,
    ),
    (
        "5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e",
        504_000_000,
    ),
    (
        "512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605",
        630_000_000,
    ),
    ("00147dd65592d0ab2fe0d0257d571abf032cd9db93dc", 378_000_000),
    (
        "512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831",
        672_000_000,
    ),
    (
        "5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5",
        546_000_000,
    ),
    (
        "512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220",
        588_000_000,
    ),
];

const INPUT_0_SIGHASH: &str = "2514a6272f85cfa0f45eb907fcb0d121b808ed37c6ea160a5a9046ed5526d555";
const INPUT_0_WITNESS: &str = "ed7c1647cb97379e76892be0cacff57ec4a7102aa24296ca39af7541246d8ff14d38958d4cc1e2e478e4d4a764bbfd835b16d4e314b72937b29833060b87276c03";
const INPUT_4_SIGHASH: &str = "4f900a0bae3f1446fd48490c2958b5a023228f01661cda3496a11da502a7f7ef";
const INPUT_4_WITNESS: &str = "b4010dd48a617db09926f729e79c33ae0b4e94b79f04a1ae93ede6315eb3669de185a17d2b0ac9ee09fd4c64b678a0b61a0a86fa888a273c8511be83bfd6810f";

fn bitcoin(network: BitcoinNetwork) -> ChainScope {
    ChainScope::for_network(ChainNetwork::Bitcoin(network))
}

fn fractal(network: FractalBitcoinNetwork) -> ChainScope {
    ChainScope::for_network(ChainNetwork::FractalBitcoin(network))
}

fn transaction() -> Transaction {
    deserialize(&hex::decode(RAW_UNSIGNED_TX).expect("official vector hex"))
        .expect("official unsigned transaction")
}

fn prevouts() -> Vec<TxOut> {
    PREVOUTS
        .iter()
        .map(|(script, amount)| TxOut {
            value: Amount::from_sat(*amount),
            script_pubkey: ScriptBuf::from_bytes(hex::decode(script).expect("script hex")),
        })
        .collect()
}

fn request(input_index: usize, sighash_type: TapSighashType) -> TaprootKeySpendRequest {
    TaprootKeySpendRequest::new(
        bitcoin(BitcoinNetwork::Signet),
        transaction(),
        prevouts(),
        input_index,
        sighash_type,
    )
    .expect("official vector request")
}

fn output_key(index: usize) -> XOnlyPublicKey {
    let script = &PREVOUTS[index].0;
    XOnlyPublicKey::from_slice(&hex::decode(&script[4..]).expect("output key hex"))
        .expect("P2TR output key")
}

#[test]
fn matches_official_bip341_single_sighash_and_signature_vector() {
    let payload =
        taproot_key_spend_payload(&request(0, TapSighashType::Single)).expect("BIP341 payload");
    assert_eq!(hex::encode(payload.sighash()), INPUT_0_SIGHASH);

    let witness = hex::decode(INPUT_0_WITNESS).expect("witness hex");
    verify_taproot_key_spend_signature(&payload, output_key(0), &witness)
        .expect("official BIP341 signature verifies");

    let schnorr: [u8; 64] = witness[..64].try_into().expect("64-byte signature");
    assert_eq!(
        assemble_taproot_key_spend_signature(schnorr, TapSighashType::Single)
            .expect("signature assembly"),
        witness
    );
}

#[test]
fn default_sighash_uses_the_canonical_64_byte_encoding() {
    let payload =
        taproot_key_spend_payload(&request(4, TapSighashType::Default)).expect("BIP341 payload");
    assert_eq!(hex::encode(payload.sighash()), INPUT_4_SIGHASH);
    let witness = hex::decode(INPUT_4_WITNESS).expect("witness hex");
    assert_eq!(witness.len(), 64);
    verify_taproot_key_spend_signature(&payload, output_key(4), &witness)
        .expect("official default signature verifies");
    let schnorr: [u8; 64] = witness.try_into().expect("64-byte signature");
    assert_eq!(
        assemble_taproot_key_spend_signature(schnorr, TapSighashType::Default)
            .expect("signature assembly")
            .len(),
        64
    );

    let mut non_canonical = hex::decode(INPUT_4_WITNESS).expect("witness hex");
    non_canonical.push(0);
    assert!(matches!(
        verify_taproot_key_spend_signature(&payload, output_key(4), &non_canonical),
        Err(BitcoinAdapterError::InvalidTaprootSignatureEncoding)
    ));
}

#[test]
fn verification_rejects_wrong_message_and_wrong_sighash_byte() {
    let payload =
        taproot_key_spend_payload(&request(0, TapSighashType::Single)).expect("BIP341 payload");
    let witness = hex::decode(INPUT_0_WITNESS).expect("witness hex");
    assert!(matches!(
        verify_taproot_key_spend_signature(&payload, output_key(1), &witness),
        Err(BitcoinAdapterError::InvalidTaprootSignature)
    ));

    let mut wrong_type = witness;
    wrong_type[64] = TapSighashType::All as u8;
    assert!(matches!(
        verify_taproot_key_spend_signature(&payload, output_key(0), &wrong_type),
        Err(BitcoinAdapterError::SignatureSighashMismatch { .. })
    ));
}

#[test]
fn payload_keeps_consensus_digest_and_chain_binding_separate() {
    let payload =
        taproot_key_spend_payload(&request(0, TapSighashType::Single)).expect("BIP341 payload");
    assert_eq!(payload.scope(), bitcoin(BitcoinNetwork::Signet));
    assert!(matches!(
        payload.require_scope(fractal(FractalBitcoinNetwork::Signet)),
        Err(BitcoinAdapterError::ScopeMismatch { .. })
    ));

    let mainnet_request = TaprootKeySpendRequest::new(
        bitcoin(BitcoinNetwork::Mainnet),
        transaction(),
        prevouts(),
        0,
        TapSighashType::Single,
    )
    .expect("structurally valid request");
    assert!(matches!(
        taproot_key_spend_payload(&mainnet_request),
        Err(BitcoinAdapterError::MainnetNotActivated { .. })
    ));
}

#[test]
fn request_rejects_incomplete_prevouts_and_non_taproot_inputs() {
    let mut missing = prevouts();
    missing.pop();
    assert!(matches!(
        TaprootKeySpendRequest::new(
            bitcoin(BitcoinNetwork::Signet),
            transaction(),
            missing,
            0,
            TapSighashType::Single,
        ),
        Err(BitcoinAdapterError::PrevoutCountMismatch { .. })
    ));
    assert!(matches!(
        TaprootKeySpendRequest::new(
            bitcoin(BitcoinNetwork::Signet),
            transaction(),
            prevouts(),
            2,
            TapSighashType::All,
        ),
        Err(BitcoinAdapterError::SigningInputNotTaproot { input_index: 2 })
    ));

    let mut signed = transaction();
    signed.input[0].witness.push([1_u8]);
    assert!(matches!(
        TaprootKeySpendRequest::new(
            bitcoin(BitcoinNetwork::Signet),
            signed,
            prevouts(),
            0,
            TapSighashType::Single,
        ),
        Err(BitcoinAdapterError::TransactionAlreadySigned)
    ));
}

#[test]
fn chain_suite_reviews_and_verifies_only_its_bound_scope_and_output_key() {
    let request = request(0, TapSighashType::Single);
    let material = TaprootReviewMaterial::from_request(&request).expect("review material");
    let suite =
        BitcoinChainSuite::new(bitcoin(BitcoinNetwork::Signet), output_key(0)).expect("test suite");
    let review = suite
        .review_transaction(&material.encode().expect("canonical material"))
        .expect("review succeeds");
    assert_eq!(
        review.review_digest,
        <[u8; 32]>::from(Sha256::digest(
            material.encode().expect("canonical material")
        ))
    );
    assert_eq!(review.scope, bitcoin(BitcoinNetwork::Signet));
    assert_eq!(hex::encode(review.signing_message_digest), INPUT_0_SIGHASH);
    assert!(suite.capabilities().transaction_review);
    assert!(suite.capabilities().final_signature_verification);
    suite
        .verify_finalized_signature(&review, &hex::decode(INPUT_0_WITNESS).expect("witness hex"))
        .expect("suite verifies official signature");

    let mut stale_material = material.encode().expect("material");
    let schema = b"\"schema_version\":1";
    let offset = stale_material
        .windows(schema.len())
        .position(|window| window == schema)
        .expect("schema field");
    stale_material[offset..offset + schema.len()].copy_from_slice(b"\"schema_version\":2");
    assert!(matches!(
        suite.review_transaction(&stale_material),
        Err(ReviewContractError::UnsupportedSchemaVersion {
            expected: 1,
            actual: 2
        })
    ));

    let fractal_material = TaprootReviewMaterial::from_request(
        &TaprootKeySpendRequest::new(
            fractal(FractalBitcoinNetwork::Signet),
            transaction(),
            prevouts(),
            0,
            TapSighashType::Single,
        )
        .expect("Fractal request"),
    )
    .expect("Fractal material");
    assert!(matches!(
        suite.review_transaction(&fractal_material.encode().expect("material")),
        Err(ReviewContractError::InvalidFinalizedSignature(_))
    ));

    let wrong_key_suite =
        BitcoinChainSuite::new(bitcoin(BitcoinNetwork::Signet), output_key(1)).expect("test suite");
    assert!(matches!(
        wrong_key_suite.review_transaction(&material.encode().expect("material")),
        Err(ReviewContractError::InvalidFinalizedSignature(_))
    ));

    let wrong_scope_review = ReviewArtifact::new(
        fractal(FractalBitcoinNetwork::Signet),
        review.review_digest,
        review.signing_message_digest,
        review.summary.clone(),
    )
    .expect("forged review");
    assert!(matches!(
        suite.verify_finalized_signature(
            &wrong_scope_review,
            &hex::decode(INPUT_0_WITNESS).expect("witness hex")
        ),
        Err(ReviewContractError::InvalidFinalizedSignature(_))
    ));

    let mut stale_review = review;
    stale_review.schema_version = 2;
    assert!(matches!(
        suite.verify_finalized_signature(
            &stale_review,
            &hex::decode(INPUT_0_WITNESS).expect("witness hex")
        ),
        Err(ReviewContractError::UnsupportedSchemaVersion {
            expected: 1,
            actual: 2
        })
    ));
}

#[test]
fn final_verification_rejects_a_forged_review_artifact_without_canonical_material() {
    let suite =
        BitcoinChainSuite::new(bitcoin(BitcoinNetwork::Signet), output_key(0)).expect("test suite");
    let forged = ReviewArtifact::new(
        bitcoin(BitcoinNetwork::Signet),
        [TapSighashType::Single as u8; 32],
        hex::decode(INPUT_0_SIGHASH)
            .expect("sighash hex")
            .try_into()
            .expect("32-byte sighash"),
        "attacker supplied review".to_owned(),
    )
    .expect("structurally valid forged review");

    assert!(matches!(
        suite.verify_finalized_signature(
            &forged,
            &hex::decode(INPUT_0_WITNESS).expect("witness hex")
        ),
        Err(ReviewContractError::InvalidFinalizedSignature(_))
    ));
}

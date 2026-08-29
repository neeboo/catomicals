use catomicals_chain_bitcoin_cash::{Error, ForkIdSighashType, Transaction, fork_id_sighash};

// Bitcoin Cash Node master@b31ed10, src/test/data/sighash.json.
// The official corpus uses arbitrary upper 24-bit fork IDs; these six cases
// cover each valid base mode with and without ANYONECANPAY.
const BCHN_VECTORS: [(&str, &str, usize, u32, &str); 6] = [
    (
        "13938a7d011e4545c281cbd8c6c85c796194285adb908ab052755cf65b60c5f7fc7e0e125c020000000953530000ac6a526a00d36774ce04d94bb802000000000600516353ac63f9f9fe000000000000b0123a05000000000251ace0b7c10400000000055351abab6300000000",
        "5300655100",
        0,
        467_995_457,
        "6bfb3e169f83f480b12c45223182650ae9dfa1e6be45e42a70b4bfdbf75cf923",
    ),
    (
        "84899c7602ddc570c897ee99edc6a6dc9c3a0da16f6be46f0e7195b498cdedaa3cb770c5b502000000045152635348b31c6768815b8ac924a10b821675ae9fba28197a6419fda574432561d50828dd3f77a40300000000ffbe079b0278e8f10400000000026a537850dd01000000000653006300520000000000",
        "5165635200",
        0,
        3_987_903_554,
        "50c9f573a2fad3d94513d0443becc8fc6d02d4e5733df3e1e5da973a779cfca4",
    ),
    (
        "697e29af01d275c36d6b3424db612b546ee7fcad7cbf297f32376fe9e8a92131ed89994af30300000003516363ffffffff0181b604010000000004ab6aabab002c37a9",
        "636a5153ac52ac6352",
        0,
        432_739_651,
        "99dbc3ea9cf5ebb68af86d7edccebdb61e566c6fc272cbeae3b5bf75e98505bf",
    ),
    (
        "93d8f06902da2ce38da2097a129d4c18f5232807c6b29ab1755c4847df971b9b7cb931e84b01000000075165acac006563ffffffff53f90702c960b353a1aa190c824ed00b2d54e82f5dcabe0e2c554315d842e0510300000008515153ab5253ac51b876d449016b8314000000000003ab0053ebfa6370",
        "6aac5353ab51ac00ac",
        1,
        4_248_495_297,
        "5584674cffe5d565975fa00b9ba77c75c030e37df280331c108c7fada6331636",
    ),
    (
        "973b155403ca855be099b7218a4b4b8dec19ea73bfca28d81d86ab338a7107b253010a263601000000045152acabffffffff26aaaa1b690999a4d212cc03e6cd0cb0d06bb3faddeef0566fb8924bcf9906550100000003536a6affffffff0590d7bbb14502b17bdf4b13891aba396e385daac84183abf23bca1617024cf10100000006536551636351ffffffff0332969e010000000009ab635153ab0051525193b3ff000000000006ab0052006a53412fce0300000000026363bf149151",
        "656565536300535100",
        0,
        4_079_350_978,
        "be8fb4225bebb9509dcb9a411692ca8f2c9b3a37a3b89543f4441f62f3b4bce1",
    ),
    (
        "cffe5a4202af7511ef806d6dbf6dddb2aa747665909c9411a0786eb5f0bb73862a2fd572dc0000000003535363ffffffffc6c25c58e69c4c8231b98f3feee7110ef294614b1670d8fec8f3ee8611fe03750000000008636aabac0051536571a8ad9102ffd79b020000000002650015c1a6050000000007530065ab650052f349d2b0",
        "ac65",
        0,
        1_840_901_827,
        "1c7bd5f3a74b617ef4583c701dab669984a90db698d2fc707b41592cd1803f4c",
    ),
];

#[test]
fn forkid_sighash_matches_bchn_all_none_single_and_anyonecanpay_vectors() {
    for (raw_tx, script_code, input_index, raw_type, expected) in BCHN_VECTORS {
        let tx = Transaction::decode(&hex::decode(raw_tx).unwrap()).unwrap();
        let hash_type = ForkIdSighashType::from_consensus(raw_type).unwrap();
        let digest = fork_id_sighash(
            &tx,
            input_index,
            &hex::decode(script_code).unwrap(),
            0,
            hash_type,
        )
        .unwrap();
        // BCHN renders uint256 values in reverse byte order; the API returns
        // the raw 32 bytes passed to secp256k1.
        assert_eq!(
            hex::encode(digest.into_iter().rev().collect::<Vec<_>>()),
            expected,
            "hashtype {raw_type:#x}"
        );
    }
}

#[test]
fn sighash_type_fails_closed_without_forkid_or_with_unknown_base_mode() {
    assert!(matches!(
        ForkIdSighashType::from_consensus(0x01),
        Err(Error::MissingForkId)
    ));
    assert!(matches!(
        ForkIdSighashType::from_consensus(0x44),
        Err(Error::UnsupportedSighashType(0x44))
    ));
    assert_eq!(ForkIdSighashType::ALL_ANYONECANPAY.to_consensus(), 0xc1);
}

#[test]
fn transaction_decoder_rejects_noncanonical_lengths_and_trailing_data() {
    // version=1, input count encoded as 0xfd 01 00 instead of canonical 01.
    let noncanonical = hex::decode("01000000fd0100").unwrap();
    assert!(matches!(
        Transaction::decode(&noncanonical),
        Err(Error::NonCanonicalVarInt)
    ));

    let mut tx = hex::decode(BCHN_VECTORS[2].0).unwrap();
    tx.push(0);
    assert!(matches!(
        Transaction::decode(&tx),
        Err(Error::TrailingTransactionData)
    ));
}

#[test]
fn sighash_rejects_input_index_out_of_bounds() {
    let tx = Transaction::decode(&hex::decode(BCHN_VECTORS[2].0).unwrap()).unwrap();
    assert!(matches!(
        fork_id_sighash(&tx, tx.inputs.len(), &[], 0, ForkIdSighashType::ALL),
        Err(Error::InputIndexOutOfBounds { .. })
    ));
}

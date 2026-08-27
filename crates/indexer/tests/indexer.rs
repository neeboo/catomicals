use std::path::Path;
use std::sync::{Arc, Barrier};

use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version as BlockVersion};
use bitcoin::hashes::Hash;
use bitcoin::pow::CompactTarget;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Block, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode,
    TxOut, Witness,
};
use catomicals_indexer::{ConfirmationStatus, Indexer, IndexerConfig, ObservationKind};
use catomicals_issuance::pow::{find_nonce, hash_tail, pow_hash};
use catomicals_issuance::script::{issuer_script, nums_internal_key};
use catomicals_issuance::state::IssuerState;
use catomicals_issuance::terms::{IssuanceTerms, SuccessorRule, item_commitment};
use catomicals_issuance::verify::{MintWitness, build_mint_tx, canonical_issuer_spk};

fn terms() -> IssuanceTerms {
    IssuanceTerms {
        item_id: [0x42; 32],
        target_prefix: 0,
        total_supply: 4,
        successor_rule: SuccessorRule::RecursiveIssuer,
        lane_count: 1,
        salt: [0x7a; 32],
        metadata: b"indexer fixture".to_vec(),
    }
}

fn config() -> IndexerConfig {
    IndexerConfig::new("issuance-verifier-v1", [terms()])
}

fn coinbase_tx(tag: u8, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![tag]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: outputs,
    }
}

fn block(prev: BlockHash, nonce: u32, txdata: Vec<Transaction>) -> Block {
    Block {
        header: Header {
            version: BlockVersion::ONE,
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::all_zeros(),
            time: nonce,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce,
        },
        txdata,
    }
}

fn plain_output(value: u64, tag: u8) -> TxOut {
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey: ScriptBuf::from_bytes(vec![0x6a, 0x01, tag]),
    }
}

fn open(path: &Path) -> Indexer {
    Indexer::open(path, config()).unwrap()
}

#[test]
fn block_commit_records_raw_evidence_and_survives_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let tx = coinbase_tx(1, vec![plain_output(25_000, 1)]);
    let txid = tx.compute_txid();
    let b = block(BlockHash::all_zeros(), 1, vec![tx]);
    let hash = b.block_hash();

    {
        let indexer = open(temp.path());
        indexer.apply_block(0, &b).unwrap();
        let record = indexer.transaction(txid).unwrap().unwrap();
        assert_eq!(record.provenance.block_hash, hash);
        assert_eq!(record.provenance.block_height, 0);
        assert_eq!(record.provenance.txid, txid);
        assert_eq!(record.provenance.tx_index, 0);
        assert_eq!(record.provenance.input_index, None);
        assert_eq!(record.provenance.output_index, None);
        assert_eq!(record.provenance.raw_evidence.block_hash, hash);
        assert_eq!(record.provenance.raw_evidence.tx_index, 0);
        assert_eq!(record.provenance.verifier_version, "issuance-verifier-v1");
        assert_eq!(
            record.provenance.confirmation,
            ConfirmationStatus::Confirmed
        );
        assert_eq!(
            record.provenance.observation,
            ObservationKind::DiscoveryOnly
        );

        let utxo = indexer.utxo(OutPoint::new(txid, 0)).unwrap().unwrap();
        assert_eq!(utxo.value_sat, 25_000);
        assert_eq!(utxo.provenance.output_index, Some(0));
        assert!(
            !indexer
                .block_by_height(0)
                .unwrap()
                .unwrap()
                .raw_block
                .is_empty()
        );
    }

    let reopened = open(temp.path());
    assert_eq!(reopened.tip().unwrap().unwrap().hash, hash);
    assert!(reopened.transaction(txid).unwrap().is_some());
}

#[test]
fn failed_block_is_not_partially_visible() {
    let temp = tempfile::tempdir().unwrap();
    let indexer = open(temp.path());
    let first = block(
        BlockHash::all_zeros(),
        1,
        vec![coinbase_tx(1, vec![plain_output(10_000, 1)])],
    );
    indexer.apply_block(0, &first).unwrap();

    let missing = OutPoint::new(bitcoin::Txid::from_byte_array([0x55; 32]), 7);
    let bad_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: missing,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![plain_output(1_000, 2)],
    };
    let bad_txid = bad_tx.compute_txid();
    let bad = block(first.block_hash(), 2, vec![bad_tx]);
    assert!(indexer.apply_block(1, &bad).is_err());
    assert_eq!(indexer.tip().unwrap().unwrap().hash, first.block_hash());
    assert!(indexer.transaction(bad_txid).unwrap().is_none());
    assert!(indexer.block_by_height(1).unwrap().is_none());
}

#[test]
fn fresh_database_rejects_a_non_genesis_start_height() {
    let temp = tempfile::tempdir().unwrap();
    let indexer = open(temp.path());
    let non_genesis = block(
        BlockHash::all_zeros(),
        100,
        vec![coinbase_tx(1, vec![plain_output(10_000, 1)])],
    );

    assert!(indexer.apply_block(100, &non_genesis).is_err());
    assert!(indexer.tip().unwrap().is_none());
}

#[test]
fn duplicate_prevout_in_one_transaction_is_rejected_atomically() {
    let temp = tempfile::tempdir().unwrap();
    let indexer = open(temp.path());
    let funding_tx = coinbase_tx(1, vec![plain_output(10_000, 1)]);
    let funding_outpoint = OutPoint::new(funding_tx.compute_txid(), 0);
    let funding = block(BlockHash::all_zeros(), 1, vec![funding_tx]);
    indexer.apply_block(0, &funding).unwrap();
    let duplicate_spend = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: funding_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: funding_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            },
        ],
        output: vec![plain_output(9_000, 2)],
    };
    let duplicate_txid = duplicate_spend.compute_txid();
    let candidate = block(funding.block_hash(), 2, vec![duplicate_spend]);

    assert!(indexer.apply_block(1, &candidate).is_err());
    assert_eq!(indexer.tip().unwrap().unwrap().hash, funding.block_hash());
    assert!(indexer.utxo(funding_outpoint).unwrap().is_some());
    assert!(indexer.transaction(duplicate_txid).unwrap().is_none());
}

#[test]
fn concurrent_competing_blocks_have_exactly_one_writer() {
    let temp = tempfile::tempdir().unwrap();
    let indexer = Arc::new(open(temp.path()));
    let workers = 12;
    let barrier = Arc::new(Barrier::new(workers));
    let mut handles = Vec::new();
    let mut txids = Vec::new();

    for tag in 1..=workers as u8 {
        let transaction = coinbase_tx(tag, vec![plain_output(10_000, tag)]);
        txids.push(transaction.compute_txid());
        let candidate = block(BlockHash::all_zeros(), tag as u32, vec![transaction]);
        let indexer = Arc::clone(&indexer);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            indexer.apply_block(0, &candidate)
        }));
    }

    let successes = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .filter(Result::is_ok)
        .count();
    assert_eq!(successes, 1);
    let tip = indexer.tip().unwrap().unwrap();
    assert_eq!(indexer.block_by_height(0).unwrap().unwrap().hash, tip.hash);
    assert_eq!(
        txids
            .into_iter()
            .filter(|txid| indexer.transaction(*txid).unwrap().is_some())
            .count(),
        1
    );
}

#[test]
fn verified_issuance_transition_is_an_observation_with_complete_lineage() {
    let temp = tempfile::tempdir().unwrap();
    let indexer = open(temp.path());
    let terms = terms();
    let state = IssuerState::initial(&terms, 0).unwrap();
    let issuer = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: canonical_issuer_spk(&state),
    };
    let funding_tx = coinbase_tx(1, vec![issuer.clone()]);
    let issuer_outpoint = OutPoint::new(funding_tx.compute_txid(), 0);
    let funding_block = block(BlockHash::all_zeros(), 1, vec![funding_tx]);
    indexer.apply_block(0, &funding_block).unwrap();

    let owner_key = {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let secret = bitcoin::secp256k1::SecretKey::from_slice(&[3; 32]).unwrap();
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret);
        bitcoin::XOnlyPublicKey::from_keypair(&keypair).0
    };
    let commitment = item_commitment(
        &state.terms_hash,
        state.lane,
        state.seq,
        &owner_key.serialize(),
        b"payload",
    );
    let nonce = find_nonce(
        &state.terms_hash,
        state.lane,
        state.seq,
        &commitment,
        state.target_prefix,
        0,
    )
    .unwrap();
    let digest = pow_hash(&state.terms_hash, state.lane, state.seq, &commitment, nonce);
    let witness = MintWitness {
        nonce,
        item_commitment: commitment,
        hash_tail: hash_tail(&digest, state.target_prefix),
        owner_key,
        payload: b"payload".to_vec(),
    };
    let successor_state = state.successor().unwrap().unwrap();
    let successor = TxOut {
        value: Amount::from_sat(96_000),
        script_pubkey: canonical_issuer_spk(&successor_state),
    };
    let mint = build_mint_tx(
        issuer_outpoint,
        &issuer,
        &state,
        &witness,
        Amount::from_sat(1_000),
        Some(&successor),
        control_block(&state),
    )
    .unwrap();
    let mint_txid = mint.compute_txid();
    let mint_block = block(funding_block.block_hash(), 2, vec![mint]);
    indexer.apply_block(1, &mint_block).unwrap();

    let transition = indexer.issuance_transition(mint_txid, 0).unwrap().unwrap();
    assert_eq!(transition.issuer_outpoint, issuer_outpoint);
    assert_eq!(transition.item_outpoint, OutPoint::new(mint_txid, 0));
    assert_eq!(
        transition.successor_outpoint,
        Some(OutPoint::new(mint_txid, 1))
    );
    assert_eq!(transition.provenance.input_index, Some(0));
    assert_eq!(transition.provenance.output_index, Some(0));
    assert_eq!(
        transition.provenance.observation,
        ObservationKind::WalletPolicyVerified
    );
    assert_eq!(
        transition.provenance.confirmation,
        ConfirmationStatus::Confirmed
    );
    assert!(indexer.utxo(issuer_outpoint).unwrap().is_none());

    indexer.rollback_tip().unwrap();
    assert!(indexer.issuance_transition(mint_txid, 0).unwrap().is_none());
    assert!(indexer.utxo(issuer_outpoint).unwrap().is_some());
    assert!(indexer.utxo(OutPoint::new(mint_txid, 0)).unwrap().is_none());
    assert!(indexer.utxo(OutPoint::new(mint_txid, 1)).unwrap().is_none());
    indexer.apply_block(1, &mint_block).unwrap();
    assert!(indexer.issuance_transition(mint_txid, 0).unwrap().is_some());
}

#[test]
fn shallow_and_deep_reorgs_restore_utxos_and_replace_history() {
    let temp = tempfile::tempdir().unwrap();
    let indexer = open(temp.path());
    let a1_tx = coinbase_tx(1, vec![plain_output(10_000, 1)]);
    let a1_out = OutPoint::new(a1_tx.compute_txid(), 0);
    let a1 = block(BlockHash::all_zeros(), 1, vec![a1_tx]);
    let a2_tx = spend(a1_out, 9_000, 2);
    let a2_out = OutPoint::new(a2_tx.compute_txid(), 0);
    let a2 = block(a1.block_hash(), 2, vec![a2_tx]);
    let a3_tx = spend(a2_out, 8_000, 3);
    let old_a3_txid = a3_tx.compute_txid();
    let a3 = block(a2.block_hash(), 3, vec![a3_tx]);
    indexer.apply_block(0, &a1).unwrap();
    indexer.apply_block(1, &a2).unwrap();
    indexer.apply_block(2, &a3).unwrap();

    indexer.rollback_tip().unwrap();
    assert_eq!(indexer.tip().unwrap().unwrap().hash, a2.block_hash());
    assert!(indexer.utxo(a2_out).unwrap().is_some());
    assert!(indexer.transaction(old_a3_txid).unwrap().is_none());
    indexer.apply_block(2, &a3).unwrap();

    let b2_tx = spend(a1_out, 8_500, 12);
    let b2_out = OutPoint::new(b2_tx.compute_txid(), 0);
    let b2 = block(a1.block_hash(), 22, vec![b2_tx]);
    let b3_tx = spend(b2_out, 8_000, 13);
    let b3_txid = b3_tx.compute_txid();
    let b3 = block(b2.block_hash(), 23, vec![b3_tx]);
    indexer
        .reorganize(a1.block_hash(), &[(1, b2), (2, b3)])
        .unwrap();

    assert_eq!(indexer.tip().unwrap().unwrap().height, 2);
    assert!(indexer.transaction(old_a3_txid).unwrap().is_none());
    assert!(indexer.transaction(b3_txid).unwrap().is_some());
    assert!(indexer.utxo(a2_out).unwrap().is_none());
}

#[test]
fn physical_checkpoint_reopens_and_replays_the_tail() {
    let temp = tempfile::tempdir().unwrap();
    let checkpoint_parent = tempfile::tempdir().unwrap();
    let checkpoint_path = checkpoint_parent.path().join("height-1");
    let indexer = open(temp.path());
    let first = block(
        BlockHash::all_zeros(),
        1,
        vec![coinbase_tx(1, vec![plain_output(10_000, 1)])],
    );
    indexer.apply_block(0, &first).unwrap();
    let manifest = indexer
        .create_checkpoint("height-1", &checkpoint_path)
        .unwrap();
    assert_eq!(manifest.tip.height, 0);

    let second = block(
        first.block_hash(),
        2,
        vec![coinbase_tx(2, vec![plain_output(20_000, 2)])],
    );
    indexer.apply_block(1, &second).unwrap();

    let rebuilt = open(&checkpoint_path);
    assert_eq!(rebuilt.tip().unwrap().unwrap().height, 0);
    assert_eq!(rebuilt.checkpoint("height-1").unwrap().unwrap(), manifest);
    rebuilt.apply_block(1, &second).unwrap();
    assert_eq!(rebuilt.tip().unwrap(), indexer.tip().unwrap());
}

#[test]
fn batch_utxo_lookup_preserves_request_order_and_missing_entries() {
    let temp = tempfile::tempdir().unwrap();
    let indexer = open(temp.path());
    let tx = coinbase_tx(1, vec![plain_output(10_000, 1), plain_output(20_000, 2)]);
    let txid = tx.compute_txid();
    let b = block(BlockHash::all_zeros(), 1, vec![tx]);
    indexer.apply_block(0, &b).unwrap();
    let missing = OutPoint::new(bitcoin::Txid::from_byte_array([0x99; 32]), 0);

    let rows = indexer
        .utxos(&[OutPoint::new(txid, 1), missing, OutPoint::new(txid, 0)])
        .unwrap();
    assert_eq!(rows[0].as_ref().unwrap().value_sat, 20_000);
    assert!(rows[1].is_none());
    assert_eq!(rows[2].as_ref().unwrap().value_sat, 10_000);
}

#[test]
fn malformed_replacement_is_rejected_before_any_rollback() {
    let temp = tempfile::tempdir().unwrap();
    let indexer = open(temp.path());
    let a1 = block(
        BlockHash::all_zeros(),
        1,
        vec![coinbase_tx(1, vec![plain_output(10_000, 1)])],
    );
    let a2 = block(
        a1.block_hash(),
        2,
        vec![coinbase_tx(2, vec![plain_output(10_000, 2)])],
    );
    indexer.apply_block(0, &a1).unwrap();
    indexer.apply_block(1, &a2).unwrap();
    let original_tip = indexer.tip().unwrap();
    let disconnected = block(
        BlockHash::from_byte_array([0xaa; 32]),
        3,
        vec![coinbase_tx(3, vec![plain_output(10_000, 3)])],
    );

    assert!(
        indexer
            .reorganize(a1.block_hash(), &[(1, disconnected)])
            .is_err()
    );
    assert_eq!(indexer.tip().unwrap(), original_tip);
    assert!(indexer.block_by_height(1).unwrap().is_some());
}

#[test]
fn database_uses_separate_column_families_for_hot_and_rebuild_state() {
    let temp = tempfile::tempdir().unwrap();
    let indexer = open(temp.path());
    drop(indexer);

    let mut families = rocksdb::DB::list_cf(&rocksdb::Options::default(), temp.path()).unwrap();
    families.sort();
    assert_eq!(
        families,
        vec![
            "blocks",
            "checkpoints",
            "default",
            "heights",
            "issuance_transitions",
            "meta",
            "transactions",
            "undo",
            "utxos",
        ]
    );
}

fn spend(previous_output: OutPoint, value: u64, tag: u8) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![plain_output(value, tag)],
    }
}

fn control_block(state: &IssuerState) -> Vec<u8> {
    use bitcoin::taproot::{LeafVersion, TaprootBuilder};

    let script = ScriptBuf::from_bytes(issuer_script(state));
    let info = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .unwrap()
        .finalize(
            &bitcoin::secp256k1::Secp256k1::verification_only(),
            nums_internal_key(),
        )
        .unwrap();
    info.control_block(&(script, LeafVersion::TapScript))
        .unwrap()
        .serialize()
}

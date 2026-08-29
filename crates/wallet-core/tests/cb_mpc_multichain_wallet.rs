#![cfg(feature = "native-cbmpc")]

use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};

use catomicals_cb_mpc_signer::{
    CbMpcCancellation, CbMpcRuntime, CbMpcRuntimeLimits, CbMpcSignerSet, DurableSessionClaimStore,
    LocalCbMpcProvider, PartyId, SessionTransport, TransportFailure,
    generate_native_provider_2_of_3,
};
use catomicals_chain_bitcoin_cash::{
    BitcoinCashChainSuite, BitcoinCashNetwork, BitcoinCashSignatureAlgorithm,
    BitcoinCashSigningRequest, ForkIdSighashType as BitcoinCashSighashType, OutPoint,
    Transaction as BitcoinCashTransaction, TxIn, TxOut,
};
use catomicals_chain_bsv::{
    BsvChainSuite, BsvNetwork, BsvSigningRequest, ForkIdSighashType, Transaction as BsvTransaction,
    TxInput, TxOutput,
};
use catomicals_chain_domain::{ChainNetwork, ChainScope, KaspaNetwork};
use catomicals_chain_kaspa::{KaspaChainSuite, KaspaReviewMaterial, KaspaVerifier};
use catomicals_signing_domain::{SignerBackendRequirement, SigningSuiteId};
use catomicals_wallet::{
    BitcoinCashCbMpcSignatureAssembler, BsvCbMpcSignatureAssembler, CbMpcChainSigningExecutor,
    CbMpcWalletCoordinator, ChainSigningExecution, ChainSigningExecutor,
    KaspaCbMpcSignatureAssembler, SignerProfile, SigningJobError, SigningJobRequest,
};
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::{
    hashing::sighash_type::SIG_HASH_ALL,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry},
};
use kaspa_hashes::Hash;
use kaspa_txscript::pay_to_address_script;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use uuid::Uuid;

const NOW: i64 = 1_800_000_000;

struct Queue {
    frames: Mutex<VecDeque<Vec<u8>>>,
    available: Condvar,
}

struct Network(Vec<Vec<Queue>>);

impl Network {
    fn new(parties: usize) -> Arc<Self> {
        Arc::new(Self(
            (0..parties)
                .map(|_| {
                    (0..parties)
                        .map(|_| Queue {
                            frames: Mutex::new(VecDeque::new()),
                            available: Condvar::new(),
                        })
                        .collect()
                })
                .collect(),
        ))
    }

    fn transport(self: &Arc<Self>, party: usize) -> MemoryTransport {
        MemoryTransport {
            network: Arc::clone(self),
            party,
        }
    }
}

struct MemoryTransport {
    network: Arc<Network>,
    party: usize,
}

impl SessionTransport for MemoryTransport {
    fn send(&self, receiver: usize, frame: &[u8], _: Instant) -> Result<(), TransportFailure> {
        let queue = &self.network.0[receiver][self.party];
        queue.frames.lock().unwrap().push_back(frame.to_vec());
        queue.available.notify_one();
        Ok(())
    }

    fn receive(&self, sender: usize, deadline: Instant) -> Result<Vec<u8>, TransportFailure> {
        let queue = &self.network.0[self.party][sender];
        let mut frames = queue.frames.lock().unwrap();
        loop {
            if let Some(frame) = frames.pop_front() {
                return Ok(frame);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(TransportFailure::Timeout);
            }
            let (next, timeout) = queue
                .available
                .wait_timeout(frames, deadline - now)
                .unwrap();
            frames = next;
            if timeout.timed_out() && frames.is_empty() {
                return Err(TransportFailure::Timeout);
            }
        }
    }
}

fn parties() -> Vec<PartyId> {
    ["desktop", "mobile", "onepassword"]
        .map(|party| PartyId::new(party).unwrap())
        .to_vec()
}

fn signer_set() -> CbMpcSignerSet {
    CbMpcSignerSet::new("personal-wallet", 9, 2, parties()).unwrap()
}

fn limits() -> CbMpcRuntimeLimits {
    CbMpcRuntimeLimits::new(
        Duration::from_secs(30),
        Duration::from_secs(90),
        4 * 1024 * 1024,
    )
    .unwrap()
}

fn providers() -> ([LocalCbMpcProvider; 3], [u8; 33]) {
    let network = Network::new(3);
    let transports = [
        network.transport(0),
        network.transport(1),
        network.transport(2),
    ];
    let providers = generate_native_provider_2_of_3(
        &signer_set(),
        [&transports[0], &transports[1], &transports[2]],
        limits(),
        &CbMpcCancellation::new(),
    )
    .unwrap();
    let group_key = providers[0].group_public_key();
    (providers, group_key)
}

fn private_claims() -> (tempfile::TempDir, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let claims = root.path().canonicalize().unwrap().join("claims");
    (root, claims)
}

fn profile(scope: ChainScope, suite: SigningSuiteId, group_key: [u8; 33]) -> SignerProfile {
    SignerProfile::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        scope,
        suite,
        SignerBackendRequirement::CbMpcThresholdEcdsa,
        "personal-wallet".to_owned(),
        "passkey:primary".to_owned(),
        9,
        2,
        3,
        group_key.to_vec(),
        "opaque-provider://personal-wallet".to_owned(),
    )
    .unwrap()
}

fn request(session_id: [u8; 32]) -> SigningJobRequest {
    SigningJobRequest {
        job_id: Uuid::new_v4(),
        intent_id: Uuid::new_v4(),
        policy_snapshot_digest: [41; 32],
        chain_snapshot_digest: [42; 32],
        online_parties: [parties()[0].clone(), parties()[1].clone()],
        receiver: parties()[0].clone(),
        session_id,
        expires_at: NOW + 120,
    }
}

#[test]
fn bsv_wallet_executes_real_two_of_three_and_rejects_drift_and_replay() {
    let (providers, group_key) = providers();
    let scope = ChainScope::for_network(ChainNetwork::Bsv(BsvNetwork::Regtest));
    let profile = profile(scope, SigningSuiteId::BSV_ECDSA_CB_MPC_V1, group_key);
    let suite = BsvChainSuite::new(BsvNetwork::Regtest, group_key).unwrap();
    let material = BsvSigningRequest {
        network: BsvNetwork::Regtest,
        transaction: BsvTransaction {
            version: 2,
            inputs: vec![TxInput {
                previous_txid_le: [3; 32],
                previous_output_index: 1,
                script_sig: vec![],
                sequence: 0xffff_fffe,
            }],
            outputs: vec![TxOutput {
                value_satoshis: 49_000,
                script_pubkey: vec![0x51],
            }],
            lock_time: 7,
        },
        input_index: 0,
        script_code: vec![0x51],
        input_value_satoshis: 50_000,
        sighash_type: ForkIdSighashType::ALL,
    }
    .encode()
    .unwrap();
    let (_claims_root, claims) = private_claims();
    let coordinator = CbMpcWalletCoordinator::new(
        profile,
        signer_set(),
        CbMpcRuntime::new_native(
            limits(),
            Arc::new(DurableSessionClaimStore::open(&claims).unwrap()),
        )
        .unwrap(),
    )
    .unwrap();
    let job = coordinator
        .prepare_job(&suite, &material, request([71; 32]), NOW)
        .unwrap();
    let execution = ChainSigningExecution {
        job,
        operation_binding_digest: [72; 32],
    };
    let [provider0, provider1, _provider2] = providers;
    let sign_network = Network::new(2);
    let executor = CbMpcChainSigningExecutor::new(
        Box::new(suite),
        coordinator,
        [provider0, provider1],
        [
            Box::new(sign_network.transport(0)),
            Box::new(sign_network.transport(1)),
        ],
        Box::new(BsvCbMpcSignatureAssembler),
        CbMpcCancellation::new(),
    )
    .unwrap();

    let mut wrong_suite = execution.clone();
    wrong_suite.job.signing_suite_id = SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1;
    assert_eq!(
        executor.execute(&wrong_suite, NOW),
        Err(SigningJobError::ProfileDrift)
    );
    let mut wrong_network = execution.clone();
    wrong_network.job.chain_scope = ChainScope::for_network(ChainNetwork::Bsv(BsvNetwork::Testnet));
    assert_eq!(
        executor.execute(&wrong_network, NOW),
        Err(SigningJobError::ProfileDrift)
    );

    executor.execute(&execution, NOW).unwrap();
    assert!(matches!(
        executor.execute(&execution, NOW + 1),
        Err(SigningJobError::Backend(_))
    ));
}

#[test]
fn bitcoin_cash_wallet_reuses_the_standard_cb_mpc_executor() {
    let (providers, group_key) = providers();
    let network = BitcoinCashNetwork::Chipnet;
    let scope = ChainScope::for_network(ChainNetwork::BitcoinCash(network));
    let profile = profile(
        scope,
        SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1,
        group_key,
    );
    let suite = BitcoinCashChainSuite::new(
        network,
        BitcoinCashSignatureAlgorithm::Ecdsa,
        &group_key,
        BitcoinCashSighashType::ALL,
    )
    .unwrap();
    let material = BitcoinCashSigningRequest::new(
        network,
        BitcoinCashTransaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: [3; 32],
                    output_index: 1,
                },
                script_sig: vec![],
                sequence: 0xffff_fffe,
            }],
            outputs: vec![TxOut {
                value: 49_000,
                script_pubkey: vec![0x51],
            }],
            lock_time: 7,
        },
        0,
        vec![0x51],
        50_000,
        BitcoinCashSighashType::ALL,
    )
    .encode();
    let (_claims_root, claims) = private_claims();
    let coordinator = CbMpcWalletCoordinator::new(
        profile,
        signer_set(),
        CbMpcRuntime::new_native(
            limits(),
            Arc::new(DurableSessionClaimStore::open(&claims).unwrap()),
        )
        .unwrap(),
    )
    .unwrap();
    let job = coordinator
        .prepare_job(&suite, &material, request([76; 32]), NOW)
        .unwrap();
    let execution = ChainSigningExecution {
        job,
        operation_binding_digest: [77; 32],
    };
    let [provider0, provider1, _provider2] = providers;
    let sign_network = Network::new(2);
    let executor = CbMpcChainSigningExecutor::new(
        Box::new(suite),
        coordinator,
        [provider0, provider1],
        [
            Box::new(sign_network.transport(0)),
            Box::new(sign_network.transport(1)),
        ],
        Box::new(BitcoinCashCbMpcSignatureAssembler),
        CbMpcCancellation::new(),
    )
    .unwrap();

    executor.execute(&execution, NOW).unwrap();
}

#[test]
fn kaspa_wallet_executes_real_two_of_three_and_real_script_verification() {
    let (providers, group_key) = providers();
    let network = KaspaNetwork::Testnet11;
    let scope = ChainScope::for_network(ChainNetwork::Kaspa(network));
    let profile = profile(scope, SigningSuiteId::KASPA_ECDSA_CB_MPC_V1, group_key);
    let suite = KaspaChainSuite::new(network, KaspaVerifier::EcdsaCbMpc(group_key)).unwrap();
    let input_script = pay_to_address_script(&Address::new(
        Prefix::Testnet,
        Version::PubKeyECDSA,
        &group_key,
    ));
    let output_secret = SecretKey::from_slice(&[9; 32]).unwrap();
    let output_key = PublicKey::from_secret_key(&Secp256k1::new(), &output_secret).serialize();
    let output_script = pay_to_address_script(&Address::new(
        Prefix::Testnet,
        Version::PubKeyECDSA,
        &output_key,
    ));
    let transaction = Transaction::new(
        0,
        vec![TransactionInput::new(
            TransactionOutpoint::new(Hash::from_bytes([0x11; 32]), 7),
            vec![],
            1,
            1,
        )],
        vec![TransactionOutput::new(900, output_script)],
        42,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    let material = KaspaReviewMaterial::new(
        network,
        transaction,
        vec![UtxoEntry::new(1_000, input_script, 8, false, None)],
        0,
        SIG_HASH_ALL,
    )
    .unwrap()
    .encode()
    .unwrap();
    let (_claims_root, claims) = private_claims();
    let coordinator = CbMpcWalletCoordinator::new(
        profile,
        signer_set(),
        CbMpcRuntime::new_native(
            limits(),
            Arc::new(DurableSessionClaimStore::open(&claims).unwrap()),
        )
        .unwrap(),
    )
    .unwrap();
    let job = coordinator
        .prepare_job(&suite, &material, request([81; 32]), NOW)
        .unwrap();
    let execution = ChainSigningExecution {
        job,
        operation_binding_digest: [82; 32],
    };
    let [provider0, provider1, _provider2] = providers;
    let sign_network = Network::new(2);
    let executor = CbMpcChainSigningExecutor::new(
        Box::new(suite),
        coordinator,
        [provider0, provider1],
        [
            Box::new(sign_network.transport(0)),
            Box::new(sign_network.transport(1)),
        ],
        Box::new(KaspaCbMpcSignatureAssembler),
        CbMpcCancellation::new(),
    )
    .unwrap();

    executor.execute(&execution, NOW).unwrap();
    assert!(matches!(
        executor.execute(&execution, NOW + 1),
        Err(SigningJobError::Backend(_))
    ));
}

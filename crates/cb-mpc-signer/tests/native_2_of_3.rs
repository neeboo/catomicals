#![cfg(feature = "native-cbmpc")]

use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use catomicals_cb_mpc_signer::{
    ApprovedCbMpcSignRequest, ApprovedCbMpcSignRequestParts, CbMpcError, CbMpcProfile,
    CbMpcRuntime, CbMpcRuntimeLimits, CbMpcSignerSet, DurableSessionClaimStore, PartyId,
    SessionTransport, TransportFailure, generate_native_2_of_3,
};
use catomicals_chain_domain::{
    BitcoinCashNetwork, BsvNetwork, ChainNetwork, ChainScope, KaspaNetwork, ReviewArtifact,
};
use catomicals_signing_domain::ReviewBinding;
use secp256k1::{Message, PublicKey, Secp256k1, ecdsa::Signature};

const NOW: i64 = 1_800_000_000;

fn private_tempdir(prefix: &str) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::Builder::new().prefix(prefix).tempdir().unwrap();
    let canonical_path = directory.path().canonicalize().unwrap();
    (directory, canonical_path)
}

struct Queue {
    frames: Mutex<VecDeque<Vec<u8>>>,
    available: Condvar,
}

impl Queue {
    fn new() -> Self {
        Self {
            frames: Mutex::new(VecDeque::new()),
            available: Condvar::new(),
        }
    }
}

struct MemoryNetwork {
    queues: Vec<Vec<Queue>>,
}

impl MemoryNetwork {
    fn new(party_count: usize) -> Arc<Self> {
        Arc::new(Self {
            queues: (0..party_count)
                .map(|_| (0..party_count).map(|_| Queue::new()).collect())
                .collect(),
        })
    }

    fn transport(self: &Arc<Self>, self_index: usize) -> MemoryTransport {
        MemoryTransport {
            network: Arc::clone(self),
            self_index,
        }
    }
}

struct MemoryTransport {
    network: Arc<MemoryNetwork>,
    self_index: usize,
}

impl SessionTransport for MemoryTransport {
    fn send(
        &self,
        receiver: usize,
        frame: &[u8],
        _deadline: Instant,
    ) -> Result<(), TransportFailure> {
        let queue = self
            .network
            .queues
            .get(receiver)
            .and_then(|senders| senders.get(self.self_index))
            .ok_or(TransportFailure::Terminated)?;
        queue.frames.lock().unwrap().push_back(frame.to_vec());
        queue.available.notify_one();
        Ok(())
    }

    fn receive(&self, sender: usize, deadline: Instant) -> Result<Vec<u8>, TransportFailure> {
        let queue = self
            .network
            .queues
            .get(self.self_index)
            .and_then(|senders| senders.get(sender))
            .ok_or(TransportFailure::Terminated)?;
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
    ["desktop", "mobile-backup", "onepassword"]
        .map(|name| PartyId::new(name).unwrap())
        .to_vec()
}

fn signer_set() -> CbMpcSignerSet {
    CbMpcSignerSet::new("personal-wallet", 7, 2, parties()).unwrap()
}

fn request(
    profile: CbMpcProfile,
    public_key: [u8; 33],
    online_indices: [usize; 2],
    session_byte: u8,
    digest_byte: u8,
) -> ApprovedCbMpcSignRequest {
    let scope = match profile {
        CbMpcProfile::BitcoinCashEcdsaV1 => {
            ChainScope::for_network(ChainNetwork::BitcoinCash(BitcoinCashNetwork::Mainnet))
        }
        CbMpcProfile::BsvEcdsaV1 => ChainScope::for_network(ChainNetwork::Bsv(BsvNetwork::Mainnet)),
        CbMpcProfile::KaspaEcdsaV1 => {
            ChainScope::for_network(ChainNetwork::Kaspa(KaspaNetwork::Testnet11))
        }
    };
    let review = ReviewArtifact::new(
        scope,
        [digest_byte.wrapping_add(1); 32],
        [digest_byte; 32],
        "independent native cb-mpc test".to_owned(),
        vec![digest_byte],
    )
    .unwrap();
    let binding = ReviewBinding::new(
        scope,
        profile.signing_suite_id(),
        "personal-wallet",
        7,
        review.schema_version,
        review.review_digest,
    )
    .unwrap();
    let all = parties();
    ApprovedCbMpcSignRequest::new(
        ApprovedCbMpcSignRequestParts {
            profile,
            review,
            review_binding: binding,
            signer_set: signer_set(),
            group_public_key: public_key,
            policy_snapshot_digest: [41; 32],
            chain_snapshot_digest: [42; 32],
            online_parties: online_indices
                .iter()
                .map(|index| all[*index].clone())
                .collect(),
            receiver: all[online_indices[0]].clone(),
            session_id: [session_byte; 32],
            expires_at: NOW + 120,
        },
        NOW,
    )
    .unwrap()
}

#[test]
fn real_native_backend_signs_three_profiles_and_every_kaspa_quorum() {
    let limits = CbMpcRuntimeLimits::new(
        Duration::from_secs(30),
        Duration::from_secs(90),
        4 * 1024 * 1024,
    )
    .unwrap();
    let dkg_network = MemoryNetwork::new(3);
    let dkg_transports = [
        dkg_network.transport(0),
        dkg_network.transport(1),
        dkg_network.transport(2),
    ];
    let shares = generate_native_2_of_3(
        &signer_set(),
        [&dkg_transports[0], &dkg_transports[1], &dkg_transports[2]],
        limits,
    )
    .expect("real cb-mpc DKG");
    let group_public_key = shares[0].group_public_key();
    assert!(
        shares
            .iter()
            .all(|share| share.group_public_key() == group_public_key)
    );
    assert!(format!("{:?}", shares[0]).contains("REDACTED"));
    let exported = shares[0].export_secret().expect("zeroizing export");
    let exported_debug = format!("{exported:?}");
    assert!(exported_debug.contains("REDACTED"));
    assert!(!exported_debug.contains(&hex::encode(exported.expose_secret())));
    let restored =
        catomicals_cb_mpc_signer::CbMpcShare::from_serialized(parties()[0].clone(), exported)
            .expect("restore zeroizing share");
    assert_eq!(restored.group_public_key(), group_public_key);

    let (_runtime_root, runtime_root_path) = private_tempdir("cb-mpc-native-");
    let runtime_claims = runtime_root_path.join("claims");
    let runtime = CbMpcRuntime::new_native(
        limits,
        Arc::new(DurableSessionClaimStore::open(&runtime_claims).unwrap()),
    )
    .unwrap();
    let cases = [
        (CbMpcProfile::BitcoinCashEcdsaV1, [0, 1], 51, 61),
        (CbMpcProfile::BsvEcdsaV1, [0, 2], 52, 62),
        (CbMpcProfile::KaspaEcdsaV1, [0, 1], 53, 63),
        (CbMpcProfile::KaspaEcdsaV1, [0, 2], 54, 64),
        (CbMpcProfile::KaspaEcdsaV1, [1, 2], 55, 65),
    ];
    for (profile, online, session, digest) in cases {
        let request = request(profile, group_public_key, online, session, digest);
        let network = MemoryNetwork::new(2);
        let transports = [network.transport(0), network.transport(1)];
        let result = runtime
            .sign(
                &request,
                [&shares[online[0]], &shares[online[1]]],
                [&transports[0], &transports[1]],
                NOW,
            )
            .expect("real cb-mpc signature");

        let signature = Signature::from_der(result.der()).expect("strict DER");
        assert_eq!(signature.serialize_der().as_ref(), result.der());
        let mut normalized = signature;
        normalized.normalize_s();
        assert_eq!(normalized, signature, "signature must use low S");
        assert_eq!(
            secp256k1::ecdsa::Signature::from_compact(&result.compact_low_s()).unwrap(),
            signature
        );
        Secp256k1::verification_only()
            .verify_ecdsa(
                &Message::from_digest([digest; 32]),
                &signature,
                &PublicKey::from_slice(&group_public_key).unwrap(),
            )
            .expect("independent group-key verification");

        assert_eq!(
            runtime.sign(
                &request,
                [&shares[online[0]], &shares[online[1]]],
                [&transports[0], &transports[1]],
                NOW,
            ),
            Err(CbMpcError::SessionTerminal)
        );
    }

    let blocking = Arc::new(BlockingState::new());
    let blocking_transports = [
        BlockingTransport::new(Arc::clone(&blocking)),
        BlockingTransport::new(Arc::clone(&blocking)),
    ];
    let blocked_request = request(
        CbMpcProfile::BitcoinCashEcdsaV1,
        group_public_key,
        [0, 1],
        71,
        81,
    );
    std::thread::scope(|scope| {
        let operation = scope.spawn(|| {
            runtime.sign(
                &blocked_request,
                [&shares[0], &shares[1]],
                [&blocking_transports[0], &blocking_transports[1]],
                NOW,
            )
        });
        blocking.wait_until_receive();

        let competing_request = request(CbMpcProfile::BsvEcdsaV1, group_public_key, [0, 1], 72, 82);
        let competing_network = MemoryNetwork::new(2);
        let competing_transports = [
            competing_network.transport(0),
            competing_network.transport(1),
        ];
        assert_eq!(
            runtime.sign(
                &competing_request,
                [&shares[0], &shares[1]],
                [&competing_transports[0], &competing_transports[1]],
                NOW,
            ),
            Err(CbMpcError::ShareBusy)
        );

        blocking.terminate();
        assert_eq!(
            operation.join().unwrap(),
            Err(CbMpcError::TransportTerminated)
        );
    });
    let replay_network = MemoryNetwork::new(2);
    let replay_transports = [replay_network.transport(0), replay_network.transport(1)];
    assert_eq!(
        runtime.sign(
            &blocked_request,
            [&shares[0], &shares[1]],
            [&replay_transports[0], &replay_transports[1]],
            NOW,
        ),
        Err(CbMpcError::SessionTerminal)
    );

    drop(runtime);
    let restarted_runtime = CbMpcRuntime::new_native(
        limits,
        Arc::new(DurableSessionClaimStore::open(&runtime_claims).unwrap()),
    )
    .unwrap();
    assert_eq!(
        restarted_runtime.sign(
            &blocked_request,
            [&shares[0], &shares[1]],
            [&replay_transports[0], &replay_transports[1]],
            NOW,
        ),
        Err(CbMpcError::SessionTerminal)
    );

    let (_timeout_root, timeout_root_path) = private_tempdir("cb-mpc-timeout-");
    let timeout_claims = timeout_root_path.join("claims");
    let timeout_runtime = CbMpcRuntime::new_native(
        CbMpcRuntimeLimits::new(
            Duration::from_millis(50),
            Duration::from_secs(1),
            4 * 1024 * 1024,
        )
        .unwrap(),
        Arc::new(DurableSessionClaimStore::open(&timeout_claims).unwrap()),
    )
    .unwrap();
    let timeout_request = request(CbMpcProfile::BsvEcdsaV1, group_public_key, [1, 2], 73, 83);
    let timeout_state = Arc::new(BlockingState::new());
    let timeout_transports = [
        BlockingTransport::new(Arc::clone(&timeout_state)),
        BlockingTransport::new(timeout_state),
    ];
    assert_eq!(
        timeout_runtime.sign(
            &timeout_request,
            [&shares[1], &shares[2]],
            [&timeout_transports[0], &timeout_transports[1]],
            NOW,
        ),
        Err(CbMpcError::TransportTimeout)
    );
    assert_eq!(
        timeout_runtime.sign(
            &timeout_request,
            [&shares[1], &shares[2]],
            [&timeout_transports[0], &timeout_transports[1]],
            NOW,
        ),
        Err(CbMpcError::SessionTerminal)
    );
    drop(timeout_runtime);
    let restarted_timeout = CbMpcRuntime::new_native(
        CbMpcRuntimeLimits::new(
            Duration::from_millis(50),
            Duration::from_secs(1),
            4 * 1024 * 1024,
        )
        .unwrap(),
        Arc::new(DurableSessionClaimStore::open(&timeout_claims).unwrap()),
    )
    .unwrap();
    assert_eq!(
        restarted_timeout.sign(
            &timeout_request,
            [&shares[1], &shares[2]],
            [&timeout_transports[0], &timeout_transports[1]],
            NOW,
        ),
        Err(CbMpcError::SessionTerminal)
    );
}

struct BlockingState {
    receive_entered: Mutex<bool>,
    changed: Condvar,
    terminated: AtomicBool,
}

impl BlockingState {
    fn new() -> Self {
        Self {
            receive_entered: Mutex::new(false),
            changed: Condvar::new(),
            terminated: AtomicBool::new(false),
        }
    }

    fn wait_until_receive(&self) {
        let mut entered = self.receive_entered.lock().unwrap();
        while !*entered {
            entered = self.changed.wait(entered).unwrap();
        }
    }

    fn terminate(&self) {
        self.terminated.store(true, Ordering::Release);
        self.changed.notify_all();
    }
}

struct BlockingTransport {
    state: Arc<BlockingState>,
}

impl BlockingTransport {
    fn new(state: Arc<BlockingState>) -> Self {
        Self { state }
    }
}

impl SessionTransport for BlockingTransport {
    fn send(
        &self,
        _receiver: usize,
        _frame: &[u8],
        _deadline: Instant,
    ) -> Result<(), TransportFailure> {
        Ok(())
    }

    fn receive(&self, _sender: usize, deadline: Instant) -> Result<Vec<u8>, TransportFailure> {
        let mut entered = self.state.receive_entered.lock().unwrap();
        *entered = true;
        self.state.changed.notify_all();
        while !self.state.terminated.load(Ordering::Acquire) {
            let now = Instant::now();
            if now >= deadline {
                return Err(TransportFailure::Timeout);
            }
            let (next, timeout) = self
                .state
                .changed
                .wait_timeout(entered, deadline - now)
                .unwrap();
            entered = next;
            if timeout.timed_out() && !self.state.terminated.load(Ordering::Acquire) {
                return Err(TransportFailure::Timeout);
            }
        }
        Err(TransportFailure::Terminated)
    }
}

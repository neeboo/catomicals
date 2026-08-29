#![cfg(feature = "native-cbmpc")]

use std::{
    collections::VecDeque,
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};

use catomicals_cb_mpc_signer::{
    CbMpcCancellation, CbMpcError, CbMpcRuntimeLimits, CbMpcShareProtector, CbMpcSignerSet,
    LocalCbMpcProvider, PartyId, SecretShareMaterial, SessionTransport, TransportFailure,
    generate_native_provider_2_of_3,
};

struct TestProtector;

impl CbMpcShareProtector for TestProtector {
    fn seal(&self, secret: &[u8]) -> Result<Vec<u8>, CbMpcError> {
        Ok(secret.iter().map(|byte| byte ^ 0xa5).collect())
    }

    fn open(&self, sealed: &[u8]) -> Result<SecretShareMaterial, CbMpcError> {
        SecretShareMaterial::new(sealed.iter().map(|byte| byte ^ 0xa5).collect())
    }
}

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
    fn send(
        &self,
        receiver: usize,
        frame: &[u8],
        _deadline: Instant,
    ) -> Result<(), TransportFailure> {
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

fn signer_set() -> CbMpcSignerSet {
    CbMpcSignerSet::new(
        "wallet",
        1,
        2,
        ["desktop", "mobile", "onepassword"]
            .map(|id| PartyId::new(id).unwrap())
            .to_vec(),
    )
    .unwrap()
}

#[test]
fn dkg_returns_opaque_providers_and_import_preserves_identity() {
    let limits = CbMpcRuntimeLimits::new(
        Duration::from_secs(30),
        Duration::from_secs(90),
        4 * 1024 * 1024,
    )
    .unwrap();
    let network = Network::new(3);
    let transports = [
        network.transport(0),
        network.transport(1),
        network.transport(2),
    ];
    let providers = generate_native_provider_2_of_3(
        &signer_set(),
        [&transports[0], &transports[1], &transports[2]],
        limits,
        &CbMpcCancellation::new(),
    )
    .unwrap();

    assert_eq!(providers[0].party().as_str(), "desktop");
    assert!(providers.iter().all(|provider| {
        provider.group_public_key() == providers[0].group_public_key()
            && format!("{provider:?}").contains("REDACTED")
    }));

    let sealed = providers[0].seal_for_persistence(&TestProtector).unwrap();
    let restored = LocalCbMpcProvider::import_sealed(
        PartyId::new("desktop").unwrap(),
        providers[0].group_public_key(),
        &sealed,
        &TestProtector,
    )
    .unwrap();
    assert_eq!(restored.party().as_str(), "desktop");
    assert_eq!(restored.group_public_key(), providers[0].group_public_key());
}

#[test]
fn cancellation_is_checked_before_dkg_claims_protocol_resources() {
    let limits =
        CbMpcRuntimeLimits::new(Duration::from_secs(1), Duration::from_secs(2), 1024).unwrap();
    let cancellation = CbMpcCancellation::new();
    cancellation.cancel();
    let network = Network::new(3);
    let transports = [
        network.transport(0),
        network.transport(1),
        network.transport(2),
    ];
    assert!(matches!(
        generate_native_provider_2_of_3(
            &signer_set(),
            [&transports[0], &transports[1], &transports[2]],
            limits,
            &cancellation,
        ),
        Err(CbMpcError::Interrupted)
    ));
}

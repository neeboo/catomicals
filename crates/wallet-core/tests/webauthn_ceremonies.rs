use std::collections::BTreeMap;

use catomicals_threshold::{
    FrostCoordinator, LocalFrostParticipant, NonceGuard, participant_identifier, run_local_dkg,
};
use catomicals_wallet::{
    ApprovalFinishRequest, CreateIntentRequest, PasskeyRegistrationFinishRequest,
    PasskeyRegistrationStartRequest, RelyingPartyConfig, WalletNodeError, WalletNodeService,
};
use ring::{
    digest,
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
};
use serde_cbor_2::Value as Cbor;
use serde_json::json;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};
use webauthn_rs_proto::{
    AuthenticationExtensionsClientOutputs, AuthenticatorAssertionResponseRaw,
    AuthenticatorAttestationResponseRaw, RegistrationExtensionsClientOutputs,
};

struct SoftwarePasskey {
    credential_id: Vec<u8>,
    key: EcdsaKeyPair,
    counter: u32,
}

impl SoftwarePasskey {
    fn new() -> Self {
        let rng = SystemRandom::new();
        let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("generate P-256 key");
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref(), &rng)
                .expect("parse P-256 key");
        Self {
            credential_id: vec![0xa5; 32],
            key,
            counter: 0,
        }
    }

    fn client_data(kind: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "type": kind,
            "challenge": catomicals_wallet::b64url_encode(challenge),
            "origin": origin,
            "crossOrigin": false
        }))
        .unwrap()
    }

    fn registration(
        &self,
        options: &CreationChallengeResponse,
        origin: &str,
    ) -> RegisterPublicKeyCredential {
        let rp_id = &options.public_key.rp.id;
        let client_data = Self::client_data(
            "webauthn.create",
            options.public_key.challenge.as_slice(),
            origin,
        );
        let public = self.key.public_key().as_ref();
        assert_eq!(public.len(), 65);
        let cose = Cbor::Map(BTreeMap::from([
            (Cbor::Integer(1), Cbor::Integer(2)),
            (Cbor::Integer(3), Cbor::Integer(-7)),
            (Cbor::Integer(-1), Cbor::Integer(1)),
            (Cbor::Integer(-2), Cbor::Bytes(public[1..33].to_vec())),
            (Cbor::Integer(-3), Cbor::Bytes(public[33..65].to_vec())),
        ]));
        let mut auth_data = digest::digest(&digest::SHA256, rp_id.as_bytes())
            .as_ref()
            .to_vec();
        auth_data.push(0x45); // UP | UV | AT
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        auth_data.extend_from_slice(&[0; 16]);
        auth_data.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&self.credential_id);
        auth_data.extend_from_slice(&serde_cbor_2::to_vec(&cose).unwrap());
        let attestation = Cbor::Map(BTreeMap::from([
            (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
            (Cbor::Text("attStmt".into()), Cbor::Map(BTreeMap::new())),
            (Cbor::Text("authData".into()), Cbor::Bytes(auth_data)),
        ]));
        RegisterPublicKeyCredential {
            id: catomicals_wallet::b64url_encode(&self.credential_id),
            raw_id: self.credential_id.clone().into(),
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: serde_cbor_2::to_vec(&attestation).unwrap().into(),
                client_data_json: client_data.into(),
                transports: None,
            },
            type_: "public-key".into(),
            extensions: RegistrationExtensionsClientOutputs::default(),
        }
    }

    fn assertion(
        &mut self,
        options: &RequestChallengeResponse,
        origin: &str,
        rp_id: &str,
        flags: u8,
    ) -> PublicKeyCredential {
        self.counter += 1;
        let client_data = Self::client_data(
            "webauthn.get",
            options.public_key.challenge.as_slice(),
            origin,
        );
        let mut auth_data = digest::digest(&digest::SHA256, rp_id.as_bytes())
            .as_ref()
            .to_vec();
        auth_data.push(flags);
        auth_data.extend_from_slice(&self.counter.to_be_bytes());
        let client_hash = digest::digest(&digest::SHA256, &client_data);
        let mut signed = auth_data.clone();
        signed.extend_from_slice(client_hash.as_ref());
        let signature = self.key.sign(&SystemRandom::new(), &signed).unwrap();
        PublicKeyCredential {
            id: catomicals_wallet::b64url_encode(&self.credential_id),
            raw_id: self.credential_id.clone().into(),
            response: AuthenticatorAssertionResponseRaw {
                authenticator_data: auth_data.into(),
                client_data_json: client_data.into(),
                signature: signature.as_ref().to_vec().into(),
                user_handle: None,
            },
            extensions: AuthenticationExtensionsClientOutputs::default(),
            type_: "public-key".into(),
        }
    }
}

fn configured_service() -> (WalletNodeService, LocalFrostParticipant) {
    let mut dkg = run_local_dkg(3, 2).unwrap();
    let signer1 = LocalFrostParticipant::new(
        1,
        dkg.key_packages
            .remove(&participant_identifier(1).unwrap())
            .unwrap(),
        NonceGuard::new(),
    )
    .unwrap();
    let signer2 = LocalFrostParticipant::new(
        2,
        dkg.key_packages
            .remove(&participant_identifier(2).unwrap())
            .unwrap(),
        NonceGuard::new(),
    )
    .unwrap();
    let config = RelyingPartyConfig {
        rp_id: "localhost".into(),
        rp_origin: "http://localhost:18787".into(),
        rp_name: "Catomicals local wallet".into(),
        ceremony_ttl_seconds: 300,
    };
    (
        WalletNodeService::new(config, Some(signer1), dkg.public_key_package, 2).unwrap(),
        signer2,
    )
}

fn enroll(service: &mut WalletNodeService, passkey: &SoftwarePasskey, now: i64) {
    let started = service
        .registration_start(
            PasskeyRegistrationStartRequest {
                label: "primary".into(),
                user_name: "local-owner".into(),
                display_name: "Local Owner".into(),
            },
            now,
        )
        .unwrap();
    let credential = passkey.registration(&started.public_key, "http://localhost:18787");
    service
        .registration_finish(
            PasskeyRegistrationFinishRequest {
                ceremony_id: started.ceremony_id,
                credential,
            },
            now + 1,
        )
        .unwrap();
}

fn intent(service: &mut WalletNodeService, nonce: u8, now: i64) -> Uuid {
    service
        .create_intent(
            CreateIntentRequest {
                wallet_id: Uuid::from_bytes([1; 16]),
                signer_id: 1,
                tx_digest: [nonce; 32],
                session_id: [nonce.wrapping_add(1); 32],
                expiry: now + 120,
            },
            now,
        )
        .unwrap()
        .id
}

#[test]
fn real_registration_and_assertion_release_exact_frost_action_once() {
    let now = 1_800_000_000;
    let (mut service, mut signer2) = configured_service();
    let mut passkey = SoftwarePasskey::new();
    enroll(&mut service, &passkey, now);
    assert_eq!(service.wallet_status().credentials, 1);

    let intent_id = intent(&mut service, 0x21, now + 2);
    let approval = service.approval_start(intent_id, now + 3).unwrap();
    let assertion = passkey.assertion(
        &approval.public_key,
        "http://localhost:18787",
        "localhost",
        0x05,
    );
    let finish = ApprovalFinishRequest {
        ceremony_id: approval.ceremony_id,
        credential: assertion.clone(),
    };
    service
        .approval_finish(intent_id, finish.clone(), now + 4)
        .unwrap();
    assert!(matches!(
        service.approval_finish(intent_id, finish, now + 4),
        Err(WalletNodeError::CeremonyNotFound)
    ));

    let intent = service.read_intent(intent_id).unwrap();
    let own = service.signer_round1(intent_id, now + 5).unwrap();
    let other = signer2.round1(intent.session_id, intent.tx_digest).unwrap();
    let mut coordinator = FrostCoordinator::new(
        intent.session_id,
        intent.tx_digest,
        2,
        service.public_key_package().clone(),
    );
    coordinator.add_commitment(1, own).unwrap();
    coordinator.add_commitment(2, other).unwrap();
    let session = coordinator.signing_session().unwrap();
    let share = service.signer_round2(intent_id, &session, now + 6).unwrap();
    coordinator.add_signature_share(1, share).unwrap();
    assert_eq!(
        service.read_intent(intent_id).unwrap().status,
        catomicals_wallet::IntentStatus::Approved,
        "one local signature share is not an aggregate threshold signature"
    );
    assert!(matches!(
        service.signer_round2(intent_id, &session, now + 6),
        Err(WalletNodeError::AuthorizationUnavailable)
    ));
}

#[test]
fn rp_origin_challenge_presence_verification_signature_and_binding_are_enforced() {
    let now = 1_800_100_000;
    let (mut service, _) = configured_service();
    let mut passkey = SoftwarePasskey::new();
    enroll(&mut service, &passkey, now);
    let intended = intent(&mut service, 0x31, now + 2);
    let substituted = intent(&mut service, 0x41, now + 2);

    let bad_cases = [
        ("https://evil.example", "localhost", 0x05),
        ("http://localhost:18787", "evil.example", 0x05),
        ("http://localhost:18787", "localhost", 0x04),
        ("http://localhost:18787", "localhost", 0x01),
    ];
    for (origin, rp_id, flags) in bad_cases {
        let start = service.approval_start(intended, now + 3).unwrap();
        let assertion = passkey.assertion(&start.public_key, origin, rp_id, flags);
        assert!(matches!(
            service.approval_finish(
                intended,
                ApprovalFinishRequest {
                    ceremony_id: start.ceremony_id,
                    credential: assertion
                },
                now + 4
            ),
            Err(WalletNodeError::WebAuthn(_))
        ));
    }

    let start = service.approval_start(intended, now + 3).unwrap();
    let mut wrong_challenge = start.public_key.clone();
    wrong_challenge.public_key.challenge = vec![0x99; 32].into();
    let assertion = passkey.assertion(
        &wrong_challenge,
        "http://localhost:18787",
        "localhost",
        0x05,
    );
    assert!(matches!(
        service.approval_finish(
            intended,
            ApprovalFinishRequest {
                ceremony_id: start.ceremony_id,
                credential: assertion
            },
            now + 4
        ),
        Err(WalletNodeError::WebAuthn(_))
    ));

    let start = service.approval_start(intended, now + 3).unwrap();
    let mut assertion = passkey.assertion(
        &start.public_key,
        "http://localhost:18787",
        "localhost",
        0x05,
    );
    assertion.response.signature = vec![0; 64].into();
    assert!(matches!(
        service.approval_finish(
            intended,
            ApprovalFinishRequest {
                ceremony_id: start.ceremony_id,
                credential: assertion
            },
            now + 4
        ),
        Err(WalletNodeError::WebAuthn(_))
    ));

    let start = service.approval_start(intended, now + 3).unwrap();
    let assertion = passkey.assertion(
        &start.public_key,
        "http://localhost:18787",
        "localhost",
        0x05,
    );
    assert!(matches!(
        service.approval_finish(
            substituted,
            ApprovalFinishRequest {
                ceremony_id: start.ceremony_id,
                credential: assertion
            },
            now + 4
        ),
        Err(WalletNodeError::IntentBindingMismatch)
    ));
}

#[test]
fn registration_state_is_server_side_one_use_and_remote_origin_requires_https() {
    let now = 1_800_200_000;
    let (mut service, _) = configured_service();
    let passkey = SoftwarePasskey::new();
    let start = service
        .registration_start(
            PasskeyRegistrationStartRequest {
                label: "primary".into(),
                user_name: "owner".into(),
                display_name: "Owner".into(),
            },
            now,
        )
        .unwrap();
    let credential = passkey.registration(&start.public_key, "http://localhost:18787");
    let finish = PasskeyRegistrationFinishRequest {
        ceremony_id: start.ceremony_id,
        credential,
    };
    service
        .registration_finish(finish.clone(), now + 1)
        .unwrap();
    assert!(matches!(
        service.registration_finish(finish, now + 1),
        Err(WalletNodeError::CeremonyNotFound)
    ));
    assert!(matches!(
        service.registration_start(
            PasskeyRegistrationStartRequest {
                label: "attacker".into(),
                user_name: "attacker".into(),
                display_name: "Attacker".into(),
            },
            now + 2,
        ),
        Err(WalletNodeError::RegistrationLocked)
    ));

    let bad = RelyingPartyConfig {
        rp_id: "wallet.example".into(),
        rp_origin: "http://wallet.example".into(),
        rp_name: "Wallet".into(),
        ceremony_ttl_seconds: 300,
    };
    assert!(matches!(
        WalletNodeService::without_signer(bad),
        Err(WalletNodeError::InsecureRemoteOrigin)
    ));
}

#[test]
fn concurrent_bootstrap_registration_cannot_enroll_a_second_passkey() {
    let now = 1_800_250_000;
    let (mut service, _) = configured_service();
    let first_passkey = SoftwarePasskey::new();
    let mut second_passkey = SoftwarePasskey::new();
    second_passkey.credential_id[0] ^= 1;

    let first = service
        .registration_start(
            PasskeyRegistrationStartRequest {
                label: "primary".into(),
                user_name: "owner".into(),
                display_name: "Owner".into(),
            },
            now,
        )
        .unwrap();
    let second = service
        .registration_start(
            PasskeyRegistrationStartRequest {
                label: "racing-passkey".into(),
                user_name: "attacker".into(),
                display_name: "Attacker".into(),
            },
            now,
        )
        .unwrap();

    service
        .registration_finish(
            PasskeyRegistrationFinishRequest {
                ceremony_id: first.ceremony_id,
                credential: first_passkey.registration(&first.public_key, "http://localhost:18787"),
            },
            now + 1,
        )
        .unwrap();

    assert!(matches!(
        service.registration_finish(
            PasskeyRegistrationFinishRequest {
                ceremony_id: second.ceremony_id,
                credential: second_passkey
                    .registration(&second.public_key, "http://localhost:18787"),
            },
            now + 1,
        ),
        Err(WalletNodeError::RegistrationLocked)
    ));
    assert_eq!(service.wallet_status().credentials, 1);
}

#[test]
fn signature_counter_regression_and_expired_binding_are_rejected() {
    let now = 1_800_300_000;
    let (mut service, _) = configured_service();
    let mut passkey = SoftwarePasskey::new();
    enroll(&mut service, &passkey, now);

    let first = intent(&mut service, 0x51, now + 2);
    let start = service.approval_start(first, now + 3).unwrap();
    let assertion = passkey.assertion(
        &start.public_key,
        "http://localhost:18787",
        "localhost",
        0x05,
    );
    service
        .approval_finish(
            first,
            ApprovalFinishRequest {
                ceremony_id: start.ceremony_id,
                credential: assertion,
            },
            now + 4,
        )
        .unwrap();

    passkey.counter = 0;
    let second = intent(&mut service, 0x61, now + 5);
    let start = service.approval_start(second, now + 6).unwrap();
    let assertion = passkey.assertion(
        &start.public_key,
        "http://localhost:18787",
        "localhost",
        0x05,
    );
    assert!(matches!(
        service.approval_finish(
            second,
            ApprovalFinishRequest {
                ceremony_id: start.ceremony_id,
                credential: assertion,
            },
            now + 7,
        ),
        Err(WalletNodeError::WebAuthn(_))
    ));

    let third = intent(&mut service, 0x71, now + 8);
    let start = service.approval_start(third, now + 9).unwrap();
    let assertion = passkey.assertion(
        &start.public_key,
        "http://localhost:18787",
        "localhost",
        0x05,
    );
    assert!(matches!(
        service.approval_finish(
            third,
            ApprovalFinishRequest {
                ceremony_id: start.ceremony_id,
                credential: assertion,
            },
            now + 200,
        ),
        Err(WalletNodeError::CeremonyExpired)
    ));
}

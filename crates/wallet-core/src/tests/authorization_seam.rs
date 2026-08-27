//! Package-internal proof of the legacy authorization seam and real FROST
//! BIP340 threshold signing. Production approval uses `WalletNodeService`.

use std::collections::BTreeMap;

use catomicals_threshold::{
    NonceGuard, aggregate_and_verify, build_session, generate_threshold, participant_identifier,
    session::signature_to_bytes, sign_share,
};
use catomicals_wallet::{
    ApprovalError, ApprovalVerifier, CreateIntentRequest, CryptographicApprovalVerifier,
    PasskeyApproval, PasskeyVerifier, WalletApi, WebAuthnAssertion,
    auth::b64url_encode,
    auth::make_client_data,
    intent::{IntentId, IntentStatus},
    threshold_seam::AuthorizationError,
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const TEST_NOW: i64 = 1_700_000_000;

struct TestCryptographicVerifier;

impl ApprovalVerifier for TestCryptographicVerifier {
    fn verify(
        &self,
        challenge: &[u8; 32],
        approval: &PasskeyApproval,
    ) -> Result<(), ApprovalError> {
        if challenge != &approval.intent_digest {
            return Err(ApprovalError::ChallengeMismatch);
        }
        Ok(())
    }
}

impl CryptographicApprovalVerifier for TestCryptographicVerifier {}

fn digest(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn approval_for(intent_digest: [u8; 32]) -> PasskeyApproval {
    let b64 = b64url_encode(&intent_digest);
    PasskeyApproval {
        intent_digest,
        assertion: WebAuthnAssertion {
            credential_id: "cred-1".to_owned(),
            authenticator_data: b64url_encode(&[1u8; 37]),
            client_data_json: b64url_encode(make_client_data(&b64).as_bytes()),
            signature: b64url_encode(&[2u8; 64]),
        },
    }
}

fn build_api(now: i64) -> (WalletApi, IntentId) {
    let kg = generate_threshold(3, 2).expect("keygen");
    let xonly = catomicals_threshold::group_pubkey_xonly(&kg.public_key_package).expect("xonly");
    let mut api = WalletApi::new();
    api.configure_threshold(2, 3, xonly);
    api.set_signers(vec![
        catomicals_wallet::SignerSnapshot {
            id: 1,
            label: "signer-1".into(),
            online: true,
        },
        catomicals_wallet::SignerSnapshot {
            id: 2,
            label: "signer-2".into(),
            online: true,
        },
        catomicals_wallet::SignerSnapshot {
            id: 3,
            label: "signer-3".into(),
            online: false,
        },
    ]);
    let tx_digest = digest(b"catomicals demo transaction v1");
    let intent = api
        .create_intent(
            CreateIntentRequest {
                wallet_id: Uuid::new_v4(),
                signer_id: 1,
                tx_digest,
                session_id: digest(b"frost-session-1"),
                expiry: now + 3600,
            },
            now,
        )
        .expect("create intent");
    assert_eq!(intent.status, IntentStatus::Pending);
    (api, intent.id)
}

/// Run a full 2-of-3 FROST signing over `tx_digest` with `session_id`. Each
/// participating signer presents its own Passkey-approved authorization.
fn run_threshold_sign(
    session_id: [u8; 32],
    tx_digest: [u8; 32],
    mut authorizations: BTreeMap<u16, catomicals_wallet::SigningAuthorization>,
    nonce_guard: &mut NonceGuard,
) -> Result<[u8; 64], catomicals_threshold::SigningError> {
    let kg = generate_threshold(3, 2).expect("keygen");
    let mut commitments = BTreeMap::new();
    let mut nonces = BTreeMap::new();
    for id in [1u16, 2u16] {
        let key_package: frost_secp256k1_tr::keys::KeyPackage = kg.shares
            [&participant_identifier(id).unwrap()]
            .clone()
            .try_into()
            .expect("key package");
        let (n, c) = frost_secp256k1_tr::round1::commit(key_package.signing_share(), &mut OsRng);
        nonces.insert(id, (n, key_package));
        commitments.insert(participant_identifier(id).unwrap(), c);
    }
    let session = build_session(
        session_id,
        tx_digest,
        2,
        commitments,
        kg.public_key_package.clone(),
    );

    let mut shares = BTreeMap::new();
    for (id, (n, kp)) in nonces {
        let auth = authorizations.remove(&id).ok_or({
            catomicals_threshold::SigningError::Authorization(AuthorizationError::WrongSigner)
        })?;
        let mut auth = auth;
        shares.insert(
            participant_identifier(id).unwrap(),
            sign_share(&session, id, &n, &kp, nonce_guard, &mut auth, TEST_NOW + 1)?,
        );
    }
    let signature = aggregate_and_verify(&session, &shares)?;
    signature_to_bytes(&signature)
}

#[test]
fn passkey_gated_threshold_signing_end_to_end() {
    let now = 1_700_000_000i64;
    let mut api = build_api(now).0;
    let intent = api.list_intents().remove(0);
    let intent_id = intent.id;

    // 1. challenge is the exact intent digest
    let challenge = api.approval_challenge(&intent_id, now).expect("challenge");
    assert_eq!(challenge.challenge, intent.digest());

    // 2. human approves via Passkey (structural verification for the dev seam)
    let authorization = api
        .submit_signing(
            &intent_id,
            approval_for(challenge.challenge),
            &TestCryptographicVerifier,
            now,
        )
        .expect("submit signing");
    assert_eq!(
        api.read_approval(&intent_id).unwrap().status,
        IntentStatus::Approved
    );
    assert_eq!(authorization.tx_digest, intent.tx_digest);
    assert_eq!(authorization.session_id, intent.session_id);

    // 3. every participating share needs its own Passkey-approved intent
    let intent2 = api
        .create_intent(
            CreateIntentRequest {
                wallet_id: intent.wallet_id,
                signer_id: 2,
                tx_digest: intent.tx_digest,
                session_id: intent.session_id,
                expiry: now + 3600,
            },
            now,
        )
        .expect("intent 2");
    let challenge2 = api.approval_challenge(&intent2.id, now).unwrap();
    let authorization2 = api
        .submit_signing(
            &intent2.id,
            approval_for(challenge2.challenge),
            &TestCryptographicVerifier,
            now,
        )
        .expect("submit signing 2");

    let mut guard = NonceGuard::new();
    let mut authorizations = BTreeMap::new();
    authorizations.insert(1, authorization);
    authorizations.insert(2, authorization2);
    let sig = run_threshold_sign(
        intent.session_id,
        intent.tx_digest,
        authorizations,
        &mut guard,
    )
    .expect("threshold signature");
    assert_eq!(sig.len(), 64);

    // 4. signer consumed the token exactly once
    api.mark_signed(&intent_id, now + 3).unwrap();
    assert_eq!(
        api.read_approval(&intent_id).unwrap().status,
        IntentStatus::Signed
    );
}

#[test]
fn authorization_is_one_time() {
    let now = 1_700_000_000i64;
    let mut api = build_api(now).0;
    let intent = api.list_intents().remove(0);
    let challenge = api.approval_challenge(&intent.id, now).unwrap();
    let mut authorization = api
        .submit_signing(
            &intent.id,
            approval_for(challenge.challenge),
            &TestCryptographicVerifier,
            now,
        )
        .unwrap();

    let mut guard = NonceGuard::new();
    let kg = generate_threshold(3, 2).unwrap();
    let kp1: frost_secp256k1_tr::keys::KeyPackage = kg.shares[&participant_identifier(1).unwrap()]
        .clone()
        .try_into()
        .unwrap();
    let (n1, c1) = frost_secp256k1_tr::round1::commit(kp1.signing_share(), &mut OsRng);
    // The signing package must satisfy the key package threshold (2-of-3), so
    // include both participants' commitments even though only signer 1 signs.
    let kp2: frost_secp256k1_tr::keys::KeyPackage = kg.shares[&participant_identifier(2).unwrap()]
        .clone()
        .try_into()
        .unwrap();
    let (_n2, c2) = frost_secp256k1_tr::round1::commit(kp2.signing_share(), &mut OsRng);
    let mut commitments = BTreeMap::new();
    commitments.insert(participant_identifier(1).unwrap(), c1);
    commitments.insert(participant_identifier(2).unwrap(), c2);
    let session = build_session(
        intent.session_id,
        intent.tx_digest,
        2,
        commitments,
        kg.public_key_package.clone(),
    );
    let _ = sign_share(
        &session,
        1,
        &n1,
        &kp1,
        &mut guard,
        &mut authorization,
        now + 1,
    )
    .unwrap();

    // The same signer cannot sign again with the same token: it is consumed.
    let (n1b, _c1b) = frost_secp256k1_tr::round1::commit(kp1.signing_share(), &mut OsRng);
    let err = sign_share(
        &session,
        1,
        &n1b,
        &kp1,
        &mut guard,
        &mut authorization,
        now + 1,
    )
    .expect_err("token must be consumed");
    assert!(matches!(
        err,
        catomicals_threshold::SigningError::Authorization(AuthorizationError::AlreadyConsumed)
    ));
}

#[test]
fn second_submission_of_same_intent_rejected() {
    let now = 1_700_000_000i64;
    let mut api = build_api(now).0;
    let intent = api.list_intents().remove(0);
    let challenge = api.approval_challenge(&intent.id, now).unwrap();
    let _ = api
        .submit_signing(
            &intent.id,
            approval_for(challenge.challenge),
            &TestCryptographicVerifier,
            now,
        )
        .unwrap();
    let err = api
        .submit_signing(
            &intent.id,
            approval_for(challenge.challenge),
            &TestCryptographicVerifier,
            now,
        )
        .expect_err("already approved");
    assert!(matches!(
        err,
        catomicals_wallet::WalletError::AlreadyApproved
    ));
}

#[test]
fn wrong_approval_digest_is_rejected() {
    let now = 1_700_000_000i64;
    let mut api = build_api(now).0;
    let intent = api.list_intents().remove(0);
    let wrong = approval_for([0xAB; 32]);
    let err = api
        .submit_signing(&intent.id, wrong, &TestCryptographicVerifier, now)
        .expect_err("wrong digest");
    assert!(matches!(
        err,
        catomicals_wallet::WalletError::Gate(catomicals_wallet::GateError::ApprovalMismatch)
    ));
}

#[test]
fn expired_intent_is_rejected() {
    let now = 1_700_000_000i64;
    let mut api = WalletApi::new();
    let intent = api
        .create_intent(
            CreateIntentRequest {
                wallet_id: Uuid::new_v4(),
                signer_id: 1,
                tx_digest: [1u8; 32],
                session_id: [2u8; 32],
                expiry: now + 3600,
            },
            now,
        )
        .expect("create");
    // The intent expires before the approval is submitted.
    let err = api
        .submit_signing(
            &intent.id,
            approval_for(intent.digest()),
            &TestCryptographicVerifier,
            now + 7200,
        )
        .expect_err("expired");
    assert!(matches!(
        err,
        catomicals_wallet::WalletError::Gate(catomicals_wallet::GateError::Expired)
    ));
}

#[test]
fn nonce_reuse_is_rejected_by_guard() {
    let now = 1_700_000_000i64;
    let mut api = build_api(now).0;
    let intent = api.list_intents().remove(0);
    let challenge = api.approval_challenge(&intent.id, now).unwrap();
    let mut auth_a = api
        .submit_signing(
            &intent.id,
            approval_for(challenge.challenge),
            &TestCryptographicVerifier,
            now,
        )
        .unwrap();

    // A second approved intent lets the same signer try again — the nonce
    // guard is what must stop the reuse.
    let intent2 = api
        .create_intent(
            CreateIntentRequest {
                wallet_id: intent.wallet_id,
                signer_id: 1,
                tx_digest: intent.tx_digest,
                session_id: [0x0B; 32],
                expiry: now + 3600,
            },
            now,
        )
        .unwrap();
    let challenge2 = api.approval_challenge(&intent2.id, now).unwrap();
    let mut auth_b = api
        .submit_signing(
            &intent2.id,
            approval_for(challenge2.challenge),
            &TestCryptographicVerifier,
            now,
        )
        .unwrap();

    let kg = generate_threshold(3, 2).unwrap();
    let kp: frost_secp256k1_tr::keys::KeyPackage = kg.shares[&participant_identifier(1).unwrap()]
        .clone()
        .try_into()
        .unwrap();
    let (nonces, commitments) = frost_secp256k1_tr::round1::commit(kp.signing_share(), &mut OsRng);

    let kp2: frost_secp256k1_tr::keys::KeyPackage = kg.shares[&participant_identifier(2).unwrap()]
        .clone()
        .try_into()
        .unwrap();
    let (_n2, c2) = frost_secp256k1_tr::round1::commit(kp2.signing_share(), &mut OsRng);

    let mut guard = NonceGuard::new();
    // Session A uses the first intent's session id (bound by auth_a).
    let mut ca = BTreeMap::new();
    ca.insert(participant_identifier(1).unwrap(), commitments);
    ca.insert(participant_identifier(2).unwrap(), c2);
    let session_a = build_session(
        intent.session_id,
        intent.tx_digest,
        2,
        ca,
        kg.public_key_package.clone(),
    );
    // Session B (different id, same message)
    let mut cb = BTreeMap::new();
    cb.insert(participant_identifier(1).unwrap(), commitments);
    cb.insert(participant_identifier(2).unwrap(), c2);
    let session_b = build_session(
        [0x0B; 32],
        intent.tx_digest,
        2,
        cb,
        kg.public_key_package.clone(),
    );

    // First use in session A succeeds.
    let _ = sign_share(
        &session_a,
        1,
        &nonces,
        &kp,
        &mut guard,
        &mut auth_a,
        now + 1,
    )
    .unwrap();

    // Reuse of the same nonces in session B must be rejected by the guard.
    let err = sign_share(
        &session_b,
        1,
        &nonces,
        &kp,
        &mut guard,
        &mut auth_b,
        now + 1,
    )
    .expect_err("nonce reuse");
    assert!(matches!(
        err,
        catomicals_threshold::SigningError::NonceReuse(
            catomicals_threshold::NonceReuseError::ReusedInOtherSession(_)
        )
    ));
}

#[test]
fn wrong_message_does_not_verify() {
    let now = 1_700_000_000i64;
    let mut api = build_api(now).0;
    let intent = api.list_intents().remove(0);
    let challenge = api.approval_challenge(&intent.id, now).unwrap();
    let authorization = api
        .submit_signing(
            &intent.id,
            approval_for(challenge.challenge),
            &TestCryptographicVerifier,
            now,
        )
        .unwrap();

    let kg = generate_threshold(3, 2).unwrap();
    let mut commitments = BTreeMap::new();
    let mut nonces = BTreeMap::new();
    for id in [1u16, 2u16] {
        let kp: frost_secp256k1_tr::keys::KeyPackage = kg.shares
            [&participant_identifier(id).unwrap()]
            .clone()
            .try_into()
            .unwrap();
        let (n, c) = frost_secp256k1_tr::round1::commit(kp.signing_share(), &mut OsRng);
        nonces.insert(id, (n, kp));
        commitments.insert(participant_identifier(id).unwrap(), c);
    }
    let mut guard = NonceGuard::new();
    // Session over the *intended* message
    let session = build_session(
        intent.session_id,
        intent.tx_digest,
        2,
        commitments.clone(),
        kg.public_key_package.clone(),
    );
    let mut shares = BTreeMap::new();
    for (id, (n, kp)) in nonces {
        // fresh authorizations for the second participant
        let mut auth = authorization.clone();
        if id == 2 {
            let intent2 = api
                .create_intent(
                    CreateIntentRequest {
                        wallet_id: intent.wallet_id,
                        signer_id: 2,
                        tx_digest: intent.tx_digest,
                        session_id: intent.session_id,
                        expiry: now + 3600,
                    },
                    now,
                )
                .unwrap();
            auth = api
                .submit_signing(
                    &intent2.id,
                    approval_for(intent2.digest()),
                    &TestCryptographicVerifier,
                    now,
                )
                .unwrap();
        }
        shares.insert(
            participant_identifier(id).unwrap(),
            sign_share(&session, id, &n, &kp, &mut guard, &mut auth, now + 1).unwrap(),
        );
    }
    // Aggregate without requiring verification so we can attack the message.
    let signature = catomicals_threshold::session::aggregate(
        &session.signing_package,
        &shares,
        &session.public_key_package,
    )
    .unwrap();

    // Now verify the *same* signature against a different message digest.
    let wrong_session = build_session(
        intent.session_id,
        digest(b"attacker message"),
        2,
        commitments,
        kg.public_key_package,
    );
    let err = catomicals_threshold::session::verify_signature(&wrong_session, &signature)
        .expect_err("must not verify");
    assert!(matches!(err, catomicals_threshold::SigningError::Frost(_)));
}

#[test]
fn approval_verifier_binds_challenge() {
    // Sanity: an approval whose client-data challenge is not the intent digest
    // is rejected even if the `intent_digest` field was forged to match.
    let intent_digest = [7u8; 32];
    let other = b64url_encode(&[9u8; 32]);
    let approval = PasskeyApproval {
        intent_digest,
        assertion: WebAuthnAssertion {
            credential_id: "cred-1".into(),
            authenticator_data: b64url_encode(&[1u8; 37]),
            client_data_json: b64url_encode(make_client_data(&other).as_bytes()),
            signature: b64url_encode(&[2u8; 64]),
        },
    };
    let verifier = PasskeyVerifier {
        credentials: &|_| true,
        verify_assertion: &|_| Ok(()),
    };
    assert_eq!(
        verifier.verify(&intent_digest, &approval),
        Err(catomicals_wallet::ApprovalError::ChallengeMismatch)
    );
}

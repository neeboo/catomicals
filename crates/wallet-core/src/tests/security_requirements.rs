//! Package-internal security acceptance tests for the wallet-to-FROST seam.

use std::collections::BTreeMap;

use catomicals_threshold::{
    AuthorizationError, NonceGuard, NonceReuseError, SigningError, aggregate_and_verify,
    build_session, generate_threshold, group_pubkey_xonly, participant_identifier, sign_share,
    signature_to_bytes,
};
use catomicals_wallet::{
    ApprovalError, ApprovalVerifier, CreateIntentRequest, CryptographicApprovalVerifier,
    PasskeyApproval, SigningAuthorization, WalletApi, WebAuthnAssertion,
};
use frost_secp256k1_tr::{keys::KeyPackage, round1};
use rand::rngs::OsRng;
use secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const NOW: i64 = 1_700_000_000;

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

fn digest(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

fn approval(intent_digest: [u8; 32]) -> PasskeyApproval {
    PasskeyApproval {
        intent_digest,
        assertion: WebAuthnAssertion {
            credential_id: "test-credential".into(),
            authenticator_data: String::new(),
            client_data_json: String::new(),
            signature: String::new(),
        },
    }
}

fn create_intent(
    api: &mut WalletApi,
    wallet_id: Uuid,
    signer_id: u16,
    message: [u8; 32],
    session_id: [u8; 32],
    expiry: i64,
) -> catomicals_wallet::SigningIntent {
    api.create_intent(
        CreateIntentRequest {
            wallet_id,
            signer_id,
            tx_digest: message,
            session_id,
            expiry,
        },
        NOW,
    )
    .unwrap()
}

fn authorize(
    api: &mut WalletApi,
    intent: &catomicals_wallet::SigningIntent,
) -> SigningAuthorization {
    api.submit_signing(
        &intent.id,
        approval(intent.digest()),
        &TestCryptographicVerifier,
        NOW,
    )
    .unwrap()
}

#[test]
fn authorization_records_issuance_time_and_expires_at_signer_use() {
    let wallet_id = Uuid::new_v4();
    let message = digest(b"expiry test transaction");
    let session_id = digest(b"expiry test session");
    let mut api = WalletApi::new();
    let intent = create_intent(&mut api, wallet_id, 1, message, session_id, NOW + 60);
    let mut authorization = authorize(&mut api, &intent);
    assert_eq!(authorization.issued_at, NOW);

    let keygen = generate_threshold(3, 2).unwrap();
    let key_package: KeyPackage = keygen.shares[&participant_identifier(1).unwrap()]
        .clone()
        .try_into()
        .unwrap();
    let (nonces, commitment) = round1::commit(key_package.signing_share(), &mut OsRng);
    let key_package_2: KeyPackage = keygen.shares[&participant_identifier(2).unwrap()]
        .clone()
        .try_into()
        .unwrap();
    let (_, commitment_2) = round1::commit(key_package_2.signing_share(), &mut OsRng);
    let commitments = BTreeMap::from([
        (participant_identifier(1).unwrap(), commitment),
        (participant_identifier(2).unwrap(), commitment_2),
    ]);
    let session = build_session(
        session_id,
        message,
        2,
        commitments,
        keygen.public_key_package,
    );

    let error = sign_share(
        &session,
        1,
        &nonces,
        &key_package,
        &mut NonceGuard::new(),
        &mut authorization,
        NOW + 61,
    )
    .expect_err("authorization must be checked again when the share is used");
    assert!(matches!(
        error,
        SigningError::Authorization(AuthorizationError::Expired)
    ));
}

#[test]
fn real_two_of_three_signature_is_bip340_compatible_and_rejects_wrong_message() {
    let wallet_id = Uuid::new_v4();
    let message = digest(b"protected trade transaction");
    let session_id = digest(b"protected trade frost session");
    let keygen = generate_threshold(3, 2).unwrap();
    let xonly = group_pubkey_xonly(&keygen.public_key_package).unwrap();
    let mut api = WalletApi::new();

    let mut authorizations = BTreeMap::new();
    for signer_id in [1u16, 2u16] {
        let intent = create_intent(
            &mut api,
            wallet_id,
            signer_id,
            message,
            session_id,
            NOW + 300,
        );
        authorizations.insert(signer_id, authorize(&mut api, &intent));
    }

    let mut commitments = BTreeMap::new();
    let mut signer_material = BTreeMap::new();
    for signer_id in [1u16, 2u16] {
        let key_package: KeyPackage = keygen.shares[&participant_identifier(signer_id).unwrap()]
            .clone()
            .try_into()
            .unwrap();
        let (nonces, commitment) = round1::commit(key_package.signing_share(), &mut OsRng);
        commitments.insert(participant_identifier(signer_id).unwrap(), commitment);
        signer_material.insert(signer_id, (nonces, key_package));
    }
    let session = build_session(
        session_id,
        message,
        2,
        commitments,
        keygen.public_key_package,
    );
    let mut nonce_guard = NonceGuard::new();
    let mut shares = BTreeMap::new();
    for (signer_id, (nonces, key_package)) in signer_material {
        let share = sign_share(
            &session,
            signer_id,
            &nonces,
            &key_package,
            &mut nonce_guard,
            authorizations.get_mut(&signer_id).unwrap(),
            NOW + 1,
        )
        .unwrap();
        shares.insert(participant_identifier(signer_id).unwrap(), share);
    }

    let signature = signature_to_bytes(&aggregate_and_verify(&session, &shares).unwrap()).unwrap();
    assert_eq!(signature.len(), 64);

    // Verify with rust-secp256k1's independent BIP340 implementation, which is
    // the same 64-byte signature format accepted by Taproot key-path spends.
    let secp = Secp256k1::verification_only();
    let public_key = XOnlyPublicKey::from_slice(&xonly).unwrap();
    let schnorr_signature = Signature::from_slice(&signature).unwrap();
    secp.verify_schnorr(
        &schnorr_signature,
        &Message::from_digest(message),
        &public_key,
    )
    .unwrap();
    assert!(
        secp.verify_schnorr(
            &schnorr_signature,
            &Message::from_digest(digest(b"wrong transaction")),
            &public_key,
        )
        .is_err()
    );
}

#[test]
fn signer_id_binding_and_nonce_reuse_are_rejected() {
    let wallet_id = Uuid::new_v4();
    let message = digest(b"signer and nonce test transaction");
    let session_a_id = digest(b"session-a");
    let session_b_id = digest(b"session-b");
    let keygen = generate_threshold(3, 2).unwrap();
    let key_package_1: KeyPackage = keygen.shares[&participant_identifier(1).unwrap()]
        .clone()
        .try_into()
        .unwrap();
    let key_package_2: KeyPackage = keygen.shares[&participant_identifier(2).unwrap()]
        .clone()
        .try_into()
        .unwrap();
    let (nonces_1, commitment_1) = round1::commit(key_package_1.signing_share(), &mut OsRng);
    let (_, commitment_2) = round1::commit(key_package_2.signing_share(), &mut OsRng);
    let commitments = BTreeMap::from([
        (participant_identifier(1).unwrap(), commitment_1),
        (participant_identifier(2).unwrap(), commitment_2),
    ]);

    let mut api = WalletApi::new();
    let signer_one_intent = create_intent(&mut api, wallet_id, 1, message, session_a_id, NOW + 300);
    let mut wrong_signer_authorization = authorize(&mut api, &signer_one_intent);
    let session_a = build_session(
        session_a_id,
        message,
        2,
        commitments.clone(),
        keygen.public_key_package.clone(),
    );
    let error = sign_share(
        &session_a,
        2,
        &nonces_1,
        &key_package_2,
        &mut NonceGuard::new(),
        &mut wrong_signer_authorization,
        NOW + 1,
    )
    .expect_err("authorization for signer 1 must not authorize signer 2");
    assert!(matches!(
        error,
        SigningError::Authorization(AuthorizationError::WrongSigner)
    ));

    let first_intent = create_intent(&mut api, wallet_id, 1, message, session_a_id, NOW + 300);
    let second_intent = create_intent(&mut api, wallet_id, 1, message, session_b_id, NOW + 300);
    let mut first_authorization = authorize(&mut api, &first_intent);
    let mut second_authorization = authorize(&mut api, &second_intent);
    let session_b = build_session(
        session_b_id,
        message,
        2,
        commitments,
        keygen.public_key_package,
    );
    let mut guard = NonceGuard::new();
    sign_share(
        &session_a,
        1,
        &nonces_1,
        &key_package_1,
        &mut guard,
        &mut first_authorization,
        NOW + 1,
    )
    .unwrap();
    let error = sign_share(
        &session_b,
        1,
        &nonces_1,
        &key_package_1,
        &mut guard,
        &mut second_authorization,
        NOW + 1,
    )
    .expect_err("FROST nonce reuse must be rejected across sessions");
    assert!(matches!(
        error,
        SigningError::NonceReuse(NonceReuseError::ReusedInOtherSession(_))
    ));
}

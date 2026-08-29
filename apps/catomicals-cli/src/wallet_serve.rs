//! Typed HTTP adapter for the self-hosted wallet node.

use std::{
    io::Read,
    sync::{Arc, Mutex},
    time::Duration,
};

use catomicals_threshold::{
    LocalFrostParticipant, NonceGuard, participant_identifier, run_local_dkg,
};
use catomicals_wallet::{
    ApprovalFinishRequest, CreateChatMessageRequest, CreateIntentRequest, CreateTradeIntentRequest,
    CreateTransactionIntentRequest, PasskeyRegistrationFinishRequest,
    PasskeyRegistrationStartRequest, RelyingPartyConfig, TradeSigningRequest,
    TransactionReviewRequest, WalletNodeError, WalletNodeService, WalletStore,
};
use catomicals_wallet_storage::RestoreState;
use serde::Serialize;
use serde_json::json;
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

use crate::wallet::ServeArgs;

const MAX_HTTP_BODY_BYTES: usize = 1024 * 1024;
const NODE_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

pub fn serve(args: ServeArgs) -> anyhow::Result<()> {
    let addr = args.addr.clone();
    if !is_loopback_bind(&addr) && !args.allow_non_loopback_bind {
        anyhow::bail!(
            "wallet server bind `{addr}` is not loopback; pass --allow-non-loopback-bind behind an HTTPS reverse proxy"
        );
    }

    let config = RelyingPartyConfig {
        rp_id: args.rp_id.clone(),
        rp_origin: args.rp_origin.clone(),
        rp_name: args.rp_name.clone(),
        ceremony_ttl_seconds: args.ceremony_ttl_seconds,
    };
    let now = unix_time();
    let (mut api, signer_lease) = if let Some(data_dir) = &args.data_dir {
        let wallet_id = uuid::Uuid::parse_str(&args.wallet_id)
            .map_err(|error| anyhow::anyhow!("invalid --wallet-id: {error}"))?;
        let store = crate::walletd::open_authority(data_dir, wallet_id, now)?;
        let authority_wallet_id = store
            .wallet_id()
            .ok_or_else(|| anyhow::anyhow!("durable wallet authority is not initialized"))?;
        let signer = open_durable_signer(
            data_dir,
            authority_wallet_id,
            args.signer_id,
            now,
            store.restore_state()?,
        )?;
        let min_signers = signer.min_signers();
        let (participant, public_key_package, _audit, lease) = signer.into_runtime_parts();
        (
            WalletNodeService::new_with_recovered_signer_store(
                config,
                participant,
                public_key_package,
                min_signers,
                Box::new(store),
                now,
            )?,
            Some(lease),
        )
    } else {
        let mut dkg = run_local_dkg(3, 2).map_err(|error| anyhow::anyhow!("local DKG: {error}"))?;
        let key_package = dkg
            .key_packages
            .remove(&participant_identifier(args.signer_id)?)
            .ok_or_else(|| anyhow::anyhow!("signer id must be in 1..=3"))?;
        let participant =
            LocalFrostParticipant::new(args.signer_id, key_package, NonceGuard::new())?;
        (
            WalletNodeService::new(config, Some(participant), dkg.public_key_package, 2)?,
            None,
        )
    };
    if let Some(node) = crate::wallet::probe_node_public(&args.node) {
        api.set_node_snapshot(Some(node));
    }

    let server = Server::http(&addr).map_err(|error| anyhow::anyhow!("binding {addr}: {error}"))?;
    let state = Arc::new(Mutex::new(api));
    spawn_node_refresh(Arc::clone(&state), args.node.clone())?;
    let cors = args.cors_origin.clone();

    println!("catomicals wallet server on http://{addr}");
    println!("  WebAuthn RP: {} at {}", args.rp_id, args.rp_origin);
    println!("  CORS origin: {cors}");
    if args.data_dir.is_some() {
        println!("  authority state: durable SQLite (schema checked; single writer)");
        println!("  signer: one recovered local participant (encrypted development backend)");
        println!("  secret storage: XChaCha20-Poly1305 envelope records; private files are 0600");
    } else {
        println!(
            "  signer: {} (ephemeral local DKG; development only)",
            args.signer_id
        );
        println!("  persistence and secret storage: process memory only");
    }
    println!("  node RPC is never exposed by this service");

    for request in server.incoming_requests() {
        let _ = handle(&state, &cors, request);
    }
    drop(signer_lease);
    Ok(())
}

fn open_durable_signer(
    data_dir: &std::path::Path,
    wallet_id: uuid::Uuid,
    signer_id: u16,
    now: i64,
    restore_state: RestoreState,
) -> anyhow::Result<crate::persistent_signer::PersistentSigner> {
    if restore_state == RestoreState::Normal {
        crate::persistent_signer::PersistentSigner::open_or_initialize(
            data_dir, wallet_id, signer_id, now,
        )
    } else {
        crate::persistent_signer::PersistentSigner::open_existing(
            data_dir, wallet_id, signer_id,
        )
        .map_err(|error| {
            anyhow::anyhow!(
                "wallet authority is in {restore_state:?}; refusing to initialize a replacement signer: {error:#}"
            )
        })
    }
}

fn update_node_snapshot(
    state: &Mutex<WalletNodeService>,
    snapshot: Option<catomicals_wallet::NodeSnapshot>,
) {
    if let Ok(mut api) = state.lock() {
        api.set_node_snapshot(snapshot);
    }
}

fn spawn_node_refresh(
    state: Arc<Mutex<WalletNodeService>>,
    node: crate::NodeArgs,
) -> anyhow::Result<()> {
    std::thread::Builder::new()
        .name("catomicals-node-refresh".into())
        .spawn(move || {
            loop {
                std::thread::sleep(NODE_REFRESH_INTERVAL);
                update_node_snapshot(&state, crate::wallet::probe_node_public(&node));
            }
        })
        .map(|_| ())
        .map_err(|error| anyhow::anyhow!("starting node refresh worker: {error}"))
}

fn is_loopback_bind(addr: &str) -> bool {
    if let Ok(socket) = addr.parse::<std::net::SocketAddr>() {
        return socket.ip().is_loopback();
    }
    let Some((host, port)) = addr.rsplit_once(':') else {
        return false;
    };
    host.eq_ignore_ascii_case("localhost") && port.parse::<u16>().is_ok()
}

fn handle(
    state: &Mutex<WalletNodeService>,
    cors: &str,
    mut request: Request,
) -> std::io::Result<()> {
    let method = request.method().clone();
    let url = request.url().to_string();
    let result = if method == Method::Options {
        JsonResponse {
            status: 204,
            body: String::new(),
        }
    } else {
        match read_json_body(request.as_reader()) {
            Ok(body) => dispatch_json(state, &method, &url, &body, unix_time()),
            Err(response) => response,
        }
    };
    respond(cors, request, result)
}

fn unix_time() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

struct JsonResponse {
    status: u16,
    body: String,
}

fn read_json_body(mut reader: impl Read) -> Result<String, JsonResponse> {
    let mut bytes = Vec::with_capacity(4096);
    reader
        .by_ref()
        .take((MAX_HTTP_BODY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            json_response(
                400,
                &json!({"error": {"code": "request_body_unreadable", "message": error.to_string()}}),
            )
        })?;
    if bytes.len() > MAX_HTTP_BODY_BYTES {
        return Err(json_response(
            413,
            &json!({"error": {
                "code": "request_body_too_large",
                "message": format!("request body exceeds {MAX_HTTP_BODY_BYTES} bytes")
            }}),
        ));
    }
    String::from_utf8(bytes).map_err(|error| {
        json_response(
            400,
            &json!({"error": {"code": "invalid_json", "message": error.to_string()}}),
        )
    })
}

fn json_response(status: u16, value: &impl Serialize) -> JsonResponse {
    JsonResponse {
        status,
        body: serde_json::to_string(value).unwrap_or_else(|_| {
            r#"{"error":{"code":"serialization","message":"response serialization failed"}}"#.into()
        }),
    }
}

fn parse_body<T: serde::de::DeserializeOwned>(body: &str) -> Result<T, JsonResponse> {
    serde_json::from_str(body).map_err(|error| {
        json_response(
            400,
            &json!({"error": {"code": "invalid_json", "message": error.to_string()}}),
        )
    })
}

fn parse_id(value: &str) -> Result<uuid::Uuid, JsonResponse> {
    uuid::Uuid::parse_str(value).map_err(|error| {
        json_response(
            400,
            &json!({"error": {"code": "invalid_intent_id", "message": error.to_string()}}),
        )
    })
}

fn parse_chat_message_id(value: &str) -> Result<uuid::Uuid, JsonResponse> {
    uuid::Uuid::parse_str(value).map_err(|error| {
        json_response(
            400,
            &json!({"error": {"code": "invalid_chat_message_id", "message": error.to_string()}}),
        )
    })
}

fn node_error(error: WalletNodeError) -> JsonResponse {
    let (status, code) = match error {
        WalletNodeError::IntentNotFound => (404, "intent_not_found"),
        WalletNodeError::ChatMessageNotFound => (404, "chat_message_not_found"),
        WalletNodeError::CeremonyNotFound => (409, "ceremony_consumed_or_missing"),
        WalletNodeError::NoCredentials => (409, "passkey_required"),
        WalletNodeError::IntentNotPending
        | WalletNodeError::IntentExpired
        | WalletNodeError::IntentBindingMismatch
        | WalletNodeError::AuthorizationUnavailable
        | WalletNodeError::RecoveredIntentApprovalUnavailable
        | WalletNodeError::CeremonyExpired
        | WalletNodeError::CredentialAlreadyRegistered => (409, "state_conflict"),
        WalletNodeError::WebAuthn(_) | WalletNodeError::UserVerificationRequired => {
            (401, "webauthn_rejected")
        }
        WalletNodeError::TradeNodeUnavailable => (503, "trade_node_unavailable"),
        WalletNodeError::TradePolicy(_) => (422, "trade_policy_rejected"),
        WalletNodeError::TransactionPolicy(_) => (422, "transaction_policy_rejected"),
        WalletNodeError::InvalidChatMessage => (422, "invalid_chat_message"),
        WalletNodeError::ChatHistoryFull => (429, "chat_history_full"),
        _ => (400, "invalid_request"),
    };
    json_response(
        status,
        &json!({"error": {"code": code, "message": error.to_string()}}),
    )
}

fn dispatch_json(
    state: &Mutex<WalletNodeService>,
    method: &Method,
    url: &str,
    body: &str,
    now: i64,
) -> JsonResponse {
    let mut api = match state.lock() {
        Ok(api) => api,
        Err(_) => {
            return json_response(
                500,
                &json!({"error": {"code": "state_poisoned", "message": "wallet state unavailable"}}),
            );
        }
    };
    let path = url.split_once('?').map_or(url, |(path, _)| path);
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();

    let result: Result<(u16, serde_json::Value), JsonResponse> = match (method, segments.as_slice())
    {
        (&Method::Get, ["api", "v1", "node", "status"]) => {
            return json_response(200, &api.node_status());
        }
        (&Method::Get, ["api", "v1", "wallet", "status"]) | (&Method::Get, ["api", "status"]) => {
            return json_response(200, &api.wallet_status());
        }
        (&Method::Get, ["api", "v1", "signer", "status"]) => {
            return json_response(200, &api.signer_status());
        }
        (&Method::Get, ["api", "v1", "webauthn", "credentials"]) => {
            return json_response(200, &api.credentials());
        }
        (&Method::Get, ["api", "v1", "intents"]) => {
            return json_response(200, &api.list_intents());
        }
        (&Method::Get, ["api", "v1", "chat", "state"]) => {
            return json_response(200, &api.chat_state(now));
        }
        (&Method::Post, ["api", "v1", "chat", "messages"]) => {
            parse_body::<CreateChatMessageRequest>(body)
                .and_then(|request| api.create_chat_message(request, now).map_err(node_error))
                .map(|value| (201, serde_json::to_value(value).unwrap_or_default()))
        }
        (&Method::Get, ["api", "v1", "chat", "messages", id]) => parse_chat_message_id(id)
            .and_then(|id| api.read_chat_message(id, now).map_err(node_error))
            .map(|value| (200, serde_json::to_value(value).unwrap_or_default())),
        (&Method::Post, ["api", "v1", "transactions", "inspect"]) => {
            parse_body::<TransactionReviewRequest>(body)
                .and_then(|request| api.inspect_transaction(&request).map_err(node_error))
                .map(|value| (200, serde_json::to_value(value).unwrap_or_default()))
        }
        (&Method::Post, ["api", "v1", "transactions", "intents"]) => {
            parse_body::<CreateTransactionIntentRequest>(body)
                .and_then(|request| {
                    api.create_transaction_intent(request, now)
                        .map_err(node_error)
                })
                .map(|value| (201, serde_json::to_value(value).unwrap_or_default()))
        }
        (&Method::Get, ["api", "v1", "transactions", "intents", id]) => parse_id(id)
            .and_then(|id| api.transaction_review(id).map_err(node_error))
            .map(|value| (200, serde_json::to_value(value).unwrap_or_default())),
        (&Method::Post, ["api", "v1", "trades", "verify"]) => {
            parse_body::<TradeSigningRequest>(body)
                .and_then(|request| api.verify_trade_for_agent(&request).map_err(node_error))
                .map(|value| (200, serde_json::to_value(value).unwrap_or_default()))
        }
        (&Method::Post, ["api", "v1", "trades", "intents"]) => {
            parse_body::<CreateTradeIntentRequest>(body)
                .and_then(|request| api.create_trade_intent(request, now).map_err(node_error))
                .map(|value| (201, serde_json::to_value(value).unwrap_or_default()))
        }
        (&Method::Get, ["api", "v1", "trades", "intents", id]) => parse_id(id)
            .and_then(|id| api.trade_verification(id).map_err(node_error))
            .map(|value| (200, serde_json::to_value(value).unwrap_or_default())),
        (&Method::Post, ["api", "v1", "intents"]) => parse_body::<CreateIntentRequest>(body)
            .and_then(|request| api.create_intent(request, now).map_err(node_error))
            .map(|value| (201, serde_json::to_value(value).unwrap_or_default())),
        (&Method::Get, ["api", "v1", "intents", id]) => parse_id(id)
            .and_then(|id| api.read_intent(id).map_err(node_error))
            .map(|value| (200, serde_json::to_value(value).unwrap_or_default())),
        (&Method::Post, ["api", "v1", "intents", id, "cancel"]) => parse_id(id)
            .and_then(|id| api.cancel_intent(id, now).map_err(node_error))
            .map(|value| (200, serde_json::to_value(value).unwrap_or_default())),
        (&Method::Post, ["api", "v1", "webauthn", "register", "start"]) => {
            parse_body::<PasskeyRegistrationStartRequest>(body)
                .and_then(|request| api.registration_start(request, now).map_err(node_error))
                .map(|value| (200, serde_json::to_value(value).unwrap_or_default()))
        }
        (&Method::Post, ["api", "v1", "webauthn", "register", "finish"]) => {
            parse_body::<PasskeyRegistrationFinishRequest>(body)
                .and_then(|request| api.registration_finish(request, now).map_err(node_error))
                .map(|value| (200, serde_json::to_value(value).unwrap_or_default()))
        }
        (&Method::Post, ["api", "v1", "intents", id, "approve", "start"]) => parse_id(id)
            .and_then(|id| api.approval_start(id, now).map_err(node_error))
            .map(|value| (200, serde_json::to_value(value).unwrap_or_default())),
        (&Method::Post, ["api", "v1", "intents", id, "approve", "finish"]) => parse_id(id)
            .and_then(|id| {
                parse_body::<ApprovalFinishRequest>(body)
                    .and_then(|request| api.approval_finish(id, request, now).map_err(node_error))
            })
            .map(|value| (200, serde_json::to_value(value).unwrap_or_default())),
        (&Method::Get, ["api", "v1", "signing", id, "status"]) => parse_id(id)
            .and_then(|id| api.signing_status(id, now).map_err(node_error))
            .map(|value| (200, serde_json::to_value(value).unwrap_or_default())),
        _ => {
            return json_response(
                404,
                &json!({"error": {"code": "route_not_found", "message": "not found"}}),
            );
        }
    };

    match result {
        Ok((status, value)) => json_response(status, &value),
        Err(response) => response,
    }
}

fn respond(cors: &str, request: Request, result: JsonResponse) -> std::io::Result<()> {
    let mut response =
        Response::from_string(result.body).with_status_code(StatusCode(result.status));
    response
        .add_header(Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap());
    response.add_header(
        Header::from_bytes(&b"Access-Control-Allow-Origin"[..], cors.as_bytes()).unwrap(),
    );
    response.add_header(
        Header::from_bytes(
            &b"Access-Control-Allow-Methods"[..],
            &b"GET, POST, OPTIONS"[..],
        )
        .unwrap(),
    );
    response.add_header(
        Header::from_bytes(&b"Access-Control-Allow-Headers"[..], &b"Content-Type"[..]).unwrap(),
    );
    request.respond(response)
}

#[cfg(test)]
mod typed_route_tests {
    use super::*;
    use bitcoin::{
        Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
        Witness, absolute,
        consensus::encode::serialize_hex,
        hashes::Hash,
        secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey},
        transaction,
    };
    use catomicals_threshold::{
        LocalFrostParticipant, NonceGuard, participant_identifier, run_local_dkg,
    };
    use catomicals_wallet::{CreateIntentRequest, RelyingPartyConfig, WalletNodeService};
    use uuid::Uuid;

    #[test]
    fn recovery_state_never_creates_a_replacement_signer() {
        let directory = tempfile::tempdir().unwrap();
        let wallet_id = Uuid::from_bytes([0x28; 16]);

        let error = open_durable_signer(
            directory.path(),
            wallet_id,
            1,
            1_800_000_000,
            RestoreState::Recovering,
        )
        .unwrap_err();

        assert!(error.to_string().contains("refusing to initialize"));
        assert!(!directory.path().join("signer.json").exists());
        assert!(!directory.path().join("signer-secrets").exists());
    }

    fn service() -> Mutex<WalletNodeService> {
        let mut dkg = run_local_dkg(3, 2).unwrap();
        let participant = LocalFrostParticipant::new(
            1,
            dkg.key_packages
                .remove(&participant_identifier(1).unwrap())
                .unwrap(),
            NonceGuard::new(),
        )
        .unwrap();
        Mutex::new(
            WalletNodeService::new(
                RelyingPartyConfig::default(),
                Some(participant),
                dkg.public_key_package,
                2,
            )
            .unwrap(),
        )
    }

    #[test]
    fn recovered_intent_approval_has_a_stable_state_conflict_error() {
        let response = node_error(WalletNodeError::RecoveredIntentApprovalUnavailable);
        assert_eq!(response.status, 409);
        let body: serde_json::Value = serde_json::from_str(&response.body).unwrap();
        assert_eq!(body["error"]["code"], "state_conflict");
    }

    fn p2tr_script(secret: u8) -> ScriptBuf {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[secret; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
        Address::p2tr(&secp, xonly, None, Network::Signet).script_pubkey()
    }

    fn transaction_review_json() -> serde_json::Value {
        let spent = OutPoint::new(Txid::from_byte_array([8; 32]), 1);
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: spent,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(95_000),
                script_pubkey: p2tr_script(9),
            }],
        };
        json!({
            "raw_tx_hex": serialize_hex(&tx),
            "prevouts": [{
                "outpoint": spent.to_string(),
                "value_sat": 100_000,
                "script_pubkey_hex": hex::encode(p2tr_script(8).as_bytes()),
            }],
            "input_index": 0,
            "max_fee_sat": 5_000,
        })
    }

    #[test]
    fn transaction_review_routes_derive_digest_and_reject_digest_injection() {
        let state = service();
        let transaction = transaction_review_json();
        let inspect = dispatch_json(
            &state,
            &Method::Post,
            "/api/v1/transactions/inspect",
            &transaction.to_string(),
            1_800_000_000,
        );
        assert_eq!(inspect.status, 200, "{}", inspect.body);
        let review: serde_json::Value = serde_json::from_str(&inspect.body).unwrap();
        assert_eq!(review["fee_sat"], 5_000);
        assert_eq!(review["sighash_hex"].as_str().map(str::len), Some(64));
        assert!(state.lock().unwrap().list_intents().is_empty());

        let create = json!({
            "wallet_id": "00000000-0000-0000-0000-000000000001",
            "signer_id": 1,
            "session_id": "22".repeat(32),
            "expiry": 1_800_000_300_i64,
            "transaction": transaction,
        });
        let response = dispatch_json(
            &state,
            &Method::Post,
            "/api/v1/transactions/intents",
            &create.to_string(),
            1_800_000_000,
        );
        assert_eq!(response.status, 201, "{}", response.body);
        let intent: serde_json::Value = serde_json::from_str(&response.body).unwrap();
        assert_eq!(intent["tx_digest"], review["sighash_hex"]);
        let id = intent["id"].as_str().unwrap();

        let stored = dispatch_json(
            &state,
            &Method::Get,
            &format!("/api/v1/transactions/intents/{id}"),
            "",
            1_800_000_001,
        );
        assert_eq!(stored.status, 200, "{}", stored.body);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&stored.body).unwrap()["txid"],
            review["txid"]
        );

        let mut injected = create;
        injected["tx_digest"] = json!("ff".repeat(32));
        let rejected = dispatch_json(
            &state,
            &Method::Post,
            "/api/v1/transactions/intents",
            &injected.to_string(),
            1_800_000_000,
        );
        assert_eq!(rejected.status, 400, "{}", rejected.body);
    }

    #[test]
    fn live_node_refresh_replaces_stale_state_and_closes_on_unavailability() {
        let state = service();
        update_node_snapshot(
            &state,
            Some(catomicals_wallet::NodeSnapshot {
                chain: "signet".into(),
                blocks: 319_732,
                headers: 319_732,
                subversion: "/Satoshi:29.4.0(inquisition)/".into(),
                op_cat_active: true,
            }),
        );
        assert_eq!(
            state.lock().unwrap().wallet_status().node.unwrap().blocks,
            319_732
        );

        update_node_snapshot(&state, None);
        assert!(state.lock().unwrap().wallet_status().node.is_none());
    }

    #[test]
    fn typed_status_intent_registration_and_signing_routes_are_secret_free() {
        let state = service();
        let mut payloads = Vec::new();
        for path in [
            "/api/v1/node/status",
            "/api/v1/wallet/status",
            "/api/v1/signer/status",
        ] {
            let response = dispatch_json(&state, &Method::Get, path, "", 1_800_000_000);
            assert_eq!(response.status, 200, "{}", response.body);
            payloads.push(response.body);
        }

        let create = CreateIntentRequest {
            wallet_id: Uuid::from_bytes([1; 16]),
            signer_id: 1,
            tx_digest: [2; 32],
            session_id: [3; 32],
            expiry: 1_800_000_300,
        };
        let response = dispatch_json(
            &state,
            &Method::Post,
            "/api/v1/intents",
            &serde_json::to_string(&create).unwrap(),
            1_800_000_000,
        );
        assert_eq!(response.status, 201, "{}", response.body);
        let created = serde_json::from_str::<serde_json::Value>(&response.body).unwrap();
        assert_eq!(created["tx_digest"], hex::encode([2; 32]));
        assert_eq!(created["session_id"], hex::encode([3; 32]));
        assert_eq!(created["nonce"].as_str().map(str::len), Some(64));
        let id = created["id"].as_str().unwrap().to_owned();
        payloads.push(response.body);

        for path in [
            format!("/api/v1/intents/{id}"),
            format!("/api/v1/signing/{id}/status"),
        ] {
            let response = dispatch_json(&state, &Method::Get, &path, "", 1_800_000_001);
            assert_eq!(response.status, 200, "{}", response.body);
            payloads.push(response.body);
        }

        let response = dispatch_json(
            &state,
            &Method::Post,
            "/api/v1/webauthn/register/start",
            r#"{"label":"primary","user_name":"owner","display_name":"Owner"}"#,
            1_800_000_002,
        );
        assert_eq!(response.status, 200, "{}", response.body);
        assert!(response.body.contains("publicKey"));
        payloads.push(response.body);

        let response = dispatch_json(
            &state,
            &Method::Post,
            &format!("/api/v1/intents/{id}/approve/start"),
            "",
            1_800_000_003,
        );
        assert_eq!(response.status, 409);

        let joined = payloads.join("\n").to_ascii_lowercase();
        for forbidden in [
            "key_package",
            "signing_share",
            "secret_share",
            "signing_nonces",
            "authorization_token",
        ] {
            assert!(!joined.contains(forbidden), "leaked field {forbidden}");
        }
    }

    #[test]
    fn missing_intent_and_route_have_typed_status_codes() {
        let state = service();
        let missing = dispatch_json(
            &state,
            &Method::Get,
            "/api/v1/intents/00000000-0000-0000-0000-000000000001",
            "",
            1_800_000_000,
        );
        assert_eq!(missing.status, 404);
        let route = dispatch_json(&state, &Method::Get, "/nope", "", 1_800_000_000);
        assert_eq!(route.status, 404);
    }

    #[test]
    fn protected_trade_routes_are_typed_and_reject_unverified_payloads() {
        let state = service();
        for path in ["/api/v1/trades/verify", "/api/v1/trades/intents"] {
            let response = dispatch_json(&state, &Method::Post, path, "{}", 1_800_000_000);
            assert_eq!(response.status, 400, "{path}: {}", response.body);
            assert!(!response.body.contains("route_not_found"));
        }
    }

    #[test]
    fn chat_message_lifecycle_is_typed_and_secret_free() {
        let state = service();
        let empty = dispatch_json(
            &state,
            &Method::Get,
            "/api/v1/chat/state",
            "",
            1_800_000_000,
        );
        assert_eq!(empty.status, 200, "{}", empty.body);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&empty.body).unwrap()["messages"],
            json!([])
        );

        let created = dispatch_json(
            &state,
            &Method::Post,
            "/api/v1/chat/messages",
            r#"{"content":"What can this wallet do?"}"#,
            1_800_000_001,
        );
        assert_eq!(created.status, 201, "{}", created.body);
        let value = serde_json::from_str::<serde_json::Value>(&created.body).unwrap();
        let message_id = value["user_message"]["id"].as_str().unwrap();

        let read = dispatch_json(
            &state,
            &Method::Get,
            &format!("/api/v1/chat/messages/{message_id}"),
            "",
            1_800_000_002,
        );
        assert_eq!(read.status, 200, "{}", read.body);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&read.body).unwrap()["content"],
            "What can this wallet do?"
        );

        let joined = format!("{}\n{}\n{}", empty.body, created.body, read.body);
        for forbidden in [
            "nonce",
            "authorization_token",
            "key_package",
            "signing_share",
            "secret_share",
            "verifier",
        ] {
            assert!(
                !joined.to_ascii_lowercase().contains(forbidden),
                "leaked {forbidden}"
            );
        }
    }

    #[test]
    fn chat_wallet_action_creates_only_a_passkey_required_intent() {
        let state = service();
        let request = json!({
            "content": "Prepare this exact transaction",
            "wallet_action": {
                "type": "sign_taproot_transaction",
                "wallet_id": "11111111-1111-1111-1111-111111111111",
                "signer_id": 1,
                "tx_digest": "22".repeat(32),
                "session_id": "33".repeat(32),
                "expiry": 1_800_000_600_i64
            }
        });
        let created = dispatch_json(
            &state,
            &Method::Post,
            "/api/v1/chat/messages",
            &request.to_string(),
            1_800_000_000,
        );
        assert_eq!(created.status, 201, "{}", created.body);
        let value = serde_json::from_str::<serde_json::Value>(&created.body).unwrap();
        let action = &value["wallet_message"]["wallet_action"];
        assert_eq!(action["authorization"], "passkey_required");
        assert_eq!(action["tx_digest_hex"], "22".repeat(32));
        assert_eq!(action["session_id_hex"], "33".repeat(32));
        assert!(action.get("intent_digest_hex").is_some());
        assert!(action.get("nonce").is_none());

        let signer = dispatch_json(
            &state,
            &Method::Get,
            "/api/v1/signer/status",
            "",
            1_800_000_001,
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&signer.body).unwrap()["approved_actions"],
            0
        );

        let chat_approval = dispatch_json(
            &state,
            &Method::Post,
            "/api/v1/chat/messages/11111111-1111-1111-1111-111111111111/approve",
            r#"{"approved":true}"#,
            1_800_000_002,
        );
        assert_eq!(chat_approval.status, 404);
    }

    #[test]
    fn chat_rejects_caller_supplied_authorization_fields() {
        let state = service();
        for body in [
            r#"{"content":"approve","verifier":"accept-all"}"#.to_owned(),
            json!({
                "content": "approve",
                "wallet_action": {
                    "type": "sign_taproot_transaction",
                    "wallet_id": "11111111-1111-1111-1111-111111111111",
                    "signer_id": 1,
                    "tx_digest": "22".repeat(32),
                    "session_id": "33".repeat(32),
                    "expiry": 1_800_000_600_i64,
                    "approved": true,
                    "credential": {"id": "fake"}
                }
            })
            .to_string(),
        ] {
            let response = dispatch_json(
                &state,
                &Method::Post,
                "/api/v1/chat/messages",
                &body,
                1_800_000_000,
            );
            assert_eq!(response.status, 400, "{}", response.body);
            assert!(response.body.contains("invalid_json"), "{}", response.body);
        }
        assert!(state.lock().unwrap().list_intents().is_empty());
    }

    #[test]
    fn loopback_bind_validation_rejects_hostname_prefix_spoofing() {
        assert!(is_loopback_bind("127.0.0.1:18787"));
        assert!(is_loopback_bind("127.23.45.67:18787"));
        assert!(is_loopback_bind("[::1]:18787"));
        assert!(is_loopback_bind("localhost:18787"));
        assert!(!is_loopback_bind("localhost.attacker.example:18787"));
        assert!(!is_loopback_bind("127.0.0.1.attacker.example:18787"));
        assert!(!is_loopback_bind("0.0.0.0:18787"));
        assert!(!is_loopback_bind("localhost:not-a-port"));
    }

    #[test]
    fn request_body_limit_rejects_oversized_json() {
        let oversized = vec![b'x'; MAX_HTTP_BODY_BYTES + 1];
        let response = read_json_body(std::io::Cursor::new(oversized)).unwrap_err();
        assert_eq!(response.status, 413);
        assert!(response.body.contains("request_body_too_large"));
    }
}

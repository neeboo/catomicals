use catomicals_threshold::{
    LocalFrostParticipant, NonceGuard, participant_identifier, run_local_dkg,
};
use uuid::Uuid;

use crate::{
    ChatAuthorizationState, ChatMessageKind, ChatMessageRole, ChatWalletActionRequest,
    CreateChatMessageRequest, IntentStatus, MAX_CHAT_MESSAGES, RelyingPartyConfig, WalletNodeError,
    WalletNodeService,
};

const NOW: i64 = 1_800_000_000;

fn service() -> WalletNodeService {
    let mut dkg = run_local_dkg(3, 2).unwrap();
    let participant = LocalFrostParticipant::new(
        1,
        dkg.key_packages
            .remove(&participant_identifier(1).unwrap())
            .unwrap(),
        NonceGuard::new(),
    )
    .unwrap();
    WalletNodeService::new(
        RelyingPartyConfig::default(),
        Some(participant),
        dkg.public_key_package,
        2,
    )
    .unwrap()
}

fn signing_message() -> CreateChatMessageRequest {
    CreateChatMessageRequest {
        content: "Prepare this exact Taproot signing action".into(),
        wallet_action: Some(ChatWalletActionRequest::SignTaprootTransaction {
            wallet_id: Uuid::from_bytes([0x11; 16]),
            signer_id: 1,
            tx_digest: [0x22; 32],
            session_id: [0x33; 32],
            expiry: NOW + 600,
        }),
    }
}

#[test]
fn ordinary_message_has_a_complete_lifecycle_without_creating_an_intent() {
    let mut service = service();

    let exchange = service
        .create_chat_message(
            CreateChatMessageRequest {
                content: "What can this wallet do?".into(),
                wallet_action: None,
            },
            NOW,
        )
        .unwrap();

    assert_eq!(exchange.user_message.role, ChatMessageRole::User);
    assert_eq!(exchange.user_message.kind, ChatMessageKind::Text);
    assert_eq!(exchange.wallet_message.role, ChatMessageRole::Wallet);
    assert_eq!(exchange.wallet_message.kind, ChatMessageKind::Text);
    assert!(exchange.user_message.wallet_action.is_none());
    assert!(exchange.wallet_message.wallet_action.is_none());
    assert!(service.list_intents().is_empty());

    let state = service.chat_state(NOW);
    assert_eq!(state.messages.len(), 2);
    assert_eq!(state.pending_wallet_actions, 0);
    assert_eq!(
        service
            .read_chat_message(exchange.user_message.id, NOW)
            .unwrap(),
        exchange.user_message
    );
}

#[test]
fn wallet_message_creates_an_exact_bound_pending_intent_and_no_authorization() {
    let mut service = service();

    let exchange = service.create_chat_message(signing_message(), NOW).unwrap();
    let action = exchange.wallet_message.wallet_action.unwrap();
    let intent = service.read_intent(action.intent_id).unwrap();

    assert_eq!(exchange.wallet_message.kind, ChatMessageKind::WalletAction);
    assert_eq!(intent.status, IntentStatus::Pending);
    assert_eq!(intent.wallet_id, Uuid::from_bytes([0x11; 16]));
    assert_eq!(intent.signer_id, 1);
    assert_eq!(intent.tx_digest, [0x22; 32]);
    assert_eq!(intent.session_id, [0x33; 32]);
    assert_eq!(intent.expiry, NOW + 600);
    assert_eq!(action.tx_digest_hex, hex::encode(intent.tx_digest));
    assert_eq!(action.session_id_hex, hex::encode(intent.session_id));
    assert_eq!(action.intent_digest_hex, hex::encode(intent.digest()));
    assert_eq!(
        action.authorization,
        ChatAuthorizationState::PasskeyRequired
    );
    assert_eq!(service.signer_status().approved_actions, 0);
    assert_eq!(
        service.approval_start(intent.id, NOW + 1).unwrap_err(),
        WalletNodeError::NoCredentials
    );
}

#[test]
fn chat_state_projects_the_current_intent_lifecycle() {
    let mut service = service();
    let exchange = service.create_chat_message(signing_message(), NOW).unwrap();
    let intent_id = exchange.wallet_message.wallet_action.unwrap().intent_id;

    service.cancel_intent(intent_id, NOW + 1).unwrap();

    let state = service.chat_state(NOW + 1);
    let action = state
        .messages
        .iter()
        .find_map(|message| message.wallet_action.as_ref())
        .unwrap();
    assert_eq!(action.status, IntentStatus::Cancelled);
    assert_eq!(action.authorization, ChatAuthorizationState::Cancelled);
    assert_eq!(state.pending_wallet_actions, 0);
}

#[test]
fn chat_responses_do_not_serialize_secrets_or_verifier_inputs() {
    let mut service = service();
    service.create_chat_message(signing_message(), NOW).unwrap();

    let json = serde_json::to_string(&service.chat_state(NOW)).unwrap();
    for forbidden in [
        "nonce",
        "authorization_token",
        "key_package",
        "secret_share",
        "signing_share",
        "verifier",
        "credential",
        "assertion",
    ] {
        assert!(
            !json.to_ascii_lowercase().contains(forbidden),
            "leaked {forbidden}"
        );
    }
}

#[test]
fn bounded_chat_history_rejects_new_messages_before_creating_wallet_state() {
    let mut service = service();
    for index in 0..(MAX_CHAT_MESSAGES / 2) {
        service
            .create_chat_message(
                CreateChatMessageRequest {
                    content: format!("message {index}"),
                    wallet_action: None,
                },
                NOW,
            )
            .unwrap();
    }

    assert_eq!(service.chat_state(NOW).messages.len(), MAX_CHAT_MESSAGES);
    assert_eq!(
        service
            .create_chat_message(signing_message(), NOW)
            .unwrap_err(),
        WalletNodeError::ChatHistoryFull
    );
    assert!(service.list_intents().is_empty());
}

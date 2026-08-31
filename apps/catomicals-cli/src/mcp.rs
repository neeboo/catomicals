//! Local stdio MCP adapter for the loopback wallet HTTP API.
//!
//! The adapter shares wallet state with the browser. It deliberately has no
//! WebAuthn, FROST share, signing, or broadcast tool.

use std::{sync::Arc, time::Duration};

use clap::Subcommand;
use reqwest::{Client, Method, StatusCode};
use rmcp::{
    Json, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{Implementation, JsonObject, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::{Host, Url};

pub(crate) fn object_output_schema() -> Arc<JsonObject> {
    Arc::new(
        json!({
            "type": "object",
            "additionalProperties": true,
        })
        .as_object()
        .expect("static object output schema")
        .clone(),
    )
}

#[derive(Debug, Subcommand)]
pub enum McpCommand {
    /// Serve the wallet tools over MCP stdio. Protocol data is the only stdout output.
    Serve {
        /// Loopback wallet node API started by `catomicals wallet serve`.
        #[arg(
            long,
            env = "CATOMICALS_WALLET_URL",
            default_value = "http://127.0.0.1:18787"
        )]
        wallet_url: String,
    },
    /// Serve the six Cordis configuration tools over MCP stdio.
    CordisServe,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IntentIdParams {
    /// UUID returned when the signing intent was created.
    pub intent_id: String,
}

impl IntentIdParams {
    /// The agent surface routes exclusively by exact path segments on the
    /// wallet server, so an `intent_id` must be a canonical UUID token before
    /// it is interpolated into a URL. Any other string (slash, `?`, `..`, or
    /// percent-encoding) could otherwise re-route the request to a different
    /// endpoint; this check fails closed before any HTTP request is built.
    fn validate(&self) -> Result<(), String> {
        uuid::Uuid::parse_str(&self.intent_id)
            .map(|_| ())
            .map_err(|_| {
                format!(
                    "invalid intent_id `{}`: expected a canonical UUID",
                    self.intent_id
                )
            })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddChatMessageParams {
    /// Plain-language wallet question or note. This cannot attach an opaque signing digest.
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TransactionPrevoutParams {
    /// Outpoint in txid:vout form, in the exact same order as transaction inputs.
    pub outpoint: String,
    /// Confirmed value of the spent output in satoshis.
    pub value_sat: u64,
    /// Complete spent scriptPubKey encoded as hexadecimal.
    pub script_pubkey_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InspectTransactionParams {
    /// Canonical unsigned Bitcoin transaction encoding.
    pub raw_tx_hex: String,
    /// One trusted previous-output record per transaction input, in input order.
    pub prevouts: Vec<TransactionPrevoutParams>,
    /// Taproot input whose BIP341 key-spend digest the wallet should derive.
    pub input_index: usize,
    /// Hard fee ceiling. The wallet rejects the request when the actual fee is higher.
    pub max_fee_sat: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateTransactionIntentParams {
    /// Wallet namespace UUID shown by the local UI.
    pub wallet_id: String,
    /// Local FROST participant id expected to act after user approval.
    pub signer_id: u16,
    /// Fresh 32-byte FROST session id encoded as 64 hexadecimal characters.
    pub session_id: String,
    /// Unix timestamp after which this intent cannot be approved or signed.
    pub expiry: i64,
    /// Full transaction material. The wallet derives the signing digest from this object.
    pub transaction: InspectTransactionParams,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckProtectedTradeParams {
    /// Complete typed TradeSigningRequest JSON for list, buy, or cancel verification.
    pub trade: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InspectCovhubProposalParams {
    /// Complete `covhub.wallet-proposal/v1` JSON object. The wallet parses it
    /// strictly, verifies the canonical content digest, and re-runs the local
    /// chain suite over the decoded transaction material. Read-only.
    pub proposal: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateCovhubIntentParams {
    /// Complete `covhub.wallet-proposal/v1` JSON object. The wallet repeats
    /// full inspection before creating any intent.
    pub proposal: Value,
    /// Fresh 32-byte session id encoded as 64 lowercase hexadecimal characters.
    pub session_id: String,
    /// Local signer profile UUID whose chain scope matches the proposal.
    pub profile_id: String,
}

#[derive(Debug, Clone)]
struct WalletHttpClient {
    base_url: String,
    client: Client,
    #[cfg(test)]
    mock: Option<MockWallet>,
}

/// Test-only in-process wallet backend. No socket is opened, so the MCP
/// protocol tests run inside the credential-isolated sandbox where network
/// bind is denied. Records every request and answers from a canned table.
#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub(super) struct MockWallet {
    calls: Arc<std::sync::Mutex<Vec<(String, String)>>>,
    responses: Arc<std::sync::Mutex<Vec<(String, Value)>>>,
}

#[cfg(test)]
impl MockWallet {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn answer(&self, path: &str, value: Value) {
        self.responses
            .lock()
            .unwrap()
            .push((path.to_owned(), value));
    }

    pub(super) fn calls(&self) -> Vec<(String, String)> {
        self.calls.lock().unwrap().clone()
    }
}

impl WalletHttpClient {
    fn new(wallet_url: &str) -> anyhow::Result<Self> {
        let parsed = Url::parse(wallet_url)?;
        if parsed.scheme() != "http" {
            anyhow::bail!("MCP wallet URL must use http on a loopback interface");
        }
        let loopback = match parsed.host() {
            Some(Host::Ipv4(address)) => address.is_loopback(),
            Some(Host::Ipv6(address)) => address.is_loopback(),
            Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
            None => false,
        };
        if !loopback || !parsed.username().is_empty() || parsed.password().is_some() {
            anyhow::bail!("MCP wallet URL must be an unauthenticated loopback address");
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            anyhow::bail!("MCP wallet URL cannot contain a query or fragment");
        }
        let client = Client::builder().timeout(Duration::from_secs(15)).build()?;
        Ok(Self {
            base_url: wallet_url.trim_end_matches('/').to_owned(),
            client,
            #[cfg(test)]
            mock: None,
        })
    }

    /// Test-only backend that answers wallet HTTP calls in-process. No socket
    /// is opened, so the MCP protocol tests run inside the credential-isolated
    /// sandbox where network bind is denied.
    #[cfg(test)]
    fn mock(base_url: &str, wallet: MockWallet) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            client: Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .unwrap(),
            mock: Some(wallet),
        }
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, String> {
        #[cfg(test)]
        if let Some(mock) = &self.mock {
            mock.calls.lock().unwrap().push((
                method.as_str().to_owned(),
                format!(
                    "{path}{}",
                    body.map(|value| value.to_string()).unwrap_or_default()
                ),
            ));
            let responses = mock.responses.lock().unwrap();
            return responses
                .iter()
                .find(|(expected, _)| expected == path)
                .map(|(_, value)| value.clone())
                .ok_or_else(|| format!("unexpected wallet path {path}"));
        }
        let mut request = self
            .client
            .request(method, format!("{}{}", self.base_url, path));
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request
            .send()
            .await
            .map_err(|error| format!("wallet node unavailable: {error}"))?;
        let status = response.status();
        let value = response
            .json::<Value>()
            .await
            .map_err(|error| format!("wallet node returned invalid JSON: {error}"))?;
        if status.is_success() {
            Ok(value)
        } else {
            Err(wallet_error(status, &value))
        }
    }

    async fn get(&self, path: &str) -> Result<Json<Value>, String> {
        self.request(Method::GET, path, None).await.map(Json)
    }

    async fn post(&self, path: &str, body: Value) -> Result<Json<Value>, String> {
        self.request(Method::POST, path, Some(body)).await.map(Json)
    }
}

fn wallet_error(status: StatusCode, value: &Value) -> String {
    let code = value
        .pointer("/error/code")
        .and_then(Value::as_str)
        .unwrap_or("http_error");
    let message = value
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or("wallet request failed");
    format!("wallet node rejected request ({status}, {code}): {message}")
}

#[derive(Debug, Clone)]
pub struct McpWalletServer {
    wallet: WalletHttpClient,
    tool_router: ToolRouter<Self>,
}

#[tool_handler(router = self.tool_router)]
impl rmcp::ServerHandler for McpWalletServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_instructions(
                "Inspect the complete transaction before creating an intent. The user must review and approve every intent with a Passkey in the Catomicals UI. This server cannot approve, sign, or broadcast."
            )
    }
}

#[tool_router(router = tool_router)]
impl McpWalletServer {
    fn new(wallet_url: &str) -> anyhow::Result<Self> {
        Ok(Self {
            wallet: WalletHttpClient::new(wallet_url)?,
            tool_router: Self::tool_router(),
        })
    }

    #[cfg(test)]
    fn with_wallet(wallet: WalletHttpClient) -> anyhow::Result<Self> {
        Ok(Self {
            wallet,
            tool_router: Self::tool_router(),
        })
    }

    #[tool(
        name = "get_wallet_status",
        description = "Read the shared local wallet, Signet node, signer, pending approval, and recent intent status. Read-only.",
        output_schema = object_output_schema()
    )]
    async fn get_wallet_status(&self) -> Result<Json<Value>, String> {
        self.wallet.get("/api/v1/wallet/status").await
    }

    #[tool(
        name = "list_signing_intents",
        description = "List signing intents from the shared wallet. Read-only; approval remains user-only.",
        output_schema = object_output_schema()
    )]
    async fn list_signing_intents(&self) -> Result<Json<Value>, String> {
        self.wallet.get("/api/v1/intents").await
    }

    #[tool(
        name = "read_signing_intent",
        description = "Read one immutable signing intent by UUID. Read-only.",
        output_schema = object_output_schema()
    )]
    async fn read_signing_intent(
        &self,
        Parameters(params): Parameters<IntentIdParams>,
    ) -> Result<Json<Value>, String> {
        params.validate()?;
        self.wallet
            .get(&format!("/api/v1/intents/{}", params.intent_id))
            .await
    }

    #[tool(
        name = "cancel_signing_intent",
        description = "Cancel a pending signing intent. This cannot approve, sign, or broadcast it.",
        output_schema = object_output_schema()
    )]
    async fn cancel_signing_intent(
        &self,
        Parameters(params): Parameters<IntentIdParams>,
    ) -> Result<Json<Value>, String> {
        params.validate()?;
        self.wallet
            .post(
                &format!("/api/v1/intents/{}/cancel", params.intent_id),
                json!({}),
            )
            .await
    }

    #[tool(
        name = "get_chat_state",
        description = "Read the local chat transcript and pending wallet-action count. Read-only.",
        output_schema = object_output_schema()
    )]
    async fn get_chat_state(&self) -> Result<Json<Value>, String> {
        self.wallet.get("/api/v1/chat/state").await
    }

    #[tool(
        name = "add_chat_message",
        description = "Append a plain-language message to the wallet chat. Cannot attach a signing digest or authorize an action.",
        output_schema = object_output_schema()
    )]
    async fn add_chat_message(
        &self,
        Parameters(params): Parameters<AddChatMessageParams>,
    ) -> Result<Json<Value>, String> {
        self.wallet
            .post(
                "/api/v1/chat/messages",
                json!({ "content": params.content }),
            )
            .await
    }

    #[tool(
        name = "inspect_transaction",
        description = "Decode and policy-check a complete unsigned Taproot Signet transaction with ordered trusted prevouts. Returns fees, inputs, outputs, warnings, and a wallet-derived BIP341 digest; does not sign.",
        output_schema = object_output_schema()
    )]
    async fn inspect_transaction(
        &self,
        Parameters(params): Parameters<InspectTransactionParams>,
    ) -> Result<Json<Value>, String> {
        self.wallet
            .post(
                "/api/v1/transactions/inspect",
                serde_json::to_value(params).map_err(|error| error.to_string())?,
            )
            .await
    }

    #[tool(
        name = "create_transaction_intent",
        description = "Re-check a complete unsigned transaction, derive its BIP341 digest inside the wallet, and create a pending intent for later user Passkey approval. There is no caller-supplied digest.",
        output_schema = object_output_schema()
    )]
    async fn create_transaction_intent(
        &self,
        Parameters(params): Parameters<CreateTransactionIntentParams>,
    ) -> Result<Json<Value>, String> {
        self.wallet
            .post(
                "/api/v1/transactions/intents",
                serde_json::to_value(params).map_err(|error| error.to_string())?,
            )
            .await
    }

    #[tool(
        name = "check_protected_trade",
        description = "Independently verify a typed Catomicals list, buy, or cancel transaction against current Signet policy. Returns verification only and creates no intent.",
        output_schema = object_output_schema()
    )]
    async fn check_protected_trade(
        &self,
        Parameters(params): Parameters<CheckProtectedTradeParams>,
    ) -> Result<Json<Value>, String> {
        self.wallet
            .post("/api/v1/trades/verify", params.trade)
            .await
    }

    #[tool(
        name = "inspect_covhub_wallet_proposal",
        description = "Strictly parse a complete covhub.wallet-proposal/v1, verify its canonical RFC 8785 content digest, decode and size-check the transaction material, and independently re-run the local chain suite to reproduce the review. Read-only; creates no intent and never accepts a CovHub-provided digest or status.",
        output_schema = object_output_schema()
    )]
    async fn inspect_covhub_wallet_proposal(
        &self,
        Parameters(params): Parameters<InspectCovhubProposalParams>,
    ) -> Result<Json<Value>, String> {
        self.wallet
            .post(
                crate::wallet_serve::covhub_bridge::COVHUB_INSPECT_ROUTE,
                json!({ "proposal": params.proposal }),
            )
            .await
    }

    #[tool(
        name = "create_covhub_signing_intent",
        description = "Repeat full CovHub proposal inspection and, only when the proposal is ready_for_wallet_review, unexpired, digest-verified, on a supported local test network, and matched to the selected local signer profile, create a pending intent bound to the locally recomputed review. The intent is Passkey-gated: it cannot be signed or broadcast until the user approves it in the Catomicals UI. There is no caller-supplied signing digest.",
        output_schema = object_output_schema()
    )]
    async fn create_covhub_signing_intent(
        &self,
        Parameters(params): Parameters<CreateCovhubIntentParams>,
    ) -> Result<Json<Value>, String> {
        self.wallet
            .post(
                crate::wallet_serve::covhub_bridge::COVHUB_INTENT_ROUTE,
                json!({
                    "proposal": params.proposal,
                    "session_id": params.session_id,
                    "profile_id": params.profile_id,
                }),
            )
            .await
    }

    #[cfg(test)]
    fn tool_names(&self) -> Vec<String> {
        let mut names: Vec<_> = self
            .tool_router
            .list_all()
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect();
        names.sort();
        names
    }
}

pub fn run(command: McpCommand) -> anyhow::Result<()> {
    match command {
        McpCommand::Serve { wallet_url } => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async move {
                let server = McpWalletServer::new(&wallet_url)?;
                server
                    .serve((tokio::io::stdin(), tokio::io::stdout()))
                    .await?
                    .waiting()
                    .await?;
                anyhow::Ok(())
            })
        }
        McpCommand::CordisServe => crate::cordis_mcp::run(),
    }
}

#[cfg(test)]
mod tests {
    use rmcp::{ServiceExt, model::CallToolRequestParams};
    use serde_json::{Value, json};

    use super::{McpWalletServer, WalletHttpClient};

    #[test]
    fn agent_tool_surface_is_exact_and_excludes_custody_actions() {
        let server = McpWalletServer::new("http://127.0.0.1:18787").unwrap();
        assert_eq!(
            server.tool_names(),
            [
                "add_chat_message",
                "cancel_signing_intent",
                "check_protected_trade",
                "create_covhub_signing_intent",
                "create_transaction_intent",
                "get_chat_state",
                "get_wallet_status",
                "inspect_covhub_wallet_proposal",
                "inspect_transaction",
                "list_signing_intents",
                "read_signing_intent",
            ]
        );
    }

    #[test]
    fn wallet_backend_must_be_loopback_http() {
        for rejected in [
            "https://127.0.0.1:18787",
            "http://wallet.example:18787",
            "http://user:password@127.0.0.1:18787",
        ] {
            assert!(
                McpWalletServer::new(rejected).is_err(),
                "accepted {rejected}"
            );
        }
        assert!(McpWalletServer::new("http://localhost:18787").is_ok());
        assert!(McpWalletServer::new("http://[::1]:18787").is_ok());
    }

    #[tokio::test]
    async fn mcp_protocol_lists_schemas_and_calls_shared_wallet_http() -> anyhow::Result<()> {
        let mock = super::MockWallet::new();
        mock.answer(
            "/api/v1/wallet/status",
            json!({"node": null, "signers": [], "recent_intents": []}),
        );
        let server = McpWalletServer::with_wallet(WalletHttpClient::mock(
            "http://127.0.0.1:18787",
            mock.clone(),
        ))?;

        let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            server.serve(server_transport).await?.waiting().await?;
            anyhow::Ok(())
        });
        let client = ().serve(client_transport).await?;

        let tools = client.list_all_tools().await?;
        assert_eq!(tools.len(), 11);
        for tool in &tools {
            assert_eq!(
                tool.output_schema
                    .as_ref()
                    .and_then(|schema| schema.get("type"))
                    .and_then(Value::as_str),
                Some("object"),
                "{} must publish an object outputSchema for strict MCP clients",
                tool.name,
            );
        }
        let inspect = tools
            .iter()
            .find(|tool| tool.name == "inspect_transaction")
            .unwrap();
        let inspect_schema = serde_json::to_string(&inspect.input_schema)?;
        assert!(inspect_schema.contains("raw_tx_hex"));
        assert!(inspect_schema.contains("prevouts"));
        assert!(inspect_schema.contains("max_fee_sat"));

        let covhub_inspect = tools
            .iter()
            .find(|tool| tool.name == "inspect_covhub_wallet_proposal")
            .unwrap();
        let covhub_inspect_schema = serde_json::to_string(&covhub_inspect.input_schema)?;
        assert!(covhub_inspect_schema.contains("proposal"));

        let covhub_intent = tools
            .iter()
            .find(|tool| tool.name == "create_covhub_signing_intent")
            .unwrap();
        let covhub_intent_schema = serde_json::to_string(&covhub_intent.input_schema)?;
        assert!(covhub_intent_schema.contains("proposal"));
        assert!(covhub_intent_schema.contains("session_id"));
        assert!(covhub_intent_schema.contains("profile_id"));

        for forbidden in [
            "approve_signing_intent",
            "produce_signature_share",
            "run_frost_round",
            "sign_transaction",
            "broadcast_transaction",
            "covhub_approve",
            "capture_passkey_assertion",
            "covhub_broadcast",
        ] {
            assert!(!tools.iter().any(|tool| tool.name == forbidden));
        }

        let result = client
            .call_tool(CallToolRequestParams::new("get_wallet_status"))
            .await?;
        assert_eq!(
            result.structured_content,
            Some(json!({
                "node": null,
                "signers": [],
                "recent_intents": [],
            }))
        );

        client.cancel().await?;
        server_task.await??;

        assert_eq!(
            mock.calls(),
            vec![("GET".to_owned(), "/api/v1/wallet/status".to_owned())]
        );
        Ok(())
    }

    #[tokio::test]
    async fn covhub_mcp_tools_relay_exact_bounded_requests() -> anyhow::Result<()> {
        let mock = super::MockWallet::new();
        mock.answer(
            "/api/v1/covhub/proposals/inspect",
            json!({"proposal_id": "proposal:test", "eligible": true}),
        );
        mock.answer(
            "/api/v1/covhub/proposals/intents",
            json!({"intent": {"status": "pending"}, "requires_passkey_approval": true}),
        );
        let server = McpWalletServer::with_wallet(WalletHttpClient::mock(
            "http://127.0.0.1:18787",
            mock.clone(),
        ))?;

        let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            server.serve(server_transport).await?.waiting().await?;
            anyhow::Ok(())
        });
        let client = ().serve(client_transport).await?;

        let proposal =
            json!({"schema": "covhub.wallet-proposal/v1", "proposal_id": "proposal:test"});
        let inspect = client
            .call_tool(
                CallToolRequestParams::new("inspect_covhub_wallet_proposal").with_arguments(
                    json!({ "proposal": proposal.clone() })
                        .as_object()
                        .unwrap()
                        .clone(),
                ),
            )
            .await?;
        assert_eq!(
            inspect.structured_content,
            Some(json!({"proposal_id": "proposal:test", "eligible": true}))
        );

        let intent = client
            .call_tool(
                CallToolRequestParams::new("create_covhub_signing_intent").with_arguments(
                    json!({
                        "proposal": proposal,
                        "session_id": "3333333333333333333333333333333333333333333333333333333333333333",
                        "profile_id": "61616161-6161-4161-8161-616161616161",
                    })
                    .as_object()
                    .unwrap()
                    .clone(),
                ),
            )
            .await?;
        assert_eq!(
            intent.structured_content,
            Some(json!({"intent": {"status": "pending"}, "requires_passkey_approval": true}))
        );

        client.cancel().await?;
        server_task.await??;

        let recorded = mock.calls();
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0].0, "POST");
        assert!(
            recorded[0]
                .1
                .starts_with("/api/v1/covhub/proposals/inspect{")
        );
        assert!(recorded[0].1.contains("proposal:test"));
        assert!(recorded[0].1.contains("proposal_id"));
        assert_eq!(recorded[1].0, "POST");
        assert!(
            recorded[1]
                .1
                .starts_with("/api/v1/covhub/proposals/intents{")
        );
        assert!(recorded[1].1.contains("session_id"));
        assert!(recorded[1].1.contains("profile_id"));
        // No approval/signing/secret/broadcast path is ever relayed.
        assert!(!recorded.iter().any(|(_, path)| {
            path.contains("approve") || path.contains("sign") || path.contains("broadcast")
        }));
        Ok(())
    }

    #[tokio::test]
    async fn intent_id_parameters_are_strict_uuids_and_never_reroute_a_request()
    -> anyhow::Result<()> {
        let mock = super::MockWallet::new();
        let server = McpWalletServer::with_wallet(WalletHttpClient::mock(
            "http://127.0.0.1:18787",
            mock.clone(),
        ))?;
        let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            server.serve(server_transport).await?.waiting().await?;
            anyhow::Ok(())
        });
        let client = ().serve(client_transport).await?;

        // These are the exact hostile `intent_id` strings that previously
        // redirected `cancel_signing_intent` to approval/start or a signing
        // job execute once reqwest normalized the URL. The agent surface now
        // fails closed on any non-UUID intent_id before an HTTP request is
        // built.
        for hostile in [
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/approve/start?x",
            "../signing/jobs/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/execute?x",
            "../../intents/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/approve/start?x",
            "not-a-uuid",
            "",
        ] {
            let result = client
                .call_tool(
                    CallToolRequestParams::new("cancel_signing_intent").with_arguments(
                        json!({ "intent_id": hostile }).as_object().unwrap().clone(),
                    ),
                )
                .await?;
            assert_eq!(
                result.is_error,
                Some(true),
                "cancel_signing_intent accepted hostile id {hostile:?}"
            );
            assert!(result.structured_content.is_none());
        }

        // The read tool is gated identically.
        let result = client
            .call_tool(
                CallToolRequestParams::new("read_signing_intent").with_arguments(
                    json!({ "intent_id": "../signing/jobs/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" })
                        .as_object()
                        .unwrap()
                        .clone(),
                ),
            )
            .await?;
        assert_eq!(
            result.is_error,
            Some(true),
            "read_signing_intent accepted a hostile intent_id"
        );

        // No wallet call was made for any hostile id.
        assert!(mock.calls().is_empty());

        client.cancel().await?;
        server_task.await??;
        Ok(())
    }
}

//! Local stdio MCP adapter for the loopback wallet HTTP API.
//!
//! The adapter shares wallet state with the browser. It deliberately has no
//! WebAuthn, FROST share, signing, or broadcast tool.

use std::time::Duration;

use clap::Subcommand;
use reqwest::{Client, Method, StatusCode};
use rmcp::{
    Json, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{Implementation, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::{Host, Url};

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
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IntentIdParams {
    /// UUID returned when the signing intent was created.
    pub intent_id: String,
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

#[derive(Debug, Clone)]
struct WalletHttpClient {
    base_url: String,
    client: Client,
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
        })
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, String> {
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

    #[tool(
        name = "get_wallet_status",
        description = "Read the shared local wallet, Signet node, signer, pending approval, and recent intent status. Read-only."
    )]
    async fn get_wallet_status(&self) -> Result<Json<Value>, String> {
        self.wallet.get("/api/v1/wallet/status").await
    }

    #[tool(
        name = "list_signing_intents",
        description = "List signing intents from the shared wallet. Read-only; approval remains user-only."
    )]
    async fn list_signing_intents(&self) -> Result<Json<Value>, String> {
        self.wallet.get("/api/v1/intents").await
    }

    #[tool(
        name = "read_signing_intent",
        description = "Read one immutable signing intent by UUID. Read-only."
    )]
    async fn read_signing_intent(
        &self,
        Parameters(params): Parameters<IntentIdParams>,
    ) -> Result<Json<Value>, String> {
        self.wallet
            .get(&format!("/api/v1/intents/{}", params.intent_id))
            .await
    }

    #[tool(
        name = "cancel_signing_intent",
        description = "Cancel a pending signing intent. This cannot approve, sign, or broadcast it."
    )]
    async fn cancel_signing_intent(
        &self,
        Parameters(params): Parameters<IntentIdParams>,
    ) -> Result<Json<Value>, String> {
        self.wallet
            .post(
                &format!("/api/v1/intents/{}/cancel", params.intent_id),
                json!({}),
            )
            .await
    }

    #[tool(
        name = "get_chat_state",
        description = "Read the local chat transcript and pending wallet-action count. Read-only."
    )]
    async fn get_chat_state(&self) -> Result<Json<Value>, String> {
        self.wallet.get("/api/v1/chat/state").await
    }

    #[tool(
        name = "add_chat_message",
        description = "Append a plain-language message to the wallet chat. Cannot attach a signing digest or authorize an action."
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
        description = "Decode and policy-check a complete unsigned Taproot Signet transaction with ordered trusted prevouts. Returns fees, inputs, outputs, warnings, and a wallet-derived BIP341 digest; does not sign."
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
        description = "Re-check a complete unsigned transaction, derive its BIP341 digest inside the wallet, and create a pending intent for later user Passkey approval. There is no caller-supplied digest."
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
        description = "Independently verify a typed Catomicals list, buy, or cancel transaction against current Signet policy. Returns verification only and creates no intent."
    )]
    async fn check_protected_trade(
        &self,
        Parameters(params): Parameters<CheckProtectedTradeParams>,
    ) -> Result<Json<Value>, String> {
        self.wallet
            .post("/api/v1/trades/verify", params.trade)
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
    }
}

#[cfg(test)]
mod tests {
    use rmcp::{ServiceExt, model::CallToolRequestParams};
    use serde_json::json;

    use super::McpWalletServer;

    #[test]
    fn agent_tool_surface_is_exact_and_excludes_custody_actions() {
        let server = McpWalletServer::new("http://127.0.0.1:18787").unwrap();
        assert_eq!(
            server.tool_names(),
            [
                "add_chat_message",
                "cancel_signing_intent",
                "check_protected_trade",
                "create_transaction_intent",
                "get_chat_state",
                "get_wallet_status",
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
        let http = tiny_http::Server::http("127.0.0.1:0")
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let wallet_url = format!("http://{}", http.server_addr());
        let http_thread = std::thread::spawn(move || {
            let request = http.recv().unwrap();
            assert_eq!(request.method(), &tiny_http::Method::Get);
            assert_eq!(request.url(), "/api/v1/wallet/status");
            let header = tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap();
            request
                .respond(
                    tiny_http::Response::from_string(
                        json!({"node": null, "signers": [], "recent_intents": []}).to_string(),
                    )
                    .with_header(header),
                )
                .unwrap();
        });

        let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
        let server = McpWalletServer::new(&wallet_url)?;
        let server_task = tokio::spawn(async move {
            server.serve(server_transport).await?.waiting().await?;
            anyhow::Ok(())
        });
        let client = ().serve(client_transport).await?;

        let tools = client.list_all_tools().await?;
        assert_eq!(tools.len(), 9);
        let inspect = tools
            .iter()
            .find(|tool| tool.name == "inspect_transaction")
            .unwrap();
        let inspect_schema = serde_json::to_string(&inspect.input_schema)?;
        assert!(inspect_schema.contains("raw_tx_hex"));
        assert!(inspect_schema.contains("prevouts"));
        assert!(inspect_schema.contains("max_fee_sat"));
        for forbidden in [
            "approve_signing_intent",
            "produce_signature_share",
            "run_frost_round",
            "sign_transaction",
            "broadcast_transaction",
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
                "recent_intents": []
            }))
        );

        client.cancel().await?;
        server_task.await??;
        http_thread.join().unwrap();
        Ok(())
    }
}

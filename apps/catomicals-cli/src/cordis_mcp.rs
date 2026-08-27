//! Local stdio MCP adapter for the private Cordis desktop bridge.

use std::{collections::BTreeMap, fmt, time::Duration};

use reqwest::{Client, StatusCode};
use rmcp::{
    Json, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{Implementation, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
};
use schemars::{JsonSchema, Schema};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::{Host, Url};

const INVALID_BRIDGE_URL: &str = "Cordis bridge URL must be http://127.0.0.1:<non-zero-port>";
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_SETTING_STRING_CHARS: usize = 65_536;
const MAX_SETTING_CHANGES: usize = 128;
const MIN_SAFE_INTEGER: i64 = -9_007_199_254_740_991;
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

fn parse_bridge_origin(value: &str) -> anyhow::Result<String> {
    if !value.starts_with("http://127.0.0.1:") {
        anyhow::bail!(INVALID_BRIDGE_URL);
    }
    let parsed = Url::parse(value).map_err(|_| anyhow::anyhow!(INVALID_BRIDGE_URL))?;
    let valid = parsed.scheme() == "http"
        && matches!(parsed.host(), Some(Host::Ipv4(address)) if address.octets() == [127, 0, 0, 1])
        && matches!(parsed.port(), Some(port) if port != 0)
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.path() == "/"
        && parsed.query().is_none()
        && parsed.fragment().is_none();
    if !valid {
        anyhow::bail!(INVALID_BRIDGE_URL);
    }
    Ok(parsed.as_str().trim_end_matches('/').to_owned())
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct PluginIdParams {
    #[schemars(
        length(max = 128),
        regex(pattern = "^@catomicals/plugin-[a-z0-9]+(?:-[a-z0-9]+)*$")
    )]
    plugin_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
enum SettingValue {
    String(#[schemars(length(max = 65536))] String),
    Boolean(bool),
    Integer(#[schemars(range(min = MIN_SAFE_INTEGER, max = MAX_SAFE_INTEGER))] i64),
    Null,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct SettingsPatch {
    #[schemars(range(min = 1))]
    schema_version: u64,
    #[schemars(transform = settings_changes_schema)]
    changes: BTreeMap<String, SettingValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct SettingsPatchParams {
    #[schemars(
        length(max = 128),
        regex(pattern = "^@catomicals/plugin-[a-z0-9]+(?:-[a-z0-9]+)*$")
    )]
    plugin_id: String,
    patch: SettingsPatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct EmptyArguments {}

fn settings_changes_schema(schema: &mut Schema) {
    schema.insert("minProperties".to_owned(), 1.into());
    schema.insert("maxProperties".to_owned(), 128.into());
    schema.insert(
        "propertyNames".to_owned(),
        serde_json::json!({
            "pattern": "^[a-z][A-Za-z0-9]*(?:[.-][A-Za-z0-9]+)*$",
            "maxLength": 128
        }),
    );
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeEnvelope {
    ok: bool,
    result: Option<Value>,
    error: Option<BridgeError>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeError {
    code: String,
    message: String,
}

#[derive(Clone)]
struct CordisHttpClient {
    base_url: String,
    session_token: String,
    client: Client,
}

impl fmt::Debug for CordisHttpClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CordisHttpClient")
            .field("base_url", &"<redacted>")
            .field("session_token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl CordisHttpClient {
    fn new(bridge_url: &str, session_token: &str) -> anyhow::Result<Self> {
        if session_token.is_empty() {
            anyhow::bail!("Cordis session token is not configured");
        }
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .build()?;
        Ok(Self {
            base_url: parse_bridge_origin(bridge_url)?,
            session_token: session_token.to_owned(),
            client,
        })
    }

    async fn post<T: Serialize>(
        &self,
        path: &'static str,
        body: &T,
    ) -> Result<Json<Value>, String> {
        let request_body = serde_json::to_vec(body)
            .map_err(|_| "Cordis request could not be encoded".to_owned())?;
        if request_body.len() > MAX_REQUEST_BYTES {
            return Err("Cordis request exceeded limit".to_owned());
        }
        let mut response = self
            .client
            .post(format!("{}{}", self.base_url, path))
            .bearer_auth(&self.session_token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(request_body)
            .send()
            .await
            .map_err(|_| "Cordis bridge unavailable".to_owned())?;
        let status = response.status();
        if status.is_redirection() {
            return Err("Cordis bridge refused redirect".to_owned());
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err("Cordis bridge response exceeded limit".to_owned());
        }

        let mut response_body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "Cordis bridge returned an invalid response".to_owned())?
        {
            if response_body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err("Cordis bridge response exceeded limit".to_owned());
            }
            response_body.extend_from_slice(&chunk);
        }
        let envelope: BridgeEnvelope = serde_json::from_slice(&response_body)
            .map_err(|_| "Cordis bridge returned an invalid response".to_owned())?;
        decode_bridge_envelope(status, envelope).map(Json)
    }
}

fn decode_bridge_envelope(status: StatusCode, envelope: BridgeEnvelope) -> Result<Value, String> {
    match (
        status.is_success(),
        envelope.ok,
        envelope.result,
        envelope.error,
    ) {
        (true, true, Some(result), None) => Ok(result),
        (_, false, None, Some(error)) => {
            let _ = error.message;
            let code = stable_bridge_error_code(&error.code);
            Err(format!("Cordis bridge rejected request ({code})"))
        }
        _ => Err("Cordis bridge returned an invalid response".to_owned()),
    }
}

fn stable_bridge_error_code(code: &str) -> &'static str {
    match code {
        "route_not_found" => "route_not_found",
        "method_not_allowed" => "method_not_allowed",
        "unauthorized" => "unauthorized",
        "forbidden_request" => "forbidden_request",
        "unsupported_media_type" => "unsupported_media_type",
        "request_too_large" => "request_too_large",
        "invalid_request" => "invalid_request",
        "cordis_request_failed" => "cordis_request_failed",
        "response_too_large" => "response_too_large",
        "bridge_unavailable" => "bridge_unavailable",
        "bridge_busy" => "bridge_busy",
        _ => "cordis_request_failed",
    }
}

fn validate_plugin_id(plugin_id: &str) -> Result<(), String> {
    let Some(suffix) = plugin_id.strip_prefix("@catomicals/plugin-") else {
        return Err("Invalid Cordis plugin id".to_owned());
    };
    if plugin_id.len() > 128
        || suffix.is_empty()
        || suffix.split('-').any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
    {
        return Err("Invalid Cordis plugin id".to_owned());
    }
    Ok(())
}

fn validate_settings_patch(patch: &SettingsPatch) -> Result<(), String> {
    if patch.schema_version == 0
        || patch.changes.is_empty()
        || patch.changes.len() > MAX_SETTING_CHANGES
    {
        return Err("Invalid Cordis settings patch".to_owned());
    }
    for (key, value) in &patch.changes {
        if !valid_setting_id(key) {
            return Err("Invalid Cordis settings patch".to_owned());
        }
        match value {
            SettingValue::String(value) if value.chars().count() > MAX_SETTING_STRING_CHARS => {
                return Err("Invalid Cordis settings patch".to_owned());
            }
            SettingValue::Integer(value)
                if !(MIN_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(value) =>
            {
                return Err("Invalid Cordis settings patch".to_owned());
            }
            _ => {}
        }
    }
    Ok(())
}

fn valid_setting_id(value: &str) -> bool {
    if value.len() > 128 {
        return false;
    }
    let mut segments = value.split(['.', '-']);
    let Some(first) = segments.next() else {
        return false;
    };
    let mut first_bytes = first.bytes();
    matches!(first_bytes.next(), Some(byte) if byte.is_ascii_lowercase())
        && first_bytes.all(|byte| byte.is_ascii_alphanumeric())
        && segments.all(|segment| {
            !segment.is_empty() && segment.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
}

#[derive(Debug, Clone)]
struct McpCordisServer {
    bridge: CordisHttpClient,
    tool_router: ToolRouter<Self>,
}

#[tool_handler(router = self.tool_router)]
impl rmcp::ServerHandler for McpCordisServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "catomicals-config",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "Read Cordis plugin state and create settings intents for user review. This server cannot confirm, apply, install, read secrets, sign, or broadcast.",
            )
    }
}

#[tool_router(router = tool_router)]
impl McpCordisServer {
    fn new(bridge_url: &str, session_token: &str) -> anyhow::Result<Self> {
        Ok(Self {
            bridge: CordisHttpClient::new(bridge_url, session_token)?,
            tool_router: Self::tool_router(),
        })
    }

    #[tool(
        name = "list_plugins",
        description = "List verified Cordis plugins and their current status. Read-only."
    )]
    async fn list_plugins(
        &self,
        Parameters(_params): Parameters<EmptyArguments>,
    ) -> Result<Json<Value>, String> {
        self.bridge
            .post("/v1/cordis/list_plugins", &EmptyArguments {})
            .await
    }

    #[tool(
        name = "read_plugin_manifest",
        description = "Read one verified Cordis plugin manifest. Read-only."
    )]
    async fn read_plugin_manifest(
        &self,
        Parameters(params): Parameters<PluginIdParams>,
    ) -> Result<Json<Value>, String> {
        validate_plugin_id(&params.plugin_id)?;
        self.bridge
            .post("/v1/cordis/read_plugin_manifest", &params)
            .await
    }

    #[tool(
        name = "read_plugin_settings_schema",
        description = "Read one Cordis plugin settings schema. Read-only."
    )]
    async fn read_plugin_settings_schema(
        &self,
        Parameters(params): Parameters<PluginIdParams>,
    ) -> Result<Json<Value>, String> {
        validate_plugin_id(&params.plugin_id)?;
        self.bridge
            .post("/v1/cordis/read_plugin_settings_schema", &params)
            .await
    }

    #[tool(
        name = "read_plugin_health",
        description = "Read one Cordis plugin health snapshot. Read-only."
    )]
    async fn read_plugin_health(
        &self,
        Parameters(params): Parameters<PluginIdParams>,
    ) -> Result<Json<Value>, String> {
        validate_plugin_id(&params.plugin_id)?;
        self.bridge
            .post("/v1/cordis/read_plugin_health", &params)
            .await
    }

    #[tool(
        name = "validate_plugin_settings_patch",
        description = "Validate a sparse plugin settings patch without changing state."
    )]
    async fn validate_plugin_settings_patch(
        &self,
        Parameters(params): Parameters<SettingsPatchParams>,
    ) -> Result<Json<Value>, String> {
        validate_plugin_id(&params.plugin_id)?;
        validate_settings_patch(&params.patch)?;
        self.bridge
            .post("/v1/cordis/validate_plugin_settings_patch", &params)
            .await
    }

    #[tool(
        name = "create_plugin_settings_intent",
        description = "Create a pending plugin settings intent for explicit user review. Cannot confirm or apply it."
    )]
    async fn create_plugin_settings_intent(
        &self,
        Parameters(params): Parameters<SettingsPatchParams>,
    ) -> Result<Json<Value>, String> {
        validate_plugin_id(&params.plugin_id)?;
        validate_settings_patch(&params.patch)?;
        self.bridge
            .post("/v1/cordis/create_plugin_settings_intent", &params)
            .await
    }
}

pub fn run() -> anyhow::Result<()> {
    let bridge_url = std::env::var("CATOMICALS_CORDIS_BRIDGE_URL")
        .map_err(|_| anyhow::anyhow!("Cordis bridge URL is not configured"))?;
    let session_token = std::env::var("CATOMICALS_CORDIS_SESSION_TOKEN")
        .map_err(|_| anyhow::anyhow!("Cordis session token is not configured"))?;
    if session_token.is_empty() {
        anyhow::bail!("Cordis session token is not configured");
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        McpCordisServer::new(&bridge_url, &session_token)?
            .serve((tokio::io::stdin(), tokio::io::stdout()))
            .await?
            .waiting()
            .await?;
        anyhow::Ok(())
    })
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, time::Duration};

    use rmcp::handler::server::wrapper::Parameters;
    use serde_json::json;

    use super::{
        EmptyArguments, McpCordisServer, PluginIdParams, SettingValue, SettingsPatch,
        SettingsPatchParams,
    };

    fn receive_request(server: &tiny_http::Server) -> tiny_http::Request {
        server
            .recv_timeout(Duration::from_secs(2))
            .expect("receive bridge request")
            .expect("bridge request timed out")
    }

    #[tokio::test]
    async fn six_tools_send_fixed_paths_bearer_and_closed_arguments() -> anyhow::Result<()> {
        let http = tiny_http::Server::http("127.0.0.1:0")
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let bridge_url = format!("http://{}", http.server_addr());
        let expected = [
            ("/v1/cordis/list_plugins", json!({})),
            (
                "/v1/cordis/read_plugin_manifest",
                json!({"plugin_id": "@catomicals/plugin-mcp"}),
            ),
            (
                "/v1/cordis/read_plugin_settings_schema",
                json!({"plugin_id": "@catomicals/plugin-mcp"}),
            ),
            (
                "/v1/cordis/read_plugin_health",
                json!({"plugin_id": "@catomicals/plugin-mcp"}),
            ),
            (
                "/v1/cordis/validate_plugin_settings_patch",
                json!({
                    "plugin_id": "@catomicals/plugin-mcp",
                    "patch": {"schema_version": 1, "changes": {"enabled": true}}
                }),
            ),
            (
                "/v1/cordis/create_plugin_settings_intent",
                json!({
                    "plugin_id": "@catomicals/plugin-mcp",
                    "patch": {"schema_version": 1, "changes": {"enabled": true}}
                }),
            ),
        ];
        let http_thread = std::thread::spawn(move || {
            for (path, body) in expected {
                let mut request = receive_request(&http);
                assert_eq!(request.method(), &tiny_http::Method::Post);
                assert_eq!(request.url(), path);
                assert!(request.headers().iter().any(|header| {
                    header.field.equiv("Authorization")
                        && header.value.as_str() == "Bearer bridge-secret"
                }));
                assert!(request.headers().iter().any(|header| {
                    header.field.equiv("Content-Type")
                        && header.value.as_str().starts_with("application/json")
                }));
                let mut bytes = Vec::new();
                request
                    .as_reader()
                    .read_to_end(&mut bytes)
                    .expect("request body");
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
                    body
                );
                let header =
                    tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap();
                request
                    .respond(
                        tiny_http::Response::from_string(
                            json!({"ok": true, "result": {"path": path}}).to_string(),
                        )
                        .with_header(header),
                    )
                    .unwrap();
            }
        });

        let server = McpCordisServer::new(&bridge_url, "bridge-secret")?;
        let plugin = || {
            Parameters(PluginIdParams {
                plugin_id: "@catomicals/plugin-mcp".to_owned(),
            })
        };
        let patch = || {
            Parameters(SettingsPatchParams {
                plugin_id: "@catomicals/plugin-mcp".to_owned(),
                patch: SettingsPatch {
                    schema_version: 1,
                    changes: BTreeMap::from([("enabled".to_owned(), SettingValue::Boolean(true))]),
                },
            })
        };

        assert_eq!(
            server
                .list_plugins(Parameters(EmptyArguments {}))
                .await
                .map_err(anyhow::Error::msg)?
                .0["path"],
            expected_path(0)
        );
        assert_eq!(
            server
                .read_plugin_manifest(plugin())
                .await
                .map_err(anyhow::Error::msg)?
                .0["path"],
            expected_path(1)
        );
        assert_eq!(
            server
                .read_plugin_settings_schema(plugin())
                .await
                .map_err(anyhow::Error::msg)?
                .0["path"],
            expected_path(2)
        );
        assert_eq!(
            server
                .read_plugin_health(plugin())
                .await
                .map_err(anyhow::Error::msg)?
                .0["path"],
            expected_path(3)
        );
        assert_eq!(
            server
                .validate_plugin_settings_patch(patch())
                .await
                .map_err(anyhow::Error::msg)?
                .0["path"],
            expected_path(4)
        );
        assert_eq!(
            server
                .create_plugin_settings_intent(patch())
                .await
                .map_err(anyhow::Error::msg)?
                .0["path"],
            expected_path(5)
        );

        http_thread.join().unwrap();
        Ok(())
    }

    fn expected_path(index: usize) -> serde_json::Value {
        json!(
            [
                "/v1/cordis/list_plugins",
                "/v1/cordis/read_plugin_manifest",
                "/v1/cordis/read_plugin_settings_schema",
                "/v1/cordis/read_plugin_health",
                "/v1/cordis/validate_plugin_settings_patch",
                "/v1/cordis/create_plugin_settings_intent",
            ][index]
        )
    }

    fn tool_error(result: Result<rmcp::Json<serde_json::Value>, String>) -> String {
        match result {
            Ok(_) => panic!("expected tool error"),
            Err(error) => error,
        }
    }

    #[tokio::test]
    async fn redirect_is_not_followed() -> anyhow::Result<()> {
        let target = tiny_http::Server::http("127.0.0.1:0")
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let target_url = format!("http://{}/stolen", target.server_addr());
        let bridge = tiny_http::Server::http("127.0.0.1:0")
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let bridge_url = format!("http://{}", bridge.server_addr());
        let bridge_thread = std::thread::spawn(move || {
            let request = receive_request(&bridge);
            request
                .respond(
                    tiny_http::Response::from_string(
                        json!({"ok": true, "result": {"redirected": true}}).to_string(),
                    )
                    .with_status_code(302)
                    .with_header(tiny_http::Header::from_bytes("Location", target_url).unwrap()),
                )
                .unwrap();
        });

        let server = McpCordisServer::new(&bridge_url, "bridge-secret")?;
        assert_eq!(
            tool_error(server.list_plugins(Parameters(EmptyArguments {})).await),
            "Cordis bridge refused redirect"
        );
        bridge_thread.join().unwrap();
        assert!(target.recv_timeout(Duration::from_millis(200))?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn oversized_bridge_response_is_rejected_before_json_parsing() -> anyhow::Result<()> {
        let bridge = tiny_http::Server::http("127.0.0.1:0")
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let bridge_url = format!("http://{}", bridge.server_addr());
        let bridge_thread = std::thread::spawn(move || {
            let request = receive_request(&bridge);
            request
                .respond(tiny_http::Response::from_data(vec![
                    b'x';
                    super::MAX_RESPONSE_BYTES
                        + 1
                ]))
                .unwrap();
        });

        let server = McpCordisServer::new(&bridge_url, "bridge-secret")?;
        assert_eq!(
            tool_error(server.list_plugins(Parameters(EmptyArguments {})).await),
            "Cordis bridge response exceeded limit"
        );
        bridge_thread.join().unwrap();
        Ok(())
    }

    #[tokio::test]
    async fn bridge_error_envelope_becomes_a_stable_sanitized_tool_error() -> anyhow::Result<()> {
        let bridge = tiny_http::Server::http("127.0.0.1:0")
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let bridge_url = format!("http://{}", bridge.server_addr());
        let bridge_thread = std::thread::spawn(move || {
            let request = receive_request(&bridge);
            request
                .respond(
                    tiny_http::Response::from_string(
                        json!({
                            "ok": false,
                            "error": {
                                "code": "invalid_request",
                                "message": "secret-token /Users/operator/private"
                            }
                        })
                        .to_string(),
                    )
                    .with_status_code(400)
                    .with_header(
                        tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap(),
                    ),
                )
                .unwrap();
        });

        let server = McpCordisServer::new(&bridge_url, "bridge-secret")?;
        let error = tool_error(server.list_plugins(Parameters(EmptyArguments {})).await);
        assert_eq!(error, "Cordis bridge rejected request (invalid_request)");
        assert!(!error.contains("secret-token"));
        assert!(!error.contains("/Users/"));
        bridge_thread.join().unwrap();
        Ok(())
    }

    #[tokio::test]
    async fn invalid_typed_arguments_are_rejected_without_contacting_the_bridge()
    -> anyhow::Result<()> {
        let bridge = tiny_http::Server::http("127.0.0.1:0")
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let bridge_url = format!("http://{}", bridge.server_addr());
        let server = McpCordisServer::new(&bridge_url, "bridge-secret")?;

        let invalid_plugin = tool_error(
            server
                .read_plugin_manifest(Parameters(PluginIdParams {
                    plugin_id: "@catomicals/plugin-UPPER".to_owned(),
                }))
                .await,
        );
        assert_eq!(invalid_plugin, "Invalid Cordis plugin id");

        let oversized = tool_error(
            server
                .create_plugin_settings_intent(Parameters(SettingsPatchParams {
                    plugin_id: "@catomicals/plugin-mcp".to_owned(),
                    patch: SettingsPatch {
                        schema_version: 1,
                        changes: BTreeMap::from([(
                            "endpoint".to_owned(),
                            SettingValue::String("x".repeat(super::MAX_REQUEST_BYTES)),
                        )]),
                    },
                }))
                .await,
        );
        assert_eq!(oversized, "Cordis request exceeded limit");
        assert!(bridge.recv_timeout(Duration::from_millis(200))?.is_none());
        Ok(())
    }

    #[test]
    fn debug_output_does_not_expose_the_bridge_url_or_session_token() {
        let server = McpCordisServer::new("http://127.0.0.1:18788", "top-secret-token").unwrap();
        let debug = format!("{server:?}");
        assert!(!debug.contains("top-secret-token"));
        assert!(!debug.contains("127.0.0.1:18788"));
    }
}

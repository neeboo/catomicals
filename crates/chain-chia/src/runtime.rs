use std::time::Duration;

use catomicals_chain_domain::{ChainNetwork, ChainScope, ChiaNetwork};
use reqwest::{Client, Url};
use serde_json::{Value, json};

use crate::{
    ChiaAdapterError, ChiaSpendBundle, ChiaSpendOutput, ThresholdBlsCommitment,
    ThresholdBlsDealerKeyKind, consensus_constants_for_scope, verify_threshold_spend_bundle,
};

const MAX_RPC_RESPONSE_BYTES: usize = 64 * 1024;

/// Immutable wallet review record required before broadcasting a SpendBundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChiaPushReview {
    pub scope: ChainScope,
    pub bundle_id: [u8; 32],
    pub coin_id: [u8; 32],
    pub outputs: Vec<ChiaSpendOutput>,
}

/// Receipt returned only after the full node reports mempool success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChiaPushReceipt {
    pub bundle_id: [u8; 32],
    pub status: &'static str,
}

/// Wallet-callable Chia execution adapter. It verifies the reviewed bundle
/// locally with official consensus code before any network request is made.
#[derive(Debug, Clone)]
pub struct ChiaRuntimeAdapter {
    scope: ChainScope,
    endpoint: Url,
    client: Client,
}

impl ChiaRuntimeAdapter {
    /// Explicit local/test mode. Only unencrypted loopback HTTP is accepted.
    pub fn new_loopback_http(
        scope: ChainScope,
        endpoint: &str,
        timeout: Duration,
    ) -> Result<Self, ChiaAdapterError> {
        let endpoint = validate_endpoint(scope, endpoint, timeout)?;
        if endpoint.scheme() != "http" {
            return Err(ChiaAdapterError::ChiaRpcMutualTlsRequired);
        }
        if !endpoint.host_str().is_some_and(is_loopback_host) {
            return Err(ChiaAdapterError::InsecureChiaRpcEndpoint);
        }
        let client = base_client_builder(timeout)
            .build()
            .map_err(|error| ChiaAdapterError::ChiaRpcRequest(error.to_string()))?;
        Ok(Self {
            scope,
            endpoint,
            client,
        })
    }

    /// Builds a client for Chia's default mutually authenticated HTTPS RPC.
    /// `identity_pem` contains the client certificate followed by its private
    /// key; `root_ca_pem` is the Chia installation's private CA certificate.
    pub fn new_private_mtls(
        scope: ChainScope,
        endpoint: &str,
        timeout: Duration,
        identity_pem: &[u8],
        root_ca_pem: &[u8],
    ) -> Result<Self, ChiaAdapterError> {
        if identity_pem.is_empty() || root_ca_pem.is_empty() {
            return Err(ChiaAdapterError::ChiaRpcMutualTlsRequired);
        }
        let endpoint = validate_endpoint(scope, endpoint, timeout)?;
        if endpoint.scheme() != "https" {
            return Err(ChiaAdapterError::ChiaRpcMutualTlsRequired);
        }
        let identity = reqwest::Identity::from_pem(identity_pem)
            .map_err(|error| ChiaAdapterError::ChiaRpcRequest(error.to_string()))?;
        let root_ca = reqwest::Certificate::from_pem(root_ca_pem)
            .map_err(|error| ChiaAdapterError::ChiaRpcRequest(error.to_string()))?;
        let client = base_client_builder(timeout)
            .tls_built_in_root_certs(false)
            .identity(identity)
            .add_root_certificate(root_ca)
            .build()
            .map_err(|error| ChiaAdapterError::ChiaRpcRequest(error.to_string()))?;
        Ok(Self {
            scope,
            endpoint,
            client,
        })
    }

    pub async fn push_tx(
        &self,
        bundle_bytes: &[u8],
        key_kind: ThresholdBlsDealerKeyKind,
        commitment: &ThresholdBlsCommitment,
        review: &ChiaPushReview,
    ) -> Result<ChiaPushReceipt, ChiaAdapterError> {
        let verified =
            verify_threshold_spend_bundle(self.scope, key_kind, commitment, bundle_bytes)?;
        if review.scope != self.scope
            || review.bundle_id != verified.bundle_id
            || review.coin_id != verified.coin_id
            || review.outputs != verified.outputs
        {
            return Err(ChiaAdapterError::ChiaSpendReviewMismatch);
        }

        let network = self.post("get_network_info", json!({})).await?;
        let expected = expected_network(self.scope)?;
        require_success(&network)?;
        let network_name = required_string(&network, "network_name")?;
        let prefix = required_string(&network, "network_prefix")?;
        if network_name != expected.0 || prefix != expected.1 {
            return Err(ChiaAdapterError::ChiaRpcNetworkMismatch {
                expected: format!("{}/{}", expected.0, expected.1),
                actual: format!("{network_name}/{prefix}"),
            });
        }

        let additional = self.post("get_aggsig_additional_data", json!({})).await?;
        require_success(&additional)?;
        let actual = required_string(&additional, "additional_data")?;
        let constants = consensus_constants_for_scope(self.scope)?;
        if decode_bytes32(actual)? != constants.agg_sig_me_additional_data.to_bytes() {
            return Err(ChiaAdapterError::ChiaRpcAdditionalDataMismatch);
        }

        let bundle = ChiaSpendBundle::from_bytes(bundle_bytes)
            .map_err(|error| ChiaAdapterError::InvalidChiaSpendBundle(error.to_string()))?;
        let response = self
            .post(
                "push_tx",
                json!({ "spend_bundle": spend_bundle_json(&bundle) }),
            )
            .await?;
        require_success(&response)?;
        let status = required_string(&response, "status")?;
        if status != "SUCCESS" {
            return Err(ChiaAdapterError::ChiaRpcRejected(status.to_owned()));
        }
        Ok(ChiaPushReceipt {
            bundle_id: verified.bundle_id,
            status: "SUCCESS",
        })
    }

    async fn post(&self, path: &str, body: Value) -> Result<Value, ChiaAdapterError> {
        let url = self
            .endpoint
            .join(path)
            .map_err(|error| ChiaAdapterError::InvalidChiaRpcEndpoint(error.to_string()))?;
        let response = self
            .client
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|error| ChiaAdapterError::ChiaRpcRequest(error.to_string()))?;
        if !response.status().is_success() {
            return Err(ChiaAdapterError::ChiaRpcRejected(format!(
                "HTTP {}",
                response.status()
            )));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RPC_RESPONSE_BYTES as u64)
        {
            return Err(ChiaAdapterError::ChiaRpcResponseTooLarge);
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|error| ChiaAdapterError::ChiaRpcRequest(error.to_string()))?;
        if bytes.len() > MAX_RPC_RESPONSE_BYTES {
            return Err(ChiaAdapterError::ChiaRpcResponseTooLarge);
        }
        serde_json::from_slice(&bytes)
            .map_err(|error| ChiaAdapterError::MalformedChiaRpcResponse(error.to_string()))
    }
}

fn validate_endpoint(
    scope: ChainScope,
    endpoint: &str,
    timeout: Duration,
) -> Result<Url, ChiaAdapterError> {
    consensus_constants_for_scope(scope)?;
    if timeout.is_zero() {
        return Err(ChiaAdapterError::InvalidChiaRpcEndpoint(
            "timeout must be greater than zero".to_owned(),
        ));
    }
    let endpoint = Url::parse(endpoint)
        .map_err(|error| ChiaAdapterError::InvalidChiaRpcEndpoint(error.to_string()))?;
    if endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
    {
        return Err(ChiaAdapterError::InvalidChiaRpcEndpoint(
            "query, fragment, and URL credentials are not allowed".to_owned(),
        ));
    }
    if !matches!(endpoint.scheme(), "http" | "https") {
        return Err(ChiaAdapterError::InvalidChiaRpcEndpoint(format!(
            "unsupported scheme {}",
            endpoint.scheme()
        )));
    }
    Ok(endpoint)
}

fn base_client_builder(timeout: Duration) -> reqwest::ClientBuilder {
    Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn expected_network(scope: ChainScope) -> Result<(&'static str, &'static str), ChiaAdapterError> {
    match scope.network {
        ChainNetwork::Chia(ChiaNetwork::Mainnet) => Ok(("mainnet", "xch")),
        ChainNetwork::Chia(ChiaNetwork::Testnet11) => Ok(("testnet11", "txch")),
        _ => Err(ChiaAdapterError::UnsupportedChainScope(scope)),
    }
}

fn require_success(value: &Value) -> Result<(), ChiaAdapterError> {
    if value.get("success").and_then(Value::as_bool) == Some(true) {
        Ok(())
    } else {
        Err(ChiaAdapterError::ChiaRpcRejected(
            value
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("success was not true")
                .to_owned(),
        ))
    }
}

fn required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, ChiaAdapterError> {
    value.get(field).and_then(Value::as_str).ok_or_else(|| {
        ChiaAdapterError::MalformedChiaRpcResponse(format!("missing string field {field}"))
    })
}

fn decode_bytes32(value: &str) -> Result<[u8; 32], ChiaAdapterError> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    let mut output = [0_u8; 32];
    hex::decode_to_slice(value, &mut output)
        .map_err(|error| ChiaAdapterError::MalformedChiaRpcResponse(error.to_string()))?;
    Ok(output)
}

fn spend_bundle_json(bundle: &ChiaSpendBundle) -> Value {
    let coin_spends = bundle
        .coin_spends
        .iter()
        .map(|spend| {
            json!({
                "coin": {
                    "parent_coin_info": hex_value(spend.coin.parent_coin_info.as_slice()),
                    "puzzle_hash": hex_value(spend.coin.puzzle_hash.as_slice()),
                    "amount": spend.coin.amount,
                },
                "puzzle_reveal": hex_value(spend.puzzle_reveal.as_slice()),
                "solution": hex_value(spend.solution.as_slice()),
            })
        })
        .collect::<Vec<_>>();
    json!({
        "coin_spends": coin_spends,
        "aggregated_signature": hex_value(&bundle.aggregated_signature.to_bytes()),
    })
}

fn hex_value(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

use chia_traits::Streamable;

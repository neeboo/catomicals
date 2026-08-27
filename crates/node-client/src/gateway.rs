use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoincore_rpc::RpcApi;
use bitcoincore_rpc::bitcoin::consensus::deserialize;
use bitcoincore_rpc::bitcoin::{BlockHash, OutPoint, ScriptBuf, Transaction, Txid};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::deployment::{self, DeploymentStatus, OP_CAT_DEPLOYMENT_NAME};
use crate::rpc::NodeConnection;
use crate::{NodeIdentity, NodeIdentityError, validate_node_identity};

/// Maximum age of a snapshot accepted as a write-path precondition.
pub const MAX_WRITE_SNAPSHOT_AGE_SECS: u64 = 30;

#[derive(Debug)]
struct RpcFailure {
    code: Option<i32>,
    message: String,
}

impl From<bitcoincore_rpc::Error> for RpcFailure {
    fn from(error: bitcoincore_rpc::Error) -> Self {
        let code = match &error {
            bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::jsonrpc::error::Error::Rpc(error)) => {
                Some(error.code)
            }
            _ => None,
        };
        Self {
            code,
            message: error.to_string(),
        }
    }
}

trait RpcBackend {
    fn call(&self, method: &'static str, params: &[Value]) -> Result<Value, RpcFailure>;
}

impl RpcBackend for NodeConnection {
    fn call(&self, method: &'static str, params: &[Value]) -> Result<Value, RpcFailure> {
        RpcApi::call(self.client(), method, params).map_err(Into::into)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportedChain {
    Signet,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeSnapshotId(String);

impl NodeSnapshotId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for NodeSnapshotId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainTip {
    pub block_hash: BlockHash,
    pub height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainSnapshot {
    pub id: NodeSnapshotId,
    pub chain: SupportedChain,
    pub tip: ChainTip,
    pub headers: u64,
    pub median_time: u64,
    pub observed_at: u64,
    pub subversion: String,
    pub op_cat: DeploymentStatus,
    pub txindex: TxIndexStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxIndexStatus {
    pub synced: bool,
    pub best_block_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedPrevout {
    pub outpoint: OutPoint,
    pub value_sat: u64,
    pub script_pubkey: ScriptBuf,
    pub confirmations: u32,
    pub coinbase: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrevoutResolution {
    pub snapshot: ChainSnapshot,
    pub prevouts: Vec<ResolvedPrevout>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SinglePrevoutResolution {
    pub snapshot: ChainSnapshot,
    pub prevout: ResolvedPrevout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawTransaction {
    hex: String,
    txid: Txid,
}

impl Serialize for RawTransaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.hex)
    }
}

impl<'de> Deserialize<'de> for RawTransaction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw_hex = String::deserialize(deserializer)?;
        Self::from_hex(&raw_hex).map_err(serde::de::Error::custom)
    }
}

impl RawTransaction {
    pub fn from_hex(raw_hex: &str) -> Result<Self, NodeGatewayError> {
        let bytes =
            hex::decode(raw_hex).map_err(|error| NodeGatewayError::InvalidRawTransaction {
                detail: error.to_string(),
            })?;
        let transaction: Transaction =
            deserialize(&bytes).map_err(|error| NodeGatewayError::InvalidRawTransaction {
                detail: error.to_string(),
            })?;
        Ok(Self {
            hex: raw_hex.to_ascii_lowercase(),
            txid: transaction.compute_txid(),
        })
    }

    pub fn as_hex(&self) -> &str {
        &self.hex
    }

    pub fn txid(&self) -> Txid {
        self.txid
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MempoolAcceptance {
    pub snapshot: ChainSnapshot,
    pub txid: Txid,
    pub allowed: bool,
    pub reject_reason: Option<String>,
    pub vsize: Option<u64>,
    pub fee_sat: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TransactionStatus {
    Confirmed {
        block_hash: BlockHash,
        confirmations: u32,
    },
    Mempool,
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionObservation {
    pub snapshot: ChainSnapshot,
    pub txid: Txid,
    pub status: TransactionStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BroadcastOutcome {
    Submitted,
    AlreadyKnown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BroadcastReceipt {
    pub snapshot: ChainSnapshot,
    pub txid: Txid,
    pub outcome: BroadcastOutcome,
}

#[derive(Debug, thiserror::Error)]
pub enum NodeGatewayError {
    #[error("node RPC `{method}` failed{code_suffix}: {message}", code_suffix = code.map(|value| format!(" with code {value}")).unwrap_or_default())]
    RpcCall {
        method: &'static str,
        code: Option<i32>,
        message: String,
    },
    #[error("node RPC `{method}` returned malformed data: {detail}")]
    MalformedResponse {
        method: &'static str,
        detail: String,
    },
    #[error("node identity validation failed: {0}")]
    Identity(#[from] NodeIdentityError),
    #[error("deployment check failed: {0}")]
    Deployment(#[from] deployment::DeploymentError),
    #[error("prevout `{outpoint}` does not exist")]
    PrevoutMissing { outpoint: OutPoint },
    #[error("prevout `{outpoint}` is already spent")]
    PrevoutSpent { outpoint: OutPoint },
    #[error(
        "prevout `{outpoint}` was resolved at block `{actual}`, expected current tip `{expected}`"
    )]
    PrevoutEvidenceMismatch {
        outpoint: OutPoint,
        expected: BlockHash,
        actual: BlockHash,
    },
    #[error("chain tip changed from `{before}` to `{after}` during the node operation")]
    ChainTipChanged {
        before: NodeSnapshotId,
        after: NodeSnapshotId,
    },
    #[error("raw transaction is invalid: {detail}")]
    InvalidRawTransaction { detail: String },
    #[error("node RPC `{method}` returned {actual} results, expected {expected}")]
    UnexpectedResultCount {
        method: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("node RPC `{method}` returned txid `{actual}`, expected `{expected}`")]
    TransactionIdMismatch {
        method: &'static str,
        expected: Txid,
        actual: Txid,
    },
    #[error("node returned inconsistent status for transaction `{txid}`: {detail}")]
    InconsistentTransactionStatus { txid: Txid, detail: String },
    #[error("node snapshot is stale: expected `{expected}`, current `{actual}`")]
    StaleSnapshot {
        expected: NodeSnapshotId,
        actual: NodeSnapshotId,
    },
    #[error("transaction `{txid}` failed mempool preflight at `{snapshot}`: {reason}")]
    MempoolRejected {
        txid: Txid,
        snapshot: NodeSnapshotId,
        reason: String,
    },
    #[error(
        "node snapshot `{snapshot}` is expired: observed at {observed_at}, current time {now}, maximum age {max_age_secs}s"
    )]
    ExpiredSnapshot {
        snapshot: NodeSnapshotId,
        observed_at: u64,
        now: u64,
        max_age_secs: u64,
    },
    #[error("Bitcoin Core transaction index is not enabled; start the node with `txindex=1`")]
    TxIndexMissing,
    #[error("Bitcoin Core transaction index is not synchronized (best height {best_block_height})")]
    TxIndexNotSynced { best_block_height: u64 },
    #[error(
        "Bitcoin Core transaction index height {best_block_height} does not match chain tip height {tip_height}"
    )]
    TxIndexHeightMismatch {
        best_block_height: u64,
        tip_height: u64,
    },
}

pub struct NodeGateway<'a> {
    backend: &'a dyn RpcBackend,
}

impl<'a> NodeGateway<'a> {
    pub fn new(connection: &'a NodeConnection) -> Self {
        Self {
            backend: connection,
        }
    }

    #[cfg(test)]
    fn with_backend(backend: &'a dyn RpcBackend) -> Self {
        Self { backend }
    }

    pub fn chain_snapshot(&self) -> Result<ChainSnapshot, NodeGatewayError> {
        #[derive(Deserialize)]
        struct BlockchainInfo {
            chain: String,
            blocks: u64,
            headers: u64,
            bestblockhash: String,
            mediantime: u64,
        }

        #[derive(Deserialize)]
        struct NetworkInfo {
            subversion: String,
        }

        let blockchain: BlockchainInfo = self.call_typed("getblockchaininfo", &[])?;
        let network: NetworkInfo = self.call_typed("getnetworkinfo", &[])?;
        let deployment_value = self.call_value("getdeploymentinfo", &[])?;
        let op_cat = deployment::deployment_status(&deployment_value, OP_CAT_DEPLOYMENT_NAME)?;
        let indexes = self.call_value("getindexinfo", &[])?;
        let txindex = require_synced_txindex(&indexes, blockchain.blocks)?;

        validate_node_identity(&NodeIdentity {
            chain: blockchain.chain.clone(),
            subversion: network.subversion.clone(),
            cat_active: op_cat.active,
        })?;

        let block_hash = BlockHash::from_str(&blockchain.bestblockhash).map_err(|error| {
            NodeGatewayError::MalformedResponse {
                method: "getblockchaininfo",
                detail: format!("invalid bestblockhash: {error}"),
            }
        })?;
        let id = NodeSnapshotId(format!(
            "signet:{block_hash}:{}:op_cat:active",
            blockchain.blocks
        ));
        let observed_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(ChainSnapshot {
            id,
            chain: SupportedChain::Signet,
            tip: ChainTip {
                block_hash,
                height: blockchain.blocks,
            },
            headers: blockchain.headers,
            median_time: blockchain.mediantime,
            observed_at,
            subversion: network.subversion,
            op_cat,
            txindex,
        })
    }

    pub fn resolve_prevouts(
        &self,
        outpoints: &[OutPoint],
    ) -> Result<PrevoutResolution, NodeGatewayError> {
        let before = self.chain_snapshot()?;
        let mut prevouts = Vec::with_capacity(outpoints.len());

        for outpoint in outpoints {
            let params = [
                Value::String(outpoint.txid.to_string()),
                Value::from(outpoint.vout),
                Value::Bool(true),
            ];
            let result: Option<bitcoincore_rpc::json::GetTxOutResult> =
                self.call_typed("gettxout", &params)?;
            let Some(result) = result else {
                let classification = self.classify_unavailable_prevout(*outpoint);
                let after = self.chain_snapshot()?;
                self.ensure_same_tip(&before, &after)?;
                return Err(classification);
            };

            if result.bestblock != before.tip.block_hash {
                return Err(NodeGatewayError::PrevoutEvidenceMismatch {
                    outpoint: *outpoint,
                    expected: before.tip.block_hash,
                    actual: result.bestblock,
                });
            }
            prevouts.push(ResolvedPrevout {
                outpoint: *outpoint,
                value_sat: result.value.to_sat(),
                script_pubkey: ScriptBuf::from(result.script_pub_key.hex),
                confirmations: result.confirmations,
                coinbase: result.coinbase,
            });
        }

        let after = self.chain_snapshot()?;
        self.ensure_same_tip(&before, &after)?;
        Ok(PrevoutResolution {
            snapshot: after,
            prevouts,
        })
    }

    pub fn resolve_prevout(
        &self,
        outpoint: OutPoint,
    ) -> Result<SinglePrevoutResolution, NodeGatewayError> {
        let mut resolution = self.resolve_prevouts(&[outpoint])?;
        let prevout = resolution
            .prevouts
            .pop()
            .expect("single-outpoint resolution returns one prevout");
        Ok(SinglePrevoutResolution {
            snapshot: resolution.snapshot,
            prevout,
        })
    }

    pub fn test_mempool_accept(
        &self,
        transaction: &RawTransaction,
    ) -> Result<MempoolAcceptance, NodeGatewayError> {
        let before = self.chain_snapshot()?;
        let result = self.test_mempool_accept_at(transaction, &before)?;
        let after = self.chain_snapshot()?;
        self.ensure_same_tip(&before, &after)?;
        Ok(MempoolAcceptance {
            snapshot: after,
            ..result
        })
    }

    pub fn transaction_status(
        &self,
        txid: Txid,
    ) -> Result<TransactionObservation, NodeGatewayError> {
        #[derive(Deserialize)]
        struct RawTransactionStatus {
            txid: Txid,
            #[serde(default)]
            blockhash: Option<BlockHash>,
            #[serde(default)]
            confirmations: Option<u32>,
            #[serde(default)]
            in_active_chain: Option<bool>,
        }

        let before = self.chain_snapshot()?;
        let params = [Value::String(txid.to_string()), Value::Bool(true)];
        let status = match self.backend.call("getrawtransaction", &params) {
            Err(error) if error.code == Some(-5) => TransactionStatus::Missing,
            Err(error) => {
                return Err(NodeGatewayError::RpcCall {
                    method: "getrawtransaction",
                    code: error.code,
                    message: error.message,
                });
            }
            Ok(value) => {
                let response: RawTransactionStatus =
                    serde_json::from_value(value).map_err(|error| {
                        NodeGatewayError::MalformedResponse {
                            method: "getrawtransaction",
                            detail: error.to_string(),
                        }
                    })?;
                if response.txid != txid {
                    return Err(NodeGatewayError::TransactionIdMismatch {
                        method: "getrawtransaction",
                        expected: txid,
                        actual: response.txid,
                    });
                }
                match (response.blockhash, response.confirmations) {
                    (Some(block_hash), Some(confirmations))
                        if confirmations > 0 && response.in_active_chain != Some(false) =>
                    {
                        TransactionStatus::Confirmed {
                            block_hash,
                            confirmations,
                        }
                    }
                    (None, None | Some(0)) => TransactionStatus::Mempool,
                    _ => {
                        return Err(NodeGatewayError::InconsistentTransactionStatus {
                            txid,
                            detail: format!(
                                "blockhash={:?}, confirmations={:?}, in_active_chain={:?}",
                                response.blockhash,
                                response.confirmations,
                                response.in_active_chain
                            ),
                        });
                    }
                }
            }
        };
        let after = self.chain_snapshot()?;
        self.ensure_same_tip(&before, &after)?;
        Ok(TransactionObservation {
            snapshot: after,
            txid,
            status,
        })
    }

    pub fn broadcast_transaction(
        &self,
        transaction: &RawTransaction,
        expected_snapshot: &ChainSnapshot,
    ) -> Result<BroadcastReceipt, NodeGatewayError> {
        let now = unix_time();
        if now < expected_snapshot.observed_at
            || now.saturating_sub(expected_snapshot.observed_at) > MAX_WRITE_SNAPSHOT_AGE_SECS
        {
            return Err(NodeGatewayError::ExpiredSnapshot {
                snapshot: expected_snapshot.id.clone(),
                observed_at: expected_snapshot.observed_at,
                now,
                max_age_secs: MAX_WRITE_SNAPSHOT_AGE_SECS,
            });
        }
        let before = self.chain_snapshot()?;
        if before.id != expected_snapshot.id {
            return Err(NodeGatewayError::StaleSnapshot {
                expected: expected_snapshot.id.clone(),
                actual: before.id,
            });
        }

        let acceptance = self.test_mempool_accept_at(transaction, &before)?;
        if !acceptance.allowed {
            let reason = acceptance
                .reject_reason
                .unwrap_or_else(|| "node rejected transaction without a reason".to_owned());
            if is_already_known_message(&reason) {
                let after = self.chain_snapshot()?;
                self.ensure_same_tip(&before, &after)?;
                return Ok(BroadcastReceipt {
                    snapshot: after,
                    txid: transaction.txid(),
                    outcome: BroadcastOutcome::AlreadyKnown,
                });
            }
            return Err(NodeGatewayError::MempoolRejected {
                txid: transaction.txid(),
                snapshot: before.id,
                reason,
            });
        }

        let pre_broadcast = self.chain_snapshot()?;
        self.ensure_same_tip(&before, &pre_broadcast)?;
        let params = [Value::String(transaction.as_hex().to_owned())];
        let outcome = match self.backend.call("sendrawtransaction", &params) {
            Ok(value) => {
                let actual: Txid = serde_json::from_value(value).map_err(|error| {
                    NodeGatewayError::MalformedResponse {
                        method: "sendrawtransaction",
                        detail: error.to_string(),
                    }
                })?;
                if actual != transaction.txid() {
                    return Err(NodeGatewayError::TransactionIdMismatch {
                        method: "sendrawtransaction",
                        expected: transaction.txid(),
                        actual,
                    });
                }
                BroadcastOutcome::Submitted
            }
            Err(error) if error.code == Some(-27) || is_already_known_message(&error.message) => {
                BroadcastOutcome::AlreadyKnown
            }
            Err(error) => {
                return Err(NodeGatewayError::RpcCall {
                    method: "sendrawtransaction",
                    code: error.code,
                    message: error.message,
                });
            }
        };

        let post_broadcast = self.chain_snapshot()?;
        self.ensure_same_tip(&pre_broadcast, &post_broadcast)?;

        Ok(BroadcastReceipt {
            snapshot: post_broadcast,
            txid: transaction.txid(),
            outcome,
        })
    }

    fn test_mempool_accept_at(
        &self,
        transaction: &RawTransaction,
        snapshot: &ChainSnapshot,
    ) -> Result<MempoolAcceptance, NodeGatewayError> {
        let params = [Value::Array(vec![Value::String(
            transaction.as_hex().to_owned(),
        )])];
        let mut results: Vec<bitcoincore_rpc::json::TestMempoolAcceptResult> =
            self.call_typed("testmempoolaccept", &params)?;
        if results.len() != 1 {
            return Err(NodeGatewayError::UnexpectedResultCount {
                method: "testmempoolaccept",
                expected: 1,
                actual: results.len(),
            });
        }
        let result = results.pop().expect("length checked");
        if result.txid != transaction.txid() {
            return Err(NodeGatewayError::TransactionIdMismatch {
                method: "testmempoolaccept",
                expected: transaction.txid(),
                actual: result.txid,
            });
        }
        Ok(MempoolAcceptance {
            snapshot: snapshot.clone(),
            txid: result.txid,
            allowed: result.allowed,
            reject_reason: result.reject_reason,
            vsize: result.vsize,
            fee_sat: result.fees.map(|fees| fees.base.to_sat()),
        })
    }

    fn classify_unavailable_prevout(&self, outpoint: OutPoint) -> NodeGatewayError {
        #[derive(Deserialize)]
        struct RawTransactionSummary {
            txid: Txid,
            vout: Vec<RawTransactionOutput>,
        }

        #[derive(Deserialize)]
        struct RawTransactionOutput {
            n: u32,
        }

        let params = [Value::String(outpoint.txid.to_string()), Value::Bool(true)];
        match self.backend.call("getrawtransaction", &params) {
            Ok(value) => {
                let parsed: RawTransactionSummary = match serde_json::from_value(value) {
                    Ok(parsed) => parsed,
                    Err(error) => {
                        return NodeGatewayError::MalformedResponse {
                            method: "getrawtransaction",
                            detail: error.to_string(),
                        };
                    }
                };
                if parsed.txid != outpoint.txid
                    || !parsed.vout.iter().any(|output| output.n == outpoint.vout)
                {
                    NodeGatewayError::PrevoutMissing { outpoint }
                } else {
                    NodeGatewayError::PrevoutSpent { outpoint }
                }
            }
            Err(error) if error.code == Some(-5) => NodeGatewayError::PrevoutMissing { outpoint },
            Err(error) => NodeGatewayError::RpcCall {
                method: "getrawtransaction",
                code: error.code,
                message: error.message,
            },
        }
    }

    fn ensure_same_tip(
        &self,
        before: &ChainSnapshot,
        after: &ChainSnapshot,
    ) -> Result<(), NodeGatewayError> {
        if before.id != after.id {
            return Err(NodeGatewayError::ChainTipChanged {
                before: before.id.clone(),
                after: after.id.clone(),
            });
        }
        Ok(())
    }

    fn call_value(
        &self,
        method: &'static str,
        params: &[Value],
    ) -> Result<Value, NodeGatewayError> {
        self.backend
            .call(method, params)
            .map_err(|error| NodeGatewayError::RpcCall {
                method,
                code: error.code,
                message: error.message,
            })
    }

    fn call_typed<T: for<'de> Deserialize<'de>>(
        &self,
        method: &'static str,
        params: &[Value],
    ) -> Result<T, NodeGatewayError> {
        let value = self.call_value(method, params)?;
        serde_json::from_value(value).map_err(|error| NodeGatewayError::MalformedResponse {
            method,
            detail: error.to_string(),
        })
    }
}

fn is_already_known_message(message: &str) -> bool {
    let normalized = message.to_ascii_lowercase();
    normalized.contains("already in block chain")
        || normalized.contains("already known")
        || normalized.contains("txn-already-in-mempool")
        || normalized.contains("txn-already-known")
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) fn require_synced_txindex(
    indexes: &Value,
    tip_height: u64,
) -> Result<TxIndexStatus, NodeGatewayError> {
    let index = indexes
        .as_object()
        .ok_or_else(|| NodeGatewayError::MalformedResponse {
            method: "getindexinfo",
            detail: "expected an object".to_owned(),
        })?
        .get("txindex")
        .ok_or(NodeGatewayError::TxIndexMissing)?;
    let synced = index
        .get("synced")
        .and_then(Value::as_bool)
        .ok_or_else(|| NodeGatewayError::MalformedResponse {
            method: "getindexinfo",
            detail: "txindex.synced is missing or is not a boolean".to_owned(),
        })?;
    let best_block_height = index
        .get("best_block_height")
        .and_then(Value::as_u64)
        .ok_or_else(|| NodeGatewayError::MalformedResponse {
            method: "getindexinfo",
            detail: "txindex.best_block_height is missing or is not an unsigned integer".to_owned(),
        })?;
    if !synced {
        return Err(NodeGatewayError::TxIndexNotSynced { best_block_height });
    }
    if best_block_height != tip_height {
        return Err(NodeGatewayError::TxIndexHeightMismatch {
            best_block_height,
            tip_height,
        });
    }
    Ok(TxIndexStatus {
        synced,
        best_block_height,
    })
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use serde_json::{Value, json};

    use super::*;
    use crate::NodeIdentityError;

    #[derive(Debug)]
    struct ScriptedCall {
        method: &'static str,
        result: Result<Value, RpcFailure>,
    }

    #[derive(Debug, Default)]
    struct ScriptedBackend {
        calls: RefCell<VecDeque<ScriptedCall>>,
    }

    impl ScriptedBackend {
        fn new(calls: impl IntoIterator<Item = ScriptedCall>) -> Self {
            Self {
                calls: RefCell::new(calls.into_iter().collect()),
            }
        }

        fn ok(method: &'static str, value: Value) -> ScriptedCall {
            ScriptedCall {
                method,
                result: Ok(value),
            }
        }

        fn error(method: &'static str, code: i32, message: &str) -> ScriptedCall {
            ScriptedCall {
                method,
                result: Err(RpcFailure {
                    code: Some(code),
                    message: message.to_owned(),
                }),
            }
        }

        fn assert_exhausted(&self) {
            assert!(self.calls.borrow().is_empty(), "unused scripted RPC calls");
        }
    }

    impl RpcBackend for ScriptedBackend {
        fn call(&self, method: &'static str, _params: &[Value]) -> Result<Value, RpcFailure> {
            let call = self
                .calls
                .borrow_mut()
                .pop_front()
                .expect("unexpected RPC call");
            assert_eq!(call.method, method);
            call.result
        }
    }

    fn chain_info(chain: &str, tip: &str, height: u64) -> Value {
        json!({
            "chain": chain,
            "blocks": height,
            "headers": height,
            "bestblockhash": tip,
            "mediantime": 1_700_000_000_u64
        })
    }

    fn network_info() -> Value {
        json!({ "subversion": "/Satoshi:29.4.0(bitcoin-inquisition)/" })
    }

    fn deployment_info(active: bool) -> Value {
        json!({
            "deployments": {
                "op_cat": { "type": "heretical", "active": active, "height": 0 }
            }
        })
    }

    fn txindex_info(synced: bool, best_block_height: u64) -> Value {
        json!({
            "txindex": {
                "synced": synced,
                "best_block_height": best_block_height
            }
        })
    }

    fn snapshot_calls(tip: &str, height: u64) -> Vec<ScriptedCall> {
        vec![
            ScriptedBackend::ok("getblockchaininfo", chain_info("signet", tip, height)),
            ScriptedBackend::ok("getnetworkinfo", network_info()),
            ScriptedBackend::ok("getdeploymentinfo", deployment_info(true)),
            ScriptedBackend::ok("getindexinfo", txindex_info(true, height)),
        ]
    }

    fn snapshot_id(tip: &str, height: u64) -> NodeSnapshotId {
        NodeSnapshotId(format!("signet:{tip}:{height}:op_cat:active"))
    }

    fn expected_snapshot(tip: &str, height: u64) -> ChainSnapshot {
        ChainSnapshot {
            id: snapshot_id(tip, height),
            chain: SupportedChain::Signet,
            tip: ChainTip {
                block_hash: BlockHash::from_str(tip).unwrap(),
                height,
            },
            headers: height,
            median_time: 1_700_000_000,
            observed_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            subversion: "/Satoshi:29.4.0(bitcoin-inquisition)/".to_owned(),
            op_cat: DeploymentStatus {
                name: "op_cat".to_owned(),
                kind: "heretical".to_owned(),
                active: true,
                height: Some(0),
            },
            txindex: TxIndexStatus {
                synced: true,
                best_block_height: height,
            },
        }
    }

    fn outpoint(txid_byte: &str, vout: u32) -> bitcoincore_rpc::bitcoin::OutPoint {
        bitcoincore_rpc::bitcoin::OutPoint::from_str(&format!("{}:{vout}", txid_byte.repeat(32)))
            .unwrap()
    }

    fn empty_transaction() -> RawTransaction {
        RawTransaction::from_hex(concat!(
            "02000000",
            "01",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "ffffffff",
            "00",
            "ffffffff",
            "01",
            "0000000000000000",
            "00",
            "00000000"
        ))
        .unwrap()
    }

    #[test]
    fn chain_snapshot_binds_signet_tip_and_cat_deployment() {
        let tip = "11".repeat(32);
        let backend = ScriptedBackend::new([
            ScriptedBackend::ok("getblockchaininfo", chain_info("signet", &tip, 42)),
            ScriptedBackend::ok("getnetworkinfo", network_info()),
            ScriptedBackend::ok("getdeploymentinfo", deployment_info(true)),
            ScriptedBackend::ok("getindexinfo", txindex_info(true, 42)),
        ]);

        let snapshot = NodeGateway::with_backend(&backend)
            .chain_snapshot()
            .unwrap();

        assert_eq!(snapshot.chain, SupportedChain::Signet);
        assert_eq!(snapshot.tip.height, 42);
        assert_eq!(snapshot.tip.block_hash.to_string(), tip);
        assert!(snapshot.op_cat.active);
        assert_eq!(
            snapshot.id.as_str(),
            format!("signet:{tip}:42:op_cat:active")
        );
        backend.assert_exhausted();
    }

    #[test]
    fn chain_snapshot_rejects_the_wrong_chain() {
        let tip = "22".repeat(32);
        let backend = ScriptedBackend::new([
            ScriptedBackend::ok("getblockchaininfo", chain_info("main", &tip, 42)),
            ScriptedBackend::ok("getnetworkinfo", network_info()),
            ScriptedBackend::ok("getdeploymentinfo", deployment_info(true)),
            ScriptedBackend::ok("getindexinfo", txindex_info(true, 42)),
        ]);

        let error = NodeGateway::with_backend(&backend)
            .chain_snapshot()
            .unwrap_err();

        assert!(matches!(
            error,
            NodeGatewayError::Identity(NodeIdentityError::WrongChain(chain)) if chain == "main"
        ));
        backend.assert_exhausted();
    }

    #[test]
    fn chain_snapshot_rejects_partial_node_responses() {
        let backend = ScriptedBackend::new([ScriptedBackend::ok(
            "getblockchaininfo",
            json!({ "chain": "signet", "blocks": 42 }),
        )]);

        let error = NodeGateway::with_backend(&backend)
            .chain_snapshot()
            .unwrap_err();

        assert!(matches!(
            error,
            NodeGatewayError::MalformedResponse {
                method: "getblockchaininfo",
                ..
            }
        ));
        backend.assert_exhausted();
    }

    #[test]
    fn chain_snapshot_requires_a_synced_txindex_at_the_current_tip() {
        let tip = "2a".repeat(32);
        let backend = ScriptedBackend::new([
            ScriptedBackend::ok("getblockchaininfo", chain_info("signet", &tip, 42)),
            ScriptedBackend::ok("getnetworkinfo", network_info()),
            ScriptedBackend::ok("getdeploymentinfo", deployment_info(true)),
            ScriptedBackend::ok("getindexinfo", txindex_info(true, 42)),
        ]);

        let snapshot = NodeGateway::with_backend(&backend)
            .chain_snapshot()
            .unwrap();

        assert!(snapshot.txindex.synced);
        assert_eq!(snapshot.txindex.best_block_height, 42);
        backend.assert_exhausted();
    }

    #[test]
    fn chain_snapshot_rejects_missing_unsynced_or_lagging_txindex() {
        enum Expected {
            Missing,
            NotSynced,
            HeightMismatch,
        }
        for (index_info, expected) in [
            (json!({}), Expected::Missing),
            (txindex_info(false, 41), Expected::NotSynced),
            (txindex_info(true, 41), Expected::HeightMismatch),
        ] {
            let tip = "2b".repeat(32);
            let backend = ScriptedBackend::new([
                ScriptedBackend::ok("getblockchaininfo", chain_info("signet", &tip, 42)),
                ScriptedBackend::ok("getnetworkinfo", network_info()),
                ScriptedBackend::ok("getdeploymentinfo", deployment_info(true)),
                ScriptedBackend::ok("getindexinfo", index_info),
            ]);

            let error = NodeGateway::with_backend(&backend)
                .chain_snapshot()
                .unwrap_err();

            assert!(match expected {
                Expected::Missing => matches!(error, NodeGatewayError::TxIndexMissing),
                Expected::NotSynced => {
                    matches!(error, NodeGatewayError::TxIndexNotSynced { .. })
                }
                Expected::HeightMismatch => {
                    matches!(error, NodeGatewayError::TxIndexHeightMismatch { .. })
                }
            });
            backend.assert_exhausted();
        }
    }

    #[test]
    fn resolve_prevouts_returns_authoritative_values_bound_to_a_stable_tip() {
        let tip = "33".repeat(32);
        let wanted = outpoint("44", 1);
        let mut calls = snapshot_calls(&tip, 120);
        calls.push(ScriptedBackend::ok(
            "gettxout",
            json!({
                "bestblock": tip,
                "confirmations": 7,
                "value": 0.00001234,
                "scriptPubKey": { "asm": "1", "hex": "51" },
                "coinbase": false
            }),
        ));
        calls.extend(snapshot_calls(&"33".repeat(32), 120));
        let backend = ScriptedBackend::new(calls);

        let resolution = NodeGateway::with_backend(&backend)
            .resolve_prevouts(&[wanted])
            .unwrap();

        assert_eq!(resolution.snapshot.tip.height, 120);
        assert_eq!(resolution.prevouts.len(), 1);
        assert_eq!(resolution.prevouts[0].outpoint, wanted);
        assert_eq!(resolution.prevouts[0].value_sat, 1_234);
        assert_eq!(resolution.prevouts[0].script_pubkey.as_bytes(), &[0x51]);
        assert_eq!(resolution.prevouts[0].confirmations, 7);
        backend.assert_exhausted();
    }

    #[test]
    fn resolve_prevout_is_a_typed_single_output_contract() {
        let tip = "34".repeat(32);
        let wanted = outpoint("45", 0);
        let mut calls = snapshot_calls(&tip, 120);
        calls.push(ScriptedBackend::ok(
            "gettxout",
            json!({
                "bestblock": tip,
                "confirmations": 1,
                "value": 0.00000001,
                "scriptPubKey": { "asm": "1", "hex": "51" },
                "coinbase": false
            }),
        ));
        calls.extend(snapshot_calls(&"34".repeat(32), 120));
        let backend = ScriptedBackend::new(calls);

        let resolution = NodeGateway::with_backend(&backend)
            .resolve_prevout(wanted)
            .unwrap();

        assert_eq!(resolution.prevout.outpoint, wanted);
        assert_eq!(resolution.prevout.value_sat, 1);
        assert_eq!(resolution.snapshot.id, snapshot_id(&tip, 120));
        backend.assert_exhausted();
    }

    #[test]
    fn resolve_prevouts_distinguishes_a_spent_output() {
        let tip = "55".repeat(32);
        let wanted = outpoint("66", 0);
        let mut calls = snapshot_calls(&tip, 121);
        calls.push(ScriptedBackend::ok("gettxout", Value::Null));
        calls.push(ScriptedBackend::ok(
            "getrawtransaction",
            json!({ "txid": wanted.txid, "vout": [{ "n": 0 }] }),
        ));
        calls.extend(snapshot_calls(&tip, 121));
        let backend = ScriptedBackend::new(calls);

        let error = NodeGateway::with_backend(&backend)
            .resolve_prevouts(&[wanted])
            .unwrap_err();

        assert!(matches!(
            error,
            NodeGatewayError::PrevoutSpent { outpoint } if outpoint == wanted
        ));
        backend.assert_exhausted();
    }

    #[test]
    fn resolve_prevouts_rechecks_the_tip_before_returning_a_null_output_classification() {
        let first_tip = "67".repeat(32);
        let next_tip = "68".repeat(32);
        let wanted = outpoint("69", 0);
        let mut calls = snapshot_calls(&first_tip, 121);
        calls.push(ScriptedBackend::ok("gettxout", Value::Null));
        calls.push(ScriptedBackend::ok(
            "getrawtransaction",
            json!({ "txid": wanted.txid, "vout": [{ "n": 0 }] }),
        ));
        calls.extend(snapshot_calls(&next_tip, 122));
        let backend = ScriptedBackend::new(calls);

        let error = NodeGateway::with_backend(&backend)
            .resolve_prevouts(&[wanted])
            .unwrap_err();

        assert!(matches!(error, NodeGatewayError::ChainTipChanged { .. }));
        backend.assert_exhausted();
    }

    #[test]
    fn resolve_prevouts_distinguishes_a_missing_output() {
        let tip = "77".repeat(32);
        let wanted = outpoint("88", 2);
        let mut calls = snapshot_calls(&tip, 122);
        calls.push(ScriptedBackend::ok("gettxout", Value::Null));
        calls.push(ScriptedBackend::error(
            "getrawtransaction",
            -5,
            "No such mempool or blockchain transaction",
        ));
        calls.extend(snapshot_calls(&tip, 122));
        let backend = ScriptedBackend::new(calls);

        let error = NodeGateway::with_backend(&backend)
            .resolve_prevouts(&[wanted])
            .unwrap_err();

        assert!(matches!(
            error,
            NodeGatewayError::PrevoutMissing { outpoint } if outpoint == wanted
        ));
        backend.assert_exhausted();
    }

    #[test]
    fn resolve_prevouts_rejects_partial_gettxout_data() {
        let tip = "99".repeat(32);
        let wanted = outpoint("aa", 0);
        let mut calls = snapshot_calls(&tip, 123);
        calls.push(ScriptedBackend::ok(
            "gettxout",
            json!({ "bestblock": tip, "confirmations": 1, "value": 1.0 }),
        ));
        let backend = ScriptedBackend::new(calls);

        let error = NodeGateway::with_backend(&backend)
            .resolve_prevouts(&[wanted])
            .unwrap_err();

        assert!(matches!(
            error,
            NodeGatewayError::MalformedResponse {
                method: "gettxout",
                ..
            }
        ));
        backend.assert_exhausted();
    }

    #[test]
    fn resolve_prevouts_closes_when_the_tip_changes_during_resolution() {
        let first_tip = "bb".repeat(32);
        let next_tip = "cc".repeat(32);
        let wanted = outpoint("dd", 0);
        let mut calls = snapshot_calls(&first_tip, 124);
        calls.push(ScriptedBackend::ok(
            "gettxout",
            json!({
                "bestblock": first_tip,
                "confirmations": 1,
                "value": 0.1,
                "scriptPubKey": { "asm": "1", "hex": "51" },
                "coinbase": false
            }),
        ));
        calls.extend(snapshot_calls(&next_tip, 125));
        let backend = ScriptedBackend::new(calls);

        let error = NodeGateway::with_backend(&backend)
            .resolve_prevouts(&[wanted])
            .unwrap_err();

        assert!(matches!(error, NodeGatewayError::ChainTipChanged { .. }));
        backend.assert_exhausted();
    }

    #[test]
    fn raw_transaction_rejects_malformed_hex_and_non_transaction_bytes() {
        assert!(matches!(
            RawTransaction::from_hex("zz"),
            Err(NodeGatewayError::InvalidRawTransaction { .. })
        ));
        assert!(matches!(
            RawTransaction::from_hex("00"),
            Err(NodeGatewayError::InvalidRawTransaction { .. })
        ));
    }

    #[test]
    fn raw_transaction_deserialization_recomputes_instead_of_trusting_a_claimed_txid() {
        let transaction = empty_transaction();
        let forged = json!({
            "hex": transaction.as_hex(),
            "txid": "ff".repeat(32)
        });

        assert!(serde_json::from_value::<RawTransaction>(forged).is_err());
        let encoded = serde_json::to_value(&transaction).unwrap();
        let decoded: RawTransaction = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, transaction);
    }

    #[test]
    fn test_mempool_accept_returns_allowed_result_with_tip_identity() {
        let tip = "de".repeat(32);
        let transaction = empty_transaction();
        let mut calls = snapshot_calls(&tip, 130);
        calls.push(ScriptedBackend::ok(
            "testmempoolaccept",
            json!([{
                "txid": transaction.txid(),
                "allowed": true,
                "vsize": 10,
                "fees": { "base": 0.00000010 }
            }]),
        ));
        calls.extend(snapshot_calls(&tip, 130));
        let backend = ScriptedBackend::new(calls);

        let result = NodeGateway::with_backend(&backend)
            .test_mempool_accept(&transaction)
            .unwrap();

        assert!(result.allowed);
        assert_eq!(result.txid, transaction.txid());
        assert_eq!(result.vsize, Some(10));
        assert_eq!(result.fee_sat, Some(10));
        assert_eq!(result.snapshot.tip.height, 130);
        backend.assert_exhausted();
    }

    #[test]
    fn test_mempool_accept_preserves_rejection_reason() {
        let tip = "ef".repeat(32);
        let transaction = empty_transaction();
        let mut calls = snapshot_calls(&tip, 131);
        calls.push(ScriptedBackend::ok(
            "testmempoolaccept",
            json!([{
                "txid": transaction.txid(),
                "allowed": false,
                "reject-reason": "missing-inputs"
            }]),
        ));
        calls.extend(snapshot_calls(&tip, 131));
        let backend = ScriptedBackend::new(calls);

        let result = NodeGateway::with_backend(&backend)
            .test_mempool_accept(&transaction)
            .unwrap();

        assert!(!result.allowed);
        assert_eq!(result.reject_reason.as_deref(), Some("missing-inputs"));
        backend.assert_exhausted();
    }

    #[test]
    fn test_mempool_accept_rejects_empty_or_partial_results() {
        let tip = "f0".repeat(32);
        let transaction = empty_transaction();
        let mut calls = snapshot_calls(&tip, 132);
        calls.push(ScriptedBackend::ok("testmempoolaccept", json!([])));
        let backend = ScriptedBackend::new(calls);

        let error = NodeGateway::with_backend(&backend)
            .test_mempool_accept(&transaction)
            .unwrap_err();

        assert!(matches!(
            error,
            NodeGatewayError::UnexpectedResultCount {
                method: "testmempoolaccept",
                expected: 1,
                actual: 0
            }
        ));
        backend.assert_exhausted();
    }

    #[test]
    fn test_mempool_accept_rejects_a_txid_mismatch() {
        let tip = "f1".repeat(32);
        let transaction = empty_transaction();
        let other_txid = "f2".repeat(32);
        let mut calls = snapshot_calls(&tip, 133);
        calls.push(ScriptedBackend::ok(
            "testmempoolaccept",
            json!([{ "txid": other_txid, "allowed": true }]),
        ));
        let backend = ScriptedBackend::new(calls);

        let error = NodeGateway::with_backend(&backend)
            .test_mempool_accept(&transaction)
            .unwrap_err();

        assert!(matches!(
            error,
            NodeGatewayError::TransactionIdMismatch { .. }
        ));
        backend.assert_exhausted();
    }

    #[test]
    fn transaction_status_reports_a_confirmed_transaction() {
        let tip = "12".repeat(32);
        let block = "13".repeat(32);
        let txid = Txid::from_str(&"14".repeat(32)).unwrap();
        let mut calls = snapshot_calls(&tip, 140);
        calls.push(ScriptedBackend::ok(
            "getrawtransaction",
            json!({
                "txid": txid,
                "blockhash": block,
                "confirmations": 3,
                "in_active_chain": true
            }),
        ));
        calls.extend(snapshot_calls(&tip, 140));
        let backend = ScriptedBackend::new(calls);

        let observation = NodeGateway::with_backend(&backend)
            .transaction_status(txid)
            .unwrap();

        assert!(matches!(
            observation.status,
            TransactionStatus::Confirmed {
                confirmations: 3,
                block_hash
            } if block_hash.to_string() == block
        ));
        assert_eq!(observation.snapshot.tip.height, 140);
        backend.assert_exhausted();
    }

    #[test]
    fn transaction_status_reports_a_mempool_transaction() {
        let tip = "15".repeat(32);
        let txid = Txid::from_str(&"16".repeat(32)).unwrap();
        let mut calls = snapshot_calls(&tip, 141);
        calls.push(ScriptedBackend::ok(
            "getrawtransaction",
            json!({ "txid": txid, "confirmations": 0 }),
        ));
        calls.extend(snapshot_calls(&tip, 141));
        let backend = ScriptedBackend::new(calls);

        let observation = NodeGateway::with_backend(&backend)
            .transaction_status(txid)
            .unwrap();

        assert_eq!(observation.status, TransactionStatus::Mempool);
        backend.assert_exhausted();
    }

    #[test]
    fn transaction_status_reports_a_missing_transaction() {
        let tip = "17".repeat(32);
        let txid = Txid::from_str(&"18".repeat(32)).unwrap();
        let mut calls = snapshot_calls(&tip, 142);
        calls.push(ScriptedBackend::error(
            "getrawtransaction",
            -5,
            "No such mempool or blockchain transaction",
        ));
        calls.extend(snapshot_calls(&tip, 142));
        let backend = ScriptedBackend::new(calls);

        let observation = NodeGateway::with_backend(&backend)
            .transaction_status(txid)
            .unwrap();

        assert_eq!(observation.status, TransactionStatus::Missing);
        backend.assert_exhausted();
    }

    #[test]
    fn transaction_status_rejects_partial_node_data() {
        let tip = "19".repeat(32);
        let txid = Txid::from_str(&"1a".repeat(32)).unwrap();
        let mut calls = snapshot_calls(&tip, 143);
        calls.push(ScriptedBackend::ok(
            "getrawtransaction",
            json!({ "confirmations": 1 }),
        ));
        let backend = ScriptedBackend::new(calls);

        let error = NodeGateway::with_backend(&backend)
            .transaction_status(txid)
            .unwrap_err();

        assert!(matches!(
            error,
            NodeGatewayError::MalformedResponse {
                method: "getrawtransaction",
                ..
            }
        ));
        backend.assert_exhausted();
    }

    #[test]
    fn broadcast_transaction_preflights_and_returns_the_tip_identity() {
        let tip = "21".repeat(32);
        let transaction = empty_transaction();
        let mut calls = snapshot_calls(&tip, 150);
        calls.push(ScriptedBackend::ok(
            "testmempoolaccept",
            json!([{ "txid": transaction.txid(), "allowed": true }]),
        ));
        calls.extend(snapshot_calls(&tip, 150));
        calls.push(ScriptedBackend::ok(
            "sendrawtransaction",
            json!(transaction.txid()),
        ));
        calls.extend(snapshot_calls(&tip, 150));
        let backend = ScriptedBackend::new(calls);

        let receipt = NodeGateway::with_backend(&backend)
            .broadcast_transaction(&transaction, &expected_snapshot(&tip, 150))
            .unwrap();

        assert_eq!(receipt.txid, transaction.txid());
        assert_eq!(receipt.outcome, BroadcastOutcome::Submitted);
        assert_eq!(receipt.snapshot.id, snapshot_id(&tip, 150));
        backend.assert_exhausted();
    }

    #[test]
    fn broadcast_transaction_closes_on_mempool_rejection() {
        let tip = "22".repeat(32);
        let transaction = empty_transaction();
        let mut calls = snapshot_calls(&tip, 151);
        calls.push(ScriptedBackend::ok(
            "testmempoolaccept",
            json!([{
                "txid": transaction.txid(),
                "allowed": false,
                "reject-reason": "missing-inputs"
            }]),
        ));
        let backend = ScriptedBackend::new(calls);

        let error = NodeGateway::with_backend(&backend)
            .broadcast_transaction(&transaction, &expected_snapshot(&tip, 151))
            .unwrap_err();

        assert!(matches!(
            error,
            NodeGatewayError::MempoolRejected { ref reason, .. } if reason == "missing-inputs"
        ));
        backend.assert_exhausted();
    }

    #[test]
    fn broadcast_transaction_reports_an_already_known_transaction() {
        let tip = "23".repeat(32);
        let transaction = empty_transaction();
        let mut calls = snapshot_calls(&tip, 152);
        calls.push(ScriptedBackend::ok(
            "testmempoolaccept",
            json!([{ "txid": transaction.txid(), "allowed": true }]),
        ));
        calls.extend(snapshot_calls(&tip, 152));
        calls.push(ScriptedBackend::error(
            "sendrawtransaction",
            -27,
            "Transaction already in block chain",
        ));
        calls.extend(snapshot_calls(&tip, 152));
        let backend = ScriptedBackend::new(calls);

        let receipt = NodeGateway::with_backend(&backend)
            .broadcast_transaction(&transaction, &expected_snapshot(&tip, 152))
            .unwrap();

        assert_eq!(receipt.outcome, BroadcastOutcome::AlreadyKnown);
        backend.assert_exhausted();
    }

    #[test]
    fn broadcast_transaction_treats_mempool_already_known_as_idempotent_after_tip_recheck() {
        let tip = "28".repeat(32);
        let transaction = empty_transaction();
        let mut calls = snapshot_calls(&tip, 152);
        calls.push(ScriptedBackend::ok(
            "testmempoolaccept",
            json!([{
                "txid": transaction.txid(),
                "allowed": false,
                "reject-reason": "txn-already-in-mempool"
            }]),
        ));
        calls.extend(snapshot_calls(&tip, 152));
        let backend = ScriptedBackend::new(calls);

        let receipt = NodeGateway::with_backend(&backend)
            .broadcast_transaction(&transaction, &expected_snapshot(&tip, 152))
            .unwrap();

        assert_eq!(receipt.outcome, BroadcastOutcome::AlreadyKnown);
        assert_eq!(receipt.snapshot.id, snapshot_id(&tip, 152));
        backend.assert_exhausted();
    }

    #[test]
    fn broadcast_transaction_rechecks_the_tip_after_sendrawtransaction() {
        let first_tip = "29".repeat(32);
        let next_tip = "2c".repeat(32);
        let transaction = empty_transaction();
        let mut calls = snapshot_calls(&first_tip, 152);
        calls.push(ScriptedBackend::ok(
            "testmempoolaccept",
            json!([{ "txid": transaction.txid(), "allowed": true }]),
        ));
        calls.extend(snapshot_calls(&first_tip, 152));
        calls.push(ScriptedBackend::ok(
            "sendrawtransaction",
            json!(transaction.txid()),
        ));
        calls.extend(snapshot_calls(&next_tip, 153));
        let backend = ScriptedBackend::new(calls);

        let error = NodeGateway::with_backend(&backend)
            .broadcast_transaction(&transaction, &expected_snapshot(&first_tip, 152))
            .unwrap_err();

        assert!(matches!(error, NodeGatewayError::ChainTipChanged { .. }));
        backend.assert_exhausted();
    }

    #[test]
    fn broadcast_transaction_preserves_non_idempotent_rpc_errors() {
        let tip = "24".repeat(32);
        let transaction = empty_transaction();
        let mut calls = snapshot_calls(&tip, 153);
        calls.push(ScriptedBackend::ok(
            "testmempoolaccept",
            json!([{ "txid": transaction.txid(), "allowed": true }]),
        ));
        calls.extend(snapshot_calls(&tip, 153));
        calls.push(ScriptedBackend::error(
            "sendrawtransaction",
            -26,
            "mandatory-script-verify-flag-failed",
        ));
        let backend = ScriptedBackend::new(calls);

        let error = NodeGateway::with_backend(&backend)
            .broadcast_transaction(&transaction, &expected_snapshot(&tip, 153))
            .unwrap_err();

        assert!(matches!(
            error,
            NodeGatewayError::RpcCall {
                method: "sendrawtransaction",
                code: Some(-26),
                ..
            }
        ));
        backend.assert_exhausted();
    }

    #[test]
    fn broadcast_transaction_rejects_a_stale_expected_snapshot() {
        let current_tip = "25".repeat(32);
        let stale_tip = "26".repeat(32);
        let transaction = empty_transaction();
        let backend = ScriptedBackend::new(snapshot_calls(&current_tip, 154));

        let error = NodeGateway::with_backend(&backend)
            .broadcast_transaction(&transaction, &expected_snapshot(&stale_tip, 153))
            .unwrap_err();

        assert!(matches!(error, NodeGatewayError::StaleSnapshot { .. }));
        backend.assert_exhausted();
    }

    #[test]
    fn broadcast_transaction_rejects_an_expired_snapshot_even_when_tip_is_unchanged() {
        let tip = "27".repeat(32);
        let transaction = empty_transaction();
        let mut expected = expected_snapshot(&tip, 155);
        expected.observed_at = 1;
        let backend = ScriptedBackend::default();

        let error = NodeGateway::with_backend(&backend)
            .broadcast_transaction(&transaction, &expected)
            .unwrap_err();

        assert!(matches!(error, NodeGatewayError::ExpiredSnapshot { .. }));
        backend.assert_exhausted();
    }
}

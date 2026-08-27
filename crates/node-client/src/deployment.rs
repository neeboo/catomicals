//! Parsing of `getdeploymentinfo` for OP_CAT (BIP 347) activation status.

use serde_json::Value;

/// The deployment name Inquisition uses for BIP 347 OP_CAT
/// (see `src/binana/op_cat.json` -> `"deployment": "OP_CAT"`, lowered).
pub const OP_CAT_DEPLOYMENT_NAME: &str = "op_cat";

/// Status of a single deployment as reported by `getdeploymentinfo`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeploymentStatus {
    pub name: String,
    pub kind: String,
    pub active: bool,
    pub height: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeploymentError {
    #[error("getdeploymentinfo response has no `deployments` object")]
    NoDeployments,
    #[error("deployment `{0}` was not reported by the node")]
    NotReported(String),
    #[error("deployment `{0}` entry has unexpected shape")]
    Malformed(String),
}

/// Extract the deployment status for `name` from a raw `getdeploymentinfo`
/// response.
pub fn deployment_status(info: &Value, name: &str) -> Result<DeploymentStatus, DeploymentError> {
    let deployments = info
        .get("deployments")
        .and_then(Value::as_object)
        .ok_or(DeploymentError::NoDeployments)?;
    let entry = deployments
        .get(name)
        .ok_or_else(|| DeploymentError::NotReported(name.to_owned()))?;
    let kind = entry
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned();
    let active = entry
        .get("active")
        .and_then(Value::as_bool)
        .ok_or_else(|| DeploymentError::Malformed(name.to_owned()))?;
    let height = entry.get("height").and_then(Value::as_i64);
    Ok(DeploymentStatus {
        name: name.to_owned(),
        kind,
        active,
        height,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_active_heretical_op_cat() {
        let info = json!({
            "hash": "0x00",
            "height": 1234,
            "deployments": {
                "testdummy": { "type": "bip9", "active": false },
                "op_cat": { "type": "heretical", "active": true, "height": 0 }
            }
        });
        let dep = deployment_status(&info, OP_CAT_DEPLOYMENT_NAME).unwrap();
        assert_eq!(dep.name, "op_cat");
        assert_eq!(dep.kind, "heretical");
        assert!(dep.active);
        assert_eq!(dep.height, Some(0));
    }

    #[test]
    fn rejects_missing_deployment() {
        let info = json!({ "deployments": { "taproot": {} } });
        assert_eq!(
            deployment_status(&info, OP_CAT_DEPLOYMENT_NAME),
            Err(DeploymentError::NotReported("op_cat".into()))
        );
    }

    #[test]
    fn rejects_inactive_cat() {
        let info = json!({ "deployments": { "op_cat": { "type": "heretical", "active": false } } });
        let dep = deployment_status(&info, OP_CAT_DEPLOYMENT_NAME).unwrap();
        assert!(!dep.active);
    }
}

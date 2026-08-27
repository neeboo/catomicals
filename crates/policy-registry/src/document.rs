use serde::{Deserialize, Serialize};

use crate::{
    CompileError, INQUISITION_SIGNET_PROFILE, POLICY_CANONICALIZATION, POLICY_SCHEMA_VERSION,
    Result,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BitcoinNetwork {
    Signet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DigestAlgorithm {
    Sha256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OpCatRequirement {
    Required,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkProfile {
    pub bitcoin_network: BitcoinNetwork,
    pub deployment_profile: String,
    pub op_cat: OpCatRequirement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuccessorRuleInput {
    RecursiveIssuer,
    ShardedLanes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceInput {
    pub item_id: String,
    pub target_prefix: u8,
    pub total_supply: u32,
    pub successor_rule: SuccessorRuleInput,
    pub lane_count: u8,
    pub salt: String,
    pub metadata_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptInput {
    pub txid: String,
    pub vout: u32,
    pub script_pubkey_hex: String,
    pub item_sat_amount: u64,
    pub terms_hash: String,
    pub item_id: String,
    pub item_commitment: String,
    pub lane: u8,
    pub sequence: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListingInput {
    pub receipt: ReceiptInput,
    pub seller_key: String,
    pub seller_payout_script_hex: String,
    pub price_sat: u64,
    pub creator_fee_script_hex: String,
    pub creator_fee_sat: u64,
    pub cancel_script_hex: String,
    pub expiry_height: u32,
    pub max_network_fee_sat: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "policy_kind", deny_unknown_fields)]
pub enum PolicyDocument {
    #[serde(rename = "catomicals-issuance-v1")]
    Issuance {
        schema_version: u16,
        canonicalization: String,
        digest_algorithm: DigestAlgorithm,
        network: NetworkProfile,
        name: String,
        input: IssuanceInput,
    },
    #[serde(rename = "catomicals-fixed-price-listing-v1")]
    FixedPriceListing {
        schema_version: u16,
        canonicalization: String,
        digest_algorithm: DigestAlgorithm,
        network: NetworkProfile,
        name: String,
        input: ListingInput,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolInput<'a> {
    Issuance(&'a IssuanceInput),
    FixedPriceListing(&'a ListingInput),
}

impl PolicyDocument {
    pub fn schema_version(&self) -> u16 {
        match self {
            Self::Issuance { schema_version, .. }
            | Self::FixedPriceListing { schema_version, .. } => *schema_version,
        }
    }

    pub fn canonicalization(&self) -> &str {
        match self {
            Self::Issuance {
                canonicalization, ..
            }
            | Self::FixedPriceListing {
                canonicalization, ..
            } => canonicalization,
        }
    }

    pub fn network(&self) -> &NetworkProfile {
        match self {
            Self::Issuance { network, .. } | Self::FixedPriceListing { network, .. } => network,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Issuance { name, .. } | Self::FixedPriceListing { name, .. } => name,
        }
    }

    pub fn input(&self) -> ProtocolInput<'_> {
        match self {
            Self::Issuance { input, .. } => ProtocolInput::Issuance(input),
            Self::FixedPriceListing { input, .. } => ProtocolInput::FixedPriceListing(input),
        }
    }

    pub fn validate_profile(&self) -> Result<()> {
        if self.schema_version() != POLICY_SCHEMA_VERSION {
            return Err(CompileError::UnsupportedProfile(
                "schema_version must be 1".to_owned(),
            ));
        }
        if self.canonicalization() != POLICY_CANONICALIZATION {
            return Err(CompileError::UnsupportedProfile(
                "canonicalization must be catomicals-policy-jcs-v1".to_owned(),
            ));
        }
        if self.network().deployment_profile != INQUISITION_SIGNET_PROFILE {
            return Err(CompileError::UnsupportedProfile(format!(
                "deployment_profile must be {INQUISITION_SIGNET_PROFILE}"
            )));
        }
        if self.name().is_empty() || self.name().len() > 120 {
            return Err(CompileError::UnsupportedProfile(
                "name must contain 1..=120 bytes".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn invalid_issuance_supply(&self) -> Option<Self> {
        if !matches!(self, Self::Issuance { .. }) {
            return None;
        }
        let mut changed = self.clone();
        if let Self::Issuance { input, .. } = &mut changed {
            input.total_supply = 0;
        }
        Some(changed)
    }

    pub(crate) fn invalid_listing_price(&self) -> Option<Self> {
        if !matches!(self, Self::FixedPriceListing { .. }) {
            return None;
        }
        let mut changed = self.clone();
        if let Self::FixedPriceListing { input, .. } = &mut changed {
            input.price_sat = 0;
        }
        Some(changed)
    }

    pub(crate) fn renamed(&self, name: &str) -> Self {
        let mut changed = self.clone();
        match &mut changed {
            Self::Issuance { name: current, .. }
            | Self::FixedPriceListing { name: current, .. } => *current = name.to_owned(),
        }
        changed
    }
}

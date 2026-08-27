use std::str::FromStr;

use base64::Engine;
use bitcoin::consensus::encode::serialize;
use bitcoin::{OutPoint, ScriptBuf, Txid};
use catomicals_issuance::script::{issuer_output_key, issuer_script, parse_issuer_script};
use catomicals_issuance::state::IssuerState;
use catomicals_issuance::terms::{IssuanceTerms, SuccessorRule};
use catomicals_trading::{ItemReceipt, ListingArtifacts, ListingTerms, Network};
use serde::{Deserialize, Serialize};

use crate::{
    CompileError, IssuanceInput, ListingInput, MAX_ARTIFACT_SET_BYTES, MAX_BUNDLE_BYTES,
    MAX_POLICY_DOCUMENT_BYTES, MAX_VECTOR_SET_BYTES, POLICY_COMPILER_VERSION,
    POLICY_SCHEMA_VERSION, PolicyArtifact, PolicyDocument, PolicyTestVector, ProtocolInput, Result,
    SuccessorRuleInput, VectorInput, VectorResult, jcs, sha256_digest,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationRun {
    pub compiler_version: String,
    pub policy_hash: String,
    pub artifact_set_digest: String,
    pub vector_set_digest: String,
    pub results: Vec<VectorResult>,
    pub all_passed: bool,
    pub run_digest: String,
}

#[derive(Serialize)]
struct ValidationRunDigest<'a> {
    compiler_version: &'a str,
    policy_hash: &'a str,
    artifact_set_digest: &'a str,
    vector_set_digest: &'a str,
    results: &'a [VectorResult],
    all_passed: bool,
}

impl ValidationRun {
    fn new(
        policy_hash: &str,
        artifact_set_digest: &str,
        vector_set_digest: &str,
        results: Vec<VectorResult>,
    ) -> Result<Self> {
        let all_passed = results.iter().all(|result| result.passed);
        let compiler_version = POLICY_COMPILER_VERSION.to_owned();
        let run_digest = sha256_digest(&jcs(&ValidationRunDigest {
            compiler_version: &compiler_version,
            policy_hash,
            artifact_set_digest,
            vector_set_digest,
            results: &results,
            all_passed,
        })?);
        Ok(Self {
            compiler_version,
            policy_hash: policy_hash.to_owned(),
            artifact_set_digest: artifact_set_digest.to_owned(),
            vector_set_digest: vector_set_digest.to_owned(),
            results,
            all_passed,
            run_digest,
        })
    }

    fn validate(&self) -> Result<()> {
        let expected = Self::new(
            &self.policy_hash,
            &self.artifact_set_digest,
            &self.vector_set_digest,
            self.results.clone(),
        )?;
        if &expected != self || !self.all_passed {
            return Err(CompileError::ValidationRunMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBundle {
    pub schema_version: u16,
    pub compiler_version: String,
    pub document: PolicyDocument,
    pub policy_hash: String,
    pub artifacts: Vec<PolicyArtifact>,
    pub artifact_set_digest: String,
    pub test_vectors: Vec<PolicyTestVector>,
    pub vector_set_digest: String,
    pub validation_run: ValidationRun,
}

impl PolicyBundle {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        jcs(self)
    }
}

pub fn compile_policy_json(bytes: &[u8]) -> Result<PolicyBundle> {
    if bytes.len() > MAX_POLICY_DOCUMENT_BYTES {
        return Err(CompileError::LimitExceeded("policy document"));
    }
    let document: PolicyDocument = serde_json::from_slice(bytes)
        .map_err(|error| CompileError::InvalidJson(error.to_string()))?;
    compile_document(document)
}

fn compile_document(document: PolicyDocument) -> Result<PolicyBundle> {
    document.validate_profile()?;
    let policy_hash = policy_hash(&document)?;
    let artifacts = compile_artifacts(&document)?;
    let artifact_bytes = jcs(&artifacts)?;
    if artifact_bytes.len() > MAX_ARTIFACT_SET_BYTES {
        return Err(CompileError::LimitExceeded("artifact set"));
    }
    let artifact_set_digest = sha256_digest(&artifact_bytes);
    let test_vectors = vectors(&document, &policy_hash, &artifacts)?;
    let vector_bytes = jcs(&test_vectors)?;
    if vector_bytes.len() > MAX_VECTOR_SET_BYTES {
        return Err(CompileError::LimitExceeded("test vector set"));
    }
    let vector_set_digest = sha256_digest(&vector_bytes);
    let results = test_vectors.iter().map(run_vector).collect();
    let validation_run = ValidationRun::new(
        &policy_hash,
        &artifact_set_digest,
        &vector_set_digest,
        results,
    )?;
    if !validation_run.all_passed {
        return Err(CompileError::VectorMismatch);
    }
    Ok(PolicyBundle {
        schema_version: POLICY_SCHEMA_VERSION,
        compiler_version: POLICY_COMPILER_VERSION.to_owned(),
        document,
        policy_hash,
        artifacts,
        artifact_set_digest,
        test_vectors,
        vector_set_digest,
        validation_run,
    })
}

pub fn inspect_bundle(bytes: &[u8]) -> Result<PolicyBundle> {
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(CompileError::LimitExceeded("policy bundle"));
    }
    let bundle: PolicyBundle = serde_json::from_slice(bytes)
        .map_err(|error| CompileError::InvalidJson(error.to_string()))?;
    if jcs(&bundle)? != bytes {
        return Err(CompileError::NonCanonicalBundle);
    }
    bundle.document.validate_profile()?;
    if bundle.schema_version != POLICY_SCHEMA_VERSION
        || bundle.compiler_version != POLICY_COMPILER_VERSION
        || policy_hash(&bundle.document)? != bundle.policy_hash
    {
        return Err(CompileError::PolicyHashMismatch);
    }
    let artifact_bytes = jcs(&bundle.artifacts)?;
    if artifact_bytes.len() > MAX_ARTIFACT_SET_BYTES
        || sha256_digest(&artifact_bytes) != bundle.artifact_set_digest
    {
        return Err(CompileError::ArtifactSetMismatch);
    }
    for artifact in &bundle.artifacts {
        artifact.validate()?;
    }
    let vector_bytes = jcs(&bundle.test_vectors)?;
    if vector_bytes.len() > MAX_VECTOR_SET_BYTES
        || sha256_digest(&vector_bytes) != bundle.vector_set_digest
    {
        return Err(CompileError::VectorMismatch);
    }
    let results: Vec<_> = bundle.test_vectors.iter().map(run_vector).collect();
    if results != bundle.validation_run.results {
        return Err(CompileError::VectorMismatch);
    }
    bundle.validation_run.validate()?;
    if bundle.validation_run.policy_hash != bundle.policy_hash
        || bundle.validation_run.artifact_set_digest != bundle.artifact_set_digest
        || bundle.validation_run.vector_set_digest != bundle.vector_set_digest
    {
        return Err(CompileError::ValidationRunMismatch);
    }
    let expected = compile_document(bundle.document.clone())?;
    if expected.artifacts != bundle.artifacts
        || expected.artifact_set_digest != bundle.artifact_set_digest
    {
        return Err(CompileError::ArtifactMismatch);
    }
    if expected.test_vectors != bundle.test_vectors
        || expected.vector_set_digest != bundle.vector_set_digest
    {
        return Err(CompileError::VectorMismatch);
    }
    if expected.validation_run != bundle.validation_run {
        return Err(CompileError::ValidationRunMismatch);
    }
    Ok(bundle)
}

fn policy_hash(document: &PolicyDocument) -> Result<String> {
    Ok(sha256_digest(&jcs(document)?))
}

fn compile_artifacts(document: &PolicyDocument) -> Result<Vec<PolicyArtifact>> {
    match document.input() {
        ProtocolInput::Issuance(input) => compile_issuance(input),
        ProtocolInput::FixedPriceListing(input) => compile_listing(input),
    }
}

fn compile_issuance(input: &IssuanceInput) -> Result<Vec<PolicyArtifact>> {
    let terms = issuance_terms(input)?;
    let mut artifacts = Vec::with_capacity(usize::from(terms.materialized_lanes()) * 4);
    for lane in 0..terms.materialized_lanes() {
        let state = IssuerState::initial(&terms, lane)
            .map_err(|error| CompileError::InvalidIssuance(error.to_string()))?;
        let script = issuer_script(&state);
        if parse_issuer_script(&script) != Some(state) {
            return Err(CompileError::InvalidIssuance(
                "issuer script does not round-trip".to_owned(),
            ));
        }
        artifacts.push(PolicyArtifact::new(
            "issuance_terms",
            Some(lane),
            "application/vnd.catomicals.issuance-terms-v1",
            terms.canonical_bytes(),
        )?);
        artifacts.push(PolicyArtifact::new(
            "issuer_state",
            Some(lane),
            "application/jcs+json",
            jcs(&state)?,
        )?);
        artifacts.push(PolicyArtifact::new(
            "issuer_tapscript",
            Some(lane),
            "application/vnd.bitcoin.tapscript",
            script,
        )?);
        artifacts.push(PolicyArtifact::new(
            "issuer_output_key",
            Some(lane),
            "application/vnd.bitcoin.x-only-public-key",
            issuer_output_key(&state).serialize().to_vec(),
        )?);
    }
    Ok(artifacts)
}

fn issuance_terms(input: &IssuanceInput) -> Result<IssuanceTerms> {
    let item_id = hex32(&input.item_id, CompileError::InvalidIssuance)?;
    let salt = hex32(&input.salt, CompileError::InvalidIssuance)?;
    let metadata = base64::engine::general_purpose::STANDARD
        .decode(&input.metadata_base64)
        .map_err(|error| CompileError::InvalidIssuance(error.to_string()))?;
    if metadata.len() > crate::MAX_METADATA_BYTES {
        return Err(CompileError::InvalidIssuance(format!(
            "metadata exceeds {} bytes",
            crate::MAX_METADATA_BYTES
        )));
    }
    if input.total_supply == 0 {
        return Err(CompileError::InvalidIssuance(
            "total_supply must be greater than zero".to_owned(),
        ));
    }
    if input.target_prefix > 32 {
        return Err(CompileError::InvalidIssuance(
            "target_prefix must be at most 32".to_owned(),
        ));
    }
    let successor_rule = match input.successor_rule {
        SuccessorRuleInput::RecursiveIssuer if input.lane_count == 1 => {
            SuccessorRule::RecursiveIssuer
        }
        SuccessorRuleInput::ShardedLanes
            if input.lane_count >= 2 && u32::from(input.lane_count) <= input.total_supply =>
        {
            SuccessorRule::ShardedLanes
        }
        SuccessorRuleInput::RecursiveIssuer => {
            return Err(CompileError::InvalidIssuance(
                "recursive issuer requires lane_count=1".to_owned(),
            ));
        }
        SuccessorRuleInput::ShardedLanes => {
            return Err(CompileError::InvalidIssuance(
                "sharded lanes require 2..=total_supply lanes".to_owned(),
            ));
        }
    };
    Ok(IssuanceTerms {
        item_id,
        target_prefix: input.target_prefix,
        total_supply: input.total_supply,
        successor_rule,
        lane_count: input.lane_count,
        salt,
        metadata,
    })
}

fn compile_listing(input: &ListingInput) -> Result<Vec<PolicyArtifact>> {
    let listing = listing_terms(input)?;
    let outputs = ListingArtifacts::new(&listing)
        .map_err(|error| CompileError::InvalidListing(error.to_string()))?;
    Ok(vec![
        PolicyArtifact::new(
            "listing_terms",
            None,
            "application/vnd.catomicals.fixed-price-listing-v1",
            outputs.canonical_bytes,
        )?,
        PolicyArtifact::new(
            "listing_commitment",
            None,
            "application/vnd.catomicals.sha256-commitment",
            outputs.commitment.to_vec(),
        )?,
        PolicyArtifact::new(
            "buy_leaf",
            None,
            "application/vnd.bitcoin.tapscript",
            outputs.buy_leaf.into_bytes(),
        )?,
        PolicyArtifact::new(
            "cancel_leaf",
            None,
            "application/vnd.bitcoin.tapscript",
            outputs.cancel_leaf.into_bytes(),
        )?,
        PolicyArtifact::new(
            "listing_output",
            None,
            "application/vnd.bitcoin.script-pubkey",
            outputs.listing_output.into_bytes(),
        )?,
        PolicyArtifact::new(
            "order_txout",
            None,
            "application/vnd.bitcoin.consensus-txout",
            serialize(&outputs.order_txout),
        )?,
    ])
}

fn listing_terms(input: &ListingInput) -> Result<ListingTerms> {
    let txid = Txid::from_str(&input.receipt.txid)
        .map_err(|error| CompileError::InvalidListing(error.to_string()))?;
    let seller_key = bitcoin::XOnlyPublicKey::from_str(&input.seller_key)
        .map_err(|error| CompileError::InvalidListing(error.to_string()))?;
    let script = |encoded: &str| -> Result<ScriptBuf> {
        hex::decode(encoded)
            .map(ScriptBuf::from_bytes)
            .map_err(|error| CompileError::InvalidListing(error.to_string()))
    };
    let listing = ListingTerms {
        protocol_version: 1,
        network: Network::Signet,
        receipt: ItemReceipt {
            network: Network::Signet,
            outpoint: OutPoint::new(txid, input.receipt.vout),
            script_pubkey: script(&input.receipt.script_pubkey_hex)?,
            item_sat_amount: input.receipt.item_sat_amount,
            terms_hash: hex32(&input.receipt.terms_hash, CompileError::InvalidListing)?,
            item_id: hex32(&input.receipt.item_id, CompileError::InvalidListing)?,
            item_commitment: hex32(&input.receipt.item_commitment, CompileError::InvalidListing)?,
            lane: input.receipt.lane,
            sequence: input.receipt.sequence,
        },
        seller_key,
        seller_payout_script: script(&input.seller_payout_script_hex)?,
        price_sat: input.price_sat,
        creator_fee_script: script(&input.creator_fee_script_hex)?,
        creator_fee_sat: input.creator_fee_sat,
        cancel_script: script(&input.cancel_script_hex)?,
        expiry_height: input.expiry_height,
        max_network_fee_sat: input.max_network_fee_sat,
    };
    listing
        .validate()
        .map_err(|error| CompileError::InvalidListing(error.to_string()))?;
    Ok(listing)
}

fn vectors(
    document: &PolicyDocument,
    policy_hash: &str,
    artifacts: &[PolicyArtifact],
) -> Result<Vec<PolicyTestVector>> {
    let mut tampered_artifact = artifacts
        .first()
        .cloned()
        .ok_or(CompileError::ArtifactMismatch)?;
    if let Some(last) = tampered_artifact.content_hex.pop() {
        tampered_artifact
            .content_hex
            .push(if last == '0' { '1' } else { '0' });
    }
    let mut vectors = vec![
        PolicyTestVector {
            vector_id: "positive.compile".to_owned(),
            input: VectorInput::CompileDocument {
                document: document.clone(),
            },
            expected_accept: true,
        },
        PolicyTestVector {
            vector_id: "negative.document_tamper".to_owned(),
            input: VectorInput::VerifyPolicyHash {
                document: document.renamed(&format!("{} tampered", document.name())),
                claimed_policy_hash: policy_hash.to_owned(),
            },
            expected_accept: false,
        },
        PolicyTestVector {
            vector_id: "negative.artifact_tamper".to_owned(),
            input: VectorInput::VerifyArtifact {
                artifact: tampered_artifact,
            },
            expected_accept: false,
        },
    ];
    if let Some(invalid) = document.invalid_issuance_supply() {
        vectors.push(PolicyTestVector {
            vector_id: "negative.zero_supply".to_owned(),
            input: VectorInput::CompileDocument { document: invalid },
            expected_accept: false,
        });
    }
    if let Some(invalid) = document.invalid_listing_price() {
        vectors.push(PolicyTestVector {
            vector_id: "negative.zero_price".to_owned(),
            input: VectorInput::CompileDocument { document: invalid },
            expected_accept: false,
        });
    }
    Ok(vectors)
}

fn run_vector(vector: &PolicyTestVector) -> VectorResult {
    let actual_accept = match &vector.input {
        VectorInput::CompileDocument { document } => {
            document.validate_profile().is_ok() && compile_artifacts(document).is_ok()
        }
        VectorInput::VerifyPolicyHash {
            document,
            claimed_policy_hash,
        } => policy_hash(document)
            .map(|actual| actual == *claimed_policy_hash)
            .unwrap_or(false),
        VectorInput::VerifyArtifact { artifact } => artifact.validate().is_ok(),
    };
    VectorResult {
        vector_id: vector.vector_id.clone(),
        expected_accept: vector.expected_accept,
        actual_accept,
        passed: actual_accept == vector.expected_accept,
    }
}

fn hex32(encoded: &str, error: fn(String) -> CompileError) -> Result<[u8; 32]> {
    let bytes = hex::decode(encoded).map_err(|source| error(source.to_string()))?;
    let value = bytes
        .try_into()
        .map_err(|_| error("expected exactly 32 bytes of lowercase hex".to_owned()))?;
    if encoded.len() == 64
        && encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(value)
    } else {
        Err(error(
            "expected exactly 32 bytes of lowercase hex".to_owned(),
        ))
    }
}

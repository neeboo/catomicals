//! Consensus signature assemblers for the wallet's threshold ECDSA chains.

use catomicals_cb_mpc_signer::CanonicalEcdsaSignature;
use catomicals_chain_bitcoin_cash::{
    BitcoinCashSigningRequest, assemble_ecdsa_transaction_signature,
};
use catomicals_chain_bsv::assemble_reviewed_cb_mpc_signature;
use catomicals_chain_domain::{ChainId, ChainNetwork};
use catomicals_chain_kaspa::assemble_reviewed_cb_mpc_ecdsa_signature;
use catomicals_signing_domain::{SignerBackendRequirement, SigningSuiteId};

use crate::{CbMpcConsensusSignatureAssembler, SigningJob};

#[derive(Debug, Default, Clone, Copy)]
pub struct BitcoinCashCbMpcSignatureAssembler;

impl CbMpcConsensusSignatureAssembler for BitcoinCashCbMpcSignatureAssembler {
    fn assemble(
        &self,
        job: &SigningJob,
        signature: &CanonicalEcdsaSignature,
    ) -> Result<Vec<u8>, String> {
        require_chain_job(
            job,
            ChainId::BitcoinCash,
            SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1,
        )?;
        if !matches!(job.chain_scope.network, ChainNetwork::BitcoinCash(_)) {
            return Err("Bitcoin Cash job has a foreign network scope".to_owned());
        }
        let request = BitcoinCashSigningRequest::decode(&job.review.reviewed_material)
            .map_err(|error| error.to_string())?;
        assemble_ecdsa_transaction_signature(signature.der(), request.hash_type)
            .map_err(|error| error.to_string())
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct BsvCbMpcSignatureAssembler;

impl CbMpcConsensusSignatureAssembler for BsvCbMpcSignatureAssembler {
    fn assemble(
        &self,
        job: &SigningJob,
        signature: &CanonicalEcdsaSignature,
    ) -> Result<Vec<u8>, String> {
        require_chain_job(job, ChainId::Bsv, SigningSuiteId::BSV_ECDSA_CB_MPC_V1)?;
        if !matches!(job.chain_scope.network, ChainNetwork::Bsv(_)) {
            return Err("BSV job has a foreign network scope".to_owned());
        }
        assemble_reviewed_cb_mpc_signature(&job.review.reviewed_material, signature.der())
            .map_err(|error| error.to_string())
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct KaspaCbMpcSignatureAssembler;

impl CbMpcConsensusSignatureAssembler for KaspaCbMpcSignatureAssembler {
    fn assemble(
        &self,
        job: &SigningJob,
        signature: &CanonicalEcdsaSignature,
    ) -> Result<Vec<u8>, String> {
        require_chain_job(job, ChainId::Kaspa, SigningSuiteId::KASPA_ECDSA_CB_MPC_V1)?;
        if !matches!(job.chain_scope.network, ChainNetwork::Kaspa(_)) {
            return Err("Kaspa job has a foreign network scope".to_owned());
        }
        assemble_reviewed_cb_mpc_ecdsa_signature(&job.review.reviewed_material, signature.der())
            .map_err(|error| error.to_string())
    }
}

fn require_chain_job(
    job: &SigningJob,
    expected_chain: ChainId,
    expected_suite: SigningSuiteId,
) -> Result<(), String> {
    if job.chain_scope.chain != expected_chain
        || job.chain_scope.network.chain_id() != expected_chain
        || job.signing_suite_id != expected_suite
        || job.backend_requirement != SignerBackendRequirement::CbMpcThresholdEcdsa
    {
        return Err("signing job does not match the CB-MPC chain assembler".to_owned());
    }
    Ok(())
}

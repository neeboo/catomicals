use std::time::{SystemTime, UNIX_EPOCH};

use catomicals_policy_registry::{ActivationProposal, inspect_bundle};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::sqlite::{append_audit, ensure_mutations_allowed, metadata_in};
use crate::{ActivationStatus, PolicyStoreOutcome, Result, StorageError, WalletStorage};

impl WalletStorage {
    /// Store a fully inspected deterministic bundle in one immediate
    /// transaction. A repeated policy hash is idempotent only when the entire
    /// canonical bundle is byte-identical.
    pub fn store_policy_bundle_bytes(
        &mut self,
        policy_hash: &str,
        canonical_bundle: &[u8],
        now: i64,
    ) -> Result<PolicyStoreOutcome> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        let existing = tx
            .query_row(
                "SELECT canonical_bundle FROM policy_documents WHERE policy_hash = ?1",
                [policy_hash],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            return if existing == canonical_bundle {
                Ok(PolicyStoreOutcome::AlreadyPresent)
            } else {
                Err(StorageError::ImmutableConflict("policy_documents"))
            };
        }

        let bundle = inspect_bundle(canonical_bundle)
            .map_err(|error| StorageError::InvalidStoredValue(error.to_string()))?;
        if bundle.policy_hash != policy_hash {
            return Err(StorageError::InvalidStoredValue(
                "claimed policy hash does not match bundle".to_owned(),
            ));
        }
        let canonical_document = serde_jcs::to_vec(&bundle.document)
            .map_err(|error| StorageError::InvalidStoredValue(error.to_string()))?;
        tx.execute(
            "INSERT INTO policy_documents
             (policy_hash, wallet_id, wallet_epoch, schema_version, canonical_document,
              canonical_bundle, artifact_set_digest, vector_set_digest,
              validation_run_digest, compiler_version, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                bundle.policy_hash,
                metadata.wallet_id.to_string(),
                metadata.epoch,
                bundle.schema_version,
                canonical_document,
                canonical_bundle,
                bundle.artifact_set_digest,
                bundle.vector_set_digest,
                bundle.validation_run.run_digest,
                bundle.compiler_version,
                now,
            ],
        )?;

        {
            let mut insert = tx.prepare_cached(
                "INSERT INTO policy_artifacts
                 (policy_hash, artifact_id, wallet_id, wallet_epoch, kind, lane,
                  media_type, content, content_digest, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            )?;
            for artifact in &bundle.artifacts {
                let content = artifact
                    .validate()
                    .map_err(|error| StorageError::InvalidStoredValue(error.to_string()))?;
                insert.execute(params![
                    bundle.policy_hash,
                    artifact.artifact_id,
                    metadata.wallet_id.to_string(),
                    metadata.epoch,
                    artifact.kind,
                    artifact.lane,
                    artifact.media_type,
                    content,
                    artifact.content_digest,
                    now,
                ])?;
            }
        }
        {
            let mut insert = tx.prepare_cached(
                "INSERT INTO policy_test_vectors
                 (policy_hash, vector_id, wallet_id, wallet_epoch, input_jcs,
                  input_digest, expected_accept, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            for vector in &bundle.test_vectors {
                let input_jcs = serde_jcs::to_vec(&vector.input)
                    .map_err(|error| StorageError::InvalidStoredValue(error.to_string()))?;
                let input_digest = sha256_digest(&input_jcs);
                insert.execute(params![
                    bundle.policy_hash,
                    vector.vector_id,
                    metadata.wallet_id.to_string(),
                    metadata.epoch,
                    input_jcs,
                    input_digest,
                    vector.expected_accept,
                    now,
                ])?;
            }
        }
        let results_jcs = serde_jcs::to_vec(&bundle.validation_run.results)
            .map_err(|error| StorageError::InvalidStoredValue(error.to_string()))?;
        tx.execute(
            "INSERT INTO policy_validation_runs
             (run_digest, policy_hash, wallet_id, wallet_epoch, compiler_version,
              artifact_set_digest, vector_set_digest, results_jcs, all_passed, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                bundle.validation_run.run_digest,
                bundle.policy_hash,
                metadata.wallet_id.to_string(),
                metadata.epoch,
                bundle.validation_run.compiler_version,
                bundle.validation_run.artifact_set_digest,
                bundle.validation_run.vector_set_digest,
                results_jcs,
                bundle.validation_run.all_passed,
                now,
            ],
        )?;
        append_audit(
            &tx,
            &metadata,
            "policy.bundle_stored",
            Some(bundle.policy_hash),
            now,
        )?;
        tx.commit()?;
        Ok(PolicyStoreOutcome::Inserted)
    }

    pub fn policy_bundle_bytes(&self, policy_hash: &str) -> Result<Option<Vec<u8>>> {
        self.connection
            .query_row(
                "SELECT canonical_bundle FROM policy_documents WHERE policy_hash = ?1",
                [policy_hash],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    /// Persist only a pending activation proposal. There is intentionally no
    /// storage API in this slice that can promote a binding or activation to
    /// active.
    pub fn propose_policy_activation(&mut self, proposal: &ActivationProposal) -> Result<()> {
        proposal
            .verify()
            .map_err(|_| StorageError::InvalidPolicyActivation)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        if metadata.wallet_id != proposal.wallet_id || metadata.epoch != proposal.wallet_epoch {
            return Err(StorageError::StaleEpoch {
                current: metadata.epoch,
                provided: proposal.wallet_epoch,
            });
        }
        let validated = tx
            .query_row(
                "SELECT d.artifact_set_digest, d.validation_run_digest, r.all_passed
                 FROM policy_documents d
                 JOIN policy_validation_runs r ON r.run_digest = d.validation_run_digest
                 WHERE d.policy_hash = ?1 AND d.wallet_id = ?2 AND d.wallet_epoch = ?3",
                params![
                    proposal.policy_hash,
                    proposal.wallet_id.to_string(),
                    proposal.wallet_epoch,
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, bool>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((artifact_set_digest, validation_run_digest, all_passed)) = validated else {
            return Err(StorageError::PolicyNotValidated);
        };
        if !all_passed
            || artifact_set_digest != proposal.artifact_set_digest
            || validation_run_digest != proposal.validation_run_digest
        {
            return Err(StorageError::PolicyNotValidated);
        }
        tx.execute(
            "INSERT INTO policy_bindings
             (binding_id, policy_hash, wallet_id, wallet_epoch, signer_set_id,
              signer_epoch, chain_profile, artifact_set_digest,
              validation_run_digest, binding_state, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'pending_activation', ?10)",
            params![
                proposal.binding_id.to_string(),
                proposal.policy_hash,
                proposal.wallet_id.to_string(),
                proposal.wallet_epoch,
                proposal.signer_set_id.to_string(),
                proposal.signer_epoch,
                proposal.chain_profile,
                proposal.artifact_set_digest,
                proposal.validation_run_digest,
                proposal.created_at,
            ],
        )?;
        tx.execute(
            "INSERT INTO policy_activations
             (activation_id, binding_id, policy_hash, wallet_id, wallet_epoch,
              signer_set_id, signer_epoch, chain_profile, artifact_set_digest,
              validation_run_digest, approval_digest, activation_state,
              expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'pending', ?12, ?13)",
            params![
                proposal.activation_id.to_string(),
                proposal.binding_id.to_string(),
                proposal.policy_hash,
                proposal.wallet_id.to_string(),
                proposal.wallet_epoch,
                proposal.signer_set_id.to_string(),
                proposal.signer_epoch,
                proposal.chain_profile,
                proposal.artifact_set_digest,
                proposal.validation_run_digest,
                proposal.approval_digest,
                proposal.expires_at,
                proposal.created_at,
            ],
        )?;
        append_audit(
            &tx,
            &metadata,
            "policy.activation_proposed",
            Some(proposal.activation_id.to_string()),
            proposal.created_at,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn policy_activation_status(
        &self,
        activation_id: Uuid,
    ) -> Result<Option<ActivationStatus>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(i64::MAX);
        self.policy_activation_status_at(activation_id, now)
    }

    pub fn policy_activation_status_at(
        &self,
        activation_id: Uuid,
        now: i64,
    ) -> Result<Option<ActivationStatus>> {
        self.connection
            .query_row(
                "SELECT activation.wallet_epoch, activation.expires_at, metadata.epoch
                 FROM policy_activations activation
                 JOIN wallet_metadata metadata ON metadata.wallet_id = activation.wallet_id
                 WHERE activation.activation_id = ?1",
                [activation_id.to_string()],
                |row| {
                    let activation_epoch = row.get::<_, u64>(0)?;
                    let expires_at = row.get::<_, i64>(1)?;
                    let current_epoch = row.get::<_, u64>(2)?;
                    Ok(if activation_epoch != current_epoch {
                        ActivationStatus::InvalidatedByRecovery
                    } else if now >= expires_at {
                        ActivationStatus::Expired
                    } else {
                        ActivationStatus::Pending
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn policy_binding_usable_for_signing(&self, binding_id: Uuid) -> Result<bool> {
        let binding = self
            .connection
            .query_row(
                "SELECT binding.binding_state, binding.wallet_epoch, metadata.epoch
                 FROM policy_bindings binding
                 JOIN wallet_metadata metadata ON metadata.wallet_id = binding.wallet_id
                 WHERE binding.binding_id = ?1",
                [binding_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, u64>(2)?,
                    ))
                },
            )
            .optional()?;
        Ok(binding
            .map(|(state, binding_epoch, current_epoch)| {
                state == "active" && binding_epoch == current_epoch
            })
            .unwrap_or(false))
    }
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

CREATE TABLE signer_profiles (
    profile_id TEXT PRIMARY KEY CHECK (length(profile_id) = 36),
    wallet_id TEXT NOT NULL REFERENCES wallet_metadata(wallet_id),
    chain_scope_json TEXT NOT NULL CHECK (json_valid(chain_scope_json)),
    signing_suite_id TEXT NOT NULL,
    backend_requirement TEXT NOT NULL,
    signer_set_id TEXT NOT NULL CHECK (length(signer_set_id) BETWEEN 1 AND 128),
    authorization_signer_id TEXT NOT NULL CHECK (length(authorization_signer_id) BETWEEN 1 AND 128),
    signer_epoch INTEGER NOT NULL CHECK (signer_epoch > 0),
    threshold INTEGER NOT NULL CHECK (threshold > 0),
    max_signers INTEGER NOT NULL CHECK (max_signers >= threshold),
    verification_key BLOB NOT NULL CHECK (length(verification_key) BETWEEN 1 AND 256),
    secret_ref_id TEXT NOT NULL REFERENCES secret_refs(id),
    created_at INTEGER NOT NULL,
    UNIQUE (wallet_id, chain_scope_json, signing_suite_id, signer_set_id, signer_epoch)
) STRICT, WITHOUT ROWID;

CREATE TABLE signer_address_bindings (
    binding_id TEXT PRIMARY KEY CHECK (length(binding_id) = 36),
    profile_id TEXT NOT NULL REFERENCES signer_profiles(profile_id),
    chain_scope_json TEXT NOT NULL CHECK (json_valid(chain_scope_json)),
    address TEXT NOT NULL CHECK (length(address) BETWEEN 1 AND 512),
    verification_key_digest BLOB NOT NULL CHECK (length(verification_key_digest) = 32),
    created_at INTEGER NOT NULL,
    UNIQUE (profile_id, address)
) STRICT, WITHOUT ROWID;

CREATE TABLE signing_jobs (
    job_id TEXT PRIMARY KEY CHECK (length(job_id) = 36),
    wallet_id TEXT NOT NULL REFERENCES wallet_metadata(wallet_id),
    profile_id TEXT NOT NULL REFERENCES signer_profiles(profile_id),
    intent_id TEXT NOT NULL REFERENCES transaction_intents(id),
    chain_scope_json TEXT NOT NULL CHECK (json_valid(chain_scope_json)),
    signing_suite_id TEXT NOT NULL,
    backend_requirement TEXT NOT NULL,
    review_schema_version INTEGER NOT NULL CHECK (review_schema_version > 0),
    review_artifact_json TEXT NOT NULL CHECK (json_valid(review_artifact_json)),
    review_digest BLOB NOT NULL CHECK (length(review_digest) = 32),
    signing_message_digest BLOB NOT NULL CHECK (length(signing_message_digest) = 32),
    policy_snapshot_digest BLOB NOT NULL CHECK (length(policy_snapshot_digest) = 32),
    chain_snapshot_digest BLOB NOT NULL CHECK (length(chain_snapshot_digest) = 32),
    session_id BLOB NOT NULL UNIQUE CHECK (length(session_id) = 32),
    selected_parties_json TEXT NOT NULL CHECK (json_valid(selected_parties_json)),
    receiver TEXT NOT NULL CHECK (length(receiver) BETWEEN 1 AND 64),
    operation_binding_digest BLOB CHECK (operation_binding_digest IS NULL OR length(operation_binding_digest) = 32),
    status TEXT NOT NULL CHECK (status IN ('prepared', 'signing', 'finalized', 'aborted', 'expired', 'failed')),
    final_signature BLOB CHECK (final_signature IS NULL OR length(final_signature) BETWEEN 1 AND 4096),
    terminal_reason TEXT CHECK (terminal_reason IS NULL OR length(terminal_reason) BETWEEN 1 AND 128),
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    CHECK (expires_at > created_at),
    CHECK (
        (status = 'prepared' AND operation_binding_digest IS NULL AND final_signature IS NULL AND terminal_reason IS NULL)
        OR (status = 'signing' AND operation_binding_digest IS NOT NULL AND final_signature IS NULL AND terminal_reason IS NULL)
        OR (status = 'finalized' AND operation_binding_digest IS NOT NULL AND final_signature IS NOT NULL AND terminal_reason IS NULL)
        OR (status IN ('aborted', 'expired', 'failed') AND final_signature IS NULL AND terminal_reason IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

-- A signing job is durable authority state, while this ledger is the
-- one-time boundary immediately before provider I/O. Its unique session and
-- immutable binding prevent a restarted wallet from contacting signers twice
-- for the same authorized operation.
CREATE TABLE chain_executor_claims (
    job_id TEXT PRIMARY KEY REFERENCES signing_jobs(job_id),
    wallet_id TEXT NOT NULL REFERENCES wallet_metadata(wallet_id),
    profile_id TEXT NOT NULL REFERENCES signer_profiles(profile_id),
    signing_suite_id TEXT NOT NULL,
    backend_requirement TEXT NOT NULL,
    session_id BLOB NOT NULL UNIQUE CHECK (length(session_id) = 32),
    review_domain_digest BLOB NOT NULL CHECK (length(review_domain_digest) = 32),
    signing_message_digest BLOB NOT NULL CHECK (length(signing_message_digest) = 32),
    operation_binding_digest BLOB NOT NULL CHECK (length(operation_binding_digest) = 32),
    claimed_at INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE INDEX signer_profiles_wallet_scope
ON signer_profiles(wallet_id, chain_scope_json, signing_suite_id);

CREATE INDEX signer_address_bindings_profile
ON signer_address_bindings(profile_id, created_at);

CREATE INDEX signing_jobs_recovery
ON signing_jobs(wallet_id, profile_id, status, updated_at);

CREATE INDEX chain_executor_claims_profile
ON chain_executor_claims(wallet_id, profile_id, claimed_at);

CREATE TRIGGER signer_profiles_no_update
BEFORE UPDATE ON signer_profiles BEGIN
    SELECT RAISE(ABORT, 'signer profiles are immutable; rotate to a new profile');
END;

CREATE TRIGGER signer_profiles_no_delete
BEFORE DELETE ON signer_profiles BEGIN
    SELECT RAISE(ABORT, 'signer profiles are retained for audit');
END;

CREATE TRIGGER signer_address_bindings_no_update
BEFORE UPDATE ON signer_address_bindings BEGIN
    SELECT RAISE(ABORT, 'signer address bindings are immutable');
END;

CREATE TRIGGER signer_address_bindings_no_delete
BEFORE DELETE ON signer_address_bindings BEGIN
    SELECT RAISE(ABORT, 'signer address bindings are retained for audit');
END;

CREATE TRIGGER signing_jobs_binding_immutable
BEFORE UPDATE ON signing_jobs
WHEN OLD.wallet_id != NEW.wallet_id
  OR OLD.profile_id != NEW.profile_id
  OR OLD.intent_id != NEW.intent_id
  OR OLD.chain_scope_json != NEW.chain_scope_json
  OR OLD.signing_suite_id != NEW.signing_suite_id
  OR OLD.backend_requirement != NEW.backend_requirement
  OR OLD.review_schema_version != NEW.review_schema_version
  OR OLD.review_artifact_json != NEW.review_artifact_json
  OR OLD.review_digest != NEW.review_digest
  OR OLD.signing_message_digest != NEW.signing_message_digest
  OR OLD.policy_snapshot_digest != NEW.policy_snapshot_digest
  OR OLD.chain_snapshot_digest != NEW.chain_snapshot_digest
  OR OLD.session_id != NEW.session_id
  OR OLD.selected_parties_json != NEW.selected_parties_json
  OR OLD.receiver != NEW.receiver
  OR OLD.operation_binding_digest IS NOT NEW.operation_binding_digest
  OR OLD.expires_at != NEW.expires_at
  OR OLD.created_at != NEW.created_at
BEGIN
    SELECT RAISE(ABORT, 'signing job binding is immutable');
END;

CREATE TRIGGER signing_jobs_no_delete
BEFORE DELETE ON signing_jobs BEGIN
    SELECT RAISE(ABORT, 'signing jobs are retained for audit');
END;

CREATE TRIGGER chain_executor_claims_no_update
BEFORE UPDATE ON chain_executor_claims BEGIN
    SELECT RAISE(ABORT, 'chain executor claims are immutable');
END;

CREATE TRIGGER chain_executor_claims_no_delete
BEFORE DELETE ON chain_executor_claims BEGIN
    SELECT RAISE(ABORT, 'chain executor claims are retained for audit');
END;

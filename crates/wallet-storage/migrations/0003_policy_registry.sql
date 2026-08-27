CREATE TABLE policy_documents (
    policy_hash TEXT PRIMARY KEY CHECK (
        length(policy_hash) = 71
        AND substr(policy_hash, 1, 7) = 'sha256:'
        AND substr(policy_hash, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    wallet_id TEXT NOT NULL REFERENCES wallet_metadata(wallet_id),
    wallet_epoch INTEGER NOT NULL CHECK (wallet_epoch > 0),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    canonical_document BLOB NOT NULL CHECK (length(canonical_document) > 0),
    canonical_bundle BLOB NOT NULL CHECK (length(canonical_bundle) > 0),
    artifact_set_digest TEXT NOT NULL CHECK (length(artifact_set_digest) = 71),
    vector_set_digest TEXT NOT NULL CHECK (length(vector_set_digest) = 71),
    validation_run_digest TEXT NOT NULL CHECK (length(validation_run_digest) = 71),
    compiler_version TEXT NOT NULL CHECK (length(compiler_version) > 0),
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE policy_artifacts (
    policy_hash TEXT NOT NULL REFERENCES policy_documents(policy_hash),
    artifact_id TEXT NOT NULL,
    wallet_id TEXT NOT NULL REFERENCES wallet_metadata(wallet_id),
    wallet_epoch INTEGER NOT NULL CHECK (wallet_epoch > 0),
    kind TEXT NOT NULL CHECK (length(kind) > 0),
    lane INTEGER,
    media_type TEXT NOT NULL CHECK (length(media_type) > 0),
    content BLOB NOT NULL,
    content_digest TEXT NOT NULL CHECK (length(content_digest) = 71),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (policy_hash, artifact_id)
) STRICT;

CREATE TABLE policy_test_vectors (
    policy_hash TEXT NOT NULL REFERENCES policy_documents(policy_hash),
    vector_id TEXT NOT NULL,
    wallet_id TEXT NOT NULL REFERENCES wallet_metadata(wallet_id),
    wallet_epoch INTEGER NOT NULL CHECK (wallet_epoch > 0),
    input_jcs BLOB NOT NULL CHECK (length(input_jcs) > 0),
    input_digest TEXT NOT NULL CHECK (length(input_digest) = 71),
    expected_accept INTEGER NOT NULL CHECK (expected_accept IN (0, 1)),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (policy_hash, vector_id)
) STRICT;

CREATE TABLE policy_validation_runs (
    run_digest TEXT PRIMARY KEY CHECK (length(run_digest) = 71),
    policy_hash TEXT NOT NULL REFERENCES policy_documents(policy_hash),
    wallet_id TEXT NOT NULL REFERENCES wallet_metadata(wallet_id),
    wallet_epoch INTEGER NOT NULL CHECK (wallet_epoch > 0),
    compiler_version TEXT NOT NULL CHECK (length(compiler_version) > 0),
    artifact_set_digest TEXT NOT NULL CHECK (length(artifact_set_digest) = 71),
    vector_set_digest TEXT NOT NULL CHECK (length(vector_set_digest) = 71),
    results_jcs BLOB NOT NULL CHECK (length(results_jcs) > 0),
    all_passed INTEGER NOT NULL CHECK (all_passed = 1),
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE policy_bindings (
    binding_id TEXT PRIMARY KEY,
    policy_hash TEXT NOT NULL REFERENCES policy_documents(policy_hash),
    wallet_id TEXT NOT NULL REFERENCES wallet_metadata(wallet_id),
    wallet_epoch INTEGER NOT NULL CHECK (wallet_epoch > 0),
    signer_set_id TEXT NOT NULL,
    signer_epoch INTEGER NOT NULL CHECK (signer_epoch > 0),
    chain_profile TEXT NOT NULL CHECK (chain_profile = 'bitcoin-inquisition-signet-v29.4-op-cat'),
    artifact_set_digest TEXT NOT NULL CHECK (length(artifact_set_digest) = 71),
    validation_run_digest TEXT NOT NULL REFERENCES policy_validation_runs(run_digest),
    binding_state TEXT NOT NULL CHECK (binding_state = 'pending_activation'),
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE policy_activations (
    activation_id TEXT PRIMARY KEY,
    binding_id TEXT NOT NULL UNIQUE REFERENCES policy_bindings(binding_id),
    policy_hash TEXT NOT NULL REFERENCES policy_documents(policy_hash),
    wallet_id TEXT NOT NULL REFERENCES wallet_metadata(wallet_id),
    wallet_epoch INTEGER NOT NULL CHECK (wallet_epoch > 0),
    signer_set_id TEXT NOT NULL,
    signer_epoch INTEGER NOT NULL CHECK (signer_epoch > 0),
    chain_profile TEXT NOT NULL CHECK (chain_profile = 'bitcoin-inquisition-signet-v29.4-op-cat'),
    artifact_set_digest TEXT NOT NULL CHECK (length(artifact_set_digest) = 71),
    validation_run_digest TEXT NOT NULL REFERENCES policy_validation_runs(run_digest),
    approval_digest TEXT NOT NULL UNIQUE CHECK (length(approval_digest) = 71),
    activation_state TEXT NOT NULL CHECK (activation_state = 'pending'),
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL CHECK (expires_at > created_at)
) STRICT;

CREATE INDEX policy_documents_wallet_epoch
ON policy_documents(wallet_id, wallet_epoch, created_at);

CREATE INDEX policy_artifacts_policy
ON policy_artifacts(policy_hash, artifact_id);

CREATE INDEX policy_test_vectors_policy
ON policy_test_vectors(policy_hash, vector_id);

CREATE INDEX policy_validation_runs_policy
ON policy_validation_runs(policy_hash, all_passed, created_at);

CREATE INDEX policy_bindings_wallet_epoch
ON policy_bindings(wallet_id, wallet_epoch, policy_hash, signer_set_id, signer_epoch);

CREATE INDEX policy_activations_wallet_epoch_state_expiry
ON policy_activations(wallet_id, wallet_epoch, activation_state, expires_at);

CREATE TRIGGER policy_documents_no_update BEFORE UPDATE ON policy_documents
BEGIN SELECT RAISE(ABORT, 'policy documents are immutable'); END;
CREATE TRIGGER policy_documents_no_delete BEFORE DELETE ON policy_documents
BEGIN SELECT RAISE(ABORT, 'policy documents are append-only'); END;
CREATE TRIGGER policy_artifacts_no_update BEFORE UPDATE ON policy_artifacts
BEGIN SELECT RAISE(ABORT, 'policy artifacts are immutable'); END;
CREATE TRIGGER policy_artifacts_no_delete BEFORE DELETE ON policy_artifacts
BEGIN SELECT RAISE(ABORT, 'policy artifacts are append-only'); END;
CREATE TRIGGER policy_test_vectors_no_update BEFORE UPDATE ON policy_test_vectors
BEGIN SELECT RAISE(ABORT, 'policy test vectors are immutable'); END;
CREATE TRIGGER policy_test_vectors_no_delete BEFORE DELETE ON policy_test_vectors
BEGIN SELECT RAISE(ABORT, 'policy test vectors are append-only'); END;
CREATE TRIGGER policy_validation_runs_no_update BEFORE UPDATE ON policy_validation_runs
BEGIN SELECT RAISE(ABORT, 'policy validation runs are immutable'); END;
CREATE TRIGGER policy_validation_runs_no_delete BEFORE DELETE ON policy_validation_runs
BEGIN SELECT RAISE(ABORT, 'policy validation runs are append-only'); END;
CREATE TRIGGER policy_bindings_no_update BEFORE UPDATE ON policy_bindings
BEGIN SELECT RAISE(ABORT, 'policy bindings are immutable'); END;
CREATE TRIGGER policy_bindings_no_delete BEFORE DELETE ON policy_bindings
BEGIN SELECT RAISE(ABORT, 'policy bindings are append-only'); END;
CREATE TRIGGER policy_activations_no_update BEFORE UPDATE ON policy_activations
BEGIN SELECT RAISE(ABORT, 'policy activations are immutable'); END;
CREATE TRIGGER policy_activations_no_delete BEFORE DELETE ON policy_activations
BEGIN SELECT RAISE(ABORT, 'policy activations are append-only'); END;

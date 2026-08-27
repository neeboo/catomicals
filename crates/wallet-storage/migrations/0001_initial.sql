CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY CHECK (version > 0),
    checksum TEXT NOT NULL CHECK (length(checksum) = 64)
) STRICT;

CREATE TABLE wallet_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    wallet_id TEXT NOT NULL UNIQUE,
    epoch INTEGER NOT NULL CHECK (epoch > 0),
    restore_state TEXT NOT NULL CHECK (
        restore_state IN ('normal', 'snapshotting', 'restore_precheck', 'cutover', 'recovering')
    ),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE transaction_intents (
    id TEXT PRIMARY KEY,
    wallet_id TEXT NOT NULL REFERENCES wallet_metadata(wallet_id),
    epoch INTEGER NOT NULL CHECK (epoch > 0),
    tx_digest BLOB NOT NULL CHECK (length(tx_digest) = 32),
    policy_hash BLOB NOT NULL CHECK (length(policy_hash) = 32),
    session_id BLOB NOT NULL CHECK (length(session_id) = 32),
    status TEXT NOT NULL CHECK (
        status IN ('pending', 'approved', 'signing', 'signed', 'cancelled', 'expired', 'invalidated')
    ),
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE credential_metadata (
    credential_id TEXT PRIMARY KEY,
    wallet_id TEXT NOT NULL REFERENCES wallet_metadata(wallet_id),
    label TEXT NOT NULL,
    cose_public_key TEXT NOT NULL,
    sign_count INTEGER NOT NULL CHECK (sign_count >= 0),
    enrolled_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE approval_ceremonies (
    id TEXT PRIMARY KEY,
    wallet_id TEXT NOT NULL REFERENCES wallet_metadata(wallet_id),
    intent_id TEXT NOT NULL REFERENCES transaction_intents(id),
    epoch INTEGER NOT NULL CHECK (epoch > 0),
    started_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > started_at),
    completed_at INTEGER,
    invalidated_at INTEGER
) STRICT;

CREATE TABLE one_time_authorizations (
    id TEXT PRIMARY KEY,
    wallet_id TEXT NOT NULL REFERENCES wallet_metadata(wallet_id),
    intent_id TEXT NOT NULL REFERENCES transaction_intents(id),
    epoch INTEGER NOT NULL CHECK (epoch > 0),
    binding_digest BLOB NOT NULL CHECK (length(binding_digest) = 32),
    expires_at INTEGER NOT NULL,
    issued_at INTEGER NOT NULL,
    consumed_at INTEGER,
    invalidated_at INTEGER
) STRICT;

CREATE TABLE nonce_claims (
    fingerprint BLOB PRIMARY KEY CHECK (length(fingerprint) = 32),
    wallet_id TEXT NOT NULL REFERENCES wallet_metadata(wallet_id),
    epoch INTEGER NOT NULL CHECK (epoch > 0),
    session_id BLOB NOT NULL CHECK (length(session_id) = 32),
    claimed_at INTEGER NOT NULL,
    invalidated_at INTEGER
) STRICT;

CREATE TABLE secret_refs (
    id TEXT PRIMARY KEY,
    wallet_id TEXT NOT NULL REFERENCES wallet_metadata(wallet_id),
    backend TEXT NOT NULL CHECK (backend IN ('os_keychain', 'hsm', 'encrypted_file')),
    handle TEXT NOT NULL CHECK (
        (backend = 'os_keychain' AND substr(handle, 1, 11) = 'keychain://' AND length(handle) > 11)
        OR (backend = 'hsm' AND substr(handle, 1, 6) = 'hsm://' AND length(handle) > 6)
        OR (
            backend = 'encrypted_file'
            AND substr(handle, 1, 17) = 'encrypted-file://'
            AND length(handle) > 17
        )
    ),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    wallet_id TEXT NOT NULL REFERENCES wallet_metadata(wallet_id),
    epoch INTEGER NOT NULL CHECK (epoch > 0),
    event_type TEXT NOT NULL,
    subject_id TEXT,
    payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
    created_at INTEGER NOT NULL
) STRICT;

CREATE UNIQUE INDEX one_authorization_per_intent
ON one_time_authorizations(intent_id);

CREATE INDEX transaction_intents_epoch_status
ON transaction_intents(epoch, status);

CREATE INDEX approval_ceremonies_intent_epoch
ON approval_ceremonies(intent_id, epoch);

CREATE INDEX approval_ceremonies_epoch_completion
ON approval_ceremonies(epoch, completed_at, invalidated_at);

CREATE INDEX authorizations_intent_epoch
ON one_time_authorizations(intent_id, epoch);

CREATE INDEX authorizations_epoch_availability
ON one_time_authorizations(epoch, consumed_at, invalidated_at, expires_at);

CREATE INDEX nonce_claims_epoch_invalidation
ON nonce_claims(epoch, invalidated_at);

CREATE INDEX audit_events_wallet_epoch
ON audit_events(wallet_id, epoch, sequence);

CREATE INDEX credential_metadata_wallet
ON credential_metadata(wallet_id);

CREATE INDEX secret_refs_wallet
ON secret_refs(wallet_id);

CREATE TRIGGER audit_events_no_update
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are append-only');
END;

CREATE TRIGGER audit_events_no_delete
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are append-only');
END;

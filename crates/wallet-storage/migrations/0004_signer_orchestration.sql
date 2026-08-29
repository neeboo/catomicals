CREATE TABLE signer_request_nonces (
    wallet_id TEXT NOT NULL REFERENCES wallet_metadata(wallet_id),
    signer_set_id TEXT NOT NULL CHECK (length(signer_set_id) = 36),
    signer_epoch INTEGER NOT NULL CHECK (signer_epoch > 0),
    signer_id INTEGER NOT NULL CHECK (signer_id > 0 AND signer_id <= 65535),
    device_id TEXT NOT NULL CHECK (length(device_id) = 36),
    device_generation INTEGER NOT NULL CHECK (device_generation > 0),
    request_nonce BLOB NOT NULL CHECK (length(request_nonce) = 32),
    operation_id TEXT NOT NULL CHECK (length(operation_id) = 36),
    intent_id TEXT NOT NULL CHECK (length(intent_id) = 36),
    session_id BLOB NOT NULL CHECK (length(session_id) = 32),
    taproot_sighash BLOB NOT NULL CHECK (length(taproot_sighash) = 32),
    policy_digest BLOB NOT NULL CHECK (length(policy_digest) = 32),
    operation_binding_digest BLOB NOT NULL CHECK (length(operation_binding_digest) = 32),
    claimed_at INTEGER NOT NULL,
    PRIMARY KEY (
        wallet_id, signer_set_id, signer_epoch, signer_id,
        device_id, device_generation, request_nonce
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE signer_device_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    wallet_id TEXT NOT NULL REFERENCES wallet_metadata(wallet_id),
    signer_set_id TEXT NOT NULL CHECK (length(signer_set_id) = 36),
    signer_epoch INTEGER NOT NULL CHECK (signer_epoch > 0),
    signer_id INTEGER NOT NULL CHECK (signer_id > 0 AND signer_id <= 65535),
    device_id TEXT NOT NULL CHECK (length(device_id) = 36),
    device_generation INTEGER NOT NULL CHECK (device_generation > 0),
    provider TEXT NOT NULL CHECK (provider IN ('remote_mtls', 'hsm_adapter')),
    identity_public_key BLOB NOT NULL CHECK (length(identity_public_key) = 32),
    mtls_spki_sha256 BLOB CHECK (
        mtls_spki_sha256 IS NULL OR length(mtls_spki_sha256) = 32
    ),
    event_type TEXT NOT NULL CHECK (event_type IN ('registered', 'rotated', 'revoked')),
    occurred_at INTEGER NOT NULL,
    UNIQUE (wallet_id, signer_set_id, signer_epoch, signer_id, device_generation, event_type),
    CHECK (
        (event_type = 'registered' AND device_generation = 1)
        OR (event_type = 'rotated' AND device_generation > 1)
        OR event_type = 'revoked'
    )
) STRICT;

CREATE INDEX signer_request_nonces_operation
ON signer_request_nonces(wallet_id, signer_set_id, signer_epoch, operation_id, signer_id);

CREATE INDEX signer_device_events_latest
ON signer_device_events(wallet_id, signer_set_id, signer_epoch, signer_id, sequence DESC);

CREATE TRIGGER signer_request_nonces_no_update
BEFORE UPDATE ON signer_request_nonces
BEGIN
    SELECT RAISE(ABORT, 'signer request nonce claims are append-only');
END;

CREATE TRIGGER signer_request_nonces_no_delete
BEFORE DELETE ON signer_request_nonces
BEGIN
    SELECT RAISE(ABORT, 'signer request nonce claims are append-only');
END;

CREATE TRIGGER signer_request_nonces_operation_binding
BEFORE INSERT ON signer_request_nonces
WHEN EXISTS (
    SELECT 1 FROM signer_request_nonces prior
    WHERE prior.wallet_id = NEW.wallet_id
      AND prior.signer_set_id = NEW.signer_set_id
      AND prior.signer_epoch = NEW.signer_epoch
      AND prior.signer_id = NEW.signer_id
      AND prior.operation_id = NEW.operation_id
      AND prior.operation_binding_digest != NEW.operation_binding_digest
)
BEGIN
    SELECT RAISE(ABORT, 'signer operation binding drift');
END;

CREATE TRIGGER signer_device_events_no_update
BEFORE UPDATE ON signer_device_events
BEGIN
    SELECT RAISE(ABORT, 'signer device events are append-only');
END;

CREATE TRIGGER signer_device_events_no_delete
BEFORE DELETE ON signer_device_events
BEGIN
    SELECT RAISE(ABORT, 'signer device events are append-only');
END;

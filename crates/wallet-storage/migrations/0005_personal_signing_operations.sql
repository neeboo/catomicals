CREATE TABLE personal_signing_operations (
    operation_id TEXT PRIMARY KEY CHECK (length(operation_id) = 36),
    wallet_id TEXT NOT NULL REFERENCES wallet_metadata(wallet_id),
    profile_id TEXT NOT NULL CHECK (length(profile_id) = 36),
    signer_set_id TEXT NOT NULL CHECK (length(signer_set_id) = 36),
    signer_epoch INTEGER NOT NULL CHECK (signer_epoch > 0),
    intent_id TEXT NOT NULL CHECK (length(intent_id) = 36),
    session_id BLOB NOT NULL CHECK (length(session_id) = 32),
    taproot_sighash BLOB NOT NULL CHECK (length(taproot_sighash) = 32),
    policy_digest BLOB NOT NULL CHECK (length(policy_digest) = 32),
    chain_snapshot_digest BLOB NOT NULL CHECK (length(chain_snapshot_digest) = 32),
    group_pubkey_xonly BLOB NOT NULL CHECK (length(group_pubkey_xonly) = 32),
    profile_binding_digest BLOB NOT NULL CHECK (length(profile_binding_digest) = 32),
    operation_binding_digest BLOB NOT NULL CHECK (length(operation_binding_digest) = 32),
    allowed_participants BLOB NOT NULL CHECK (length(allowed_participants) = 6),
    selected_participants BLOB NOT NULL CHECK (length(selected_participants) = 4),
    threshold INTEGER NOT NULL CHECK (threshold = 2),
    max_signers INTEGER NOT NULL CHECK (max_signers = 3),
    status TEXT NOT NULL CHECK (status IN (
        'collecting_commitments', 'collecting_shares', 'finalized',
        'aborted', 'expired', 'failed'
    )),
    signing_package BLOB CHECK (
        signing_package IS NULL OR (length(signing_package) > 0 AND length(signing_package) <= 16384)
    ),
    final_signature BLOB CHECK (final_signature IS NULL OR length(final_signature) = 64),
    terminal_reason TEXT CHECK (terminal_reason IS NULL OR length(terminal_reason) BETWEEN 1 AND 64),
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    CHECK (expires_at > created_at),
    CHECK (
        (status = 'collecting_commitments' AND signing_package IS NULL AND final_signature IS NULL AND terminal_reason IS NULL)
        OR (status = 'collecting_shares' AND signing_package IS NOT NULL AND final_signature IS NULL AND terminal_reason IS NULL)
        OR (status = 'finalized' AND signing_package IS NOT NULL AND final_signature IS NOT NULL AND terminal_reason IS NULL)
        OR (status IN ('aborted', 'expired', 'failed') AND final_signature IS NULL AND terminal_reason IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE personal_signing_receipts (
    operation_id TEXT NOT NULL REFERENCES personal_signing_operations(operation_id),
    signer_id INTEGER NOT NULL CHECK (signer_id > 0 AND signer_id <= 3),
    round TEXT NOT NULL CHECK (round IN ('commitment', 'signature_share')),
    device_id TEXT NOT NULL CHECK (length(device_id) = 36),
    device_generation INTEGER NOT NULL CHECK (device_generation > 0),
    request_binding_digest BLOB NOT NULL CHECK (length(request_binding_digest) = 32),
    payload BLOB NOT NULL CHECK (length(payload) > 0 AND length(payload) <= 16384),
    received_at INTEGER NOT NULL,
    PRIMARY KEY (operation_id, signer_id, round)
) STRICT, WITHOUT ROWID;

CREATE INDEX personal_signing_operations_recovery
ON personal_signing_operations(wallet_id, signer_set_id, signer_epoch, status, updated_at);

CREATE TRIGGER personal_signing_operations_binding_immutable
BEFORE UPDATE ON personal_signing_operations
WHEN OLD.wallet_id != NEW.wallet_id
  OR OLD.profile_id != NEW.profile_id
  OR OLD.signer_set_id != NEW.signer_set_id
  OR OLD.signer_epoch != NEW.signer_epoch
  OR OLD.intent_id != NEW.intent_id
  OR OLD.session_id != NEW.session_id
  OR OLD.taproot_sighash != NEW.taproot_sighash
  OR OLD.policy_digest != NEW.policy_digest
  OR OLD.chain_snapshot_digest != NEW.chain_snapshot_digest
  OR OLD.group_pubkey_xonly != NEW.group_pubkey_xonly
  OR OLD.profile_binding_digest != NEW.profile_binding_digest
  OR OLD.operation_binding_digest != NEW.operation_binding_digest
  OR OLD.allowed_participants != NEW.allowed_participants
  OR OLD.selected_participants != NEW.selected_participants
  OR OLD.threshold != NEW.threshold
  OR OLD.max_signers != NEW.max_signers
  OR OLD.expires_at != NEW.expires_at
  OR OLD.created_at != NEW.created_at
BEGIN
    SELECT RAISE(ABORT, 'personal signing operation binding is immutable');
END;

CREATE TRIGGER personal_signing_operations_no_delete
BEFORE DELETE ON personal_signing_operations
BEGIN
    SELECT RAISE(ABORT, 'personal signing operations are retained for audit');
END;

CREATE TRIGGER personal_signing_receipts_no_update
BEFORE UPDATE ON personal_signing_receipts
BEGIN
    SELECT RAISE(ABORT, 'personal signing receipts are append-only');
END;

CREATE TRIGGER personal_signing_receipts_no_delete
BEFORE DELETE ON personal_signing_receipts
BEGIN
    SELECT RAISE(ABORT, 'personal signing receipts are append-only');
END;

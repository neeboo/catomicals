ALTER TABLE transaction_intents ADD COLUMN network TEXT;
ALTER TABLE transaction_intents ADD COLUMN protocol_version INTEGER;
ALTER TABLE transaction_intents ADD COLUMN action TEXT;
ALTER TABLE transaction_intents ADD COLUMN signer_id TEXT;
ALTER TABLE transaction_intents ADD COLUMN approval_nonce BLOB;
ALTER TABLE transaction_intents ADD COLUMN intent_schema_version INTEGER;

ALTER TABLE credential_metadata ADD COLUMN passkey_json TEXT;
ALTER TABLE credential_metadata ADD COLUMN passkey_format TEXT;
ALTER TABLE credential_metadata ADD COLUMN credential_record_version INTEGER;
ALTER TABLE credential_metadata ADD COLUMN credential_state TEXT;

ALTER TABLE approval_ceremonies ADD COLUMN binding_digest BLOB;
ALTER TABLE approval_ceremonies ADD COLUMN credential_id TEXT;

ALTER TABLE nonce_claims ADD COLUMN authorization_id TEXT;
ALTER TABLE nonce_claims ADD COLUMN intent_id TEXT;
ALTER TABLE nonce_claims ADD COLUMN signer_id TEXT;

UPDATE transaction_intents
SET status = 'invalidated', updated_at = MAX(updated_at, CAST(strftime('%s', 'now') AS INTEGER))
WHERE status IN ('pending', 'approved', 'signing');

UPDATE credential_metadata SET credential_state = 'legacy_unusable';

UPDATE approval_ceremonies
SET invalidated_at = COALESCE(invalidated_at, CAST(strftime('%s', 'now') AS INTEGER))
WHERE completed_at IS NULL;

CREATE TABLE webauthn_profiles (
    wallet_id TEXT PRIMARY KEY REFERENCES wallet_metadata(wallet_id),
    user_id TEXT NOT NULL CHECK (length(user_id) > 0),
    rp_id TEXT NOT NULL CHECK (length(rp_id) > 0),
    rp_origin TEXT NOT NULL CHECK (length(rp_origin) > 0),
    record_version INTEGER NOT NULL CHECK (record_version > 0),
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE intent_materials (
    intent_id TEXT NOT NULL REFERENCES transaction_intents(id),
    kind TEXT NOT NULL CHECK (kind IN ('unsigned_transaction', 'policy_input', 'node_snapshot')),
    payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
    payload_hash BLOB NOT NULL CHECK (length(payload_hash) = 32),
    node_snapshot_id TEXT NOT NULL CHECK (length(node_snapshot_id) > 0),
    PRIMARY KEY (intent_id, kind)
) STRICT;

CREATE UNIQUE INDEX transaction_intents_v2_approval_nonce
ON transaction_intents(wallet_id, approval_nonce)
WHERE intent_schema_version = 2 AND approval_nonce IS NOT NULL;

CREATE INDEX transaction_intents_v2_status_page
ON transaction_intents(wallet_id, epoch, status, created_at, id)
WHERE intent_schema_version = 2;

CREATE INDEX transaction_intents_v2_latest
ON transaction_intents(wallet_id, epoch, created_at DESC, id DESC)
WHERE intent_schema_version = 2;

CREATE INDEX intent_materials_intent_kind
ON intent_materials(intent_id, kind);

CREATE INDEX authorizations_v2_available
ON one_time_authorizations(wallet_id, epoch, intent_id, consumed_at, invalidated_at, expires_at);

CREATE INDEX nonce_claims_v2_binding
ON nonce_claims(wallet_id, epoch, intent_id, authorization_id, signer_id);

CREATE TRIGGER transaction_intents_v2_required
BEFORE INSERT ON transaction_intents
WHEN NEW.intent_schema_version = 2 AND (
    NEW.network IS NULL OR NEW.network NOT IN ('mainnet', 'testnet', 'signet', 'regtest')
    OR NEW.protocol_version IS NULL OR NEW.protocol_version <= 0
    OR NEW.action IS NULL OR NEW.action NOT IN ('issue', 'mint', 'transfer', 'swap', 'spend')
    OR NEW.signer_id IS NULL OR length(NEW.signer_id) = 0
    OR NEW.approval_nonce IS NULL OR length(NEW.approval_nonce) != 32
)
BEGIN
    SELECT RAISE(ABORT, 'v2 intent security fields are required');
END;

CREATE TRIGGER transaction_intents_v2_required_update
BEFORE UPDATE ON transaction_intents
WHEN NEW.intent_schema_version = 2 AND (
    NEW.network IS NULL OR NEW.network NOT IN ('mainnet', 'testnet', 'signet', 'regtest')
    OR NEW.protocol_version IS NULL OR NEW.protocol_version <= 0
    OR NEW.action IS NULL OR NEW.action NOT IN ('issue', 'mint', 'transfer', 'swap', 'spend')
    OR NEW.signer_id IS NULL OR length(NEW.signer_id) = 0
    OR NEW.approval_nonce IS NULL OR length(NEW.approval_nonce) != 32
)
BEGIN
    SELECT RAISE(ABORT, 'v2 intent security fields are required');
END;

CREATE TRIGGER transaction_intents_v2_immutable
BEFORE UPDATE OF id, wallet_id, epoch, tx_digest, policy_hash, session_id, expires_at,
                 created_at, network, protocol_version, action, signer_id, approval_nonce,
                 intent_schema_version
ON transaction_intents
WHEN OLD.intent_schema_version = 2
BEGIN
    SELECT RAISE(ABORT, 'v2 intent security fields are immutable');
END;

CREATE TRIGGER credential_metadata_v2_required_insert
BEFORE INSERT ON credential_metadata
WHEN NEW.credential_state = 'active' AND (
    NEW.passkey_json IS NULL OR NOT json_valid(NEW.passkey_json)
    OR NEW.passkey_format IS NULL OR length(NEW.passkey_format) = 0
    OR NEW.credential_record_version IS NULL OR NEW.credential_record_version <= 0
)
BEGIN
    SELECT RAISE(ABORT, 'active passkey record is incomplete');
END;

CREATE TRIGGER credential_metadata_v2_required_update
BEFORE UPDATE ON credential_metadata
WHEN NEW.credential_state = 'active' AND (
    NEW.passkey_json IS NULL OR NOT json_valid(NEW.passkey_json)
    OR NEW.passkey_format IS NULL OR length(NEW.passkey_format) = 0
    OR NEW.credential_record_version IS NULL OR NEW.credential_record_version <= 0
)
BEGIN
    SELECT RAISE(ABORT, 'active passkey record is incomplete');
END;

CREATE TRIGGER approval_ceremonies_v2_required
BEFORE INSERT ON approval_ceremonies
WHEN (SELECT intent_schema_version FROM transaction_intents WHERE id = NEW.intent_id) = 2
     AND (NEW.binding_digest IS NULL OR length(NEW.binding_digest) != 32
          OR NEW.credential_id IS NULL OR length(NEW.credential_id) = 0)
BEGIN
    SELECT RAISE(ABORT, 'passkey approval binding is required');
END;

CREATE TRIGGER nonce_claims_v2_binding_required
BEFORE INSERT ON nonce_claims
WHEN (NEW.authorization_id IS NOT NULL OR NEW.intent_id IS NOT NULL OR NEW.signer_id IS NOT NULL)
     AND (
         NEW.authorization_id IS NULL
         OR NEW.intent_id IS NULL
         OR NEW.signer_id IS NULL
         OR length(NEW.signer_id) = 0
         OR NOT EXISTS (
             SELECT 1 FROM one_time_authorizations authorization
             WHERE authorization.id = NEW.authorization_id
               AND authorization.wallet_id = NEW.wallet_id
               AND authorization.epoch = NEW.epoch
               AND authorization.intent_id = NEW.intent_id
         )
         OR NOT EXISTS (
             SELECT 1 FROM transaction_intents intent
             WHERE intent.id = NEW.intent_id
               AND intent.wallet_id = NEW.wallet_id
               AND intent.epoch = NEW.epoch
               AND intent.intent_schema_version = 2
               AND intent.signer_id = NEW.signer_id
               AND intent.session_id = NEW.session_id
         )
     )
BEGIN
    SELECT RAISE(ABORT, 'v2 nonce claim binding is incomplete or inconsistent');
END;

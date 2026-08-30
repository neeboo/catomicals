CREATE TRIGGER approval_ceremonies_v2_binding_immutable
BEFORE UPDATE OF intent_id, binding_digest, credential_id
ON approval_ceremonies
WHEN (
    (SELECT intent_schema_version FROM transaction_intents WHERE id = OLD.intent_id) = 2
    OR (SELECT intent_schema_version FROM transaction_intents WHERE id = NEW.intent_id) = 2
)
AND (
    OLD.intent_id IS NOT NEW.intent_id
    OR OLD.binding_digest IS NOT NEW.binding_digest
    OR OLD.credential_id IS NOT NEW.credential_id
)
BEGIN
    SELECT RAISE(ABORT, 'v2 approval binding is immutable');
END;

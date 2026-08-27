use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::{Result, StorageError};

pub const CURRENT_SCHEMA_VERSION: i32 = 3;
const MIGRATIONS: &[(i32, &str)] = &[
    (1, include_str!("../migrations/0001_initial.sql")),
    (
        2,
        include_str!("../migrations/0002_wallet_core_integration.sql"),
    ),
    (3, include_str!("../migrations/0003_policy_registry.sql")),
];

pub(crate) fn migrate(connection: &mut Connection) -> Result<()> {
    let found = connection.pragma_query_value(None, "user_version", |row| row.get::<_, i32>(0))?;
    if found > CURRENT_SCHEMA_VERSION {
        return Err(StorageError::SchemaTooNew {
            found,
            supported: CURRENT_SCHEMA_VERSION,
        });
    }
    if found > 0 {
        validate_migration_checksums(connection, found)?;
    }
    for (version, script) in MIGRATIONS
        .iter()
        .copied()
        .filter(|(version, _)| *version > found)
    {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(script)?;
        tx.execute(
            "INSERT INTO schema_migrations(version, checksum) VALUES (?1, ?2)",
            params![version, migration_checksum(script)],
        )?;
        tx.pragma_update(None, "user_version", version)?;
        tx.commit()?;
    }
    validate_migration_checksums(connection, CURRENT_SCHEMA_VERSION)?;
    validate_live_schema(connection)
}

pub(crate) fn validate_existing(connection: &Connection) -> Result<()> {
    let found = connection.pragma_query_value(None, "user_version", |row| row.get::<_, i32>(0))?;
    if found != CURRENT_SCHEMA_VERSION {
        return Err(StorageError::SchemaIntegrity {
            reason: "backup schema version does not match the current schema",
        });
    }
    validate_migration_checksums(connection, found)?;
    validate_live_schema(connection)
}

fn migration_checksum(script: &str) -> String {
    // Git may materialize text files with CRLF on Windows or on developer
    // machines configured with `core.autocrlf=true`. Migration identity must
    // follow the repository content, not checkout-specific line endings, or a
    // database created from an LF checkout cannot be opened from a CRLF one.
    let canonical = script.replace("\r\n", "\n");
    hex::encode(Sha256::digest(canonical.as_bytes()))
}

fn validate_migration_checksums(connection: &Connection, applied_version: i32) -> Result<()> {
    if object_sql(connection, "table", "schema_migrations")?.is_none() {
        return Err(StorageError::SchemaIntegrity {
            reason: "migration ledger missing",
        });
    }
    let ledger_rows =
        connection.query_row("SELECT count(*) FROM schema_migrations", [], |row| {
            row.get::<_, u64>(0)
        })?;
    if ledger_rows != applied_version as u64 {
        return Err(StorageError::SchemaIntegrity {
            reason: "migration ledger has unexpected entries",
        });
    }
    for (version, script) in MIGRATIONS.iter().take(applied_version as usize) {
        let stored = connection
            .query_row(
                "SELECT checksum FROM schema_migrations WHERE version = ?1",
                [version],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or(StorageError::SchemaIntegrity {
                reason: "migration checksum missing",
            })?;
        if stored != migration_checksum(script) {
            return Err(StorageError::SchemaIntegrity {
                reason: "migration checksum mismatch",
            });
        }
    }
    Ok(())
}

fn validate_live_schema(connection: &Connection) -> Result<()> {
    const TABLES: &[&str] = &[
        "schema_migrations",
        "wallet_metadata",
        "transaction_intents",
        "credential_metadata",
        "approval_ceremonies",
        "one_time_authorizations",
        "nonce_claims",
        "secret_refs",
        "audit_events",
        "webauthn_profiles",
        "intent_materials",
        "policy_documents",
        "policy_artifacts",
        "policy_test_vectors",
        "policy_validation_runs",
        "policy_bindings",
        "policy_activations",
    ];
    const INDEXES: &[&str] = &[
        "one_authorization_per_intent",
        "transaction_intents_epoch_status",
        "approval_ceremonies_intent_epoch",
        "approval_ceremonies_epoch_completion",
        "authorizations_intent_epoch",
        "authorizations_epoch_availability",
        "nonce_claims_epoch_invalidation",
        "audit_events_wallet_epoch",
        "credential_metadata_wallet",
        "secret_refs_wallet",
        "transaction_intents_v2_approval_nonce",
        "transaction_intents_v2_status_page",
        "transaction_intents_v2_latest",
        "intent_materials_intent_kind",
        "authorizations_v2_available",
        "nonce_claims_v2_binding",
        "policy_documents_wallet_epoch",
        "policy_artifacts_policy",
        "policy_test_vectors_policy",
        "policy_validation_runs_policy",
        "policy_bindings_wallet_epoch",
        "policy_activations_wallet_epoch_state_expiry",
    ];
    for table in TABLES {
        require_object(connection, "table", table)?;
    }

    for trigger in [
        "transaction_intents_v2_required",
        "transaction_intents_v2_required_update",
        "transaction_intents_v2_immutable",
        "credential_metadata_v2_required_insert",
        "credential_metadata_v2_required_update",
        "approval_ceremonies_v2_required",
        "nonce_claims_v2_binding_required",
    ] {
        require_object(connection, "trigger", trigger)?;
    }
    for table in [
        "policy_documents",
        "policy_artifacts",
        "policy_test_vectors",
        "policy_validation_runs",
        "policy_bindings",
        "policy_activations",
    ] {
        for operation in ["update", "delete"] {
            let trigger_name = format!("{table}_no_{operation}");
            let trigger = normalized_object_sql(connection, "trigger", &trigger_name)?;
            if !trigger.contains(&format!("before {operation} on {table}"))
                || !trigger.contains("raise(abort")
            {
                return Err(StorageError::SchemaIntegrity {
                    reason: "policy append-only trigger invalid",
                });
            }
        }
    }
    for index in INDEXES {
        require_object(connection, "index", index)?;
    }

    let update_trigger = normalized_object_sql(connection, "trigger", "audit_events_no_update")?;
    if !update_trigger.contains("before update on audit_events")
        || !update_trigger.contains("raise(abort")
    {
        return Err(StorageError::SchemaIntegrity {
            reason: "append-only audit update trigger invalid",
        });
    }
    let delete_trigger = normalized_object_sql(connection, "trigger", "audit_events_no_delete")?;
    if !delete_trigger.contains("before delete on audit_events")
        || !delete_trigger.contains("raise(abort")
    {
        return Err(StorageError::SchemaIntegrity {
            reason: "append-only audit delete trigger invalid",
        });
    }
    let secret_refs = normalized_object_sql(connection, "table", "secret_refs")?;
    if !secret_refs.contains("check")
        || !secret_refs.contains(
            "backend = 'os_keychain' and substr(handle, 1, 11) = 'keychain://' and length(handle) > 11",
        )
        || !secret_refs.contains(
            "backend = 'hsm' and substr(handle, 1, 6) = 'hsm://' and length(handle) > 6",
        )
        || !secret_refs.contains(
            "backend = 'encrypted_file' and substr(handle, 1, 17) = 'encrypted-file://' and length(handle) > 17",
        )
    {
        return Err(StorageError::SchemaIntegrity {
            reason: "secret handle constraint invalid",
        });
    }
    let unique_authorization =
        normalized_object_sql(connection, "index", "one_authorization_per_intent")?;
    if !unique_authorization.contains("create unique index")
        || !unique_authorization.contains("(intent_id)")
    {
        return Err(StorageError::SchemaIntegrity {
            reason: "authorization uniqueness constraint invalid",
        });
    }
    let approval_nonce_index =
        normalized_object_sql(connection, "index", "transaction_intents_v2_approval_nonce")?;
    if !approval_nonce_index.contains("create unique index")
        || !approval_nonce_index.contains("on transaction_intents(wallet_id, approval_nonce)")
        || !approval_nonce_index.contains("where intent_schema_version = 2")
        || !approval_nonce_index.contains("approval_nonce is not null")
    {
        return Err(StorageError::SchemaIntegrity {
            reason: "v2 approval nonce uniqueness constraint invalid",
        });
    }
    for (trigger_name, operation) in [
        ("transaction_intents_v2_required", "before insert"),
        ("transaction_intents_v2_required_update", "before update"),
    ] {
        let required = normalized_object_sql(connection, "trigger", trigger_name)?;
        if !required.contains(operation)
            || !required.contains("new.intent_schema_version = 2")
            || !required.contains("new.network")
            || !required.contains("new.protocol_version")
            || !required.contains("new.action")
            || !required.contains("new.signer_id")
            || !required.contains("new.approval_nonce")
            || !required.contains("length(new.approval_nonce) != 32")
            || !required.contains("raise(abort")
        {
            return Err(StorageError::SchemaIntegrity {
                reason: "v2 required intent trigger invalid",
            });
        }
    }
    let immutable_intent =
        normalized_object_sql(connection, "trigger", "transaction_intents_v2_immutable")?;
    for protected_field in [
        "wallet_id",
        "epoch",
        "tx_digest",
        "policy_hash",
        "session_id",
        "expires_at",
        "created_at",
        "network",
        "protocol_version",
        "action",
        "signer_id",
        "approval_nonce",
        "intent_schema_version",
    ] {
        if !immutable_intent.contains(protected_field) {
            return Err(StorageError::SchemaIntegrity {
                reason: "v2 immutable intent trigger invalid",
            });
        }
    }
    if !immutable_intent.contains("raise(abort") {
        return Err(StorageError::SchemaIntegrity {
            reason: "v2 immutable intent trigger invalid",
        });
    }
    let status_page =
        normalized_object_sql(connection, "index", "transaction_intents_v2_status_page")?;
    if !status_page.contains("on transaction_intents(wallet_id, epoch, status, created_at, id)")
        || !status_page.contains("where intent_schema_version = 2")
    {
        return Err(StorageError::SchemaIntegrity {
            reason: "v2 status page index invalid",
        });
    }
    let latest = normalized_object_sql(connection, "index", "transaction_intents_v2_latest")?;
    if !latest.contains("on transaction_intents(wallet_id, epoch, created_at desc, id desc)")
        || !latest.contains("where intent_schema_version = 2")
    {
        return Err(StorageError::SchemaIntegrity {
            reason: "v2 latest intent index invalid",
        });
    }
    let available = normalized_object_sql(connection, "index", "authorizations_v2_available")?;
    if !available.contains(
        "on one_time_authorizations(wallet_id, epoch, intent_id, consumed_at, invalidated_at, expires_at)",
    ) {
        return Err(StorageError::SchemaIntegrity {
            reason: "v2 available authorization index invalid",
        });
    }
    let nonce_index = normalized_object_sql(connection, "index", "nonce_claims_v2_binding")?;
    if !nonce_index
        .contains("on nonce_claims(wallet_id, epoch, intent_id, authorization_id, signer_id)")
    {
        return Err(StorageError::SchemaIntegrity {
            reason: "v2 nonce binding index invalid",
        });
    }
    let nonce_binding =
        normalized_object_sql(connection, "trigger", "nonce_claims_v2_binding_required")?;
    if !nonce_binding.contains("before insert on nonce_claims")
        || !nonce_binding.contains("new.authorization_id")
        || !nonce_binding.contains("new.intent_id")
        || !nonce_binding.contains("new.signer_id")
        || !nonce_binding.contains("one_time_authorizations")
        || !nonce_binding.contains("transaction_intents")
        || !nonce_binding.contains("raise(abort")
    {
        return Err(StorageError::SchemaIntegrity {
            reason: "v2 nonce binding trigger invalid",
        });
    }
    let materials = normalized_object_sql(connection, "table", "intent_materials")?;
    if !materials.contains("json_valid(payload_json)")
        || !materials.contains("length(payload_hash) = 32")
        || !materials.contains("primary key (intent_id, kind)")
    {
        return Err(StorageError::SchemaIntegrity {
            reason: "intent material integrity constraints invalid",
        });
    }
    Ok(())
}

fn require_object(connection: &Connection, object_type: &str, name: &str) -> Result<()> {
    if object_sql(connection, object_type, name)?.is_some() {
        Ok(())
    } else {
        Err(StorageError::SchemaIntegrity {
            reason: "required schema object missing",
        })
    }
}

fn normalized_object_sql(connection: &Connection, object_type: &str, name: &str) -> Result<String> {
    object_sql(connection, object_type, name)?
        .map(|sql| {
            sql.to_ascii_lowercase()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        })
        .ok_or(StorageError::SchemaIntegrity {
            reason: "required schema object missing",
        })
}

fn object_sql(connection: &Connection, object_type: &str, name: &str) -> Result<Option<String>> {
    connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = ?1 AND name = ?2",
            params![object_type, name],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
}

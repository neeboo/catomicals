use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::{Result, StorageError};

pub const CURRENT_SCHEMA_VERSION: i32 = 1;
const INITIAL_MIGRATION: &str = include_str!("../migrations/0001_initial.sql");

pub(crate) fn migrate(connection: &mut Connection) -> Result<()> {
    let found = connection.pragma_query_value(None, "user_version", |row| row.get::<_, i32>(0))?;
    if found > CURRENT_SCHEMA_VERSION {
        return Err(StorageError::SchemaTooNew {
            found,
            supported: CURRENT_SCHEMA_VERSION,
        });
    }
    if found == 0 {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(INITIAL_MIGRATION)?;
        tx.execute(
            "INSERT INTO schema_migrations(version, checksum) VALUES (?1, ?2)",
            params![CURRENT_SCHEMA_VERSION, initial_migration_checksum()],
        )?;
        tx.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION)?;
        tx.commit()?;
    }
    validate_migration_checksum(connection)?;
    validate_live_schema(connection)
}

fn initial_migration_checksum() -> String {
    hex::encode(Sha256::digest(INITIAL_MIGRATION.as_bytes()))
}

fn validate_migration_checksum(connection: &Connection) -> Result<()> {
    if object_sql(connection, "table", "schema_migrations")?.is_none() {
        return Err(StorageError::SchemaIntegrity {
            reason: "migration ledger missing",
        });
    }
    let ledger_rows =
        connection.query_row("SELECT count(*) FROM schema_migrations", [], |row| {
            row.get::<_, u64>(0)
        })?;
    if ledger_rows != 1 {
        return Err(StorageError::SchemaIntegrity {
            reason: "migration ledger has unexpected entries",
        });
    }
    let stored = connection
        .query_row(
            "SELECT checksum FROM schema_migrations WHERE version = ?1",
            [CURRENT_SCHEMA_VERSION],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or(StorageError::SchemaIntegrity {
            reason: "migration checksum missing",
        })?;
    if stored != initial_migration_checksum() {
        return Err(StorageError::SchemaIntegrity {
            reason: "migration checksum mismatch",
        });
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
    ];
    for table in TABLES {
        require_object(connection, "table", table)?;
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

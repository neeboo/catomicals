use std::path::Path;

use catomicals_wallet::DurableWalletStore;
use uuid::Uuid;

const WALLET_DATABASE: &str = "wallet.sqlite3";

pub fn open_authority(
    data_dir: &Path,
    wallet_id: Uuid,
    now: i64,
) -> anyhow::Result<DurableWalletStore> {
    std::fs::create_dir_all(data_dir)?;
    let database = data_dir.join(WALLET_DATABASE);
    if database.exists() {
        DurableWalletStore::open(&database).map_err(Into::into)
    } else {
        DurableWalletStore::initialize(&database, wallet_id, now).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use catomicals_wallet::{StorageMode, WalletStore};
    use uuid::Uuid;

    #[test]
    fn explicit_data_directory_opens_single_writer_durable_authority() {
        let directory = tempfile::tempdir().unwrap();
        let wallet_id = Uuid::from_bytes([0x29; 16]);
        let authority = open_authority(directory.path(), wallet_id, 1_800_000_000).unwrap();
        assert_eq!(authority.descriptor().mode, StorageMode::Durable);
        assert!(open_authority(directory.path(), wallet_id, 1_800_000_001).is_err());
        drop(authority);
        assert!(open_authority(directory.path(), wallet_id, 1_800_000_002).is_ok());
    }
}

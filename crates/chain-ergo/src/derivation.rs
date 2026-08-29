use std::fmt;

use ergo_lib::wallet::derivation_path::{ChildIndexHardened, ChildIndexNormal, DerivationPath};

use crate::ErgoAdapterError;

pub const ERGO_COIN_TYPE: u32 = 429;
const HARDENED_INDEX: u32 = 1 << 31;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErgoDerivationPath(DerivationPath);

impl fmt::Display for ErgoDerivationPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Builds the EIP-3 path `m/44'/429'/account'/0/address_index`.
///
/// EIP-3 deliberately fixes the change component at external branch zero.
pub fn derive_eip3_path(
    account: u32,
    address_index: u32,
) -> Result<ErgoDerivationPath, ErgoAdapterError> {
    let account = checked_index("account", account)?;
    let address_index = checked_index("address_index", address_index)?;
    let account = ChildIndexHardened::from_31_bit(account).map_err(|_| {
        ErgoAdapterError::InvalidDerivationIndex {
            field: "account",
            value: account,
        }
    })?;
    let address_index = ChildIndexNormal::normal(address_index).map_err(|_| {
        ErgoAdapterError::InvalidDerivationIndex {
            field: "address_index",
            value: address_index,
        }
    })?;
    Ok(ErgoDerivationPath(DerivationPath::new(
        account,
        vec![address_index],
    )))
}

fn checked_index(field: &'static str, value: u32) -> Result<u32, ErgoAdapterError> {
    if value >= HARDENED_INDEX {
        Err(ErgoAdapterError::InvalidDerivationIndex { field, value })
    } else {
        Ok(value)
    }
}

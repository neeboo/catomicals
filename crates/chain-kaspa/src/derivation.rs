use crate::KaspaAdapterError;

pub const KASPA_COIN_TYPE: u32 = 111_111;
const HARDENED_INDEX: u32 = 1 << 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivationBranch {
    Receive,
    Change,
}

impl DerivationBranch {
    const fn index(self) -> u32 {
        match self {
            Self::Receive => 0,
            Self::Change => 1,
        }
    }
}

pub fn derive_single_sig_path(
    account: u32,
    branch: DerivationBranch,
    address_index: u32,
) -> Result<String, KaspaAdapterError> {
    validate_index("account", account)?;
    validate_index("address_index", address_index)?;
    Ok(format!(
        "m/44'/{KASPA_COIN_TYPE}'/{account}'/{}/{address_index}",
        branch.index()
    ))
}

pub fn derive_multisig_path(
    account: u32,
    cosigner_index: u32,
    branch: DerivationBranch,
    address_index: u32,
) -> Result<String, KaspaAdapterError> {
    validate_index("account", account)?;
    validate_index("cosigner_index", cosigner_index)?;
    validate_index("address_index", address_index)?;
    Ok(format!(
        "m/45'/{KASPA_COIN_TYPE}'/{account}'/{cosigner_index}/{}/{address_index}",
        branch.index()
    ))
}

fn validate_index(field: &'static str, value: u32) -> Result<(), KaspaAdapterError> {
    if value >= HARDENED_INDEX {
        return Err(KaspaAdapterError::InvalidDerivationIndex { field, value });
    }
    Ok(())
}

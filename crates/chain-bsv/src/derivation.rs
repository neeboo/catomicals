use std::{fmt, str::FromStr};

use crate::BsvError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bip44Path {
    account: u32,
    change: bool,
    address_index: u32,
}

impl Bip44Path {
    pub const COIN_TYPE: u32 = 236;
    const HARDENED: u32 = 1 << 31;

    pub fn new(account: u32, change: bool, address_index: u32) -> Result<Self, BsvError> {
        if account >= Self::HARDENED || address_index >= Self::HARDENED {
            return Err(BsvError::InvalidDerivationPath(
                "child number must be below 2^31".to_owned(),
            ));
        }
        Ok(Self {
            account,
            change,
            address_index,
        })
    }

    pub const fn account(self) -> u32 {
        self.account
    }

    pub const fn change(self) -> bool {
        self.change
    }

    pub const fn address_index(self) -> u32 {
        self.address_index
    }

    pub const fn components(self) -> [u32; 5] {
        [
            44 | Self::HARDENED,
            Self::COIN_TYPE | Self::HARDENED,
            self.account | Self::HARDENED,
            self.change as u32,
            self.address_index,
        ]
    }
}

impl fmt::Display for Bip44Path {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "m/44'/236'/{}'/{}/{}",
            self.account, self.change as u8, self.address_index
        )
    }
}

impl FromStr for Bip44Path {
    type Err = BsvError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parts = value.split('/').collect::<Vec<_>>();
        if parts.len() != 6 || parts[0] != "m" || parts[1] != "44'" || parts[2] != "236'" {
            return Err(BsvError::InvalidDerivationPath(value.to_owned()));
        }
        let account = parts[3]
            .strip_suffix('\'')
            .ok_or_else(|| BsvError::InvalidDerivationPath(value.to_owned()))?
            .parse::<u32>()
            .map_err(|_| BsvError::InvalidDerivationPath(value.to_owned()))?;
        let change = match parts[4] {
            "0" => false,
            "1" => true,
            _ => return Err(BsvError::InvalidDerivationPath(value.to_owned())),
        };
        let address_index = parts[5]
            .parse::<u32>()
            .map_err(|_| BsvError::InvalidDerivationPath(value.to_owned()))?;
        Self::new(account, change, address_index)
    }
}

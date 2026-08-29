use std::{fmt, str::FromStr};

use crate::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bip44Path {
    account: u32,
    change: u32,
    address_index: u32,
}

impl Bip44Path {
    pub const PURPOSE: u32 = 44;
    pub const COIN_TYPE: u32 = 145;

    pub fn new(account: u32, change: u32, address_index: u32) -> Result<Self, Error> {
        require_unhardened("account", account)?;
        if change > 1 {
            return Err(Error::InvalidChange(change));
        }
        require_unhardened("address_index", address_index)?;
        Ok(Self {
            account,
            change,
            address_index,
        })
    }

    pub const fn account(self) -> u32 {
        self.account
    }

    pub const fn change(self) -> u32 {
        self.change
    }

    pub const fn address_index(self) -> u32 {
        self.address_index
    }

    pub const fn components(self) -> [u32; 5] {
        [
            Self::PURPOSE | (1 << 31),
            Self::COIN_TYPE | (1 << 31),
            self.account | (1 << 31),
            self.change,
            self.address_index,
        ]
    }
}

impl fmt::Display for Bip44Path {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "m/{}'/{}'/{}'/{}/{}",
            Self::PURPOSE,
            Self::COIN_TYPE,
            self.account,
            self.change,
            self.address_index
        )
    }
}

impl FromStr for Bip44Path {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parts: Vec<_> = value.split('/').collect();
        if parts.len() != 6 || parts[0] != "m" || parts[1] != "44'" || parts[2] != "145'" {
            return Err(Error::InvalidDerivationPath);
        }
        let account = parts[3]
            .strip_suffix('\'')
            .ok_or(Error::InvalidDerivationPath)?
            .parse()
            .map_err(|_| Error::InvalidDerivationPath)?;
        if parts[4].ends_with('\'') || parts[5].ends_with('\'') {
            return Err(Error::InvalidDerivationPath);
        }
        let change = parts[4].parse().map_err(|_| Error::InvalidDerivationPath)?;
        let address_index = parts[5].parse().map_err(|_| Error::InvalidDerivationPath)?;
        Self::new(account, change, address_index)
    }
}

fn require_unhardened(field: &'static str, value: u32) -> Result<(), Error> {
    if value < 1 << 31 {
        Ok(())
    } else {
        Err(Error::InvalidDerivationIndex { field, value })
    }
}

//! Stateful wrappers around the Zcash Foundation FROST distributed key
//! generation protocol.

use std::collections::BTreeMap;

use frost_secp256k1_tr::{
    Identifier,
    keys::{KeyPackage, PublicKeyPackage, dkg},
};
use rand::rngs::OsRng;

/// Output of the in-process DKG demonstration.
///
/// `key_packages` are secret and intentionally have no serde implementation.
pub struct LocalDkgOutput {
    pub min_signers: u16,
    pub max_signers: u16,
    pub key_packages: BTreeMap<Identifier, KeyPackage>,
    pub public_key_package: PublicKeyPackage,
}

impl core::fmt::Debug for LocalDkgOutput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LocalDkgOutput")
            .field("min_signers", &self.min_signers)
            .field("max_signers", &self.max_signers)
            .field(
                "key_packages",
                &format_args!("<{} redacted>", self.key_packages.len()),
            )
            .field("public_key_package", &self.public_key_package)
            .finish()
    }
}

/// Run all DKG participants locally while preserving the protocol's ownership
/// boundaries between its three parts.
///
/// The in-process router demonstrates the protocol; deployment still requires
/// authenticated broadcast in round one and confidential authenticated
/// delivery in round two.
pub fn run_local_dkg(
    max_signers: u16,
    min_signers: u16,
) -> Result<LocalDkgOutput, frost_secp256k1_tr::Error> {
    let mut round1_secrets = BTreeMap::new();
    let mut received_round1: BTreeMap<Identifier, BTreeMap<Identifier, dkg::round1::Package>> =
        BTreeMap::new();

    for raw_id in 1..=max_signers {
        let id = Identifier::try_from(raw_id)?;
        let (secret, package) = dkg::part1(id, max_signers, min_signers, OsRng)?;
        round1_secrets.insert(id, secret);
        for receiver_raw in 1..=max_signers {
            if receiver_raw == raw_id {
                continue;
            }
            let receiver = Identifier::try_from(receiver_raw)?;
            received_round1
                .entry(receiver)
                .or_default()
                .insert(id, package.clone());
        }
    }

    let mut round2_secrets = BTreeMap::new();
    let mut received_round2: BTreeMap<Identifier, BTreeMap<Identifier, dkg::round2::Package>> =
        BTreeMap::new();
    for raw_id in 1..=max_signers {
        let id = Identifier::try_from(raw_id)?;
        let secret = round1_secrets
            .remove(&id)
            .ok_or(frost_secp256k1_tr::Error::UnknownIdentifier)?;
        let packages = received_round1
            .get(&id)
            .ok_or(frost_secp256k1_tr::Error::UnknownIdentifier)?;
        let (secret, outgoing) = dkg::part2(secret, packages)?;
        round2_secrets.insert(id, secret);
        for (receiver, package) in outgoing {
            received_round2
                .entry(receiver)
                .or_default()
                .insert(id, package);
        }
    }

    let mut key_packages = BTreeMap::new();
    let mut common_public: Option<PublicKeyPackage> = None;
    for raw_id in 1..=max_signers {
        let id = Identifier::try_from(raw_id)?;
        let round2_secret = round2_secrets
            .get(&id)
            .ok_or(frost_secp256k1_tr::Error::UnknownIdentifier)?;
        let round1 = received_round1
            .get(&id)
            .ok_or(frost_secp256k1_tr::Error::UnknownIdentifier)?;
        let round2 = received_round2
            .get(&id)
            .ok_or(frost_secp256k1_tr::Error::UnknownIdentifier)?;
        let (key, public) = dkg::part3(round2_secret, round1, round2)?;
        if let Some(expected) = &common_public {
            if expected != &public {
                return Err(frost_secp256k1_tr::Error::IncorrectPackage);
            }
        } else {
            common_public = Some(public.clone());
        }
        key_packages.insert(id, key);
    }

    let public_key_package = common_public.ok_or(frost_secp256k1_tr::Error::InvalidMaxSigners)?;
    Ok(LocalDkgOutput {
        min_signers,
        max_signers,
        key_packages,
        public_key_package,
    })
}

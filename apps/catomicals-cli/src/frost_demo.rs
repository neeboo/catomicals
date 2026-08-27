//! `frost demo`: run a 2-of-3 FROST BIP340 signing end-to-end, demonstrating
//! that even a dev-only (non-Passkey) authorization must satisfy the exact
//! same seam a wallet token satisfies.

use std::collections::BTreeMap;

use anyhow::Context;
use catomicals_threshold::{
    AuthorizationError, FrostCoordinator, FrostSession, LocalFrostParticipant, NonceGuard,
    SigningAuthorization, participant_identifier, run_local_dkg, session::signature_to_bytes,
};
use clap::Subcommand;
use sha2::{Digest, Sha256};

#[derive(Subcommand)]
pub enum FrostCommand {
    /// Run the 2-of-3 threshold signing demo with a dev authorization token.
    Demo(DemoArgs),
}

#[derive(Debug, clap::Args)]
pub struct DemoArgs {
    /// Message to sign (string; hashed to a 32-byte BIP340 digest).
    #[arg(long, default_value = "catomicals demo transaction v1")]
    message: String,
    #[arg(long, default_value_t = 3)]
    max_signers: u16,
    #[arg(long, default_value_t = 2)]
    min_signers: u16,
}

pub fn run(cmd: FrostCommand) -> anyhow::Result<()> {
    match cmd {
        FrostCommand::Demo(args) => demo(args),
    }
}

/// Dev-only token that binds the exact session/message/signer and is one-time.
/// Production tokens come from `catomicals-wallet` after a Passkey approval.
struct DevAuthorization {
    session_id: [u8; 32],
    message: [u8; 32],
    signer_id: u16,
    expiry: i64,
    consumed: bool,
}

impl SigningAuthorization for DevAuthorization {
    fn authorize(
        &mut self,
        session_id: &[u8; 32],
        message: &[u8; 32],
        signer_id: u16,
        now: i64,
    ) -> Result<(), AuthorizationError> {
        if self.consumed {
            return Err(AuthorizationError::AlreadyConsumed);
        }
        if &self.session_id != session_id {
            return Err(AuthorizationError::WrongSession);
        }
        if &self.message != message {
            return Err(AuthorizationError::WrongMessage);
        }
        if self.signer_id != signer_id {
            return Err(AuthorizationError::WrongSigner);
        }
        if now > self.expiry {
            return Err(AuthorizationError::Expired);
        }
        self.consumed = true;
        Ok(())
    }
}

fn demo(args: DemoArgs) -> anyhow::Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);
    let tx_digest: [u8; 32] = Sha256::digest(args.message.as_bytes()).into();

    let mut dkg = run_local_dkg(args.max_signers, args.min_signers)
        .context("distributed key generation failed")?;
    let group_xonly = catomicals_threshold::group_pubkey_xonly(&dkg.public_key_package)?;
    let session_id = Sha256::digest(b"demo session id").into();

    let mut coordinator = FrostCoordinator::new(
        session_id,
        tx_digest,
        args.min_signers,
        dkg.public_key_package,
    );
    let mut participants = BTreeMap::new();
    for id in 1u16..=args.min_signers {
        let key_package = dkg
            .key_packages
            .remove(&participant_identifier(id)?)
            .context("missing DKG participant")?;
        let mut participant = LocalFrostParticipant::new(id, key_package, NonceGuard::new())?;
        let commitment = participant.round1(session_id, tx_digest)?;
        coordinator.add_commitment(id, commitment)?;
        participants.insert(id, participant);
    }
    let session = coordinator.signing_session()?;
    for (id, participant) in &mut participants {
        let mut auth = DevAuthorization {
            session_id,
            message: tx_digest,
            signer_id: *id,
            expiry: now + 300,
            consumed: false,
        };
        let share = participant
            .round2(&session, &mut auth, now)
            .context("signer share rejected")?;
        coordinator.add_signature_share(*id, share)?;
    }

    let signature = coordinator.finalize().context("aggregate/verify failed")?;
    let sig_bytes = signature_to_bytes(&signature)?;

    println!("frost demo ({} of {})", args.min_signers, args.max_signers);
    println!("  message digest    {}", hex::encode(tx_digest));
    println!("  session id        {}", hex::encode(session_id));
    println!(
        "  group pubkey      {} (BIP340 X-only)",
        hex::encode(group_xonly)
    );
    println!(
        "  signature         {} (R||s, 64 bytes)",
        hex::encode(sig_bytes)
    );
    println!("  verified          true (aggregate_and_verify passed)");
    println!("  key generation    Zcash FROST DKG, local participant simulation");
    println!("  authorization     dev token, one-time, exact-bound (demo only)");
    Ok(())
}

// Ensure the type-level signature used above is referenced (avoids dead-code
// warnings when docs mention it).
#[allow(dead_code)]
fn _typecheck(_s: &FrostSession) {}

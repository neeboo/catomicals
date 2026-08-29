use chia_bls::{PublicKey, Signature};
use chia_consensus::{
    consensus_constants::{ConsensusConstants, TEST_CONSTANTS},
    flags::MEMPOOL_MODE,
    owned_conditions::OwnedSpendBundleConditions,
    spendbundle_conditions::get_conditions_from_spendbundle,
    spendbundle_validation::validate_clvm_and_signature,
};
use chia_protocol::{Bytes, Bytes32, Coin, CoinSpend, Program, SpendBundle};
use chia_puzzle_types::standard::{StandardArgs, StandardSolution};
use chia_puzzles::P2_DELEGATED_PUZZLE_OR_HIDDEN_PUZZLE;
use chia_traits::Streamable;
use clvm_traits::{ToClvm, clvm_list, clvm_quote};
use clvm_utils::CurriedProgram;
use clvmr::{
    Allocator, ClvmFlags, NodePtr, SExp,
    op_utils::{first, rest},
    serde::{node_from_bytes, node_to_bytes},
};
use sha2::{Digest, Sha256};

use crate::{
    AggSigMe, BlsSignatureShare, ChiaAdapterError, ThresholdBlsCommitment,
    ThresholdBlsDealerKeyKind, ThresholdBlsSecretShare, interpolate_threshold_signature_2_of_3,
    scope_profile, sign_threshold_share_2_of_3,
};
use catomicals_chain_domain::ChainScope;

const MAX_BLOCK_COST: u64 = 11_000_000_000;

pub use chia_protocol::{
    Coin as ChiaCoin, CoinSpend as ChiaCoinSpend, Program as ChiaProgram,
    SpendBundle as ChiaSpendBundle,
};

/// One XCH output emitted by a standard delegated-puzzle spend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChiaSpendOutput {
    pub puzzle_hash: [u8; 32],
    pub amount: u64,
    /// Complete optional CREATE_COIN payload, preserved in order for review.
    pub memos: Vec<Vec<u8>>,
}

impl ChiaSpendOutput {
    pub fn new(puzzle_hash: [u8; 32], amount: u64) -> Self {
        Self {
            puzzle_hash,
            amount,
            memos: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_memos(mut self, memos: Vec<Vec<u8>>) -> Self {
        self.memos = memos;
        self
    }
}

/// Consensus-derived details of a verified one-coin threshold SpendBundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChiaSpendBundle {
    pub bundle_id: [u8; 32],
    pub coin_id: [u8; 32],
    pub condition_message: Vec<u8>,
    pub outputs: Vec<ChiaSpendOutput>,
}

/// Returns the exact official consensus constants selected for this supported
/// Chia network. Testnet overrides mirror Chia's `initial-config.yaml`.
pub fn consensus_constants_for_scope(
    scope: ChainScope,
) -> Result<ConsensusConstants, ChiaAdapterError> {
    let profile = scope_profile(scope)?;
    let mut constants = TEST_CONSTANTS.clone();
    match scope.network {
        catomicals_chain_domain::ChainNetwork::Chia(
            catomicals_chain_domain::ChiaNetwork::Mainnet,
        ) => {
            constants.testnet = false;
        }
        catomicals_chain_domain::ChainNetwork::Chia(
            catomicals_chain_domain::ChiaNetwork::Testnet11,
        ) => {
            constants.sub_slot_iters_starting = 67_108_864;
            constants.difficulty_constant_factor = 10_052_721_566_054;
            constants.difficulty_starting = 30;
            constants.epoch_blocks = 768;
            constants.min_plot_size_v1 = 18;
            constants.hard_fork_height = 0;
            constants.soft_fork8_height = 3_755_000;
            constants.soft_fork9_height = 3_924_000;
            constants.plot_filter_128_height = 6_029_568;
            constants.plot_filter_64_height = 11_075_328;
            constants.plot_filter_32_height = 16_121_088;
            constants.genesis_challenge = Bytes32::new(profile.agg_sig_me_additional_data);
            constants.agg_sig_me_additional_data = Bytes32::new(profile.agg_sig_me_additional_data);
            constants.agg_sig_parent_additional_data =
                derived_agg_sig_data(profile.agg_sig_me_additional_data, 43);
            constants.agg_sig_puzzle_additional_data =
                derived_agg_sig_data(profile.agg_sig_me_additional_data, 44);
            constants.agg_sig_amount_additional_data =
                derived_agg_sig_data(profile.agg_sig_me_additional_data, 45);
            constants.agg_sig_puzzle_amount_additional_data =
                derived_agg_sig_data(profile.agg_sig_me_additional_data, 46);
            constants.agg_sig_parent_amount_additional_data =
                derived_agg_sig_data(profile.agg_sig_me_additional_data, 47);
            constants.agg_sig_parent_puzzle_additional_data =
                derived_agg_sig_data(profile.agg_sig_me_additional_data, 48);
            constants.genesis_pre_farm_farmer_puzzle_hash = parse_static_bytes32(
                "08296fc227decd043aee855741444538e4cc9a31772c4d1a9e6242d1e777e42a",
            );
            constants.genesis_pre_farm_pool_puzzle_hash = parse_static_bytes32(
                "3ef7c233fc0785f3c0cae5992c1d35e7c955ca37a423571c1607ba392a9d12f7",
            );
            constants.testnet = true;
        }
        _ => return Err(ChiaAdapterError::UnsupportedChainScope(scope)),
    }
    Ok(constants)
}

fn derived_agg_sig_data(seed: [u8; 32], discriminator: u8) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(seed);
    hasher.update([discriminator]);
    Bytes32::new(hasher.finalize().into())
}

fn parse_static_bytes32(value: &str) -> Bytes32 {
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(value, &mut bytes).expect("static Chia bytes32 is valid hex");
    Bytes32::new(bytes)
}

/// A standard Chia coin spend whose exact consensus `AGG_SIG_ME` request has
/// already been extracted and bound to the selected network.
#[derive(Debug, Clone)]
pub struct ThresholdChiaSpend {
    scope: ChainScope,
    coin_spend: CoinSpend,
    commitment: ThresholdBlsCommitment,
    agg_sig_me: AggSigMe,
    condition_message: Vec<u8>,
    outputs: Vec<ChiaSpendOutput>,
}

impl ThresholdChiaSpend {
    /// Builds the canonical Chia standard puzzle for the threshold group key,
    /// delegates the requested CREATE_COIN conditions, and extracts the
    /// resulting `AGG_SIG_ME` from consensus execution.
    ///
    /// `key_kind` is an explicit provenance assertion. A BLS public key alone
    /// cannot prove that hardened derivation and the synthetic offset happened
    /// before Shamir splitting, so callers must carry this marker from the
    /// dealer/provisioning record. Other key kinds fail closed here.
    pub fn standard(
        scope: ChainScope,
        coin: Coin,
        key_kind: ThresholdBlsDealerKeyKind,
        commitment: ThresholdBlsCommitment,
        outputs: Vec<ChiaSpendOutput>,
    ) -> Result<Self, ChiaAdapterError> {
        scope_profile(scope)?;
        if key_kind != ThresholdBlsDealerKeyKind::FinalSigningKey {
            return Err(ChiaAdapterError::ThresholdKeyMustBeFinalSigningKey);
        }
        if outputs.is_empty() {
            return Err(ChiaAdapterError::EmptyChiaSpendOutputs);
        }
        let output_total = outputs.iter().try_fold(0_u64, |total, output| {
            total
                .checked_add(output.amount)
                .ok_or(ChiaAdapterError::ChiaOutputAmountOverflow)
        })?;
        if output_total > coin.amount {
            return Err(ChiaAdapterError::ChiaOutputsExceedInput {
                input: coin.amount,
                outputs: output_total,
            });
        }

        let expected_puzzle_hash = standard_threshold_puzzle_hash(commitment.group_public_key())?;
        if coin.puzzle_hash.to_bytes() != expected_puzzle_hash {
            return Err(ChiaAdapterError::ThresholdStandardPuzzleHashMismatch {
                expected: expected_puzzle_hash,
                actual: coin.puzzle_hash.to_bytes(),
            });
        }

        let coin_spend = build_standard_coin_spend(coin, commitment.group_public_key(), &outputs)?;
        let inspected = inspect_unsigned_spend(scope, &commitment, coin_spend.clone())?;
        if inspected.outputs != outputs {
            return Err(ChiaAdapterError::ThresholdSpendConditionMismatch);
        }
        Ok(Self {
            scope,
            coin_spend,
            commitment,
            agg_sig_me: inspected.agg_sig_me,
            condition_message: inspected.condition_message,
            outputs,
        })
    }

    pub fn coin_spend(&self) -> &CoinSpend {
        &self.coin_spend
    }

    pub fn coin_id(&self) -> [u8; 32] {
        self.coin_spend.coin.coin_id().to_bytes()
    }

    pub fn condition_message(&self) -> &[u8] {
        &self.condition_message
    }

    pub fn outputs(&self) -> &[ChiaSpendOutput] {
        &self.outputs
    }

    /// Canonical unsigned SpendBundle retained by the chain-neutral review
    /// contract. The identity aggregate signature is allowed only at review.
    pub fn to_review_bytes(&self) -> Result<Vec<u8>, ChiaAdapterError> {
        SpendBundle::new(vec![self.coin_spend.clone()], Signature::default())
            .to_bytes()
            .map_err(|error| ChiaAdapterError::InvalidChiaSpendBundle(error.to_string()))
    }

    /// Signs the consensus-derived network/coin/condition message. The caller
    /// cannot substitute an arbitrary message at this boundary.
    pub fn sign_share(
        &self,
        share: &ThresholdBlsSecretShare,
    ) -> Result<BlsSignatureShare, ChiaAdapterError> {
        sign_threshold_share_2_of_3(&self.commitment, share, self.agg_sig_me.final_message())
    }

    /// Verifies both partials, interpolates the final Chia signature, and emits
    /// the official streamable SpendBundle encoding accepted by Chia nodes.
    pub fn finalize(
        &self,
        shares: &[BlsSignatureShare],
    ) -> Result<FinalizedChiaSpendBundle, ChiaAdapterError> {
        let signature = interpolate_threshold_signature_2_of_3(
            &self.commitment,
            self.agg_sig_me.final_message(),
            shares,
        )?;
        let signature = Signature::from_bytes(&signature)
            .map_err(|error| ChiaAdapterError::InvalidSignature(error.to_string()))?;
        let bundle = SpendBundle::new(vec![self.coin_spend.clone()], signature);
        verify_bundle(self.scope, &self.commitment, &bundle)?;
        Ok(FinalizedChiaSpendBundle { bundle })
    }
}

/// Consensus-derived details of a canonical unsigned threshold review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewedThresholdChiaSpend {
    pub coin_id: [u8; 32],
    pub signing_message_digest: [u8; 32],
    pub outputs: Vec<ChiaSpendOutput>,
}

pub fn review_threshold_spend(
    scope: ChainScope,
    key_kind: ThresholdBlsDealerKeyKind,
    commitment: &ThresholdBlsCommitment,
    bytes: &[u8],
) -> Result<ReviewedThresholdChiaSpend, ChiaAdapterError> {
    let spend = threshold_spend_from_review(scope, key_kind, commitment, bytes)?;
    Ok(ReviewedThresholdChiaSpend {
        coin_id: spend.coin_id(),
        signing_message_digest: Sha256::digest(spend.agg_sig_me.final_message()).into(),
        outputs: spend.outputs,
    })
}

/// Signs one threshold partial from the canonical unsigned SpendBundle that
/// was retained by the wallet review. No caller-supplied message is accepted.
pub fn sign_reviewed_threshold_share(
    scope: ChainScope,
    key_kind: ThresholdBlsDealerKeyKind,
    commitment: &ThresholdBlsCommitment,
    reviewed_bundle: &[u8],
    share: &ThresholdBlsSecretShare,
) -> Result<BlsSignatureShare, ChiaAdapterError> {
    threshold_spend_from_review(scope, key_kind, commitment, reviewed_bundle)?.sign_share(share)
}

/// Interpolates two verified partials into the exact reviewed SpendBundle and
/// runs the official Chia consensus verifier before returning it.
pub fn finalize_reviewed_threshold_spend(
    scope: ChainScope,
    key_kind: ThresholdBlsDealerKeyKind,
    commitment: &ThresholdBlsCommitment,
    reviewed_bundle: &[u8],
    shares: &[BlsSignatureShare],
) -> Result<FinalizedChiaSpendBundle, ChiaAdapterError> {
    threshold_spend_from_review(scope, key_kind, commitment, reviewed_bundle)?.finalize(shares)
}

fn threshold_spend_from_review(
    scope: ChainScope,
    key_kind: ThresholdBlsDealerKeyKind,
    commitment: &ThresholdBlsCommitment,
    bytes: &[u8],
) -> Result<ThresholdChiaSpend, ChiaAdapterError> {
    if key_kind != ThresholdBlsDealerKeyKind::FinalSigningKey {
        return Err(ChiaAdapterError::ThresholdKeyMustBeFinalSigningKey);
    }
    let bundle = SpendBundle::from_bytes(bytes)
        .map_err(|error| ChiaAdapterError::InvalidChiaSpendBundle(error.to_string()))?;
    if bundle
        .to_bytes()
        .map_err(|error| ChiaAdapterError::InvalidChiaSpendBundle(error.to_string()))?
        != bytes
    {
        return Err(ChiaAdapterError::InvalidChiaSpendBundle(
            "non-canonical review material".to_owned(),
        ));
    }
    if bundle.aggregated_signature != Signature::default() {
        return Err(ChiaAdapterError::InvalidChiaSpendBundle(
            "review material must not contain a finalized signature".to_owned(),
        ));
    }
    if bundle.coin_spends.len() != 1 {
        return Err(ChiaAdapterError::ThresholdSpendMustHaveOneCoin {
            actual: bundle.coin_spends.len(),
        });
    }
    let coin_spend = bundle.coin_spends[0].clone();
    let inspected = inspect_unsigned_spend(scope, commitment, coin_spend.clone())?;
    Ok(ThresholdChiaSpend {
        scope,
        coin_spend,
        commitment: commitment.clone(),
        agg_sig_me: inspected.agg_sig_me,
        condition_message: inspected.condition_message,
        outputs: inspected.outputs,
    })
}

/// A finalized official Chia SpendBundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedChiaSpendBundle {
    bundle: SpendBundle,
}

impl FinalizedChiaSpendBundle {
    pub fn bundle(&self) -> &SpendBundle {
        &self.bundle
    }

    pub fn bundle_id(&self) -> [u8; 32] {
        self.bundle.name().to_bytes()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ChiaAdapterError> {
        self.bundle
            .to_bytes()
            .map_err(|error| ChiaAdapterError::InvalidChiaSpendBundle(error.to_string()))
    }
}

/// Returns the canonical standard-puzzle hash for an already synthesized
/// threshold group public key.
pub fn standard_threshold_puzzle_hash(
    group_public_key: [u8; 48],
) -> Result<[u8; 32], ChiaAdapterError> {
    let public_key = PublicKey::from_bytes(&group_public_key)
        .map_err(|error| ChiaAdapterError::InvalidPublicKey(error.to_string()))?;
    if public_key.is_inf() {
        return Err(ChiaAdapterError::IdentityPublicKey);
    }
    Ok(StandardArgs::curry_tree_hash(public_key).to_bytes())
}

/// Parses a streamable SpendBundle, executes its puzzle with Chia consensus
/// rules, requires exactly one group-key `AGG_SIG_ME`, and verifies the final
/// signature against the selected network's additional data.
pub fn verify_threshold_spend_bundle(
    scope: ChainScope,
    key_kind: ThresholdBlsDealerKeyKind,
    commitment: &ThresholdBlsCommitment,
    bundle_bytes: &[u8],
) -> Result<VerifiedChiaSpendBundle, ChiaAdapterError> {
    scope_profile(scope)?;
    if key_kind != ThresholdBlsDealerKeyKind::FinalSigningKey {
        return Err(ChiaAdapterError::ThresholdKeyMustBeFinalSigningKey);
    }
    let bundle = SpendBundle::from_bytes(bundle_bytes)
        .map_err(|error| ChiaAdapterError::InvalidChiaSpendBundle(error.to_string()))?;
    verify_bundle(scope, commitment, &bundle)
}

struct InspectedSpend {
    agg_sig_me: AggSigMe,
    condition_message: Vec<u8>,
    outputs: Vec<ChiaSpendOutput>,
}

fn build_standard_coin_spend(
    coin: Coin,
    group_public_key: [u8; 48],
    outputs: &[ChiaSpendOutput],
) -> Result<CoinSpend, ChiaAdapterError> {
    let public_key = PublicKey::from_bytes(&group_public_key)
        .map_err(|error| ChiaAdapterError::InvalidPublicKey(error.to_string()))?;
    if public_key.is_inf() {
        return Err(ChiaAdapterError::IdentityPublicKey);
    }

    let mut allocator = Allocator::new();
    let standard_mod = node_from_bytes(&mut allocator, &P2_DELEGATED_PUZZLE_OR_HIDDEN_PUZZLE)
        .map_err(|error| ChiaAdapterError::InvalidChiaProgram(error.to_string()))?;
    let puzzle = CurriedProgram {
        program: standard_mod,
        args: StandardArgs::new(public_key),
    }
    .to_clvm(&mut allocator)
    .map_err(|error| ChiaAdapterError::InvalidChiaProgram(error.to_string()))?;

    let create_coin_conditions = outputs
        .iter()
        .map(|output| {
            let memos = output
                .memos
                .iter()
                .cloned()
                .map(Bytes::new)
                .collect::<Vec<_>>();
            clvm_list!(
                51_u8,
                Bytes32::new(output.puzzle_hash),
                output.amount,
                memos
            )
        })
        .collect::<Vec<_>>();
    let delegated_puzzle = clvm_quote!(create_coin_conditions)
        .to_clvm(&mut allocator)
        .map_err(|error| ChiaAdapterError::InvalidChiaProgram(error.to_string()))?;
    let solution = StandardSolution {
        original_public_key: None,
        delegated_puzzle,
        solution: NodePtr::NIL,
    }
    .to_clvm(&mut allocator)
    .map_err(|error| ChiaAdapterError::InvalidChiaProgram(error.to_string()))?;

    let puzzle_reveal = node_to_bytes(&allocator, puzzle)
        .map_err(|error| ChiaAdapterError::InvalidChiaProgram(error.to_string()))?;
    let solution = node_to_bytes(&allocator, solution)
        .map_err(|error| ChiaAdapterError::InvalidChiaProgram(error.to_string()))?;
    Ok(CoinSpend::new(
        coin,
        Program::new(puzzle_reveal.into()),
        Program::new(solution.into()),
    ))
}

fn inspect_unsigned_spend(
    scope: ChainScope,
    commitment: &ThresholdBlsCommitment,
    coin_spend: CoinSpend,
) -> Result<InspectedSpend, ChiaAdapterError> {
    let bundle = SpendBundle::new(vec![coin_spend], Signature::default());
    let constants = consensus_constants_for_scope(scope)?;
    let mut allocator = Allocator::new();
    let conditions =
        get_conditions_from_spendbundle(&mut allocator, &bundle, MAX_BLOCK_COST, 0, &constants)
            .map_err(|error| ChiaAdapterError::InvalidChiaSpendConditions(error.to_string()))?;
    let conditions = OwnedSpendBundleConditions::from(&allocator, conditions);
    if conditions.spends.len() != 1 {
        return Err(ChiaAdapterError::ThresholdSpendMustHaveOneCoin {
            actual: conditions.spends.len(),
        });
    }
    if !conditions.agg_sig_unsafe.is_empty() {
        return Err(ChiaAdapterError::UnexpectedChiaAggregateSignatureCondition);
    }
    let spend = &conditions.spends[0];
    if !spend.agg_sig_parent.is_empty()
        || !spend.agg_sig_puzzle.is_empty()
        || !spend.agg_sig_amount.is_empty()
        || !spend.agg_sig_puzzle_amount.is_empty()
        || !spend.agg_sig_parent_amount.is_empty()
        || !spend.agg_sig_parent_puzzle.is_empty()
    {
        return Err(ChiaAdapterError::UnexpectedChiaAggregateSignatureCondition);
    }
    if spend.agg_sig_me.len() != 1 {
        return Err(ChiaAdapterError::ThresholdSpendAggSigMeCount {
            actual: spend.agg_sig_me.len(),
        });
    }
    let (public_key, condition_message) = &spend.agg_sig_me[0];
    if public_key.to_bytes() != commitment.group_public_key() {
        return Err(ChiaAdapterError::ThresholdSpendGroupKeyMismatch);
    }
    let condition_message = condition_message.to_vec();
    let agg_sig_me = AggSigMe::new(scope, &condition_message, spend.coin_id.to_bytes())?;
    let outputs = extract_create_coin_payloads(&bundle.coin_spends[0])?;
    Ok(InspectedSpend {
        agg_sig_me,
        condition_message,
        outputs,
    })
}

fn verify_bundle(
    scope: ChainScope,
    commitment: &ThresholdBlsCommitment,
    bundle: &SpendBundle,
) -> Result<VerifiedChiaSpendBundle, ChiaAdapterError> {
    if bundle.coin_spends.len() != 1 {
        return Err(ChiaAdapterError::ThresholdSpendMustHaveOneCoin {
            actual: bundle.coin_spends.len(),
        });
    }
    let constants = consensus_constants_for_scope(scope)?;
    validate_clvm_and_signature(
        bundle,
        constants.max_block_cost_clvm,
        &constants,
        MEMPOOL_MODE,
    )
    .map_err(|error| ChiaAdapterError::InvalidChiaSpendBundle(error.to_string()))?;
    let inspected = inspect_unsigned_spend(scope, commitment, bundle.coin_spends[0].clone())?;
    let signature = bundle.aggregated_signature.to_bytes();
    if !inspected
        .agg_sig_me
        .verify(commitment.group_public_key(), signature)?
    {
        return Err(ChiaAdapterError::InvalidThresholdSpendSignature);
    }
    Ok(VerifiedChiaSpendBundle {
        bundle_id: bundle.name().to_bytes(),
        coin_id: bundle.coin_spends[0].coin.coin_id().to_bytes(),
        condition_message: inspected.condition_message,
        outputs: inspected.outputs,
    })
}

fn extract_create_coin_payloads(
    coin_spend: &CoinSpend,
) -> Result<Vec<ChiaSpendOutput>, ChiaAdapterError> {
    let mut allocator = Allocator::new();
    let (_, mut conditions) = coin_spend
        .puzzle_reveal
        .run(
            &mut allocator,
            ClvmFlags::empty(),
            MAX_BLOCK_COST,
            &coin_spend.solution,
        )
        .map_err(|error| ChiaAdapterError::InvalidChiaProgram(error.to_string()))?;
    let mut outputs = Vec::new();
    while let Some((condition, tail)) = allocator.next(conditions) {
        conditions = tail;
        let opcode = first(&allocator, condition)
            .map_err(|error| ChiaAdapterError::InvalidChiaSpendConditions(error.to_string()))?;
        let opcode = match allocator.sexp(opcode) {
            SExp::Atom => allocator.atom(opcode),
            SExp::Pair(..) => continue,
        };
        if opcode.as_ref() != [51] {
            continue;
        }
        let args = rest(&allocator, condition)
            .map_err(|error| ChiaAdapterError::InvalidChiaSpendConditions(error.to_string()))?;
        let (puzzle_hash, after_puzzle_hash) = allocator.next(args).ok_or_else(|| {
            ChiaAdapterError::InvalidChiaSpendConditions(
                "CREATE_COIN missing puzzle hash".to_owned(),
            )
        })?;
        let (amount, after_amount) = allocator.next(after_puzzle_hash).ok_or_else(|| {
            ChiaAdapterError::InvalidChiaSpendConditions("CREATE_COIN missing amount".to_owned())
        })?;
        let puzzle_hash = allocator.atom(puzzle_hash);
        let puzzle_hash: [u8; 32] = puzzle_hash.as_ref().try_into().map_err(|_| {
            ChiaAdapterError::InvalidChiaSpendConditions(
                "CREATE_COIN puzzle hash is not 32 bytes".to_owned(),
            )
        })?;
        let amount = clvm_atom_to_u64(allocator.atom(amount).as_ref())?;
        let memos = if let Some((memo_list, _)) = allocator.next(after_amount) {
            extract_memo_list(&allocator, memo_list)?
        } else {
            Vec::new()
        };
        outputs.push(ChiaSpendOutput {
            puzzle_hash,
            amount,
            memos,
        });
    }
    Ok(outputs)
}

fn extract_memo_list(
    allocator: &Allocator,
    mut list: NodePtr,
) -> Result<Vec<Vec<u8>>, ChiaAdapterError> {
    let mut memos = Vec::new();
    while let Some((memo, tail)) = allocator.next(list) {
        list = tail;
        match allocator.sexp(memo) {
            SExp::Atom => memos.push(allocator.atom(memo).to_vec()),
            SExp::Pair(..) => {
                return Err(ChiaAdapterError::InvalidChiaSpendConditions(
                    "CREATE_COIN memo must be an atom".to_owned(),
                ));
            }
        }
    }
    if list != NodePtr::NIL {
        return Err(ChiaAdapterError::InvalidChiaSpendConditions(
            "CREATE_COIN memo payload must be a proper list".to_owned(),
        ));
    }
    Ok(memos)
}

fn clvm_atom_to_u64(bytes: &[u8]) -> Result<u64, ChiaAdapterError> {
    if bytes.len() > 8 || bytes.first().is_some_and(|byte| byte & 0x80 != 0) {
        return Err(ChiaAdapterError::InvalidChiaSpendConditions(
            "CREATE_COIN amount is not a non-negative u64".to_owned(),
        ));
    }
    let mut amount = [0_u8; 8];
    amount[8 - bytes.len()..].copy_from_slice(bytes);
    Ok(u64::from_be_bytes(amount))
}

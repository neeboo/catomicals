//! Print reproducible transaction-size and contention estimates for the two
//! wallet-policy issuance models.

use bitcoin::Amount;
use catomicals_issuance::models::compare;
use catomicals_issuance::terms::{IssuanceTerms, SuccessorRule};

fn main() {
    let terms = IssuanceTerms {
        item_id: [0x42; 32],
        target_prefix: 1,
        total_supply: 1_000,
        successor_rule: SuccessorRule::RecursiveIssuer,
        lane_count: 8,
        salt: [0x7a; 32],
        metadata: b"catomicals measured issuance".to_vec(),
    };
    let report = compare(&terms, Amount::from_sat(1_000_000), Amount::from_sat(1_000));
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("model report serializes")
    );
}

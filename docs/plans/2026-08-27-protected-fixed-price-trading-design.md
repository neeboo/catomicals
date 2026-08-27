# Protected fixed-price trading design

## Security model

The traded object is an explicitly scoped receipt for one issuance-verified,
seller-controlled item outpoint. A listing moves that exact outpoint into a
two-leaf Taproot order output while preserving the item sat amount. The listing
commitment binds Signet, the issuance terms hash, item ID and commitment,
issuance lane and sequence, seller key and payout script, fixed price, creator
fee script and amount, item sat amount, expiry height, cancellation recipient,
and maximum transaction fee.

The buy leaf commits the listing hash and requires the seller's Schnorr
signature. The cancel leaf commits the same listing hash, applies
`OP_CHECKLOCKTIMEVERIFY` at the listing expiry, and requires the seller's
signature. Both signatures use Taproot `SIGHASH_DEFAULT`, so they commit every
input, previous output, sequence, and output. OP_CAT is not presented as output
introspection: seller-signature policy and independent raw-transaction checks
protect the payout, fee, recipient, and amount. The listing commitment is
consensus-visible, while the meaning and output classification remain wallet
policy.

## Transactions and APIs

The list transaction spends the receipt outpoint at input zero and creates the
canonical order output at output zero. A buy spends that order outpoint at
input zero and creates, in order, the buyer item, seller payout, fixed creator
fee, and optional buyer change. A cancel spends the same order outpoint through
the timelocked cancel leaf and creates the seller item plus optional seller
change. Extra funding inputs pay transaction fees so the item amount is
preserved across every path.

The agent verifier and wallet verifier decode and classify raw unsigned
transactions through separate implementations. Both require complete ordered
prevouts, empty pre-approval witnesses, `SIGHASH_DEFAULT`, bounded positive
fees, canonical scripts, and exact committed outputs. The buy request also
contains a BIP340 buyer-ownership proof over the listing hash, order outpoint,
unsigned transaction ID, buyer key, and proposal expiry. The wallet derives the
actual BIP341 signing digest itself and creates a Passkey intent from that
digest; it re-runs wallet policy before starting WebAuthn approval.

## Competition and UI semantics

Every buy and cancel spends the same order outpoint. Multiple candidates may be
shown as submitted or pending, but only one can confirm. Once a winner confirms,
all other candidates become conflicted and identify the winning transaction.
Submission time is informational only. The model makes no first-seen, auction,
or miner-ordering fairness claim. A buy signed before expiry can confirm after
expiry and race a now-valid cancel; Bitcoin block ordering decides the winner.

## Verification

Rust tests cover valid list, buy, and cancel paths; every committed listing
field; seller payout, creator fee, recipient, amount, input, prevout, expiry,
fee, and ownership substitutions; copied and partially signed transaction
attacks; and two-buyer plus buy-versus-cancel conflict resolution. An executable
Bitcoin Inquisition test evaluates the signed Taproot buy and cancel leaves with
full transaction context, then proves mutated seller payment, creator fee, and
recipient transactions fail `OP_CHECKSIG`.

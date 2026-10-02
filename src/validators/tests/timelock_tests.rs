//! Timelocks judged through the witness validator: a required native
//! script's `TimelockStart` / `TimelockExpiry` leaves are judged against the
//! transaction's validity interval (body keys 8 and 3), never against the
//! slot of the validation context.

use crate::common::{Asset, TxInput, TxOutput, UTxO};
use crate::validators::input_contexts::{UtxoInputContext, ValidationInputContext};
use crate::validators::phase_1::errors::Phase1Error;
use crate::validators::phase_1::validation::WitnessValidator;
use crate::validators::tests::fixtures::{preview_simple_context, PREVIEW_SIMPLE_TX_HEX};
use cardano_serialization_lib as csl;

fn key_hash(byte: u8) -> csl::Ed25519KeyHash {
    csl::Ed25519KeyHash::from_bytes(vec![byte; 28]).unwrap()
}

fn list(items: Vec<csl::NativeScript>) -> csl::NativeScripts {
    let mut out = csl::NativeScripts::new();
    for item in items {
        out.add(&item);
    }
    out
}

fn start(slot: u64) -> csl::NativeScript {
    csl::NativeScript::new_timelock_start(&csl::TimelockStart::new_timelockstart(
        &csl::BigNum::from(slot),
    ))
}

fn expiry(slot: u64) -> csl::NativeScript {
    csl::NativeScript::new_timelock_expiry(&csl::TimelockExpiry::new_timelockexpiry(
        &csl::BigNum::from(slot),
    ))
}

fn all(items: Vec<csl::NativeScript>) -> csl::NativeScript {
    csl::NativeScript::new_script_all(&csl::ScriptAll::new(&list(items)))
}

/// Whether the witness validator reports `policy` unsuccessful when it is
/// required (as a minting policy, provided by a reference input) by a
/// transaction whose validity interval is `[invalid_before, invalid_hereafter)`
/// and whose context slot is `slot`.
fn unsuccessful(
    policy: &csl::NativeScript,
    invalid_before: Option<u64>,
    invalid_hereafter: Option<u64>,
    slot: u64,
) -> bool {
    let tx = csl::FixedTransaction::from_hex(PREVIEW_SIMPLE_TX_HEX).unwrap();
    let mut ctx: ValidationInputContext = preview_simple_context();
    ctx.slot = slot;

    let mut body = tx.body();
    assert!(
        body.validity_start_interval_bignum().is_none(),
        "the fixture has no validity start to begin with"
    );
    body.remove_ttl();
    if let Some(s) = invalid_before {
        body.set_validity_start_interval_bignum(&csl::BigNum::from(s));
    }
    if let Some(s) = invalid_hereafter {
        body.set_ttl(&csl::BigNum::from(s));
    }

    let policy_hash = policy.hash();
    let mut assets = csl::MintAssets::new();
    assets
        .insert(&csl::AssetName::new(b"t".to_vec()).unwrap(), &csl::Int::new_i32(1))
        .unwrap();
    let mut mint = csl::Mint::new();
    mint.insert(&policy_hash, &assets);
    body.set_mint(&mint);

    let ref_tx_hash = vec![0xCD; 32];
    let mut ref_inputs = csl::TransactionInputs::new();
    ref_inputs.add(&csl::TransactionInput::new(
        &csl::TransactionHash::from_bytes(ref_tx_hash.clone()).unwrap(),
        0,
    ));
    body.set_reference_inputs(&ref_inputs);
    ctx.utxo_set.push(UtxoInputContext {
        utxo: UTxO {
            input: TxInput {
                tx_hash: hex::encode(&ref_tx_hash),
                output_index: 0,
            },
            output: TxOutput {
                address: ctx.utxo_set[0].utxo.output.address.clone(),
                amount: vec![Asset {
                    unit: "lovelace".to_string(),
                    quantity: "10000000".to_string(),
                }],
                data_hash: None,
                plutus_data: None,
                script_ref: Some(hex::encode(csl::ScriptRef::new_native_script(policy).to_bytes())),
                script_hash: Some(policy_hash.to_hex()),
            },
        },
        is_spent: false,
    });

    let result = WitnessValidator::new(&body, &tx.witness_set(), &tx.transaction_hash(), &ctx)
        .unwrap()
        .validate();
    result
        .errors
        .iter()
        .any(|e| matches!(e.error, Phase1Error::NativeScriptIsUnsuccessful { .. }))
}

#[test]
fn time_start_holds_iff_the_interval_starts_at_or_after_it() {
    let lock = start(1_000);
    // Absent start is -infinity: never at or after the lock.
    assert!(unsuccessful(&lock, None, None, 5_000));
    assert!(unsuccessful(&lock, None, Some(9_000), 5_000));
    assert!(unsuccessful(&lock, Some(999), None, 5_000));
    assert!(!unsuccessful(&lock, Some(1_000), None, 5_000), "equality holds");
    assert!(!unsuccessful(&lock, Some(1_001), None, 5_000));
}

#[test]
fn time_expire_holds_iff_the_interval_ends_at_or_before_it() {
    let lock = expiry(1_000);
    // Absent ttl is +infinity: never at or before the lock.
    assert!(unsuccessful(&lock, None, None, 0));
    assert!(unsuccessful(&lock, Some(10), None, 0));
    assert!(unsuccessful(&lock, None, Some(1_001), 0));
    assert!(!unsuccessful(&lock, None, Some(1_000), 0), "equality holds");
    assert!(!unsuccessful(&lock, None, Some(999), 0));
}

#[test]
fn the_context_slot_does_not_decide_a_timelock() {
    // Context slot inside the interval but past / before the locks: the
    // interval alone decides.
    let lock = all(vec![start(1_000), expiry(2_000)]);
    assert!(!unsuccessful(&lock, Some(1_000), Some(2_000), 1_000));
    assert!(!unsuccessful(&lock, Some(1_000), Some(2_000), 1_999));
    assert!(!unsuccessful(&lock, Some(1_500), Some(1_600), 0));
    assert!(!unsuccessful(&lock, Some(1_500), Some(1_600), 3_000_000));
    // A slot inside the locks does not rescue an interval outside them.
    assert!(unsuccessful(&lock, Some(900), Some(2_000), 1_500));
    assert!(unsuccessful(&lock, Some(1_000), Some(2_001), 1_500));
    assert!(unsuccessful(&lock, Some(1_000), None, 1_500));
    assert!(unsuccessful(&lock, None, Some(2_000), 1_500));
}

/// A vesting-style policy as wallets build them on mainnet: a key signs
/// before a deadline, or anyone after an unlock slot. The transaction
/// claims through the unlock branch with a validity interval starting at
/// the unlock slot and a ttl two hours later; the context slot is a later
/// tip, still inside the interval.
#[test]
fn a_mainnet_style_vesting_policy_follows_the_interval() {
    let unlock = 140_000_000u64;
    let deadline = 139_000_000u64;
    let policy = csl::NativeScript::new_script_any(&csl::ScriptAny::new(&list(vec![
        all(vec![
            csl::NativeScript::new_script_pubkey(&csl::ScriptPubkey::new(&key_hash(0x77))),
            expiry(deadline),
        ]),
        start(unlock),
    ])));
    // Interval [unlock, unlock + 7200), tip unlock + 600: holds.
    assert!(!unsuccessful(&policy, Some(unlock), Some(unlock + 7_200), unlock + 600));
    // Tip exactly at the unlock slot: the ledger accepts (unlock <= start),
    // although `slot > unlock` does not hold.
    assert!(!unsuccessful(&policy, Some(unlock), Some(unlock + 7_200), unlock));
    // Interval opening before the unlock slot, tip already past it: the
    // ledger rejects (start < unlock), although `slot > unlock` holds.
    assert!(unsuccessful(&policy, Some(unlock - 1), Some(unlock + 7_200), unlock + 600));
    // No validity start at all: the unlock branch can never hold.
    assert!(unsuccessful(&policy, None, Some(unlock + 7_200), unlock + 600));
}

#[test]
fn timelocks_nest_inside_all_any_and_n_of_k() {
    let key = csl::NativeScript::new_script_pubkey(&csl::ScriptPubkey::new(&key_hash(0x01)));
    let any = csl::NativeScript::new_script_any(&csl::ScriptAny::new(&list(vec![
        key.clone(),
        start(500),
    ])));
    assert!(!unsuccessful(&any, Some(500), None, 0));
    assert!(unsuccessful(&any, Some(499), None, 10_000));

    let n_of_k = csl::NativeScript::new_script_n_of_k(&csl::ScriptNOfK::new(
        2,
        &list(vec![key, start(500), expiry(800)]),
    ));
    assert!(!unsuccessful(&n_of_k, Some(500), Some(800), 600));
    assert!(unsuccessful(&n_of_k, Some(500), None, 600), "only one of three");
    assert!(unsuccessful(&n_of_k, None, Some(801), 600), "none of three");
}

/// A timelock leaf 6,000 levels down.
#[test]
fn a_deep_timelock_leaf_follows_the_interval() {
    std::thread::Builder::new()
        .stack_size(4 << 20)
        .spawn(|| {
            let levels = 6_000;
            let mut bytes = Vec::with_capacity(levels * 3 + 8);
            for _ in 0..levels {
                bytes.extend_from_slice(&[0x82, 0x01, 0x81]);
            }
            // [4, 1000]
            bytes.extend_from_slice(&[0x82, 0x04, 0x19, 0x03, 0xe8]);
            let script = csl::NativeScript::from_bytes(bytes).unwrap();
            assert!(!unsuccessful(&script, Some(1_000), None, 0));
            assert!(unsuccessful(&script, Some(999), None, 5_000));
            assert!(unsuccessful(&script, None, None, 5_000));
        })
        .unwrap()
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

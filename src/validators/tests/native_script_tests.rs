//! Unit tests for
//! [`crate::validators::phase_1::validation::NativeScriptExecutor`].
//!
//! Mirrors the ledger's `evalTimelock` from `Cardano.Ledger.Allegra.Scripts`:
//! pubkey ✔ iff its hash is in the witness set; `all` = AND of children; `any`
//! = OR; `n_of_k` ≥ n successes; `TimelockStart s` ✔ iff the transaction
//! has a validity start and `s ≤ start`; `TimelockExpiry s` ✔ iff it has a
//! ttl and `ttl ≤ s`.

use crate::validators::phase_1::validation::native_script_executor::ValidityInterval;
use crate::validators::phase_1::validation::NativeScriptExecutor;
use cardano_serialization_lib as csl;
use std::collections::HashSet;

fn key_hash(byte: u8) -> csl::Ed25519KeyHash {
    csl::Ed25519KeyHash::from_bytes(vec![byte; 28]).unwrap()
}

fn sigs(hashes: &[csl::Ed25519KeyHash]) -> HashSet<csl::Ed25519KeyHash> {
    hashes.iter().cloned().collect()
}

fn none() -> ValidityInterval {
    ValidityInterval::default()
}

fn pubkey_script(byte: u8) -> csl::NativeScript {
    csl::NativeScript::new_script_pubkey(&csl::ScriptPubkey::new(&key_hash(byte)))
}

fn scripts_list(items: Vec<csl::NativeScript>) -> csl::NativeScripts {
    let mut list = csl::NativeScripts::new();
    for s in items {
        list.add(&s);
    }
    list
}

#[test]
fn pubkey_ok_when_signature_present() {
    let script = pubkey_script(0x01);
    let signatures = sigs(&[key_hash(0x01)]);
    let exec = NativeScriptExecutor::new(&script, &signatures, none());
    assert_eq!(exec.execute().unwrap(), true);
}

#[test]
fn pubkey_fails_when_signature_missing() {
    let script = pubkey_script(0x01);
    let signatures = sigs(&[]);
    let exec = NativeScriptExecutor::new(&script, &signatures, none());
    assert_eq!(exec.execute().unwrap(), false);
}

#[test]
fn script_all_requires_every_child() {
    let script = csl::NativeScript::new_script_all(&csl::ScriptAll::new(
        &scripts_list(vec![pubkey_script(0x01), pubkey_script(0x02)]),
    ));
    assert_eq!(
        NativeScriptExecutor::new(&script, &sigs(&[key_hash(0x01), key_hash(0x02)]), none())
            .execute()
            .unwrap(),
        true
    );
    assert_eq!(
        NativeScriptExecutor::new(&script, &sigs(&[key_hash(0x01)]), none())
            .execute()
            .unwrap(),
        false
    );
}

#[test]
fn script_all_with_empty_children_is_true() {
    // Matches ledger semantics: AND over an empty set is vacuously true.
    let script = csl::NativeScript::new_script_all(&csl::ScriptAll::new(
        &scripts_list(vec![]),
    ));
    assert_eq!(
        NativeScriptExecutor::new(&script, &sigs(&[]), none())
            .execute()
            .unwrap(),
        true
    );
}

#[test]
fn script_any_requires_at_least_one_child() {
    let script = csl::NativeScript::new_script_any(&csl::ScriptAny::new(
        &scripts_list(vec![pubkey_script(0x01), pubkey_script(0x02)]),
    ));
    assert_eq!(
        NativeScriptExecutor::new(&script, &sigs(&[key_hash(0x02)]), none())
            .execute()
            .unwrap(),
        true
    );
    assert_eq!(
        NativeScriptExecutor::new(&script, &sigs(&[]), none())
            .execute()
            .unwrap(),
        false
    );
}

#[test]
fn script_any_with_empty_children_is_false() {
    // OR over empty set is false.
    let script = csl::NativeScript::new_script_any(&csl::ScriptAny::new(
        &scripts_list(vec![]),
    ));
    assert_eq!(
        NativeScriptExecutor::new(&script, &sigs(&[]), none())
            .execute()
            .unwrap(),
        false
    );
}

#[test]
fn script_n_of_k_threshold_enforced() {
    let script = csl::NativeScript::new_script_n_of_k(&csl::ScriptNOfK::new(
        2,
        &scripts_list(vec![
            pubkey_script(0x01),
            pubkey_script(0x02),
            pubkey_script(0x03),
        ]),
    ));
    // 2 of 3 satisfied.
    assert_eq!(
        NativeScriptExecutor::new(
            &script,
            &sigs(&[key_hash(0x01), key_hash(0x03)]),
            none(),
        )
        .execute()
        .unwrap(),
        true
    );
    // Only 1 of 3 satisfied.
    assert_eq!(
        NativeScriptExecutor::new(&script, &sigs(&[key_hash(0x02)]), none())
            .execute()
            .unwrap(),
        false
    );
    // All 3 satisfied (≥ 2).
    assert_eq!(
        NativeScriptExecutor::new(
            &script,
            &sigs(&[key_hash(0x01), key_hash(0x02), key_hash(0x03)]),
            none(),
        )
        .execute()
        .unwrap(),
        true
    );
}

#[test]
fn script_n_of_k_threshold_zero_always_true() {
    let script = csl::NativeScript::new_script_n_of_k(&csl::ScriptNOfK::new(
        0,
        &scripts_list(vec![pubkey_script(0x01)]),
    ));
    assert_eq!(
        NativeScriptExecutor::new(&script, &sigs(&[]), none())
            .execute()
            .unwrap(),
        true
    );
}

fn interval(before: Option<u64>, hereafter: Option<u64>) -> ValidityInterval {
    ValidityInterval::new(before, hereafter)
}

fn holds(script: &csl::NativeScript, signed: &[csl::Ed25519KeyHash], at: ValidityInterval) -> bool {
    NativeScriptExecutor::new(script, &sigs(signed), at).execute().unwrap()
}

#[test]
fn timelock_start_needs_a_validity_start_at_or_after_it() {
    // RequireTimeStart s ✔ iff s <= invalid_before; absent start = -inf.
    let script = csl::NativeScript::new_timelock_start(
        &csl::TimelockStart::new_timelockstart(&csl::BigNum::from(100u64)),
    );
    assert!(!holds(&script, &[], interval(None, None)), "no start");
    assert!(!holds(&script, &[], interval(None, Some(50))), "ttl only");
    assert!(!holds(&script, &[], interval(Some(99), None)), "start 99 < 100");
    assert!(holds(&script, &[], interval(Some(100), None)), "start 100 == 100");
    assert!(holds(&script, &[], interval(Some(101), Some(200))), "start 101 > 100");
}

#[test]
fn timelock_expiry_needs_a_ttl_at_or_before_it() {
    // RequireTimeExpire s ✔ iff invalid_hereafter <= s; absent ttl = +inf.
    let script = csl::NativeScript::new_timelock_expiry(
        &csl::TimelockExpiry::new_timelockexpiry(&csl::BigNum::from(100u64)),
    );
    assert!(!holds(&script, &[], interval(None, None)), "no ttl");
    assert!(!holds(&script, &[], interval(Some(10), None)), "start only");
    assert!(holds(&script, &[], interval(None, Some(99))), "ttl 99 < 100");
    assert!(holds(&script, &[], interval(Some(0), Some(100))), "ttl 100 == 100");
    assert!(!holds(&script, &[], interval(None, Some(101))), "ttl 101 > 100");
}

#[test]
fn nested_all_of_any_composes_correctly() {
    // all_of[ any_of[k1,k2], pubkey(k3), timelock_expiry(100) ]
    let any_k1_k2 = csl::NativeScript::new_script_any(&csl::ScriptAny::new(
        &scripts_list(vec![pubkey_script(0x01), pubkey_script(0x02)]),
    ));
    let expiry = csl::NativeScript::new_timelock_expiry(
        &csl::TimelockExpiry::new_timelockexpiry(&csl::BigNum::from(100u64)),
    );
    let all = csl::NativeScript::new_script_all(&csl::ScriptAll::new(
        &scripts_list(vec![any_k1_k2, pubkey_script(0x03), expiry]),
    ));

    // k2 + k3, ttl 50 → pass.
    assert!(holds(&all, &[key_hash(0x02), key_hash(0x03)], interval(None, Some(50))));
    // k3 only → any-branch fails.
    assert!(!holds(&all, &[key_hash(0x03)], interval(None, Some(50))));
    // k2 + k3 but ttl past the expiry → timelock fails.
    assert!(!holds(&all, &[key_hash(0x02), key_hash(0x03)], interval(None, Some(500))));
    // k2 + k3 but no ttl → timelock fails.
    assert!(!holds(&all, &[key_hash(0x02), key_hash(0x03)], interval(Some(0), None)));
}

#[test]
fn timelocks_inside_n_of_k_count_like_any_sub_script() {
    let start = csl::NativeScript::new_timelock_start(
        &csl::TimelockStart::new_timelockstart(&csl::BigNum::from(10u64)),
    );
    let expiry = csl::NativeScript::new_timelock_expiry(
        &csl::TimelockExpiry::new_timelockexpiry(&csl::BigNum::from(20u64)),
    );
    let script = csl::NativeScript::new_script_n_of_k(&csl::ScriptNOfK::new(
        2,
        &scripts_list(vec![pubkey_script(0x01), start, expiry]),
    ));
    assert!(holds(&script, &[], interval(Some(10), Some(20))));
    assert!(holds(&script, &[key_hash(0x01)], interval(Some(10), None)));
    assert!(!holds(&script, &[], interval(Some(10), Some(21))));
    assert!(!holds(&script, &[key_hash(0x01)], interval(Some(9), Some(21))));
}

#[test]
fn witness_validator_flags_unsuccessful_native_script() {
    // Integration: hook an always-failing native script to a required witness
    // path (ref-input with script_ref). The native script is `pubkey(k1)` but
    // we deliberately do NOT provide a signature — the tx still has its own
    // vkey (signing the body), so the signatures set the executor sees lacks
    // k1, and the script must be reported unsuccessful.
    use crate::common::{Asset, TxInput, TxOutput, UTxO};
    use crate::validators::input_contexts::UtxoInputContext;
    use crate::validators::phase_1::errors::Phase1Error;
    use crate::validators::phase_1::validation::WitnessValidator;
    use crate::validators::tests::fixtures::{
        preview_simple_context, PREVIEW_SIMPLE_TX_HEX,
    };

    let tx = csl::FixedTransaction::from_hex(PREVIEW_SIMPLE_TX_HEX).unwrap();
    let mut ctx = preview_simple_context();

    // Mint a token under policy = hash(pubkey(k1)). This introduces a native
    // script requirement that cannot be satisfied without k1's signature.
    let policy_script = pubkey_script(0x42);
    let policy_hash = policy_script.hash();
    let mut mint = csl::Mint::new();
    let mut assets = csl::MintAssets::new();
    assets
        .insert(
            &csl::AssetName::new(b"x".to_vec()).unwrap(),
            &csl::Int::new_i32(1),
        )
        .unwrap();
    mint.insert(&policy_hash, &assets);

    let mut body = tx.body();
    body.set_mint(&mint);

    // Provide the script through a reference input so we don't have to touch
    // the witness set's native_scripts collection (any native script there
    // would be treated as extraneous if unused).
    let ref_tx_hash = vec![0xAB; 32];
    let ref_input = csl::TransactionInput::new(
        &csl::TransactionHash::from_bytes(ref_tx_hash.clone()).unwrap(),
        0,
    );
    let mut ref_inputs = csl::TransactionInputs::new();
    ref_inputs.add(&ref_input);
    body.set_reference_inputs(&ref_inputs);

    let script_ref_hex = hex::encode(
        csl::ScriptRef::new_native_script(&policy_script).to_bytes(),
    );
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
                script_ref: Some(script_ref_hex),
                script_hash: Some(policy_hash.to_hex()),
            },
        },
        is_spent: false,
    });

    let validator =
        WitnessValidator::new(&body, &tx.witness_set(), &tx.transaction_hash(), &ctx)
            .unwrap();
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::NativeScriptIsUnsuccessful { .. }
        )),
        "expected NativeScriptIsUnsuccessful, got: {:?}",
        result.errors
    );
}

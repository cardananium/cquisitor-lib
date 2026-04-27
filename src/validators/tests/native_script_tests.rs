//! Unit tests for
//! [`crate::validators::phase_1::validation::NativeScriptExecutor`].
//!
//! Mirrors the ledger's `evalNativeScript` from `Cardano.Ledger.Allegra.Scripts`:
//! pubkey ✔ iff its hash is in the witness set; `all` = AND of children; `any`
//! = OR; `n_of_k` ≥ n successes; `TimelockStart s` ✔ iff `slot > s` (i.e.
//! invalid-before); `TimelockExpiry s` ✔ iff `slot ≤ s` (invalid-hereafter).

use crate::validators::phase_1::validation::NativeScriptExecutor;
use cardano_serialization_lib as csl;
use std::collections::HashSet;

fn key_hash(byte: u8) -> csl::Ed25519KeyHash {
    csl::Ed25519KeyHash::from_bytes(vec![byte; 28]).unwrap()
}

fn sigs(hashes: &[csl::Ed25519KeyHash]) -> HashSet<csl::Ed25519KeyHash> {
    hashes.iter().cloned().collect()
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
    let exec = NativeScriptExecutor::new(&script, &signatures, 0);
    assert_eq!(exec.execute().unwrap(), true);
}

#[test]
fn pubkey_fails_when_signature_missing() {
    let script = pubkey_script(0x01);
    let signatures = sigs(&[]);
    let exec = NativeScriptExecutor::new(&script, &signatures, 0);
    assert_eq!(exec.execute().unwrap(), false);
}

#[test]
fn script_all_requires_every_child() {
    let script = csl::NativeScript::new_script_all(&csl::ScriptAll::new(
        &scripts_list(vec![pubkey_script(0x01), pubkey_script(0x02)]),
    ));
    assert_eq!(
        NativeScriptExecutor::new(&script, &sigs(&[key_hash(0x01), key_hash(0x02)]), 0)
            .execute()
            .unwrap(),
        true
    );
    assert_eq!(
        NativeScriptExecutor::new(&script, &sigs(&[key_hash(0x01)]), 0)
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
        NativeScriptExecutor::new(&script, &sigs(&[]), 0)
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
        NativeScriptExecutor::new(&script, &sigs(&[key_hash(0x02)]), 0)
            .execute()
            .unwrap(),
        true
    );
    assert_eq!(
        NativeScriptExecutor::new(&script, &sigs(&[]), 0)
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
        NativeScriptExecutor::new(&script, &sigs(&[]), 0)
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
            0,
        )
        .execute()
        .unwrap(),
        true
    );
    // Only 1 of 3 satisfied.
    assert_eq!(
        NativeScriptExecutor::new(&script, &sigs(&[key_hash(0x02)]), 0)
            .execute()
            .unwrap(),
        false
    );
    // All 3 satisfied (≥ 2).
    assert_eq!(
        NativeScriptExecutor::new(
            &script,
            &sigs(&[key_hash(0x01), key_hash(0x02), key_hash(0x03)]),
            0,
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
        NativeScriptExecutor::new(&script, &sigs(&[]), 0)
            .execute()
            .unwrap(),
        true
    );
}

#[test]
fn timelock_start_is_invalid_before_slot() {
    // TimelockStart s == "invalid before slot s" → true iff current_slot > s.
    let script = csl::NativeScript::new_timelock_start(
        &csl::TimelockStart::new_timelockstart(&csl::BigNum::from(100u64)),
    );
    assert_eq!(
        NativeScriptExecutor::new(&script, &sigs(&[]), 50)
            .execute()
            .unwrap(),
        false,
        "slot 50 < 100 → not yet valid"
    );
    assert_eq!(
        NativeScriptExecutor::new(&script, &sigs(&[]), 100)
            .execute()
            .unwrap(),
        false,
        "slot 100 == 100 → strictly-greater-than rule rejects"
    );
    assert_eq!(
        NativeScriptExecutor::new(&script, &sigs(&[]), 101)
            .execute()
            .unwrap(),
        true,
        "slot 101 > 100 → valid"
    );
}

#[test]
fn timelock_expiry_is_invalid_hereafter_slot() {
    // TimelockExpiry s == "invalid at or after slot s" → true iff
    // current_slot ≤ s.
    let script = csl::NativeScript::new_timelock_expiry(
        &csl::TimelockExpiry::new_timelockexpiry(&csl::BigNum::from(100u64)),
    );
    assert_eq!(
        NativeScriptExecutor::new(&script, &sigs(&[]), 99)
            .execute()
            .unwrap(),
        true,
        "slot 99 ≤ 100 → still valid"
    );
    assert_eq!(
        NativeScriptExecutor::new(&script, &sigs(&[]), 100)
            .execute()
            .unwrap(),
        true,
        "slot 100 ≤ 100 → still valid"
    );
    assert_eq!(
        NativeScriptExecutor::new(&script, &sigs(&[]), 101)
            .execute()
            .unwrap(),
        false,
        "slot 101 > 100 → expired"
    );
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

    // k2 + k3, slot 50 → pass.
    assert_eq!(
        NativeScriptExecutor::new(
            &all,
            &sigs(&[key_hash(0x02), key_hash(0x03)]),
            50,
        )
        .execute()
        .unwrap(),
        true
    );
    // k3 only → any-branch fails.
    assert_eq!(
        NativeScriptExecutor::new(&all, &sigs(&[key_hash(0x03)]), 50)
            .execute()
            .unwrap(),
        false
    );
    // k2 + k3 but slot past expiry → timelock fails.
    assert_eq!(
        NativeScriptExecutor::new(
            &all,
            &sigs(&[key_hash(0x02), key_hash(0x03)]),
            500,
        )
        .execute()
        .unwrap(),
        false
    );
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

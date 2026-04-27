//! Unit tests for
//! [`crate::validators::phase_1::validation::TransactionLimitsValidator`].
//!
//! Covers the limits rules from the UTXO rule:
//! * Transaction size ≤ maxTxSize
//! * Execution units ≤ maxTxExUnits
//! * Reference scripts ≤ 200 KiB
//! * Inputs non-empty
//! * current_slot ∈ [validityStart, ttl]
//! * All inputs unspent
//! * Reference inputs don't overlap with spending inputs

use crate::validators::phase_1::errors::{Phase1Error, Phase1Warning};
use crate::validators::phase_1::validation::TransactionLimitsValidator;
use crate::validators::tests::fixtures::{preview_simple_context, PREVIEW_SIMPLE_TX_HEX};
use cardano_serialization_lib as csl;

fn parse_tx() -> csl::FixedTransaction {
    csl::FixedTransaction::from_hex(PREVIEW_SIMPLE_TX_HEX).unwrap()
}

#[test]
fn limits_pass_for_conforming_tx() {
    let tx = parse_tx();
    let ctx = preview_simple_context();
    let tx_size = PREVIEW_SIMPLE_TX_HEX.len() / 2;

    let validator =
        TransactionLimitsValidator::new(tx_size, &tx.body(), &tx.witness_set(), &ctx)
            .unwrap();
    let result = validator.validate();

    assert!(
        result.errors.is_empty(),
        "expected no limit errors, got: {:?}",
        result.errors
    );
}

#[test]
fn tx_size_over_limit_produces_max_tx_size_error() {
    let tx = parse_tx();
    let mut ctx = preview_simple_context();
    ctx.protocol_parameters.max_transaction_size = 50;

    let tx_size = PREVIEW_SIMPLE_TX_HEX.len() / 2;
    let validator =
        TransactionLimitsValidator::new(tx_size, &tx.body(), &tx.witness_set(), &ctx)
            .unwrap();
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::MaxTxSizeUTxO { .. }
        )),
        "expected MaxTxSizeUTxO, got: {:?}",
        result.errors
    );
}

#[test]
fn ttl_before_current_slot_is_outside_validity() {
    // Build a minimal body that explicitly sets a ttl, then advance the
    // ledger's slot past it.
    let mut inputs = csl::TransactionInputs::new();
    inputs.add(&csl::TransactionInput::new(
        &csl::TransactionHash::from_bytes(vec![0x01; 32]).unwrap(),
        0,
    ));
    let mut body = csl::TransactionBody::new_tx_body(
        &inputs,
        &csl::TransactionOutputs::new(),
        &csl::BigNum::from(0u64),
    );
    body.set_ttl(&csl::BigNum::from(500u64));
    let witness_set = csl::TransactionWitnessSet::new();

    let mut ctx = preview_simple_context();
    ctx.slot = 1_000;

    let validator =
        TransactionLimitsValidator::new(10, &body, &witness_set, &ctx).unwrap();
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::OutsideValidityIntervalUTxO { .. }
        )),
        "expected OutsideValidityIntervalUTxO, got: {:?}",
        result.errors
    );
}

#[test]
fn validity_start_after_current_slot_is_outside_validity() {
    let mut inputs = csl::TransactionInputs::new();
    inputs.add(&csl::TransactionInput::new(
        &csl::TransactionHash::from_bytes(vec![0x02; 32]).unwrap(),
        0,
    ));
    let mut body = csl::TransactionBody::new_tx_body(
        &inputs,
        &csl::TransactionOutputs::new(),
        &csl::BigNum::from(0u64),
    );
    body.set_validity_start_interval_bignum(&csl::BigNum::from(5_000u64));
    let witness_set = csl::TransactionWitnessSet::new();

    let mut ctx = preview_simple_context();
    ctx.slot = 1_000;

    let validator =
        TransactionLimitsValidator::new(10, &body, &witness_set, &ctx).unwrap();
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::OutsideValidityIntervalUTxO { .. }
        )),
        "expected OutsideValidityIntervalUTxO, got: {:?}",
        result.errors
    );
}

#[test]
fn spent_input_reports_bad_inputs_utxo() {
    let tx = parse_tx();
    let mut ctx = preview_simple_context();
    ctx.utxo_set[0].is_spent = true;

    let tx_size = PREVIEW_SIMPLE_TX_HEX.len() / 2;
    let validator =
        TransactionLimitsValidator::new(tx_size, &tx.body(), &tx.witness_set(), &ctx)
            .unwrap();
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::BadInputsUTxO { .. }
        )),
        "expected BadInputsUTxO, got: {:?}",
        result.errors
    );
}

#[test]
fn missing_input_utxo_also_reports_bad_inputs_utxo() {
    let tx = parse_tx();
    let mut ctx = preview_simple_context();
    // Empty utxo set → input can't be resolved → treated as spent/invalid.
    ctx.utxo_set.clear();

    let tx_size = PREVIEW_SIMPLE_TX_HEX.len() / 2;
    let validator =
        TransactionLimitsValidator::new(tx_size, &tx.body(), &tx.witness_set(), &ctx)
            .unwrap();
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::BadInputsUTxO { .. }
        )),
        "expected BadInputsUTxO for missing UTxO, got: {:?}",
        result.errors
    );
}

#[test]
fn empty_input_set_reports_input_set_empty() {
    // Build a minimal body with no inputs.
    let body = csl::TransactionBody::new_tx_body(
        &csl::TransactionInputs::new(),
        &csl::TransactionOutputs::new(),
        &csl::BigNum::from(0u64),
    );
    let witness_set = csl::TransactionWitnessSet::new();
    let ctx = preview_simple_context();

    let validator =
        TransactionLimitsValidator::new(10, &body, &witness_set, &ctx).unwrap();
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::InputSetEmptyUTxO
        )),
        "expected InputSetEmptyUTxO, got: {:?}",
        result.errors
    );
}

#[test]
fn reference_scripts_over_200kb_are_rejected() {
    // Put a >200KiB PlutusV2 script_ref behind a reference input.
    use crate::common::{Asset, TxInput, TxOutput, UTxO};
    use crate::validators::input_contexts::UtxoInputContext;

    let huge_payload = vec![0xAAu8; 205 * 1024];
    let huge_script = csl::PlutusScript::new_v2(huge_payload);
    let script_ref = csl::ScriptRef::new_plutus_script(&huge_script);
    let script_ref_hex = hex::encode(script_ref.to_bytes());

    let ref_tx_id = vec![0xDE; 32];
    let ref_input = csl::TransactionInput::new(
        &csl::TransactionHash::from_bytes(ref_tx_id.clone()).unwrap(),
        0,
    );
    let mut ref_inputs = csl::TransactionInputs::new();
    ref_inputs.add(&ref_input);

    let tx = parse_tx();
    let mut body = tx.body();
    body.set_reference_inputs(&ref_inputs);

    let mut ctx = preview_simple_context();
    ctx.utxo_set.push(UtxoInputContext {
        utxo: UTxO {
            input: TxInput {
                tx_hash: hex::encode(&ref_tx_id),
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
                script_hash: None,
            },
        },
        is_spent: false,
    });

    let tx_size = PREVIEW_SIMPLE_TX_HEX.len() / 2;
    let validator =
        TransactionLimitsValidator::new(tx_size, &body, &tx.witness_set(), &ctx)
            .unwrap();
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::RefScriptsSizeTooBig { .. }
        )),
        "expected RefScriptsSizeTooBig, got: {:?}",
        result.errors
    );
}

#[test]
fn ex_units_beyond_tx_budget_are_rejected() {
    // Attach a redeemer whose ex-units exceed the per-tx cap.
    let tx = parse_tx();
    let ctx = preview_simple_context();
    let redeemer = csl::Redeemer::new(
        &csl::RedeemerTag::new_spend(),
        &csl::BigNum::from(0u64),
        &csl::PlutusData::new_integer(&csl::BigInt::from(0)),
        &csl::ExUnits::new(
            &csl::BigNum::from(100_000_000u64), // max_tx mem = 14_000_000
            &csl::BigNum::from(100_000_000_000u64),
        ),
    );
    let mut redeemers = csl::Redeemers::new();
    redeemers.add(&redeemer);
    let mut witness_set = tx.witness_set();
    witness_set.set_redeemers(&redeemers);

    let tx_size = PREVIEW_SIMPLE_TX_HEX.len() / 2;
    let validator =
        TransactionLimitsValidator::new(tx_size, &tx.body(), &witness_set, &ctx)
            .unwrap();
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::ExUnitsTooBigUTxO { .. }
        )),
        "expected ExUnitsTooBigUTxO, got: {:?}",
        result.errors
    );
}

#[test]
fn reference_input_overlapping_with_spending_input_is_rejected() {
    // Same TransactionInput listed in both inputs and reference_inputs.
    let tx = parse_tx();
    let ctx = preview_simple_context();
    let first_input = tx.body().inputs().get(0);
    let mut ref_inputs = csl::TransactionInputs::new();
    ref_inputs.add(&first_input);
    let mut body = tx.body();
    body.set_reference_inputs(&ref_inputs);

    let tx_size = PREVIEW_SIMPLE_TX_HEX.len() / 2;
    let validator =
        TransactionLimitsValidator::new(tx_size, &body, &tx.witness_set(), &ctx)
            .unwrap();
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::ReferenceInputOverlapsWithInput { .. }
        )),
        "expected ReferenceInputOverlapsWithInput, got: {:?}",
        result.errors
    );
}

#[test]
fn withdrawals_not_sorted_emits_warning() {
    // Two withdrawals in a body-level Withdrawals collection. Withdrawals is
    // a LinkedHashMap → insertion order is preserved. Insert reward address
    // ending with 0xBB first, then 0xAA, and BTreeSet will reorder → unsorted.
    let cred_bb = csl::Credential::from_keyhash(
        &csl::Ed25519KeyHash::from_bytes(vec![0xBB; 28]).unwrap(),
    );
    let cred_aa = csl::Credential::from_keyhash(
        &csl::Ed25519KeyHash::from_bytes(vec![0xAA; 28]).unwrap(),
    );
    let reward_bb = csl::RewardAddress::new(
        csl::NetworkInfo::testnet_preview().network_id(),
        &cred_bb,
    );
    let reward_aa = csl::RewardAddress::new(
        csl::NetworkInfo::testnet_preview().network_id(),
        &cred_aa,
    );
    let mut withdrawals = csl::Withdrawals::new();
    withdrawals.insert(&reward_bb, &csl::BigNum::from(0u64));
    withdrawals.insert(&reward_aa, &csl::BigNum::from(0u64));

    let mut inputs = csl::TransactionInputs::new();
    inputs.add(&csl::TransactionInput::new(
        &csl::TransactionHash::from_bytes(vec![0x01; 32]).unwrap(),
        0,
    ));
    let mut body = csl::TransactionBody::new_tx_body(
        &inputs,
        &csl::TransactionOutputs::new(),
        &csl::BigNum::from(0u64),
    );
    body.set_withdrawals(&withdrawals);

    let witness_set = csl::TransactionWitnessSet::new();
    let ctx = preview_simple_context();
    let validator =
        TransactionLimitsValidator::new(10, &body, &witness_set, &ctx).unwrap();
    let result = validator.validate();

    assert!(
        result.warnings.iter().any(|w| matches!(
            w.warning,
            Phase1Warning::WithdrawalsAreNotSorted
        )),
        "expected WithdrawalsAreNotSorted warning, got: {:?}",
        result.warnings
    );
}

#[test]
fn unsorted_inputs_warning_fires_for_out_of_order_inputs() {
    // Two inputs referring to txids "bb..." then "aa...". The validator uses
    // lexicographic order for TransactionId.
    let mut inputs = csl::TransactionInputs::new();
    let id_b = csl::TransactionHash::from_bytes(vec![0xbb; 32]).unwrap();
    let id_a = csl::TransactionHash::from_bytes(vec![0xaa; 32]).unwrap();
    inputs.add(&csl::TransactionInput::new(&id_b, 0));
    inputs.add(&csl::TransactionInput::new(&id_a, 0));

    let body = csl::TransactionBody::new_tx_body(
        &inputs,
        &csl::TransactionOutputs::new(),
        &csl::BigNum::from(0u64),
    );
    let witness_set = csl::TransactionWitnessSet::new();
    let ctx = preview_simple_context();

    let validator =
        TransactionLimitsValidator::new(10, &body, &witness_set, &ctx).unwrap();
    let result = validator.validate();

    assert!(
        result.warnings.iter().any(|w| matches!(
            w.warning,
            Phase1Warning::InputsAreNotSorted
        )),
        "expected InputsAreNotSorted warning, got: {:?}",
        result.warnings
    );
}

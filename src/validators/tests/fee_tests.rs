//! Unit tests for [`crate::validators::phase_1::validation::FeeValidator`].
//!
//! The fee validator reproduces the ledger's `minfee` rule: it recomputes the
//! minimum acceptable fee from linear fee params + reference-script cost +
//! ex-units cost and compares against `tx_body.fee`. A shortfall is an error
//! (FeeTooSmallUTxO); an excess ≥10% is surfaced as a warning.

use crate::validators::phase_1::errors::{Phase1Error, Phase1Warning};
use crate::validators::phase_1::validation::fee::FeeValidator;
use crate::validators::tests::fixtures::{preview_simple_context, PREVIEW_SIMPLE_TX_HEX};
use cardano_serialization_lib as csl;

fn parse_tx() -> csl::FixedTransaction {
    csl::FixedTransaction::from_hex(PREVIEW_SIMPLE_TX_HEX).unwrap()
}

#[test]
fn fee_validator_accepts_fee_at_or_above_minimum() {
    // The preview fixture tx pays 200_000 lovelace. Its size-only min fee
    // under default params is ~170k, so it's slightly over — we should see no
    // error from the fee validator regardless (over-payment is never an error,
    // only an info-level warning if it exceeds the 10% slack).
    let tx = parse_tx();
    let ctx = preview_simple_context();
    let tx_size = PREVIEW_SIMPLE_TX_HEX.len() / 2;

    let validator =
        FeeValidator::new(tx_size, &tx.body(), &tx.witness_set(), &ctx).unwrap();
    let result = validator.validate();

    assert!(
        result.errors.is_empty(),
        "expected no fee errors, got: {:?}",
        result.errors
    );
}

#[test]
fn fee_too_small_reports_error_with_decomposition() {
    // Force expected min-fee far above the declared 200_000 lovelace fee by
    // jacking up the per-byte coefficient.
    let tx = parse_tx();
    let mut ctx = preview_simple_context();
    ctx.protocol_parameters.min_fee_coefficient_a = 10_000;

    let tx_size = PREVIEW_SIMPLE_TX_HEX.len() / 2;
    let validator =
        FeeValidator::new(tx_size, &tx.body(), &tx.witness_set(), &ctx).unwrap();
    let result = validator.validate();

    let fee_error = result.errors.iter().find(|e| {
        matches!(
            e.error,
            Phase1Error::FeeTooSmallUTxO {
                actual_fee: _,
                min_fee: _,
                fee_decomposition: _
            }
        )
    });
    assert!(fee_error.is_some(), "expected FeeTooSmallUTxO error");
    if let Some(err) = fee_error {
        if let Phase1Error::FeeTooSmallUTxO {
            actual_fee,
            min_fee,
            ..
        } = &err.error
        {
            assert_eq!(*actual_fee, 200_000);
            assert!(
                *min_fee > *actual_fee,
                "min_fee {} should exceed actual_fee {}",
                min_fee,
                actual_fee
            );
        }
    }
}

#[test]
fn fee_over_paid_emits_warning_but_no_error() {
    // Drive expected min-fee to basically zero so 200_000 is >10% over.
    let tx = parse_tx();
    let mut ctx = preview_simple_context();
    ctx.protocol_parameters.min_fee_coefficient_a = 0;
    ctx.protocol_parameters.min_fee_constant_b = 0;

    let tx_size = PREVIEW_SIMPLE_TX_HEX.len() / 2;
    let validator =
        FeeValidator::new(tx_size, &tx.body(), &tx.witness_set(), &ctx).unwrap();
    let result = validator.validate();

    assert!(
        result.errors.is_empty(),
        "no fee errors expected, got: {:?}",
        result.errors
    );
    assert!(
        result.warnings.iter().any(|w| matches!(
            w.warning,
            Phase1Warning::FeeIsBiggerThanMinFee { .. }
        )),
        "expected FeeIsBiggerThanMinFee warning, got: {:?}",
        result.warnings
    );
}

#[test]
fn reference_script_utxo_adds_to_expected_fee() {
    // Give the spending input a reference script blob. The validator's
    // reference-scripts fee = size_bytes * coins_per_byte, summed over all
    // UTxOs that the tx touches (spends + references).
    use crate::common::{Asset, TxInput, TxOutput, UTxO};
    use crate::validators::input_contexts::UtxoInputContext;

    let tx = parse_tx();
    let mut ctx = preview_simple_context();
    // Provide the spending input's UTxO plus a reference input carrying a
    // 200-byte script_ref. Fixture's base coin/byte for ref scripts = 15.
    let ref_tx_id = vec![0xC0; 32];
    let mut ref_inputs = csl::TransactionInputs::new();
    ref_inputs.add(&csl::TransactionInput::new(
        &csl::TransactionHash::from_bytes(ref_tx_id.clone()).unwrap(),
        0,
    ));
    let mut body = tx.body();
    body.set_reference_inputs(&ref_inputs);

    // Real PlutusV2 ScriptRef with 1000 raw UPLC bytes. `reference_script_size`
    // counts only the inner UPLC (= 1000), matching cardano-ledger's
    // originalBytesSize.
    let plutus_script = csl::PlutusScript::new_v2(vec![0x01; 1000]);
    let script_ref_hex = hex::encode(
        csl::ScriptRef::new_plutus_script(&plutus_script).to_bytes(),
    );
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
        FeeValidator::new(tx_size, &body, &tx.witness_set(), &ctx).unwrap();

    // Per cardano-ledger: raw UPLC size × 15 coins/byte in a single tier
    // (1000 < 25_600). 1000 × 15 = 15_000 lovelace.
    assert_eq!(
        validator.fee_decomposition.reference_scripts_fee, 15_000,
        "1000 byte plutus binary @ 15 coins/byte must produce 15_000 lovelace"
    );
    assert!(
        validator.expected_fee > validator.fee_decomposition.tx_size_fee,
        "expected_fee should include ref-script fee"
    );
}

#[test]
fn redeemer_execution_units_add_to_expected_fee() {
    // Attach a redeemer with a very large ex-units budget so the validator
    // computes a substantial execution_units_fee and flags the tx as
    // underpaid.
    let tx = parse_tx();
    let ctx = preview_simple_context();
    let redeemer = csl::Redeemer::new(
        &csl::RedeemerTag::new_spend(),
        &csl::BigNum::from(0u64),
        &csl::PlutusData::new_integer(&csl::BigInt::from(0)),
        &csl::ExUnits::new(
            &csl::BigNum::from(10_000_000u64),
            &csl::BigNum::from(5_000_000_000u64),
        ),
    );
    let mut redeemers = csl::Redeemers::new();
    redeemers.add(&redeemer);
    let mut witness_set = tx.witness_set();
    witness_set.set_redeemers(&redeemers);

    let tx_size = PREVIEW_SIMPLE_TX_HEX.len() / 2;
    let validator =
        FeeValidator::new(tx_size, &tx.body(), &witness_set, &ctx).unwrap();

    assert!(
        validator.fee_decomposition.execution_units_fee > 0,
        "redeemer must add execution_units_fee, got {}",
        validator.fee_decomposition.execution_units_fee
    );
    // actual_fee (200_000) can't possibly cover this — must fail.
    let result = validator.validate();
    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            crate::validators::phase_1::errors::Phase1Error::FeeTooSmallUTxO { .. }
        )),
        "expected FeeTooSmallUTxO once ex-units are priced in, got: {:?}",
        result.errors
    );
}

#[test]
fn same_script_bytes_in_two_utxos_are_counted_twice() {
    // cardano-ledger's txNonDistinctRefScriptsSize dedups by TxIn (set union)
    // but NOT by script hash. Two reference inputs carrying byte-identical
    // Plutus scripts must count twice.
    use crate::common::{Asset, TxInput, TxOutput, UTxO};
    use crate::validators::input_contexts::UtxoInputContext;

    let tx = parse_tx();
    let mut ctx = preview_simple_context();

    // Same script content placed under two different UTxOs.
    let plutus_script = csl::PlutusScript::new_v2(vec![0x02; 500]);
    let script_ref_hex = hex::encode(
        csl::ScriptRef::new_plutus_script(&plutus_script).to_bytes(),
    );

    let ref_tx_a = vec![0xAA; 32];
    let ref_tx_b = vec![0xBB; 32];
    let mut ref_inputs = csl::TransactionInputs::new();
    ref_inputs.add(&csl::TransactionInput::new(
        &csl::TransactionHash::from_bytes(ref_tx_a.clone()).unwrap(),
        0,
    ));
    ref_inputs.add(&csl::TransactionInput::new(
        &csl::TransactionHash::from_bytes(ref_tx_b.clone()).unwrap(),
        0,
    ));
    let mut body = tx.body();
    body.set_reference_inputs(&ref_inputs);

    for tx_hash_bytes in [ref_tx_a, ref_tx_b] {
        ctx.utxo_set.push(UtxoInputContext {
            utxo: UTxO {
                input: TxInput {
                    tx_hash: hex::encode(tx_hash_bytes),
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
                    script_ref: Some(script_ref_hex.clone()),
                    script_hash: None,
                },
            },
            is_spent: false,
        });
    }

    let tx_size = PREVIEW_SIMPLE_TX_HEX.len() / 2;
    let validator =
        FeeValidator::new(tx_size, &body, &tx.witness_set(), &ctx).unwrap();

    // 2 × 500 bytes × 15 coins/byte = 15_000 lovelace.
    assert_eq!(
        validator.fee_decomposition.reference_scripts_fee, 15_000,
        "identical scripts in two UTxOs must both be counted"
    );
}

#[test]
fn utxo_in_both_inputs_and_reference_inputs_is_counted_once() {
    // Set-union semantics: if the ref_input overlaps with a spending input,
    // the ref-script size must not double-count. (Overlap itself is flagged
    // by the limits validator, but fee computation already dedups.)
    use crate::common::{Asset, TxInput, TxOutput, UTxO};
    use crate::validators::input_contexts::UtxoInputContext;

    let tx = parse_tx();
    let mut ctx = preview_simple_context();
    let plutus_script = csl::PlutusScript::new_v2(vec![0x03; 500]);
    let script_ref_hex = hex::encode(
        csl::ScriptRef::new_plutus_script(&plutus_script).to_bytes(),
    );

    // Attach a script_ref to the actual spending input (first input of the
    // fixture tx) AND also list that same input as a reference input.
    let first_input = tx.body().inputs().get(0);
    let first_input_tx_hash = first_input.transaction_id().to_hex();
    let first_input_index = first_input.index();

    // Find the spending UTxO and attach a script_ref to it.
    if let Some(utxo) = ctx
        .utxo_set
        .iter_mut()
        .find(|u| u.utxo.input.tx_hash == first_input_tx_hash)
    {
        utxo.utxo.output.script_ref = Some(script_ref_hex);
    } else {
        // Safety net for fixture changes.
        ctx.utxo_set.push(UtxoInputContext {
            utxo: UTxO {
                input: TxInput {
                    tx_hash: first_input_tx_hash.clone(),
                    output_index: first_input_index,
                },
                output: TxOutput {
                    address: ctx.utxo_set[0].utxo.output.address.clone(),
                    amount: vec![Asset {
                        unit: "lovelace".to_string(),
                        quantity: "1221175714".to_string(),
                    }],
                    data_hash: None,
                    plutus_data: None,
                    script_ref: Some(script_ref_hex),
                    script_hash: None,
                },
            },
            is_spent: false,
        });
    }

    let mut ref_inputs = csl::TransactionInputs::new();
    ref_inputs.add(&first_input);
    let mut body = tx.body();
    body.set_reference_inputs(&ref_inputs);

    let tx_size = PREVIEW_SIMPLE_TX_HEX.len() / 2;
    let validator =
        FeeValidator::new(tx_size, &body, &tx.witness_set(), &ctx).unwrap();

    // Should be counted ONCE: 500 × 15 = 7_500 lovelace.
    assert_eq!(
        validator.fee_decomposition.reference_scripts_fee, 7_500,
        "a UTxO appearing in both inputs and reference_inputs must count once"
    );
}

#[test]
fn ref_script_fee_crosses_tier_boundary_at_25_6kib() {
    // cardano-ledger `tierRefScriptFee` uses size_increment = 25_600 bytes and
    // multiplier = 1.2. For a 30_000-byte script at base 15:
    //   first 25_600 bytes: 25_600 × 15 = 384_000
    //   next  4_400 bytes: 4_400  × 15 × 1.2 = 79_200
    //   total = 463_200 lovelace.
    use crate::common::{Asset, TxInput, TxOutput, UTxO};
    use crate::validators::input_contexts::UtxoInputContext;

    let tx = parse_tx();
    let mut ctx = preview_simple_context();
    let plutus_script = csl::PlutusScript::new_v2(vec![0x04; 30_000]);
    let script_ref_hex = hex::encode(
        csl::ScriptRef::new_plutus_script(&plutus_script).to_bytes(),
    );
    let ref_tx_id = vec![0xEE; 32];
    let mut ref_inputs = csl::TransactionInputs::new();
    ref_inputs.add(&csl::TransactionInput::new(
        &csl::TransactionHash::from_bytes(ref_tx_id.clone()).unwrap(),
        0,
    ));
    let mut body = tx.body();
    body.set_reference_inputs(&ref_inputs);

    ctx.utxo_set.push(UtxoInputContext {
        utxo: UTxO {
            input: TxInput {
                tx_hash: hex::encode(ref_tx_id),
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
        FeeValidator::new(tx_size, &body, &tx.witness_set(), &ctx).unwrap();

    assert_eq!(
        validator.fee_decomposition.reference_scripts_fee, 463_200,
        "multi-tier ref-script fee formula mismatch"
    );
}

#[test]
fn fee_decomposition_is_exposed_before_validation() {
    // Constructing the validator without running it should still produce the
    // decomposition — the CLI/UX surfaces it even on the happy path.
    let tx = parse_tx();
    let ctx = preview_simple_context();
    let tx_size = PREVIEW_SIMPLE_TX_HEX.len() / 2;

    let validator =
        FeeValidator::new(tx_size, &tx.body(), &tx.witness_set(), &ctx).unwrap();

    assert_eq!(validator.actual_fee, 200_000);
    // No ref-scripts and no redeemers in this tx.
    assert_eq!(validator.fee_decomposition.reference_scripts_fee, 0);
    assert_eq!(validator.fee_decomposition.execution_units_fee, 0);
    assert_eq!(
        validator.expected_fee,
        validator.fee_decomposition.tx_size_fee
    );
}

//! Unit tests for [`crate::validators::phase_1::validation::OutputValidator`].
//!
//! Mirrors the ledger's output checks from `Utxo` rule:
//! * Each output must carry at least `min_ada_for_output(coinsPerUTxOByte)`
//! * Serialized Value must fit under `maxValueSize`

use crate::validators::phase_1::errors::Phase1Error;
use crate::validators::phase_1::validation::OutputValidator;
use crate::validators::tests::fixtures::{preview_simple_context, PREVIEW_SIMPLE_TX_HEX};
use cardano_serialization_lib as csl;

fn parse_tx() -> csl::FixedTransaction {
    csl::FixedTransaction::from_hex(PREVIEW_SIMPLE_TX_HEX).unwrap()
}

#[test]
fn outputs_pass_under_default_parameters() {
    let tx = parse_tx();
    let ctx = preview_simple_context();

    let validator = OutputValidator::new(&tx.body(), &ctx);
    let result = validator.validate();

    assert!(
        result.errors.is_empty(),
        "expected no output errors, got: {:?}",
        result.errors
    );
    assert!(validator.oversized_outputs.is_empty());
    assert!(validator.outputs_below_min_ada.is_empty());
}

#[test]
fn output_below_min_ada_is_reported() {
    // Crank coinsPerUTxOByte so the current outputs fail the min-ada check.
    // min_ada ≈ (output_size + 160) * coinsPerUTxOByte, so 10^9 per byte is
    // guaranteed to fail for any reasonable output.
    let tx = parse_tx();
    let mut ctx = preview_simple_context();
    ctx.protocol_parameters.ada_per_utxo_byte = 1_000_000_000;

    let validator = OutputValidator::new(&tx.body(), &ctx);
    let result = validator.validate();

    let has_below_min = result.errors.iter().any(|e| {
        matches!(
            e.error,
            Phase1Error::OutputTooSmallUTxO {
                output_amount: _,
                min_amount: _
            }
        )
    });
    assert!(
        has_below_min,
        "expected OutputTooSmallUTxO error, got: {:?}",
        result.errors
    );
    // Both outputs in the test tx are well below the inflated min-ada.
    assert_eq!(validator.outputs_below_min_ada.len(), 2);
}

#[test]
fn output_value_too_big_triggers_error() {
    // Forcing maxValueSize to 1 byte makes every non-empty output oversize.
    let tx = parse_tx();
    let mut ctx = preview_simple_context();
    ctx.protocol_parameters.max_value_size = 1;

    let validator = OutputValidator::new(&tx.body(), &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::OutputsValueTooBig { .. }
        )),
        "expected OutputsValueTooBig error, got: {:?}",
        result.errors
    );
}

#[test]
fn output_exactly_at_min_ada_passes() {
    // Pick an address, compute its min-ada under default params, place the
    // output at exactly that amount — must pass.
    let addr = csl::Address::from_bech32(
        "addr_test1qre8tjm4mqhhxlzf9qqrn9r7fpy3nmsyfjpv9exw4uhjmpucfslttj9qrd94837wcn8uzwf5tg5dyjnweyvgw0z9ntwsl3q7la",
    )
    .unwrap();
    // Use a temp output to compute min_ada for the final shape.
    let provisional = csl::TransactionOutput::new(
        &addr,
        &csl::Value::new(&csl::BigNum::from(1_000_000u64)),
    );
    let ctx = preview_simple_context();
    let data_cost = csl::DataCost::new_coins_per_byte(
        &csl::BigNum::from(ctx.protocol_parameters.ada_per_utxo_byte),
    );
    let min_ada = csl::min_ada_for_output(&provisional, &data_cost).unwrap();

    let output = csl::TransactionOutput::new(&addr, &csl::Value::new(&min_ada));
    let mut outputs = csl::TransactionOutputs::new();
    outputs.add(&output);
    let body = csl::TransactionBody::new_tx_body(
        &csl::TransactionInputs::new(),
        &outputs,
        &csl::BigNum::from(0u64),
    );

    let validator = OutputValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        !result.errors.iter().any(|e| matches!(
            e.error,
            crate::validators::phase_1::errors::Phase1Error::OutputTooSmallUTxO { .. }
        )),
        "exactly min_ada must pass, got: {:?}",
        result.errors
    );
}

#[test]
fn output_one_lovelace_below_min_ada_fails() {
    let addr = csl::Address::from_bech32(
        "addr_test1qre8tjm4mqhhxlzf9qqrn9r7fpy3nmsyfjpv9exw4uhjmpucfslttj9qrd94837wcn8uzwf5tg5dyjnweyvgw0z9ntwsl3q7la",
    )
    .unwrap();
    let provisional = csl::TransactionOutput::new(
        &addr,
        &csl::Value::new(&csl::BigNum::from(1_000_000u64)),
    );
    let ctx = preview_simple_context();
    let data_cost = csl::DataCost::new_coins_per_byte(
        &csl::BigNum::from(ctx.protocol_parameters.ada_per_utxo_byte),
    );
    let min_ada: u64 = csl::min_ada_for_output(&provisional, &data_cost)
        .unwrap()
        .into();
    assert!(min_ada > 0);

    let output = csl::TransactionOutput::new(
        &addr,
        &csl::Value::new(&csl::BigNum::from(min_ada - 1)),
    );
    let mut outputs = csl::TransactionOutputs::new();
    outputs.add(&output);
    let body = csl::TransactionBody::new_tx_body(
        &csl::TransactionInputs::new(),
        &outputs,
        &csl::BigNum::from(0u64),
    );

    let validator = OutputValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            crate::validators::phase_1::errors::Phase1Error::OutputTooSmallUTxO { .. }
        )),
        "min_ada - 1 must fail, got: {:?}",
        result.errors
    );
}

#[test]
fn output_error_location_uses_output_index() {
    let tx = parse_tx();
    let mut ctx = preview_simple_context();
    ctx.protocol_parameters.ada_per_utxo_byte = 1_000_000_000;

    let validator = OutputValidator::new(&tx.body(), &ctx);
    let result = validator.validate();

    for err in &result.errors {
        for loc in &err.locations {
            assert!(
                loc.starts_with("transaction.body.outputs."),
                "expected output location, got: {}",
                loc
            );
        }
    }
}

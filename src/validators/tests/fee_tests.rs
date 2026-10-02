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

/// A transaction (987 bytes, a 4-element array ending in `f5 f6`) paying
/// exactly the minimum fee under a = 44, b = 155381:
/// 198 765 = 986 × 44 + 155 381. The ledger sizes it as
/// `[body, witnesses, auxiliary data]` (cardano-ledger Alonzo
/// `toCBORForSizeComputation`): its bytes without the `is_valid` flag.
const EXACT_MIN_FEE_TX_HEX: &str = concat!(
    "84a500d901028b8258200933a9ac5b7f3442da67b1d507c4a0ccdbfb838e81797b1caad284ee3a8fe9d30f82582019bf",
    "a24bfaaf19e17ef98652ecf1a542d269969110da49f8ccab7f072c98262005825820229ad6e337792e6c076e60b25ad8",
    "25db3d3bf2188616ac7bbc37cdaf858c09d9128258203622d6f302322b1c044725d946a2c7aa642577beeaeafea5596c",
    "512d3613e37801825820762e626a9eb13b6f59f1f206660a3582d240e9c43569eaa0081a91d40e49efb207825820865a",
    "14718d917908e39a9dd423da2a0ea065d25bdb605e1f0f223c596b2e939508825820c7440ef9b8f5e00af12174552adf",
    "7d93df75467ca8ebb1f1329724c950762b0609825820cd25c300400e15a75a423a79add2d72778e5690ddc473a2bef85",
    "b478d8cef4f007825820e568b0d6359de557cae26f9041bc1d3f0181e2817ce66fa9f1cef1179b74a04002825820eb83",
    "1f9e80c88cdbccc6038a64ab21c76a8784e12c6908de179bd668bc3b78610c825820fc2e58aaee88e8d503e9a56fd436",
    "e93638f4a588326ff124886226c4e5e7422c040181825839012563d19a3af61217a9d9ff1b523a874a7b2e7da5ed337c",
    "11837ea6f7bffd570ab0de092940d5d7590716c6141a1de1b44b67a42022bddfa01b00000003f930ff32021a0003086d",
    "05a1581de1f5fe8de787d0798542be9e729fe3f85ecec2af37ca6e049355ab13441b00000002cfef0f8313a18204581c",
    "77b0a93c26ac65be36e9a9f220f9a43cbc57d705fc5d8f1de5fdeea1a1825820c21b00f90f18fce4003edf42b0b0d455",
    "126e01c946e80cc5341a9f9750caf79500820182782c68747470733a2f2f616461737461742e6e65742f5f6d6574612f",
    "647265702f766f746538332e6a736f6e6c64582084fca71fb3b3632719fd8c0079743fa4956c5b4670c0faa01772dc52",
    "bc746184a100d90102838258203717ae838aa7955cad914f9b2167d70179f45197b4185e9f3f7927b8428c2fc1584099",
    "ecb3112974bf390d0780ff4fb8be6d168e667d740a469d3deb065d3c10ff45cae2083cd5c4bc59fa88d3a4a226237b64",
    "f0632aac69ff1e105bb261e9a3b906825820bee5fbb9341ad0bd08c4ff88b7669ec02db2ffb110e4e9f497a5060cef64",
    "db755840e3eec2cee4ea26cb5496f4c0c3650c7e8d4f116bc3c319f3cced994c477aa593626bee6ae249dcd110ef6208",
    "62cd149d2355dc45a781b10c84516c9c691ba40e8258209feb0eb50ee4874346190e334fb6b5a4599e579cc42b0feeab",
    "41fa374468b8e8584005faaeda96ba51e7178911c624864aba7c3e0280537c8e34f2c93ba84d565e6bb27f36866198c0",
    "c4126197e8ceb74c02406f615ad8fe6dcbb7ddb5308cec1701f5f6",
);

/// A context holding every input of [`EXACT_MIN_FEE_TX_HEX`] (as 1 ADA
/// at a key address; the balance is not what these tests check), under
/// a = 44, b = 155 381.
fn exact_min_fee_context() -> crate::validators::input_contexts::ValidationInputContext {
    use crate::validators::input_contexts::UtxoInputContext;
    let tx = csl::FixedTransaction::from_hex(EXACT_MIN_FEE_TX_HEX).unwrap();
    let inputs = tx.body().inputs();
    let mut ctx = preview_simple_context();
    ctx.network_type = crate::validators::common::NetworkType::Mainnet;
    ctx.utxo_set = (0..inputs.len())
        .map(|i| {
            let input = inputs.get(i);
            let utxo = format!(
                r#"{{"input":{{"outputIndex":{},"txHash":"{}"}},"output":{{"address":"addr1q9ykqfsvcgatem65ffslr7hw08jt9tksvwf727mx38z44eh4l6x70p7s0xz59057w20787z7emp27d72dczfx4dtzdzqgdwnls","amount":[{{"unit":"lovelace","quantity":"1000000"}}],"scriptHash":null}}}}"#,
                input.index(),
                input.transaction_id().to_hex()
            );
            UtxoInputContext {
                utxo: serde_json::from_str(&utxo).unwrap(),
                is_spent: false,
            }
        })
        .collect();
    ctx.protocol_parameters.min_fee_coefficient_a = 44;
    ctx.protocol_parameters.min_fee_constant_b = 155_381;
    ctx
}

fn fee_too_small(
    result: &crate::validators::validation_result::ValidationResult,
) -> Option<(u64, u64)> {
    result.errors.iter().find_map(|e| match &e.error {
        Phase1Error::FeeTooSmallUTxO {
            actual_fee,
            min_fee,
            ..
        } => Some((*actual_fee, *min_fee)),
        _ => None,
    })
}

#[test]
fn the_ledger_size_leaves_out_the_is_valid_flag() {
    let bytes = hex::decode(EXACT_MIN_FEE_TX_HEX).unwrap();
    assert_eq!(bytes.len(), 987);
    assert_eq!(crate::csl_preflight::ledger_tx_size(&bytes), Some(986));
    // A three-element transaction is measured whole; an indefinite-length
    // array by its components and one byte of header.
    assert_eq!(
        crate::csl_preflight::ledger_tx_size(&hex::decode("83a0a0f6").unwrap()),
        Some(4)
    );
    assert_eq!(
        crate::csl_preflight::ledger_tx_size(&hex::decode("9fa0a0f5f6ff").unwrap()),
        Some(4)
    );
    assert_eq!(
        crate::csl_preflight::ledger_tx_size(&hex::decode("82a0a0").unwrap()),
        None
    );
}

#[test]
fn a_transaction_paying_the_exact_ledger_minimum_fee_passes() {
    use crate::validators::validator::validate_transaction;
    let result = validate_transaction(EXACT_MIN_FEE_TX_HEX, exact_min_fee_context()).unwrap();
    assert_eq!(fee_too_small(&result), None, "{:?}", result.errors);
    // One lovelace more per byte: the minimum is priced on 986 bytes.
    let mut ctx = exact_min_fee_context();
    ctx.protocol_parameters.min_fee_coefficient_a = 45;
    let result = validate_transaction(EXACT_MIN_FEE_TX_HEX, ctx).unwrap();
    assert_eq!(fee_too_small(&result), Some((198_765, 986 * 45 + 155_381)));
}

#[test]
fn the_size_limit_holds_the_ledger_size() {
    use crate::validators::validator::validate_transaction;
    let too_big = |max: u32| {
        let mut ctx = exact_min_fee_context();
        ctx.protocol_parameters.max_transaction_size = max;
        validate_transaction(EXACT_MIN_FEE_TX_HEX, ctx)
            .unwrap()
            .errors
            .iter()
            .find_map(|e| match &e.error {
                Phase1Error::MaxTxSizeUTxO {
                    actual_size,
                    max_size,
                } => Some((*actual_size, *max_size)),
                _ => None,
            })
    };
    assert_eq!(too_big(986), None);
    assert_eq!(too_big(985), Some((986, 985)));
}

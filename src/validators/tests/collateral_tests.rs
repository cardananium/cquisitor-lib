//! Unit tests for
//! [`crate::validators::phase_1::validation::CollateralValidator`].
//!
//! Matches Babbage/Conway collateral rules:
//! * If the tx contains any redeemer, collateral is required
//! * Collateral ≥ fee * collateralPercentage / 100
//! * All collateral UTxOs must be key-locked, non-reward addresses, ADA-only
//! * Optional `collateral_return` must satisfy min-ada
//! * total_collateral (if declared) must equal sum(inputs) − collateral_return

use crate::common::{Asset, TxInput, TxOutput, UTxO};
use crate::validators::input_contexts::UtxoInputContext;
use crate::validators::phase_1::errors::{Phase1Error, Phase1Warning};
use crate::validators::phase_1::validation::CollateralValidator;
use crate::validators::tests::fixtures::preview_simple_context;
use cardano_serialization_lib as csl;

fn key_payment_address_bech32() -> String {
    // Standard preview base address used throughout the fixtures.
    "addr_test1qre8tjm4mqhhxlzf9qqrn9r7fpy3nmsyfjpv9exw4uhjmpucfslttj9qrd94837wcn8uzwf5tg5dyjnweyvgw0z9ntwsl3q7la".to_string()
}

fn mock_input(index: u32) -> csl::TransactionInput {
    let id = csl::TransactionHash::from_bytes(vec![index as u8; 32]).unwrap();
    csl::TransactionInput::new(&id, 0)
}

fn mock_utxo_ctx(index: u32, address: String, amount: Vec<Asset>) -> UtxoInputContext {
    UtxoInputContext {
        utxo: UTxO {
            input: TxInput {
                tx_hash: hex::encode(vec![index as u8; 32]),
                output_index: 0,
            },
            output: TxOutput {
                address,
                amount,
                data_hash: None,
                plutus_data: None,
                script_ref: None,
                script_hash: None,
            },
        },
        is_spent: false,
    }
}

fn build_body_with_redeemer_requirement(
    collateral: Option<csl::TransactionInputs>,
    total_collateral: Option<u64>,
    fee: u64,
) -> csl::TransactionBody {
    let mut body = csl::TransactionBody::new_tx_body(
        &csl::TransactionInputs::new(),
        &csl::TransactionOutputs::new(),
        &csl::BigNum::from(fee),
    );
    if let Some(collateral) = collateral {
        body.set_collateral(&collateral);
    }
    if let Some(total) = total_collateral {
        body.set_total_collateral(&csl::BigNum::from(total));
    }
    body
}

fn witness_set_with_one_redeemer() -> csl::TransactionWitnessSet {
    let mut witness_set = csl::TransactionWitnessSet::new();
    let redeemer = csl::Redeemer::new(
        &csl::RedeemerTag::new_spend(),
        &csl::BigNum::from(0u64),
        &csl::PlutusData::new_integer(&csl::BigInt::from(0)),
        &csl::ExUnits::new(&csl::BigNum::from(1u64), &csl::BigNum::from(1u64)),
    );
    let mut redeemers = csl::Redeemers::new();
    redeemers.add(&redeemer);
    witness_set.set_redeemers(&redeemers);
    witness_set
}

#[test]
fn no_redeemers_no_collateral_is_ok() {
    let body = build_body_with_redeemer_requirement(None, None, 200_000);
    let witness_set = csl::TransactionWitnessSet::new();
    let ctx = preview_simple_context();

    let validator = CollateralValidator::new(&body, &witness_set, &ctx);
    let result = validator.validate();

    assert!(!validator.need_collateral);
    assert!(
        result.errors.is_empty(),
        "no collateral is fine for non-script tx: {:?}",
        result.errors
    );
}

#[test]
fn script_tx_with_valid_collateral_has_no_errors_or_warnings() {
    // Single collateral input, pure-ADA, key-locked, total_collateral declared
    // and equal to the input sum, collateral covers 150% of fee: must pass
    // clean — no errors, no warnings.
    let mut collateral = csl::TransactionInputs::new();
    collateral.add(&mock_input(1));

    // Fee 200_000 → required = 300_000. Collateral input = 1 ADA, well over.
    let body = build_body_with_redeemer_requirement(
        Some(collateral),
        Some(1_000_000),
        200_000,
    );
    let witness_set = witness_set_with_one_redeemer();
    let mut ctx = preview_simple_context();
    ctx.utxo_set.push(mock_utxo_ctx(
        1,
        key_payment_address_bech32(),
        vec![Asset {
            unit: "lovelace".to_string(),
            quantity: "1000000".to_string(),
        }],
    ));

    let validator = CollateralValidator::new(&body, &witness_set, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.is_empty(),
        "valid collateral must produce no errors, got: {:?}",
        result.errors
    );
    assert!(
        result.warnings.is_empty(),
        "valid collateral must produce no warnings, got: {:?}",
        result.warnings
    );
}

#[test]
fn unnecessary_collateral_on_non_script_tx_emits_warning() {
    let mut collateral = csl::TransactionInputs::new();
    collateral.add(&mock_input(1));
    let body = build_body_with_redeemer_requirement(Some(collateral), None, 200_000);
    let witness_set = csl::TransactionWitnessSet::new();
    let mut ctx = preview_simple_context();
    ctx.utxo_set.push(mock_utxo_ctx(
        1,
        key_payment_address_bech32(),
        vec![Asset {
            unit: "lovelace".to_string(),
            quantity: "10_000_000".replace('_', ""),
        }],
    ));

    let validator = CollateralValidator::new(&body, &witness_set, &ctx);
    let result = validator.validate();

    assert!(
        result.warnings.iter().any(|w| matches!(
            w.warning,
            Phase1Warning::CollateralIsUnnecessary
        )),
        "expected CollateralIsUnnecessary warning, got: {:?}",
        result.warnings
    );
}

#[test]
fn script_tx_without_collateral_is_rejected() {
    let body = build_body_with_redeemer_requirement(None, None, 200_000);
    let witness_set = witness_set_with_one_redeemer();
    let ctx = preview_simple_context();

    let validator = CollateralValidator::new(&body, &witness_set, &ctx);
    let result = validator.validate();

    assert!(validator.need_collateral);
    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::NoCollateralInputs
        )),
        "expected NoCollateralInputs, got: {:?}",
        result.errors
    );
}

#[test]
fn insufficient_collateral_is_reported() {
    let mut collateral = csl::TransactionInputs::new();
    collateral.add(&mock_input(1));
    // Declared total = 10 lovelace but fee * 150% = 300_000. Sum is also 10
    // because the only collateral UTxO holds 10 lovelace.
    let body = build_body_with_redeemer_requirement(Some(collateral), Some(10), 200_000);
    let witness_set = witness_set_with_one_redeemer();
    let mut ctx = preview_simple_context();
    ctx.utxo_set.push(mock_utxo_ctx(
        1,
        key_payment_address_bech32(),
        vec![Asset {
            unit: "lovelace".to_string(),
            quantity: "10".to_string(),
        }],
    ));

    let validator = CollateralValidator::new(&body, &witness_set, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::InsufficientCollateral { .. }
        )),
        "expected InsufficientCollateral, got: {:?}",
        result.errors
    );
}

#[test]
fn collateral_with_non_ada_assets_is_rejected() {
    let mut collateral = csl::TransactionInputs::new();
    collateral.add(&mock_input(1));
    let body = build_body_with_redeemer_requirement(Some(collateral), None, 200_000);
    let witness_set = witness_set_with_one_redeemer();
    let mut ctx = preview_simple_context();
    // 10 ADA + a native asset in the collateral UTxO.
    ctx.utxo_set.push(mock_utxo_ctx(
        1,
        key_payment_address_bech32(),
        vec![
            Asset {
                unit: "lovelace".to_string(),
                quantity: "10000000".to_string(),
            },
            Asset {
                unit: "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0deadbeef".to_string(),
                quantity: "1".to_string(),
            },
        ],
    ));

    let validator = CollateralValidator::new(&body, &witness_set, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::CollateralInputContainsNonAdaAssets { .. }
        )),
        "expected CollateralInputContainsNonAdaAssets, got: {:?}",
        result.errors
    );
}

#[test]
fn too_many_collateral_inputs_is_rejected() {
    let mut collateral = csl::TransactionInputs::new();
    collateral.add(&mock_input(1));
    collateral.add(&mock_input(2));
    collateral.add(&mock_input(3));
    collateral.add(&mock_input(4));
    let body = build_body_with_redeemer_requirement(Some(collateral), None, 200_000);
    let witness_set = witness_set_with_one_redeemer();
    let mut ctx = preview_simple_context();
    for i in 1..=4 {
        ctx.utxo_set.push(mock_utxo_ctx(
            i,
            key_payment_address_bech32(),
            vec![Asset {
                unit: "lovelace".to_string(),
                quantity: "10000000".to_string(),
            }],
        ));
    }

    let validator = CollateralValidator::new(&body, &witness_set, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::TooManyCollateralInputs { .. }
        )),
        "expected TooManyCollateralInputs, got: {:?}",
        result.errors
    );
}

#[test]
fn calculated_collateral_with_non_ada_assets_is_rejected_when_return_present() {
    // With a collateral_return declared, the validator checks the *net*
    // (inputs − return). If inputs carry non-ADA assets that aren't fully
    // returned, the net contains tokens → error.
    let mut collateral = csl::TransactionInputs::new();
    collateral.add(&mock_input(1));

    let mut body = build_body_with_redeemer_requirement(Some(collateral), None, 200_000);
    // Collateral return = pure-ADA output to a preview address.
    let return_output = csl::TransactionOutput::new(
        &csl::Address::from_bech32(&key_payment_address_bech32()).unwrap(),
        &csl::Value::new(&csl::BigNum::from(5_000_000u64)),
    );
    body.set_collateral_return(&return_output);

    let witness_set = witness_set_with_one_redeemer();
    let mut ctx = preview_simple_context();
    ctx.utxo_set.push(mock_utxo_ctx(
        1,
        key_payment_address_bech32(),
        vec![
            Asset {
                unit: "lovelace".to_string(),
                quantity: "10000000".to_string(),
            },
            Asset {
                unit: "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0feeddeef"
                    .to_string(),
                quantity: "42".to_string(),
            },
        ],
    ));

    let validator = CollateralValidator::new(&body, &witness_set, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::CalculatedCollateralContainsNonAdaAssets
        )),
        "expected CalculatedCollateralContainsNonAdaAssets, got: {:?}",
        result.errors
    );
}

#[test]
fn collateral_return_below_min_ada_is_rejected() {
    // Build a collateral_return whose declared coin is far below the min-ada
    // for that output size under the fixture coins_per_byte.
    let mut collateral = csl::TransactionInputs::new();
    collateral.add(&mock_input(1));

    let mut body = build_body_with_redeemer_requirement(Some(collateral), None, 200_000);
    let tiny_return = csl::TransactionOutput::new(
        &csl::Address::from_bech32(&key_payment_address_bech32()).unwrap(),
        &csl::Value::new(&csl::BigNum::from(1u64)), // 1 lovelace, way below min-ada
    );
    body.set_collateral_return(&tiny_return);

    let witness_set = witness_set_with_one_redeemer();
    let mut ctx = preview_simple_context();
    ctx.utxo_set.push(mock_utxo_ctx(
        1,
        key_payment_address_bech32(),
        vec![Asset {
            unit: "lovelace".to_string(),
            quantity: "10000000".to_string(),
        }],
    ));

    let validator = CollateralValidator::new(&body, &witness_set, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::CollateralReturnTooSmall { .. }
        )),
        "expected CollateralReturnTooSmall, got: {:?}",
        result.errors
    );
}

#[test]
fn collateral_input_from_reward_address_emits_warning() {
    // Reward-address inputs make no sense as collateral (the ledger doesn't
    // spend from reward accounts this way). The validator surfaces a warning.
    let mut collateral = csl::TransactionInputs::new();
    collateral.add(&mock_input(1));

    let body = build_body_with_redeemer_requirement(Some(collateral), None, 200_000);
    let witness_set = witness_set_with_one_redeemer();
    let mut ctx = preview_simple_context();

    let cred = csl::Credential::from_keyhash(
        &csl::Ed25519KeyHash::from_bytes(vec![0xAA; 28]).unwrap(),
    );
    let reward_addr = csl::RewardAddress::new(
        csl::NetworkInfo::testnet_preview().network_id(),
        &cred,
    );
    ctx.utxo_set.push(mock_utxo_ctx(
        1,
        reward_addr.to_address().to_bech32(None).unwrap(),
        vec![Asset {
            unit: "lovelace".to_string(),
            quantity: "10000000".to_string(),
        }],
    ));

    let validator = CollateralValidator::new(&body, &witness_set, &ctx);
    let result = validator.validate();

    assert!(
        result.warnings.iter().any(|w| matches!(
            w.warning,
            Phase1Warning::CollateralInputUsesRewardAddress { .. }
        )),
        "expected CollateralInputUsesRewardAddress warning, got: {:?}",
        result.warnings
    );
}

#[test]
fn incorrect_total_collateral_field_is_rejected() {
    let mut collateral = csl::TransactionInputs::new();
    collateral.add(&mock_input(1));
    // Declared total = 500_000 but actual input = 10_000_000.
    let body = build_body_with_redeemer_requirement(Some(collateral), Some(500_000), 200_000);
    let witness_set = witness_set_with_one_redeemer();
    let mut ctx = preview_simple_context();
    ctx.utxo_set.push(mock_utxo_ctx(
        1,
        key_payment_address_bech32(),
        vec![Asset {
            unit: "lovelace".to_string(),
            quantity: "10000000".to_string(),
        }],
    ));

    let validator = CollateralValidator::new(&body, &witness_set, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::IncorrectTotalCollateralField { .. }
        )),
        "expected IncorrectTotalCollateralField, got: {:?}",
        result.errors
    );
}

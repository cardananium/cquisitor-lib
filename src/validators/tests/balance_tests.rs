//! Unit tests for [`crate::validators::phase_1::validation::BalanceValidator`].
//!
//! Reflects the UTXO conservation rule from cardano-ledger:
//! `consumed(pp, utxo, tx) == produced(pp, tx)`, where `consumed` sums inputs,
//! withdrawals and refunds and `produced` sums outputs, fees, deposits,
//! donation and burn.

use crate::validators::input_contexts::AccountInputContext;
use crate::validators::phase_1::errors::Phase1Error;
use crate::validators::phase_1::validation::BalanceValidator;
use crate::validators::tests::fixtures::{preview_simple_context, PREVIEW_SIMPLE_TX_HEX};
use cardano_serialization_lib as csl;

fn parse_tx() -> csl::FixedTransaction {
    csl::FixedTransaction::from_hex(PREVIEW_SIMPLE_TX_HEX).unwrap()
}

#[test]
fn balanced_tx_produces_no_errors() {
    // The fixture tx consumes a single UTxO and produces two outputs plus
    // 200_000 lovelace in fees. We adjust the UTxO quantity so consumed ==
    // produced; the default fixture intentionally records the captured on-chain
    // balance (which may not perfectly reconcile — the baseline test in
    // validator.rs just logs the discrepancy rather than asserting on it).
    let tx = parse_tx();
    let mut ctx = preview_simple_context();
    let produced: i128 = (0..tx.body().outputs().len())
        .map(|i| {
            tx.body()
                .outputs()
                .get(i)
                .amount()
                .coin()
                .to_str()
                .parse::<i128>()
                .unwrap()
        })
        .sum::<i128>()
        + tx.body().fee().to_str().parse::<i128>().unwrap();
    ctx.utxo_set[0].utxo.output.amount[0].quantity = produced.to_string();

    let validator = BalanceValidator::new(&tx.body(), &ctx);
    let result = validator.validate();

    assert!(
        result.errors.is_empty(),
        "expected balanced tx to pass, got: {:?}",
        result.errors
    );
}

#[test]
fn inflating_input_triggers_value_not_conserved() {
    // If the ledger claims the UTxO held more lovelace than the tx spends,
    // the conservation check should fail.
    let tx = parse_tx();
    let mut ctx = preview_simple_context();
    ctx.utxo_set[0].utxo.output.amount[0].quantity = "9999999999".to_string();

    let validator = BalanceValidator::new(&tx.body(), &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::ValueNotConservedUTxO { .. }
        )),
        "expected ValueNotConservedUTxO, got: {:?}",
        result.errors
    );
}

#[test]
fn deflating_input_also_triggers_value_not_conserved() {
    let tx = parse_tx();
    let mut ctx = preview_simple_context();
    ctx.utxo_set[0].utxo.output.amount[0].quantity = "100".to_string();

    let validator = BalanceValidator::new(&tx.body(), &ctx);
    let result = validator.validate();

    let err = result
        .errors
        .iter()
        .find(|e| matches!(e.error, Phase1Error::ValueNotConservedUTxO { .. }))
        .expect("expected ValueNotConservedUTxO");
    if let Phase1Error::ValueNotConservedUTxO {
        input_sum,
        output_sum,
        ..
    } = &err.error
    {
        assert!(
            output_sum.coins > input_sum.coins,
            "outputs ({}) should exceed inputs ({}) in this test",
            output_sum.coins,
            input_sum.coins
        );
    }
}

#[test]
fn treasury_value_mismatch_is_reported_when_body_declares_it() {
    // Construct a minimal body that declares a current_treasury_value which
    // disagrees with the provided ledger state.
    let mut body = csl::TransactionBody::new_tx_body(
        &csl::TransactionInputs::new(),
        &csl::TransactionOutputs::new(),
        &csl::BigNum::from(0u64),
    );
    body.set_current_treasury_value(&csl::BigNum::from(12345u64));

    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.treasury_value = 99999;

    let validator = BalanceValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::TreasuryValueMismatch { .. }
        )),
        "expected TreasuryValueMismatch, got: {:?}",
        result.errors
    );
}

#[test]
fn withdrawal_from_unknown_account_is_rejected() {
    // Build a body with a single withdrawal but no matching account context.
    let cred = csl::Credential::from_keyhash(
        &csl::Ed25519KeyHash::from_bytes(vec![1u8; 28]).unwrap(),
    );
    let reward_address = csl::RewardAddress::new(
        csl::NetworkInfo::testnet_preview().network_id(),
        &cred,
    );
    let mut withdrawals = csl::Withdrawals::new();
    withdrawals.insert(&reward_address, &csl::BigNum::from(1_000u64));

    let mut body = csl::TransactionBody::new_tx_body(
        &csl::TransactionInputs::new(),
        &csl::TransactionOutputs::new(),
        &csl::BigNum::from(0u64),
    );
    body.set_withdrawals(&withdrawals);

    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();

    let validator = BalanceValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::RewardAccountNotExisting { .. }
        )),
        "expected RewardAccountNotExisting, got: {:?}",
        result.errors
    );
}

#[test]
fn withdrawal_from_explicitly_deregistered_account_is_rejected() {
    // The ledger knows about this stake credential but its registration has
    // been withdrawn. `is_registered: false` must be treated identically to
    // "no such account at all" — both yield `RewardAccountNotExisting`.
    let cred = csl::Credential::from_keyhash(
        &csl::Ed25519KeyHash::from_bytes(vec![0x45; 28]).unwrap(),
    );
    let reward_address = csl::RewardAddress::new(
        csl::NetworkInfo::testnet_preview().network_id(),
        &cred,
    );
    let bech32 = reward_address.to_address().to_bech32(None).unwrap();

    let mut withdrawals = csl::Withdrawals::new();
    withdrawals.insert(&reward_address, &csl::BigNum::from(1_000u64));

    let mut body = csl::TransactionBody::new_tx_body(
        &csl::TransactionInputs::new(),
        &csl::TransactionOutputs::new(),
        &csl::BigNum::from(0u64),
    );
    body.set_withdrawals(&withdrawals);

    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.account_contexts.push(AccountInputContext {
        bech32_address: bech32,
        is_registered: false, // <-- seen by ledger, but not currently registered
        payed_deposit: None,
        delegated_to_drep: None,
        delegated_to_pool: None,
        balance: Some(1_000), // balance field is ignored while unregistered
    });

    let validator = BalanceValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::RewardAccountNotExisting { .. }
        )),
        "expected RewardAccountNotExisting for deregistered account, got: {:?}",
        result.errors
    );

    // And: the amount-mismatch check must be short-circuited — we do not
    // report *both* errors because that would be misleading.
    assert!(
        !result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::WrongRequestedWithdrawalAmount { .. }
        )),
        "unregistered account must not also trigger amount-mismatch"
    );
}

#[test]
fn withdrawal_exactly_matching_balance_is_accepted() {
    // Per cardano-ledger SHELLEY-WDRL rule: `Map.map (const Coin 0) wdrls ==
    // Map.intersection rewards wdrls`. You must withdraw *exactly* the
    // available rewards on each account — no less, no more.
    let cred = csl::Credential::from_keyhash(
        &csl::Ed25519KeyHash::from_bytes(vec![0x42; 28]).unwrap(),
    );
    let reward_address = csl::RewardAddress::new(
        csl::NetworkInfo::testnet_preview().network_id(),
        &cred,
    );
    let bech32 = reward_address.to_address().to_bech32(None).unwrap();

    let mut withdrawals = csl::Withdrawals::new();
    withdrawals.insert(&reward_address, &csl::BigNum::from(1_000u64));

    let mut body = csl::TransactionBody::new_tx_body(
        &csl::TransactionInputs::new(),
        &csl::TransactionOutputs::new(),
        &csl::BigNum::from(0u64),
    );
    body.set_withdrawals(&withdrawals);

    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.account_contexts.push(AccountInputContext {
        bech32_address: bech32,
        is_registered: true,
        payed_deposit: None,
        delegated_to_drep: Some("drep_always_abstain".to_string()),
        delegated_to_pool: None,
        balance: Some(1_000),
    });

    let validator = BalanceValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        !result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::WrongRequestedWithdrawalAmount { .. }
        )),
        "exact balance match must pass, got: {:?}",
        result.errors
    );
}

#[test]
fn withdrawal_over_available_balance_is_rejected() {
    // Withdraw 1_500 lovelace while the account has only 1_000 available —
    // over-withdraw must be flagged the same way as under-withdraw.
    let cred = csl::Credential::from_keyhash(
        &csl::Ed25519KeyHash::from_bytes(vec![0x43; 28]).unwrap(),
    );
    let reward_address = csl::RewardAddress::new(
        csl::NetworkInfo::testnet_preview().network_id(),
        &cred,
    );
    let bech32 = reward_address.to_address().to_bech32(None).unwrap();

    let mut withdrawals = csl::Withdrawals::new();
    withdrawals.insert(&reward_address, &csl::BigNum::from(1_500u64));

    let mut body = csl::TransactionBody::new_tx_body(
        &csl::TransactionInputs::new(),
        &csl::TransactionOutputs::new(),
        &csl::BigNum::from(0u64),
    );
    body.set_withdrawals(&withdrawals);

    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.account_contexts.push(AccountInputContext {
        bech32_address: bech32,
        is_registered: true,
        payed_deposit: None,
        delegated_to_drep: Some("drep_always_abstain".to_string()),
        delegated_to_pool: None,
        balance: Some(1_000),
    });

    let validator = BalanceValidator::new(&body, &ctx);
    let result = validator.validate();

    let err = result
        .errors
        .iter()
        .find(|e| matches!(e.error, Phase1Error::WrongRequestedWithdrawalAmount { .. }))
        .expect("expected WrongRequestedWithdrawalAmount on over-withdraw");
    if let Phase1Error::WrongRequestedWithdrawalAmount {
        expected_amount,
        requested_amount,
        ..
    } = &err.error
    {
        assert_eq!(*expected_amount, 1_000);
        assert_eq!(*requested_amount, 1_500);
    }
}

#[test]
fn withdrawal_with_unknown_balance_is_not_flagged() {
    // If the ledger state we've been handed doesn't know the current reward
    // balance, the validator must NOT fabricate a mismatch error. The
    // per-amount check fires only when we have ground truth.
    let cred = csl::Credential::from_keyhash(
        &csl::Ed25519KeyHash::from_bytes(vec![0x44; 28]).unwrap(),
    );
    let reward_address = csl::RewardAddress::new(
        csl::NetworkInfo::testnet_preview().network_id(),
        &cred,
    );
    let bech32 = reward_address.to_address().to_bech32(None).unwrap();

    let mut withdrawals = csl::Withdrawals::new();
    withdrawals.insert(&reward_address, &csl::BigNum::from(1_000u64));

    let mut body = csl::TransactionBody::new_tx_body(
        &csl::TransactionInputs::new(),
        &csl::TransactionOutputs::new(),
        &csl::BigNum::from(0u64),
    );
    body.set_withdrawals(&withdrawals);

    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.account_contexts.push(AccountInputContext {
        bech32_address: bech32,
        is_registered: true,
        payed_deposit: None,
        delegated_to_drep: Some("drep_always_abstain".to_string()),
        delegated_to_pool: None,
        balance: None,
    });

    let validator = BalanceValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        !result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::WrongRequestedWithdrawalAmount { .. }
        )),
        "unknown balance must not trigger amount-mismatch, got: {:?}",
        result.errors
    );
}

#[test]
fn withdrawal_amount_mismatch_is_rejected() {
    let cred = csl::Credential::from_keyhash(
        &csl::Ed25519KeyHash::from_bytes(vec![2u8; 28]).unwrap(),
    );
    let reward_address = csl::RewardAddress::new(
        csl::NetworkInfo::testnet_preview().network_id(),
        &cred,
    );
    let bech32 = reward_address.to_address().to_bech32(None).unwrap();

    let mut withdrawals = csl::Withdrawals::new();
    withdrawals.insert(&reward_address, &csl::BigNum::from(500u64));

    let mut body = csl::TransactionBody::new_tx_body(
        &csl::TransactionInputs::new(),
        &csl::TransactionOutputs::new(),
        &csl::BigNum::from(0u64),
    );
    body.set_withdrawals(&withdrawals);

    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    // The ledger says this account's available rewards = 1000, but the tx
    // withdraws only 500. Cardano-ledger requires withdraw == available.
    ctx.account_contexts.push(AccountInputContext {
        bech32_address: bech32,
        is_registered: true,
        payed_deposit: None,
        delegated_to_drep: Some("drep_always_abstain".to_string()),
        delegated_to_pool: None,
        balance: Some(1_000),
    });

    let validator = BalanceValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::WrongRequestedWithdrawalAmount { .. }
        )),
        "expected WrongRequestedWithdrawalAmount, got: {:?}",
        result.errors
    );
}

#[test]
fn donation_is_counted_on_the_produced_side() {
    // Body declares 500 lovelace donation. For conservation to hold,
    // consumed (= input coin) must equal produced (= fee + donation).
    // Under-supply is caught by ValueNotConservedUTxO.
    let mut body = csl::TransactionBody::new_tx_body(
        &csl::TransactionInputs::new(),
        &csl::TransactionOutputs::new(),
        &csl::BigNum::from(0u64),
    );
    body.set_donation(&csl::BigNum::from(500u64));

    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();

    let validator = BalanceValidator::new(&body, &ctx);
    let result = validator.validate();

    let err = result
        .errors
        .iter()
        .find(|e| matches!(e.error, Phase1Error::ValueNotConservedUTxO { .. }))
        .expect("expected ValueNotConservedUTxO when donation is unfunded");
    if let Phase1Error::ValueNotConservedUTxO { output_sum, .. } = &err.error {
        assert_eq!(
            output_sum.coins, 500,
            "donation must appear on the produced side"
        );
    }
}

#[test]
fn positive_mint_adds_to_consumed_side() {
    // Build a tx body that mints 1 unit of an asset. Value conservation
    // should see +1 token on the consumed side. An output that spends that
    // token back out balances the equation.
    let policy_hash = csl::ScriptHash::from_bytes(vec![0xA0; 28]).unwrap();
    let asset_name = csl::AssetName::new(b"FOO".to_vec()).unwrap();
    let mut mint_assets = csl::MintAssets::new();
    mint_assets
        .insert(&asset_name, &csl::Int::new_i32(1))
        .unwrap();
    let mut mint = csl::Mint::new();
    mint.insert(&policy_hash, &mint_assets);

    // Output carrying the minted token (spends it to a preview address).
    let mut asset_map = csl::Assets::new();
    asset_map.insert(&asset_name, &csl::BigNum::from(1u64));
    let mut multi = csl::MultiAsset::new();
    multi.insert(&policy_hash, &asset_map);
    let mut value = csl::Value::new(&csl::BigNum::from(0u64));
    value.set_multiasset(&multi);
    let output = csl::TransactionOutput::new(
        &csl::Address::from_bech32(
            "addr_test1qre8tjm4mqhhxlzf9qqrn9r7fpy3nmsyfjpv9exw4uhjmpucfslttj9qrd94837wcn8uzwf5tg5dyjnweyvgw0z9ntwsl3q7la",
        )
        .unwrap(),
        &value,
    );
    let mut outputs = csl::TransactionOutputs::new();
    outputs.add(&output);

    let mut body = csl::TransactionBody::new_tx_body(
        &csl::TransactionInputs::new(),
        &outputs,
        &csl::BigNum::from(0u64),
    );
    body.set_mint(&mint);

    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();

    let validator = BalanceValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.is_empty(),
        "mint + matching output should balance, got: {:?}",
        result.errors
    );
}

#[test]
fn negative_mint_burn_adds_to_produced_side() {
    // Burn 1 unit of an asset that came in via an input UTxO. Value
    // conservation: consumed (input token) = produced (burn).
    let policy_hex = "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";
    let asset_name_hex = "464f4f"; // "FOO" hex
    let unit = format!("{}{}", policy_hex, asset_name_hex);

    // Input carrying the token.
    let mut ctx = preview_simple_context();
    ctx.utxo_set[0].utxo.output.amount = vec![
        crate::common::Asset {
            unit: "lovelace".to_string(),
            quantity: "0".to_string(),
        },
        crate::common::Asset {
            unit: unit.clone(),
            quantity: "1".to_string(),
        },
    ];

    // Tx body: burn 1 FOO, no outputs, no fee.
    let policy_hash =
        csl::ScriptHash::from_bytes(hex::decode(policy_hex).unwrap()).unwrap();
    let asset_name =
        csl::AssetName::new(hex::decode(asset_name_hex).unwrap()).unwrap();
    let mut mint_assets = csl::MintAssets::new();
    mint_assets
        .insert(&asset_name, &csl::Int::new_negative(&csl::BigNum::from(1u64)))
        .unwrap();
    let mut mint = csl::Mint::new();
    mint.insert(&policy_hash, &mint_assets);

    let mut inputs = csl::TransactionInputs::new();
    inputs.add(&csl::TransactionInput::new(
        &csl::TransactionHash::from_bytes(
            hex::decode(&ctx.utxo_set[0].utxo.input.tx_hash).unwrap(),
        )
        .unwrap(),
        ctx.utxo_set[0].utxo.input.output_index,
    ));
    let mut body = csl::TransactionBody::new_tx_body(
        &inputs,
        &csl::TransactionOutputs::new(),
        &csl::BigNum::from(0u64),
    );
    body.set_mint(&mint);

    let validator = BalanceValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.is_empty(),
        "burn must balance input token, got: {:?}",
        result.errors
    );
}

#[test]
fn key_hash_withdrawal_without_drep_delegation_is_rejected() {
    // Conway DRep gate: withdrawals from key-hash stake creds require the
    // account to already be delegated to some DRep.
    let cred = csl::Credential::from_keyhash(
        &csl::Ed25519KeyHash::from_bytes(vec![3u8; 28]).unwrap(),
    );
    let reward_address = csl::RewardAddress::new(
        csl::NetworkInfo::testnet_preview().network_id(),
        &cred,
    );
    let bech32 = reward_address.to_address().to_bech32(None).unwrap();

    let mut withdrawals = csl::Withdrawals::new();
    withdrawals.insert(&reward_address, &csl::BigNum::from(1_000u64));

    let mut body = csl::TransactionBody::new_tx_body(
        &csl::TransactionInputs::new(),
        &csl::TransactionOutputs::new(),
        &csl::BigNum::from(0u64),
    );
    body.set_withdrawals(&withdrawals);

    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.account_contexts.push(AccountInputContext {
        bech32_address: bech32,
        is_registered: true,
        payed_deposit: None,
        delegated_to_drep: None, // <-- no DRep
        delegated_to_pool: None,
        balance: Some(1_000),
    });

    let validator = BalanceValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::WithdrawalNotAllowedBecauseNotDelegatedToDRep { .. }
        )),
        "expected WithdrawalNotAllowedBecauseNotDelegatedToDRep, got: {:?}",
        result.errors
    );
}

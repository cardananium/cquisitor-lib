//! Unit tests for
//! [`crate::validators::phase_1::validation::NetworkValidator`].
//!
//! cardano-ledger enforces network-id consistency at multiple points in the
//! UTXO / GOV rules. This file covers each of them.

use crate::validators::common::NetworkType;
use crate::validators::phase_1::errors::Phase1Error;
use crate::validators::phase_1::validation::NetworkValidator;
use crate::validators::tests::fixtures::preview_simple_context;
use cardano_serialization_lib as csl;

fn preview_id() -> u8 {
    csl::NetworkInfo::testnet_preview().network_id()
}

fn mainnet_id() -> u8 {
    csl::NetworkInfo::mainnet().network_id()
}

fn preview_stake_cred() -> csl::Credential {
    csl::Credential::from_keyhash(
        &csl::Ed25519KeyHash::from_bytes(vec![0x11; 28]).unwrap(),
    )
}

fn base_address(net: u8) -> csl::Address {
    let payment = csl::Credential::from_keyhash(
        &csl::Ed25519KeyHash::from_bytes(vec![0x22; 28]).unwrap(),
    );
    let stake = preview_stake_cred();
    csl::BaseAddress::new(net, &payment, &stake).to_address()
}

fn empty_body() -> csl::TransactionBody {
    csl::TransactionBody::new_tx_body(
        &csl::TransactionInputs::new(),
        &csl::TransactionOutputs::new(),
        &csl::BigNum::from(0u64),
    )
}

#[test]
fn all_preview_addresses_pass_happy_path() {
    // Fixture context is Preview; outputs belong to preview → no errors.
    let output = csl::TransactionOutput::new(
        &base_address(preview_id()),
        &csl::Value::new(&csl::BigNum::from(1_000_000u64)),
    );
    let mut outputs = csl::TransactionOutputs::new();
    outputs.add(&output);
    let body = csl::TransactionBody::new_tx_body(
        &csl::TransactionInputs::new(),
        &outputs,
        &csl::BigNum::from(0u64),
    );

    let ctx = preview_simple_context();
    let validator = NetworkValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.is_empty(),
        "preview output on preview ledger must pass, got: {:?}",
        result.errors
    );
}

#[test]
fn mainnet_output_on_preview_ledger_is_rejected() {
    let output = csl::TransactionOutput::new(
        &base_address(mainnet_id()),
        &csl::Value::new(&csl::BigNum::from(1_000_000u64)),
    );
    let mut outputs = csl::TransactionOutputs::new();
    outputs.add(&output);
    let body = csl::TransactionBody::new_tx_body(
        &csl::TransactionInputs::new(),
        &outputs,
        &csl::BigNum::from(0u64),
    );

    let ctx = preview_simple_context();
    let validator = NetworkValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::WrongNetwork { .. }
        )),
        "expected WrongNetwork, got: {:?}",
        result.errors
    );
}

#[test]
fn mainnet_withdrawal_on_preview_ledger_is_rejected() {
    let mainnet_reward =
        csl::RewardAddress::new(mainnet_id(), &preview_stake_cred());
    let mut withdrawals = csl::Withdrawals::new();
    withdrawals.insert(&mainnet_reward, &csl::BigNum::from(0u64));

    let mut body = empty_body();
    body.set_withdrawals(&withdrawals);

    let ctx = preview_simple_context();
    let validator = NetworkValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::WrongNetworkWithdrawal { .. }
        )),
        "expected WrongNetworkWithdrawal, got: {:?}",
        result.errors
    );
}

#[test]
fn body_network_id_mismatch_is_rejected() {
    // tx_body.network_id set to Mainnet while ledger says Preview.
    let mut body = empty_body();
    body.set_network_id(&csl::NetworkId::mainnet());

    let ctx = preview_simple_context();
    let validator = NetworkValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::WrongNetworkInTxBody { .. }
        )),
        "expected WrongNetworkInTxBody, got: {:?}",
        result.errors
    );
}

#[test]
fn body_network_id_testnet_on_preview_passes() {
    // NetworkId has only Mainnet / Testnet variants. Testnet maps to any
    // testnet network id (0). Preview ledger should accept it.
    let mut body = empty_body();
    body.set_network_id(&csl::NetworkId::testnet());

    let ctx = preview_simple_context();
    let validator = NetworkValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        !result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::WrongNetworkInTxBody { .. }
        )),
        "testnet network_id must pass on preview: {:?}",
        result.errors
    );
}

#[test]
fn proposal_return_account_on_wrong_network_is_rejected() {
    let mainnet_reward =
        csl::RewardAddress::new(mainnet_id(), &preview_stake_cred());
    let anchor = csl::Anchor::new(
        &csl::URL::new("https://example.com/p.json".to_string()).unwrap(),
        &csl::AnchorDataHash::from_bytes(vec![0x33; 32]).unwrap(),
    );
    let gov_action = csl::GovernanceAction::new_info_action(&csl::InfoAction::new());
    let proposal = csl::VotingProposal::new(
        &gov_action,
        &anchor,
        &mainnet_reward,
        &csl::BigNum::from(100_000_000_000u64),
    );
    let mut proposals = csl::VotingProposals::new();
    proposals.add(&proposal);

    let mut body = empty_body();
    body.set_voting_proposals(&proposals);

    let ctx = preview_simple_context();
    let validator = NetworkValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::ProposalProcedureNetworkIdMismatch { .. }
        )),
        "expected ProposalProcedureNetworkIdMismatch, got: {:?}",
        result.errors
    );
}

#[test]
fn treasury_withdrawal_account_on_wrong_network_is_rejected() {
    let preview_reward =
        csl::RewardAddress::new(preview_id(), &preview_stake_cred());
    let mainnet_reward =
        csl::RewardAddress::new(mainnet_id(), &preview_stake_cred());

    let mut withdrawals = csl::TreasuryWithdrawals::new();
    withdrawals.insert(&mainnet_reward, &csl::BigNum::from(1_000u64));
    let treasury_action = csl::TreasuryWithdrawalsAction::new(&withdrawals);
    let gov_action =
        csl::GovernanceAction::new_treasury_withdrawals_action(&treasury_action);

    let anchor = csl::Anchor::new(
        &csl::URL::new("https://example.com/p.json".to_string()).unwrap(),
        &csl::AnchorDataHash::from_bytes(vec![0x44; 32]).unwrap(),
    );
    let proposal = csl::VotingProposal::new(
        &gov_action,
        &anchor,
        &preview_reward, // proposal's own return addr is fine
        &csl::BigNum::from(100_000_000_000u64),
    );
    let mut proposals = csl::VotingProposals::new();
    proposals.add(&proposal);

    let mut body = empty_body();
    body.set_voting_proposals(&proposals);

    let ctx = preview_simple_context();
    let validator = NetworkValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::TreasuryWithdrawalsNetworkIdMismatch { .. }
        )),
        "expected TreasuryWithdrawalsNetworkIdMismatch, got: {:?}",
        result.errors
    );
}

#[test]
fn mainnet_context_accepts_mainnet_output() {
    let output = csl::TransactionOutput::new(
        &base_address(mainnet_id()),
        &csl::Value::new(&csl::BigNum::from(1_000_000u64)),
    );
    let mut outputs = csl::TransactionOutputs::new();
    outputs.add(&output);
    let body = csl::TransactionBody::new_tx_body(
        &csl::TransactionInputs::new(),
        &outputs,
        &csl::BigNum::from(0u64),
    );

    let mut ctx = preview_simple_context();
    ctx.network_type = NetworkType::Mainnet;
    ctx.utxo_set.clear();

    let validator = NetworkValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.is_empty(),
        "mainnet output on mainnet ledger must pass, got: {:?}",
        result.errors
    );
}

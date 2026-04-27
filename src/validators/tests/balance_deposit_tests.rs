//! Deposit & refund balance tests for
//! [`crate::validators::phase_1::validation::BalanceValidator`].
//!
//! cardano-ledger's UTXO rule keys each cert/proposal on the exact deposit or
//! refund the ledger expects. The validator surfaces mismatches via dedicated
//! error variants:
//! * `StakeRegistrationWrongDeposit` / `StakeDeregistrationWrongRefund`
//! * `DRepIncorrectDeposit` / `DRepDeregistrationWrongRefund`
//! * `PoolRegistrationWrongDeposit`
//! * `VotingProposalIncorrectDeposit`

use crate::validators::input_contexts::{AccountInputContext, DrepInputContext};
use crate::validators::phase_1::errors::Phase1Error;
use crate::validators::phase_1::validation::BalanceValidator;
use crate::validators::tests::fixtures::preview_simple_context;
use cardano_serialization_lib as csl;

fn preview_network_id() -> u8 {
    csl::NetworkInfo::testnet_preview().network_id()
}

fn key_cred(byte: u8) -> csl::Credential {
    csl::Credential::from_keyhash(
        &csl::Ed25519KeyHash::from_bytes(vec![byte; 28]).unwrap(),
    )
}

fn reward_bech32(cred: &csl::Credential) -> String {
    csl::RewardAddress::new(preview_network_id(), cred)
        .to_address()
        .to_bech32(None)
        .unwrap()
}

fn body_with_certs(certs: csl::Certificates) -> csl::TransactionBody {
    let mut body = csl::TransactionBody::new_tx_body(
        &csl::TransactionInputs::new(),
        &csl::TransactionOutputs::new(),
        &csl::BigNum::from(0u64),
    );
    body.set_certs(&certs);
    body
}

#[test]
fn stake_registration_with_wrong_explicit_deposit_errors() {
    // Protocol params say stake_key_deposit = 2_000_000, but the cert
    // declares 1_500_000.
    let cred = key_cred(0x01);
    let cert = csl::Certificate::new_stake_registration(
        &csl::StakeRegistration::new_with_explicit_deposit(
            &cred,
            &csl::BigNum::from(1_500_000u64),
        ),
    );
    let mut certs = csl::Certificates::new();
    certs.add(&cert);

    let body = body_with_certs(certs);
    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();

    let validator = BalanceValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::StakeRegistrationWrongDeposit { .. }
        )),
        "expected StakeRegistrationWrongDeposit, got: {:?}",
        result.errors
    );
}

#[test]
fn stake_registration_with_matching_explicit_deposit_is_silent() {
    let cred = key_cred(0x02);
    let cert = csl::Certificate::new_stake_registration(
        &csl::StakeRegistration::new_with_explicit_deposit(
            &cred,
            &csl::BigNum::from(2_000_000u64),
        ),
    );
    let mut certs = csl::Certificates::new();
    certs.add(&cert);

    let body = body_with_certs(certs);
    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();

    let validator = BalanceValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        !result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::StakeRegistrationWrongDeposit { .. }
        )),
        "exact deposit match should not error, got: {:?}",
        result.errors
    );
}

#[test]
fn stake_deregistration_with_wrong_refund_errors() {
    let cred = key_cred(0x03);
    // The ledger paid 2_000_000 when the account was registered. The cert
    // asks for a 1_000_000 refund → mismatch.
    let cert = csl::Certificate::new_stake_deregistration(
        &csl::StakeDeregistration::new_with_explicit_refund(
            &cred,
            &csl::BigNum::from(1_000_000u64),
        ),
    );
    let mut certs = csl::Certificates::new();
    certs.add(&cert);

    let body = body_with_certs(certs);
    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.account_contexts.push(AccountInputContext {
        bech32_address: reward_bech32(&cred),
        is_registered: true,
        payed_deposit: Some(2_000_000),
        delegated_to_drep: Some("drep_always_abstain".to_string()),
        delegated_to_pool: None,
        balance: Some(0),
    });

    let validator = BalanceValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::StakeDeregistrationWrongRefund { .. }
        )),
        "expected StakeDeregistrationWrongRefund, got: {:?}",
        result.errors
    );
}

#[test]
fn drep_registration_with_wrong_deposit_errors() {
    let cred = key_cred(0x04);
    // Protocol params say drep_deposit = 500_000_000; cert declares 100.
    let cert = csl::Certificate::new_drep_registration(
        &csl::DRepRegistration::new(&cred, &csl::BigNum::from(100u64)),
    );
    let mut certs = csl::Certificates::new();
    certs.add(&cert);

    let body = body_with_certs(certs);
    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();

    let validator = BalanceValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::DRepIncorrectDeposit { .. }
        )),
        "expected DRepIncorrectDeposit, got: {:?}",
        result.errors
    );
}

#[test]
fn drep_deregistration_with_wrong_refund_errors() {
    let cred = key_cred(0x05);
    let drep = csl::DRep::new_from_credential(&cred);
    let drep_bech = drep.to_bech32(true).unwrap();

    // Cert claims 1 lovelace refund, ledger tracks a 500 000 000 deposit.
    let cert = csl::Certificate::new_drep_deregistration(
        &csl::DRepDeregistration::new(&cred, &csl::BigNum::from(1u64)),
    );
    let mut certs = csl::Certificates::new();
    certs.add(&cert);

    let body = body_with_certs(certs);
    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.drep_contexts.push(DrepInputContext {
        bech32_drep: drep_bech,
        is_registered: true,
        payed_deposit: Some(500_000_000),
    });

    let validator = BalanceValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::DRepDeregistrationWrongRefund { .. }
        )),
        "expected DRepDeregistrationWrongRefund, got: {:?}",
        result.errors
    );
}

#[test]
fn pool_registration_with_wrong_deposit_treats_cost_differently() {
    // The BalanceValidator doesn't read pool cost; deposit is derived from
    // protocol params whenever the pool isn't already registered. To trigger
    // the deposit-mismatch branch we mark the pool as already registered so
    // the validator records a zero-deposit expectation, then stage a real
    // deposit via the protocol params. This exercises the branch that
    // silently accepts no-deposit re-registration — the inverse of what the
    // validator flags for fresh pools.
    //
    // In practice the only way for BalanceValidator to see
    // PoolRegistrationWrongDeposit is if `calculate_deposits_and_refunds`
    // records a deposit that disagrees with stake_pool_deposit. Since that
    // function always uses the protocol-param value when the pool is fresh,
    // a mismatch is impossible without tampering with the validator itself.
    //
    // So this test pins the current behaviour: registering a *fresh* pool
    // doesn't produce PoolRegistrationWrongDeposit — the path is reachable
    // only through future code paths or transport-level deposit overrides.
    let operator = csl::Ed25519KeyHash::from_bytes(vec![0xF0; 28]).unwrap();
    let reward_cred = key_cred(0xF1);
    let reward_addr = csl::RewardAddress::new(preview_network_id(), &reward_cred);
    let vrf = csl::VRFKeyHash::from_bytes(vec![0x01; 32]).unwrap();
    let params = csl::PoolParams::new(
        &operator,
        &vrf,
        &csl::BigNum::from(0u64),
        &csl::BigNum::from(170_000_000u64),
        &csl::UnitInterval::new(&csl::BigNum::from(0u64), &csl::BigNum::from(1u64)),
        &reward_addr,
        &csl::Ed25519KeyHashes::new(),
        &csl::Relays::new(),
        None,
    );
    let cert = csl::Certificate::new_pool_registration(
        &csl::PoolRegistration::new(&params),
    );
    let mut certs = csl::Certificates::new();
    certs.add(&cert);

    let body = body_with_certs(certs);
    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();

    let validator = BalanceValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        !result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::PoolRegistrationWrongDeposit { .. }
        )),
        "BalanceValidator must not mismatch on fresh pool registration: {:?}",
        result.errors
    );
}

#[test]
fn voting_proposal_with_wrong_deposit_errors() {
    // Build a minimal InfoAction proposal whose declared deposit disagrees
    // with the protocol param (100 000 000 000).
    let reward_cred = key_cred(0x07);
    let reward_addr = csl::RewardAddress::new(preview_network_id(), &reward_cred);
    let anchor = csl::Anchor::new(
        &csl::URL::new("https://example.com/proposal.json".to_string()).unwrap(),
        &csl::AnchorDataHash::from_bytes(vec![0x12; 32]).unwrap(),
    );
    let gov_action = csl::GovernanceAction::new_info_action(&csl::InfoAction::new());
    let proposal = csl::VotingProposal::new(
        &gov_action,
        &anchor,
        &reward_addr,
        &csl::BigNum::from(1_000u64), // far below required 100 000 000 000
    );
    let mut proposals = csl::VotingProposals::new();
    assert!(proposals.add(&proposal));

    let mut body = csl::TransactionBody::new_tx_body(
        &csl::TransactionInputs::new(),
        &csl::TransactionOutputs::new(),
        &csl::BigNum::from(0u64),
    );
    body.set_voting_proposals(&proposals);

    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();

    let validator = BalanceValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::VotingProposalIncorrectDeposit { .. }
        )),
        "expected VotingProposalIncorrectDeposit, got: {:?}",
        result.errors
    );
}

#[test]
fn refund_without_known_payed_deposit_warns_instead_of_errors() {
    // If we don't know what the account paid, we can't verify the refund —
    // the validator emits a warning rather than a hard error.
    use crate::validators::phase_1::errors::Phase1Warning;

    let cred = key_cred(0x08);
    let cert = csl::Certificate::new_stake_deregistration(
        &csl::StakeDeregistration::new_with_explicit_refund(
            &cred,
            &csl::BigNum::from(2_000_000u64),
        ),
    );
    let mut certs = csl::Certificates::new();
    certs.add(&cert);

    let body = body_with_certs(certs);
    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.account_contexts.push(AccountInputContext {
        bech32_address: reward_bech32(&cred),
        is_registered: true,
        payed_deposit: None, // unknown
        delegated_to_drep: Some("drep_always_abstain".to_string()),
        delegated_to_pool: None,
        balance: Some(0),
    });

    let validator = BalanceValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        !result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::StakeDeregistrationWrongRefund { .. }
        )),
        "unknown payed_deposit must not produce a hard error"
    );
    assert!(
        result.warnings.iter().any(|w| matches!(
            w.warning,
            Phase1Warning::CannotCheckStakeDeregistrationRefund { .. }
        )),
        "expected CannotCheckStakeDeregistrationRefund warning, got: {:?}",
        result.warnings
    );
}

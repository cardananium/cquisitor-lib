//! Unit tests for
//! [`crate::validators::phase_1::validation::RegistrationValidator`].
//!
//! Validates certificate ordering and state transitions per the Conway
//! DELEG / POOL / GOVCERT rules in cardano-ledger:
//! * Stake reg/dereg must honour current registration state
//! * Pool retirement epoch ∈ (now, now + eMax]
//! * Vote delegations target a registered DRep (or the AlwaysX specials)
//! * DRep registration allows re-registration only as a warning

use crate::validators::common::NetworkType;
use crate::validators::input_contexts::{
    AccountInputContext, DrepInputContext, PoolInputContext,
};
use crate::validators::phase_1::errors::{Phase1Error, Phase1Warning};
use crate::validators::phase_1::validation::RegistrationValidator;
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

fn pool_key_hash(byte: u8) -> csl::Ed25519KeyHash {
    csl::Ed25519KeyHash::from_bytes(vec![byte; 28]).unwrap()
}

fn reward_bech32(cred: &csl::Credential) -> String {
    csl::RewardAddress::new(preview_network_id(), cred)
        .to_address()
        .to_bech32(None)
        .unwrap()
}

fn empty_body() -> csl::TransactionBody {
    csl::TransactionBody::new_tx_body(
        &csl::TransactionInputs::new(),
        &csl::TransactionOutputs::new(),
        &csl::BigNum::from(0u64),
    )
}

fn body_with_certs(certs: csl::Certificates) -> csl::TransactionBody {
    let mut body = empty_body();
    body.set_certs(&certs);
    body
}

#[test]
fn stake_registration_on_fresh_account_passes() {
    let cred = key_cred(0xAA);
    let cert = csl::Certificate::new_stake_registration(
        &csl::StakeRegistration::new(&cred),
    );
    let mut certs = csl::Certificates::new();
    certs.add(&cert);

    let body = body_with_certs(certs);
    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.network_type = NetworkType::Preview;

    let validator = RegistrationValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.is_empty(),
        "fresh registration should pass, got: {:?}",
        result.errors
    );
}

#[test]
fn duplicate_stake_registration_in_same_tx_warns_and_errors() {
    // CSL's `Certificates` is a de-duplicated set, so two identical certs
    // would collapse to one. Emulate the "two registration certs for the same
    // credential" case by pairing `StakeRegistration` with
    // `StakeRegistration::new_with_explicit_deposit` — distinct CBOR, same
    // credential.
    let cred = key_cred(0xBB);
    let cert1 = csl::Certificate::new_stake_registration(
        &csl::StakeRegistration::new(&cred),
    );
    let cert2 = csl::Certificate::new_stake_registration(
        &csl::StakeRegistration::new_with_explicit_deposit(
            &cred,
            &csl::BigNum::from(2_000_000u64),
        ),
    );
    let mut certs = csl::Certificates::new();
    assert!(certs.add(&cert1));
    assert!(certs.add(&cert2));

    let body = body_with_certs(certs);
    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();

    let validator = RegistrationValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::StakeAlreadyRegistered { .. }
        )),
        "expected StakeAlreadyRegistered for the second cert, got: {:?}",
        result.errors
    );
    assert!(
        result.warnings.iter().any(|w| matches!(
            w.warning,
            Phase1Warning::DuplicateRegistrationInTx { .. }
        )),
        "expected DuplicateRegistrationInTx warning, got: {:?}",
        result.warnings
    );
}

#[test]
fn stake_registration_on_already_registered_account_errors() {
    let cred = key_cred(0xCC);
    let cert = csl::Certificate::new_stake_registration(
        &csl::StakeRegistration::new(&cred),
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
        delegated_to_drep: None,
        delegated_to_pool: None,
        balance: Some(0),
    });

    let validator = RegistrationValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::StakeAlreadyRegistered { .. }
        )),
        "expected StakeAlreadyRegistered, got: {:?}",
        result.errors
    );
}

#[test]
fn stake_deregistration_of_unregistered_account_errors() {
    let cred = key_cred(0xDD);
    let cert = csl::Certificate::new_stake_deregistration(
        &csl::StakeDeregistration::new(&cred),
    );
    let mut certs = csl::Certificates::new();
    certs.add(&cert);

    let body = body_with_certs(certs);
    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();

    let validator = RegistrationValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::StakeNotRegistered { .. }
        )),
        "expected StakeNotRegistered, got: {:?}",
        result.errors
    );
}

#[test]
fn stake_deregistration_with_nonzero_balance_errors() {
    let cred = key_cred(0xEE);
    let cert = csl::Certificate::new_stake_deregistration(
        &csl::StakeDeregistration::new(&cred),
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
        delegated_to_drep: None,
        delegated_to_pool: None,
        balance: Some(1_234),
    });

    let validator = RegistrationValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::StakeNonZeroAccountBalance { .. }
        )),
        "expected StakeNonZeroAccountBalance, got: {:?}",
        result.errors
    );
}

#[test]
fn pool_retirement_with_out_of_range_epoch_is_rejected() {
    let pool_hash = pool_key_hash(0x11);
    // current_epoch = slot / 432_000. The fixture uses slot = 1_000_000 → epoch 2.
    // max_epoch_for_pool_retirement = 18. Retirement epoch = 100 is out of range.
    let cert = csl::Certificate::new_pool_retirement(&csl::PoolRetirement::new(
        &pool_hash, 100,
    ));
    let mut certs = csl::Certificates::new();
    certs.add(&cert);

    let body = body_with_certs(certs);
    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.pool_contexts.push(PoolInputContext {
        pool_id: pool_hash.to_hex(),
        is_registered: true,
        retirement_epoch: None,
    });

    let validator = RegistrationValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::WrongRetirementEpoch { .. }
        )),
        "expected WrongRetirementEpoch, got: {:?}",
        result.errors
    );
}

#[test]
fn pool_retirement_for_unregistered_pool_is_rejected() {
    let pool_hash = pool_key_hash(0x22);
    let cert = csl::Certificate::new_pool_retirement(&csl::PoolRetirement::new(
        &pool_hash, 5,
    ));
    let mut certs = csl::Certificates::new();
    certs.add(&cert);

    let body = body_with_certs(certs);
    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();

    let validator = RegistrationValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::StakePoolNotRegistered { .. }
        )),
        "expected StakePoolNotRegistered, got: {:?}",
        result.errors
    );
}

#[test]
fn vote_delegation_to_unregistered_drep_is_rejected() {
    let stake_cred = key_cred(0x33);
    let drep_cred = key_cred(0x44);
    let drep = csl::DRep::new_from_credential(&drep_cred);

    let cert = csl::Certificate::new_vote_delegation(
        &csl::VoteDelegation::new(&stake_cred, &drep),
    );
    let mut certs = csl::Certificates::new();
    certs.add(&cert);

    let body = body_with_certs(certs);
    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.account_contexts.push(AccountInputContext {
        bech32_address: reward_bech32(&stake_cred),
        is_registered: true,
        payed_deposit: Some(2_000_000),
        delegated_to_drep: None,
        delegated_to_pool: None,
        balance: Some(0),
    });

    let validator = RegistrationValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::DelegateeDRepNotRegistered { .. }
        )),
        "expected DelegateeDRepNotRegistered, got: {:?}",
        result.errors
    );
}

#[test]
fn vote_delegation_to_always_abstain_is_accepted() {
    let stake_cred = key_cred(0x55);
    let drep = csl::DRep::new_always_abstain();

    let cert = csl::Certificate::new_vote_delegation(
        &csl::VoteDelegation::new(&stake_cred, &drep),
    );
    let mut certs = csl::Certificates::new();
    certs.add(&cert);

    let body = body_with_certs(certs);
    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.account_contexts.push(AccountInputContext {
        bech32_address: reward_bech32(&stake_cred),
        is_registered: true,
        payed_deposit: Some(2_000_000),
        delegated_to_drep: None,
        delegated_to_pool: None,
        balance: Some(0),
    });

    let validator = RegistrationValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        !result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::DelegateeDRepNotRegistered { .. }
        )),
        "AlwaysAbstain should never require registration, got: {:?}",
        result.errors
    );
}

#[test]
fn drep_re_registration_produces_warning() {
    let cred = key_cred(0x66);
    let drep = csl::DRep::new_from_credential(&cred);
    let drep_bech = drep.to_bech32(true).unwrap();

    let cert = csl::Certificate::new_drep_registration(
        &csl::DRepRegistration::new(&cred, &csl::BigNum::from(500_000_000u64)),
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

    let validator = RegistrationValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.warnings.iter().any(|w| matches!(
            w.warning,
            Phase1Warning::DRepAlreadyRegistered { .. }
        )),
        "expected DRepAlreadyRegistered warning, got: {:?}",
        result.warnings
    );
}

#[test]
fn stake_and_vote_delegation_checks_stake_pool_drep() {
    // Joint cert: stake_deleg(pool) + vote_deleg(drep). Both targets must be
    // registered; the stake credential must also already be registered.
    let stake_cred = key_cred(0x10);
    let pool_hash = pool_key_hash(0x11);
    let drep_cred = key_cred(0x12);
    let drep = csl::DRep::new_from_credential(&drep_cred);

    let cert = csl::Certificate::new_stake_and_vote_delegation(
        &csl::StakeAndVoteDelegation::new(&stake_cred, &pool_hash, &drep),
    );
    let mut certs = csl::Certificates::new();
    certs.add(&cert);

    let body = body_with_certs(certs);
    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    // Stake not registered + pool not registered + drep not registered → 3 errors.

    let validator = RegistrationValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(result.errors.iter().any(|e| matches!(
        e.error,
        Phase1Error::StakeNotRegistered { .. }
    )));
    assert!(result.errors.iter().any(|e| matches!(
        e.error,
        Phase1Error::StakePoolNotRegistered { .. }
    )));
    assert!(result.errors.iter().any(|e| matches!(
        e.error,
        Phase1Error::DelegateeDRepNotRegistered { .. }
    )));
}

#[test]
fn stake_vote_registration_and_delegation_registers_stake_and_checks_pool_drep() {
    // Combined register-and-delegate-both. Must not error on stake (it gets
    // registered in this cert) but must error on unregistered pool + drep.
    let stake_cred = key_cred(0x20);
    let pool_hash = pool_key_hash(0x21);
    let drep_cred = key_cred(0x22);
    let drep = csl::DRep::new_from_credential(&drep_cred);

    let cert = csl::Certificate::new_stake_vote_registration_and_delegation(
        &csl::StakeVoteRegistrationAndDelegation::new(
            &stake_cred,
            &pool_hash,
            &drep,
            &csl::BigNum::from(2_000_000u64),
        ),
    );
    let mut certs = csl::Certificates::new();
    certs.add(&cert);

    let body = body_with_certs(certs);
    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();

    let validator = RegistrationValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        !result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::StakeNotRegistered { .. }
        )),
        "registration part of the cert should register the stake key"
    );
    assert!(result.errors.iter().any(|e| matches!(
        e.error,
        Phase1Error::StakePoolNotRegistered { .. }
    )));
    assert!(result.errors.iter().any(|e| matches!(
        e.error,
        Phase1Error::DelegateeDRepNotRegistered { .. }
    )));
}

#[test]
fn vote_registration_and_delegation_on_already_registered_stake_errors() {
    let stake_cred = key_cred(0x30);
    let drep = csl::DRep::new_always_abstain();

    let cert = csl::Certificate::new_vote_registration_and_delegation(
        &csl::VoteRegistrationAndDelegation::new(
            &stake_cred,
            &drep,
            &csl::BigNum::from(2_000_000u64),
        ),
    );
    let mut certs = csl::Certificates::new();
    certs.add(&cert);

    let body = body_with_certs(certs);
    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.account_contexts.push(AccountInputContext {
        bech32_address: reward_bech32(&stake_cred),
        is_registered: true,
        payed_deposit: Some(2_000_000),
        delegated_to_drep: None,
        delegated_to_pool: None,
        balance: Some(0),
    });

    let validator = RegistrationValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::StakeAlreadyRegistered { .. }
        )),
        "expected StakeAlreadyRegistered, got: {:?}",
        result.errors
    );
}

#[test]
fn drep_update_on_unregistered_drep_warns() {
    let cred = key_cred(0x40);
    let cert = csl::Certificate::new_drep_update(&csl::DRepUpdate::new(&cred));
    let mut certs = csl::Certificates::new();
    certs.add(&cert);

    let body = body_with_certs(certs);
    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();

    let validator = RegistrationValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.warnings.iter().any(|w| matches!(
            w.warning,
            Phase1Warning::DRepNotRegistered { .. }
        )),
        "expected DRepNotRegistered warning, got: {:?}",
        result.warnings
    );
}

#[test]
fn delegation_to_retiring_pool_emits_warning() {
    // Retirement cert BEFORE delegation in the same tx — state tracks pool
    // as retiring, and the subsequent delegation must produce a warning.
    let stake_cred = key_cred(0x50);
    let pool_hash = pool_key_hash(0x51);

    let retirement_cert = csl::Certificate::new_pool_retirement(
        &csl::PoolRetirement::new(&pool_hash, 5),
    );
    let deleg_cert = csl::Certificate::new_stake_delegation(
        &csl::StakeDelegation::new(&stake_cred, &pool_hash),
    );
    let mut certs = csl::Certificates::new();
    certs.add(&retirement_cert);
    certs.add(&deleg_cert);

    let body = body_with_certs(certs);
    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.account_contexts.push(AccountInputContext {
        bech32_address: reward_bech32(&stake_cred),
        is_registered: true,
        payed_deposit: Some(2_000_000),
        delegated_to_drep: None,
        delegated_to_pool: None,
        balance: Some(0),
    });
    ctx.pool_contexts.push(PoolInputContext {
        pool_id: pool_hash.to_hex(),
        is_registered: true,
        retirement_epoch: None,
    });

    let validator = RegistrationValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.warnings.iter().any(|w| matches!(
            w.warning,
            Phase1Warning::DelegationToRetiringPool { .. }
        )),
        "expected DelegationToRetiringPool warning, got: {:?}",
        result.warnings
    );
}

#[test]
fn genesis_key_delegation_cert_is_unsupported() {
    let cert = csl::Certificate::new_genesis_key_delegation(
        &csl::GenesisKeyDelegation::new(
            &csl::GenesisHash::from_bytes(vec![0xC1; 28]).unwrap(),
            &csl::GenesisDelegateHash::from_bytes(vec![0xC2; 28]).unwrap(),
            &csl::VRFKeyHash::from_bytes(vec![0xC3; 32]).unwrap(),
        ),
    );
    let mut certs = csl::Certificates::new();
    certs.add(&cert);

    let body = body_with_certs(certs);
    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();

    let validator = RegistrationValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::GenesisKeyDelegationCertificateIsNotSupported
        )),
        "expected GenesisKeyDelegationCertificateIsNotSupported, got: {:?}",
        result.errors
    );
}

#[test]
fn move_instantaneous_rewards_cert_is_unsupported() {
    let mir = csl::MoveInstantaneousReward::new_to_other_pot(
        csl::MIRPot::Reserves,
        &csl::BigNum::from(0u64),
    );
    let cert = csl::Certificate::new_move_instantaneous_rewards_cert(
        &csl::MoveInstantaneousRewardsCert::new(&mir),
    );
    let mut certs = csl::Certificates::new();
    certs.add(&cert);

    let body = body_with_certs(certs);
    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();

    let validator = RegistrationValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::MoveInstantaneousRewardsCertificateIsNotSupported
        )),
        "expected MoveInstantaneousRewardsCertificateIsNotSupported, got: {:?}",
        result.errors
    );
}

#[test]
fn pool_registration_with_cost_below_min_errors() {
    let operator = pool_key_hash(0x77);
    let reward_cred = key_cred(0x88);
    let reward_address =
        csl::RewardAddress::new(preview_network_id(), &reward_cred);
    let vrf = csl::VRFKeyHash::from_bytes(vec![0x01; 32]).unwrap();
    let pool_params = csl::PoolParams::new(
        &operator,
        &vrf,
        &csl::BigNum::from(0u64),
        &csl::BigNum::from(1u64), // cost = 1 lovelace, far below min_pool_cost
        &csl::UnitInterval::new(&csl::BigNum::from(0u64), &csl::BigNum::from(1u64)),
        &reward_address,
        &csl::Ed25519KeyHashes::new(),
        &csl::Relays::new(),
        None,
    );
    let cert = csl::Certificate::new_pool_registration(
        &csl::PoolRegistration::new(&pool_params),
    );
    let mut certs = csl::Certificates::new();
    certs.add(&cert);

    let body = body_with_certs(certs);
    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();

    let validator = RegistrationValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::StakePoolCostTooLow { .. }
        )),
        "expected StakePoolCostTooLow, got: {:?}",
        result.errors
    );
}

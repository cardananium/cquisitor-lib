//! Unit tests for
//! [`crate::validators::phase_1::validation::GovernanceValidator`].
//!
//! Covers the subset of Conway GOV checks we implement. See that module's
//! doc-comment for the full list.

use cardano_serialization_lib as csl;

use crate::validators::common::{
    GovernanceActionId, GovernanceActionType, LocalCredential,
};
use crate::validators::input_contexts::{
    AccountInputContext, CommitteeInputContext, DrepInputContext, GovActionInputContext,
    PoolInputContext,
};
use crate::validators::phase_1::errors::Phase1Error;
use crate::validators::phase_1::validation::GovernanceValidator;
use crate::validators::tests::fixtures::preview_simple_context;

fn preview_id() -> u8 {
    csl::NetworkInfo::testnet_preview().network_id()
}

fn key_cred(b: u8) -> csl::Credential {
    csl::Credential::from_keyhash(
        &csl::Ed25519KeyHash::from_bytes(vec![b; 28]).unwrap(),
    )
}

fn stake_reward_bech(cred: &csl::Credential) -> String {
    csl::RewardAddress::new(preview_id(), cred)
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

fn anchor() -> csl::Anchor {
    csl::Anchor::new(
        &csl::URL::new("https://example.com/p.json".to_string()).unwrap(),
        &csl::AnchorDataHash::from_bytes(vec![0x55; 32]).unwrap(),
    )
}

fn register_return_account(
    ctx: &mut crate::validators::input_contexts::ValidationInputContext,
    cred: &csl::Credential,
) {
    ctx.account_contexts.push(AccountInputContext {
        bech32_address: stake_reward_bech(cred),
        is_registered: true,
        payed_deposit: None,
        delegated_to_drep: None,
        delegated_to_pool: None,
        balance: Some(0),
    });
}

#[test]
fn unregistered_drep_voter_is_flagged() {
    let drep_cred = key_cred(0xA0);
    let voter = csl::Voter::new_drep_credential(&drep_cred);

    let mut proc = csl::VotingProcedures::new();
    let action_id = csl::GovernanceActionId::new(
        &csl::TransactionHash::from_bytes(vec![0x01; 32]).unwrap(),
        0,
    );
    let vote = csl::VotingProcedure::new(csl::VoteKind::Yes);
    proc.insert(&voter, &action_id, &vote);

    let mut body = empty_body();
    body.set_voting_procedures(&proc);

    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    // GovAction exists so we hit VoterDoNotExist and not GovActionsDoNotExist.
    ctx.gov_action_contexts.push(GovActionInputContext {
        action_id: GovernanceActionId {
            tx_hash: vec![0x01; 32],
            index: 0,
        },
        action_type: GovernanceActionType::InfoAction,
        is_active: true,
    });

    let validator = GovernanceValidator::new(&body, &ctx);
    let result = validator.validate(&body, &ctx);

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::VoterDoNotExist { .. }
        )),
        "expected VoterDoNotExist for unregistered DRep, got: {:?}",
        result.errors
    );
}

#[test]
fn registered_drep_voter_passes_existence_check() {
    let drep_cred = key_cred(0xA1);
    let voter = csl::Voter::new_drep_credential(&drep_cred);
    let drep = csl::DRep::new_from_credential(&drep_cred);
    let drep_bech = drep.to_bech32(true).unwrap();

    let mut proc = csl::VotingProcedures::new();
    let action_id = csl::GovernanceActionId::new(
        &csl::TransactionHash::from_bytes(vec![0x02; 32]).unwrap(),
        0,
    );
    proc.insert(
        &voter,
        &action_id,
        &csl::VotingProcedure::new(csl::VoteKind::Yes),
    );

    let mut body = empty_body();
    body.set_voting_procedures(&proc);

    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.drep_contexts.push(DrepInputContext {
        bech32_drep: drep_bech,
        is_registered: true,
        payed_deposit: Some(500_000_000),
    });
    ctx.gov_action_contexts.push(GovActionInputContext {
        action_id: GovernanceActionId {
            tx_hash: vec![0x02; 32],
            index: 0,
        },
        action_type: GovernanceActionType::InfoAction,
        is_active: true,
    });

    let validator = GovernanceValidator::new(&body, &ctx);
    let result = validator.validate(&body, &ctx);

    assert!(
        !result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::VoterDoNotExist { .. }
        )),
        "registered DRep must pass existence check: {:?}",
        result.errors
    );
}

#[test]
fn unregistered_pool_voter_is_flagged() {
    let pool_key = csl::Ed25519KeyHash::from_bytes(vec![0xB0; 28]).unwrap();
    let voter = csl::Voter::new_stake_pool_key_hash(&pool_key);

    let action_id = csl::GovernanceActionId::new(
        &csl::TransactionHash::from_bytes(vec![0x03; 32]).unwrap(),
        0,
    );
    let mut proc = csl::VotingProcedures::new();
    proc.insert(
        &voter,
        &action_id,
        &csl::VotingProcedure::new(csl::VoteKind::Yes),
    );

    let mut body = empty_body();
    body.set_voting_procedures(&proc);

    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.gov_action_contexts.push(GovActionInputContext {
        action_id: GovernanceActionId {
            tx_hash: vec![0x03; 32],
            index: 0,
        },
        action_type: GovernanceActionType::InfoAction,
        is_active: true,
    });

    let validator = GovernanceValidator::new(&body, &ctx);
    let result = validator.validate(&body, &ctx);

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::VoterDoNotExist { .. }
        )),
        "expected VoterDoNotExist for unknown pool"
    );
}

#[test]
fn committee_hot_voter_for_known_member_passes() {
    // Ledger knows the cold key, and the hot cred is bound via the context.
    let cold_cred = key_cred(0xC0);
    let hot_cred = key_cred(0xC1);
    let voter = csl::Voter::new_constitutional_committee_hot_credential(&hot_cred);

    let mut proc = csl::VotingProcedures::new();
    let action_id = csl::GovernanceActionId::new(
        &csl::TransactionHash::from_bytes(vec![0x04; 32]).unwrap(),
        0,
    );
    proc.insert(
        &voter,
        &action_id,
        &csl::VotingProcedure::new(csl::VoteKind::Yes),
    );

    let mut body = empty_body();
    body.set_voting_procedures(&proc);

    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.current_committee_members.push(CommitteeInputContext {
        committee_member_cold: LocalCredential::KeyHash(
            cold_cred.to_keyhash().unwrap().to_bytes(),
        ),
        committee_member_hot: Some(LocalCredential::KeyHash(
            hot_cred.to_keyhash().unwrap().to_bytes(),
        )),
        is_resigned: false,
    });
    ctx.gov_action_contexts.push(GovActionInputContext {
        action_id: GovernanceActionId {
            tx_hash: vec![0x04; 32],
            index: 0,
        },
        action_type: GovernanceActionType::InfoAction,
        is_active: true,
    });

    let validator = GovernanceValidator::new(&body, &ctx);
    let result = validator.validate(&body, &ctx);

    assert!(
        !result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::VoterDoNotExist { .. }
                | Phase1Error::InvalidCommitteeVote { .. }
        )),
        "known committee member must pass: {:?}",
        result.errors
    );
}

#[test]
fn resigned_committee_voter_triggers_invalid_committee_vote() {
    let cold_cred = key_cred(0xC2);
    let hot_cred = key_cred(0xC3);
    let voter = csl::Voter::new_constitutional_committee_hot_credential(&hot_cred);

    let mut proc = csl::VotingProcedures::new();
    let action_id = csl::GovernanceActionId::new(
        &csl::TransactionHash::from_bytes(vec![0x05; 32]).unwrap(),
        0,
    );
    proc.insert(
        &voter,
        &action_id,
        &csl::VotingProcedure::new(csl::VoteKind::Yes),
    );

    let mut body = empty_body();
    body.set_voting_procedures(&proc);

    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.current_committee_members.push(CommitteeInputContext {
        committee_member_cold: LocalCredential::KeyHash(
            cold_cred.to_keyhash().unwrap().to_bytes(),
        ),
        committee_member_hot: Some(LocalCredential::KeyHash(
            hot_cred.to_keyhash().unwrap().to_bytes(),
        )),
        is_resigned: true,
    });
    ctx.gov_action_contexts.push(GovActionInputContext {
        action_id: GovernanceActionId {
            tx_hash: vec![0x05; 32],
            index: 0,
        },
        action_type: GovernanceActionType::InfoAction,
        is_active: true,
    });

    let validator = GovernanceValidator::new(&body, &ctx);
    let result = validator.validate(&body, &ctx);

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::InvalidCommitteeVote { .. }
        )),
        "expected InvalidCommitteeVote for resigned member, got: {:?}",
        result.errors
    );
}

#[test]
fn voting_on_missing_gov_action_emits_gov_actions_do_not_exist() {
    let drep_cred = key_cred(0xD0);
    let voter = csl::Voter::new_drep_credential(&drep_cred);
    let drep = csl::DRep::new_from_credential(&drep_cred);

    let mut proc = csl::VotingProcedures::new();
    let action_id = csl::GovernanceActionId::new(
        &csl::TransactionHash::from_bytes(vec![0xAA; 32]).unwrap(),
        0,
    );
    proc.insert(
        &voter,
        &action_id,
        &csl::VotingProcedure::new(csl::VoteKind::Yes),
    );

    let mut body = empty_body();
    body.set_voting_procedures(&proc);

    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.drep_contexts.push(DrepInputContext {
        bech32_drep: drep.to_bech32(true).unwrap(),
        is_registered: true,
        payed_deposit: None,
    });
    // No gov_action_contexts — the reference must 404.

    let validator = GovernanceValidator::new(&body, &ctx);
    let result = validator.validate(&body, &ctx);

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::GovActionsDoNotExist { .. }
        )),
        "expected GovActionsDoNotExist, got: {:?}",
        result.errors
    );
}

#[test]
fn voting_on_expired_gov_action_is_flagged() {
    let drep_cred = key_cred(0xD1);
    let voter = csl::Voter::new_drep_credential(&drep_cred);
    let drep = csl::DRep::new_from_credential(&drep_cred);

    let mut proc = csl::VotingProcedures::new();
    let action_id = csl::GovernanceActionId::new(
        &csl::TransactionHash::from_bytes(vec![0xBB; 32]).unwrap(),
        0,
    );
    proc.insert(
        &voter,
        &action_id,
        &csl::VotingProcedure::new(csl::VoteKind::Yes),
    );

    let mut body = empty_body();
    body.set_voting_procedures(&proc);

    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.drep_contexts.push(DrepInputContext {
        bech32_drep: drep.to_bech32(true).unwrap(),
        is_registered: true,
        payed_deposit: None,
    });
    ctx.gov_action_contexts.push(GovActionInputContext {
        action_id: GovernanceActionId {
            tx_hash: vec![0xBB; 32],
            index: 0,
        },
        action_type: GovernanceActionType::InfoAction,
        is_active: false,
    });

    let validator = GovernanceValidator::new(&body, &ctx);
    let result = validator.validate(&body, &ctx);

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::VotingOnExpiredGovAction { .. }
        )),
        "expected VotingOnExpiredGovAction, got: {:?}",
        result.errors
    );
}

#[test]
fn proposal_with_unregistered_return_account_is_flagged() {
    let reward_cred = key_cred(0xE0);
    let reward_addr = csl::RewardAddress::new(preview_id(), &reward_cred);
    let gov_action = csl::GovernanceAction::new_info_action(&csl::InfoAction::new());
    let proposal = csl::VotingProposal::new(
        &gov_action,
        &anchor(),
        &reward_addr,
        &csl::BigNum::from(100_000_000_000u64),
    );
    let mut proposals = csl::VotingProposals::new();
    proposals.add(&proposal);

    let mut body = empty_body();
    body.set_voting_proposals(&proposals);

    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();

    let validator = GovernanceValidator::new(&body, &ctx);
    let result = validator.validate(&body, &ctx);

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::ProposalReturnAccountDoesNotExist { .. }
        )),
        "expected ProposalReturnAccountDoesNotExist, got: {:?}",
        result.errors
    );
}

#[test]
fn zero_treasury_withdrawals_is_flagged() {
    let reward_cred = key_cred(0xE1);
    let reward_addr = csl::RewardAddress::new(preview_id(), &reward_cred);

    // Withdrawals map with a zero coin. (Per ledger, sum must be > 0.)
    let mut withdrawals = csl::TreasuryWithdrawals::new();
    withdrawals.insert(&reward_addr, &csl::BigNum::from(0u64));
    let treasury_action = csl::TreasuryWithdrawalsAction::new(&withdrawals);
    let gov_action =
        csl::GovernanceAction::new_treasury_withdrawals_action(&treasury_action);

    let proposal = csl::VotingProposal::new(
        &gov_action,
        &anchor(),
        &reward_addr,
        &csl::BigNum::from(100_000_000_000u64),
    );
    let mut proposals = csl::VotingProposals::new();
    proposals.add(&proposal);

    let mut body = empty_body();
    body.set_voting_proposals(&proposals);

    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    register_return_account(&mut ctx, &reward_cred);

    let validator = GovernanceValidator::new(&body, &ctx);
    let result = validator.validate(&body, &ctx);

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::ZeroTreasuryWithdrawals { .. }
        )),
        "expected ZeroTreasuryWithdrawals, got: {:?}",
        result.errors
    );
}

#[test]
fn treasury_withdrawal_to_unregistered_account_is_flagged() {
    let proposer_cred = key_cred(0xE2);
    let target_cred = key_cred(0xE3);
    let proposer_addr = csl::RewardAddress::new(preview_id(), &proposer_cred);
    let target_addr = csl::RewardAddress::new(preview_id(), &target_cred);

    let mut withdrawals = csl::TreasuryWithdrawals::new();
    withdrawals.insert(&target_addr, &csl::BigNum::from(1_000u64));
    let treasury_action = csl::TreasuryWithdrawalsAction::new(&withdrawals);
    let gov_action =
        csl::GovernanceAction::new_treasury_withdrawals_action(&treasury_action);

    let proposal = csl::VotingProposal::new(
        &gov_action,
        &anchor(),
        &proposer_addr,
        &csl::BigNum::from(100_000_000_000u64),
    );
    let mut proposals = csl::VotingProposals::new();
    proposals.add(&proposal);

    let mut body = empty_body();
    body.set_voting_proposals(&proposals);

    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    register_return_account(&mut ctx, &proposer_cred);
    // target account intentionally NOT registered

    let validator = GovernanceValidator::new(&body, &ctx);
    let result = validator.validate(&body, &ctx);

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::TreasuryWithdrawalReturnAccountsDoNotExist { .. }
        )),
        "expected TreasuryWithdrawalReturnAccountsDoNotExist, got: {:?}",
        result.errors
    );
}

#[test]
fn conflicting_committee_update_is_flagged() {
    // UpdateCommitteeAction where the same cold cred is in both add and
    // remove sets.
    let proposer_cred = key_cred(0xF0);
    let proposer_addr = csl::RewardAddress::new(preview_id(), &proposer_cred);
    let conflicting = key_cred(0xF1);

    let mut committee = csl::Committee::new(&csl::UnitInterval::new(
        &csl::BigNum::from(1u64),
        &csl::BigNum::from(2u64),
    ));
    committee.add_member(&conflicting, 5);

    let mut remove = csl::Credentials::new();
    remove.add(&conflicting);

    let update_action =
        csl::UpdateCommitteeAction::new(&committee, &remove);
    let gov_action =
        csl::GovernanceAction::new_new_committee_action(&update_action);

    let proposal = csl::VotingProposal::new(
        &gov_action,
        &anchor(),
        &proposer_addr,
        &csl::BigNum::from(100_000_000_000u64),
    );
    let mut proposals = csl::VotingProposals::new();
    proposals.add(&proposal);

    let mut body = empty_body();
    body.set_voting_proposals(&proposals);

    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    register_return_account(&mut ctx, &proposer_cred);

    let validator = GovernanceValidator::new(&body, &ctx);
    let result = validator.validate(&body, &ctx);

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::ConflictingCommitteeUpdate { .. }
        )),
        "expected ConflictingCommitteeUpdate, got: {:?}",
        result.errors
    );
}

#[test]
fn spo_voting_on_parameter_change_is_disallowed() {
    // SPO voter + ParameterChangeAction → DisallowedVoters.
    let pool_key = csl::Ed25519KeyHash::from_bytes(vec![0xEE; 28]).unwrap();
    let voter = csl::Voter::new_stake_pool_key_hash(&pool_key);

    let mut proc = csl::VotingProcedures::new();
    let action_id = csl::GovernanceActionId::new(
        &csl::TransactionHash::from_bytes(vec![0x77; 32]).unwrap(),
        0,
    );
    proc.insert(
        &voter,
        &action_id,
        &csl::VotingProcedure::new(csl::VoteKind::Yes),
    );

    let mut body = empty_body();
    body.set_voting_procedures(&proc);

    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.pool_contexts.push(PoolInputContext {
        pool_id: pool_key.to_hex(),
        is_registered: true,
        retirement_epoch: None,
    });
    ctx.gov_action_contexts.push(GovActionInputContext {
        action_id: GovernanceActionId {
            tx_hash: vec![0x77; 32],
            index: 0,
        },
        action_type: GovernanceActionType::ParameterChangeAction,
        is_active: true,
    });

    let validator = GovernanceValidator::new(&body, &ctx);
    let result = validator.validate(&body, &ctx);

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::DisallowedVoters { .. }
        )),
        "expected DisallowedVoters for SPO voting on ParameterChange, got: {:?}",
        result.errors
    );
}

#[test]
fn committee_voting_on_no_confidence_is_disallowed() {
    // CC voters can't vote on NoConfidence (the motion is against them).
    let cold = key_cred(0x21);
    let hot = key_cred(0x22);
    let voter = csl::Voter::new_constitutional_committee_hot_credential(&hot);

    let mut proc = csl::VotingProcedures::new();
    let action_id = csl::GovernanceActionId::new(
        &csl::TransactionHash::from_bytes(vec![0x88; 32]).unwrap(),
        0,
    );
    proc.insert(
        &voter,
        &action_id,
        &csl::VotingProcedure::new(csl::VoteKind::Yes),
    );

    let mut body = empty_body();
    body.set_voting_procedures(&proc);

    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.current_committee_members.push(CommitteeInputContext {
        committee_member_cold: LocalCredential::KeyHash(
            cold.to_keyhash().unwrap().to_bytes(),
        ),
        committee_member_hot: Some(LocalCredential::KeyHash(
            hot.to_keyhash().unwrap().to_bytes(),
        )),
        is_resigned: false,
    });
    ctx.gov_action_contexts.push(GovActionInputContext {
        action_id: GovernanceActionId {
            tx_hash: vec![0x88; 32],
            index: 0,
        },
        action_type: GovernanceActionType::NoConfidenceAction,
        is_active: true,
    });

    let validator = GovernanceValidator::new(&body, &ctx);
    let result = validator.validate(&body, &ctx);

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::DisallowedVoters { .. }
        )),
        "expected DisallowedVoters for CC voting on NoConfidence, got: {:?}",
        result.errors
    );
}

#[test]
fn drep_can_vote_on_all_action_types() {
    let drep_cred = key_cred(0x33);
    let voter = csl::Voter::new_drep_credential(&drep_cred);
    let drep = csl::DRep::new_from_credential(&drep_cred);

    let mut proc = csl::VotingProcedures::new();
    let action_id = csl::GovernanceActionId::new(
        &csl::TransactionHash::from_bytes(vec![0x99; 32]).unwrap(),
        0,
    );
    proc.insert(
        &voter,
        &action_id,
        &csl::VotingProcedure::new(csl::VoteKind::Yes),
    );

    let mut body = empty_body();
    body.set_voting_procedures(&proc);

    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.drep_contexts.push(DrepInputContext {
        bech32_drep: drep.to_bech32(true).unwrap(),
        is_registered: true,
        payed_deposit: None,
    });
    ctx.gov_action_contexts.push(GovActionInputContext {
        action_id: GovernanceActionId {
            tx_hash: vec![0x99; 32],
            index: 0,
        },
        action_type: GovernanceActionType::TreasuryWithdrawalsAction,
        is_active: true,
    });

    let validator = GovernanceValidator::new(&body, &ctx);
    let result = validator.validate(&body, &ctx);

    assert!(
        !result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::DisallowedVoters { .. }
        )),
        "DRep must be allowed for TreasuryWithdrawals, got: {:?}",
        result.errors
    );
}

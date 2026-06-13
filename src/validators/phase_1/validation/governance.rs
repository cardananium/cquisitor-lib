//! Governance / votes / proposals validator.
//!
//! Covers a significant portion of the Conway GOV / RATIFY / ENACT rules from
//! cardano-ledger (`Cardano/Ledger/Conway/Rules/Gov.hs`):
//!
//! * `VoterDoNotExist` — DRep / stake-pool / committee voters must be registered
//! * `InvalidCommitteeVote` — committee hot voter must be bound to a currently
//!   seated (non-resigned) committee member
//! * `GovActionsDoNotExist` — every gov action id referenced from a vote or a
//!   proposal's `prev_gov_action_id` must be known to the ledger
//! * `VotingOnExpiredGovAction` — can't vote on an action that the ledger
//!   tracks as no longer active
//! * `ZeroTreasuryWithdrawals` — `TreasuryWithdrawalsAction` must move > 0
//! * `ProposalReturnAccountDoesNotExist` — proposal deposit's return account
//!   must be a registered stake account
//! * `TreasuryWithdrawalReturnAccountsDoNotExist` — each withdrawal target
//!   account must be a registered stake account
//! * `ConflictingCommitteeUpdate` — `UpdateCommitteeAction`'s add/remove sets
//!   must be disjoint
//! * `DisallowedVoters` — voter × action matrix per Conway spec
//!
//! Checks still deferred (TODOs, out of scope for this module):
//! * `MalformedProposal`, `ExpirationEpochTooSmall`, `InvalidPrevGovActionId`
//!   (lineage check), `ProposalCantFollow`, `InvalidConstitutionPolicyHash`.

use cardano_serialization_lib as csl;
use serde_json::json;
use std::collections::HashSet;

use crate::validators::{
    common::{GovernanceActionId, Voter as ErrVoter},
    helpers::csl_credential_to_local_credential,
    input_contexts::ValidationInputContext,
    phase_1::errors::{Phase1Error, ValidationPhase1Error},
    validation_result::ValidationResult,
};

pub struct GovernanceValidator;

impl GovernanceValidator {
    pub fn new(
        _tx_body: &csl::TransactionBody,
        _validation_input_context: &ValidationInputContext,
    ) -> Self {
        Self
    }

    pub fn validate(
        &self,
        tx_body: &csl::TransactionBody,
        ctx: &ValidationInputContext,
    ) -> ValidationResult {
        let mut errors = Vec::new();

        validate_votes(tx_body, ctx, &mut errors);
        validate_proposals(tx_body, ctx, &mut errors);

        ValidationResult::new_phase_1(errors, Vec::new())
    }
}

fn err_voter_from_csl(voter: &csl::Voter) -> ErrVoter {
    match voter.kind() {
        csl::VoterKind::ConstitutionalCommitteeHotKeyHash => {
            let bytes = voter
                .to_constitutional_committee_hot_credential()
                .and_then(|c| c.to_keyhash())
                .map(|k| k.to_bytes())
                .unwrap_or_default();
            ErrVoter::ConstitutionalCommitteeHotKeyHash(bytes)
        }
        csl::VoterKind::ConstitutionalCommitteeHotScriptHash => {
            let bytes = voter
                .to_constitutional_committee_hot_credential()
                .and_then(|c| c.to_scripthash())
                .map(|h| h.to_bytes())
                .unwrap_or_default();
            ErrVoter::ConstitutionalCommitteeHotScriptHash(bytes)
        }
        csl::VoterKind::DRepKeyHash => {
            let bytes = voter
                .to_drep_credential()
                .and_then(|c| c.to_keyhash())
                .map(|k| k.to_bytes())
                .unwrap_or_default();
            ErrVoter::DRepKeyHash(bytes)
        }
        csl::VoterKind::DRepScriptHash => {
            let bytes = voter
                .to_drep_credential()
                .and_then(|c| c.to_scripthash())
                .map(|h| h.to_bytes())
                .unwrap_or_default();
            ErrVoter::DRepScriptHash(bytes)
        }
        csl::VoterKind::StakingPoolKeyHash => {
            let bytes = voter
                .to_stake_pool_key_hash()
                .map(|k| k.to_bytes())
                .unwrap_or_default();
            ErrVoter::StakingPoolKeyHash(bytes)
        }
    }
}

fn gov_action_id_from_csl(id: &csl::GovernanceActionId) -> GovernanceActionId {
    GovernanceActionId {
        tx_hash: id.transaction_id().to_bytes(),
        index: id.index(),
    }
}

fn validate_votes(
    tx_body: &csl::TransactionBody,
    ctx: &ValidationInputContext,
    errors: &mut Vec<ValidationPhase1Error>,
) {
    let Some(procedures) = tx_body.voting_procedures() else {
        return;
    };
    let voters = procedures.get_voters();

    // Collect in-tx committee hot-auths so a fresh CC voter authorized inside
    // this tx is still considered "existing".
    let in_tx_hot_auths = collect_in_tx_committee_hot_auths(tx_body);

    for i in 0..voters.len() {
        let Some(voter) = voters.get(i) else {
            continue;
        };

        check_voter_existence(
            &voter,
            i as u32,
            ctx,
            &in_tx_hot_auths,
            errors,
        );

        let action_ids = procedures.get_governance_action_ids_by_voter(&voter);
        for j in 0..action_ids.len() {
            let Some(action_id) = action_ids.get(j) else {
                continue;
            };
            let location = format!(
                "transaction.body.voting_procedures.{}.{}",
                i, j
            );
            check_gov_action_ref(
                &action_id,
                &voter,
                &location,
                ctx,
                errors,
            );
        }
    }
}

fn collect_in_tx_committee_hot_auths(
    tx_body: &csl::TransactionBody,
) -> HashSet<(bool, Vec<u8>)> {
    let mut set = HashSet::new();
    let Some(certs) = tx_body.certs() else {
        return set;
    };
    for i in 0..certs.len() {
        let cert = certs.get(i);
        if cert.kind() != csl::CertificateKind::CommitteeHotAuth {
            continue;
        }
        let Some(auth) = cert.as_committee_hot_auth() else {
            continue;
        };
        let hot = auth.committee_hot_credential();
        match hot.kind() {
            csl::CredKind::Key => {
                if let Some(k) = hot.to_keyhash() {
                    // bool flag: `true` = script-hash, `false` = key-hash.
                    set.insert((false, k.to_bytes()));
                }
            }
            csl::CredKind::Script => {
                if let Some(h) = hot.to_scripthash() {
                    set.insert((true, h.to_bytes()));
                }
            }
        }
    }
    set
}

fn check_voter_existence(
    voter: &csl::Voter,
    index: u32,
    ctx: &ValidationInputContext,
    in_tx_hot_auths: &HashSet<(bool, Vec<u8>)>,
    errors: &mut Vec<ValidationPhase1Error>,
) {
    let location = format!("transaction.body.voting_procedures.{}", index);
    let err_voter = err_voter_from_csl(voter);

    match voter.kind() {
        csl::VoterKind::DRepKeyHash | csl::VoterKind::DRepScriptHash => {
            let drep_cred = match voter.to_drep_credential() {
                Some(c) => c,
                None => return,
            };
            let drep = csl::DRep::new_from_credential(&drep_cred);
            let bech = drep.to_bech32(true).unwrap_or_default();
            let registered = ctx
                .find_drep_context(&bech)
                .map(|d| d.is_registered)
                .unwrap_or(false);
            if !registered {
                errors.push(ValidationPhase1Error::new(
                    Phase1Error::VoterDoNotExist {
                        missing_voter: json!(err_voter),
                    },
                    location,
                ));
            }
        }
        csl::VoterKind::StakingPoolKeyHash => {
            let Some(pool_key) = voter.to_stake_pool_key_hash() else {
                return;
            };
            let pool_hex = pool_key.to_hex();
            let registered = ctx
                .find_pool_context(&pool_hex)
                .map(|p| p.is_registered)
                .unwrap_or(false);
            if !registered {
                errors.push(ValidationPhase1Error::new(
                    Phase1Error::VoterDoNotExist {
                        missing_voter: json!(err_voter),
                    },
                    location,
                ));
            }
        }
        csl::VoterKind::ConstitutionalCommitteeHotKeyHash
        | csl::VoterKind::ConstitutionalCommitteeHotScriptHash => {
            // Hot credentials are indirect: we know the hot cred, but the
            // committee roster is keyed by cold creds. Look it up via
            // find_current_committee_member_by_hot_credential + the in-tx
            // hot-auth set.
            let Some(hot) = voter.to_constitutional_committee_hot_credential()
            else {
                return;
            };
            let local = csl_credential_to_local_credential(&hot);
            let in_tx_authed = match hot.kind() {
                csl::CredKind::Key => hot
                    .to_keyhash()
                    .map(|k| in_tx_hot_auths.contains(&(false, k.to_bytes())))
                    .unwrap_or(false),
                csl::CredKind::Script => hot
                    .to_scripthash()
                    .map(|h| in_tx_hot_auths.contains(&(true, h.to_bytes())))
                    .unwrap_or(false),
            };
            let current = ctx
                .find_current_committee_member_by_hot_credential(&local);
            let potential = ctx
                .find_potential_committee_member_by_hot_credential(&local);

            if !in_tx_authed && current.is_none() && potential.is_none() {
                errors.push(ValidationPhase1Error::new(
                    Phase1Error::VoterDoNotExist {
                        missing_voter: json!(err_voter),
                    },
                    location,
                ));
            } else if let Some(member) = current {
                if member.is_resigned {
                    errors.push(ValidationPhase1Error::new(
                        Phase1Error::InvalidCommitteeVote {
                            voter: json!(err_voter),
                            message: "Committee member has previously resigned"
                                .to_string(),
                        },
                        location,
                    ));
                }
            } else if let Some(member) = potential {
                if member.is_resigned {
                    errors.push(ValidationPhase1Error::new(
                        Phase1Error::InvalidCommitteeVote {
                            voter: json!(err_voter),
                            message: "Potential committee member has resigned"
                                .to_string(),
                        },
                        location,
                    ));
                }
            }
        }
    }
}

fn check_gov_action_ref(
    action_id: &csl::GovernanceActionId,
    voter: &csl::Voter,
    location: &str,
    ctx: &ValidationInputContext,
    errors: &mut Vec<ValidationPhase1Error>,
) {
    let local_id = gov_action_id_from_csl(action_id);
    match ctx.find_gov_action_context(local_id.clone()) {
        None => {
            errors.push(ValidationPhase1Error::new(
                Phase1Error::GovActionsDoNotExist {
                    invalid_action_ids: vec![local_id],
                },
                location.to_string(),
            ));
        }
        Some(action) => {
            if !action.is_active {
                errors.push(ValidationPhase1Error::new(
                    Phase1Error::VotingOnExpiredGovAction {
                        expired_gov_action: local_id,
                    },
                    location.to_string(),
                ));
            }
            // Matrix check: some voters aren't allowed for some action types.
            if let Some(disallowed_pair) =
                disallowed_voter_for_action(voter, &action.action_type)
            {
                errors.push(ValidationPhase1Error::new(
                    Phase1Error::DisallowedVoters {
                        disallowed_pairs: vec![disallowed_pair],
                    },
                    location.to_string(),
                ));
            }
        }
    }
}

/// Conway voter × gov-action matrix (per
/// cardano-ledger Conway/Rules/Gov.hs).
///
/// Returns `Some(pair)` if the pair is disallowed.
fn disallowed_voter_for_action(
    voter: &csl::Voter,
    action_type: &crate::validators::common::GovernanceActionType,
) -> Option<(ErrVoter, GovernanceActionId)> {
    use crate::validators::common::GovernanceActionType as T;
    let is_disallowed = match voter.kind() {
        csl::VoterKind::StakingPoolKeyHash => matches!(
            action_type,
            T::ParameterChangeAction
                | T::NewConstitutionAction
                | T::TreasuryWithdrawalsAction
        ),
        csl::VoterKind::ConstitutionalCommitteeHotKeyHash
        | csl::VoterKind::ConstitutionalCommitteeHotScriptHash => {
            matches!(action_type, T::NoConfidenceAction | T::UpdateCommitteeAction)
        }
        csl::VoterKind::DRepKeyHash | csl::VoterKind::DRepScriptHash => false,
    };
    if is_disallowed {
        Some((
            err_voter_from_csl(voter),
            // We don't have a gov_action_id readily here — use a zero id
            // placeholder; the error surface is the location + voter type.
            GovernanceActionId {
                tx_hash: vec![0; 32],
                index: 0,
            },
        ))
    } else {
        None
    }
}

fn validate_proposals(
    tx_body: &csl::TransactionBody,
    ctx: &ValidationInputContext,
    errors: &mut Vec<ValidationPhase1Error>,
) {
    let Some(proposals) = tx_body.voting_proposals() else {
        return;
    };
    for i in 0..proposals.len() {
        let proposal = proposals.get(i);
        let location = format!("transaction.body.voting_proposals.{}", i);

        // Return account must be a registered stake account.
        let reward_account = proposal.reward_account();
        let bech = reward_account
            .to_address()
            .to_bech32(None)
            .unwrap_or_default();
        let registered = ctx
            .find_account_context(&bech)
            .map(|a| a.is_registered)
            .unwrap_or(false);
        if !registered {
            errors.push(ValidationPhase1Error::new(
                Phase1Error::ProposalReturnAccountDoesNotExist {
                    return_account: bech.clone(),
                },
                location.clone(),
            ));
        }

        let gov_action = proposal.governance_action();
        let proposal_index = i as u32;

        // Guardrails (constitution policy) script hash. When the caller supplied
        // the current constitution, ParameterChange and TreasuryWithdrawals
        // actions must carry exactly the constitution's guardrails script hash
        // (and none when the constitution defines none). Other action kinds are
        // not subject to the guardrails script.
        if let Some(constitution) = &ctx.constitution {
            let supplied = match gov_action.kind() {
                csl::GovernanceActionKind::ParameterChangeAction => Some(
                    gov_action
                        .as_parameter_change_action()
                        .and_then(|a| a.policy_hash())
                        .map(|h| h.to_hex()),
                ),
                csl::GovernanceActionKind::TreasuryWithdrawalsAction => Some(
                    gov_action
                        .as_treasury_withdrawals_action()
                        .and_then(|a| a.policy_hash())
                        .map(|h| h.to_hex()),
                ),
                _ => None,
            };
            if let Some(supplied_hash) = supplied {
                let expected_hash = constitution.guardrail_script_hash.clone();
                let norm = |h: &Option<String>| h.as_ref().map(|s| s.to_lowercase());
                if norm(&supplied_hash) != norm(&expected_hash) {
                    errors.push(ValidationPhase1Error::new(
                        Phase1Error::InvalidConstitutionPolicyHash {
                            supplied_hash,
                            expected_hash,
                        },
                        location.clone(),
                    ));
                }
            }
        }

        match gov_action.kind() {
            csl::GovernanceActionKind::TreasuryWithdrawalsAction => {
                if let Some(action) = gov_action.as_treasury_withdrawals_action() {
                    check_treasury_withdrawals(
                        &action,
                        proposal_index,
                        &location,
                        ctx,
                        errors,
                    );
                }
            }
            csl::GovernanceActionKind::UpdateCommitteeAction => {
                if let Some(action) = gov_action.as_new_committee_action() {
                    check_committee_update_conflict(&action, &location, errors);
                }
            }
            _ => {}
        }

        // prev_gov_action_id check: if the action references a previous id,
        // it must exist in the ledger.
        if let Some(prev) = extract_prev_gov_action_id(&gov_action) {
            let local_prev = gov_action_id_from_csl(&prev);
            if ctx.find_gov_action_context(local_prev.clone()).is_none() {
                errors.push(ValidationPhase1Error::new(
                    Phase1Error::GovActionsDoNotExist {
                        invalid_action_ids: vec![local_prev],
                    },
                    location.clone(),
                ));
            }
        }
    }
}

fn check_treasury_withdrawals(
    action: &csl::TreasuryWithdrawalsAction,
    proposal_index: u32,
    location: &str,
    ctx: &ValidationInputContext,
    errors: &mut Vec<ValidationPhase1Error>,
) {
    let withdrawals = action.withdrawals();
    let keys = withdrawals.keys();

    // Sum must be > 0.
    let mut total: u128 = 0;
    for k in 0..keys.len() {
        let reward_addr = keys.get(k);
        if let Some(coin) = withdrawals.get(&reward_addr) {
            total = total.saturating_add(
                coin.to_str().parse::<u128>().unwrap_or(0),
            );
        }
    }
    if total == 0 {
        errors.push(ValidationPhase1Error::new(
            Phase1Error::ZeroTreasuryWithdrawals {
                gov_action: GovernanceActionId {
                    tx_hash: vec![0; 32],
                    index: proposal_index,
                },
            },
            location.to_string(),
        ));
    }

    // Every target account must be a registered stake account.
    for k in 0..keys.len() {
        let reward_addr = keys.get(k);
        let bech = reward_addr
            .to_address()
            .to_bech32(None)
            .unwrap_or_default();
        let registered = ctx
            .find_account_context(&bech)
            .map(|a| a.is_registered)
            .unwrap_or(false);
        if !registered {
            errors.push(ValidationPhase1Error::new(
                Phase1Error::TreasuryWithdrawalReturnAccountsDoNotExist {
                    missing_account: bech,
                },
                location.to_string(),
            ));
        }
    }
}

fn check_committee_update_conflict(
    action: &csl::UpdateCommitteeAction,
    location: &str,
    errors: &mut Vec<ValidationPhase1Error>,
) {
    let committee = action.committee();
    let add = committee.members_keys();
    let remove = action.members_to_remove();

    let mut add_set = HashSet::new();
    for i in 0..add.len() {
        add_set.insert(csl_credential_to_local_credential(&add.get(i)));
    }

    for i in 0..remove.len() {
        let local = csl_credential_to_local_credential(&remove.get(i));
        if add_set.contains(&local) {
            errors.push(ValidationPhase1Error::new(
                Phase1Error::ConflictingCommitteeUpdate {
                    conflicting_credentials: local,
                },
                location.to_string(),
            ));
        }
    }
}

fn extract_prev_gov_action_id(
    action: &csl::GovernanceAction,
) -> Option<csl::GovernanceActionId> {
    match action.kind() {
        csl::GovernanceActionKind::ParameterChangeAction => {
            action.as_parameter_change_action()?.gov_action_id()
        }
        csl::GovernanceActionKind::HardForkInitiationAction => {
            action.as_hard_fork_initiation_action()?.gov_action_id()
        }
        csl::GovernanceActionKind::NoConfidenceAction => {
            action.as_no_confidence_action()?.gov_action_id()
        }
        csl::GovernanceActionKind::UpdateCommitteeAction => {
            action.as_new_committee_action()?.gov_action_id()
        }
        csl::GovernanceActionKind::NewConstitutionAction => {
            action.as_new_constitution_action()?.gov_action_id()
        }
        // TreasuryWithdrawals, InfoAction have no prev_gov_action_id
        _ => None,
    }
}

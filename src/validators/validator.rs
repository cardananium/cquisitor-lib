use crate::bingen::wasm_bindgen;
use crate::common::TxInput;
use crate::js_error::JsError;
use crate::validators::common::{GovernanceActionId, GovernanceActionType, NetworkType};
use crate::validators::helpers::csl_credential_to_local_credential;
use crate::validators::input_contexts::NecessaryInputData;
use crate::validators::input_contexts::ValidationInputContext;
use crate::validators::phase_1::validation::fee::FeeValidator;
use crate::validators::phase_1::validation::{
    AuxiliaryDataValidator, BalanceValidator, CollateralValidator, GovernanceValidator,
    NetworkValidator, OutputValidator, RegistrationValidator, TransactionLimitsValidator,
    WitnessValidator,
};
use crate::validators::phase_2;
use crate::validators::validation_result::ValidationResult;
use cardano_serialization_lib as csl;
use std::collections::HashSet;

#[wasm_bindgen]
pub fn get_necessary_data_list_js(tx_hex: &str, network_type: &str) -> Result<String, JsError> {
    let network_type: NetworkType = serde_json::from_str(&format!("\"{}\"", network_type))
        .map_err(|e| JsError::new(&format!("Failed to parse network type: {}", e)))?;

    let necessary_data = get_necessary_data_list(tx_hex, network_type)
        .map_err(|e| JsError::new(&format!("Failed to get necessary data: {}", e)))?;

    serde_json::to_string(&necessary_data)
        .map_err(|e| JsError::new(&format!("Failed to serialize NecessaryInputData: {}", e)))
}

pub fn get_necessary_data_list(tx_hex: &str, network_type: NetworkType) -> Result<NecessaryInputData, String> {
    let csl_tx = csl::Transaction::from_hex(tx_hex)
        .map_err(|e| format!("Failed to parse transaction: {:?}", e))?;

    let mut utxos = HashSet::new();
    let mut accounts = HashSet::new();
    let mut pools = HashSet::new();
    let mut d_reps = HashSet::new();
    let mut gov_actions = HashSet::new();
    let mut last_enacted_gov_action = HashSet::new();
    let mut committee_members_cold = HashSet::new();
    let mut committee_members_hot = HashSet::new();

    let tx_body = csl_tx.body();

    // 1. Collect UTXOs from transaction inputs
    let inputs = tx_body.inputs();
    for i in 0..inputs.len() {
        let input = inputs.get(i);
        utxos.insert(TxInput {
            tx_hash: input.transaction_id().to_hex(),
            output_index: input.index(),
        });
    }

    // 2. Collect UTXOs from collateral inputs
    if let Some(collateral) = tx_body.collateral() {
        for i in 0..collateral.len() {
            let input = collateral.get(i);
            utxos.insert(TxInput {
                tx_hash: input.transaction_id().to_hex(),
                output_index: input.index(),
            });
        }
    }

    // 3. Collect UTXOs from reference inputs
    if let Some(ref_inputs) = tx_body.reference_inputs() {
        for i in 0..ref_inputs.len() {
            let input = ref_inputs.get(i);
            utxos.insert(TxInput {
                tx_hash: input.transaction_id().to_hex(),
                output_index: input.index(),
            });
        }
    }

    // 4. Collect reward accounts from withdrawals
    if let Some(withdrawals) = tx_body.withdrawals() {
        let withdrawal_keys = withdrawals.keys();
        for i in 0..withdrawal_keys.len() {
            let reward_address = withdrawal_keys.get(i);
            accounts.insert(
                reward_address
                    .to_address()
                    .to_bech32(None)
                    .unwrap_or_else(|_| "".to_string()),
            );
        }
    }

    // 5. Collect data from certificates
    if let Some(certs) = tx_body.certs() {
        for i in 0..certs.len() {
            let cert = certs.get(i);
            match cert.kind() {
                csl::CertificateKind::StakeRegistration => {
                    if let Some(reg_cert) = cert.as_stake_registration() {
                        let stake_credential = reg_cert.stake_credential();
                        let reward_address =
                            credential_to_reward_address(&stake_credential, &network_type);
                        accounts.insert(reward_address);
                    }
                }
                csl::CertificateKind::StakeDeregistration => {
                    if let Some(dereg_cert) = cert.as_stake_deregistration() {
                        let stake_credential = dereg_cert.stake_credential();
                        let reward_address =
                            credential_to_reward_address(&stake_credential, &network_type);
                        accounts.insert(reward_address);
                    }
                }
                csl::CertificateKind::StakeDelegation => {
                    if let Some(deleg_cert) = cert.as_stake_delegation() {
                        let stake_credential = deleg_cert.stake_credential();
                        let reward_address =
                            credential_to_reward_address(&stake_credential, &network_type);
                        accounts.insert(reward_address);

                        let pool_id = deleg_cert.pool_keyhash().to_hex();
                        pools.insert(pool_id);
                    }
                }
                csl::CertificateKind::PoolRegistration => {
                    if let Some(pool_reg_cert) = cert.as_pool_registration() {
                        let pool_id = pool_reg_cert.pool_params().operator().to_hex();
                        pools.insert(pool_id);
                    }
                }
                csl::CertificateKind::PoolRetirement => {
                    if let Some(pool_ret_cert) = cert.as_pool_retirement() {
                        let pool_id = pool_ret_cert.pool_keyhash().to_hex();
                        pools.insert(pool_id);
                    }
                }
                csl::CertificateKind::DRepRegistration => {
                    if let Some(drep_reg_cert) = cert.as_drep_registration() {
                        let drep_credential = drep_reg_cert.voting_credential();
                        let drep = csl::DRep::new_from_credential(&drep_credential);
                        let drep_id = drep.to_bech32(true).unwrap_or_else(|_| "".to_string());
                        d_reps.insert(drep_id);
                    }
                }
                csl::CertificateKind::DRepDeregistration => {
                    if let Some(drep_dereg_cert) = cert.as_drep_deregistration() {
                        let drep_credential = drep_dereg_cert.voting_credential();
                        let drep = csl::DRep::new_from_credential(&drep_credential);
                        let drep_id = drep.to_bech32(true).unwrap_or_else(|_| "".to_string());
                        d_reps.insert(drep_id);
                    }
                }
                csl::CertificateKind::DRepUpdate => {
                    if let Some(drep_update_cert) = cert.as_drep_update() {
                        let drep_credential = drep_update_cert.voting_credential();
                        let drep = csl::DRep::new_from_credential(&drep_credential);
                        let drep_id = drep.to_bech32(true).unwrap_or_else(|_| "".to_string());
                        d_reps.insert(drep_id);
                    }
                }
                csl::CertificateKind::CommitteeHotAuth => {
                    if let Some(committee_auth_cert) = cert.as_committee_hot_auth() {
                        let committee_cold_credential =
                            committee_auth_cert.committee_cold_credential();
                        let local_credential =
                            csl_credential_to_local_credential(&committee_cold_credential);
                        committee_members_cold.insert(local_credential);
                    }
                }
                csl::CertificateKind::CommitteeColdResign => {
                    if let Some(committee_resign_cert) = cert.as_committee_cold_resign() {
                        let committee_cold_credential =
                            committee_resign_cert.committee_cold_credential();
                        let local_credential =
                            csl_credential_to_local_credential(&committee_cold_credential);
                        committee_members_cold.insert(local_credential);
                    }
                }
                csl::CertificateKind::StakeRegistrationAndDelegation => {
                    if let Some(reg_deleg_cert) = cert.as_stake_registration_and_delegation() {
                        let stake_credential = reg_deleg_cert.stake_credential();
                        let reward_address =
                            credential_to_reward_address(&stake_credential, &network_type);
                        accounts.insert(reward_address);

                        let pool_id = reg_deleg_cert.pool_keyhash().to_hex();
                        pools.insert(pool_id);
                    }
                }
                csl::CertificateKind::StakeAndVoteDelegation => {
                    if let Some(stake_vote_deleg_cert) = cert.as_stake_and_vote_delegation() {
                        let stake_credential = stake_vote_deleg_cert.stake_credential();
                        let reward_address =
                            credential_to_reward_address(&stake_credential, &network_type);
                        accounts.insert(reward_address);

                        let pool_id = stake_vote_deleg_cert.pool_keyhash().to_hex();
                        pools.insert(pool_id);

                        let drep = stake_vote_deleg_cert
                            .drep()
                            .to_bech32(true)
                            .unwrap_or_else(|_| "".to_string());
                        d_reps.insert(drep);
                    }
                }
                csl::CertificateKind::StakeVoteRegistrationAndDelegation => {
                    if let Some(stake_vote_reg_deleg_cert) =
                        cert.as_stake_vote_registration_and_delegation()
                    {
                        let stake_credential = stake_vote_reg_deleg_cert.stake_credential();
                        let reward_address =
                            credential_to_reward_address(&stake_credential, &network_type);
                        accounts.insert(reward_address);

                        let pool_id = stake_vote_reg_deleg_cert.pool_keyhash().to_hex();
                        pools.insert(pool_id);

                        let drep = stake_vote_reg_deleg_cert
                            .drep()
                            .to_bech32(true)
                            .unwrap_or_else(|_| "".to_string());
                        d_reps.insert(drep);
                    }
                }
                csl::CertificateKind::VoteDelegation => {
                    if let Some(vote_deleg_cert) = cert.as_vote_delegation() {
                        let stake_credential = vote_deleg_cert.stake_credential();
                        let reward_address =
                            credential_to_reward_address(&stake_credential, &network_type);
                        accounts.insert(reward_address);

                        let drep = vote_deleg_cert
                            .drep()
                            .to_bech32(true)
                            .unwrap_or_else(|_| "".to_string());
                        d_reps.insert(drep);
                    }
                }
                csl::CertificateKind::VoteRegistrationAndDelegation => {
                    if let Some(vote_reg_deleg_cert) = cert.as_vote_registration_and_delegation() {
                        let stake_credential = vote_reg_deleg_cert.stake_credential();
                        let reward_address =
                            credential_to_reward_address(&stake_credential, &network_type);
                        accounts.insert(reward_address);

                        let drep = vote_reg_deleg_cert
                            .drep()
                            .to_bech32(true)
                            .unwrap_or_else(|_| "".to_string());
                        d_reps.insert(drep);
                    }
                }
                csl::CertificateKind::GenesisKeyDelegation => {}
                csl::CertificateKind::MoveInstantaneousRewardsCert => {}
            }
        }
    }

    // 6. Collect data from voting proposals
    if let Some(voting_proposals) = tx_body.voting_proposals() {
        for i in 0..voting_proposals.len() {
            let proposal = voting_proposals.get(i);

            // Every proposal procedure has a deposit return account that must be a
            // registered stake account (checked in validate_proposals). Collect it so the
            // caller fetches its registration status; without this the account context is
            // missing and validation always reports ProposalReturnAccountDoesNotExist.
            accounts.insert(
                proposal
                    .reward_account()
                    .to_address()
                    .to_bech32(None)
                    .unwrap_or_else(|_| "".to_string()),
            );

            let gov_action = proposal.governance_action();

            // Determine governance action type and add to last enacted if needed
            match gov_action.kind() {
                csl::GovernanceActionKind::ParameterChangeAction => {
                    last_enacted_gov_action.insert(GovernanceActionType::ParameterChangeAction);
                    let parameter_change_action = gov_action.as_parameter_change_action().unwrap();
                    let previous_gov_action_id = parameter_change_action.gov_action_id();
                    if let Some(previous_gov_action_id) = previous_gov_action_id {
                        gov_actions.insert(GovernanceActionId {
                            tx_hash: previous_gov_action_id.transaction_id().to_bytes(),
                            index: previous_gov_action_id.index(),
                        });
                    }
                }
                csl::GovernanceActionKind::HardForkInitiationAction => {
                    last_enacted_gov_action.insert(GovernanceActionType::HardForkInitiationAction);
                    let hard_fork_initiation_action =
                        gov_action.as_hard_fork_initiation_action().unwrap();
                    let previous_gov_action_id = hard_fork_initiation_action.gov_action_id();
                    if let Some(previous_gov_action_id) = previous_gov_action_id {
                        gov_actions.insert(GovernanceActionId {
                            tx_hash: previous_gov_action_id.transaction_id().to_bytes(),
                            index: previous_gov_action_id.index(),
                        });
                    }
                }
                csl::GovernanceActionKind::TreasuryWithdrawalsAction => {
                    last_enacted_gov_action.insert(GovernanceActionType::TreasuryWithdrawalsAction);
                    let treasury_withdrawals_action =
                        gov_action.as_treasury_withdrawals_action().unwrap();
                    let withdrawals = treasury_withdrawals_action.withdrawals();
                    let withdrawal_keys = withdrawals.keys();
                    for i in 0..withdrawal_keys.len() {
                        let reward_address = withdrawal_keys.get(i);
                        accounts.insert(
                            reward_address
                                .to_address()
                                .to_bech32(None)
                                .unwrap_or_else(|_| "".to_string()),
                        );
                    }
                }
                csl::GovernanceActionKind::NoConfidenceAction => {
                    last_enacted_gov_action.insert(GovernanceActionType::NoConfidenceAction);
                    let no_confidence_action = gov_action.as_no_confidence_action().unwrap();
                    let previous_gov_action_id = no_confidence_action.gov_action_id();
                    if let Some(previous_gov_action_id) = previous_gov_action_id {
                        gov_actions.insert(GovernanceActionId {
                            tx_hash: previous_gov_action_id.transaction_id().to_bytes(),
                            index: previous_gov_action_id.index(),
                        });
                    }
                }
                csl::GovernanceActionKind::UpdateCommitteeAction => {
                    last_enacted_gov_action.insert(GovernanceActionType::UpdateCommitteeAction);
                    let new_committee_action = gov_action.as_new_committee_action().unwrap();
                    let previous_gov_action_id = new_committee_action.gov_action_id();
                    if let Some(previous_gov_action_id) = previous_gov_action_id {
                        gov_actions.insert(GovernanceActionId {
                            tx_hash: previous_gov_action_id.transaction_id().to_bytes(),
                            index: previous_gov_action_id.index(),
                        });
                    }
                }
                csl::GovernanceActionKind::NewConstitutionAction => {
                    last_enacted_gov_action.insert(GovernanceActionType::NewConstitutionAction);
                    let new_constitution_action = gov_action.as_new_constitution_action().unwrap();
                    let previous_gov_action_id = new_constitution_action.gov_action_id();
                    if let Some(previous_gov_action_id) = previous_gov_action_id {
                        gov_actions.insert(GovernanceActionId {
                            tx_hash: previous_gov_action_id.transaction_id().to_bytes(),
                            index: previous_gov_action_id.index(),
                        });
                    }
                }
                csl::GovernanceActionKind::InfoAction => {
                    last_enacted_gov_action.insert(GovernanceActionType::InfoAction);
                }
            }
        }
    }

    // 7. Collect data from voting procedures (votes)
    if let Some(voting_procedures) = tx_body.voting_procedures() {
        let voters = voting_procedures.get_voters();
        for i in 0..voters.len() {
            let voter = voters.get(i).unwrap();
            match voter.kind() {
                csl::VoterKind::ConstitutionalCommitteeHotKeyHash => {
                    if let Some(key_hash) = voter.to_constitutional_committee_hot_credential() {
                        let local_credential = csl_credential_to_local_credential(&key_hash);
                        committee_members_hot.insert(local_credential);
                    }
                }
                csl::VoterKind::ConstitutionalCommitteeHotScriptHash => {
                    if let Some(script_hash) = voter.to_constitutional_committee_hot_credential() {
                        let local_credential = csl_credential_to_local_credential(&script_hash);
                        committee_members_hot.insert(local_credential);
                    }
                }
                csl::VoterKind::DRepKeyHash => {
                    if let Some(key_hash) = voter.to_drep_credential() {
                        let drep = csl::DRep::new_from_credential(&key_hash);
                        let drep_id = drep.to_bech32(true).unwrap_or_else(|_| "".to_string());
                        d_reps.insert(drep_id);
                    }
                }
                csl::VoterKind::DRepScriptHash => {
                    if let Some(script_hash) = voter.to_drep_credential() {
                        let drep = csl::DRep::new_from_credential(&script_hash);
                        let drep_id = drep.to_bech32(true).unwrap_or_else(|_| "".to_string());
                        d_reps.insert(drep_id);
                    }
                }
                csl::VoterKind::StakingPoolKeyHash => {
                    if let Some(pool_key_hash) = voter.to_stake_pool_key_hash() {
                        let pool_id = pool_key_hash.to_hex();
                        pools.insert(pool_id);
                    }
                }
            }

            // Get governance actions being voted on
            let action_ids = voting_procedures.get_governance_action_ids_by_voter(&voter);
            for j in 0..action_ids.len() {
                let action_id = action_ids.get(j).unwrap();
                gov_actions.insert(GovernanceActionId {
                    tx_hash: action_id.transaction_id().to_bytes(),
                    index: action_id.index(),
                });
            }
        }
    }

    Ok(NecessaryInputData {
        utxos: utxos.into_iter().collect(),
        accounts: accounts.into_iter().collect(),
        pools: pools.into_iter().collect(),
        d_reps: d_reps.into_iter().collect(),
        gov_actions: gov_actions.into_iter().collect(),
        last_enacted_gov_action: last_enacted_gov_action.into_iter().collect(),
        committee_members_cold: committee_members_cold.into_iter().collect(),
        committee_members_hot: committee_members_hot.into_iter().collect(),
    })
}

// Helper functions
fn credential_to_reward_address(
    credential: &csl::Credential,
    network_type: &NetworkType,
) -> String {
    let network_id = match network_type {
        NetworkType::Mainnet => csl::NetworkInfo::mainnet().network_id(),
        NetworkType::Preview => csl::NetworkInfo::testnet_preview().network_id(),
        NetworkType::Preprod => csl::NetworkInfo::testnet_preprod().network_id(),
    };
    let reward_address = csl::RewardAddress::new(network_id, credential);
    reward_address
        .to_address()
        .to_bech32(None)
        .unwrap_or_else(|_| "".to_string())
}

pub fn validate_transaction(
    tx_hex: &str,
    validation_context: ValidationInputContext,
) -> Result<ValidationResult, JsError> {
    let csl_tx = csl::FixedTransaction::from_hex(tx_hex)
        .map_err(|e| JsError::new(&format!("Failed to parse transaction: {:?}", e)))?;
    let tx_body = csl_tx.body();
    let tx_witness_set = csl_tx.witness_set();
    let tx_hash = csl_tx.transaction_hash();
    let auxiliary_data = csl_tx.auxiliary_data();
    let tx_size = tx_hex.len() / 2; // Convert hex string length to bytes

    let mut overall_result = ValidationResult::new_empty();

    // 1. Balance validation
    let balance_context = BalanceValidator::new(&tx_body, &validation_context);
    let balance_result = balance_context.validate();
    overall_result.append(balance_result);

    // 2. Fee validation
    let fee_context = FeeValidator::new(tx_size, &tx_body, &tx_witness_set, &validation_context)?;
    let fee_result = fee_context.validate();
    overall_result.append(fee_result);

    // 3. Witness validation
    let witness_context =
        WitnessValidator::new(&tx_body, &tx_witness_set, &tx_hash, &validation_context)?;
    let witness_result = witness_context.validate();
    overall_result.append(witness_result);

    // 4. Collateral validation
    let collateral_context =
        CollateralValidator::new(&tx_body, &tx_witness_set, &validation_context);
    let collateral_result = collateral_context.validate();
    overall_result.append(collateral_result);

    // 5. Auxiliary data validation
    let auxiliary_context = AuxiliaryDataValidator::new(&tx_body, auxiliary_data);
    let auxiliary_result = auxiliary_context.validate();
    overall_result.append(auxiliary_result);

    // 6. Registration validation (certificates)
    let registration_context = RegistrationValidator::new(&tx_body, &validation_context);
    let registration_result = registration_context.validate();
    overall_result.append(registration_result);

    // 7. Output validation
    let output_context = OutputValidator::new(&tx_body, &validation_context);
    let output_result = output_context.validate();
    overall_result.append(output_result);

    // 8. Transaction limits validation
    let transaction_limits_context =
        TransactionLimitsValidator::new(tx_size, &tx_body, &tx_witness_set, &validation_context)?;
    let transaction_limits_result = transaction_limits_context.validate();
    overall_result.append(transaction_limits_result);

    // 8a. Network-id validation
    let network_context = NetworkValidator::new(&tx_body, &validation_context);
    let network_result = network_context.validate();
    overall_result.append(network_result);

    // 8b. Governance / votes / proposals validation
    let governance_context = GovernanceValidator::new(&tx_body, &validation_context);
    let governance_result = governance_context.validate(&tx_body, &validation_context);
    overall_result.append(governance_result);

    // 9. Votes validation

    // 10. Phase 2 validation
    let phase_2_result = phase_2::validation::phase_2_validation(tx_hex, &validation_context)?;
    overall_result.append(phase_2_result);

    Ok(overall_result)
}

#[wasm_bindgen]
pub fn validate_transaction_js(tx_hex: &str, validation_context: &str) -> Result<String, JsError> {
    let validation_context =
        serde_json::from_str(validation_context).map_err(|e| JsError::new(&e.to_string()))?;
    let validation_result = validate_transaction(tx_hex, validation_context)?;
    let json_result =
        serde_json::to_string(&validation_result).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(json_result)
}

//! Validates network_id consistency across every part of the tx that embeds
//! one, mirroring cardano-ledger's UTXO / GOV rules:
//!
//! * Every output address must match the ledger's network.
//! * Every withdrawal reward account must match.
//! * `tx_body.network_id` (if present) must match.
//! * `voting_proposal.reward_account` must match (ProposalProcedureNetworkIdMismatch).
//! * Every `TreasuryWithdrawalsAction` return account must match
//!   (TreasuryWithdrawalsNetworkIdMismatch).

use std::collections::HashSet;

use cardano_serialization_lib as csl;

use crate::validators::{
    common::NetworkType,
    helpers::string_to_csl_address,
    input_contexts::ValidationInputContext,
    phase_1::errors::{Phase1Error, ValidationPhase1Error},
    validation_result::ValidationResult,
};

pub struct NetworkValidator {
    pub expected_network_id: u8,
    pub wrong_output_addresses: HashSet<String>,
    pub wrong_withdrawal_addresses: HashSet<String>,
    pub wrong_body_network_id: Option<u8>,
    pub wrong_proposal_return_accounts: Vec<(u32, String)>,
    pub wrong_treasury_withdrawal_accounts: Vec<(u32, String)>,
}

fn expected_network_id(network_type: &NetworkType) -> u8 {
    match network_type {
        NetworkType::Mainnet => csl::NetworkInfo::mainnet().network_id(),
        NetworkType::Preview => csl::NetworkInfo::testnet_preview().network_id(),
        NetworkType::Preprod => csl::NetworkInfo::testnet_preprod().network_id(),
    }
}

impl NetworkValidator {
    pub fn new(
        tx_body: &csl::TransactionBody,
        validation_input_context: &ValidationInputContext,
    ) -> Self {
        let expected = expected_network_id(&validation_input_context.network_type);

        let wrong_output_addresses = collect_wrong_output_addresses(tx_body, expected);
        let wrong_withdrawal_addresses = collect_wrong_withdrawal_addresses(tx_body, expected);
        let wrong_body_network_id = extract_wrong_body_network_id(tx_body, expected);
        let wrong_proposal_return_accounts =
            collect_wrong_proposal_return_accounts(tx_body, expected);
        let wrong_treasury_withdrawal_accounts =
            collect_wrong_treasury_withdrawal_accounts(tx_body, expected);

        Self {
            expected_network_id: expected,
            wrong_output_addresses,
            wrong_withdrawal_addresses,
            wrong_body_network_id,
            wrong_proposal_return_accounts,
            wrong_treasury_withdrawal_accounts,
        }
    }

    pub fn validate(&self) -> ValidationResult {
        let mut errors = Vec::new();

        if !self.wrong_output_addresses.is_empty() {
            errors.push(ValidationPhase1Error::new(
                Phase1Error::WrongNetwork {
                    wrong_addresses: self.wrong_output_addresses.clone(),
                },
                "transaction.body.outputs".to_string(),
            ));
        }

        if !self.wrong_withdrawal_addresses.is_empty() {
            errors.push(ValidationPhase1Error::new(
                Phase1Error::WrongNetworkWithdrawal {
                    wrong_addresses: self.wrong_withdrawal_addresses.clone(),
                },
                "transaction.body.withdrawals".to_string(),
            ));
        }

        if let Some(actual) = self.wrong_body_network_id {
            errors.push(ValidationPhase1Error::new(
                Phase1Error::WrongNetworkInTxBody {
                    actual_network: actual,
                    expected_network: self.expected_network_id,
                },
                "transaction.body.network_id".to_string(),
            ));
        }

        for (index, reward_account) in &self.wrong_proposal_return_accounts {
            errors.push(ValidationPhase1Error::new(
                Phase1Error::ProposalProcedureNetworkIdMismatch {
                    reward_account: reward_account.clone(),
                    expected_network: self.expected_network_id,
                },
                format!("transaction.body.voting_proposals.{}", index),
            ));
        }

        for (index, reward_account) in &self.wrong_treasury_withdrawal_accounts {
            errors.push(ValidationPhase1Error::new(
                Phase1Error::TreasuryWithdrawalsNetworkIdMismatch {
                    mismatched_account: reward_account.clone(),
                    expected_network: self.expected_network_id,
                },
                format!("transaction.body.voting_proposals.{}", index),
            ));
        }

        ValidationResult::new_phase_1(errors, Vec::new())
    }
}

fn collect_wrong_output_addresses(
    tx_body: &csl::TransactionBody,
    expected: u8,
) -> HashSet<String> {
    let outputs = tx_body.outputs();
    let mut wrong = HashSet::new();
    for i in 0..outputs.len() {
        let address = outputs.get(i).address();
        // Address::network_id returns an error for malformed Byron payloads —
        // treat those as "can't tell" and leave for other validators to flag.
        if let Ok(network_id) = address.network_id() {
            if network_id != expected {
                if let Ok(bech32) = address.to_bech32(None) {
                    wrong.insert(bech32);
                }
            }
        }
    }
    wrong
}

fn collect_wrong_withdrawal_addresses(
    tx_body: &csl::TransactionBody,
    expected: u8,
) -> HashSet<String> {
    let mut wrong = HashSet::new();
    if let Some(withdrawals) = tx_body.withdrawals() {
        let keys = withdrawals.keys();
        for i in 0..keys.len() {
            let reward_addr = keys.get(i);
            if reward_addr.network_id() != expected {
                if let Ok(bech32) = reward_addr.to_address().to_bech32(None) {
                    wrong.insert(bech32);
                }
            }
        }
    }
    wrong
}

fn extract_wrong_body_network_id(
    tx_body: &csl::TransactionBody,
    expected: u8,
) -> Option<u8> {
    let declared = tx_body.network_id()?;
    let declared_id = match declared.kind() {
        csl::NetworkIdKind::Mainnet => csl::NetworkInfo::mainnet().network_id(),
        csl::NetworkIdKind::Testnet => 0,
    };
    if declared_id != expected {
        Some(declared_id)
    } else {
        None
    }
}

fn collect_wrong_proposal_return_accounts(
    tx_body: &csl::TransactionBody,
    expected: u8,
) -> Vec<(u32, String)> {
    let mut wrong = Vec::new();
    if let Some(proposals) = tx_body.voting_proposals() {
        for i in 0..proposals.len() {
            let proposal = proposals.get(i);
            let reward_account = proposal.reward_account();
            if reward_account.network_id() != expected {
                let bech32 = reward_account
                    .to_address()
                    .to_bech32(None)
                    .unwrap_or_default();
                wrong.push((i as u32, bech32));
            }
        }
    }
    wrong
}

fn collect_wrong_treasury_withdrawal_accounts(
    tx_body: &csl::TransactionBody,
    expected: u8,
) -> Vec<(u32, String)> {
    let mut wrong = Vec::new();
    let Some(proposals) = tx_body.voting_proposals() else {
        return wrong;
    };
    for i in 0..proposals.len() {
        let proposal = proposals.get(i);
        let gov_action = proposal.governance_action();
        if gov_action.kind() != csl::GovernanceActionKind::TreasuryWithdrawalsAction {
            continue;
        }
        let Some(treasury) = gov_action.as_treasury_withdrawals_action() else {
            continue;
        };
        let withdrawals = treasury.withdrawals();
        let keys = withdrawals.keys();
        for k in 0..keys.len() {
            let reward_addr = keys.get(k);
            if reward_addr.network_id() != expected {
                let bech32 = reward_addr
                    .to_address()
                    .to_bech32(None)
                    .unwrap_or_default();
                wrong.push((i as u32, bech32));
            }
        }
    }
    wrong
}

// Keep `string_to_csl_address` referenced so future address-source variants
// (e.g., collateral_return, proposal anchors) can reuse the same helper.
#[allow(dead_code)]
fn _unused() {
    let _ = string_to_csl_address;
}

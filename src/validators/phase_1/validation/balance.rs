use crate::validators::common::Value;
use crate::validators::helpers::credential_to_bech32_reward_address;
use crate::validators::input_contexts::ValidationInputContext;
use crate::validators::phase_1::errors::{
    Phase1Error, Phase1Warning, ValidationPhase1Error, ValidationPhase1Warning,
};
use crate::validators::validation_result::ValidationResult;
use crate::validators::value::MultiAsset;
use cardano_serialization_lib as csl;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DepositType {
    VotingProposal { amount: i128, index: u32 },
    StakeRegistration { amount: i128, index: u32 },
    DrepRegistration { amount: i128, index: u32 },
    PoolRegistration { amount: i128, index: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefundType {
    StakeDeregistration {
        amount: i128,
        index: u32,
        reward_address: String,
    },
    DrepDeregistration {
        amount: i128,
        index: u32,
        drep_bech32: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidRefund {
    actual_refund: RefundType,
    expected_refund_amount: i128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputsDecomposition {
    pub total_inputs: Value,
    pub refunds: Vec<RefundType>,
    pub withdrawals: Vec<Withdrawal>,
    pub mints: MultiAsset,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Withdrawal {
    pub amount: u64,
    pub index: u32,
    pub reward_address: String,
}

impl InputsDecomposition {
    pub fn get_total_sum(&self) -> Value {
        let mut total_sum = self.total_inputs.clone();
        for refund in self.refunds.iter() {
            match refund {
                RefundType::StakeDeregistration { amount, .. } => total_sum.add_coins(*amount),
                RefundType::DrepDeregistration { amount, .. } => total_sum.add_coins(*amount),
            }
        }
        total_sum.add_multiasset(&self.mints);
        for withdrawal in self.withdrawals.iter() {
            total_sum.add_coins(withdrawal.amount as i128);
        }
        total_sum
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputsDecomposition {
    pub total_output: Value,
    pub deposits: Vec<DepositType>,
    pub burn: MultiAsset,
    pub fees: i128,
    pub donation: i128,
}

impl OutputsDecomposition {
    pub fn get_total_sum(&self) -> Value {
        let mut total_sum = self.total_output.clone();
        total_sum.add_multiasset(&self.burn);
        total_sum.add_coins(self.fees);
        for deposit in self.deposits.iter() {
            match deposit {
                DepositType::VotingProposal { amount, .. } => total_sum.add_coins(*amount),
                DepositType::StakeRegistration { amount, .. } => total_sum.add_coins(*amount),
                DepositType::DrepRegistration { amount, .. } => total_sum.add_coins(*amount),
                DepositType::PoolRegistration { amount, .. } => total_sum.add_coins(*amount),
            }
        }
        total_sum.add_coins(self.donation);
        total_sum
    }
}

pub struct BalanceValidator<'a> {
    pub inputs: InputsDecomposition,
    pub outputs: OutputsDecomposition,

    pub total_full_input: Value,
    pub total_full_output: Value,

    pub validation_input_context: &'a ValidationInputContext,
    pub treasury_value: Option<u64>,
}

impl<'a> BalanceValidator<'a> {
    pub fn new(
        tx_body: &csl::TransactionBody,
        validation_input_context: &'a ValidationInputContext,
    ) -> Self {
        let total_inputs = calculate_total_inputs(tx_body, validation_input_context);
        let (refunds, cert_deposits) =
            calculate_deposits_and_refunds(tx_body, validation_input_context);

        let mut deposits = calculate_voting_proposals_deposits(tx_body);
        deposits.extend(cert_deposits);

        let withdrawals = get_withdrawals(tx_body);
        let mints = calculate_mints(tx_body);

        let total_output = calculate_total_output(tx_body);
        let burn = calculate_burn(tx_body);
        let fees = tx_body.fee().to_str().parse::<i128>().unwrap_or(0);
        let donation = get_donation(tx_body);
        let treasury_value = tx_body
            .current_treasury_value()
            .map(|value| value.to_str().parse::<u64>().unwrap_or(0));

        let inputs = InputsDecomposition {
            total_inputs,
            refunds,
            withdrawals,
            mints,
        };

        let outputs = OutputsDecomposition {
            total_output,
            deposits,
            burn,
            fees,
            donation,
        };

        let total_full_input = inputs.get_total_sum();
        let total_full_output = outputs.get_total_sum();

        Self {
            inputs,
            outputs,
            total_full_input,
            total_full_output,
            validation_input_context,
            treasury_value,
        }
    }

    pub fn validate(&self) -> ValidationResult {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // Check if total input equals total output
        if self.total_full_input != self.total_full_output {
            errors.push(ValidationPhase1Error::new(
                Phase1Error::ValueNotConservedUTxO {
                    input_sum: self.total_full_input.clone(),
                    output_sum: self.total_full_output.clone(),
                    difference: &self.total_full_input - &self.total_full_output,
                },
                "transaction.body".to_string(),
            ));
        }

        if let Some(treasury_value) = self.treasury_value {
            if self.validation_input_context.treasury_value != treasury_value {
                errors.push(ValidationPhase1Error::new(
                    Phase1Error::TreasuryValueMismatch {
                        declared_value: self.validation_input_context.treasury_value,
                        actual_value: treasury_value,
                    },
                    "transaction.body.current_treasury_value".to_string(),
                ));
            }
        }

        let withdrawals_result = self.validate_withdrawals_balance();
        errors.extend(withdrawals_result.errors);
        warnings.extend(withdrawals_result.warnings);

        let deposits_result = self.validate_deposits();
        errors.extend(deposits_result.errors);
        warnings.extend(deposits_result.warnings);

        let refunds_result = self.validate_refunds();
        errors.extend(refunds_result.errors);
        warnings.extend(refunds_result.warnings);

        ValidationResult::new_phase_1(errors, warnings)
    }

    fn validate_withdrawals_balance(&self) -> ValidationResult {
        let mut errors = Vec::new();
        let warnings = Vec::new();

        for withdrawal in self.inputs.withdrawals.iter() {
            let reward_address = withdrawal.reward_address.clone();
            let account_context = self
                .validation_input_context
                .find_account_context(&reward_address);
            if let Some(account_context) = account_context {
                if account_context.is_registered {
                    if let Some(balance) = account_context.balance {
                        if withdrawal.amount != balance {
                            errors.push(ValidationPhase1Error::new(
                                Phase1Error::WrongRequestedWithdrawalAmount {
                                    expected_amount: balance as i128,
                                    requested_amount: withdrawal.amount as i128,
                                    reward_address: reward_address.clone(),
                                },
                                format!("transaction.body.withdrawals.{}", withdrawal.index),
                            ));
                        }
                    }
                    // DRep-delegation gate (Conway v10+, CIP-1694): only checks the
                    // pre-tx state of the account. Any VoteDelegation cert appearing
                    // in this same tx is intentionally NOT considered here — by ledger
                    // semantics, withdrawals are validated against the account state as
                    // it exists at the start of the tx, before this tx's CERTS take
                    // effect. So you cannot first delegate to a DRep and withdraw in
                    // the same tx; the delegation must already be in place.
                    // Also gated on key-hash creds only — script-hash stake creds are
                    // exempt from this requirement (see is_key_hash_reward_address).
                    if account_context.delegated_to_drep.is_none()
                        && is_key_hash_reward_address(&reward_address)
                    {
                        errors.push(ValidationPhase1Error::new(
                            Phase1Error::WithdrawalNotAllowedBecauseNotDelegatedToDRep {
                                reward_address: reward_address.clone(),
                            },
                            format!("transaction.body.withdrawals.{}", withdrawal.index),
                        ));
                    }
                } else {
                    errors.push(ValidationPhase1Error::new(
                        Phase1Error::RewardAccountNotExisting {
                            reward_address: reward_address.clone(),
                        },
                        format!("transaction.body.withdrawals.{}", withdrawal.index),
                    ));
                }
            } else {
                errors.push(ValidationPhase1Error::new(
                    Phase1Error::RewardAccountNotExisting {
                        reward_address: reward_address.clone(),
                    },
                    format!("transaction.body.withdrawals.{}", withdrawal.index),
                ));
            }
        }
        ValidationResult::new_phase_1(errors, warnings)
    }

    fn validate_deposits(&self) -> ValidationResult {
        let mut errors = Vec::new();
        let warnings = Vec::new();

        for deposit in self.outputs.deposits.iter() {
            match deposit {
                DepositType::StakeRegistration { amount, index } => {
                    let stake_key_deposit = self
                        .validation_input_context
                        .protocol_parameters
                        .stake_key_deposit;
                    if *amount != stake_key_deposit as i128 {
                        errors.push(ValidationPhase1Error::new(
                            Phase1Error::StakeRegistrationWrongDeposit {
                                supplied_deposit: *amount,
                                required_deposit: stake_key_deposit as i128,
                            },
                            format!("transaction.body.certs.{}", index),
                        ));
                    }
                }
                DepositType::DrepRegistration { amount, index } => {
                    let drep_deposit = self
                        .validation_input_context
                        .protocol_parameters
                        .drep_deposit;
                    if *amount != drep_deposit as i128 {
                        errors.push(ValidationPhase1Error::new(
                            Phase1Error::DRepIncorrectDeposit {
                                supplied_deposit: *amount,
                                required_deposit: drep_deposit as i128,
                            },
                            format!("transaction.body.certs.{}", index),
                        ));
                    }
                }
                DepositType::PoolRegistration { amount, index } => {
                    let stake_pool_deposit = self
                        .validation_input_context
                        .protocol_parameters
                        .stake_pool_deposit;
                    if *amount != stake_pool_deposit as i128 {
                        errors.push(ValidationPhase1Error::new(
                            Phase1Error::PoolRegistrationWrongDeposit {
                                supplied_deposit: *amount,
                                required_deposit: stake_pool_deposit as i128,
                            },
                            format!("transaction.body.certs.{}", index),
                        ));
                    }
                }
                DepositType::VotingProposal { amount, index } => {
                    let proposal_deposit = self
                        .validation_input_context
                        .protocol_parameters
                        .governance_action_deposit;
                    if *amount != proposal_deposit as i128 {
                        errors.push(ValidationPhase1Error::new(
                            Phase1Error::VotingProposalIncorrectDeposit {
                                supplied_deposit: *amount,
                                required_deposit: proposal_deposit as i128,
                                proposal_index: *index,
                            },
                            format!("transaction.body.voting_proposals.{}", index),
                        ));
                    }
                }
            }
        }
        ValidationResult::new_phase_1(errors, warnings)
    }

    fn validate_refunds(&self) -> ValidationResult {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        for refund in self.inputs.refunds.iter() {
            match refund {
                RefundType::StakeDeregistration {
                    amount,
                    index,
                    reward_address,
                } => {
                    if let Some(account_context) = self
                        .validation_input_context
                        .find_account_context(&reward_address)
                    {
                        if let Some(payed_deposit) = account_context.payed_deposit {
                            if *amount != payed_deposit as i128 {
                                errors.push(ValidationPhase1Error::new(
                                    Phase1Error::StakeDeregistrationWrongRefund {
                                        supplied_refund: *amount,
                                        required_refund: payed_deposit as i128,
                                    },
                                    format!("transaction.body.certs.{}", index),
                                ));
                            }
                        } else {
                            warnings.push(ValidationPhase1Warning::new(
                                Phase1Warning::CannotCheckStakeDeregistrationRefund {},
                                format!("transaction.body.certs.{}", index),
                            ));
                        }
                    } else {
                        warnings.push(ValidationPhase1Warning::new(
                            Phase1Warning::CannotCheckStakeDeregistrationRefund {},
                            format!("transaction.body.certs.{}", index),
                        ));
                    }
                }
                RefundType::DrepDeregistration {
                    amount,
                    index,
                    drep_bech32,
                } => {
                    let drep_context = self
                        .validation_input_context
                        .find_drep_context(&drep_bech32);
                    if let Some(drep_context) = drep_context {
                        if let Some(payed_deposit) = drep_context.payed_deposit {
                            if *amount != payed_deposit as i128 {
                                errors.push(ValidationPhase1Error::new(
                                    Phase1Error::DRepDeregistrationWrongRefund {
                                        supplied_refund: *amount,
                                        required_refund: payed_deposit as i128,
                                    },
                                    format!("transaction.body.certs.{}", index),
                                ));
                            }
                        } else {
                            warnings.push(ValidationPhase1Warning::new(
                                Phase1Warning::CannotCheckDRepDeregistrationRefund {},
                                format!("transaction.body.certs.{}", index),
                            ));
                        }
                    } else {
                        warnings.push(ValidationPhase1Warning::new(
                            Phase1Warning::CannotCheckDRepDeregistrationRefund {},
                            format!("transaction.body.certs.{}", index),
                        ));
                    }
                }
            }
        }
        ValidationResult::new_phase_1(errors, warnings)
    }
}

fn calculate_total_inputs(
    tx_body: &csl::TransactionBody,
    validation_input_context: &ValidationInputContext,
) -> Value {
    tx_body
        .inputs()
        .into_iter()
        .map(|input| {
            let utxo =
                validation_input_context.find_utxo(input.transaction_id().to_hex(), input.index());
            if let Some(utxo) = utxo {
                Value::new_from_common_assets(&utxo.utxo.output.amount)
            } else {
                Value::new_from_coins(0)
            }
        })
        .fold(Value::new_from_coins(0), |acc, value| acc + value)
}

fn calculate_deposits_and_refunds(
    tx_body: &csl::TransactionBody,
    validation_input_context: &ValidationInputContext,
) -> (Vec<RefundType>, Vec<DepositType>) {
    let mut refunds = Vec::new();
    let mut deposits = Vec::new();

    let certificates = tx_body.certs();
    if let Some(certificates) = certificates {
        let certs_count = certificates.len();
        for i in 0..certs_count {
            let cert = certificates.get(i);
            let cert_type = cert.kind();
            match cert_type {
                csl::CertificateKind::StakeRegistration => {
                    let reg_cert = cert.as_stake_registration().unwrap();
                    let explicit_deposit = reg_cert.coin();
                    if let Some(explicit_deposit) = explicit_deposit {
                        deposits.push(DepositType::StakeRegistration {
                            amount: explicit_deposit.to_str().parse::<i128>().unwrap_or(0),
                            index: i as u32,
                        });
                    } else {
                        deposits.push(DepositType::StakeRegistration {
                            amount: validation_input_context
                                .protocol_parameters
                                .stake_key_deposit as i128,
                            index: i as u32,
                        });
                    }
                }
                csl::CertificateKind::StakeDeregistration => {
                    let dereg_cert = cert.as_stake_deregistration().unwrap();
                    let explitict_refund = dereg_cert.coin();
                    let payedout_address = credential_to_bech32_reward_address(
                        &dereg_cert.stake_credential(),
                        &validation_input_context.network_type,
                    );
                    let account_context =
                        validation_input_context.find_account_context(&payedout_address);
                    if let Some(explicit_refund) = explitict_refund {
                        refunds.push(RefundType::StakeDeregistration {
                            amount: explicit_refund.to_str().parse::<i128>().unwrap_or(0),
                            index: i as u32,
                            reward_address: payedout_address.clone(),
                        });
                    } else {
                        if let Some(account_context) = account_context {
                            if let Some(payed_deposit) = account_context.payed_deposit {
                                refunds.push(RefundType::StakeDeregistration {
                                    amount: payed_deposit as i128,
                                    index: i as u32,
                                    reward_address: payedout_address.clone(),
                                });
                            }
                        } else {
                            refunds.push(RefundType::StakeDeregistration {
                                amount: validation_input_context
                                    .protocol_parameters
                                    .stake_key_deposit
                                    as i128,
                                index: i as u32,
                                reward_address: payedout_address.clone(),
                            });
                        }
                    }
                }
                csl::CertificateKind::StakeDelegation => {}
                csl::CertificateKind::PoolRegistration => {
                    let pool_registration_cert = cert.as_pool_registration().unwrap();
                    let pool_operator = pool_registration_cert.pool_params().operator();
                    let pool_registration =
                        validation_input_context.find_pool_context(&pool_operator.to_hex());
                    if !(pool_registration
                        .map_or(false, |pool_registration| pool_registration.is_registered))
                    {
                        deposits.push(DepositType::PoolRegistration {
                            amount: validation_input_context
                                .protocol_parameters
                                .stake_pool_deposit as i128,
                            index: i as u32,
                        });
                    }
                }
                csl::CertificateKind::PoolRetirement => {}
                csl::CertificateKind::GenesisKeyDelegation => {}
                csl::CertificateKind::MoveInstantaneousRewardsCert => {}
                csl::CertificateKind::CommitteeHotAuth => {}
                csl::CertificateKind::CommitteeColdResign => {}
                csl::CertificateKind::DRepDeregistration => {
                    let dereg_cert = cert.as_drep_deregistration().unwrap();
                    let explicit_refund = dereg_cert.coin();
                    let drep_credential = dereg_cert.voting_credential();
                    let drep = csl::DRep::new_from_credential(&drep_credential);
                    let drep_bech32 = drep.to_bech32(true).unwrap_or_else(|_| "".to_string());
                    refunds.push(RefundType::DrepDeregistration {
                        amount: explicit_refund.to_str().parse::<i128>().unwrap_or(0),
                        index: i as u32,
                        drep_bech32,
                    });
                }
                csl::CertificateKind::DRepRegistration => {
                    let reg_cert = cert.as_drep_registration().unwrap();
                    let explicit_deposit = reg_cert.coin();
                    deposits.push(DepositType::DrepRegistration {
                        amount: explicit_deposit.to_str().parse::<i128>().unwrap_or(0),
                        index: i as u32,
                    });
                }
                csl::CertificateKind::DRepUpdate => {}
                csl::CertificateKind::StakeAndVoteDelegation => {}
                csl::CertificateKind::StakeRegistrationAndDelegation => {
                    let reg_cert = cert.as_stake_registration_and_delegation().unwrap();
                    let explicit_deposit = reg_cert.coin();
                    deposits.push(DepositType::StakeRegistration {
                        amount: explicit_deposit.to_str().parse::<i128>().unwrap_or(0),
                        index: i as u32,
                    });
                }
                csl::CertificateKind::StakeVoteRegistrationAndDelegation => {
                    let reg_cert = cert.as_stake_vote_registration_and_delegation().unwrap();
                    let explicit_deposit = reg_cert.coin();
                    deposits.push(DepositType::StakeRegistration {
                        amount: explicit_deposit.to_str().parse::<i128>().unwrap_or(0),
                        index: i as u32,
                    });
                }
                csl::CertificateKind::VoteDelegation => {}
                csl::CertificateKind::VoteRegistrationAndDelegation => {
                    let reg_cert = cert.as_vote_registration_and_delegation().unwrap();
                    let explicit_deposit = reg_cert.coin();
                    deposits.push(DepositType::StakeRegistration {
                        amount: explicit_deposit.to_str().parse::<i128>().unwrap_or(0),
                        index: i as u32,
                    });
                }
            }
        }
    }
    (refunds, deposits)
}

fn get_withdrawals(tx_body: &csl::TransactionBody) -> Vec<Withdrawal> {
    let withdrawals = tx_body.withdrawals();
    if let Some(withdrawals) = withdrawals {
        let withdrawals_keys = withdrawals.keys();
        let total_keys = withdrawals_keys.len();
        let mut total_withdrawals = Vec::new();
        for i in 0..total_keys {
            let key = withdrawals_keys.get(i);
            let amount = withdrawals.get(&key);
            if let Some(amount) = amount {
                total_withdrawals.push(Withdrawal {
                    amount: amount.to_str().parse::<u64>().unwrap_or(0),
                    index: i as u32,
                    reward_address: key
                        .to_address()
                        .to_bech32(None)
                        .unwrap_or_else(|_| "".to_string()),
                });
            }
        }
        total_withdrawals
    } else {
        Vec::new()
    }
}

fn calculate_mints(tx_body: &csl::TransactionBody) -> MultiAsset {
    if let Some(mint) = tx_body.mint() {
        MultiAsset::new_from_csl_multiasset(&mint.as_positive_multiasset(), true)
    } else {
        MultiAsset::new()
    }
}

fn calculate_total_output(tx_body: &csl::TransactionBody) -> Value {
    tx_body
        .outputs()
        .into_iter()
        .map(|output| Value::new_from_csl_value(&output.amount()))
        .fold(Value::new_from_coins(0), |acc, value| acc + value)
}

fn calculate_burn(tx_body: &csl::TransactionBody) -> MultiAsset {
    let mint = tx_body.mint();
    if let Some(mint) = mint {
        MultiAsset::new_from_csl_multiasset(&mint.as_negative_multiasset(), true)
    } else {
        MultiAsset::new()
    }
}

fn get_donation(tx_body: &csl::TransactionBody) -> i128 {
    let donation = tx_body.donation();
    if let Some(donation) = donation {
        donation.to_str().parse::<i128>().unwrap_or(0)
    } else {
        0
    }
}
fn calculate_voting_proposals_deposits(tx_body: &csl::TransactionBody) -> Vec<DepositType> {
    let mut deposits = Vec::new();
    let voting_proposals = tx_body.voting_proposals();
    if let Some(voting_proposals) = voting_proposals {
        let voting_proposals_count = voting_proposals.len();
        for i in 0..voting_proposals_count {
            let proposal = voting_proposals.get(i);
            let proposal_deposit = proposal.deposit();
            deposits.push(DepositType::VotingProposal {
                amount: proposal_deposit.to_str().parse::<i128>().unwrap_or(0),
                index: i as u32,
            });
        }
    }
    deposits
}

fn is_key_hash_reward_address(reward_address: &str) -> bool {
    let Ok(address) = csl::Address::from_bech32(reward_address) else {
        return false;
    };
    let Some(reward) = csl::RewardAddress::from_address(&address) else {
        return false;
    };
    reward.payment_cred().kind() == csl::CredKind::Key
}

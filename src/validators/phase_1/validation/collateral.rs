use crate::validators::{
    helpers::{csl_tx_input_to_string, string_to_csl_address},
    input_contexts::ValidationInputContext,
    phase_1::errors::{Phase1Error, Phase1Warning, ValidationPhase1Error, ValidationPhase1Warning},
    validation_result::ValidationResult,
    value::Value,
};
use cardano_serialization_lib::{self as csl, BigNum};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidInputType {
    PaymentCredentialIsScript,
    AddressIsReward,
    HasNonAdaAssets,
}

pub struct CollateralValidator {
    pub invalid_inputs: Vec<(csl::TransactionInput, u32, InvalidInputType)>,
    pub total_input: Option<Value>,
    pub collateral_return: Option<Value>,
    pub total_collateral: Option<i128>,
    pub actual_collateral: Option<Value>,
    pub estimated_minimal_collateral: i128,
    pub actual_number_of_inputs: u32,
    pub max_number_of_inputs: u32,
    pub need_collateral: bool,
    pub min_ada_for_collateral_return: Option<i128>,
}

impl CollateralValidator {
    pub fn new(
        tx_body: &csl::TransactionBody,
        tx_witness_set: &csl::TransactionWitnessSet,
        validation_input_context: &ValidationInputContext,
    ) -> Self {
        let total_input = calculate_total_input(tx_body, validation_input_context);
        let collateral_return = calculate_total_output(tx_body);
        let total_collateral = get_total_collateral(tx_body);
        let need_collateral = is_need_collateral(tx_witness_set);
        let actual_collateral = if let Some(collateral_return) = &collateral_return {
            if let Some(total_input) = &total_input {
                Some(total_input - collateral_return)
            } else {
                None
            }
        } else {
            total_input.clone()
        };
        let estimated_minimal_collateral = calculate_estimated_minimal_collateral(
            tx_body,
            validation_input_context,
            need_collateral,
        );
        let mut invalid_inputs = find_script_payment_inputs(tx_body, validation_input_context);
        invalid_inputs.extend(find_reward_address_inputs(
            tx_body,
            validation_input_context,
        ));
        invalid_inputs.extend(find_non_ada_inputs(tx_body, validation_input_context));

        let actual_number_of_inputs = tx_body.collateral().map(|x| x.len() as u32).unwrap_or(0);
        let max_number_of_inputs = validation_input_context
            .protocol_parameters
            .max_collateral_inputs;
        let min_ada_for_collateral_return =
            calculate_min_ada_for_collateral_return(tx_body, validation_input_context);
        Self {
            invalid_inputs,
            total_input,
            collateral_return,
            total_collateral,
            actual_collateral,
            estimated_minimal_collateral,
            actual_number_of_inputs,
            max_number_of_inputs,
            need_collateral,
            min_ada_for_collateral_return,
        }
    }

    pub fn validate(&self) -> ValidationResult {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        if self.actual_number_of_inputs > self.max_number_of_inputs {
            errors.push(ValidationPhase1Error::new(
                Phase1Error::TooManyCollateralInputs {
                    actual_count: self.actual_number_of_inputs,
                    max_count: self.max_number_of_inputs,
                },
                "transaction.body.collateral".to_string(),
            ));
        }

        if !self.need_collateral
            && (self.actual_number_of_inputs > 0 || self.total_collateral.is_some())
        {
            warnings.push(ValidationPhase1Warning::new(
                Phase1Warning::CollateralIsUnnecessary,
                "transaction.body.collateral".to_string(),
            ));
        }

        if self.need_collateral && self.actual_collateral.is_none() {
            errors.push(ValidationPhase1Error::new(
                Phase1Error::NoCollateralInputs,
                "transaction.body.collateral".to_string(),
            ));
        }

        if let Some(total_collateral) = self.total_collateral {
            if total_collateral < self.estimated_minimal_collateral {
                errors.push(ValidationPhase1Error::new(
                    Phase1Error::InsufficientCollateral {
                        total_collateral,
                        required_collateral: self.estimated_minimal_collateral,
                    },
                    "transaction.body.total_collateral".to_string(),
                ));
            }

            if let Some(actual_collateral) = &self.actual_collateral {
                if actual_collateral.coins != total_collateral {
                    errors.push(ValidationPhase1Error::new(
                        Phase1Error::IncorrectTotalCollateralField {
                            declared_total: total_collateral,
                            actual_sum: actual_collateral.coins,
                        },
                        "transaction.body.total_collateral".to_string(),
                    ));
                }
            }
        } else {
            if let Some(total_input) = &self.total_input {
                if total_input.coins < self.estimated_minimal_collateral {
                    errors.push(ValidationPhase1Error::new(
                        Phase1Error::InsufficientCollateral {
                            total_collateral: total_input.coins,
                            required_collateral: self.estimated_minimal_collateral,
                        },
                        "transaction.body.collateral".to_string(),
                    ));
                }
            }

            if self.collateral_return.is_some() {
                warnings.push(ValidationPhase1Warning::new(
                    Phase1Warning::TotalCollateralIsNotDeclared,
                    "transaction.body.total_collateral".to_string(),
                ));
            }
        }

        if self.collateral_return.is_some() {
            if self
                .actual_collateral
                .as_ref()
                .map(|x| x.has_assets())
                .unwrap_or(false)
            {
                errors.push(ValidationPhase1Error::new(
                    Phase1Error::CalculatedCollateralContainsNonAdaAssets,
                    "transaction.body.collateral".to_string(),
                ));
            }
        } else {
            for input in self.invalid_inputs.iter() {
                if input.2 == InvalidInputType::HasNonAdaAssets {
                    errors.push(ValidationPhase1Error::new(
                        Phase1Error::CollateralInputContainsNonAdaAssets {
                            collateral_input: csl_tx_input_to_string(&input.0),
                        },
                        format!("transaction.body.collateral.{}", input.1),
                    ));
                }
            }
        }

        if let Some(min_ada_for_collateral_return) = self.min_ada_for_collateral_return {
            if let Some(collateral_return) = &self.collateral_return {
                if collateral_return.coins < min_ada_for_collateral_return {
                    errors.push(ValidationPhase1Error::new(
                        Phase1Error::CollateralReturnTooSmall {
                            output_amount: collateral_return.coins,
                            min_amount: min_ada_for_collateral_return,
                        },
                        "transaction.body.collateral_return".to_string(),
                    ));
                }
            }
        }

        for invalid_input in self.invalid_inputs.iter() {
            if invalid_input.2 == InvalidInputType::PaymentCredentialIsScript {
                errors.push(ValidationPhase1Error::new(
                    Phase1Error::CollateralIsLockedByScript {
                        invalid_collateral: csl_tx_input_to_string(&invalid_input.0),
                    },
                    format!("transaction.body.collateral.{}", invalid_input.1),
                ));
            } else if invalid_input.2 == InvalidInputType::AddressIsReward {
                warnings.push(ValidationPhase1Warning::new(
                Phase1Warning::CollateralInputUsesRewardAddress {
                        invalid_collateral: csl_tx_input_to_string(&invalid_input.0),
                    },
                    format!("transaction.body.collateral.{}", invalid_input.1),
                ));
            }
        }
        ValidationResult::new_phase_1(errors, warnings)
    }
}

fn calculate_total_input(
    tx_body: &csl::TransactionBody,
    validation_input_context: &ValidationInputContext,
) -> Option<Value> {
    let collateral = tx_body.collateral();
    if let Some(collateral) = collateral {
        let total = collateral
            .into_iter()
            .map(|input| {
                let utxo = validation_input_context
                    .find_utxo(input.transaction_id().to_hex(), input.index());
                if let Some(utxo) = utxo {
                    Value::new_from_common_assets(&utxo.utxo.output.amount)
                } else {
                    Value::new_from_coins(0)
                }
            })
            .fold(Value::new_from_coins(0), |acc, value| acc + value);
        Some(total)
    } else {
        None
    }
}

fn calculate_total_output(tx_body: &csl::TransactionBody) -> Option<Value> {
    if let Some(collateral_return) = tx_body.collateral_return() {
        Some(Value::new_from_csl_value(&collateral_return.amount()))
    } else {
        None
    }
}

fn get_total_collateral(tx_body: &csl::TransactionBody) -> Option<i128> {
    if let Some(total_collateral) = tx_body.total_collateral() {
        Some(total_collateral.to_str().parse::<i128>().unwrap_or(0))
    } else {
        None
    }
}

fn calculate_estimated_minimal_collateral(
    tx_body: &csl::TransactionBody,
    validation_input_context: &ValidationInputContext,
    need_collateral: bool,
) -> i128 {
    if !need_collateral {
        return 0;
    }
    let tx_fee: i128 = tx_body.fee().to_str().parse::<i128>().unwrap_or(0);
    let collateral_percentage: i128 = validation_input_context
        .protocol_parameters
        .collateral_percentage
        .into();
    let collateral_amount: i128 = tx_fee * collateral_percentage / 100;
    collateral_amount
}

fn is_need_collateral(tx_witness_set: &csl::TransactionWitnessSet) -> bool {
    let redeemers_count = tx_witness_set
        .redeemers()
        .map_or(0, |redeemers| redeemers.len());
    redeemers_count > 0
}

fn find_script_payment_inputs(
    tx_body: &csl::TransactionBody,
    validation_input_context: &ValidationInputContext,
) -> Vec<(csl::TransactionInput, u32, InvalidInputType)> {
    tx_body
        .collateral()
        .unwrap_or(csl::TransactionInputs::new())
        .into_iter()
        .enumerate()
        .filter_map(|(index, input)| {
            let utxo =
                validation_input_context.find_utxo(input.transaction_id().to_hex(), input.index());

            if let Some(utxo) = utxo {
                if let Ok(csl_address) = string_to_csl_address(&utxo.utxo.output.address) {
                    if csl_address.kind() != csl::AddressKind::Reward {
                        if let Some(payment_cred) = csl_address.payment_cred() {
                            if payment_cred.kind() == csl::CredKind::Script {
                                return Some((
                                    input.clone(),
                                    index as u32,
                                    InvalidInputType::PaymentCredentialIsScript,
                                ));
                            }
                        }
                    }
                }
            }

            None
        })
        .collect()
}

fn find_reward_address_inputs(
    tx_body: &csl::TransactionBody,
    validation_input_context: &ValidationInputContext,
) -> Vec<(csl::TransactionInput, u32, InvalidInputType)> {
    tx_body
        .collateral()
        .unwrap_or(csl::TransactionInputs::new())
        .into_iter()
        .enumerate()
        .filter_map(|(index, input)| {
            let utxo =
                validation_input_context.find_utxo(input.transaction_id().to_hex(), input.index());

            if let Some(utxo) = utxo {
                if let Ok(csl_address) = string_to_csl_address(&utxo.utxo.output.address) {
                    if csl_address.kind() == csl::AddressKind::Reward {
                        return Some((
                            input.clone(),
                            index as u32,
                            InvalidInputType::AddressIsReward,
                        ));
                    }
                }
            }

            None
        })
        .collect()
}

fn find_non_ada_inputs(
    tx_body: &csl::TransactionBody,
    validation_input_context: &ValidationInputContext,
) -> Vec<(csl::TransactionInput, u32, InvalidInputType)> {
    tx_body
        .collateral()
        .unwrap_or(csl::TransactionInputs::new())
        .into_iter()
        .enumerate()
        .filter_map(|(index, input)| {
            let utxo =
                validation_input_context.find_utxo(input.transaction_id().to_hex(), input.index());

            if let Some(utxo) = utxo {
                if utxo.utxo.output.has_non_ada_assets() {
                    return Some((
                        input.clone(),
                        index as u32,
                        InvalidInputType::HasNonAdaAssets,
                    ));
                }
            }

            None
        })
        .collect()
}

fn calculate_min_ada_for_collateral_return(
    tx_body: &csl::TransactionBody,
    validation_input_context: &ValidationInputContext,
) -> Option<i128> {
    if let Some(collateral_return) = tx_body.collateral_return() {
        let coins_per_byte = validation_input_context
            .protocol_parameters
            .ada_per_utxo_byte;
        let data_cost = csl::DataCost::new_coins_per_byte(&BigNum::from(coins_per_byte));
        let min_ada = csl::min_ada_for_output(&collateral_return, &data_cost);
        match min_ada {
            Ok(min_ada) => Some(min_ada.to_str().parse::<i128>().unwrap_or(0)),
            Err(_) => None,
        }
    } else {
        None
    }
}

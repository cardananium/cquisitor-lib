use crate::js_error::JsError;
use crate::validators::input_contexts::ValidationInputContext;
use crate::validators::phase_2::data_mapper::{to_pallas_cost_modesl, to_pallas_utxos};
use crate::validators::phase_2::errors::{Phase2Error, Phase2Warning, ValidationPhase2Error, ValidationPhase2Warning};
use crate::validators::phase_2::eval_redeemer::{eval_redeemer, script_ran, slot_config_network};
use crate::validators::validation_result::{EvalRedeemerResult, ValidationResult};
use pallas_primitives::conway::{MintedTx, Redeemer};
use pallas_traverse::{Era, MultiEraTx};
use std::collections::HashSet;
use uplc::machine::cost_model::ExBudget;
use uplc::tx::{ResolvedInput, SlotConfig};
use uplc::tx::{iter_redeemers, DataLookupTable};
use crate::validators::validation_result::RedeemerTag as ValidatorRedeemerTag;

pub fn phase_2_validation(
    tx_hex: &str,
    validation_input_context: &ValidationInputContext,
) -> Result<ValidationResult, JsError> {
    // pallas decodes recursively: the bytes pass the same gate as every
    // other pallas entry point, whatever gate the caller applied before.
    let tx_bytes = crate::csl_preflight::check_pallas_cbor_hex(
        tx_hex,
        crate::csl_preflight::CslShape::Transaction,
    )
    .map_err(|e| JsError::new(&e))?;
    let mtx = MultiEraTx::decode_for_era(Era::Conway, &tx_bytes)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let tx = match mtx {
        MultiEraTx::Conway(tx) => tx.into_owned(),
        _ => return Err(JsError::new("Invalid transaction type")),
    };

    // Gather all input identifiers from the transaction.
    let request_utxos = collect_inputs(&tx);

    // Convert the UTxOs the transaction spends or references, the only ones
    // a script context holds, to the evaluator's representation: a context
    // UTxO the transaction does not name cannot refuse the evaluation.
    let requested: HashSet<&str> = request_utxos.iter().map(String::as_str).collect();
    let referenced: Vec<_> = validation_input_context
        .utxo_set
        .iter()
        .filter(|u| {
            let key = format!(
                "{}#{}",
                u.utxo.input.tx_hash.to_ascii_lowercase(),
                u.utxo.input.output_index
            );
            requested.contains(key.as_str())
        })
        .cloned()
        .collect();
    // A UTxO whose script reference or inline datum nests past what is read
    // cannot enter a script context. That is an implementation limit, not
    // a verdict: no redeemer is evaluated, each is reported not examined,
    // and phase 1 stands on its own.
    let unexamined: Vec<(String, String)> = referenced
        .iter()
        .filter_map(|u| {
            context_nesting_refusal(&u.utxo.output).map(|reason| {
                (format!("{}#{}", u.utxo.input.tx_hash.to_ascii_lowercase(), u.utxo.input.output_index), reason)
            })
        })
        .collect();
    if !unexamined.is_empty() {
        return Ok(not_examined(&tx, &unexamined));
    }
    let utxos = to_pallas_utxos(&referenced)?;

    check_missed_utxos(&request_utxos, &utxos)?;

    let slot_config = slot_config_network(&validation_input_context.network_type);

    let cost_models = to_pallas_cost_modesl(&validation_input_context.protocol_parameters.cost_models);
    let protocol_major = protocol_major_version(validation_input_context.protocol_parameters.protocol_version.0);
    let exec_result = eval_all_redeemers(&tx, &utxos, Some(&cost_models), &slot_config, protocol_major);

    Ok(exec_result)
}

/// Collects all input identifiers (including reference inputs and collateral)
/// from the given transaction.
fn collect_inputs(tx: &MintedTx) -> Vec<String> {
    let mut inputs = tx
        .transaction_body
        .inputs
        .iter()
        .map(input_to_request_format)
        .collect::<Vec<_>>();

    if let Some(ref_inputs) = &tx.transaction_body.reference_inputs {
        inputs.extend(ref_inputs.iter().map(input_to_request_format));
    }
    if let Some(collaterals) = &tx.transaction_body.collateral {
        inputs.extend(collaterals.iter().map(input_to_request_format));
    }
    inputs
}

/// Checks whether the UTXOs requested in the transaction are present in the API response.
fn check_missed_utxos(request_utxos: &[String], utxos: &[ResolvedInput]) -> Result<(), JsError> {
    let utxo_keys: HashSet<String> = utxos
        .iter()
        .map(|u| format!("{}#{}", hex::encode(u.input.transaction_id), u.input.index))
        .collect();
    let missed_utxos: Vec<String> = request_utxos
        .iter()
        .filter(|u| !utxo_keys.contains(*u))
        .cloned()
        .collect();

    if !missed_utxos.is_empty() {
        return Err(JsError::new(&format!(
            "Can't get these UTXOs from API, check the network type: {}",
            missed_utxos.join(", ")
        )));
    }
    Ok(())
}

/// The refusal for a context output whose script reference or inline datum
/// nests past what the phase-2 readers follow; `None` when both are read.
fn context_nesting_refusal(output: &crate::common::TxOutput) -> Option<String> {
    if let Some(script_ref) = &output.script_ref {
        if let Some(unexamined) = crate::validators::helpers::unexamined_script_ref(script_ref) {
            return Some(unexamined.reason);
        }
    }
    if let Some(datum) = &output.plutus_data {
        if crate::validators::phase_2::data_mapper::try_decode_from_json(datum).is_none() {
            if let Ok(bytes) = hex::decode(datum) {
                return crate::csl_preflight::pallas_nesting_refusal(&bytes, crate::csl_preflight::CslShape::Item);
            }
        }
    }
    None
}

/// Phase 2 when a script context cannot be built for an implementation
/// limit: a warning per redeemer naming the UTxOs and the bound.
fn not_examined(tx: &MintedTx, unexamined: &[(String, String)]) -> ValidationResult {
    let mut warnings = vec![];
    if let Some(redeemers) = tx.transaction_witness_set.redeemer.as_ref() {
        for (redeemer_index, _) in iter_redeemers(redeemers).enumerate() {
            for (input, reason) in unexamined {
                warnings.push(ValidationPhase2Warning::new_with_locations(
                    Phase2Warning::ScriptContextNotExamined {
                        input: input.clone(),
                        reason: reason.clone(),
                    },
                    &[format!("transaction.witness_set.redeemers.{}", redeemer_index)],
                ));
            }
        }
    }
    ValidationResult::new_phase_2(vec![], warnings, vec![])
}

/// Formats a transaction input into the expected "txhash#index" string format.
fn input_to_request_format(input: &pallas_primitives::TransactionInput) -> String {
    format!("{}#{}", hex::encode(input.transaction_id), input.index)
}

/// The protocol major version the evaluator selects builtins by; a version
/// past `u16` is treated as the newest one.
pub(crate) fn protocol_major_version(major: u32) -> u16 {
    <u16 as std::convert::TryFrom<u32>>::try_from(major).unwrap_or(u16::MAX)
}

/// Evaluates all redeemers in the transaction.
fn eval_all_redeemers(
    tx: &MintedTx,
    utxos: &[ResolvedInput],
    cost_mdls: Option<&pallas_primitives::conway::CostModels>,
    slot_config: &SlotConfig,
    protocol_major: u16,
) -> ValidationResult {
    let mut phase_2_errors = vec![];
    let mut phase_2_warnings = vec![];
    let mut eval_results = vec![];

    let lookup_table = DataLookupTable::from_transaction(tx, utxos);

    if let Some(redeemers) = tx.transaction_witness_set.redeemer.as_ref() {
        let remaining_budget = ExBudget {
            mem: i64::MAX,
            cpu: i64::MAX,
        };
        for (redeemer_index, (r_key, r_value, r_ex_units)) in iter_redeemers(redeemers).enumerate() {
            let redeemer = Redeemer {
                tag: r_key.tag,
                index: r_key.index,
                data: r_value.clone(),
                ex_units: r_ex_units,
            };
            let (eval_redeemer_result, error) = eval_redeemer(
                tx,
                utxos,
                slot_config,
                &redeemer,
                &lookup_table,
                cost_mdls,
                &remaining_budget,
                protocol_major,
            );

            let ran = script_ran(error.as_ref());
            if let Some(error) = error {
                phase_2_errors.push(ValidationPhase2Error::new_with_locations(error, &redeemer_to_tx_locations(&eval_redeemer_result, redeemer_index)));
            }

            eval_results.push(eval_redeemer_result.clone());

            // A script that never ran has no cost to compare the budget with.
            if !ran {
                continue;
            }

            let estimated_budget = &eval_redeemer_result.calculated_ex_units;
            let redeemer_budget = &eval_redeemer_result.provided_ex_units;

            if estimated_budget.mem > redeemer_budget.mem || estimated_budget.steps > redeemer_budget.steps {
                phase_2_errors.push(ValidationPhase2Error::new_with_locations(Phase2Error::NoEnoughBudget {
                    expected_budget: estimated_budget.clone(),
                    actual_budget: redeemer_budget.clone(),
                }, &redeemer_to_tx_locations(&eval_redeemer_result, redeemer_index)));
            } else if estimated_budget.mem < redeemer_budget.mem || estimated_budget.steps < redeemer_budget.steps {
                phase_2_warnings.push(ValidationPhase2Warning::new_with_locations(Phase2Warning::BudgetIsBiggerThanExpected {
                    expected_budget: estimated_budget.clone(),
                    actual_budget: redeemer_budget.clone(),
                }, &redeemer_to_tx_locations(&eval_redeemer_result, redeemer_index)));
            }
        }
    }
    ValidationResult::new_phase_2(phase_2_errors, phase_2_warnings, eval_results)
}

fn redeemer_to_tx_locations(redeemer: &EvalRedeemerResult, redeemer_index: usize) -> Vec<String> {
    let mut locations = vec![];
    let body_location = redeemer_tag_to_tx_location(&redeemer.tag, redeemer.index);
    let redeemer_location = format!("transaction.witness_set.redeemers.{}", redeemer_index);
    locations.push(body_location);
    locations.push(redeemer_location);
    locations
}

fn redeemer_tag_to_tx_location(redeemer_tag: &ValidatorRedeemerTag, redeemer_index: u64) -> String {
    match redeemer_tag {
        ValidatorRedeemerTag::Mint => format!("transaction.body.mint.{}", redeemer_index),
        ValidatorRedeemerTag::Spend => format!("transaction.body.inputs.{}", redeemer_index),
        ValidatorRedeemerTag::Cert => format!("transaction.body.certs.{}", redeemer_index),
        ValidatorRedeemerTag::Propose => format!("transaction.body.voting_proposals.{}", redeemer_index),
        ValidatorRedeemerTag::Vote => format!("transaction.body.voting_procedures.{}", redeemer_index),
        ValidatorRedeemerTag::Reward => format!("transaction.body.withdrawals.{}", redeemer_index),
    }
}
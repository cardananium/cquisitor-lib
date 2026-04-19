use crate::bingen::wasm_bindgen;
use crate::js_error::JsError;
use crate::plutus::data_mapper::{to_pallas_cost_modesl, to_pallas_utxos};
use crate::common::{CostModels, UTxO};
use pallas_primitives::conway::{MintedTx, Redeemer, RedeemerTag};
use pallas_primitives::ExUnits;
use pallas_traverse::{Era, MultiEraTx};
use serde_json::{Map, Value};
use std::collections::HashSet;
use uplc::machine::cost_model::ExBudget;
use uplc::tx::error::Error;
use uplc::tx::{eval, eval_phase_one, ResolvedInput, SlotConfig};
use uplc::tx::{iter_redeemers, DataLookupTable};
use crate::js_value::{from_js_value, from_serde_json_value, JsValue};

#[wasm_bindgen]
pub fn get_utxo_list_from_tx(tx_hex: &str) -> Result<Vec<String>, JsError> {
    let tx_bytes = hex::decode(tx_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let mtx = MultiEraTx::decode_for_era(Era::Conway, &tx_bytes)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let tx = match mtx {
        MultiEraTx::Conway(tx) => tx.into_owned(),
        _ => return Err(JsError::new("Invalid transaction type")),
    };

    Ok(collect_inputs(&tx))
}

#[wasm_bindgen]
pub fn execute_tx_scripts(
    tx_hex: &str,
    utxo_json: JsValue,
    cost_models_json: JsValue,
) -> Result<JsValue, JsError> {
    let tx_bytes = hex::decode(tx_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let mtx = MultiEraTx::decode_for_era(Era::Conway, &tx_bytes)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let tx = match mtx {
        MultiEraTx::Conway(tx) => tx.into_owned(),
        _ => return Err(JsError::new("Invalid transaction type")),
    };

    // Gather all input identifiers from the transaction.
    let request_utxos = collect_inputs(&tx);

    // Deserialize UTxO data and convert to the internal representation.
    let decoded_utxos: Vec<UTxO> = from_js_value(&utxo_json).map_err(|e| JsError::new(&e.to_string()))?;
    let utxos = to_pallas_utxos(&decoded_utxos)?;

    check_missed_utxos(&request_utxos, &decoded_utxos)?;

    let slot_config = SlotConfig::default();

    let cost_models: CostModels =
        from_js_value(&cost_models_json).map_err(|e| JsError::new(&e.to_string()))?;
    let cost_models = to_pallas_cost_modesl(&cost_models);
    let exec_result = eval_all_redeemers(&tx, &utxos, Some(&cost_models), &slot_config, false)?;

    from_serde_json_value(&build_response_object(exec_result)).map_err(|e| JsError::new(&e.to_string()))
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
fn check_missed_utxos(request_utxos: &[String], utxos: &[UTxO]) -> Result<(), JsError> {
    let utxo_keys: HashSet<String> = utxos
        .iter()
        .map(|u| format!("{}#{}", u.input.tx_hash, u.input.output_index))
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

/// Builds a JSON response object from the evaluation results.
fn build_response_object(
    exec_result: Vec<Result<(Redeemer, Redeemer), (Redeemer, Error)>>,
) -> Value {
    let response: Vec<Value> = exec_result
        .into_iter()
        .map(|result| match result {
            Ok((original, calculated)) => {
                let mut obj = Map::new();
                obj.insert("original_ex_units".to_string(), exec_units_to_json(original.ex_units));
                obj.insert("calculated_ex_units".to_string(), exec_units_to_json(calculated.ex_units));
                obj.insert("redeemer_index".to_string(), Value::String(original.index.to_string()));
                obj.insert(
                    "redeemer_tag".to_string(),
                    Value::String(redeemer_tag_to_string(&original.tag)),
                );
                Value::Object(obj)
            }
            Err((original, err)) => {
                let mut obj = Map::new();
                obj.insert("original_ex_units".to_string(), exec_units_to_json(original.ex_units));
                obj.insert("error".to_string(), Value::String(err.to_string()));
                obj.insert("redeemer_index".to_string(),  Value::String(original.index.to_string()));
                obj.insert(
                    "redeemer_tag".to_string(),
                    Value::String(redeemer_tag_to_string(&original.tag)),
                );
                Value::Object(obj)
            }
        })
        .collect();

    Value::Array(response)
}

/// Converts execution units to a JSON value.
fn exec_units_to_json(exec_unit: ExUnits) -> Value {
    let mut obj = Map::new();
    obj.insert("steps".to_string(), Value::String(exec_unit.steps.to_string()));
    obj.insert("mem".to_string(), Value::String(exec_unit.mem.to_string()));
    Value::Object(obj)
}

/// Converts a redeemer tag to its string representation.
fn redeemer_tag_to_string(tag: &RedeemerTag) -> String {
    match tag {
        RedeemerTag::Spend => "Spend".to_string(),
        RedeemerTag::Mint => "Mint".to_string(),
        RedeemerTag::Cert => "Cert".to_string(),
        RedeemerTag::Reward => "Reward".to_string(),
        RedeemerTag::Propose => "Propose".to_string(),
        RedeemerTag::Vote => "Vote".to_string(),
    }
}

/// Formats a transaction input into the expected "txhash#index" string format.
fn input_to_request_format(input: &pallas_primitives::TransactionInput) -> String {
    format!("{}#{}", hex::encode(input.transaction_id), input.index)
}

/// Evaluates all redeemers in the transaction.
fn eval_all_redeemers(
    tx: &MintedTx,
    utxos: &[ResolvedInput],
    cost_mdls: Option<&pallas_primitives::conway::CostModels>,
    slot_config: &SlotConfig,
    run_phase_one: bool,
) -> Result<Vec<Result<(Redeemer, Redeemer), (Redeemer, Error)>>, JsError> {
    let lookup_table = DataLookupTable::from_transaction(tx, utxos);

    if run_phase_one {
        eval_phase_one(tx, utxos, &lookup_table)
            .map_err(|e| JsError::new(&e.to_string()))?;
    }

    if let Some(redeemers) = tx.transaction_witness_set.redeemer.as_ref() {
        let remaining_budget = ExBudget::default();
        let results = iter_redeemers(redeemers)
            .map(|(r_key, r_value, r_ex_units)| {
                let redeemer = Redeemer {
                    tag: r_key.tag,
                    index: r_key.index,
                    data: r_value.clone(),
                    ex_units: r_ex_units,
                };
                match eval::eval_redeemer(
                    tx,
                    utxos,
                    slot_config,
                    &redeemer,
                    &lookup_table,
                    cost_mdls,
                    &remaining_budget,
                ) {
                    Ok((new_redeemer, _)) => Ok((redeemer.clone(), new_redeemer)),
                    Err(err) => Err((redeemer.clone(), err)),
                }
            })
            .collect();
        Ok(results)
    } else {
        Ok(vec![])
    }
}
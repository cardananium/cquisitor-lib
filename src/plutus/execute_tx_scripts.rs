use std::collections::HashSet;

use pallas_primitives::conway::{MintedTx, Redeemer, RedeemerTag};
use pallas_primitives::ExUnits;
use pallas_traverse::{Era, MultiEraTx};
use serde_json::{json, Value};
use uplc::machine::cost_model::ExBudget;
use uplc::tx::error::Error;
use uplc::tx::{eval, eval_phase_one, iter_redeemers, DataLookupTable, ResolvedInput, SlotConfig};

use crate::bingen::wasm_bindgen;
use crate::common::{CostModels, UTxO};
use crate::js_error::JsError;
use crate::js_value::{from_js_value, from_serde_json_value, JsValue};
use crate::plutus::data_mapper::{to_pallas_cost_models, to_pallas_utxos};

#[wasm_bindgen]
pub fn get_utxo_list_from_tx(tx_hex: &str) -> Result<Vec<String>, JsError> {
    let tx_bytes = decode_tx_hex(tx_hex)?;
    let tx = decode_conway_tx(&tx_bytes)?;
    Ok(collect_inputs(&tx))
}

#[wasm_bindgen]
pub fn execute_tx_scripts(
    tx_hex: &str,
    utxo_json: JsValue,
    cost_models_json: JsValue,
) -> Result<JsValue, JsError> {
    let tx_bytes = decode_tx_hex(tx_hex)?;
    let tx = decode_conway_tx(&tx_bytes)?;

    let decoded_utxos: Vec<UTxO> =
        from_js_value(&utxo_json).map_err(|e| JsError::new(&e.to_string()))?;
    check_missed_utxos(&collect_inputs(&tx), &decoded_utxos)?;
    let utxos = to_pallas_utxos(&decoded_utxos)?;

    let cost_models: CostModels =
        from_js_value(&cost_models_json).map_err(|e| JsError::new(&e.to_string()))?;
    let cost_models = to_pallas_cost_models(&cost_models);

    let slot_config = SlotConfig::default();
    let exec_result = eval_all_redeemers(&tx, &utxos, Some(&cost_models), &slot_config, false)?;

    from_serde_json_value(&build_response_object(exec_result))
        .map_err(|e| JsError::new(&e.to_string()))
}

fn decode_tx_hex(tx_hex: &str) -> Result<Vec<u8>, JsError> {
    hex::decode(tx_hex).map_err(|e| JsError::new(&e.to_string()))
}

fn decode_conway_tx(tx_bytes: &[u8]) -> Result<MintedTx<'_>, JsError> {
    let mtx = MultiEraTx::decode_for_era(Era::Conway, tx_bytes)
        .map_err(|e| JsError::new(&e.to_string()))?;
    match mtx {
        MultiEraTx::Conway(tx) => Ok(tx.into_owned()),
        _ => Err(JsError::new("Invalid transaction type")),
    }
}

fn collect_inputs(tx: &MintedTx) -> Vec<String> {
    let body = &tx.transaction_body;
    let mut inputs: Vec<String> = body.inputs.iter().map(input_to_request_format).collect();
    if let Some(ref_inputs) = &body.reference_inputs {
        inputs.extend(ref_inputs.iter().map(input_to_request_format));
    }
    if let Some(collaterals) = &body.collateral {
        inputs.extend(collaterals.iter().map(input_to_request_format));
    }
    inputs
}

fn check_missed_utxos(request_utxos: &[String], utxos: &[UTxO]) -> Result<(), JsError> {
    let utxo_keys: HashSet<String> = utxos
        .iter()
        .map(|u| format!("{}#{}", u.input.tx_hash, u.input.output_index))
        .collect();
    let missed: Vec<&str> = request_utxos
        .iter()
        .filter(|u| !utxo_keys.contains(*u))
        .map(String::as_str)
        .collect();

    if missed.is_empty() {
        return Ok(());
    }
    Err(JsError::new(&format!(
        "Can't get these UTXOs from API, check the network type: {}",
        missed.join(", ")
    )))
}

fn build_response_object(
    exec_result: Vec<Result<(Redeemer, Redeemer), (Redeemer, Error)>>,
) -> Value {
    Value::Array(
        exec_result
            .into_iter()
            .map(|result| match result {
                Ok((original, calculated)) => json!({
                    "original_ex_units": exec_units_to_json(original.ex_units),
                    "calculated_ex_units": exec_units_to_json(calculated.ex_units),
                    "redeemer_index": original.index.to_string(),
                    "redeemer_tag": redeemer_tag_to_string(&original.tag),
                }),
                Err((original, err)) => json!({
                    "original_ex_units": exec_units_to_json(original.ex_units),
                    "error": err.to_string(),
                    "redeemer_index": original.index.to_string(),
                    "redeemer_tag": redeemer_tag_to_string(&original.tag),
                }),
            })
            .collect(),
    )
}

fn exec_units_to_json(exec_unit: ExUnits) -> Value {
    json!({
        "steps": exec_unit.steps.to_string(),
        "mem": exec_unit.mem.to_string(),
    })
}

fn redeemer_tag_to_string(tag: &RedeemerTag) -> String {
    match tag {
        RedeemerTag::Spend => "Spend",
        RedeemerTag::Mint => "Mint",
        RedeemerTag::Cert => "Cert",
        RedeemerTag::Reward => "Reward",
        RedeemerTag::Propose => "Propose",
        RedeemerTag::Vote => "Vote",
    }
    .to_string()
}

fn input_to_request_format(input: &pallas_primitives::TransactionInput) -> String {
    format!("{}#{}", hex::encode(input.transaction_id), input.index)
}

fn eval_all_redeemers(
    tx: &MintedTx,
    utxos: &[ResolvedInput],
    cost_mdls: Option<&pallas_primitives::conway::CostModels>,
    slot_config: &SlotConfig,
    run_phase_one: bool,
) -> Result<Vec<Result<(Redeemer, Redeemer), (Redeemer, Error)>>, JsError> {
    let lookup_table = DataLookupTable::from_transaction(tx, utxos);

    if run_phase_one {
        eval_phase_one(tx, utxos, &lookup_table).map_err(|e| JsError::new(&e.to_string()))?;
    }

    let Some(redeemers) = tx.transaction_witness_set.redeemer.as_ref() else {
        return Ok(Vec::new());
    };

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
                Ok((new_redeemer, _)) => Ok((redeemer, new_redeemer)),
                Err(err) => Err((redeemer, err)),
            }
        })
        .collect();
    Ok(results)
}

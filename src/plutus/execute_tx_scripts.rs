use std::collections::HashSet;

use pallas_primitives::conway::{CostModels, Language, MintedTx, Redeemer, RedeemerTag};
use pallas_primitives::ExUnits;
use pallas_traverse::{Era, MultiEraTx};
use serde_json::{json, Value};
use uplc::ast::{FakeNamedDeBruijn, NamedDeBruijn, Program};
use uplc::machine::cost_model::ExBudget;
use uplc::machine::runtime::VAN_ROSSEM_PROTOCOL_VERSION;
use uplc::tx::error::Error as EvalError;
use uplc::tx::script_context::{
    find_script, PlutusScript, ScriptContext, TxInfoV1, TxInfoV2, TxInfoV3,
};
use uplc::tx::{
    eval_phase_one, iter_redeemers, redeemer_tag_to_string as uplc_tag, DataLookupTable,
    ResolvedInput, SlotConfig,
};

use crate::bingen::wasm_bindgen;
use crate::common::{CostModels as ContextCostModels, UTxO};
use crate::js_error::JsError;
use crate::js_value::{from_js_value, from_serde_json_value, JsValue};
use crate::plutus::data_mapper::{to_pallas_cost_models, to_pallas_utxos};
use crate::validators::phase_2::context_data::script_context_data;
use crate::validators::phase_2::context_guard::{
    script_context_refusal, transaction_refusal, withdrawal_refusal,
};
use crate::validators::phase_2::eval_redeemer::script_language;

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
    let request_utxos = collect_inputs(&tx);
    check_missed_utxos(&request_utxos, &decoded_utxos)?;
    // Only the UTxOs the transaction spends or references enter a script
    // context: a UTxO it does not name cannot refuse the evaluation.
    let requested: HashSet<&str> = request_utxos.iter().map(String::as_str).collect();
    let referenced: Vec<UTxO> = decoded_utxos
        .into_iter()
        .filter(|u| {
            let key = format!(
                "{}#{}",
                u.input.tx_hash.to_ascii_lowercase(),
                u.input.output_index
            );
            requested.contains(key.as_str())
        })
        .collect();
    let utxos = to_pallas_utxos(&referenced)?;

    let cost_models: ContextCostModels =
        from_js_value(&cost_models_json).map_err(|e| JsError::new(&e.to_string()))?;
    let cost_models = to_pallas_cost_models(&cost_models);

    let slot_config = SlotConfig::default();
    let exec_result = eval_all_redeemers(&tx, &utxos, Some(&cost_models), &slot_config, false)?;

    from_serde_json_value(&build_response_object(exec_result))
        .map_err(|e| JsError::new(&e.to_string()))
}

/// The transaction bytes, refused unless they are one well-formed CBOR
/// item nested within the bound pallas' recursive decoder is calibrated
/// for (see `crate::csl_preflight::check_pallas_cbor`).
fn decode_tx_hex(tx_hex: &str) -> Result<Vec<u8>, JsError> {
    crate::csl_preflight::check_pallas_cbor_hex(tx_hex, crate::csl_preflight::CslShape::Transaction)
        .map_err(|e| JsError::new(&format!("Failed to parse transaction: {}", e)))
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
    exec_result: Vec<Result<(Redeemer, Redeemer), (Redeemer, String)>>,
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
                    "error": err,
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
    cost_mdls: Option<&CostModels>,
    slot_config: &SlotConfig,
    run_phase_one: bool,
) -> Result<Vec<Result<(Redeemer, Redeemer), (Redeemer, String)>>, JsError> {
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
            // The context builder panics on some content a transaction can
            // hold (see `context_guard`); such content is this redeemer's
            // error. The lookup of a reward redeemer already reads the
            // withdrawal keys.
            if let Some(error) = withdrawal_refusal(tx) {
                return Err((redeemer, error.to_string()));
            }
            let found = find_script(&redeemer, tx, utxos, &lookup_table).ok();
            let refusal = transaction_refusal(tx).or_else(|| {
                found
                    .as_ref()
                    .and_then(|(script, _)| script_context_refusal(tx, &script_language(script)))
            });
            if let Some(error) = refusal {
                return Err((redeemer, error.to_string()));
            }
            match eval_redeemer(
                tx,
                utxos,
                slot_config,
                &redeemer,
                &lookup_table,
                cost_mdls,
                &remaining_budget,
            ) {
                Ok(new_redeemer) => Ok((redeemer, new_redeemer)),
                Err(err) => Err((redeemer, err.to_string())),
            }
        })
        .collect();
    Ok(results)
}

/// Run the script of `redeemer`: uplc's `eval::eval_redeemer`, with the
/// context translated by `script_context_data` (uplc cannot translate a
/// parameter change of the cost models) and an extraneous redeemer
/// answered rather than panicked on. The errors are uplc's.
fn eval_redeemer(
    tx: &MintedTx,
    utxos: &[ResolvedInput],
    slot_config: &SlotConfig,
    redeemer: &Redeemer,
    lookup_table: &DataLookupTable,
    cost_mdls: Option<&CostModels>,
    initial_budget: &ExBudget,
) -> Result<Redeemer, EvalError> {
    let (script, datum) = find_script(redeemer, tx, utxos, lookup_table)?;
    let (language, script_bytes) = match &script {
        PlutusScript::V1(script) => (Language::PlutusV1, &script.0),
        PlutusScript::V2(script) => (Language::PlutusV2, &script.0),
        PlutusScript::V3(script) => (Language::PlutusV3, &script.0),
    };
    let cost_model = cost_mdls
        .map(|models| {
            match language {
                Language::PlutusV1 => models.plutus_v1.as_ref(),
                Language::PlutusV2 => models.plutus_v2.as_ref(),
                Language::PlutusV3 => models.plutus_v3.as_ref(),
            }
            .ok_or_else(|| EvalError::CostModelNotFound(language.clone()))
        })
        .transpose()?;
    let tx_info = match language {
        Language::PlutusV1 => TxInfoV1::from_transaction(tx, utxos, slot_config)?,
        Language::PlutusV2 => TxInfoV2::from_transaction(tx, utxos, slot_config)?,
        Language::PlutusV3 => TxInfoV3::from_transaction(tx, utxos, slot_config)?,
    };
    let mut buffer = Vec::new();
    let program: Program<NamedDeBruijn> =
        Program::<FakeNamedDeBruijn>::from_cbor(script_bytes, &mut buffer)?.into();

    let script_context = tx_info
        .into_script_context(redeemer, datum.as_ref())
        .ok_or(EvalError::ExtraneousRedeemer)?;
    let is_v3 = matches!(script_context, ScriptContext::V3 { .. });
    let context_data = script_context_data(tx, script_context)
        .map_err(|reason| EvalError::FragmentDecode(reason.into()))?;
    let program = if is_v3 {
        program.apply_data(context_data)
    } else {
        if let Some(datum) = datum {
            program.apply_data(datum)
        } else {
            program
        }
        .apply_data(redeemer.data.clone())
        .apply_data(context_data)
    };

    // No protocol version is passed in: scripts run as on the newest
    // protocol the evaluator knows (11), with its builtins and costing.
    let result = match cost_model {
        Some(costs) => program.eval_as_with_protocol(
            &language,
            VAN_ROSSEM_PROTOCOL_VERSION,
            costs,
            Some(initial_budget),
        ),
        None => program.eval_version_with_protocol(
            ExBudget::default(),
            &language,
            VAN_ROSSEM_PROTOCOL_VERSION,
        ),
    };
    let cost = result.cost();
    if let Err(error) = result.result() {
        return Err(EvalError::RedeemerError {
            tag: uplc_tag(&redeemer.tag),
            index: redeemer.index,
            err: Box::new(EvalError::Machine(error, cost, result.traces())),
        });
    }
    Ok(Redeemer {
        tag: redeemer.tag,
        index: redeemer.index,
        data: redeemer.data.clone(),
        ex_units: ExUnits {
            mem: cost.mem as u64,
            steps: cost.cpu as u64,
        },
    })
}

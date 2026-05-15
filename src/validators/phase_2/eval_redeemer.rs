use pallas_codec::utils::Bytes;
use pallas_primitives::conway::{CostModel, CostModels, Language, MintedTx, Redeemer, RedeemerTag};
use uplc::{
    ast::{FakeNamedDeBruijn, NamedDeBruijn, Program},
    machine::cost_model::ExBudget,
    tx::{
        script_context::{
            find_script, DataLookupTable, PlutusScript, ScriptContext, TxInfo, TxInfoV1, TxInfoV2,
            TxInfoV3,
        },
        to_plutus_data::ToPlutusData,
        ResolvedInput, SlotConfig,
    },
    PlutusData,
};

use crate::{
    common::ExUnits,
    validators::{
        common::NetworkType, phase_2::errors::Phase2Error, validation_result::EvalRedeemerResult,
    },
};

use crate::validators::validation_result::RedeemerTag as ValidatorRedeemerTag; 

pub fn slot_config_network(network: &NetworkType) -> SlotConfig {
    match network {
        NetworkType::Mainnet => SlotConfig {
            zero_time: 1596059091000,
            zero_slot: 4492800,
            slot_length: 1000,
        },
        NetworkType::Preview => SlotConfig {
            zero_time: 1666656000000,
            zero_slot: 0,
            slot_length: 1000,
        },
        NetworkType::Preprod => SlotConfig {
            zero_time: 1654041600000 + 1728000000,
            zero_slot: 86400,
            slot_length: 1000,
        },
    }
}

pub fn eval_redeemer(
    tx: &MintedTx,
    utxos: &[ResolvedInput],
    slot_config: &SlotConfig,
    redeemer: &Redeemer,
    lookup_table: &DataLookupTable,
    cost_mdls_opt: Option<&CostModels>,
    initial_budget: &ExBudget,
) -> (EvalRedeemerResult, Option<Phase2Error>) {
    fn do_eval_redeemer(
        cost_mdl_opt: Option<&CostModel>,
        initial_budget: &ExBudget,
        lang: &Language,
        datum: Option<PlutusData>,
        redeemer: &Redeemer,
        tx_info: TxInfo,
        program: Program<NamedDeBruijn>,
    ) -> (EvalRedeemerResult, Option<Phase2Error>) {
        let script_context = tx_info
            .into_script_context(redeemer, datum.as_ref())
            .expect("couldn't create script context from transaction?");

        let script_context_data = script_context.to_plutus_data();
        let script_context_bytes = uplc::plutus_data_to_bytes(&script_context_data)
            .ok()
            .map(hex::encode);

        let program = match script_context {
            ScriptContext::V1V2 { .. } => if let Some(datum) = datum {
                program.apply_data(datum)
            } else {
                program
            }
            .apply_data(redeemer.data.clone())
            .apply_data(script_context_data),

            ScriptContext::V3 { .. } => program.apply_data(script_context_data),
        };

        let eval_result = if let Some(costs) = cost_mdl_opt {
            program.eval_as(lang, costs, Some(initial_budget))
        } else {
            program.eval_version(ExBudget::max(), lang)
        };

        let cost = eval_result.cost();
        let logs = eval_result.logs();

        let error = match eval_result.result() {
            Ok(_) => None,
            Err(err) => Some(Phase2Error::MachineError {
                error: err.to_string(),
            }),
        };

        let new_redeemer = EvalRedeemerResult {
            tag: map_tag_to_redeemer_tag(&redeemer.tag),
            index: redeemer.index as u64,
            calculated_ex_units: ExUnits {
                mem: cost.mem as u64,
                steps: cost.cpu as u64,
            },
            provided_ex_units: ExUnits {
                mem: redeemer.ex_units.mem,
                steps: redeemer.ex_units.steps,
            },
            success: error.as_ref().is_none(),
            error: error.as_ref().map(|e| e.to_string()),
            logs: logs,
            script_context_bytes,
        };

        (new_redeemer, error)
    }

    let program = |script: Bytes| {
        let mut buffer = Vec::new();
        Program::<FakeNamedDeBruijn>::from_cbor(&script, &mut buffer)
            .map(Into::<Program<NamedDeBruijn>>::into)
    };

    let redeemers_script = find_script(redeemer, tx, utxos, lookup_table).map_err(|e| {
        parse_script_lookup_error(e, redeemer)
    });

    (|| -> Result<(EvalRedeemerResult, Option<Phase2Error>), Phase2Error> {
        match redeemers_script {
            Ok((PlutusScript::V1(script), datum)) => Ok(do_eval_redeemer(
                cost_mdls_opt
                    .map(|cost_mdls| {
                        cost_mdls
                            .plutus_v1
                            .as_ref()
                            .ok_or(Phase2Error::CostModelNotFound {
                                language: language_to_string(&Language::PlutusV1),
                            })
                    })
                    .transpose()?,
                initial_budget,
                &Language::PlutusV1,
                datum,
                redeemer,
                TxInfoV1::from_transaction(tx, utxos, slot_config).map_err(|err| {
                    parse_build_context_error(err, redeemer)
                })?,
                program(script.0).map_err(|err| Phase2Error::ScriptDecodeError {
                    error: err.to_string(),
                })?,
            )),

            Ok((PlutusScript::V2(script), datum)) => Ok(do_eval_redeemer(
                cost_mdls_opt
                    .map(|cost_mdls| {
                        cost_mdls
                            .plutus_v2
                            .as_ref()
                            .ok_or(Phase2Error::CostModelNotFound {
                                language: language_to_string(&Language::PlutusV2),
                            })
                    })
                    .transpose()?,
                initial_budget,
                &Language::PlutusV2,
                datum,
                redeemer,
                TxInfoV2::from_transaction(tx, utxos, slot_config).map_err(|err| {
                    parse_build_context_error(err, redeemer)
                })?,
                program(script.0).map_err(|err| Phase2Error::ScriptDecodeError {
                    error: err.to_string(),
                })?,
            )),

            Ok((PlutusScript::V3(script), datum)) => Ok(do_eval_redeemer(
                cost_mdls_opt
                    .map(|cost_mdls| {
                        cost_mdls
                            .plutus_v3
                            .as_ref()
                            .ok_or(Phase2Error::CostModelNotFound {
                                language: language_to_string(&Language::PlutusV3),
                            })
                    })
                    .transpose()?,
                initial_budget,
                &Language::PlutusV3,
                datum,
                redeemer,
                TxInfoV3::from_transaction(tx, utxos, slot_config).map_err(|err| {
                    parse_build_context_error(err, redeemer)
                })?,
                program(script.0).map_err(|err| Phase2Error::ScriptDecodeError {
                    error: err.to_string(),
                })?,
            )),
            Err(e) => Err(e),
        }
    })()
    .unwrap_or_else(|e| eval_redeemer_result(redeemer, e))
}

fn eval_redeemer_result(
    redeemer: &Redeemer,
    error: Phase2Error,
) -> (EvalRedeemerResult, Option<Phase2Error>) {
    let new_redeemer = EvalRedeemerResult {
        tag: map_tag_to_redeemer_tag(&redeemer.tag),
        index: redeemer.index as u64,
        calculated_ex_units: ExUnits { mem: 0, steps: 0 },
        provided_ex_units: ExUnits {
            mem: redeemer.ex_units.mem,
            steps: redeemer.ex_units.steps,
        },
        success: false,
        error: Some(error.to_string()),
        logs: vec![],
        script_context_bytes: None,
    };
    (new_redeemer, Some(error))
}

fn language_to_string(language: &Language) -> String {
    match language {
        Language::PlutusV1 => "PlutusV1".to_string(),
        Language::PlutusV2 => "PlutusV2".to_string(),
        Language::PlutusV3 => "PlutusV3".to_string(),
    }
}

/// Parse error from uplc's find_script and map to specific Phase2Error variants
fn parse_script_lookup_error<E: std::fmt::Display>(error: E, redeemer: &Redeemer) -> Phase2Error {
    let error_str = error.to_string();
    
    // "missing script for redeemer" - index out of bounds
    if error_str.contains("missing script for redeemer") {
        return Phase2Error::RedeemerIndexOutOfBounds {
            tag: redeemer_tag_to_string(&redeemer.tag),
            index: redeemer.index as u64,
            max_index: None, // We don't have this info from the error message
        };
    }
    
    // "missing required script" with hash
    if error_str.contains("missing required script") {
        // Try to extract script hash from error message
        // Format: "missing required script\n       Script <hash>"
        let script_hash = error_str
            .lines()
            .find(|line| line.contains("Script"))
            .and_then(|line| line.split_whitespace().last())
            .unwrap_or("unknown")
            .to_string();
        return Phase2Error::MissingRequiredScript { script_hash };
    }
    
    // "missing required datum" with hash
    if error_str.contains("missing required datum") {
        // Try to extract datum hash from error message
        // Format: "missing required datum\n       Datum <hash>"
        let datum_hash = error_str
            .lines()
            .find(|line| line.contains("Datum"))
            .and_then(|line| line.split_whitespace().last())
            .unwrap_or("unknown")
            .to_string();
        return Phase2Error::MissingRequiredDatum { datum_hash };
    }
    
    // "redeemer points to a non-script withdrawal"
    if error_str.contains("non-script withdrawal") {
        return Phase2Error::NonScriptWithdrawal;
    }
    
    // "stake credential points to a non-script" or "non-script stake credential"
    if error_str.contains("non-script") && (error_str.contains("stake credential") || error_str.contains("credential")) {
        return Phase2Error::NonScriptCredential;
    }
    
    // "unsupported certificate type"
    if error_str.contains("unsupported certificate type") {
        return Phase2Error::UnsupportedCertificateType;
    }
    
    // "no guardrail script" or "designate procedure defines no guardrail"
    if error_str.contains("guardrail") {
        return Phase2Error::NoGuardrailScriptForProcedure;
    }
    
    // "missing required inline datum or datum hash"
    if error_str.contains("inline datum") || error_str.contains("datum hash") {
        return Phase2Error::MissingRequiredInlineDatumOrHash;
    }
    
    // Fallback for any other errors
    Phase2Error::ScriptLookupError { error: error_str }
}

fn redeemer_tag_to_string(tag: &RedeemerTag) -> String {
    match tag {
        RedeemerTag::Mint => "Mint".to_string(),
        RedeemerTag::Spend => "Spend".to_string(),
        RedeemerTag::Cert => "Cert".to_string(),
        RedeemerTag::Reward => "Reward".to_string(),
        RedeemerTag::Vote => "Vote".to_string(),
        RedeemerTag::Propose => "Propose".to_string(),
    }
}

/// Parse error from uplc's TxInfo::from_transaction and map to specific Phase2Error variants
fn parse_build_context_error<E: std::fmt::Display>(error: E, redeemer: &Redeemer) -> Phase2Error {
    let error_str = error.to_string();
    
    // "resolved Input not found" - input not in UTxO set
    // The error message contains the TransactionInput debug repr
    if error_str.contains("resolved") && error_str.contains("not found") {
        // Try to extract tx hash and index from error message
        // The TransactionInput is printed as debug, try to parse it
        let (tx_hash, tx_index) = extract_tx_input_from_error(&error_str);
        return Phase2Error::ResolvedInputNotFound { tx_hash, tx_index };
    }
    
    // "byron address not allowed when PlutusV2 scripts are present"
    if error_str.contains("byron address") || error_str.contains("Byron") {
        return Phase2Error::ByronAddressNotAllowed;
    }
    
    // "inline datum not allowed when PlutusV1 scripts are present"
    if error_str.contains("inline datum not allowed") {
        return Phase2Error::InlineDatumNotAllowedForPlutusV1;
    }
    
    // "script and input reference not allowed in PlutusV1"
    if error_str.contains("reference not allowed") || error_str.contains("input reference") {
        return Phase2Error::ReferenceInputsNotAllowedForPlutusV1;
    }
    
    // "validity start or end too far in the past"
    if error_str.contains("too far in the past") || error_str.contains("SlotTooFar") {
        // Try to extract oldest_allowed from error message
        let oldest_allowed = error_str
            .split_whitespace()
            .filter_map(|s| s.parse::<u64>().ok())
            .next()
            .unwrap_or(0);
        return Phase2Error::SlotTooFarInThePast { oldest_allowed };
    }
    
    // "address doesn't contain a payment credential"
    if error_str.contains("payment credential") {
        return Phase2Error::NoPaymentCredential;
    }
    
    // "extraneous redeemer"
    if error_str.contains("extraneous redeemer") {
        return Phase2Error::ExtraneousRedeemer {
            tag: redeemer_tag_to_string(&redeemer.tag),
            index: redeemer.index as u64,
        };
    }
    
    // Fallback for any other errors
    Phase2Error::BuildTxContextError { error: error_str }
}

/// Try to extract transaction hash and index from error message containing TransactionInput
fn extract_tx_input_from_error(error_str: &str) -> (String, u64) {
    // TransactionInput is usually printed as:
    // "TransactionInput { transaction_id: Hash<32>(0x...), index: N }"
    // or similar debug format
    
    // Try to find hex hash (64 chars)
    let tx_hash = error_str
        .split(|c: char| !c.is_ascii_hexdigit())
        .filter(|s| s.len() == 64)
        .next()
        .unwrap_or("unknown")
        .to_string();
    
    // Try to find index after "index:" or similar
    let tx_index = if let Some(idx_pos) = error_str.find("index") {
        error_str[idx_pos..]
            .split_whitespace()
            .filter_map(|s| s.trim_matches(|c: char| !c.is_ascii_digit()).parse::<u64>().ok())
            .next()
            .unwrap_or(0)
    } else {
        0
    };
    
    (tx_hash, tx_index)
}

fn map_tag_to_redeemer_tag(tag: &RedeemerTag) -> ValidatorRedeemerTag {
    match tag {
        RedeemerTag::Mint => ValidatorRedeemerTag::Mint,
        RedeemerTag::Spend => ValidatorRedeemerTag::Spend,
        RedeemerTag::Cert => ValidatorRedeemerTag::Cert,
        RedeemerTag::Propose => ValidatorRedeemerTag::Propose,
        RedeemerTag::Vote => ValidatorRedeemerTag::Vote,
        RedeemerTag::Reward  => ValidatorRedeemerTag::Reward,
    }
}

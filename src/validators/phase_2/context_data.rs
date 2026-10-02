//! The script context as the Data a script is applied to.
//!
//! uplc translates every part of a context but one: the cost models a
//! parameter change sets (`ProtocolParamUpdate` key 18), where it panics
//! (`unimplemented!`), a trap on wasm. A PlutusV3 context carries every
//! proposal of the transaction, so without this module no V3 script of a
//! transaction proposing new cost models could run, the guardrail script
//! each such proposal runs included.
//!
//! The ledger writes the changed parameters (Conway `TxInfo`:
//! `toPlutusChangedParameters`, `ToPlutusData (PParamsUpdate era)`) as a
//! map from each parameter's key to its value in ascending key order, and
//! the cost models (`ToPlutusData CostModels` over `flattenCostModels`) as
//! a map from each language's key to the list of its parameters, known and
//! unknown languages alike, in ascending language order. Here the context
//! is translated with the cost models taken out of every proposal it
//! holds, and each of those proposals then gets its key 18 entry back,
//! written the ledger's way. The languages and parameters are read from
//! the transaction's bytes: pallas keeps the three languages it knows and
//! drops the others.

use std::collections::BTreeMap;
use std::convert::TryFrom;

use pallas_codec::minicbor;
use pallas_codec::utils::{AnyCbor, KeyValuePairs, MaybeIndefArray, NonEmptySet};
use pallas_primitives::conway::{CostModels, GovAction, MintedTx, ProposalProcedure};
use uplc::{
    ast::Data,
    tx::{
        script_context::{ScriptContext, ScriptInfo, TxInfo},
        to_plutus_data::ToPlutusData,
    },
    PlutusData,
};

/// The body key of the proposal procedures.
const PROPOSAL_PROCEDURES_KEY: u64 = 20;
/// The key of the cost models in a protocol parameter update.
const COST_MODELS_KEY: u64 = 18;
/// Positions of `txInfoRedeemers` and `txInfoProposalProcedures` among the
/// fields of a PlutusV3 `TxInfo`.
const TX_INFO_REDEEMERS: usize = 9;
const TX_INFO_PROPOSAL_PROCEDURES: usize = 13;
/// The constructor of `Proposing` (a script purpose) and `ProposingScript`
/// (a script info).
const PROPOSING: u64 = 5;
/// The constructor of `ParameterChange`, in Data and in the body's CBOR.
const PARAMETER_CHANGE: u64 = 0;

/// `context` as the Data its script is applied to. `Err` names a context
/// whose translation does not have the shape it is known to have, which
/// would be a fault of this module, not of the transaction.
pub(crate) fn script_context_data(
    tx: &MintedTx,
    context: ScriptContext,
) -> Result<PlutusData, String> {
    let cost_models = proposal_cost_models(tx);
    if cost_models.iter().all(Option::is_none) {
        return Ok(context.to_plutus_data());
    }
    let ScriptContext::V3 {
        mut tx_info,
        redeemer,
        mut purpose,
    } = context
    else {
        // A PlutusV1/V2 context holds no proposal: the ledger refuses one
        // next to such a script (see `context_guard`).
        return Ok(context.to_plutus_data());
    };
    if let TxInfo::V3(info) = tx_info.as_mut() {
        info.proposal_procedures
            .iter_mut()
            .for_each(without_cost_models);
        let (KeyValuePairs::Def(redeemers) | KeyValuePairs::Indef(redeemers)) = &mut info.redeemers;
        for (purpose, _) in redeemers.iter_mut() {
            if let ScriptInfo::Proposing(_, proposal) = purpose {
                without_cost_models(proposal);
            }
        }
    }
    if let ScriptInfo::Proposing(_, proposal) = purpose.as_mut() {
        without_cost_models(proposal);
    }
    let mut data = ScriptContext::V3 {
        tx_info,
        redeemer,
        purpose,
    }
    .to_plutus_data();
    restore_cost_models(&mut data, &cost_models)
        .ok_or_else(|| "the script context has an unexpected shape".to_string())?;
    Ok(data)
}

/// For each proposal of `tx`, in body order: the cost models its parameter
/// change sets, as the ledger's Data; `None` for every other proposal.
pub(crate) fn proposal_cost_models(tx: &MintedTx) -> Vec<Option<PlutusData>> {
    let Some(proposals) = tx.transaction_body.proposal_procedures.as_ref() else {
        return Vec::new();
    };
    let raw = raw_proposal_cost_models(tx.transaction_body.raw_cbor());
    proposals
        .iter()
        .enumerate()
        .map(|(index, proposal)| {
            let GovAction::ParameterChange(_, update, _) = &proposal.gov_action else {
                return None;
            };
            let decoded = update.cost_models_for_script_languages.as_ref()?;
            let languages = raw
                .as_ref()
                .and_then(|raw| raw.get(index).cloned().flatten())
                .unwrap_or_else(|| known_languages(decoded));
            Some(cost_models_data(&languages))
        })
        .collect()
}

/// Per language key, its parameters.
type Languages = BTreeMap<u64, Vec<i64>>;

/// The cost models of each proposal as the body's bytes hold them: every
/// language, a repeated key keeping its last value as the ledger's map
/// does. `None` when the bytes do not read as expected (the caller then
/// keeps the languages pallas decoded).
fn raw_proposal_cost_models(body: &[u8]) -> Option<Vec<Option<Languages>>> {
    let entries: KeyValuePairs<u64, AnyCbor> = minicbor::decode(body).ok()?;
    let (_, proposals) = entries
        .iter()
        .rev()
        .find(|(key, _)| *key == PROPOSAL_PROCEDURES_KEY)?;
    let proposals: NonEmptySet<MaybeIndefArray<AnyCbor>> =
        minicbor::decode(proposals.raw_bytes()).ok()?;
    Some(proposals.iter().map(|p| raw_languages(p)).collect())
}

/// The cost models `proposal` (`[deposit, account, action, anchor]`) sets,
/// if its action is a parameter change (`[0, prev, update, policy]`)
/// setting them.
fn raw_languages(proposal: &[AnyCbor]) -> Option<Languages> {
    let action: MaybeIndefArray<AnyCbor> = minicbor::decode(proposal.get(2)?.raw_bytes()).ok()?;
    let kind: u64 = minicbor::decode(action.first()?.raw_bytes()).ok()?;
    if kind != PARAMETER_CHANGE {
        return None;
    }
    let update: KeyValuePairs<u64, AnyCbor> = minicbor::decode(action.get(2)?.raw_bytes()).ok()?;
    let (_, models) = update
        .iter()
        .rev()
        .find(|(key, _)| *key == COST_MODELS_KEY)?;
    let models: KeyValuePairs<u64, MaybeIndefArray<i64>> =
        minicbor::decode(models.raw_bytes()).ok()?;
    Some(
        models
            .iter()
            .map(|(language, parameters)| (*language, parameters.iter().copied().collect()))
            .collect(),
    )
}

/// The languages pallas decoded (PlutusV1, V2 and V3).
fn known_languages(models: &CostModels) -> Languages {
    [&models.plutus_v1, &models.plutus_v2, &models.plutus_v3]
        .iter()
        .enumerate()
        .filter_map(|(language, parameters)| {
            parameters
                .as_ref()
                .map(|parameters| (language as u64, parameters.clone()))
        })
        .collect()
}

/// `Map [(I language, List [I parameter])]`, languages ascending.
fn cost_models_data(languages: &Languages) -> PlutusData {
    Data::map(
        languages
            .iter()
            .map(|(language, parameters)| {
                (
                    language.to_plutus_data(),
                    Data::list(
                        parameters
                            .iter()
                            .map(ToPlutusData::to_plutus_data)
                            .collect(),
                    ),
                )
            })
            .collect(),
    )
}

fn without_cost_models(proposal: &mut ProposalProcedure) {
    if let GovAction::ParameterChange(_, update, _) = &mut proposal.gov_action {
        update.cost_models_for_script_languages = None;
    }
}

/// Put each proposal's cost models back where the V3 context `data` holds
/// the proposal: in `txInfoProposalProcedures`, in the `Proposing` keys of
/// `txInfoRedeemers`, and in a `ProposingScript` script info.
fn restore_cost_models(data: &mut PlutusData, cost_models: &[Option<PlutusData>]) -> Option<()> {
    let [tx_info, _, script_info] = constr_fields(data, 0)? else {
        return None;
    };
    let tx_info = constr_fields(tx_info, 0)?;

    let proposals = list_items(tx_info.get_mut(TX_INFO_PROPOSAL_PROCEDURES)?)?;
    for (proposal, models) in proposals.iter_mut().zip(cost_models) {
        if let Some(models) = models {
            restore_in_proposal(proposal, models)?;
        }
    }

    for (purpose, _) in map_entries(tx_info.get_mut(TX_INFO_REDEEMERS)?)?.iter_mut() {
        restore_in_proposing(purpose, cost_models)?;
    }

    restore_in_proposing(script_info, cost_models)
}

/// `Proposing index proposal` (the purpose and the script info share the
/// constructor): the proposal's cost models back; other purposes as they
/// are.
fn restore_in_proposing(
    purpose: &mut PlutusData,
    cost_models: &[Option<PlutusData>],
) -> Option<()> {
    let Some([index, proposal]) = constr_fields(purpose, PROPOSING) else {
        return Some(());
    };
    let index = usize::try_from(integer(index)?).ok()?;
    match cost_models.get(index)? {
        Some(models) => restore_in_proposal(proposal, models),
        None => Some(()),
    }
}

/// `Constr 0 [deposit, return, Constr 0 [prev, params, guardrail]]`: the
/// entry `18: models` into `params`, before its first key above 18.
fn restore_in_proposal(proposal: &mut PlutusData, models: &PlutusData) -> Option<()> {
    let [_, _, action] = constr_fields(proposal, 0)? else {
        return None;
    };
    let [_, params, _] = constr_fields(action, PARAMETER_CHANGE)? else {
        return None;
    };
    let params = map_entries(params)?;
    let at = params
        .iter()
        .position(|(key, _)| integer(key).is_some_and(|key| key > COST_MODELS_KEY as i128))
        .unwrap_or(params.len());
    params.insert(at, (COST_MODELS_KEY.to_plutus_data(), models.clone()));
    Some(())
}

/// The fields of `data` if it is constructor `index`.
fn constr_fields(data: &mut PlutusData, index: u64) -> Option<&mut [PlutusData]> {
    let PlutusData::Constr(constr) = data else {
        return None;
    };
    let found = match constr.tag {
        121..=127 => constr.tag - 121,
        1280..=1400 => constr.tag - 1280 + 7,
        102 => constr.any_constructor?,
        _ => return None,
    };
    if found != index {
        return None;
    }
    let (MaybeIndefArray::Def(fields) | MaybeIndefArray::Indef(fields)) = &mut constr.fields;
    Some(fields)
}

fn list_items(data: &mut PlutusData) -> Option<&mut Vec<PlutusData>> {
    match data {
        PlutusData::Array(MaybeIndefArray::Def(items) | MaybeIndefArray::Indef(items)) => {
            Some(items)
        }
        _ => None,
    }
}

fn map_entries(data: &mut PlutusData) -> Option<&mut Vec<(PlutusData, PlutusData)>> {
    match data {
        PlutusData::Map(KeyValuePairs::Def(entries) | KeyValuePairs::Indef(entries)) => {
            Some(entries)
        }
        _ => None,
    }
}

fn integer(data: &PlutusData) -> Option<i128> {
    match data {
        PlutusData::BigInt(uplc::BigInt::Int(int)) => Some(i128::from(int.0)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pallas_traverse::{Era, MultiEraTx};

    /// `{0: 44, 18: models, 22: 5000}` in a parameter change proposal
    /// (index 1, after an info action) of a minimal Conway transaction.
    fn transaction(models: &str) -> Vec<u8> {
        let account = format!("581de1{}", "ab".repeat(28));
        let anchor = format!("8269{}5820{}", hex::encode("https://x"), "ab".repeat(32));
        let info = format!("841a000f4240{account}8106{anchor}");
        let change = format!("841a000f4240{account}8400f6a300182c12{models}16191388f6{anchor}");
        let body = format!(
            "a4008182582011{}00018182581d61{}1a001e8480021a00030d4014d9010282{info}{change}",
            "11".repeat(31),
            "ab".repeat(28)
        );
        hex::decode(format!("84{body}a0f5f6")).unwrap()
    }

    fn cost_models_of(models: &str) -> Vec<Option<String>> {
        let bytes = transaction(models);
        let MultiEraTx::Conway(tx) = MultiEraTx::decode_for_era(Era::Conway, &bytes).unwrap()
        else {
            panic!("not a Conway transaction");
        };
        proposal_cost_models(&tx)
            .iter()
            .map(|data| {
                data.as_ref()
                    .map(|d| hex::encode(uplc::plutus_data_to_bytes(d)))
            })
            .collect()
    }

    #[test]
    fn cost_models_are_written_per_language_in_ascending_order() {
        // {2: [1, -2, 3], 0: [5]}: `{0: [5], 2: [1, -2, 3]}` as Data, lists
        // indefinite as Plutus writes non-empty lists.
        assert_eq!(
            cost_models_of("a2028301210300 8105".replace(' ', "").as_str()),
            vec![None, Some("a2009f05ff029f012103ff".to_string())]
        );
    }

    #[test]
    fn languages_pallas_does_not_know_are_kept() {
        // {9: [7], 1: [], 1: [4]}: an unknown language, and a repeated key
        // keeping its last value.
        let models = "a3 098107 0180 018104".replace(' ', "");
        assert_eq!(
            cost_models_of(&models),
            vec![None, Some("a2019f04ff099f07ff".to_string())]
        );
        // pallas drops the unknown language.
        let bytes = transaction(&models);
        let MultiEraTx::Conway(tx) = MultiEraTx::decode_for_era(Era::Conway, &bytes).unwrap()
        else {
            panic!("not a Conway transaction");
        };
        let proposals = tx.transaction_body.proposal_procedures.as_ref().unwrap();
        let GovAction::ParameterChange(_, update, _) = &proposals[1].gov_action else {
            panic!("not a parameter change");
        };
        let decoded = update.cost_models_for_script_languages.as_ref().unwrap();
        assert_eq!(
            known_languages(decoded).keys().copied().collect::<Vec<_>>(),
            vec![1]
        );
    }

    #[test]
    fn a_transaction_without_cost_model_updates_has_none() {
        let bytes = hex::decode(format!(
            "84a3008182582011{}00018182581d61{}1a001e8480021a00030d40a0f5f6",
            "11".repeat(31),
            "ab".repeat(28)
        ))
        .unwrap();
        let MultiEraTx::Conway(tx) = MultiEraTx::decode_for_era(Era::Conway, &bytes).unwrap()
        else {
            panic!("not a Conway transaction");
        };
        assert!(proposal_cost_models(&tx).is_empty());
    }
}

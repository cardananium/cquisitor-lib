use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use pallas_codec::utils::{Bytes, CborWrap, NonEmptyKeyValuePairs, PositiveCoin};
use uplc::{tx::ResolvedInput, TransactionInput};
use pallas_primitives::{conway::{
    AssetName, Coin, DatumOption, PlutusData, PolicyId,
    PostAlonzoTransactionOutput, ScriptRef, TransactionOutput, Value,
}, DatumHash, Fragment, Hash};
use crate::js_error::JsError;
use crate::common::{Asset, CostModels, TxOutput};
use crate::validators::helpers::normalize_script_ref_raw;
use crate::validators::input_contexts::UtxoInputContext;
use cardano_serialization_lib as csl;

pub fn to_pallas_cost_modesl(cost_models: &CostModels) -> pallas_primitives::conway::CostModels {
    pallas_primitives::conway::CostModels {
        plutus_v1: cost_models.plutus_v1.clone().map(|v| v.into_iter().map(|i| i as i64).collect::<Vec<i64>>()),
        plutus_v2: cost_models.plutus_v2.clone().map(|v| v.into_iter().map(|i| i as i64).collect::<Vec<i64>>()),
        plutus_v3: cost_models.plutus_v3.clone().map(|v| v.into_iter().map(|i| i as i64).collect::<Vec<i64>>()),
    }
}

pub fn to_pallas_utxos(utxos: &Vec<UtxoInputContext>) -> Result<Vec<ResolvedInput>, JsError> {
    let mut resolved_inputs = Vec::new();
    for utxo in utxos {
        let utxo = &utxo.utxo;
        let tx_hash: [u8; 32] = hex::decode(&utxo.input.tx_hash)
            .map_err(|err| JsError::new(&format!("Invalid tx hash found: {}", err)))?
            .try_into()
            .map_err(|_e| JsError::new("Invalid tx hash length found"))?;

        let resolved_input = ResolvedInput {
            input: TransactionInput {
                transaction_id: Hash::from(tx_hash),
                index: utxo.input.output_index.into(),
            },
            output: TransactionOutput::PostAlonzo(PostAlonzoTransactionOutput {
                address: Bytes::from(
                    crate::csl_preflight::address_from_bech32(&utxo.output.address)
                        .map_err(|err| JsError::new(&format!("Invalid address found: {}", err)))?
                        .to_bytes(),
                ),
                value: to_pallas_value(&utxo.output.amount)?,
                datum_option: to_pallas_datum(&utxo.output)?,
                script_ref: to_pallas_script_ref(&utxo.output.script_ref)?,
            }),
        };
        resolved_inputs.push(resolved_input);
    }
    Ok(resolved_inputs)
}

pub fn to_pallas_script_ref(
    script_ref: &Option<String>,
) -> Result<Option<CborWrap<ScriptRef>>, JsError> {
    if let Some(script_ref) = script_ref {
        let normalized = normalize_script_ref_raw(script_ref).map_err(|err| JsError::new(&format!("Invalid script ref found: {}", err)))?;
        let pallas_script = CborWrap::<ScriptRef>::decode_fragment(&normalized)
            .map_err(|err| JsError::new(&format!("Invalid script found: {}", err)))?;

        Ok(Some(pallas_script))
    } else {
        Ok(None)
    }
}

pub fn to_pallas_datum(utxo_output: &TxOutput) -> Result<Option<DatumOption>, JsError> {
    if let Some(inline_datum) = &utxo_output.plutus_data {
        if let Some(plutus_data) = try_decode_from_json(inline_datum) {
            return Ok(Some(DatumOption::Data(CborWrap(plutus_data))));
        }
        // pallas reads Plutus data recursively on the host stack: the bytes
        // pass the well-formedness and nesting gate calibrated for it first.
        let plutus_data_bytes = crate::csl_preflight::check_pallas_cbor_hex(
            inline_datum,
            crate::csl_preflight::CslShape::Item,
        )
        .map_err(|err| JsError::new(&format!("Invalid plutus data found: {}", err)))?;
        let datum = CborWrap(
            PlutusData::decode_fragment(&plutus_data_bytes)
                .map_err(|_e| JsError::new("Invalid plutus data found"))?,
        );
        Ok(Some(DatumOption::Data(datum)))
    } else if let Some(datum_hash) = &utxo_output.data_hash {
        let datum_hash_bytes: [u8; 32] = hex::decode(datum_hash)
            .map_err(|err| JsError::new(&format!("Invalid datum hash found: {}", err)))?
            .try_into()
            .map_err(|_e| JsError::new("Invalid byte length of datum hash found"))?;
        Ok(Some(DatumOption::Hash(DatumHash::from(datum_hash_bytes))))
    } else {
        Ok(None)
    }
}

pub fn try_decode_from_json(json: &str) -> Option<PlutusData> {
    csl::PlutusData::from_json(json, csl::PlutusDatumSchema::DetailedSchema)
        .map_err(|_| JsError::new("Invalid plutus data found"))
        .and_then(|plutus_data| {
            PlutusData::decode_fragment(&plutus_data.to_bytes())
                .map_err(|_| JsError::new("Invalid plutus data found"))
        })
        .ok()
}

/// Hex characters of a policy id (28 bytes) at the front of an asset unit.
const POLICY_ID_HEX_LEN: usize = 56;

pub fn to_pallas_value(assets: &Vec<Asset>) -> Result<Value, JsError> {
    if assets.len() == 1 {
        match assets[0].unit.as_str() {
            "lovelace" => Ok(Value::Coin(parse_quantity(&assets[0].quantity)?)),
            _ => Err(JsError::new(&"Invalid value")),
        }
    } else {
        to_pallas_multi_asset_value(assets)
    }
}

pub fn to_pallas_multi_asset_value(assets: &Vec<Asset>) -> Result<Value, JsError> {
    let mut coins: Coin = 0;
    let mut asset_mapping: HashMap<String, Vec<(String, String)>> = HashMap::new();
    for asset in assets {
        if asset.unit == "lovelace" || asset.unit.is_empty() {
            coins = parse_quantity(&asset.quantity)?;
        } else {
            let asset_unit = &asset.unit;
            if !asset_unit.is_char_boundary(POLICY_ID_HEX_LEN) {
                return Err(JsError::new(&format!(
                    "Invalid asset unit '{}': expected a {}-character policy id followed by the asset name",
                    asset_unit, POLICY_ID_HEX_LEN
                )));
            }
            let (policy_id, asset_name) = asset_unit.split_at(POLICY_ID_HEX_LEN);
            asset_mapping
                .entry(policy_id.to_string())
                .or_default()
                .push((asset_name.to_string(), asset.quantity.clone()))
        }
    }

    let mut multi_asset = Vec::new();
    for (policy_id, asset_list) in &asset_mapping {
        let policy_id_bytes: [u8; 28] = hex::decode(policy_id)
            .map_err(|err| JsError::new(&format!("Invalid policy id found: {}", err)))?
            .try_into()
            .map_err(|_e| JsError::new("Invalid length policy id found"))?;

        let policy_id = PolicyId::from(policy_id_bytes);
        let mut mapped_assets = Vec::new();
        for asset in asset_list {
            let (asset_name, asset_quantity) = asset;
            let asset_name_bytes =
                AssetName::from(hex::decode(asset_name).map_err(|err| {
                    JsError::new(&format!("Invalid asset name found: {}", err))
                })?);
            let quantity = parse_quantity(asset_quantity)?;
            let positive_coin = PositiveCoin::try_from(quantity).map_err(|_| {
                JsError::new(&format!("Non-positive asset quantity: {}", quantity))
            })?;
            mapped_assets.push((asset_name_bytes, positive_coin));
        }
        multi_asset.push((policy_id, NonEmptyKeyValuePairs::Def(mapped_assets)));
    }
    let pallas_multi_asset = NonEmptyKeyValuePairs::Def(multi_asset);
    Ok(Value::Multiasset(coins, pallas_multi_asset))
}

/// A UTxO quantity string as an unsigned amount; anything else is an
/// input error rather than a crash.
fn parse_quantity(quantity: &str) -> Result<u64, JsError> {
    quantity
        .parse::<u64>()
        .map_err(|err| JsError::new(&format!("Invalid quantity '{}': {}", quantity, err)))
}

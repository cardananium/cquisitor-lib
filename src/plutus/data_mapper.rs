use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};

use cardano_serialization_lib::Address;
use pallas_codec::utils::{Bytes, CborWrap, NonEmptyKeyValuePairs, PositiveCoin};
use pallas_primitives::{
    conway::{
        AssetName, Coin, DatumOption, PlutusData, PolicyId, PostAlonzoTransactionOutput,
        ScriptRef, TransactionOutput, Value,
    },
    DatumHash, Fragment, Hash,
};
use uplc::{tx::ResolvedInput, TransactionInput};

use crate::common::{Asset, CostModels, TxOutput, UTxO};
use crate::js_error::JsError;

const POLICY_ID_HEX_LEN: usize = 56;

pub fn to_pallas_cost_models(cost_models: &CostModels) -> pallas_primitives::conway::CostModels {
    pallas_primitives::conway::CostModels {
        plutus_v1: cost_models.plutus_v1.clone(),
        plutus_v2: cost_models.plutus_v2.clone(),
        plutus_v3: cost_models.plutus_v3.clone(),
    }
}

pub fn to_pallas_utxos(utxos: &[UTxO]) -> Result<Vec<ResolvedInput>, JsError> {
    utxos
        .iter()
        .map(|utxo| {
            let tx_hash: [u8; 32] = hex::decode(&utxo.input.tx_hash)
                .map_err(|err| JsError::new(&format!("Invalid tx hash found: {}", err)))?
                .try_into()
                .map_err(|_| JsError::new("Invalid tx hash length found"))?;

            let address_bytes = Address::from_bech32(&utxo.output.address)
                .map_err(|err| JsError::new(&format!("Invalid address found: {:?}", err)))?
                .to_bytes();

            Ok(ResolvedInput {
                input: TransactionInput {
                    transaction_id: Hash::from(tx_hash),
                    index: utxo.input.output_index.into(),
                },
                output: TransactionOutput::PostAlonzo(PostAlonzoTransactionOutput {
                    address: Bytes::from(address_bytes),
                    value: to_pallas_value(&utxo.output.amount)?,
                    datum_option: to_pallas_datum(&utxo.output)?,
                    script_ref: to_pallas_script_ref(&utxo.output.script_ref)?,
                }),
            })
        })
        .collect()
}

pub fn to_pallas_script_ref(
    script_ref: &Option<String>,
) -> Result<Option<CborWrap<ScriptRef>>, JsError> {
    let Some(script_ref) = script_ref else {
        return Ok(None);
    };
    let script_bytes = hex::decode(script_ref)
        .map_err(|err| JsError::new(&format!("Invalid script hex found: {}", err)))?;
    let pallas_script = ScriptRef::decode_fragment(&script_bytes)
        .map_err(|err| JsError::new(&format!("Invalid script found: {}", err)))?;
    Ok(Some(CborWrap(pallas_script)))
}

pub fn to_pallas_datum(utxo_output: &TxOutput) -> Result<Option<DatumOption>, JsError> {
    if let Some(inline_datum) = &utxo_output.plutus_data {
        let plutus_data_bytes = hex::decode(inline_datum)
            .map_err(|err| JsError::new(&format!("Invalid plutus data found: {}", err)))?;
        let datum = CborWrap(
            PlutusData::decode_fragment(&plutus_data_bytes)
                .map_err(|_| JsError::new("Invalid plutus data found"))?,
        );
        return Ok(Some(DatumOption::Data(datum)));
    }
    if let Some(datum_hash) = &utxo_output.data_hash {
        let datum_hash_bytes: [u8; 32] = hex::decode(datum_hash)
            .map_err(|err| JsError::new(&format!("Invalid datum hash found: {}", err)))?
            .try_into()
            .map_err(|_| JsError::new("Invalid byte length of datum hash found"))?;
        return Ok(Some(DatumOption::Hash(DatumHash::from(datum_hash_bytes))));
    }
    Ok(None)
}

pub fn to_pallas_value(assets: &[Asset]) -> Result<Value, JsError> {
    if assets.len() == 1 && matches!(assets[0].unit.as_str(), "lovelace") {
        let coin = parse_quantity(&assets[0].quantity)?;
        return Ok(Value::Coin(coin));
    }
    to_pallas_multi_asset_value(assets)
}

pub fn to_pallas_multi_asset_value(assets: &[Asset]) -> Result<Value, JsError> {
    let mut coins: Coin = 0;
    let mut asset_mapping: HashMap<&str, Vec<(&str, &str)>> = HashMap::new();

    for asset in assets {
        if asset.unit == "lovelace" || asset.unit.is_empty() {
            coins = parse_quantity(&asset.quantity)?;
            continue;
        }
        if asset.unit.len() < POLICY_ID_HEX_LEN {
            return Err(JsError::new(&format!(
                "Invalid asset unit (too short): {}",
                asset.unit
            )));
        }
        let (policy_id, asset_name) = asset.unit.split_at(POLICY_ID_HEX_LEN);
        asset_mapping
            .entry(policy_id)
            .or_default()
            .push((asset_name, &asset.quantity));
    }

    let mut multi_asset = Vec::with_capacity(asset_mapping.len());
    for (policy_id, asset_list) in &asset_mapping {
        let policy_id_bytes: [u8; 28] = hex::decode(policy_id)
            .map_err(|err| JsError::new(&format!("Invalid policy id found: {}", err)))?
            .try_into()
            .map_err(|_| JsError::new("Invalid length policy id found"))?;

        let mut mapped_assets = Vec::with_capacity(asset_list.len());
        for (asset_name, asset_quantity) in asset_list {
            let asset_name_bytes = AssetName::from(hex::decode(asset_name).map_err(|err| {
                JsError::new(&format!("Invalid asset name found: {}", err))
            })?);
            let quantity = parse_quantity(asset_quantity)?;
            let positive_coin = PositiveCoin::try_from(quantity).map_err(|_| {
                JsError::new(&format!("Non-positive asset quantity: {}", quantity))
            })?;
            mapped_assets.push((asset_name_bytes, positive_coin));
        }
        multi_asset.push((
            PolicyId::from(policy_id_bytes),
            NonEmptyKeyValuePairs::Def(mapped_assets),
        ));
    }

    Ok(Value::Multiasset(coins, NonEmptyKeyValuePairs::Def(multi_asset)))
}

fn parse_quantity(quantity: &str) -> Result<u64, JsError> {
    quantity
        .parse::<u64>()
        .map_err(|err| JsError::new(&format!("Invalid quantity '{}': {}", quantity, err)))
}

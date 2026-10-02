use cardano_serialization_lib::{
    AuxiliaryData, Ed25519Signature, GeneralTransactionMetadata, Int, PublicKey,
    TransactionHash, TransactionMetadatum, TransactionWitnessSet, BigNum, FixedBlock,
    FixedTransactionBody, FixedTransaction,
};
use cryptoxide::hashing::blake2b_256;
use hex;
use serde::{Deserialize, Serialize};
use crate::bingen::wasm_bindgen;
use crate::js_error::JsError;
use crate::js_value::{from_serde_json_value, JsValue};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub valid: bool,
    pub tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(rename = "invalidCatalystWitnesses")]
    pub invalid_catalyst_witnesses: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(rename = "invalidVkeyWitnesses")]
    pub invalid_vkey_witnesses: Vec<String>,
}

impl CheckResult {
    pub fn valid(tx_hash: &str) -> Self {
        CheckResult {
            valid: true,
            tx_hash: Some(tx_hash.to_string()),
            invalid_catalyst_witnesses: vec![],
            invalid_vkey_witnesses: vec![],
        }
    }

    pub fn invalid(
        tx_hash: &str,
        invalid_catalyst: Vec<String>,
        invalid_vkeys: Vec<String>,
    ) -> Self {
        CheckResult {
            valid: false,
            tx_hash: Some(tx_hash.to_string()),
            invalid_catalyst_witnesses: invalid_catalyst,
            invalid_vkey_witnesses: invalid_vkeys,
        }
    }
}

fn from_hex_string(hex_str: &str) -> Result<Vec<u8>, String> {
    hex::decode(hex_str).map_err(|e| e.to_string())
}


pub fn check_tx_signature(
    tx_hash: &str,
    pub_key_hex: &str,
    signature_hex: &str,
) -> Result<CheckResult, String> {
    let pub_key_bytes = from_hex_string(pub_key_hex)?;
    let pub_key = PublicKey::from_bytes(&pub_key_bytes)
        .map_err(|e| format!("Failed to decode PublicKey: {:?}", e))?;

    let signature_bytes = from_hex_string(signature_hex)?;
    let signature = Ed25519Signature::from_bytes(signature_bytes)
        .map_err(|e| format!("Failed to decode Ed25519Signature: {:?}", e))?;

    let tx_hash_bytes = from_hex_string(tx_hash)?;
    let is_valid = pub_key.verify(&tx_hash_bytes, &signature);
    Ok(CheckResult {
        valid: is_valid,
        tx_hash: Some(tx_hash.to_string()),
        invalid_catalyst_witnesses: vec![],
        invalid_vkey_witnesses: vec![],
    })
}

#[wasm_bindgen]
pub fn check_block_or_tx_signatures(hex_str: &str) -> Result<JsValue, JsError> {
    let block_error = match decode_block_from_hex(hex_str) {
        Ok(block) => {
            let results = check_block_txs_signatures_internal(&block)
                .map_err(|e| JsError::new(&e))?;
            return block_results_to_js(results);
        }
        Err(e) => e,
    };

    match decode_transaction_from_hex(hex_str) {
        Ok(tx) => {
            let result = check_tx_signatures_internal(&tx);
            to_js_value(&result).map_err(|e| JsError::new(&e))
        }
        Err(tx_error) => Err(JsError::new(&format!(
            "cannot parse block or transaction from given hex ({}; {})",
            block_error, tx_error
        ))),
    }
}

/// The first invalid transaction's result, or one valid result for the block.
fn block_results_to_js(results: Vec<CheckResult>) -> Result<JsValue, JsError> {
    for r in &results {
        if !r.valid {
            return to_js_value(r).map_err(|e| JsError::new(&e));
        }
    }
    let res = CheckResult::valid("All block txs are valid");
    to_js_value(&res).map_err(|e| JsError::new(&e))
}

fn decode_block_from_hex(hex_str: &str) -> Result<FixedBlock, String> {
    let block_bytes = from_hex_string(hex_str)?;
    crate::csl_preflight::check_cbor(&block_bytes, crate::csl_preflight::CslShape::Block)
        .map_err(|e| format!("Cannot decode block: {}", e))?;
    FixedBlock::from_bytes(block_bytes)
        .map_err(|e| format!("Cannot decode block: {:?}", e))
}

fn decode_transaction_from_hex(hex_str: &str) -> Result<FixedTransaction, String> {
    let tx_bytes = from_hex_string(hex_str)?;
    crate::csl_preflight::check_cbor(&tx_bytes, crate::csl_preflight::CslShape::Transaction)
        .map_err(|e| format!("Cannot decode tx: {}", e))?;
    FixedTransaction::from_bytes(tx_bytes.clone()).map_err(|e| {
        format!(
            "Cannot decode tx: {}",
            crate::csl_preflight::transaction_parse_failure(&tx_bytes, &e)
        )
    })
}

pub fn check_tx_signatures(tx_hex: &str) -> Result<CheckResult, String> {
    match decode_transaction_from_hex(tx_hex) {
        Ok(tx) => Ok(check_tx_signatures_internal(&tx)),
        Err(e) => Err(e),
    }
}

fn check_tx_signatures_internal(tx: &FixedTransaction) -> CheckResult {
    let tx_hash = tx.transaction_hash();
    let auxiliary_data = tx.auxiliary_data();
    let witness_set = tx.witness_set();

    check_body_signatures(&tx_hash, &auxiliary_data, &witness_set)
}

pub fn check_block_txs_signatures(block_hex: &str) -> Result<Vec<CheckResult>, String> {
    let block = decode_block_from_hex(block_hex)?;
    check_block_txs_signatures_internal(&block)
}

fn check_block_txs_signatures_internal(block: &FixedBlock) -> Result<Vec<CheckResult>, String> {
    let mut results = vec![];
    let txs = extract_transactions_from_block(block)?;
    for (tx_body, witness_set, aux_data) in txs {
        let tx_hash = tx_body.tx_hash();
        let check = check_body_signatures(&tx_hash, &aux_data, &witness_set);
        results.push(check);
    }
    Ok(results)
}

fn extract_transactions_from_block(
    block: &FixedBlock,
) -> Result<Vec<(FixedTransactionBody, TransactionWitnessSet, Option<AuxiliaryData>)>, String> {
    let bodies = block.transaction_bodies();
    let witnesses = block.transaction_witness_sets();
    let aux_data = block.auxiliary_data_set();
    let mut txs = vec![];
    for i in 0..bodies.len() {
        let body = bodies.get(i);
        let witness_set = witnesses.get(i);
        let aux_data = aux_data.get(i as u32);
        txs.push((body, witness_set, aux_data));
    }
    Ok(txs)
}

fn check_body_signatures(
    tx_hash: &TransactionHash,
    auxiliary_data: &Option<AuxiliaryData>,
    witness_set: &TransactionWitnessSet,
) -> CheckResult {
    let catalyst_registration_hash = get_catalyst_registration_hash(auxiliary_data);
    let catalyst_witnesses = get_catalyst_witnesses(auxiliary_data);

    // normal VKey witnesses
    let vkey_witnesses = get_vkey_witnesses(witness_set);

    let invalid_catalyst_witnesses =
        validate_bytes_signature(&catalyst_registration_hash, &catalyst_witnesses);
    let invalid_vkey_witnesses =
        validate_bytes_signature(&Some(tx_hash.to_bytes()), &vkey_witnesses);

    if !invalid_catalyst_witnesses.is_empty() || !invalid_vkey_witnesses.is_empty() {
        return CheckResult::invalid(
            &hex::encode(tx_hash.to_bytes()),
            witnesses_list_to_signatures_list(&invalid_catalyst_witnesses),
            witnesses_list_to_signatures_list(&invalid_vkey_witnesses),
        );
    }

    CheckResult::valid(&hex::encode(tx_hash.to_bytes()))
}

#[derive(Debug, Clone)]
struct PubKeySignature {
    pub pub_key: PublicKey,
    pub signature: Ed25519Signature,
}

/// Read the stake key and signature from Catalyst registration metadata, if present.
fn get_catalyst_witnesses(aux_data_opt: &Option<AuxiliaryData>) -> Vec<PubKeySignature> {
    if aux_data_opt.is_none() {
        return vec![];
    }
    let aux_data = aux_data_opt.as_ref().unwrap();
    let metadata = match aux_data.metadata() {
        None => return vec![],
        Some(md) => md,
    };
    let label_61284 = BigNum::from_str("61284").unwrap();
    let label_61285 = BigNum::from_str("61285").unwrap();

    let catalyst_meta = metadata.get(&label_61284);
    let catalyst_meta_sign = metadata.get(&label_61285);

    if catalyst_meta.is_none() || catalyst_meta_sign.is_none() {
        return vec![];
    }

    // We expect them to be maps containing certain fields.
    let stake_pub_key_bytes = match extract_map_bytes(&catalyst_meta.unwrap(), 2) {
        Ok(b) => b,
        Err(_) => return vec![],
    };

    let signature_bytes = match extract_map_bytes(&catalyst_meta_sign.unwrap(), 1) {
        Ok(b) => b,
        Err(_) => return vec![],
    };

    let stake_pub_key = match PublicKey::from_bytes(&stake_pub_key_bytes) {
        Ok(pk) => pk,
        Err(_) => return vec![],
    };

    let signature = match Ed25519Signature::from_bytes(signature_bytes) {
        Ok(sig) => sig,
        Err(_) => return vec![],
    };

    vec![PubKeySignature {
        pub_key: stake_pub_key,
        signature,
    }]
}

fn get_catalyst_registration_hash(aux_data_opt: &Option<AuxiliaryData>) -> Option<Vec<u8>> {
    if aux_data_opt.is_none() {
        return None;
    }
    let aux_data = aux_data_opt.as_ref().unwrap();
    let metadata = match aux_data.metadata() {
        None => return None,
        Some(md) => md,
    };
    let label_61284 = BigNum::from_str("61284").unwrap();

    let catalyst_meta = metadata.get(&label_61284);
    if catalyst_meta.is_none() {
        return None;
    }

    // Build a minimal general metadata that only has the 61284 label.
    let mut general_meta = GeneralTransactionMetadata::new();
    general_meta.insert(&label_61284, &catalyst_meta.unwrap());

    let general_meta_bytes = general_meta.to_bytes();
    Some(blake2b_256(&general_meta_bytes).to_vec())
}

fn extract_map_bytes(
    meta_datum: &TransactionMetadatum,
    int_key: i32,
) -> Result<Vec<u8>, String> {
    let map = meta_datum.as_map().map_err(|_| "not a map".to_string())?;
    let val_key = TransactionMetadatum::new_int(&Int::new_i32(int_key));
    let val = map.get(&val_key).map_err(|_| "key not found in map".to_string())?;
    let bytes = val.as_bytes().map_err(|_| "value not bytes".to_string())?;
    Ok(bytes)
}

fn get_vkey_witnesses(
    witness_set: &TransactionWitnessSet,
) -> Vec<PubKeySignature> {
    let mut result = vec![];

    if let Some(vkeys) = witness_set.vkeys() {
        for i in 0..vkeys.len() {
            let vkey_witness = vkeys.get(i);
            result.push(PubKeySignature {
                pub_key: vkey_witness.vkey().public_key(),
                signature: vkey_witness.signature(),
            });
        }
    }
    result
}

fn validate_bytes_signature(
    bytes_to_verify_opt: &Option<Vec<u8>>,
    witnesses: &Vec<PubKeySignature>,
) -> Vec<PubKeySignature> {
    let mut invalid = vec![];
    if bytes_to_verify_opt.is_none() {
        return invalid;
    }

    if let Some(bytes_to_verify) = bytes_to_verify_opt {
        for w in witnesses {
            if !w.pub_key.verify(bytes_to_verify, &w.signature) {
                invalid.push(PubKeySignature {
                    pub_key: w.pub_key.clone(),
                    signature: w.signature.clone(),
                });
            }
        }
    };

    invalid
}

fn witnesses_list_to_signatures_list(
    witnesses: &Vec<PubKeySignature>,
) -> Vec<String> {
    witnesses
        .iter()
        .map(|w| hex::encode(w.signature.to_bytes()))
        .collect()
}

fn to_js_value(check: &CheckResult) -> Result<JsValue, String> {
    let json_obj = serde_json::to_value(check).map_err(|e| e.to_string())?;
    from_serde_json_value(&json_obj)
}
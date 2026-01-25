use cardano_serialization_lib as csl;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

use crate::bingen::wasm_bindgen;
use crate::js_error::JsError;

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct PlutusScriptInfo {
    pub hash: String,
    pub version: PlutusVersion,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlutusVersion {
    V1,
    V2,
    V3,
}

impl From<csl::Language> for PlutusVersion {
    fn from(lang: csl::Language) -> Self {
        match lang.kind() {
            csl::LanguageKind::PlutusV1 => PlutusVersion::V1,
            csl::LanguageKind::PlutusV2 => PlutusVersion::V2,
            csl::LanguageKind::PlutusV3 => PlutusVersion::V3,
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct ExtractedHashes {
    /// Script hashes from witness set (native scripts) - indexed by position in witness set
    pub witness_native_script_hashes: Vec<Option<String>>,
    /// Script info from witness set (plutus scripts) - indexed by position in witness set
    pub witness_plutus_scripts: Vec<Option<PlutusScriptInfo>>,
    /// Datum hashes from witness set (plutus_data) - indexed by position in witness set
    pub witness_datum_hashes: Vec<Option<String>>,
    /// Inlined script info from transaction outputs (script_ref) - indexed by output index
    /// Contains hash and version for Plutus scripts, or just hash for native scripts
    pub output_inline_scripts: Vec<Option<InlineScriptInfo>>,
    /// Inlined datum hashes from transaction outputs (inline datum) - indexed by output index
    pub output_inline_datum_hashes: Vec<Option<String>>,
    /// Datum hashes from transaction outputs (data_hash field) - indexed by output index
    pub output_datum_hashes: Vec<Option<String>>,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct InlineScriptInfo {
    pub hash: String,
    pub script_type: InlineScriptType,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub enum InlineScriptType {
    Native,
    Plutus(PlutusVersion),
}

/// Extracts all script and datum hashes from a transaction
/// 
/// # Arguments
/// * `tx_hex` - Hex-encoded transaction bytes
/// 
/// # Returns
/// * `ExtractedHashes` containing all hashes found in the transaction.
///   Each vector is indexed by the entity's position (output index, witness set index, etc.)
///   None indicates that the entity at that index doesn't have the corresponding hash.
pub fn extract_hashes_from_transaction(tx_hex: &str) -> Result<ExtractedHashes, String> {
    let tx_bytes = hex::decode(tx_hex)
        .map_err(|e| format!("Failed to decode hex: {}", e))?;
    
    let tx = csl::Transaction::from_bytes(tx_bytes)
        .map_err(|e| format!("Failed to decode transaction: {:?}", e))?;
    
    let tx_body = tx.body();
    let witness_set = tx.witness_set();
    
    let mut result = ExtractedHashes {
        witness_native_script_hashes: Vec::new(),
        witness_plutus_scripts: Vec::new(),
        witness_datum_hashes: Vec::new(),
        output_inline_scripts: Vec::new(),
        output_inline_datum_hashes: Vec::new(),
        output_datum_hashes: Vec::new(),
    };
    
    // Extract from witness set
    extract_witness_set_hashes(&witness_set, &mut result);
    
    // Extract from outputs
    extract_output_hashes(&tx_body, &mut result);
    
    Ok(result)
}

fn extract_witness_set_hashes(witness_set: &csl::TransactionWitnessSet, result: &mut ExtractedHashes) {
    // Native scripts from witness set
    if let Some(native_scripts) = witness_set.native_scripts() {
        for i in 0..native_scripts.len() {
            let script = native_scripts.get(i);
            result.witness_native_script_hashes.push(Some(script.hash().to_hex()));
        }
    }
    
    // Plutus scripts from witness set
    if let Some(plutus_scripts) = witness_set.plutus_scripts() {
        for i in 0..plutus_scripts.len() {
            let script = plutus_scripts.get(i);
            result.witness_plutus_scripts.push(Some(PlutusScriptInfo {
                hash: script.hash().to_hex(),
                version: PlutusVersion::from(script.language_version()),
            }));
        }
    }
    
    // Datums from witness set (plutus_data)
    if let Some(plutus_data) = witness_set.plutus_data() {
        for i in 0..plutus_data.len() {
            let datum = plutus_data.get(i);
            let datum_hash = csl::hash_plutus_data(&datum);
            result.witness_datum_hashes.push(Some(datum_hash.to_hex()));
        }
    }
}

fn extract_output_hashes(tx_body: &csl::TransactionBody, result: &mut ExtractedHashes) {
    let outputs = tx_body.outputs();
    
    for i in 0..outputs.len() {
        let output = outputs.get(i);
        
        // Script reference (inlined script in output)
        let script_info = if let Some(script_ref) = output.script_ref() {
            if let Some(native_script) = script_ref.native_script() {
                Some(InlineScriptInfo {
                    hash: native_script.hash().to_hex(),
                    script_type: InlineScriptType::Native,
                })
            } else if let Some(plutus_script) = script_ref.plutus_script() {
                Some(InlineScriptInfo {
                    hash: plutus_script.hash().to_hex(),
                    script_type: InlineScriptType::Plutus(PlutusVersion::from(plutus_script.language_version())),
                })
            } else {
                None
            }
        } else {
            None
        };
        result.output_inline_scripts.push(script_info);
        
        // Inline datum
        let inline_datum_hash = if output.has_plutus_data() {
            if let Some(datum) = output.plutus_data() {
                Some(csl::hash_plutus_data(&datum).to_hex())
            } else {
                None
            }
        } else {
            None
        };
        result.output_inline_datum_hashes.push(inline_datum_hash);
        
        // Datum hash (not inline, just hash reference)
        let datum_hash = output.data_hash().map(|h| h.to_hex());
        result.output_datum_hashes.push(datum_hash);
    }
}

/// WASM export: Extracts all script and datum hashes from a transaction
/// Returns JSON string with ExtractedHashes structure
#[wasm_bindgen]
pub fn extract_hashes_from_transaction_js(tx_hex: &str) -> Result<String, JsError> {
    let result = extract_hashes_from_transaction(tx_hex)
        .map_err(|e| JsError::new(&format!("Failed to extract hashes: {}", e)))?;
    
    serde_json::to_string(&result)
        .map_err(|e| JsError::new(&format!("Failed to serialize ExtractedHashes: {}", e)))
}

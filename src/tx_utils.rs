use pallas_codec::minicbor;
use pallas_primitives::conway::{MintedTx, PseudoScript, PseudoTransactionOutput};
use uplc::Fragment;
use crate::bingen::wasm_bindgen;
use crate::js_error::JsError;

#[wasm_bindgen]
pub fn get_ref_script_bytes(tx_hex: &str, output_index: u32) -> Result<String, JsError> {
    let tx_bytes =
        hex::decode(tx_hex).map_err(|e| JsError::new(&format!("Failed to decode tx hex: {}", e)))?;

    let tx = MintedTx::decode_fragment(&tx_bytes)
        .map_err(|e| JsError::new(&format!("Failed to parse transaction: {}", e)))?;

    let outputs = &tx.transaction_body.outputs;
    if output_index >= outputs.len() as u32 {
        return Ok("".to_string());
    }
    let output = outputs.get(output_index as usize).unwrap();
    let ref_script = match output {
        PseudoTransactionOutput::Legacy(_) => None,
        PseudoTransactionOutput::PostAlonzo(output) => output.script_ref.as_ref().map(|x| &x.0),
    };
    match &ref_script {
        Some(ref_script) => Ok(get_pseudo_script_bytes(ref_script)),
        None => Ok("".to_string()),
    }
}

fn get_pseudo_script_bytes<T: minicbor::Encode<()>>(script: &PseudoScript<T>) -> String {
    match script {
        PseudoScript::NativeScript(script) => {
            let script_bytes = minicbor::to_vec(script).unwrap();
            hex::encode(script_bytes)
        }
        PseudoScript::PlutusV1Script(script) => {
            let script_bytes = minicbor::to_vec(script).unwrap();
            hex::encode(script_bytes)
        }
        PseudoScript::PlutusV2Script(script) => {
            let script_bytes = minicbor::to_vec(script).unwrap();
            hex::encode(script_bytes)
        }
        PseudoScript::PlutusV3Script(script) => {
            let script_bytes = minicbor::to_vec(script).unwrap();
            hex::encode(script_bytes)
        }
    }
}
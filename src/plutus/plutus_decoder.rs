use uplc::ast::{DeBruijn, NamedDeBruijn, Program};

use crate::bingen::wasm_bindgen;
use crate::js_error::JsError;
use crate::js_value::{from_serde_json_value, JsValue};
use crate::plutus::decoder_tools::to_json_program;
use crate::plutus::plutus_script_normalizer::{normalize_plutus_script, OutputEncoding};

#[wasm_bindgen]
pub fn decode_plutus_program_uplc_json(hex: &str) -> Result<JsValue, JsError> {
    let program = decode_program(hex)?;
    from_serde_json_value(&to_json_program(&program.into()))
        .map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn decode_plutus_program_pretty_uplc(hex: &str) -> Result<String, JsError> {
    let program = decode_program(hex)?;
    Ok(Program::<NamedDeBruijn>::from(program).to_pretty())
}

fn decode_program(hex: &str) -> Result<Program<DeBruijn>, JsError> {
    let decoded_hex = hex::decode(hex).map_err(|e| JsError::new(&e.to_string()))?;
    let normalized = normalize_plutus_script(&decoded_hex, OutputEncoding::SingleCBOR)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let mut flat_buffer = Vec::new();
    Program::<DeBruijn>::from_cbor(&normalized, &mut flat_buffer)
        .map_err(|e| JsError::new(&e.to_string()))
}

use crate::bingen::wasm_bindgen;
use crate::js_error::JsError;
use crate::js_value::{from_serde_json_value, JsValue};
use serde_json::{Map, Value};

mod decoder;
mod errors;
mod schema_mapper;
mod tags;
mod validation;

/// Decode CBOR hex into a positional JSON tree.
///
/// Never throws on malformed input — returns a `{ok: false, error: {...}}`
/// object with a structured decode error: `kind`, `offset`, `byte_span`,
/// structural `path`, and a human `message`. Successful decodes come back
/// as `{ok: true, value: <tree>}`.
#[wasm_bindgen]
pub fn cbor_to_json(cbor_hex: &str) -> Result<JsValue, JsError> {
    let result = match hex::decode(cbor_hex) {
        Ok(cbor) => match decoder::decode_cbor_to_value(&cbor) {
            Ok(value) => ok_result(value),
            Err(mut e) => {
                let partial = e.partial.take();
                err_result(e.to_json(), partial)
            }
        },
        Err(e) => err_result(errors::invalid_hex(e.to_string()).to_json(), None),
    };
    from_serde_json_value(&result).map_err(|e| JsError::new(&e))
}

fn ok_result(value: Value) -> Value {
    let mut obj = Map::new();
    obj.insert("ok".into(), Value::Bool(true));
    obj.insert("value".into(), value);
    Value::Object(obj)
}

fn err_result(error: Value, partial: Option<Value>) -> Value {
    let mut obj = Map::new();
    obj.insert("ok".into(), Value::Bool(false));
    obj.insert("error".into(), error);
    if let Some(p) = partial {
        obj.insert("partial".into(), p);
    }
    Value::Object(obj)
}

#[wasm_bindgen]
pub fn validate_cddl(cddl: &str) -> Result<JsValue, JsError> {
    let value = validation::validate_cddl_text(cddl);
    from_serde_json_value(&value).map_err(|e| JsError::new(&e))
}

#[wasm_bindgen]
pub fn validate_cbor_against_cddl(
    cbor_hex: &str,
    cddl: &str,
    rule_name: &str,
) -> Result<JsValue, JsError> {
    let cbor = validation::decode_hex(cbor_hex)?;
    let value = validation::validate_cbor_bytes_against_cddl(&cbor, cddl, rule_name);
    from_serde_json_value(&value).map_err(|e| JsError::new(&e))
}

/// Map decoded CBOR onto a CDDL schema and return labelled JSON.
///
/// Where `cbor_to_json` returns positional CBOR (numeric map keys, raw
/// arrays), this walks the schema in parallel and replaces those with
/// the named fields the CDDL declares. On unknown / unmatched
/// sub-structures it falls back to the raw representation rather than
/// erroring, so partial matches still yield useful output.
#[wasm_bindgen]
pub fn decode_cbor_against_cddl(
    cbor_hex: &str,
    cddl: &str,
    rule_name: &str,
) -> Result<JsValue, JsError> {
    let cbor = validation::decode_hex(cbor_hex)?;
    let value = schema_mapper::decode_cbor_against_cddl(&cbor, cddl, rule_name)?;
    from_serde_json_value(&value).map_err(|e| JsError::new(&e))
}

#[cfg(all(test, not(all(target_arch = "wasm32", not(target_os = "emscripten")))))]
mod tests {
    //! Integration-level checks that run the exported wrappers end-to-end.
    //! On native builds `JsValue` is a string-backed stub (see js_value.rs),
    //! so we can reparse its payload and verify the public shape of the API.

    use super::{cbor_to_json, validate_cbor_against_cddl, validate_cddl};
    use serde_json::Value;

    fn parse(value: crate::js_value::JsValue) -> Value {
        serde_json::from_str(&value.as_string().unwrap()).unwrap()
    }

    #[test]
    fn cbor_to_json_wrapper_decodes_a_small_document() {
        let v = parse(cbor_to_json("83010203").unwrap());
        assert_eq!(v["ok"], Value::Bool(true));
        assert_eq!(v["value"]["type"], Value::String("Array".into()));
        assert_eq!(v["value"]["items"], Value::Number(3.into()));
    }

    #[test]
    fn cbor_to_json_wrapper_reports_invalid_hex_as_structured_error() {
        let v = parse(cbor_to_json("zz").unwrap());
        assert_eq!(v["ok"], Value::Bool(false));
        assert_eq!(v["error"]["kind"], Value::String("invalid_hex".into()));
        assert_eq!(v["error"]["path"], Value::String("$".into()));
    }

    #[test]
    fn cbor_to_json_wrapper_surfaces_offset_and_path_for_invalid_syntax() {
        // 82_01_82_02_1c = [1, [2, <invalid minor>]]
        let v = parse(cbor_to_json("820182021c").unwrap());
        assert_eq!(v["ok"], Value::Bool(false));
        assert_eq!(v["error"]["kind"], Value::String("invalid_syntax".into()));
        assert_eq!(v["error"]["offset"], Value::Number(4.into()));
        assert_eq!(v["error"]["path"], Value::String("$[1][1]".into()));
    }

    #[test]
    fn cbor_to_json_wrapper_returns_partial_tree_alongside_error() {
        // 83_01_02_1c = [1, 2, <invalid>] — 2 items decoded, 1 failed.
        let v = parse(cbor_to_json("8301021c").unwrap());
        assert_eq!(v["ok"], Value::Bool(false));
        let partial = &v["partial"];
        assert_eq!(partial["type"], Value::String("Array".into()));
        assert_eq!(partial["incomplete"], Value::Bool(true));
        assert_eq!(partial["values"][0]["value"], Value::Number(1.into()));
        assert_eq!(partial["values"][1]["value"], Value::Number(2.into()));
    }

    #[test]
    fn cbor_to_json_wrapper_omits_partial_when_nothing_was_decoded() {
        // 1c fails at the very first byte — no partial to report.
        let v = parse(cbor_to_json("1c").unwrap());
        assert_eq!(v["ok"], Value::Bool(false));
        assert!(v.get("partial").is_none() || v["partial"].is_null());
    }

    #[test]
    fn validate_cddl_wrapper_reports_valid_schema() {
        let v = parse(validate_cddl("thing = {n: uint}").unwrap());
        assert_eq!(v, serde_json::json!({"valid": true}));
    }

    #[test]
    fn validate_cddl_wrapper_reports_schema_errors() {
        let v = parse(validate_cddl("this is not cddl @@@").unwrap());
        assert_eq!(v["valid"], Value::Bool(false));
        assert_eq!(v["error"]["kind"], Value::String("parse_error".into()));
    }

    #[test]
    fn validate_cbor_against_cddl_wrapper_propagates_mismatch_info() {
        let v = parse(
            validate_cbor_against_cddl("01", "thing = tstr", "thing").unwrap(),
        );
        assert_eq!(v["valid"], Value::Bool(false));
        assert_eq!(v["error"]["kind"], Value::String("mismatch".into()));
        assert_eq!(v["error"]["expected"], Value::String("tstr".into()));
    }

    #[test]
    fn validate_cbor_against_cddl_wrapper_rejects_invalid_hex() {
        let err = validate_cbor_against_cddl("zz", "thing = int", "thing")
            .err()
            .expect("expected hex error")
            .as_string()
            .unwrap_or_default();
        assert!(err.contains("invalid CBOR hex"), "unexpected: {}", err);
    }
}

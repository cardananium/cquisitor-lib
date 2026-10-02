use crate::bingen::wasm_bindgen;
use crate::deep_json::DeepJson;
use crate::js_error::JsError;
use crate::js_value::{from_serde_json_value, json_text, JsValue};
use serde_json::{Map, Value};

mod cbor_cddl_map;
#[cfg(test)]
mod cbor_cddl_map_parity;
mod cddl_tools;
mod decoder;
mod diagnostic;
mod document_cache;
pub(crate) mod errors;
pub(crate) mod limits;
mod schema_mapper;
mod socket_parity;
mod source_index;
#[cfg(test)]
mod stack_calibration;
mod tags;
#[cfg(test)]
mod test_fixtures;
mod validation;
mod walk_driver;

/// Decode CBOR hex into a positional JSON tree.
///
/// Returns JSON text `{ok: true, value}` or `{ok: false, error}` (`kind`,
/// `offset`, `byte_span`, `path`, `message`). Past the decode nesting limit:
/// `nesting_too_deep` with a partial prefix. Text form avoids host-stack
/// recursion on deep trees — see [`crate::js_value::json_text`].
#[wasm_bindgen]
pub fn cbor_to_json(cbor_hex: &str) -> Result<String, JsError> {
    let result = match hex::decode(cbor_hex) {
        Ok(cbor) => match decoder::decode_cbor_to_value(&cbor) {
            Ok(value) => ok_result(value.into_inner()),
            Err(mut e) => {
                let partial = e.partial.take().map(DeepJson::into_inner);
                err_result(e.to_json(), partial)
            }
        },
        Err(e) => err_result(errors::invalid_hex(e.to_string()).to_json(), None),
    };
    Ok(json_text(DeepJson::new(result)))
}

/// The positional decoder's verdict on `bytes` as one CBOR item: `None`
/// when it decodes whole, otherwise the same error `cbor_to_json` would
/// report (its partial tree dropped). Used to refuse input before it
/// reaches parsers that abort on malformed framing.
pub(crate) fn well_formedness_error(bytes: &[u8]) -> Option<errors::CborDecodeError> {
    match decoder::decode_cbor_to_value(bytes) {
        Ok(_) => None,
        Err(mut e) => {
            e.partial = None;
            Some(e)
        }
    }
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

/// Validate a CDDL schema: `{valid: true}` or `{valid: false, error}`.
///
/// `error.kind`: `parse_error`, `no_rules`, `unresolved_references` (all
/// occurrences, including cycles), or `nesting_too_deep`. Duplicate names
/// are `parse_error`; `/=` / `//=` are not. Missing position omits `byte_span`.
#[wasm_bindgen]
pub fn validate_cddl(cddl: &str) -> Result<JsValue, JsError> {
    let value = validation::validate_cddl_text(cddl);
    from_serde_json_value(&value).map_err(|e| JsError::new(&e))
}

/// Validate CBOR hex against CDDL rule `rule_name`.
///
/// Returns JSON text of `{valid: true}` or `{valid: false, error}`.
/// Only invalid hex throws.
#[wasm_bindgen]
pub fn validate_cbor_against_cddl(
    cbor_hex: &str,
    cddl: &str,
    rule_name: &str,
) -> Result<String, JsError> {
    let cbor = validation::decode_hex(cbor_hex)?;
    let value = validation::validate_cbor_bytes_against_cddl(&cbor, cddl, rule_name);
    Ok(json_text(DeepJson::new(value)))
}

/// Top-level rules as `[{name, kind, is_alternate, span, name_span}]`
/// for editor outline / navigation.
///
/// Works with unresolved references (mid-edit). Parse / nesting failures throw.
#[wasm_bindgen]
pub fn cddl_outline(cddl: &str) -> Result<JsValue, JsError> {
    let value = cddl_tools::outline(cddl)?;
    from_serde_json_value(&value).map_err(|e| JsError::new(&e))
}

/// `{definition: span | null, uses: span[]}` for rule `name`
/// (full spelling including `$`, as in `cddl_outline`).
///
/// Works with unresolved refs (`definition: null` + listed uses).
/// Parse / nesting failures throw.
#[wasm_bindgen]
pub fn cddl_references(cddl: &str, name: &str) -> Result<JsValue, JsError> {
    let value = cddl_tools::references(cddl, name)?;
    from_serde_json_value(&value).map_err(|e| JsError::new(&e))
}

/// Symbol at `offset`, or `null`: `role`, `kind`, `span`, `definition_span`.
///
/// Unresolved names are `prelude_or_unknown` with null `definition_span`.
/// Parse / nesting failures throw.
#[wasm_bindgen]
pub fn cddl_symbol_at(cddl: &str, offset: u32) -> Result<JsValue, JsError> {
    let value = cddl_tools::symbol_at(cddl, offset as usize)?;
    from_serde_json_value(&value).map_err(|e| JsError::new(&e))
}

/// Re-format CDDL via parse + `Display` (format-on-save).
///
/// Tolerates unresolved refs; parse errors throw. Nesting past the shared
/// schema bound is refused (serialiser cost grows with bracket depth).
#[wasm_bindgen]
pub fn cddl_format(cddl: &str) -> Result<String, JsError> {
    cddl_tools::format(cddl)
}

/// Bidirectional CBOR ↔ CDDL highlight map as JSON text.
///
/// `{ok: true, value: {entries, cbor_paths, decoded_paths}}` — paths are
/// table indices to avoid O(depth²) strings. Failures share the other
/// walkers' error envelope; row limits are this export's alone. Invalid hex throws.
#[wasm_bindgen]
pub fn map_cbor_to_cddl(cbor_hex: &str, cddl: &str, rule_name: &str) -> Result<String, JsError> {
    let cbor = validation::decode_hex(cbor_hex)?;
    // Stream rows into the envelope text (no intermediate row objects).
    let mut text = String::from("{\"ok\":true,\"value\":");
    match cbor_cddl_map::map_cbor_to_cddl_into(&mut text, &cbor, cddl, rule_name) {
        Ok(()) => {
            text.push('}');
            Ok(text)
        }
        Err(e) => Ok(json_text(DeepJson::new(err_result(e.into_object(), None)))),
    }
}

/// Map CBOR onto CDDL field names as labelled JSON text.
///
/// Success: `{ok: true, value}` with CDDL names where the schema matches;
/// unmatched subtrees fall back to raw positional form. Failure matches
/// `map_cbor_to_cddl`'s error envelope (`nesting_too_deep`,
/// `validation_too_complex`, schema/input faults). Only invalid hex throws.
#[wasm_bindgen]
pub fn decode_cbor_against_cddl(
    cbor_hex: &str,
    cddl: &str,
    rule_name: &str,
) -> Result<String, JsError> {
    let cbor = validation::decode_hex(cbor_hex)?;
    let result = match schema_mapper::decode_cbor_against_cddl(&cbor, cddl, rule_name) {
        Ok(value) => ok_result(value),
        Err(e) => err_result(e.into_object(), None),
    };
    Ok(json_text(DeepJson::new(result)))
}

#[cfg(all(test, not(all(target_arch = "wasm32", not(target_os = "emscripten")))))]
mod tests {
    //! Integration-level checks that run the exported wrappers end-to-end.
    //! On native builds `JsValue` is a string-backed stub (see js_value.rs),
    //! so we can reparse its payload and verify the public shape of the API.

    use super::{
        cbor_to_json, cddl_format, cddl_outline, cddl_references, cddl_symbol_at,
        validate_cbor_against_cddl, validate_cddl,
    };
    use crate::js_error::JsError;
    use serde_json::Value;

    /// Parsed JSON of an export answer (text walkers or native JsValue stub).
    trait AnswerText {
        fn text(self) -> String;
    }

    impl AnswerText for String {
        fn text(self) -> String {
            self
        }
    }

    impl AnswerText for crate::js_value::JsValue {
        fn text(self) -> String {
            self.as_string().unwrap()
        }
    }

    fn parse(value: impl AnswerText) -> Value {
        serde_json::from_str(&value.text()).unwrap()
    }

    fn js_message(e: JsError) -> String {
        e.as_string().unwrap_or_default()
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

    /// Oversized declared lengths must error, not OOM, on every export.
    #[test]
    fn a_declared_length_no_input_could_carry_is_answered_by_every_export() {
        for hex_bytes in [
            "5bffffffffffffffff",
            "7bffffffffffffffff",
            "9bffffffffffffffff",
            "bbffffffffffffffff",
        ] {
            let v = parse(cbor_to_json(hex_bytes).unwrap());
            assert_eq!(v["ok"], Value::Bool(false), "{}", hex_bytes);
            assert_eq!(
                v["error"]["kind"],
                Value::String("unexpected_eof".into()),
                "{}",
                hex_bytes
            );

            let v = parse(validate_cbor_against_cddl(hex_bytes, "x = any", "x").unwrap());
            assert_eq!(
                v["error"]["kind"],
                Value::String("input_parse".into()),
                "{}",
                hex_bytes
            );
            for (name, v) in [
                (
                    "decode_cbor_against_cddl",
                    parse(super::decode_cbor_against_cddl(hex_bytes, "x = any", "x").unwrap()),
                ),
                (
                    "map_cbor_to_cddl",
                    parse(super::map_cbor_to_cddl(hex_bytes, "x = any", "x").unwrap()),
                ),
            ] {
                assert_eq!(v["ok"], Value::Bool(false), "{}: {}", name, hex_bytes);
                assert_eq!(
                    v["error"]["kind"],
                    Value::String("input_parse".into()),
                    "{}: {}",
                    name,
                    hex_bytes
                );
            }
        }
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
        let v = parse(validate_cbor_against_cddl("01", "thing = tstr", "thing").unwrap());
        assert_eq!(v["valid"], Value::Bool(false));
        assert_eq!(v["error"]["kind"], Value::String("mismatch".into()));
        assert_eq!(v["error"]["expected"], Value::String("tstr".into()));
    }

    /// A schema mid-edit — `inputs` is not written yet. The editor
    /// primitives have to keep answering across the wasm boundary, not
    /// only inside the module.
    const MID_EDIT: &str = "transaction = [body, witnesses]\n\
                            body = { 0: inputs }\n\
                            witnesses = { ? 0: [* bstr] }\n";

    #[test]
    fn cddl_outline_wrapper_survives_a_dangling_reference() {
        let v = parse(cddl_outline(MID_EDIT).expect("outline must not throw"));
        let names: Vec<_> = v
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["name"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(names, vec!["transaction", "body", "witnesses"]);
        assert_eq!(v[0]["is_alternate"], Value::Bool(false));

        let refs = parse(cddl_references(MID_EDIT, "inputs").expect("references must not throw"));
        assert_eq!(refs["definition"], Value::Null);
        assert_eq!(refs["uses"].as_array().unwrap().len(), 1);

        let off = MID_EDIT.find("inputs").unwrap() as u32;
        let sym = parse(cddl_symbol_at(MID_EDIT, off).expect("symbol_at must not throw"));
        assert_eq!(sym["name"], Value::String("inputs".into()));
        assert_eq!(sym["kind"], Value::String("prelude_or_unknown".into()));

        let formatted = cddl_format(MID_EDIT).expect("format must not throw");
        assert!(formatted.contains("inputs"), "got {:?}", formatted);
    }

    #[test]
    fn cddl_ide_wrappers_still_throw_on_a_syntax_error() {
        let src = "A = [";
        assert!(cddl_outline(src).is_err());
        assert!(cddl_references(src, "A").is_err());
        assert!(cddl_symbol_at(src, 0).is_err());
        assert!(cddl_format(src).is_err());
    }

    /// Format preserves float literal notation; out-of-range floats refuse.
    #[test]
    fn cddl_format_reads_every_float_notation_and_refuses_an_unrepresentable_one() {
        // (the schema, the literal its formatted output holds)
        for (src, literal) in [
            ("a = 1.5\n", "1.5"),
            ("a = 1.5e10\n", "1.5e10"),
            ("a = 1e3\n", "1e3"),
            ("a = -2e10\n", "-2e10"),
            ("a = 0x1.5p10\n", "0x1.5p10"),
            ("a = 1E5\n", "1E5"),
            ("a = 1e+5\n", "1e+5"),
            ("a = 100.0\n", "100.0"),
        ] {
            let formatted = cddl_format(src).expect("the schema parses");
            assert!(
                formatted.contains(literal),
                "{:?} should format to {}, got {:?}",
                src,
                literal,
                formatted
            );

            // Formatted output is itself a schema the formatter accepts, and
            // reformatting it changes nothing.
            assert_eq!(
                cddl_format(&formatted).expect("formatted output parses"),
                formatted
            );
        }

        for src in ["a = 1e400\n", "a = 1.0e400\n", "a = -1e309\n"] {
            let e = js_message(cddl_format(src).expect_err("no 64-bit float holds this magnitude"));
            assert!(
                e.contains("CDDL parse error") && e.contains("Float literal out of range"),
                "{:?} should be refused for its range, got {:?}",
                src,
                e
            );
        }
    }

    #[test]
    fn validate_cddl_wrapper_surfaces_the_unresolved_array() {
        let src = "a = [alpha, beta]\nb = { k: gamma }\n";
        let v = parse(validate_cddl(src).unwrap());
        assert_eq!(v["valid"], Value::Bool(false));
        assert_eq!(
            v["error"]["kind"],
            Value::String("unresolved_references".into())
        );
        assert_eq!(
            v["error"]["message"],
            Value::String("missing definition for rule alpha".into())
        );
        let unresolved = v["error"]["unresolved"].as_array().unwrap();
        let names: Vec<_> = unresolved
            .iter()
            .map(|u| u["name"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(names, vec!["alpha", "beta", "gamma"]);
        assert_eq!(v["error"]["byte_span"], unresolved[0]["byte_span"]);
        assert_eq!(v["error"]["truncated"], Value::Bool(false));
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

    /// Nesting limits surface as `error.kind`, not throws, across walkers.
    #[test]
    fn every_walker_reports_a_limit_as_a_result_with_the_same_kind() {
        crate::cbor::test_fixtures::on_large_stack(|| {
            let limit = crate::cbor::limits::MAX_CBOR_NESTING_DEPTH;
            let hex_past = format!("{}05", "81".repeat(limit + 1));

            // Deep partial is too nested for serde_json; check the prefix.
            let decode_limit = crate::cbor::limits::MAX_CBOR_DECODE_NESTING_DEPTH;
            let hex_past_decoding = format!("{}05", "81".repeat(decode_limit + 1));
            let decoded = cbor_to_json(&hex_past_decoding).unwrap();
            assert!(
                decoded.starts_with(r#"{"ok":false,"error":{"kind":"nesting_too_deep""#),
                "{}",
                &decoded[..decoded.len().min(200)]
            );

            let validated =
                parse(validate_cbor_against_cddl(&hex_past, "x = [* x] / uint", "x").unwrap());
            assert_eq!(validated["valid"], Value::Bool(false));
            assert_eq!(
                validated["error"]["kind"],
                Value::String("nesting_too_deep".into()),
                "{}",
                validated
            );

            for (name, v) in [
                (
                    "map_cbor_to_cddl",
                    parse(super::map_cbor_to_cddl(&hex_past, "x = [* x] / uint", "x").unwrap()),
                ),
                (
                    "decode_cbor_against_cddl",
                    parse(
                        super::decode_cbor_against_cddl(&hex_past, "x = [* x] / uint", "x")
                            .unwrap(),
                    ),
                ),
            ] {
                assert_eq!(v["ok"], Value::Bool(false), "{}: {}", name, v);
                assert_eq!(v["error"], validated["error"], "{}", name);
            }

            // A chain of rule references against one item longer than
            // the bound: every walker refuses it, with the same kind.
            let mut schema = String::from("x = [a: r0] / uint\n");
            for i in 0..63 {
                schema.push_str(&format!("r{} = r{}\n", i, i + 1));
            }
            schema.push_str("r63 = x\n");
            let hex_deep = format!("{}05", "81".repeat(24));
            for (name, v) in [
                (
                    "map_cbor_to_cddl",
                    parse(super::map_cbor_to_cddl(&hex_deep, &schema, "x").unwrap()),
                ),
                (
                    "decode_cbor_against_cddl",
                    parse(super::decode_cbor_against_cddl(&hex_deep, &schema, "x").unwrap()),
                ),
            ] {
                assert_eq!(v["ok"], Value::Bool(false), "{}: {}", name, v);
                assert_eq!(
                    v["error"]["kind"],
                    Value::String("nesting_too_deep".into()),
                    "{}: {}",
                    name,
                    v
                );
                assert!(
                    v["error"]["message"]
                        .as_str()
                        .unwrap_or_default()
                        .contains("rule nesting"),
                    "{}: {}",
                    name,
                    v
                );
            }
            let v = parse(validate_cbor_against_cddl(&hex_deep, &schema, "x").unwrap());
            assert_eq!(v["valid"], Value::Bool(false));
            assert_eq!(
                v["error"]["kind"],
                Value::String("nesting_too_deep".into()),
                "{}",
                v
            );

            // Chain length / descent budget: every walker should refuse.
            let mut schema = String::from("x = [a: r0] / uint\n");
            for i in 0..62 {
                schema.push_str(&format!("r{} = r{}\n", i, i + 1));
            }
            schema.push_str("r62 = x\n");
            for (name, v) in [
                (
                    "map_cbor_to_cddl",
                    parse(super::map_cbor_to_cddl(&hex_deep, &schema, "x").unwrap()),
                ),
                (
                    "decode_cbor_against_cddl",
                    parse(super::decode_cbor_against_cddl(&hex_deep, &schema, "x").unwrap()),
                ),
            ] {
                assert_eq!(v["ok"], Value::Bool(true), "{}: {}", name, v);
            }
            let v = parse(validate_cbor_against_cddl(&hex_deep, &schema, "x").unwrap());
            assert_eq!(v["valid"], Value::Bool(true), "{}", v);

            let hex_deeper = format!("{}05", "81".repeat(3000));
            for (name, v) in [
                (
                    "map_cbor_to_cddl",
                    parse(super::map_cbor_to_cddl(&hex_deeper, &schema, "x").unwrap()),
                ),
                (
                    "decode_cbor_against_cddl",
                    parse(super::decode_cbor_against_cddl(&hex_deeper, &schema, "x").unwrap()),
                ),
            ] {
                assert_eq!(v["ok"], Value::Bool(false), "{}: {}", name, v);
                assert_eq!(
                    v["error"]["kind"],
                    Value::String("nesting_too_deep".into()),
                    "{}: {}",
                    name,
                    v
                );
                assert!(
                    v["error"]["message"]
                        .as_str()
                        .unwrap_or_default()
                        .contains(&crate::cbor::limits::MAX_CBOR_MAPPING_DESCENT_COST.to_string()),
                    "{}: {}",
                    name,
                    v
                );
            }
            let v = parse(validate_cbor_against_cddl(&hex_deeper, &schema, "x").unwrap());
            assert_eq!(v["valid"], Value::Bool(false));
            assert_eq!(
                v["error"]["kind"],
                Value::String("nesting_too_deep".into()),
                "{}",
                v
            );
        });
    }

    /// Decode succeeds at the depth limit; one level past returns a prefix.
    #[test]
    fn cbor_to_json_answers_to_the_decoders_bound_and_refuses_past_it() {
        let limit = crate::cbor::limits::MAX_CBOR_DECODE_NESTING_DEPTH;

        let at = format!("{}05", "81".repeat(limit));
        let text = cbor_to_json(&at).unwrap();
        assert!(
            text.starts_with(r#"{"ok":true,"value":{"type":"Array""#),
            "{}",
            &text[..80]
        );
        assert_eq!(text.matches(r#""type":"Array""#).count(), limit);
        assert_eq!(text.matches(r#""type":"U8""#).count(), 1);
        assert!(text.contains(r#""value":5"#));
        assert!(!text.contains("incomplete"));

        let past = format!("{}05", "81".repeat(limit + 1));
        let text = cbor_to_json(&past).unwrap();
        let envelope = r#"{"ok":false,"error":{"kind":"nesting_too_deep","message":""#;
        assert!(text.starts_with(envelope), "{}", &text[..120]);
        assert!(
            text[envelope.len()..].starts_with(&crate::cbor::limits::nesting_depth_message(limit)),
            "{}",
            &text[..200]
        );
        assert_eq!(text.matches(r#""type":"Array""#).count(), limit + 1);
        assert_eq!(text.matches(r#""incomplete":true"#).count(), limit + 1);
        assert_eq!(text.matches(r#""type":"U8""#).count(), 0);
    }

    /// Numbers: plain JSON digits when exact in JS, else the Number box.
    #[test]
    fn document_walkers_hand_numbers_over_as_digits_or_as_the_box() {
        let text = cbor_to_json("05").unwrap();
        assert!(text.ends_with(r#""value":5}}"#), "{}", text);

        let text = cbor_to_json("1bffffffffffffffff").unwrap();
        assert!(
            text.contains(r#""value":{"$serde_json::private::Number":"18446744073709551615"}"#),
            "{}",
            text
        );
        // A negative integer below what an i64 holds is carried as digits too.
        let text = cbor_to_json("3bffffffffffffffff").unwrap();
        assert!(
            text.contains(r#""value":{"$serde_json::private::Number":"-18446744073709551616"}"#),
            "{}",
            text
        );

        let v = parse(validate_cbor_against_cddl("1bffffffffffffffff", "x = uint", "x").unwrap());
        assert_eq!(v["valid"], Value::Bool(true));
        let text = super::decode_cbor_against_cddl("1bffffffffffffffff", "x = uint", "x").unwrap();
        assert_eq!(
            text,
            r#"{"ok":true,"value":{"$serde_json::private::Number":"18446744073709551615"}}"#
        );
        let text = super::decode_cbor_against_cddl("05", "x = uint", "x").unwrap();
        assert_eq!(text, r#"{"ok":true,"value":5}"#);
    }

    // ============================================================
    // Schema nesting guard
    // ============================================================

    /// Bare `[`-nesting (worst-case parse cost for the nesting guard).
    fn nested_schema(levels: usize) -> String {
        let mut src = String::from("x = ");
        for _ in 0..levels {
            src.push('[');
        }
        src.push_str("uint");
        for _ in 0..levels {
            src.push(']');
        }
        src
    }

    /// Exports must refuse schemas past the nesting pre-check.
    #[test]
    fn schema_nested_past_the_limit_is_rejected_before_parsing() {
        let src = nested_schema(super::limits::MAX_CDDL_NESTING_DEPTH + 1);

        let v = parse(validate_cddl(&src).unwrap());
        assert_eq!(v["valid"], Value::Bool(false));
        assert_eq!(v["error"]["kind"], Value::String("nesting_too_deep".into()));
        // The span marks the bracket that crossed the limit, so an editor
        // can point at it.
        let span = &v["error"]["byte_span"];
        let off = span["offset"].as_u64().unwrap() as usize;
        let len = span["length"].as_u64().unwrap() as usize;
        assert_eq!(&src[off..off + len], "[", "{}", v);
        assert_eq!(
            src[..off].matches('[').count(),
            super::limits::MAX_CDDL_NESTING_DEPTH,
            "{}",
            v
        );

        let v = parse(validate_cbor_against_cddl("05", &src, "x").unwrap());
        assert_eq!(v["valid"], Value::Bool(false));
        assert_eq!(v["error"]["kind"], Value::String("nesting_too_deep".into()));

        let throwing: Vec<(&str, Box<dyn Fn() -> Result<String, String>>)> = vec![
            (
                "cddl_outline",
                Box::new({
                    let src = src.clone();
                    move || {
                        cddl_outline(&src)
                            .map(|_| String::new())
                            .map_err(js_message)
                    }
                }),
            ),
            (
                "cddl_references",
                Box::new({
                    let src = src.clone();
                    move || {
                        cddl_references(&src, "a")
                            .map(|_| String::new())
                            .map_err(js_message)
                    }
                }),
            ),
            (
                "cddl_symbol_at",
                Box::new({
                    let src = src.clone();
                    move || {
                        cddl_symbol_at(&src, 0)
                            .map(|_| String::new())
                            .map_err(js_message)
                    }
                }),
            ),
            (
                "cddl_format",
                Box::new({
                    let src = src.clone();
                    move || cddl_format(&src).map(|_| String::new()).map_err(js_message)
                }),
            ),
        ];
        for (name, call) in throwing {
            let err = call().expect_err(name);
            assert!(
                err.contains("nesting"),
                "{}: unexpected message {}",
                name,
                err
            );
        }

        // The two mappers report the bound in the envelope, with the kind
        // and the span `validate_cddl` reports for the same text.
        for (name, v) in [
            (
                "map_cbor_to_cddl",
                parse(super::map_cbor_to_cddl("05", &src, "x").unwrap()),
            ),
            (
                "decode_cbor_against_cddl",
                parse(super::decode_cbor_against_cddl("05", &src, "x").unwrap()),
            ),
        ] {
            assert_eq!(v["ok"], Value::Bool(false), "{}: {}", name, v);
            assert_eq!(
                v["error"]["kind"],
                Value::String("nesting_too_deep".into()),
                "{}: {}",
                name,
                v
            );
            assert_eq!(
                v["error"]["byte_span"]["offset"].as_u64(),
                Some(off as u64),
                "{}: {}",
                name,
                v
            );
        }
    }

    /// The negative half: a schema that stops exactly at the limit is
    /// still answered by every export, so the guard is a boundary rather
    /// than a blanket refusal.
    #[test]
    fn schema_nested_to_the_limit_is_still_answered() {
        crate::cbor::test_fixtures::on_large_stack(|| {
            let src = nested_schema(super::limits::MAX_CDDL_NESTING_DEPTH);
            assert_eq!(
                parse(validate_cddl(&src).unwrap())["valid"],
                Value::Bool(true)
            );
            assert!(cddl_outline(&src).is_ok());
            assert!(cddl_references(&src, "a").is_ok());
            assert!(cddl_symbol_at(&src, 0).is_ok());
            assert_eq!(
                parse(super::map_cbor_to_cddl("05", &src, "x").unwrap())["ok"],
                Value::Bool(true)
            );
            assert_eq!(
                parse(super::decode_cbor_against_cddl("05", &src, "x").unwrap())["ok"],
                Value::Bool(true)
            );
            let v = parse(validate_cbor_against_cddl("05", &src, "x").unwrap());
            assert_eq!(v["valid"], Value::Bool(false));
            assert_eq!(v["error"]["kind"], Value::String("mismatch".into()));
        });
    }

    /// Format refuses the same nesting limit as the other CDDL exports.
    #[test]
    fn reformatting_is_bounded_by_the_same_limit_as_the_other_exports() {
        crate::cbor::test_fixtures::on_large_stack(|| {
            let at = nested_schema(super::limits::MAX_CDDL_NESTING_DEPTH);
            assert!(cddl_format(&at).is_ok());

            let past = nested_schema(super::limits::MAX_CDDL_NESTING_DEPTH + 1);
            let err = js_message(cddl_format(&past).expect_err("expected a refusal"));
            assert!(err.contains("nesting"), "unexpected message: {}", err);
            assert_eq!(
                parse(validate_cddl(&past).unwrap())["error"]["kind"],
                Value::String("nesting_too_deep".into())
            );
        });
    }

    /// Aggregate nesting budget refusal (not only single-run depth).
    #[test]
    fn a_schema_whose_nesting_adds_up_past_the_budget_is_refused() {
        let mut src = String::new();
        for i in 0..8 {
            src.push_str(
                &nested_schema(super::limits::MAX_CDDL_NESTING_DEPTH).replacen(
                    "x =",
                    &format!("r{} =", i),
                    1,
                ),
            );
            src.push('\n');
        }
        let v = parse(validate_cddl(&src).unwrap());
        assert_eq!(v["valid"], Value::Bool(false));
        assert_eq!(v["error"]["kind"], Value::String("nesting_too_deep".into()));
        assert!(
            v["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("too heavily"),
            "{}",
            v
        );
        assert!(cddl_outline(&src).is_err());
    }

    /// Brackets that are payload, not structure, must not be counted, or
    /// the guard would reject schemas that are nowhere near the limit.
    #[test]
    fn brackets_inside_comments_and_literals_do_not_count() {
        let mut src = String::from("; ");
        src.push_str(&"[".repeat(300));
        src.push('\n');
        src.push_str("x = \"");
        src.push_str(&"{".repeat(300));
        src.push_str("\"\n");
        src.push_str("y = h'5b5b5b5b5b'\n");
        src.push_str("z = '");
        src.push_str(&"(".repeat(300));
        src.push_str("'\n");
        src.push_str("w = [a: int]\n");

        let v = parse(validate_cddl(&src).unwrap());
        assert_eq!(v["valid"], Value::Bool(true), "{}", v);
        assert!(cddl_outline(&src).is_ok());
    }

    /// Every version of the ledger schema stays well inside the limit —
    /// its deepest bracket nesting is a single digit — so a schema of
    /// real size is not affected by the guard.
    #[test]
    fn every_schema_version_passes_the_nesting_guard() {
        for (version, src) in crate::cbor::test_fixtures::schema_suite() {
            assert_eq!(
                super::limits::cddl_nesting_overflow(src),
                None,
                "{} tripped the nesting guard",
                version
            );
            let v = parse(validate_cddl(src).unwrap());
            assert_eq!(v["valid"], Value::Bool(true), "{}: {}", version, v);
        }
    }

    // ============================================================
    // Repeated parsing
    // ============================================================

    /// Shared document cache: one parse for a pipeline of exports.
    #[test]
    fn a_pipeline_of_exports_parses_the_schema_once() {
        let cddl = crate::cbor::test_fixtures::ledger_cddl();
        let doc = crate::cbor::test_fixtures::RECORD_DOC_HEX.as_str();

        super::document_cache::clear_cache();
        super::document_cache::reset_parse_count();

        for _ in 0..3 {
            assert_eq!(
                parse(validate_cddl(cddl).unwrap())["valid"],
                Value::Bool(true)
            );
            assert!(cddl_outline(cddl).is_ok());
            assert!(cddl_references(cddl, "record").is_ok());
            assert!(cddl_symbol_at(cddl, 0).is_ok());
            assert_eq!(
                parse(super::map_cbor_to_cddl(doc, cddl, "record").unwrap())["ok"],
                Value::Bool(true)
            );
            assert_eq!(
                parse(super::decode_cbor_against_cddl(doc, cddl, "record").unwrap())["ok"],
                Value::Bool(true)
            );
            // Non-first rule: cache reorder, not a re-parse of wrapped text.
            assert_eq!(
                parse(validate_cbor_against_cddl(doc, cddl, "record").unwrap())["valid"],
                Value::Bool(true)
            );
        }

        assert_eq!(
            super::document_cache::parse_count(),
            1,
            "the schema was parsed more than once"
        );
    }

    /// Release-only wall-clock budget for the same pipeline.
    #[test]
    #[ignore = "timing-sensitive; run explicitly against a release build"]
    fn the_ledger_pipeline_stays_under_budget() {
        let cddl = crate::cbor::test_fixtures::ledger_cddl();
        let doc = crate::cbor::test_fixtures::RECORD_DOC_HEX.as_str();
        super::document_cache::clear_cache();

        let start = std::time::Instant::now();
        let _ = validate_cddl(cddl).unwrap();
        let _ = cddl_outline(cddl).unwrap();
        let _ = cddl_references(cddl, "record").unwrap();
        let _ = cddl_symbol_at(cddl, 0).unwrap();
        let _ = super::map_cbor_to_cddl(doc, cddl, "record").unwrap();
        let _ = super::decode_cbor_against_cddl(doc, cddl, "record").unwrap();
        let _ = validate_cbor_against_cddl(doc, cddl, "record").unwrap();
        let cold = start.elapsed();

        // One parse plus the real work of seven calls.
        assert!(cold.as_millis() < 150, "cold pipeline took {:?}", cold);

        let start = std::time::Instant::now();
        for _ in 0..10 {
            let _ = cddl_symbol_at(cddl, 0).unwrap();
            let _ = cddl_references(cddl, "record").unwrap();
        }
        let warm = start.elapsed();
        // Twenty calls over an unchanged document parse nothing at all.
        assert!(warm.as_millis() < 50, "warm calls took {:?}", warm);
    }
}

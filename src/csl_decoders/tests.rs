//! Tests for the decoder registry and plutus-data decoding.
//!
//! These guard the fix for: a plutus datum (top-level `Constr`) used to
//! autodetect as `ConstrPlutusData` and "decode" to a `{"hex": ...}` echo of
//! the input. The degenerate `PlutusData` sub-shapes (`ConstrPlutusData`,
//! `PlutusList`, `PlutusMap`) were removed from the registry, and the default
//! plutus-data schema was changed to `DetailedSchema` so constructors decode.

use cardano_serialization_lib as csl;

use crate::csl_decoders::specific_decoders::map_schema;
use crate::csl_decoders::universal_decoder::{
    decode_specific_type, get_decodable_types, get_possible_types_for_input,
};
use crate::js_value::JsValue;

/// Minimal `Constr` 0 datum: tag 121, indefinite array `[int 42]`.
const CONSTR_HEX: &str = "d8799f182aff";
/// A plutus list datum: `[1, 2]`.
const LIST_HEX: &str = "9f0102ff";
/// A plutus map datum: `{1: 2}`.
const MAP_HEX: &str = "a10102";
/// A plutus map whose key is itself a `Constr` (`{Constr 0 []: 0}`). This is
/// the shape `BasicConversions` cannot represent — JSON object keys must be
/// strings — so `to_json` errors unless `DetailedSchema` is used.
const CONSTR_KEY_MAP_HEX: &str = "a1d8798000";

/// Empty `DecodingParams` — exercises the default (no explicit schema) path.
fn default_params() -> JsValue {
    JsValue::new("{}")
}

#[test]
fn degenerate_plutus_types_are_not_decodable() {
    let types = get_decodable_types();
    for removed in ["ConstrPlutusData", "PlutusList", "PlutusMap"] {
        assert!(
            !types.contains(&removed.to_string()),
            "{removed} should no longer be a decodable type"
        );
    }
    assert!(
        types.contains(&"PlutusData".to_string()),
        "PlutusData must still be decodable"
    );
}

#[test]
fn decode_specific_type_rejects_removed_types() {
    for removed in ["ConstrPlutusData", "PlutusList", "PlutusMap"] {
        let res = decode_specific_type(CONSTR_HEX, removed, default_params());
        let err = res.expect_err(&format!("{removed} must not be decodable"));
        assert!(
            err.contains("Unsupported type"),
            "unexpected error for {removed}: {err}"
        );
    }
}

#[test]
fn constr_datum_autodetects_as_plutus_data() {
    let possible = get_possible_types_for_input(CONSTR_HEX);
    assert!(
        possible.contains(&"PlutusData".to_string()),
        "expected PlutusData in autodetect result {possible:?}"
    );
    assert!(
        !possible.contains(&"ConstrPlutusData".to_string()),
        "ConstrPlutusData must no longer hijack autodetect: {possible:?}"
    );
}

#[test]
fn list_and_map_datums_autodetect_as_plutus_data() {
    for hex in [LIST_HEX, MAP_HEX] {
        let possible = get_possible_types_for_input(hex);
        assert!(
            possible.contains(&"PlutusData".to_string()),
            "expected PlutusData for {hex} in {possible:?}"
        );
        assert!(!possible.contains(&"PlutusList".to_string()));
        assert!(!possible.contains(&"PlutusMap".to_string()));
    }
}

#[test]
fn plutus_data_decodes_to_tree_not_hex_echo() {
    let out = decode_specific_type(CONSTR_HEX, "PlutusData", default_params())
        .expect("PlutusData decode should succeed");
    let json = out.as_string().unwrap_or_default();

    // A real decoded tree — not the old stub `{"hex": "<input>"}` echo.
    assert!(json.contains("\"plutus_data\""), "got: {json}");
    assert!(json.contains("\"data_hash\""), "got: {json}");
    assert!(json.contains("\"constructor\""), "got: {json}");
    assert!(json.contains("\"fields\""), "got: {json}");
    assert!(
        !json.contains(CONSTR_HEX),
        "output must not echo the raw input hex: {json}"
    );
}

#[test]
fn default_schema_is_detailed_so_constructors_decode() {
    // `map_schema(None)` must resolve to `DetailedSchema`: `BasicConversions`
    // errors on constructor-keyed maps, which real datums do contain.
    assert!(matches!(
        map_schema(None),
        csl::PlutusDatumSchema::DetailedSchema
    ));

    let decoded = csl::PlutusData::from_hex(CONSTR_KEY_MAP_HEX).unwrap();
    assert!(
        decoded.to_json(map_schema(None)).is_ok(),
        "constructor-keyed datum must decode under the default schema"
    );
    assert!(
        decoded
            .to_json(csl::PlutusDatumSchema::BasicConversions)
            .is_err(),
        "BasicConversions is still expected to reject constructor keys"
    );
}

#[test]
fn constr_keyed_map_autodetects_and_decodes() {
    // The exact shape that previously failed: with the old BasicConversions
    // default, `PlutusData` decoding errored and autodetect fell through to
    // the `ConstrPlutusData` stub.
    let possible = get_possible_types_for_input(CONSTR_KEY_MAP_HEX);
    assert!(
        possible.contains(&"PlutusData".to_string()),
        "constructor-keyed map should autodetect as PlutusData, got {possible:?}"
    );

    let out = decode_specific_type(CONSTR_KEY_MAP_HEX, "PlutusData", default_params())
        .expect("constructor-keyed map should decode");
    let json = out.as_string().unwrap_or_default();
    assert!(json.contains("\"plutus_data\""), "got: {json}");
}

#[test]
fn real_plutus_data_file_decodes_as_plutus_data() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("plutus_data.hex");
    let Ok(hex) = std::fs::read_to_string(&path) else {
        eprintln!("skipping: {} not present", path.display());
        return;
    };
    let hex = hex.trim();

    let possible = get_possible_types_for_input(hex);
    assert!(
        possible.contains(&"PlutusData".to_string()),
        "real datum should autodetect as PlutusData, got {possible:?}"
    );
    assert!(
        !possible.contains(&"ConstrPlutusData".to_string()),
        "real datum must not autodetect as ConstrPlutusData, got {possible:?}"
    );

    let out = decode_specific_type(hex, "PlutusData", default_params())
        .expect("real datum should decode");
    let json = out.as_string().unwrap_or_default();
    assert!(json.contains("\"constructor\""), "got: {json}");
    assert!(json.contains("\"plutus_data\""), "got: {json}");
}

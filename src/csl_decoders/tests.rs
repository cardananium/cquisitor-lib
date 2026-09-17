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

/// A datum taken off-chain, deep enough to exercise the nested `Constr`,
/// list, map and byte-string shapes together.
const REAL_PLUTUS_DATUM_HEX: &str = concat!(
    "d8799fd8799f9fd8799fd8799f582044cae8b0f31eef71924920f4569b6c2c37fcf79700b63926019fe43698e993a200ffd8",
    "799fd8799fd87a9f581c6ab62945d0d8d6288e243b3b6437ff9c099a38e088288f5a6b7c5e8bffd87a80ffa240a1401a0032",
    "0c80581cc48cbb3d5e57ed56e276bc45f99ab39abe94e6cd7ac39fb402da47ada1480014df105553444d1a149ca8ced87b9f",
    "d8799fd8799f581cd7c7a7db47ab71ef07f0aa65e6b0bcf9409977c183e85fe6f0a5feb6ffd8799f581ce39b5f40aa85fbc1",
    "21a625d777a776eca1cb4c923426949c997d8828ff1a00138800d8799fd8799fd8799f581c636d0d0118a8933ac167d4c448",
    "150bb325deaf7a4fdfb44adc7f2f5affd8799fd8799fd8799f581ce39b5f40aa85fbc121a625d777a776eca1cb4c92342694",
    "9c997d8828ffffffffd87980ffd87a9f9f581cc48cbb3d5e57ed56e276bc45f99ab39abe94e6cd7ac39fb402da47ad480014",
    "df105553444d1a149ca8ceff9f581c1f3aec8bfe7ea4fe14c5f121e2a92e301afe414147860d557cac7e344555534443781a",
    "1492825effff43d87980ffffd87a80ffffd8799fd8799f58204ccc26d037e1183cb52aa027fe4b19921eb4e4efeaebf0e6de",
    "5bc8a7e165ee2600ffd8799fd8799fd87a9f581c4de79a0c17180030bff4c36825cb6e99caa007bc632f789561a26d56ffd8",
    "799fd8799fd87a9f581c4399813dad91bb78a5eb17c26ff50852bc75d3fa7b6e9ae87232ccc1ffffffffa440a1401a673716",
    "c6581c1f3aec8bfe7ea4fe14c5f121e2a92e301afe414147860d557cac7e34a14555534443781b000001f720672d35581c4d",
    "e79a0c17180030bff4c36825cb6e99caa007bc632f789561a26d56a15820000de140d7c7a7db47ab71ef07f0aa65e6b0bcf9",
    "409977c183e85fe6f0a5feb601581cc48cbb3d5e57ed56e276bc45f99ab39abe94e6cd7ac39fb402da47ada1480014df1055",
    "53444d1b000002ed2652495ed87b9fd8799f581cd7c7a7db47ab71ef07f0aa65e6b0bcf9409977c183e85fe6f0a5feb69f9f",
    "581c1f3aec8bfe7ea4fe14c5f121e2a92e301afe414147860d557cac7e34455553444378ff9f581cc48cbb3d5e57ed56e276",
    "bc45f99ab39abe94e6cd7ac39fb402da47ad480014df105553444dffff1b000004e2162ca91f9f0505ff9f0101ffd87a8000",
    "9f1a673716c61a08b318671a0586e240ff1901f4c24b0472dd80c9b12d2b1a0adfd87a80ffffd87a80ffffd8799fd8799f58",
    "204ccc26d037e1183cb52aa027fe4b19921eb4e4efeaebf0e6de5bc8a7e165ee2602ffd8799fd8799fd87a9f581c6ab62945",
    "d0d8d6288e243b3b6437ff9c099a38e088288f5a6b7c5e8bffd8799fd8799fd8799f581cf0e17b51bc18962397450eb62522",
    "2bce9c510cb82b213bd9cf17ea82ffffffffa340a1401a00384640581c1f3aec8bfe7ea4fe14c5f121e2a92e301afe414147",
    "860d557cac7e34a14555534443781a02fa27df581cc48cbb3d5e57ed56e276bc45f99ab39abe94e6cd7ac39fb402da47ada1",
    "480014df105553444d1a02faf080d87a9f582051b97b03d1c614d83e9e4bcde3c8500298e58dbce3b9cf61e7dbf5c594b841",
    "fdffd87a80ffffd8799fd8799f58204ccc26d037e1183cb52aa027fe4b19921eb4e4efeaebf0e6de5bc8a7e165ee2604ffd8",
    "799fd8799fd8799f581c4a7110f2c2ca1d07d1c2d3eab664eb82383762c496ecdb633c0bdd90ffd87a80ffa140a1401a9553",
    "e042d87980d87a80ffffff9fd8799fd8799f58200bbd502d7bdaadb0e928a1dc5510564bbfe8cc9f907f5bdc5d6e55021edd",
    "8e7c00ffd8799fd8799fd87a9f581c6d9d7acac59a4469ec52bb207106167c5cbfa689008ffa6ee92acc50ffd87a80ffa240",
    "a1401a007bd612581c6d9d7acac59a4469ec52bb207106167c5cbfa689008ffa6ee92acc50a14873657474696e677301d87b",
    "9fd8799fd87c9f039fd8799f581c8582e6a55ccbd7af4cabe35d6da6eaa3d543083e1ce822add9917730ffd8799f581c7180",
    "d7ad9aaf20658d8f88c32a2e5c287425618c32c9bb82d6b6c8f8ffd8799f581cbba4dff30f517f2859f8f295a97d3d85f26a",
    "818078f9294256fda2d8ffd8799f581c1f68495896a7ba5132198145359311e991a1463e95ccc6f56703653dffd8799f581c",
    "f65e667d512b26aa98a97ac22e958e5201e7ea279d74b2e4ec5883dbffffffd8799fd87a9f581c1854e9028a89496e9772a5",
    "4882729d16554f8ed9af27ec6046c9a87cffd87a80ffd8799f581c55bf4118b01e1c794647db9375ffc873e435d737007b2a",
    "dbc48cdbaaffd8799fd87a9f581cc0d7aa781d14f206f1f6468f0a2d49187d1ebcb8f59c59d75d0c27a7ffd87a80ff9f0101",
    "ffd8799f9f581c4a7110f2c2ca1d07d1c2d3eab664eb82383762c496ecdb633c0bdd90581cdb9d3f959cf66974611930849c",
    "953fab7d18e82d6405564b7868cb48ffff9fd87a9f581c4399813dad91bb78a5eb17c26ff50852bc75d3fa7b6e9ae87232cc",
    "c1ffd8799f581cbc10fe312acd69e2e12cbc2cca05aa0e432e3dee65d5a9498344e4aaffff1a000956a01a000a31601a000a",
    "31601b009fdf42f6e48000a100d8799f9f0000ffffffffd87a80ffffd8799fd8799f5820309c5db1dff1dfa17ff89ac9e6d5",
    "d0eea4a006b15646bab54ab9260d5567579700ffd8799fd8799fd87a9f581cbbece14f554b0020fe2715d05801f4680ebd40",
    "d11a58f14740b9f2c5ffd87a80ffa140a1401a00aa5514d87980d8799f581c6ab62945d0d8d6288e243b3b6437ff9c099a38",
    "e088288f5a6b7c5e8bffffffd8799fd8799f5820d8d42797c0e0e491d2054c892187f98ec2cf3dc57f1dd7dcd2ccdc01bede",
    "ce3000ffd8799fd8799fd87a9f581cbbece14f554b0020fe2715d05801f4680ebd40d11a58f14740b9f2c5ffd87a80ffa140",
    "a1401a03a73fded87980d8799f581c4de79a0c17180030bff4c36825cb6e99caa007bc632f789561a26d56ffffffff9fd879",
    "9fd8799fd87a9f581c4de79a0c17180030bff4c36825cb6e99caa007bc632f789561a26d56ffd8799fd8799fd87a9f581c43",
    "99813dad91bb78a5eb17c26ff50852bc75d3fa7b6e9ae87232ccc1ffffffffa440a1401a674b258d581c1f3aec8bfe7ea4fe",
    "14c5f121e2a92e301afe414147860d557cac7e34a14555534443781b000001f70eca1386581c4de79a0c17180030bff4c368",
    "25cb6e99caa007bc632f789561a26d56a15820000de140d7c7a7db47ab71ef07f0aa65e6b0bcf9409977c183e85fe6f0a5fe",
    "b601581cc48cbb3d5e57ed56e276bc45f99ab39abe94e6cd7ac39fb402da47ada1480014df105553444d1b000002ed3de9e2",
    "acd87b9fd8799f581cd7c7a7db47ab71ef07f0aa65e6b0bcf9409977c183e85fe6f0a5feb69f9f581c1f3aec8bfe7ea4fe14",
    "c5f121e2a92e301afe414147860d557cac7e34455553444378ff9f581cc48cbb3d5e57ed56e276bc45f99ab39abe94e6cd7a",
    "c39fb402da47ad480014df105553444dffff1b000004e21c1f37b39f0505ff9f0101ffd87a80009f1a674b258d1a08b39f6d",
    "1a0586e240ff1901f4c24b0472e2ee47d5f5dc709697d87a80ffffd87a80ffd8799fd8799fd8799f581ce0b68e229f9c043a",
    "b610067ed7f3c6d662b8f3c6bb4ec452c11f6411ffd8799fd8799fd8799f581cf0e17b51bc18962397450eb625222bce9c51",
    "0cb82b213bd9cf17ea82ffffffffa340a1401a00296990581c1f3aec8bfe7ea4fe14c5f121e2a92e301afe414147860d557c",
    "ac7e34a145555344437818a3581c4de79a0c17180030bff4c36825cb6e99caa007bc632f789561a26d56a158200014df10d7",
    "c7a7db47ab71ef07f0aa65e6b0bcf9409977c183e85fe6f0a5feb61a05f28e94d87980d87a80ffd8799fd8799fd8799f581c",
    "636d0d0118a8933ac167d4c448150bb325deaf7a4fdfb44adc7f2f5affd8799fd8799fd8799f581ce39b5f40aa85fbc121a6",
    "25d777a776eca1cb4c923426949c997d8828ffffffffa240a1401a00232fd0581c1f3aec8bfe7ea4fe14c5f121e2a92e301a",
    "fe414147860d557cac7e34a14555534443781a149740ebd87980d87a80ffd8799fd8799fd8799f581c4a7110f2c2ca1d07d1",
    "c2d3eab664eb82383762c496ecdb633c0bdd90ffd87a80ffa140a1401a9553e042d87980d87a80ffff1a0009aa99a1581c4d",
    "e79a0c17180030bff4c36825cb6e99caa007bc632f789561a26d56a158200014df10d7c7a7db47ab71ef07f0aa65e6b0bcf9",
    "409977c183e85fe6f0a5feb61a05f28e9480a1d87a9f581c598e5522eeb4faef80158a5c1d47ec1f1eaf7750b538dc3110a1",
    "cf64ff00d8799fd8799fd87a9f1b0000019cda8020a0ffd87a80ffd8799fd87a9f1b0000019cda9ea520ffd87980ffff9f58",
    "1c4a7110f2c2ca1d07d1c2d3eab664eb82383762c496ecdb633c0bdd90ffa5d87a9fd8799f582044cae8b0f31eef71924920",
    "f4569b6c2c37fcf79700b63926019fe43698e993a200ffffd87980d87a9fd8799f58204ccc26d037e1183cb52aa027fe4b19",
    "921eb4e4efeaebf0e6de5bc8a7e165ee2600ffffd8799f00009f9f02d87a80c24b0472e2ebe1a9df7f9a94a200ff9f00d87a",
    "80c24b0472e2ee47d5f5dc709697c24912bd0e325f5147e44dffffffd87a9fd8799f58204ccc26d037e1183cb52aa027fe4b",
    "19921eb4e4efeaebf0e6de5bc8a7e165ee2602ffffd87980d8799f581c4de79a0c17180030bff4c36825cb6e99caa007bc63",
    "2f789561a26d56ffd8799f581cd7c7a7db47ab71ef07f0aa65e6b0bcf9409977c183e85fe6f0a5feb6ffd87b9fd87a9f581c",
    "598e5522eeb4faef80158a5c1d47ec1f1eaf7750b538dc3110a1cf64ffffd87980a1582051b97b03d1c614d83e9e4bcde3c8",
    "500298e58dbce3b9cf61e7dbf5c594b841fdd8799fd8799f581cd7c7a7db47ab71ef07f0aa65e6b0bcf9409977c183e85fe6",
    "f0a5feb6ffd8799f581cf0e17b51bc18962397450eb625222bce9c510cb82b213bd9cf17ea82ff1a00138800d8799fd8799f",
    "d8799f581ce0b68e229f9c043ab610067ed7f3c6d662b8f3c6bb4ec452c11f6411ffd8799fd8799fd8799f581cf0e17b51bc",
    "18962397450eb625222bce9c510cb82b213bd9cf17ea82ffffffffd87980ffd87b9f9f9f581c1f3aec8bfe7ea4fe14c5f121",
    "e2a92e301afe414147860d557cac7e344555534443781a02fa273cff9f581cc48cbb3d5e57ed56e276bc45f99ab39abe94e6",
    "cd7ac39fb402da47ad480014df105553444d1a02faf080ffffff43d87980ff5820b39ec1825e0b4dda6300a8996134660907",
    "852a1f252ccd961e95d89e927a1bf2a080d87a80d87a80ffd8799f00009f9f02d87a80c24b0472e2ebe1a9df7f9a94a200ff",
    "9f00d87a80c24b0472e2ee47d5f5dc709697c24912bd0e325f5147e44dffffffd87a9fd8799f58204ccc26d037e1183cb52a",
    "a027fe4b19921eb4e4efeaebf0e6de5bc8a7e165ee2600ffd8799fd8799f581cd7c7a7db47ab71ef07f0aa65e6b0bcf94099",
    "77c183e85fe6f0a5feb69f9f581c1f3aec8bfe7ea4fe14c5f121e2a92e301afe414147860d557cac7e34455553444378ff9f",
    "581cc48cbb3d5e57ed56e276bc45f99ab39abe94e6cd7ac39fb402da47ad480014df105553444dffff1b000004e2162ca91f",
    "9f0505ff9f0101ffd87a80009f1a673716c61a08b318671a0586e240ff1901f4c24b0472dd80c9b12d2b1a0adfd87a80ffff",
    "ffff"
);

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
            "{} should no longer be a decodable type",
            removed
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
            "unexpected error for {}: {}",
            removed,
            err
        );
    }
}

#[test]
fn constr_datum_autodetects_as_plutus_data() {
    let possible = get_possible_types_for_input(CONSTR_HEX);
    assert!(
        possible.contains(&"PlutusData".to_string()),
        "expected PlutusData in autodetect result {:?}",
        possible
    );
    assert!(
        !possible.contains(&"ConstrPlutusData".to_string()),
        "ConstrPlutusData must no longer hijack autodetect: {:?}",
        possible
    );
}

#[test]
fn list_and_map_datums_autodetect_as_plutus_data() {
    for hex in [LIST_HEX, MAP_HEX] {
        let possible = get_possible_types_for_input(hex);
        assert!(
            possible.contains(&"PlutusData".to_string()),
            "expected PlutusData for {} in {:?}",
            hex,
            possible
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
    assert!(json.contains("\"plutus_data\""), "got: {}", json);
    assert!(json.contains("\"data_hash\""), "got: {}", json);
    assert!(json.contains("\"constructor\""), "got: {}", json);
    assert!(json.contains("\"fields\""), "got: {}", json);
    assert!(
        !json.contains(CONSTR_HEX),
        "output must not echo the raw input hex: {}",
        json
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
        "constructor-keyed map should autodetect as PlutusData, got {:?}",
        possible
    );

    let out = decode_specific_type(CONSTR_KEY_MAP_HEX, "PlutusData", default_params())
        .expect("constructor-keyed map should decode");
    let json = out.as_string().unwrap_or_default();
    assert!(json.contains("\"plutus_data\""), "got: {}", json);
}

#[test]
fn real_plutus_data_file_decodes_as_plutus_data() {
    let hex = REAL_PLUTUS_DATUM_HEX.trim();

    let possible = get_possible_types_for_input(hex);
    assert!(
        possible.contains(&"PlutusData".to_string()),
        "real datum should autodetect as PlutusData, got {:?}",
        possible
    );
    assert!(
        !possible.contains(&"ConstrPlutusData".to_string()),
        "real datum must not autodetect as ConstrPlutusData, got {:?}",
        possible
    );

    let out = decode_specific_type(hex, "PlutusData", default_params())
        .expect("real datum should decode");
    let json = out.as_string().unwrap_or_default();
    assert!(json.contains("\"constructor\""), "got: {}", json);
    assert!(json.contains("\"plutus_data\""), "got: {}", json);
}

/// `[[[…5…]]]`, `levels` arrays deep, as hex.
fn nested_arrays_hex(levels: usize) -> String {
    format!("{}05", "81".repeat(levels))
}

/// The typed decoders recurse over a document on the host's stack, so a
/// document is scanned for its depth before any decoder sees it: one
/// inside the bound decodes as the metadata shapes it is, one past the
/// bound decodes as nothing and is refused by name, and neither is ever
/// handed to a decoder that would recurse past what a host stack holds.
#[test]
fn typed_decoders_refuse_a_document_nested_past_their_bound() {
    use crate::cbor::limits::MAX_TYPED_DECODER_NESTING_DEPTH as BOUND;

    let inside = nested_arrays_hex(BOUND);
    let possible = get_possible_types_for_input(&inside);
    assert!(
        possible.iter().any(|t| t == "TransactionMetadatum"),
        "at the bound the metadata shapes are offered, got {:?}",
        possible
    );
    assert!(decode_specific_type(&inside, "TransactionMetadatum", default_params()).is_ok());
    // Plutus data renders each level as a few levels of JSON on its way
    // back, and the reader of that JSON has to follow all of them.
    assert!(
        decode_specific_type(&inside, "PlutusData", default_params()).is_ok(),
        "Plutus data at the bound: {:?}",
        decode_specific_type(&inside, "PlutusData", default_params()).err()
    );

    let past = nested_arrays_hex(BOUND + 1);
    assert_eq!(get_possible_types_for_input(&past), Vec::<String>::new());
    let refused = decode_specific_type(&past, "TransactionMetadatum", default_params())
        .expect_err("a document past the bound is refused");
    assert!(
        refused.contains(&format!("supported limit of {} levels", BOUND)),
        "the refusal names the bound: {}",
        refused
    );
}

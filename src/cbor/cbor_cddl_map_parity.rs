//! Parity tests: every decoded path has a map row and vice versa.
//!
//! Covers ledger fixtures plus one minimal case per disagreement mode.
//! Path enumeration shares `extend_decoded_path` with the walker.

#![cfg(test)]

use std::collections::BTreeSet;

use serde_json::Value;

use crate::cbor::cbor_cddl_map::{
    expand_paths, extend_decoded_path, map_against_ast, map_cbor_to_cddl,
};
use crate::cbor::schema_mapper::decode_against_ast;
use crate::cbor::test_fixtures::{
    datum_doc, ledger_cddl, record_doc, schema_suite, DATUM_DOC_HEX, RECORD_DOC_HEX,
};

// ============================================================
// Path enumeration
// ============================================================

/// Every addressable path of a decoded JSON tree, in the same grammar
/// `decoded_path` uses.
fn tree_paths(v: &Value, prefix: &str, out: &mut BTreeSet<String>) {
    out.insert(prefix.to_string());
    match v {
        Value::Object(o) => {
            // Schema-only `match` on an `@entries` pair — skip.
            let is_pair = o.len() == 3
                && o.contains_key("key")
                && o.contains_key("value")
                && o.contains_key("match");
            for (k, child) in o {
                if is_pair && k == "match" {
                    continue;
                }
                tree_paths(child, &extend_decoded_path(prefix, k), out);
            }
        }
        Value::Array(a) => {
            for (i, child) in a.iter().enumerate() {
                tree_paths(child, &format!("{}[{}]", prefix, i), out);
            }
        }
        _ => {}
    }
}

fn map_path_set(rows: &[Value]) -> BTreeSet<String> {
    rows.iter()
        .map(|r| {
            r["decoded_path"]
                .as_str()
                .expect("every row carries a decoded_path")
                .to_string()
        })
        .collect()
}

/// Parse once, then run every case of a corpus against the same AST.
/// Parsing a full ledger schema dominates the runtime otherwise.
struct Schema<'s> {
    source: &'s str,
    ast: cddl::ast::CDDL<'s>,
}

impl<'s> Schema<'s> {
    fn new(source: &'s str) -> Schema<'s> {
        let ast = cddl::pest_bridge::cddl_from_pest_str_checked(source)
            .unwrap_or_else(|e| panic!("schema does not parse: {}", e));
        Schema { source, ast }
    }

    fn decoded_paths(&self, rule: &str, cbor: &[u8]) -> BTreeSet<String> {
        let decoded = decode_against_ast(&self.ast, cbor, rule)
            .unwrap_or_else(|e| panic!("decode failed: {}", e));
        let mut out = BTreeSet::new();
        tree_paths(&decoded, "$", &mut out);
        out
    }

    fn rows(&self, rule: &str, cbor: &[u8]) -> Vec<Value> {
        let mut text = String::new();
        map_against_ast(&mut text, &self.ast, cbor, self.source, rule)
            .unwrap_or_else(|e| panic!("map failed: {}", e));
        expand_paths(&serde_json::from_str(&text).expect("the mapping text is JSON"))
    }

    /// Assert set equality between the decoded tree's paths and the
    /// map's, then check every span the rows carry.
    #[track_caller]
    fn assert_case(&self, name: &str, rule: &str, hex_cbor: &str) -> usize {
        let bytes = hex::decode(hex_cbor.replace(' ', ""))
            .unwrap_or_else(|e| panic!("{}: bad hex: {}", name, e));
        let expected = self.decoded_paths(rule, &bytes);
        let rows = self.rows(rule, &bytes);
        let actual = map_path_set(&rows);

        let missing: Vec<&String> = expected.difference(&actual).collect();
        let phantom: Vec<&String> = actual.difference(&expected).collect();
        assert!(
            missing.is_empty() && phantom.is_empty(),
            "{}: decoded tree and position map disagree\n  missing (in tree, no row): {:?}\n  phantom (row, not in tree): {:?}",
            name,
            missing,
            phantom
        );
        assert_span_hygiene(name, self.source, &rows);
        assert_cbor_span_hygiene(name, &bytes, &rows);
        rows.len()
    }
}

// ============================================================
// Corpus
// ============================================================

fn h(byte: &str, times: usize) -> String {
    byte.repeat(times)
}

/// 28-, 29- and 32-byte hashes with their CBOR byte-string headers.
fn hash28() -> String {
    format!("581c{}", h("ab", 28))
}
fn hash29() -> String {
    format!("581d{}", h("ab", 29))
}
fn hash32() -> String {
    format!("5820{}", h("ab", 32))
}

fn key_credential() -> String {
    format!("8200{}", hash28())
}

/// A 64-byte string with its CBOR header, the size a signature body has.
fn bytes64() -> String {
    format!("5840{}", h("ab", 64))
}

/// A one-bucket, one-label stock: `{hash28 => {h'010203' => 1}}`.
fn stock() -> String {
    format!("a1{}a14301020301", hash28())
}

/// `#6.24(bytes .cbor datum)` around the empty constructor `d87980`.
fn payload() -> String {
    "d81843d87980".to_string()
}

/// `(name, rule, hex)` triples over the ledger schema, one per shape the
/// ledger serialises: every alternative of every choice, both entry
/// forms, tagged and plain sets, and each kind of datum.
fn ledger_corpus() -> Vec<(&'static str, &'static str, String)> {
    let cred = key_credential();
    vec![
        ("ref", "ref", format!("82{}00", hash32())),
        ("index", "index", "1864".to_string()),
        ("legacy_entry", "entry", format!("82{}1864", hash29())),
        (
            "legacy_entry_with_hash",
            "entry",
            format!("83{}1864{}", hash29(), hash32()),
        ),
        ("rich_entry", "entry", format!("a200{}0105", hash29())),
        (
            "rich_entry_with_datum_and_payload",
            "entry",
            format!("a400{}01050282 01{}03{}", hash29(), payload(), payload()).replace(' ', ""),
        ),
        ("value_with_stock", "value", format!("821864{}", stock())),
        ("value_amount_only", "value", "1864".to_string()),
        ("stock", "stock", stock()),
        (
            "stock_with_negative_count",
            "stock",
            format!("a1{}a2430102030140 3829", hash28()).replace(' ', ""),
        ),
        ("int64_min", "int64", "3b7fffffffffffffff".to_string()),
        ("int64_max", "int64", "1b7fffffffffffffff".to_string()),
        ("note", "note", format!("8200{}", hash32())),
        ("credential_key", "credential", cred.clone()),
        (
            "credential_script",
            "credential",
            format!("8201{}", hash28()),
        ),
        (
            "certificate_registration",
            "certificate",
            format!("8200{}", cred),
        ),
        (
            "certificate_delegation",
            "certificate",
            format!("8301{}{}", cred, hash28()),
        ),
        (
            "certificate_retirement",
            "certificate",
            format!("8302{}1864", cred),
        ),
        (
            "certificate_transfer",
            "certificate",
            format!("8403{}{}1864", cred, cred),
        ),
        ("relay_by_address_absent", "relay", "8400f6f6f6".to_string()),
        (
            "relay_by_address",
            "relay",
            format!("84001901bb44010203045 0{}", h("ab", 16)).replace(' ', ""),
        ),
        ("relay_by_name", "relay", "8301f66161".to_string()),
        ("relay_multi_host", "relay", "82026161".to_string()),
        (
            "native_script_key",
            "native_script",
            format!("8200{}", hash28()),
        ),
        (
            "native_script_all_nested",
            "native_script",
            format!("820181 8200{}", hash28()).replace(' ', ""),
        ),
        ("native_script_any", "native_script", "820280".to_string()),
        (
            "native_script_n_of_k",
            "native_script",
            "83030180".to_string(),
        ),
        (
            "native_script_after",
            "native_script",
            "82041864".to_string(),
        ),
        (
            "native_script_before",
            "native_script",
            "82051864".to_string(),
        ),
        (
            "signature",
            "signature",
            format!("82{}{}", hash32(), bytes64()),
        ),
        ("datum_constr", "datum", "d87980".to_string()),
        (
            "datum_constr_with_fields",
            "datum",
            "d8798201 41ab".replace(' ', ""),
        ),
        (
            "datum_constr_general_form",
            "datum",
            "d866820580".to_string(),
        ),
        ("datum_map", "datum", "a10102".to_string()),
        ("datum_array", "datum", "820102".to_string()),
        ("datum_big_int", "datum", "01".to_string()),
        ("datum_big_uint", "datum", "c24101".to_string()),
        ("datum_big_nint", "datum", "c34101".to_string()),
        ("datum_bounded_bytes", "datum", "41ab".to_string()),
        (
            "payload_embedded_cbor",
            "payload",
            "d818458201420304".to_string(),
        ),
        (
            "datum_option_hash",
            "datum_option",
            format!("8200{}", hash32()),
        ),
        (
            "datum_option_inline",
            "datum_option",
            format!("8201{}", payload()),
        ),
        (
            "redeemer",
            "redeemer",
            "840001d87980821864 1864".replace(' ', ""),
        ),
        ("record_aux_map", "record_aux", "a1006161".to_string()),
        (
            "record_aux_with_scripts",
            "record_aux",
            "82a100616180".to_string(),
        ),
        ("record_aux_empty", "record_aux", "a0".to_string()),
        ("metadatum_map", "metadatum", "a1616101".to_string()),
        ("metadatum_array", "metadatum", "82016161".to_string()),
        ("metadatum_text", "metadatum", "6161".to_string()),
        ("metadatum_nint", "metadatum", "3829".to_string()),
        (
            "record_body_minimal",
            "record_body",
            "a3 0080 0180 021864".replace(' ', ""),
        ),
        (
            "record_body_tagged_sets",
            "record_body",
            format!(
                "a4 00d9010281 82{}00 01 81 82{}1864 02 1864 0d d901028 0",
                hash32(),
                hash29()
            )
            .replace(' ', ""),
        ),
        ("record_witness_empty", "record_witness", "a0".to_string()),
        (
            "record_witness_signatures",
            "record_witness",
            format!("a100d901028182{}{}", hash32(), bytes64()),
        ),
        (
            "record_minimal",
            "record",
            "84 a3008001800218 64 a0 f5 f6".replace(' ', ""),
        ),
        (
            "record_with_aux",
            "record",
            "84 a3008001800218 64 a0 f4 a1006161".replace(' ', ""),
        ),
        (
            "settings",
            "settings",
            "a3000101020382 0102".replace(' ', ""),
        ),
        (
            "settings_text_keyed",
            "settings",
            "a104a1616101".to_string(),
        ),
        ("version", "version", "820102".to_string()),
        ("extension", "extension", "820041ab".to_string()),
        ("tree_leaf", "tree", "6161".to_string()),
        ("tree_branch", "tree", "82616181 6162".replace(' ', "")),
        ("widget", "widget_0", "82016161".to_string()),
        (
            "widget_with_weight",
            "widget_0",
            "83016161 1864".replace(' ', ""),
        ),
        ("widgets", "widgets", "8182016161".to_string()),
    ]
}

/// One minimal schema per way the position map could disagree with the
/// decoded tree.
fn synthetic_corpus() -> Vec<(&'static str, &'static str, &'static str, &'static str)> {
    vec![
        (
            "type_choice_second_alternative",
            "root = alt_a / alt_b\nalt_a = tstr\nalt_b = [x: uint, y: uint]",
            "root",
            "820102",
        ),
        (
            "group_choice_second_alternative",
            "x = [a // b]\na = (0, uint)\nb = (1, tstr)",
            "x",
            "8201 6161",
        ),
        (
            "parenthesized_alternative_declines",
            "x = (tstr) / [uint, uint]",
            "x",
            "820102",
        ),
        (
            "tag_number_selects_the_right_alternative",
            "x = #6.121([* uint]) / #6.999([* uint])",
            "x",
            "d903e78101",
        ),
        (
            "embedded_cbor_payload",
            "outer = bstr .cbor inner\ninner = [a: uint, b: uint]",
            "outer",
            "43820102",
        ),
        (
            "embedded_cborseq_payload",
            "outer = bstr .cborseq inner\ninner = [a: uint, b: uint]",
            "outer",
            "43820102",
        ),
        (
            "embedded_cbor_that_does_not_fit",
            "outer = bstr .cbor inner\ninner = [a: uint, b: uint]",
            "outer",
            "4161",
        ),
        (
            "embedded_cbor_in_indefinite_bytes",
            "outer = bstr .cbor inner\ninner = [a: uint, b: uint]",
            "outer",
            "5f4382010 2ff",
        ),
        (
            "type_keyed_map_members",
            "m = { * tstr => uint }",
            "m",
            "a2616101616202",
        ),
        (
            "map_group_choice_second_alternative",
            "m = { 0: uint // 1: uint, 2: uint }",
            "m",
            "a201010202",
        ),
        (
            "mixed_named_array_named_first",
            "tx = [body: int, bool, int]",
            "tx",
            "8301f502",
        ),
        (
            "mixed_named_array_named_second",
            "tx = [bool, body: int, bool]",
            "tx",
            "83f501f4",
        ),
        (
            "overlong_unnamed_array",
            "pair = [int, int]",
            "pair",
            "83010203",
        ),
        (
            "overlong_named_array",
            "rec = [a: int, b: int]",
            "rec",
            "83010203",
        ),
        (
            "absent_required_members",
            "m = { a: uint, b: uint }",
            "m",
            "a0",
        ),
        (
            "optional_array_slot_absent",
            "t = [? uint, tstr]",
            "t",
            "816178",
        ),
        (
            "optional_array_slot_present",
            "t = [? uint, tstr]",
            "t",
            "8201 6178",
        ),
        (
            "prelude_typed_array_slots",
            "t = [int, int, int]",
            "t",
            "83010203",
        ),
        ("homogeneous_array", "t = [* int]", "t", "83010203"),
        (
            "repeating_named_array_slot",
            "t = [* item: uint]",
            "t",
            "83010203",
        ),
        (
            "repeating_named_slot_empty",
            "t = [* item: uint]",
            "t",
            "80",
        ),
        ("narrow_bignum_tag", "x = #6.2(bstr)", "x", "c243010203"),
        (
            "wide_bignum_tag",
            "x = #6.2(bstr)",
            "x",
            "c2510102030405060708091011121314151617",
        ),
        ("datetime_tag", "x = #6.0(tstr)", "x", "c06131"),
        ("negative_bignum_tag", "x = #6.3(bstr)", "x", "c343010203"),
        ("tag_not_in_schema", "x = [* uint]", "x", "d9010283010203"),
        (
            "unmatched_complex_key",
            "m = { 0: uint }",
            "m",
            "a181011864",
        ),
        (
            "duplicate_keys_force_entries_form",
            "m = { * tstr => uint }",
            "m",
            "a2616101616102",
        ),
        (
            "indefinite_and_definite_string_keys_collide",
            "m = { * tstr => uint }",
            "m",
            "a26161017f6161ff02",
        ),
        ("indefinite_array", "x = [* uint]", "x", "9f010203ff"),
        (
            "indefinite_map",
            "m = { * tstr => uint }",
            "m",
            "bf616101ff",
        ),
        (
            "indefinite_byte_string",
            "x = bstr",
            "x",
            "5f42010243030405ff",
        ),
        ("simple_value", "x = any", "x", "f8ff"),
        (
            "nothing_matches_falls_back_to_raw",
            "x = tstr",
            "x",
            "83010203",
        ),
        (
            "nothing_matches_nested_map",
            "x = tstr",
            "x",
            "a2616101616202",
        ),
        ("any_over_a_tagged_map", "x = any", "x", "d90102a1616101"),
        ("range_slot_over_a_bignum", "x = 0 .. 1000", "x", "c24101"),
        (
            "generic_rule_reference",
            "set<a> = #6.258([* a])\ninputs = set<input>\ninput = [tx: bstr, idx: uint]",
            "inputs",
            "d9010281824101 00",
        ),
        (
            "group_rule_spliced_into_array",
            "t = [g, tstr]\ng = (a: uint, b: uint)",
            "t",
            "83010261 61",
        ),
    ]
}

// ============================================================
// Span hygiene
// ============================================================

/// Every CDDL span must point at real schema text: non-empty, inside the
/// source, on the line it claims, and free of the whitespace and comments
/// a raw parser span runs into. No field is ever emitted as JSON null.
#[track_caller]
fn assert_span_hygiene(name: &str, cddl: &str, rows: &[Value]) {
    for row in rows {
        for (field, value) in row.as_object().unwrap() {
            assert!(
                !value.is_null(),
                "{}: field {} came out as null in {}",
                name,
                field,
                row
            );
        }
        let Some(span) = row.get("cddl_byte_span") else {
            continue;
        };
        let offset = span["offset"].as_u64().unwrap() as usize;
        let length = span["length"].as_u64().unwrap() as usize;
        let line = span["line"].as_u64().unwrap() as usize;
        assert!(length > 0, "{}: zero-length cddl span in {}", name, row);
        assert!(line >= 1, "{}: line 0 in {}", name, row);
        assert!(
            offset + length <= cddl.len(),
            "{}: cddl span past end of source in {}",
            name,
            row
        );
        let text = &cddl[offset..offset + length];
        assert_eq!(
            text.trim(),
            text,
            "{}: cddl span carries surrounding whitespace: {:?}",
            name,
            text
        );
        // A span may cover a multi-line construct that has a comment
        // inside it, but must never run out into a trailing comment.
        let last_line = text.rsplit('\n').next().unwrap();
        assert!(
            !last_line.contains(';'),
            "{}: cddl span ends inside a comment: {:?}",
            name,
            text
        );
        assert_eq!(
            line,
            cddl[..offset].matches('\n').count() + 1,
            "{}: wrong line for span {:?}",
            name,
            text
        );
    }
}

/// Every CBOR span must address bytes of the document, and a node's
/// anchor must contain its header.
#[track_caller]
fn assert_cbor_span_hygiene(name: &str, bytes: &[u8], rows: &[Value]) {
    for row in rows {
        let byte = row.get("cbor_byte_span");
        let anchor = row.get("cbor_anchor_span");
        for span in byte.into_iter().chain(anchor) {
            let offset = span["offset"].as_u64().unwrap() as usize;
            let length = span["length"].as_u64().unwrap() as usize;
            assert!(
                offset + length <= bytes.len(),
                "{}: cbor span {}..{} past the end of a {}-byte input in {}",
                name,
                offset,
                offset + length,
                bytes.len(),
                row
            );
        }
        if let (Some(b), Some(a)) = (byte, anchor) {
            let (bo, bl) = (b["offset"].as_u64().unwrap(), b["length"].as_u64().unwrap());
            let (ao, al) = (a["offset"].as_u64().unwrap(), a["length"].as_u64().unwrap());
            assert!(
                ao <= bo && ao + al >= bo + bl,
                "{}: anchor does not contain the byte span in {}",
                name,
                row
            );
        }
    }
}

// ============================================================
// Tests
// ============================================================

/// `datum_doc` wrapped the way the ledger carries a datum inside an
/// entry: `#6.24(bytes .cbor datum)`, the deepest payload the corpus has.
fn payload_doc() -> Vec<u8> {
    let inner = ciborium::value::Value::Bytes(datum_doc());
    let mut out = Vec::new();
    ciborium::into_writer(&ciborium::value::Value::Tag(24, Box::new(inner)), &mut out)
        .expect("the payload encodes");
    out
}

#[test]
fn ledger_sub_rules_map_every_decoded_path() {
    let schema = Schema::new(ledger_cddl());
    for (name, rule, hex) in ledger_corpus() {
        schema.assert_case(name, rule, &hex);
    }
}

#[test]
fn synthetic_cases_map_every_decoded_path() {
    for (name, cddl, rule, hex) in synthetic_corpus() {
        Schema::new(cddl).assert_case(name, rule, hex);
    }
}

#[test]
fn every_schema_version_maps_every_decoded_path_of_the_fixture_documents() {
    let payload = hex::encode(payload_doc());
    for (version, cddl) in schema_suite() {
        let schema = Schema::new(cddl);
        schema.assert_case(
            &format!("{}/record", version),
            "record",
            RECORD_DOC_HEX.as_str(),
        );
        schema.assert_case(
            &format!("{}/datum", version),
            "datum",
            DATUM_DOC_HEX.as_str(),
        );
        schema.assert_case(&format!("{}/payload", version), "payload", &payload);
    }
}

#[test]
fn embedded_cbor_rows_point_inside_the_byte_string_payload() {
    // Tag 24 payload starts at offset 3; nested rows must stay in 3..8.
    let bytes = hex::decode("d818458201420304").unwrap();
    let rows = expand_paths(&map_cbor_to_cddl(&bytes, ledger_cddl(), "payload").unwrap());
    let inner: Vec<&Value> = rows
        .iter()
        .filter(|r| {
            r["decoded_path"]
                .as_str()
                .is_some_and(|p| p.contains(r#"["@value"]["#))
        })
        .collect();
    assert!(!inner.is_empty(), "no rows inside the embedded payload");
    for row in inner {
        let offset = row["cbor_byte_span"]["offset"].as_u64().unwrap();
        assert!(
            (3..8).contains(&offset),
            "embedded row points outside the payload: {}",
            row
        );
    }
}

#[test]
fn every_payload_of_the_record_maps_its_datum_inside_the_byte_string() {
    // Each rich entry carries a `#6.24` payload; the rows below its
    // `@value` must address bytes of that payload, not of the record
    // around it.
    let bytes = record_doc();
    let rows = expand_paths(&map_cbor_to_cddl(&bytes, ledger_cddl(), "record").unwrap());
    let payload_roots: Vec<&Value> = rows
        .iter()
        .filter(|r| {
            r["decoded_path"]
                .as_str()
                .is_some_and(|p| p.ends_with(r#".payload["@value"]"#))
        })
        .collect();
    assert!(
        !payload_roots.is_empty(),
        "the record carries no embedded payload"
    );
    for root in payload_roots {
        let root_path = root["decoded_path"].as_str().unwrap();
        // The byte span of a byte string is its header; the anchor is the
        // whole item, header and content.
        let span = &root["cbor_anchor_span"];
        let start = span["offset"].as_u64().unwrap();
        let end = start + span["length"].as_u64().unwrap();
        let inside: Vec<&Value> = rows
            .iter()
            .filter(|r| {
                r["decoded_path"]
                    .as_str()
                    .is_some_and(|p| p.starts_with(root_path) && p.len() > root_path.len())
            })
            .collect();
        assert!(
            !inside.is_empty(),
            "{}: no rows inside the payload",
            root_path
        );
        for row in inside {
            let offset = row["cbor_byte_span"]["offset"].as_u64().unwrap();
            assert!(
                (start..end).contains(&offset),
                "{}: row points outside the payload {}..{}: {}",
                root_path,
                start,
                end,
                row
            );
        }
    }
}

#[test]
fn embedded_cbor_in_a_chunked_byte_string_reports_no_cbor_span() {
    // Indefinite bytes are non-contiguous; nested rows omit byte spans.
    let cddl = "outer = bstr .cbor inner\ninner = [a: uint, b: uint]";
    let bytes = hex::decode("5f43820102ff").unwrap();
    let rows = expand_paths(&map_cbor_to_cddl(&bytes, cddl, "outer").unwrap());
    let inner: Vec<&Value> = rows
        .iter()
        .filter(|r| r["decoded_path"].as_str() != Some("$"))
        .collect();
    assert!(!inner.is_empty(), "no rows below the byte string");
    for row in inner {
        assert!(
            row.get("cbor_byte_span").is_none(),
            "chunked payload row claims a byte span: {}",
            row
        );
        assert!(
            row.get("cddl_byte_span").is_some(),
            "chunked payload row lost its schema location: {}",
            row
        );
    }
}

/// Deepest fixture plus ~30% deeper datum shapes still answer within budget.
#[test]
fn the_deepest_fixture_is_answered_with_headroom_against_the_descent_budget() {
    let schema = Schema::new(ledger_cddl());
    let datum = datum_doc();
    let depth = crate::cbor::limits::cbor_nesting_depth_capped(&datum, usize::MAX);
    assert!(depth >= 20, "the fixture is the deep one: {} levels", depth);
    schema.assert_case("datum_doc", "datum", DATUM_DOC_HEX.as_str());
    schema.assert_case("payload_doc", "payload", &hex::encode(payload_doc()));
    schema.assert_case("record_doc", "record", RECORD_DOC_HEX.as_str());

    let deeper = depth * 13 / 10;
    // Constructor 0 around a list around the next: `d879 9f … ff`, two
    // levels a constructor.
    let constructors = deeper.div_ceil(2);
    let nested_constructors = "d8799f".repeat(constructors) + "05" + &"ff".repeat(constructors);
    schema.assert_case("nested constructors", "datum", &nested_constructors);
    let nested_maps = "a100".repeat(deeper) + "05";
    schema.assert_case("nested maps", "datum", &nested_maps);
    let nested_lists = "9f".repeat(deeper) + "05" + &"ff".repeat(deeper);
    schema.assert_case("nested lists", "datum", &nested_lists);
}

#[test]
fn mapping_the_full_record_stays_bounded() {
    // Trying alternatives is what makes the map agree with the decoder;
    // this is the tripwire for that search going combinatorial.
    let schema = Schema::new(ledger_cddl());
    let bytes = record_doc();
    let rows = schema.rows("record", &bytes);
    assert!(
        rows.len() < 2000,
        "position map emitted {} rows for one record",
        rows.len()
    );
    let distinct = map_path_set(&rows);
    assert!(
        distinct.len() > 100,
        "only {} distinct paths for a full record",
        distinct.len()
    );
}

/// One single-entry map per kind of CBOR key, plus maps whose keys
/// collide once stringified. The object-vs-`@entries` decision and the
/// field name a key projects onto have to be the same on both surfaces
/// or every path below the map diverges.
#[test]
fn map_keys_of_every_kind_agree_on_shape_and_labels() {
    let schema = Schema::new("m = { * any => any }");
    let cases = [
        ("definite_text", "a1616101"),
        ("indefinite_text", "a17f6161ff01"),
        ("definite_bytes", "a1410101"),
        ("indefinite_bytes", "a15f4101ff01"),
        ("uint", "a10101"),
        ("nint", "a12001"),
        ("bool", "a1f501"),
        ("null", "a1f601"),
        ("float", "a1f93c0001"),
        ("bignum_beyond_i64", "a1c2490100000000000000 0001"),
        ("array_key", "a181010 1"),
        ("tag_key", "a1c11901f401"),
        // Two distinct keys that stringify the same, and a repeated key:
        // both have to force the lossless `@entries` form.
        ("uint_and_text_collide", "a2010161310 2"),
        ("repeated_key", "a26161016161 02"),
        ("chunked_and_definite_collide", "a26161017f6161ff02"),
        ("bytes_and_hex_text_collide", "a2410101643078303102"),
    ];
    for (name, hex) in cases {
        schema.assert_case(name, "m", hex);
    }
}

/// Cross the corpus payloads with a spread of rule names, including
/// combinations where the data does not fit at all. Parity has to hold
/// for the raw fall-through shapes too, since a UI still shows them.
#[test]
fn parity_holds_for_mismatched_rule_and_payload_combinations() {
    let schema = Schema::new(ledger_cddl());
    let rules = [
        "record",
        "record_body",
        "entry",
        "value",
        "certificate",
        "native_script",
        "datum",
        "record_aux",
        "relay",
        "credential",
        "stock",
        "metadatum",
    ];
    let mut checked = 0usize;
    for (name, _, hex) in ledger_corpus() {
        for rule in rules {
            schema.assert_case(&format!("{}@{}", rule, name), rule, &hex);
            checked += 1;
        }
    }
    assert!(checked > 400, "only {} combinations checked", checked);
}

/// The map emits `@tag` / `@value` rows exactly when the decoder wraps
/// the value that way — the two must agree on which tags specialise
/// into a scalar and which do not.
#[test]
fn tag_wrapper_rows_agree_with_the_decoder() {
    let payloads = [
        ("text", "6131"),
        ("bytes", "43010203"),
        ("uint", "01"),
        ("array", "8101"),
    ];
    for tag in [0u64, 1, 2, 3, 24, 121, 258] {
        for (kind, payload) in payloads {
            let cddl = format!("x = #6.{}(any)", tag);
            let schema = Schema::new(&cddl);
            let head = if tag < 24 {
                format!("{:02x}", 0xc0 + tag)
            } else if tag < 256 {
                format!("d8{:02x}", tag)
            } else {
                format!("d9{:04x}", tag)
            };
            let hex = format!("{}{}", head, payload);
            let name = format!("tag{}/{}", tag, kind);
            schema.assert_case(&name, "x", &hex);

            let bytes = hex::decode(&hex).unwrap();
            let decoded = decode_against_ast(&schema.ast, &bytes, "x").unwrap();
            let decoder_wraps = decoded.get("@tag").is_some();
            let rows = schema.rows("x", &bytes);
            let map_wraps = rows
                .iter()
                .any(|r| r["decoded_path"] == Value::String(r#"$["@tag"]"#.into()));
            assert_eq!(
                decoder_wraps, map_wraps,
                "{}: decoder wraps={} but map wraps={}",
                name, decoder_wraps, map_wraps
            );
        }
    }
}

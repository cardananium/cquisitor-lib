//! Parity of the validator and the decoder over socket-heavy schemas.
//!
//! RFC 8610 Section 3.9: a name `/=` extends is the choice of its bodies
//! and a name `//=` extends the group choice of its bodies; a socket no
//! plug fills matches nothing. For each schema and document the decoder
//! reads the document strictly (every entry and item accounted for) exactly
//! when the validator admits it, and both resolve the same root.

#![cfg(test)]

use serde_json::{json, Value};

use crate::cbor::cbor_cddl_map::map_cbor_to_cddl;
use crate::cbor::schema_mapper::{decode_cbor_against_cddl, decode_fits_strictly};
use crate::cbor::validation::validate_cbor_bytes_against_cddl;

/// Schemas, each with the documents it is held to (hex, admitted).
pub(crate) fn corpus() -> Vec<(&'static str, &'static str, Vec<(&'static str, bool)>)> {
    vec![
        // Map keys typed by a type socket, under every occurrence indicator.
        (
            "start = {* $k => uint}\n$k /= 1\n$k /= 3\n",
            "start",
            vec![
                ("a0", true),
                ("a10307", true),
                ("a2010703 07", true),
                ("a10207", false),
                ("a1036178", false),
            ],
        ),
        (
            "start = {+ $k => uint}\n$k /= 1\n$k /= 3\n",
            "start",
            vec![("a0", false), ("a10307", true), ("a2010703 07", true)],
        ),
        (
            "start = {? $k => uint}\n$k /= 1\n$k /= 3\n",
            "start",
            vec![("a0", true), ("a10307", true), ("a2010703 07", false)],
        ),
        (
            "start = {$k => uint}\n$k /= 1\n$k /= 3\n",
            "start",
            vec![("a0", false), ("a10307", true), ("a10107", true)],
        ),
        // A socket nothing plugs matches no key.
        (
            "start = {* $k => uint}\n",
            "start",
            vec![("a0", true), ("a10107", false)],
        ),
        // A group socket nothing plugs matches no entry.
        ("start = {$$g}\n", "start", vec![("a0", false)]),
        (
            "start = {? $$g}\n",
            "start",
            vec![("a0", true), ("a1616107", false)],
        ),
        ("start = {* $$g}\n", "start", vec![("a0", true)]),
        // A plain name extended with `/=` as a key type.
        (
            "start = {* k => uint}\nk = 1\nk /= 3\n",
            "start",
            vec![("a10307", true), ("a2010703 07", true), ("a10207", false)],
        ),
        // `//=` whose first body is optional-only.
        (
            "start = {g}\ng = (? 1: uint)\ng //= (3: tstr)\n",
            "start",
            vec![
                ("a1036178", true),
                ("a10105", true),
                ("a0", true),
                ("a10305", false),
                ("a2010503 6178", false),
            ],
        ),
        // The same with the bodies the other way round.
        (
            "start = {g}\ng = (3: tstr)\ng //= (? 1: uint)\n",
            "start",
            vec![("a1036178", true), ("a10105", true), ("a0", true)],
        ),
        // Group sockets as map entries.
        (
            "start = {$$g}\n$$g //= (1: uint)\n$$g //= (3: tstr)\n",
            "start",
            vec![
                ("a1036178", true),
                ("a10105", true),
                ("a0", false),
                ("a2010503 6178", false),
            ],
        ),
        (
            "start = {* $$g}\n$$g //= (1: uint)\n$$g //= (3: tstr)\n",
            "start",
            vec![
                ("a0", true),
                ("a1036178", true),
                ("a2010503 6178", true),
                ("a10305", false),
            ],
        ),
        (
            "start = {* g}\ng = (a: uint)\ng //= (b: tstr)\n",
            "start",
            vec![("a2616107 61626178", true), ("a1616161 78", false)],
        ),
        // A group choice written out, and one named inside a larger map.
        (
            "start = {? a: uint // b: tstr}\n",
            "start",
            vec![
                ("a16162 6178", true),
                ("a1616107", true),
                ("a0", true),
                ("a2616107 61626178", false),
            ],
        ),
        (
            "start = {c: 1, g}\ng = (? a: uint // b: tstr)\n",
            "start",
            vec![
                ("a2616301 61626178", true),
                ("a1616301", true),
                ("a2616301 616107", true),
            ],
        ),
        // Sockets as values.
        (
            "start = {a: $v}\n$v /= uint\n$v /= tstr\n",
            "start",
            vec![
                ("a1616105", true),
                ("a16161 6178", true),
                ("a161614100", false),
            ],
        ),
        // Nested sockets.
        (
            "start = $v\n$v /= $w\n$v /= bstr\n$w /= uint\n$w /= tstr\n",
            "start",
            vec![("05", true), ("6178", true), ("4100", true), ("f6", false)],
        ),
        // `/=` on a plain name.
        (
            "start = x\nx = uint\nx /= tstr\n",
            "start",
            vec![("05", true), ("6178", true), ("4100", false)],
        ),
        // Sockets in arrays.
        (
            "start = [* $v]\n$v /= uint\n$v /= tstr\n",
            "start",
            vec![("80", true), ("820561 78", true), ("814100", false)],
        ),
        (
            "start = [$$g]\n$$g //= (uint)\n$$g //= (tstr, tstr)\n",
            "start",
            vec![("8105", true), ("8261786179", true), ("820561 78", false)],
        ),
        // Both sockets of one identifier; `m` roots at the type socket.
        (
            "$$m //= (1: uint)\n$m /= uint\n",
            "m",
            vec![("05", true), ("6178", false)],
        ),
        (
            "$$m //= (1: uint)\n$m /= uint\n",
            "$m",
            vec![("05", true), ("6178", false)],
        ),
        ("$m /= uint\n$$m //= (1: uint)\n", "m", vec![("05", true)]),
    ]
}

fn bytes(hex: &str) -> Vec<u8> {
    hex::decode(hex.replace(' ', "")).expect("test hex")
}

#[test]
fn the_decoder_reads_strictly_exactly_what_the_validator_admits() {
    let mut disagreements = Vec::new();
    for (schema, root, documents) in corpus() {
        for (hex, admitted) in documents {
            let cbor = bytes(hex);
            let verdict = validate_cbor_bytes_against_cddl(&cbor, schema, root);
            let valid = verdict["valid"] == json!(true);
            let fits = decode_fits_strictly(&cbor, schema, root)
                .unwrap_or_else(|e| panic!("{:?} {} {}: decode refused: {}", schema, root, hex, e));
            if valid != admitted || fits != admitted {
                disagreements.push(format!(
                    "{:?} root {} data {}: expected {}, validate {} ({}), decode strict {}",
                    schema, root, hex, admitted, valid, verdict, fits
                ));
            }
        }
    }
    assert!(disagreements.is_empty(), "{}", disagreements.join("\n"));
}

#[test]
fn an_admitted_document_decodes_without_leftovers() {
    fn leftovers(v: &Value) -> bool {
        match v {
            Value::Object(o) => o
                .iter()
                .any(|(k, v)| k == "@extra" || k == "@positional" || leftovers(v)),
            Value::Array(a) => a.iter().any(leftovers),
            _ => false,
        }
    }
    for (schema, root, documents) in corpus() {
        for (hex, admitted) in documents {
            if !admitted {
                continue;
            }
            let decoded = decode_cbor_against_cddl(&bytes(hex), schema, root)
                .unwrap_or_else(|e| panic!("{:?} {}: {}", schema, hex, e));
            assert!(!leftovers(&decoded), "{:?} {}: {}", schema, hex, decoded);
        }
    }
}

#[test]
fn every_export_roots_a_socket_identifier_alike() {
    let schema = "$$m //= (1: uint)\n$m /= uint\n";
    for root in ["m", "$m"] {
        assert_eq!(
            validate_cbor_bytes_against_cddl(&bytes("05"), schema, root),
            json!({"valid": true}),
            "{}",
            root
        );
        assert_eq!(
            decode_cbor_against_cddl(&bytes("05"), schema, root).unwrap(),
            json!(5)
        );
        let map = map_cbor_to_cddl(&bytes("05"), schema, root).unwrap();
        assert_eq!(map["entries"][0]["rule_name"], json!("$m"), "{}", map);
    }

    // A group socket is never a root, named with its prefix or reached
    // through an identifier that has no type socket.
    for (schema, root) in [(schema, "$$m"), ("$$g //= (1: uint)\n", "g")] {
        let verdict = validate_cbor_bytes_against_cddl(&bytes("05"), schema, root);
        assert_eq!(
            verdict["error"]["kind"],
            json!("group_rule_root"),
            "{}",
            verdict
        );
        let decoded = decode_cbor_against_cddl(&bytes("05"), schema, root).unwrap_err();
        assert_eq!(decoded.into_object()["kind"], json!("group_rule_root"));
        let mapped = map_cbor_to_cddl(&bytes("05"), schema, root).unwrap_err();
        assert_eq!(mapped.into_object()["kind"], json!("group_rule_root"));
    }
}

#[test]
fn an_unplugged_group_socket_in_a_map_is_a_mismatch() {
    let verdict = validate_cbor_bytes_against_cddl(&bytes("a0"), "start = {$$g}\n", "start");
    assert_eq!(verdict["error"]["kind"], json!("mismatch"), "{}", verdict);
    assert!(
        verdict["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("$$g"),
        "{}",
        verdict
    );
}

//! Stack-budget checks for every walker at its deepest admitted input.
//!
//! [`super::limits`] assumes walks spend no stack on document nesting
//! (heap containers / driver tasks). Counts cannot verify that, and a
//! stack overflow aborts the process — so each probe runs in a child
//! of this binary, one stack size at a time. Wrong answers vs exhaustion
//! are distinguished by how the child exits.
//!
//! Heap walkers: deepest input must fit on roughly the same stack as a
//! leaf; four document walkers must reach 10_000 levels on a small
//! stack. The recursive CDDL parser/serialiser is held to [`STACK_BUDGET`]
//! (a profile-dependent multiple of [`RUNTIME_STACK`]). Every walk also
//! checks its answer, not just survival.

#![cfg(test)]

use std::process::{Command, Stdio};

use serde_json::Value;

use super::limits::{
    MAX_CBOR_DECODE_NESTING_DEPTH, MAX_CBOR_NESTING_DEPTH, MAX_CBOR_VALIDATION_NESTING_DEPTH,
    MAX_CDDL_NESTING_DEPTH, MAX_EMBEDDED_DEPTH, MAX_PALLAS_NESTING_DEPTH,
    MAX_CSL_NESTING_DEPTH, MAX_TYPED_DECODER_NESTING_DEPTH,
};

/// Max rule-reference chain per data item (`cddl` default, unchanged here).
const MAX_RULE_NESTING: usize = cddl::validator::DEFAULT_MAX_RULE_NESTING;
use super::{cbor_cddl_map, cddl_tools, decoder, schema_mapper, validation};
use crate::deep_json::DeepJson;

/// The shadow stack the `wasm32` build links with: wasm-ld's default,
/// which nothing in the build enlarges. Every document walker keeps its
/// nesting on the heap, the schema parser is held to a few bracket levels
/// by its own bound, and the typed decoders' bound is measured against the
/// host's stack, not this one — so the default is enough, and
/// `check-wasm-stack.mjs` reads the size back out of the artifact to make
/// sure it stays that.
const RUNTIME_STACK: usize = 1024 * 1024;

/// Budget for the recursive CDDL parser/serialiser as a multiple of
/// [`RUNTIME_STACK`]. Per-level cost varies widely with opt level, so
/// native tests cannot be held to the runtime stack itself; heap-based
/// document walkers are checked for "nesting costs no stack" instead.
#[cfg(debug_assertions)]
const STACK_BUDGET: usize = 16 * RUNTIME_STACK;
#[cfg(not(debug_assertions))]
const STACK_BUDGET: usize = 2 * RUNTIME_STACK;

/// Env var naming the probe: `<walk>@<bytes>`.
const PROBE_SPEC: &str = "CQUISITOR_CBOR_STACK_PROBE";

/// Libtest name of [`stack_probe`].
const PROBE_TEST: &str = "cbor::stack_calibration::stack_probe";

/// Printed when a probe child finishes its walk (vs ran nothing).
const PROBE_WALKED: &str = "the probe walked";

const DECODER: &str = "decoder";
const DECODER_LEAF: &str = "decoder_leaf";
const DECODER_DEEP: &str = "decoder_deep";
const SCHEMA_WALKER: &str = "schema_walker";
const SCHEMA_WALKER_LEAF: &str = "schema_walker_leaf";
const SCHEMA_WALKER_DEEP: &str = "schema_walker_deep";
const POSITION_MAP: &str = "position_map";
const POSITION_MAP_LEAF: &str = "position_map_leaf";
const POSITION_MAP_DEEP: &str = "position_map_deep";
const TEN_THOUSAND: &str = "ten_thousand";
const VALIDATOR: &str = "validator";
const VALIDATOR_LEAF: &str = "validator_leaf";
const VALIDATOR_DEEP: &str = "validator_deep";
const EMBEDDED_CHAIN: &str = "embedded_chain";
const VALIDATOR_EMBEDDED_CHAIN: &str = "validator_embedded_chain";
const CDDL_PARSER: &str = "cddl_parser";
const TYPED_DECODER: &str = "typed_decoder";
const PALLAS: &str = "pallas";
const NATIVE_SCRIPTS: &str = "native_scripts";
const NATIVE_SCRIPTS_LEAF: &str = "native_scripts_leaf";
const NATIVE_SCRIPTS_DEEP: &str = "native_scripts_deep";
const REFUSAL: &str = "refusal";

/// `levels` nested single-element arrays around `5`.
fn nested_arrays_hex(levels: usize) -> String {
    let mut s = "81".repeat(levels);
    s.push_str("05");
    s
}

/// `levels` nested single-entry maps around `5` (key `0`).
///
/// Costly validator shape: key matched before value.
fn nested_maps_hex(levels: usize) -> String {
    let mut s = "a100".repeat(levels);
    s.push_str("05");
    s
}

/// `levels` nested four-item arrays around `5` (three leaf items each).
///
/// Costly validator shape: group walked once per item.
fn nested_multi_item_arrays_hex(levels: usize) -> String {
    let mut s = "84010203".repeat(levels);
    s.push_str("05");
    s
}

/// `levels` nested single-element arrays around an empty array.
///
/// Leaf shape for chained-alias schemas (array recursion, not type choice).
fn nested_empty_arrays_hex(levels: usize) -> String {
    let mut s = "81".repeat(levels);
    s.push_str("80");
    s
}

/// Schema with `hops` chained rule refs at every data level.
///
/// Descent-budget shape: ref chain resets per level, so cost is chain × depth.
fn chained_alias_schema(hops: usize) -> String {
    let mut schema = String::from("x = [* r0]\n");
    for alias in 0..hops - 1 {
        schema.push_str(&format!("r{} = r{}\n", alias, alias + 1));
    }
    schema.push_str(&format!("r{} = x\n", hops - 1));
    schema
}

/// Definite-length byte string carrying `payload`.
fn bstr_hex(payload: &str) -> String {
    let len = payload.len() / 2;
    if len < 0x1_0000 {
        format!("59{:04x}{}", len, payload)
    } else {
        format!("5a{:08x}{}", len, payload)
    }
}

/// Schema for `documents` chained via nesting or `.cbor` payloads.
fn embedded_chain_schema(documents: usize) -> String {
    let mut schema = String::new();
    for i in 0..documents - 1 {
        schema.push_str(&format!("a{} = [* a{}] / (bstr .cbor a{})\n", i, i, i + 1));
    }
    schema.push_str(&format!(
        "a{} = [* a{}] / uint\n",
        documents - 1,
        documents - 1
    ));
    schema
}

/// `documents` chained via `.cbor`, each with `per_document` array levels.
fn embedded_chain_hex(documents: usize, per_document: usize) -> String {
    let mut hex_bytes = nested_arrays_hex(per_document);
    for _ in 0..documents - 1 {
        hex_bytes = format!("{}{}", "81".repeat(per_document), bstr_hex(&hex_bytes));
    }
    hex_bytes
}

/// Follow `levels` of single-element arrays down to the `5`.
fn assert_descends(value: &Value, levels: usize) {
    let mut cursor = value;
    for level in 0..levels {
        cursor = &cursor
            .as_array()
            .unwrap_or_else(|| panic!("lost nesting at level {} of {}", level, levels))[0];
    }
    assert_eq!(cursor, &Value::from(5));
}

/// Follow `levels` of single-element arrays down (any leaf).
fn assert_nests(value: &Value, levels: usize) {
    let mut cursor = value;
    for level in 0..levels {
        cursor = &cursor
            .as_array()
            .unwrap_or_else(|| panic!("lost nesting at level {} of {}", level, levels))[0];
    }
}

/// Assert position map has a row for the item `levels` arrays deep.
fn assert_has_row_for(mapping: &Value, levels: usize) {
    let deepest = "$".to_string() + &"[0]".repeat(levels);
    assert!(
        cbor_cddl_map::has_path(mapping, "cbor_paths", &deepest),
        "no row for the deepest item"
    );
}

/// Assert position map has a row for `levels` labelled `.a` fields deep.
fn assert_has_labelled_row_for(mapping: &Value, levels: usize) {
    let deepest = "$".to_string() + &".a".repeat(levels);
    assert!(
        cbor_cddl_map::has_path(mapping, "decoded_paths", &deepest),
        "no row for the deepest labelled item"
    );
}

/// Follow `levels` of labelled `a` fields down to the `5`.
fn assert_descends_labelled(value: &Value, levels: usize) {
    let mut cursor = value;
    for level in 0..levels {
        cursor = cursor
            .get("a")
            .unwrap_or_else(|| panic!("level {} of {} is not labelled", level, levels));
    }
    assert_eq!(cursor, &Value::from(5));
}

/// Wrap in [`DeepJson`] so deep trees free without recursion.
fn deep(value: Value) -> DeepJson {
    DeepJson::new(value)
}

/// Deepest level ≤ `bound` that `admits` still accepts (bisection).
fn deepest_admitted_below(bound: usize, admits: impl Fn(usize) -> bool) -> usize {
    assert!(admits(1), "the bounds admit at least one level");
    let (mut admitted, mut refused) = (1, bound + 1);
    while refused - admitted > 1 {
        let mid = admitted + (refused - admitted) / 2;
        if admits(mid) {
            admitted = mid;
        } else {
            refused = mid;
        }
    }
    admitted
}

/// Validator path for the item `levels` single-element arrays deep.
fn deepest_path(levels: usize) -> String {
    "$".to_string() + &"[0]".repeat(levels)
}

/// Serialize as exports do (boundary cost included in the probe).
fn render(value: &Value) -> usize {
    crate::deep_json::write_json(value).len()
}

/// Drive one walker to its bound and check the answer.
fn walk(name: &str) {
    match name {
        // Heap walk + render/free: no frame per level.
        DECODER => {
            let bytes = hex::decode(nested_arrays_hex(MAX_CBOR_DECODE_NESTING_DEPTH)).unwrap();
            let tree = decoder::decode_cbor_to_value(&bytes).expect("decodes at the bound");
            // Positional tree nests by `values`, not bare arrays.
            let mut cursor: &Value = &tree;
            for level in 0..MAX_CBOR_DECODE_NESTING_DEPTH {
                cursor = &cursor
                    .get("values")
                    .and_then(Value::as_array)
                    .unwrap_or_else(|| panic!("lost nesting at level {}", level))[0];
            }
            assert_eq!(cursor["value"], Value::from(5));
            assert!(render(&tree) > 0);
        }

        // Decoder alone (no render): leaf and deepest bound input.
        DECODER_LEAF => {
            let tree = decoder::decode_cbor_to_value(&[0x05]).expect("decodes a leaf");
            assert_eq!(tree["value"], Value::from(5));
        }
        DECODER_DEEP => {
            let bytes = hex::decode(nested_arrays_hex(MAX_CBOR_DECODE_NESTING_DEPTH)).unwrap();
            let tree = decoder::decode_cbor_to_value(&bytes).expect("decodes at the bound");
            let mut cursor: &Value = &tree;
            for level in 0..MAX_CBOR_DECODE_NESTING_DEPTH {
                cursor = &cursor
                    .get("values")
                    .and_then(Value::as_array)
                    .unwrap_or_else(|| panic!("lost nesting at level {}", level))[0];
            }
            assert_eq!(cursor["value"], Value::from(5));
        }

        // Heap walkers: level-bound recursive shape, plus bisection of
        // the descent-budget (chained-alias) shape.
        SCHEMA_WALKER => {
            let levels = MAX_CBOR_NESTING_DEPTH;
            let bytes = hex::decode(nested_arrays_hex(levels)).unwrap();
            let out = deep(
                schema_mapper::decode_cbor_against_cddl(&bytes, "x = [* x] / uint", "x")
                    .expect("maps at the bound"),
            );
            assert_descends(&out, levels);
            assert!(render(&out) > 0);

            let schema = chained_alias_schema(MAX_RULE_NESTING - 1);
            let deepest = deepest_admitted_below(MAX_CBOR_NESTING_DEPTH / 8, |levels| {
                let bytes = hex::decode(nested_empty_arrays_hex(levels)).unwrap();
                schema_mapper::decode_cbor_against_cddl(&bytes, &schema, "x")
                    .map(deep)
                    .is_ok()
            });
            assert!(
                deepest > 256 && deepest < MAX_CBOR_NESTING_DEPTH / 8,
                "aliases: deepest {}",
                deepest
            );
            let bytes = hex::decode(nested_empty_arrays_hex(deepest)).unwrap();
            let out = deep(
                schema_mapper::decode_cbor_against_cddl(&bytes, &schema, "x")
                    .expect("maps at the bound"),
            );
            assert_nests(&out, deepest);
            assert!(render(&out) > 0);
        }

        // Schema walker alone: leaf and deepest level-bound input.
        SCHEMA_WALKER_LEAF => {
            let out = schema_mapper::decode_cbor_against_cddl(&[0x05], "x = [* x] / uint", "x")
                .expect("maps a leaf");
            assert_eq!(out, Value::from(5));
        }
        SCHEMA_WALKER_DEEP => {
            let levels = MAX_CBOR_NESTING_DEPTH;
            let bytes = hex::decode(nested_arrays_hex(levels)).unwrap();
            let out = deep(
                schema_mapper::decode_cbor_against_cddl(&bytes, "x = [* x] / uint", "x")
                    .expect("maps at the bound"),
            );
            assert_descends(&out, levels);
        }

        POSITION_MAP => {
            let levels = MAX_CBOR_NESTING_DEPTH;
            let bytes = hex::decode(nested_arrays_hex(levels)).unwrap();
            let out = deep(
                cbor_cddl_map::map_cbor_to_cddl(&bytes, "x = [* x] / uint", "x")
                    .expect("maps at the bound"),
            );
            assert_has_row_for(&out, levels);
            assert!(render(&out) > 0);

            let schema = chained_alias_schema(MAX_RULE_NESTING - 1);
            let deepest = deepest_admitted_below(MAX_CBOR_NESTING_DEPTH / 8, |levels| {
                let bytes = hex::decode(nested_empty_arrays_hex(levels)).unwrap();
                cbor_cddl_map::map_cbor_to_cddl(&bytes, &schema, "x")
                    .map(deep)
                    .is_ok()
            });
            assert!(
                deepest > 256 && deepest < MAX_CBOR_NESTING_DEPTH / 8,
                "aliases: deepest {}",
                deepest
            );
            let bytes = hex::decode(nested_empty_arrays_hex(deepest)).unwrap();
            let out = deep(
                cbor_cddl_map::map_cbor_to_cddl(&bytes, &schema, "x").expect("maps at the bound"),
            );
            assert_has_row_for(&out, deepest);
            assert!(render(&out) > 0);
        }

        // Position map alone: leaf and deepest level-bound input.
        POSITION_MAP_LEAF => {
            let out = cbor_cddl_map::map_cbor_to_cddl(&[0x05], "x = [* x] / uint", "x")
                .expect("maps a leaf");
            assert_has_row_for(&out, 0);
        }
        POSITION_MAP_DEEP => {
            let levels = MAX_CBOR_NESTING_DEPTH;
            let bytes = hex::decode(nested_arrays_hex(levels)).unwrap();
            let out = deep(
                cbor_cddl_map::map_cbor_to_cddl(&bytes, "x = [* x] / uint", "x")
                    .expect("maps at the bound"),
            );
            assert_has_row_for(&out, levels);
        }

        // Four walkers at 10_000 levels: decode/render, label, map rows,
        // and validator mismatch path/span.
        TEN_THOUSAND => {
            let levels = 10_000;
            let bytes = hex::decode(nested_arrays_hex(levels)).unwrap();

            let tree = decoder::decode_cbor_to_value(&bytes).expect("decodes");
            let mut cursor: &Value = &tree;
            for level in 0..levels {
                cursor = &cursor
                    .get("values")
                    .and_then(Value::as_array)
                    .unwrap_or_else(|| panic!("lost nesting at level {}", level))[0];
            }
            assert_eq!(cursor["value"], Value::from(5));
            assert!(render(&tree) > 0);
            drop(tree);

            let schema = "x = [a: x] / uint";
            let out =
                deep(schema_mapper::decode_cbor_against_cddl(&bytes, schema, "x").expect("maps"));
            assert_descends_labelled(&out, levels);
            assert!(render(&out) > 0);
            drop(out);

            let out = deep(cbor_cddl_map::map_cbor_to_cddl(&bytes, schema, "x").expect("maps"));
            assert_has_labelled_row_for(&out, levels);
            assert!(render(&out) > 0);
            drop(out);

            let out = validation::validate_cbor_bytes_against_cddl(&bytes, schema, "x");
            assert_eq!(out["valid"], Value::Bool(true), "{}", out);
            let mut bytes = bytes;
            *bytes.last_mut().unwrap() = 0x60;
            let out = validation::validate_cbor_bytes_against_cddl(&bytes, schema, "x");
            assert_eq!(
                out["error"]["kind"],
                Value::from("mismatch"),
                "{}",
                out["error"]["kind"]
            );
            assert_eq!(out["error"]["path"], Value::from(deepest_path(levels)));
            let span = &out["error"]["cddl_byte_span"];
            let offset = span["offset"].as_u64().expect("a schema span") as usize;
            let length = span["length"].as_u64().expect("a schema span") as usize;
            assert_eq!(&schema[offset..offset + length], "x");
        }

        // Validator heap walk: level-bound shapes (incl. the real-sized
        // ledger schema) and bisection of the chained-alias
        // descent-budget shape.
        VALIDATOR => {
            let ledger = super::test_fixtures::ledger_cddl();
            let deepest_validating = |schema: &str, rule: &str, shape: &dyn Fn(usize) -> String| {
                deepest_admitted_below(MAX_CBOR_VALIDATION_NESTING_DEPTH, |levels| {
                    let bytes = hex::decode(shape(levels)).unwrap();
                    validation::validate_cbor_bytes_against_cddl(&bytes, schema, rule)["valid"]
                        == Value::Bool(true)
                })
            };
            for (schema, rule, shape) in [
                (
                    "x = [* x] / uint",
                    "x",
                    &nested_arrays_hex as &dyn Fn(usize) -> String,
                ),
                ("x = {* uint => x} / uint", "x", &nested_maps_hex),
                (
                    "x = [* (uint, uint, uint, x)] / uint",
                    "x",
                    &nested_multi_item_arrays_hex,
                ),
                (ledger, "datum", &nested_maps_hex),
                (ledger, "datum", &nested_multi_item_arrays_hex),
            ] {
                let deepest = deepest_validating(schema, rule, shape);
                // The level bound answers for every shape. Measured for
                // `datum` too: its constructor alternatives are charged
                // per level, yet nested maps and four-item arrays both
                // reach the level bound before the descent budget.
                assert_eq!(
                    deepest, MAX_CBOR_VALIDATION_NESTING_DEPTH,
                    "{}: deepest {}",
                    rule, deepest
                );
            }

            // Chained aliases: descent budget answers inside the level bound.
            let schema = chained_alias_schema(MAX_RULE_NESTING - 1);
            let deepest = deepest_validating(&schema, "x", &nested_empty_arrays_hex);
            assert!(
                deepest > 16 && deepest < MAX_CBOR_VALIDATION_NESTING_DEPTH / 8,
                "aliases: deepest {}",
                deepest
            );
        }

        // Validator alone: leaf accept/refuse and deepest level-bound input.
        VALIDATOR_LEAF => {
            let out =
                validation::validate_cbor_bytes_against_cddl(&[0x05], "x = [* x] / uint", "x");
            assert_eq!(out["valid"], Value::Bool(true), "{}", out);
            let out =
                validation::validate_cbor_bytes_against_cddl(&[0x60], "x = [* x] / uint", "x");
            assert_eq!(out["error"]["kind"], Value::from("mismatch"), "{}", out);
            assert_eq!(out["error"]["path"], Value::from("$"), "{}", out);
        }
        VALIDATOR_DEEP => {
            let levels = MAX_CBOR_VALIDATION_NESTING_DEPTH;
            let bytes = hex::decode(nested_arrays_hex(levels)).unwrap();
            let out = validation::validate_cbor_bytes_against_cddl(&bytes, "x = [* x] / uint", "x");
            assert_eq!(out["valid"], Value::Bool(true), "{}", out);
            let mut bytes = hex::decode(nested_arrays_hex(levels)).unwrap();
            *bytes.last_mut().unwrap() = 0x60;
            let out = validation::validate_cbor_bytes_against_cddl(&bytes, "x = [* x] / uint", "x");
            assert_eq!(
                out["error"]["kind"],
                Value::from("mismatch"),
                "{}",
                out["error"]["kind"]
            );
            assert_eq!(out["error"]["path"], Value::from(deepest_path(levels)));
        }

        // Longest embedded `.cbor` chain: shared level budget across docs.
        EMBEDDED_CHAIN => {
            // Root plus every payload that may be open inside it.
            let documents = MAX_EMBEDDED_DEPTH + 1;
            let schema = embedded_chain_schema(documents);
            let per_document = MAX_CBOR_NESTING_DEPTH / documents;
            let total = per_document * documents;
            assert!(per_document > 1 && total <= MAX_CBOR_NESTING_DEPTH);

            let bytes = hex::decode(embedded_chain_hex(documents, per_document)).unwrap();
            let out = deep(
                schema_mapper::decode_cbor_against_cddl(&bytes, &schema, "a0")
                    .expect("maps the whole chain"),
            );
            assert_descends(&out, total);
            assert!(render(&out) > 0);
            drop(out);

            let out = deep(
                cbor_cddl_map::map_cbor_to_cddl(&bytes, &schema, "a0")
                    .expect("maps the whole chain"),
            );
            assert_has_row_for(&out, total);
            assert!(render(&out) > 0);
            drop(out);

            // Bound is tight: one more level per document is refused.
            let bytes = hex::decode(embedded_chain_hex(documents, per_document + 1)).unwrap();
            for refusal in [
                schema_mapper::decode_cbor_against_cddl(&bytes, &schema, "a0"),
                cbor_cddl_map::map_cbor_to_cddl(&bytes, &schema, "a0"),
            ] {
                let message = refusal.err().expect("the mappers refuse").to_string();
                assert!(
                    message.contains("nesting"),
                    "unexpected message: {}",
                    message
                );
            }
        }

        // Same embedded chain through the validator (shared level bound
        // + open-payload bound).
        VALIDATOR_EMBEDDED_CHAIN => {
            let documents = MAX_EMBEDDED_DEPTH + 1;
            let schema = embedded_chain_schema(documents);
            let validate = |per_document: usize| {
                let bytes = hex::decode(embedded_chain_hex(documents, per_document)).unwrap();
                validation::validate_cbor_bytes_against_cddl(&bytes, &schema, "a0")
            };
            // Entering a payload costs a level; remaining bound is split
            // across documents.
            let per_document = (MAX_CBOR_VALIDATION_NESTING_DEPTH - (documents - 1)) / documents;
            let total = per_document * documents + documents - 1;
            assert!(per_document > 1 && total <= MAX_CBOR_VALIDATION_NESTING_DEPTH);

            // Accept ⇒ whole chain walked (unentered `.cbor` would fail).
            let out = validate(per_document);
            assert_eq!(out["valid"], Value::Bool(true), "{}", out);

            // Bound is tight: one more level per document is refused.
            let out = validate(per_document + 1);
            assert_eq!(
                out["error"]["kind"],
                Value::from("nesting_too_deep"),
                "{}",
                out
            );

            // Shared chain bound (not per-payload): each doc alone would
            // fit, but together they exhaust it.
            let per_payload = MAX_CBOR_VALIDATION_NESTING_DEPTH / 2;
            let bytes = hex::decode(embedded_chain_hex(documents, per_payload)).unwrap();
            // Pre-walk scan admits these bytes; the walk must refuse.
            assert!(super::limits::NestingBudget::for_document(&bytes).is_some());
            let out = validation::validate_cbor_bytes_against_cddl(&bytes, &schema, "a0");
            assert_eq!(
                out["error"]["kind"],
                Value::from("nesting_too_deep"),
                "{}",
                out
            );

            // Each open payload holds a driver frame: too many shallow
            // payloads are refused even when nesting is tiny.
            let schema = embedded_chain_schema(documents + 1);
            let bytes = hex::decode(embedded_chain_hex(documents + 1, 1)).unwrap();
            let out = validation::validate_cbor_bytes_against_cddl(&bytes, &schema, "a0");
            assert_eq!(
                out["error"]["kind"],
                Value::from("nesting_too_deep"),
                "{}",
                out
            );
            assert!(
                out["error"]["message"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("open payloads"),
                "{}",
                out
            );
        }

        CDDL_PARSER => {
            let mut src = String::from("x = ");
            src.push_str(&"[".repeat(MAX_CDDL_NESTING_DEPTH));
            src.push_str("uint");
            src.push_str(&"]".repeat(MAX_CDDL_NESTING_DEPTH));

            let out = validation::validate_cddl_text(&src);
            assert_eq!(out["valid"], Value::Bool(true), "{}", out);

            let formatted = cddl_tools::format(&src).expect("formats at the bound");
            assert_eq!(
                formatted.matches('[').count(),
                MAX_CDDL_NESTING_DEPTH,
                "the serialiser rendered every level"
            );
        }

        // Past-bound input refused before the walk (cheap stack).
        REFUSAL => {
            // Far past the bound so an unguarded walker would overflow hard.
            let bytes = hex::decode(nested_arrays_hex(MAX_CBOR_DECODE_NESTING_DEPTH + 20_000)).unwrap();

            let err = decoder::decode_cbor_to_value(&bytes)
                .err()
                .expect("the decoder refuses");
            assert_eq!(err.kind, super::errors::ErrorKind::NestingTooDeep);

            for refusal in [
                schema_mapper::decode_cbor_against_cddl(&bytes, "x = [* x] / uint", "x"),
                cbor_cddl_map::map_cbor_to_cddl(&bytes, "x = [* x] / uint", "x"),
            ] {
                let message = refusal.err().expect("the mappers refuse").to_string();
                assert!(
                    message.contains("nesting"),
                    "unexpected message: {}",
                    message
                );
            }

            let out = validation::validate_cbor_bytes_against_cddl(&bytes, "x = [* x] / uint", "x");
            assert_eq!(
                out["error"]["kind"],
                Value::from("nesting_too_deep"),
                "{}",
                out
            );

            // Schema brackets past the parser nesting limit.
            let mut src = String::from("x = ");
            src.push_str(&"[".repeat(MAX_CDDL_NESTING_DEPTH + 1));
            src.push_str("uint");
            src.push_str(&"]".repeat(MAX_CDDL_NESTING_DEPTH + 1));
            let out = validation::validate_cddl_text(&src);
            assert_eq!(
                out["error"]["kind"],
                Value::from("nesting_too_deep"),
                "{}",
                out
            );
        }

        // The typed decoders recurse on the stack, one frame per level, so
        // this is the one data walk that has a per-level cost to hold
        // within a budget: the deepest document the pre-scan admits, as an
        // array chain and as a map chain, through the decoders that follow
        // nesting.
        TYPED_DECODER => {
            use crate::csl_decoders::universal_decoder::decode_specific_type;
            use crate::js_value::JsValue;
            let params = || JsValue::new("{}");
            let arrays = nested_arrays_hex(MAX_TYPED_DECODER_NESTING_DEPTH);
            let maps = nested_maps_hex(MAX_TYPED_DECODER_NESTING_DEPTH);
            for (name, doc) in [
                ("TransactionMetadatum", &arrays),
                ("TransactionMetadatum", &maps),
                ("PlutusData", &arrays),
                ("PlutusData", &maps),
            ] {
                decode_specific_type(doc, name, params())
                    .unwrap_or_else(|e| panic!("{} at the bound: {}", name, e));
            }
            // The serialization library without rendering, at its own
            // bound: a transaction whose witness datum brings it there.
            let datum_depth = MAX_CSL_NESTING_DEPTH - 3;
            for datum in [nested_arrays_hex(datum_depth), nested_maps_hex(datum_depth)] {
                let tx_hex = format!("84a3008001800200a10481{datum}f5f6");
                crate::hash_extractor::extract_hashes_from_transaction(&tx_hex)
                    .unwrap_or_else(|e| panic!("a transaction at the CSL bound: {}", e));
            }
        }

        // pallas' recursive decoders, as the exports that read with pallas
        // alone reach them: a transaction whose witness datum brings it to
        // the bound (array, witness set map, datum list: three levels
        // above), as a list chain and as a map chain, and a validation
        // context's inline datum at the bound.
        PALLAS => {
            use crate::plutus::execute_tx_scripts::get_utxo_list_from_tx;
            let datum_depth = MAX_PALLAS_NESTING_DEPTH - 3;
            for datum in [nested_arrays_hex(datum_depth), nested_maps_hex(datum_depth)] {
                let tx_hex = format!("84a3008001800200a10481{datum}f5f6");
                get_utxo_list_from_tx(&tx_hex)
                    .unwrap_or_else(|e| panic!("a transaction at the pallas bound: {}", e));
            }
            let mut utxo: crate::common::UTxO = serde_json::from_str(
                crate::validators::tests::fixtures::PREVIEW_SIMPLE_INPUT_UTXO,
            )
            .expect("the fixture UTxO reads");
            for datum in [
                nested_arrays_hex(MAX_PALLAS_NESTING_DEPTH),
                nested_maps_hex(MAX_PALLAS_NESTING_DEPTH),
            ] {
                utxo.output.plutus_data = Some(datum);
                crate::plutus::data_mapper::to_pallas_utxos(std::slice::from_ref(&utxo))
                    .unwrap_or_else(|e| panic!("a context datum at the pallas bound: {}", e));
            }
        }

        // Native scripts are exempt from the typed, CSL and pallas bounds:
        // every entry point reads them without recursion. The deepest a
        // transaction's script reference admits under the walkers' bound
        // (the payload's `[0, script]` sits five levels down; a script
        // level is two CBOR levels), through every entry point.
        NATIVE_SCRIPTS => {
            let levels = (MAX_CBOR_NESTING_DEPTH - 8) / 2;
            crate::validators::tests::deep_native_script_tests::every_entry_point(levels);
        }
        NATIVE_SCRIPTS_LEAF => {
            crate::validators::tests::deep_native_script_tests::every_entry_point(1);
        }
        NATIVE_SCRIPTS_DEEP => {
            crate::validators::tests::deep_native_script_tests::every_entry_point(3000);
        }

        other => panic!("no walk named {}", other),
    }
}

/// Probe entry: walk named by [`PROBE_SPEC`] on the named stack.
///
/// Ignored; calibration re-executes this binary per stack size so
/// exhaustion kills the child, not the suite. No-op without the env var.
#[test]
#[ignore = "an entry point the calibration tests drive, not a check of its own"]
fn stack_probe() {
    let spec = match std::env::var(PROBE_SPEC) {
        Ok(spec) => spec,
        Err(_) => return,
    };
    let (name, stack) = spec
        .split_once('@')
        .expect("a probe spec reads <walk>@<stack bytes>");
    let stack: usize = stack.parse().expect("a probe stack size is a byte count");
    let name = name.to_string();

    std::thread::Builder::new()
        .stack_size(stack)
        .spawn(move || walk(&name))
        .expect("failed to spawn the probe thread")
        .join()
        .expect("the walk did not hold");

    println!("{}", PROBE_WALKED);
}

/// Outcome of one walk on one stack.
enum Probe {
    /// Returned; all checks held.
    Walked,
    /// Ran but a check failed.
    Failed(String),
    /// Exhausted the given stack.
    Exhausted,
}

/// Run `name` on `stack` bytes in a child of this binary.
fn probe(name: &str, stack: usize) -> Probe {
    let output = Command::new(std::env::current_exe().expect("the test binary's own path"))
        .args([
            "--exact",
            PROBE_TEST,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(PROBE_SPEC, format!("{}@{}", name, stack))
        .stdin(Stdio::null())
        .output()
        .expect("failed to run a probe child");

    let stdout = String::from_utf8_lossy(&output.stdout);
    if output.status.success() {
        assert!(
            stdout.contains(PROBE_WALKED),
            "the probe child ran no walk at all:\n{}",
            stdout
        );
        return Probe::Walked;
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Stack overflow aborts the process (signal, not exit code).
    if output.status.code().is_none() || stderr.contains("stack overflow") {
        return Probe::Exhausted;
    }

    Probe::Failed(format!("{}{}", stdout, stderr))
}

/// Smallest stack `name` survives on (≤1/16 resolution), searching up
/// from `exhausted`. `None` if it never returns by 64× that size.
fn smallest_surviving_stack_above(name: &str, exhausted: usize) -> Option<usize> {
    let ceiling = exhausted.saturating_mul(64);
    let mut lo = exhausted;
    let mut hi = exhausted.saturating_mul(2);

    while !matches!(probe(name, hi), Probe::Walked) {
        if hi >= ceiling {
            return None;
        }
        lo = hi;
        hi = hi.saturating_mul(2).min(ceiling);
    }

    while hi - lo > hi / 16 {
        let mid = lo + (hi - lo) / 2;
        if matches!(probe(name, mid), Probe::Walked) {
            hi = mid;
        } else {
            lo = mid;
        }
    }

    Some(hi)
}

/// Require `name` to return on `budget` bytes; on exhaustion, measure
/// and report the stack it would have needed.
fn fits(name: &str, budget: usize) {
    match probe(name, budget) {
        Probe::Walked => {}
        Probe::Failed(output) => panic!("the {} walk did not hold at its bound:\n{}", name, output),
        Probe::Exhausted => {
            let needed = smallest_surviving_stack_above(name, budget);
            panic!(
                "the {} walk exhausts {} bytes of stack at its bound, and returns on {}. \
                 That budget is {} times the {} byte stack the runtime gives a thread: \
                 either a level costs more on this build profile than the budget was \
                 measured against, or the walk costs more per level than it did.",
                name,
                budget,
                needed.map_or_else(
                    || format!("no stack up to {} bytes", budget.saturating_mul(64)),
                    |n| format!("{} bytes", n)
                ),
                budget / RUNTIME_STACK,
                RUNTIME_STACK,
            )
        }
    }
}

// ============================================================
// The data walkers, each at the deepest input its bounds admit.
// ============================================================

#[test]
fn the_decoder_fits_its_stack_budget_at_its_bound() {
    fits(DECODER, STACK_BUDGET);
}

/// The typed decoders (and the serialization library at its own bound)
/// are recursive, so their bounds are held to a stack rather than shown
/// to cost none. The bounds themselves are set by what a WebKit worker's
/// stack holds (see `limits`); this checks the native build stays inside
/// the budget at them.
#[test]
fn the_typed_decoders_fit_their_stack_budget_at_their_bound() {
    fits(TYPED_DECODER, STACK_BUDGET);
}

/// pallas' decoders recurse like the typed decoders: at their bound they
/// fit the same budget.
#[test]
fn the_pallas_decoders_fit_their_stack_budget_at_their_bound() {
    fits(PALLAS, STACK_BUDGET);
}

/// Every entry point takes a native script nested to the walkers' bound
/// within the budget.
#[test]
fn native_scripts_at_the_walkers_bound_fit_the_stack_budget() {
    fits(NATIVE_SCRIPTS, STACK_BUDGET);
}

/// A transaction whose native scripts nest 3,000 levels deep goes through
/// every entry point on about the stack one nested a single level needs:
/// native-script nesting costs none of them stack.
#[test]
fn nesting_costs_the_native_script_readers_no_stack() {
    let floor = 16 * 1024;
    let leaf = smallest_surviving_stack_above(NATIVE_SCRIPTS_LEAF, floor)
        .expect("a one-level script goes through on some stack");
    let deep = smallest_surviving_stack_above(NATIVE_SCRIPTS_DEEP, floor);
    assert!(
        deep.is_some_and(|deep| deep <= 2 * leaf),
        "the entry points return on {} bytes for a one-level native script but need {} for \
         3,000 levels: native-script nesting is costing them stack again",
        leaf,
        deep.map_or_else(
            || format!("more than {}", floor.saturating_mul(64)),
            |n| n.to_string()
        ),
    );
}

/// Deepest decode must fit on ~the same stack as a leaf (no frame/level).
#[test]
fn nesting_costs_the_decoder_no_stack() {
    // Floor below any surviving stack so the search starts exhausted.
    let floor = 16 * 1024;
    let leaf =
        smallest_surviving_stack_above(DECODER_LEAF, floor).expect("a leaf decodes on some stack");
    let deep = smallest_surviving_stack_above(DECODER_DEEP, floor);
    assert!(
        deep.is_some_and(|deep| deep <= 2 * leaf),
        "the decoder returns on {} bytes for a leaf but needs {} at its bound: \
         nesting is costing it stack again",
        leaf,
        deep.map_or_else(
            || format!("more than {}", floor.saturating_mul(64)),
            |n| n.to_string()
        ),
    );
}

#[test]
fn the_schema_walker_fits_its_stack_budget_at_its_bound() {
    fits(SCHEMA_WALKER, STACK_BUDGET);
}

/// Deepest schema walk must fit on ~the same stack as a leaf.
#[test]
fn nesting_costs_the_schema_walker_no_stack() {
    let floor = 16 * 1024;
    let leaf = smallest_surviving_stack_above(SCHEMA_WALKER_LEAF, floor)
        .expect("a leaf maps on some stack");
    let deep = smallest_surviving_stack_above(SCHEMA_WALKER_DEEP, floor);
    assert!(
        deep.is_some_and(|deep| deep <= 2 * leaf),
        "the schema walker returns on {} bytes for a leaf but needs {} at its bound: \
         nesting is costing it stack again",
        leaf,
        deep.map_or_else(
            || format!("more than {}", floor.saturating_mul(64)),
            |n| n.to_string()
        ),
    );
}

#[test]
fn the_position_map_fits_its_stack_budget_at_its_bound() {
    fits(POSITION_MAP, STACK_BUDGET);
}

/// Position map replays on the heap; same leaf≈deep floor as the walker.
#[test]
fn nesting_costs_the_position_map_no_stack() {
    let floor = 16 * 1024;
    let leaf = smallest_surviving_stack_above(POSITION_MAP_LEAF, floor)
        .expect("a leaf maps on some stack");
    let deep = smallest_surviving_stack_above(POSITION_MAP_DEEP, floor);
    assert!(
        deep.is_some_and(|deep| deep <= 2 * leaf),
        "the position map returns on {} bytes for a leaf but needs {} at its bound: \
         nesting is costing it stack again",
        leaf,
        deep.map_or_else(
            || format!("more than {}", floor.saturating_mul(64)),
            |n| n.to_string()
        ),
    );
}

/// Four walkers reach 10_000 levels on 128 KiB with correct answers.
#[test]
fn the_four_walkers_reach_ten_thousand_levels_on_a_small_stack() {
    fits(TEN_THOUSAND, 128 * 1024);
}

/// Validator at the deepest level its bounds admit for each measured shape.
#[test]
fn the_validator_fits_its_stack_budget_at_its_bound() {
    fits(VALIDATOR, STACK_BUDGET);
}

/// Deepest validate (and deepest refusal) must fit on ~the same stack as a leaf.
#[test]
fn nesting_costs_the_validator_no_stack() {
    let floor = 16 * 1024;
    let leaf = smallest_surviving_stack_above(VALIDATOR_LEAF, floor)
        .expect("a leaf validates on some stack");
    let deep = smallest_surviving_stack_above(VALIDATOR_DEEP, floor);
    assert!(
        deep.is_some_and(|deep| deep <= 2 * leaf),
        "the validator returns on {} bytes for a leaf but needs {} at its bound: \
         nesting is costing it stack again",
        leaf,
        deep.map_or_else(
            || format!("more than {}", floor.saturating_mul(64)),
            |n| n.to_string()
        ),
    );
}

#[test]
fn an_embedded_chain_spending_the_whole_budget_fits_its_stack_budget() {
    fits(EMBEDDED_CHAIN, STACK_BUDGET);
}

/// Embedded chain through the validator at its shared level bound.
#[test]
fn an_embedded_chain_spending_the_whole_budget_fits_the_validators_stack_budget() {
    fits(VALIDATOR_EMBEDDED_CHAIN, STACK_BUDGET);
}

// ============================================================
// The schema walkers, at [`MAX_CDDL_NESTING_DEPTH`].
// ============================================================

#[test]
fn the_cddl_parser_and_serialiser_fit_their_stack_budget_at_their_bound() {
    fits(CDDL_PARSER, STACK_BUDGET);
}

// ============================================================
// The negative half: refusing input past a bound costs no walk,
// so it is held to a fraction of what a walk is allowed.
// ============================================================

#[test]
fn input_past_a_bound_is_refused_without_walking_it() {
    fits(REFUSAL, STACK_BUDGET / 8);
}

// ============================================================
// The stack these measurements are read against.
// ============================================================


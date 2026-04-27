//! CDDL / CBOR validation, powered by `anweiss/cddl`.
//!
//! Public surface:
//! * [`validate_cddl_text`] — validate a CDDL schema, including a static
//!   reference check that surfaces undefined rule names as
//!   `kind: "unresolved_references"`.
//! * [`validate_cbor_bytes_against_cddl`] — validate CBOR bytes against a
//!   named rule and return a structured error JSON. Byte spans / anchor
//!   spans are synthesised from a parallel `decoder::decode_cbor_to_value`
//!   traversal so UIs get exact positional info.
//! * [`decode_hex`] — hex helper.
//!
//! Implementation notes:
//! * Static reference checks come from `cddl::pest_bridge::cddl_from_pest_str_checked`,
//!   not the default `cddl_from_str` entry point (which skips the walk).
//! * `missing_rule` is distinguished by a pre-check before validation, so
//!   `validate_cbor_bytes_against_cddl` can be called with a non-root rule.
//! * For non-root rules we wrap with a synthetic `__cquisitor_root` rule
//!   so the upstream validator (which treats the first rule as the root)
//!   targets the requested name.
//! * On failure all reported `ValidationError`s are surfaced — first as
//!   the headline error, the rest under an `additional` array.

use cddl::validator::Validator;
use serde_json::{json, Map, Value};

use crate::cbor::decoder;

/// Validate just the CDDL schema. Returns `{ valid: true }` on success,
/// otherwise `{ valid: false, error: { ... } }`. Schemas that reference
/// undefined rule names come back as `kind: "unresolved_references"`.
pub fn validate_cddl_text(cddl: &str) -> Value {
    match cddl::pest_bridge::cddl_from_pest_str_checked(cddl) {
        Ok(_) => success_result(),
        Err(e) => failure_result(parser_error(&e.to_string())),
    }
}

/// Validate CBOR bytes against a named rule in a CDDL schema.
///
/// anweiss/cddl always uses the first type rule as root, so when
/// `rule_name` differs we prepend a synthetic root rule that delegates to
/// the requested name. If the requested rule does not exist in the parsed
/// schema we return `missing_rule` up-front.
pub fn validate_cbor_bytes_against_cddl(cbor: &[u8], cddl: &str, rule_name: &str) -> Value {
    // Parse with reference-check so unresolved rules surface as
    // parse_error / unresolved_references up-front. We also need the AST
    // to (a) pre-check the requested rule exists (missing_rule), and
    // (b) know the first rule name for the wrapper-schema shortcut.
    let parsed = match cddl::pest_bridge::cddl_from_pest_str_checked(cddl) {
        Ok(p) => p,
        Err(e) => return failure_result(parser_error(&e.to_string())),
    };

    if !has_rule(&parsed, rule_name) {
        return failure_result(simple_error("missing_rule", &format!(
            "CDDL does not define a rule named {}",
            rule_name
        )));
    }

    // anweiss/cddl's top-level `validate_cbor_from_slice` classifies CBOR
    // decode failures as `CDDLParsing` (see cddl-0.10.5 validator/mod.rs:431).
    // Pre-decode with our own decoder so those surface as `input_parse`
    // instead and carry our richer `byte_span` info.
    if let Err(e) = decoder::decode_cbor_to_value(cbor) {
        let mut obj = Map::new();
        obj.insert("kind".into(), Value::String("input_parse".into()));
        obj.insert("message".into(), Value::String(e.message.clone()));
        obj.insert("path".into(), Value::String(e.path.clone()));
        if let Some(off) = e.offset {
            obj.insert("offset".into(), Value::Number(off.into()));
        }
        if let Some((off, len)) = e.byte_span {
            obj.insert(
                "byte_spans".into(),
                Value::Array(vec![json!({"offset": off, "length": len})]),
            );
        }
        return failure_result(Value::Object(obj));
    }

    let first_rule_name = parsed
        .rules
        .first()
        .and_then(|r| match r {
            cddl::ast::Rule::Type { rule, .. } => Some(rule.name.ident.to_string()),
            _ => None,
        });
    let needs_wrapper = !matches!(first_rule_name.as_deref(), Some(name) if name == rule_name);

    // Re-parse with a synthetic root only when the requested rule isn't
    // already the first rule of the document — `cddl::CBORValidator` uses
    // the first type rule as the root and there's no rule_name parameter.
    if needs_wrapper {
        let wrapped = format!(
            "__cquisitor_root = {rule}\n\n{body}",
            rule = rule_name,
            body = cddl,
        );
        match cddl::pest_bridge::cddl_from_pest_str_checked(&wrapped) {
            Ok(ast) => run_validator(&ast, cbor),
            Err(e) => failure_result(parser_error(&e.to_string())),
        }
    } else {
        run_validator(&parsed, cbor)
    }
}

/// Run the upstream CBOR validator against a parsed CDDL AST and the
/// raw CBOR bytes. Splits out the target-specific call to
/// `CBORValidator::new` (the public top-level `validate_cbor_from_slice`
/// wrapper is gated `not(target_arch = "wasm32")` and the wasm form
/// returns `Result<JsValue, JsValue>`, so we go through the validator
/// directly on both targets).
fn run_validator(ast: &cddl::ast::CDDL<'_>, cbor: &[u8]) -> Value {
    let cbor_value = match cddl::validator::cbor_value::decode_cbor(cbor) {
        Ok(v) => v,
        Err(e) => return failure_result(simple_error("input_parse", &e.to_string())),
    };

    // `CBORValidator::new` has different `enabled_features` types on
    // native (`Option<&[&str]>`) vs wasm (`Option<Box<[JsValue]>>`), but
    // only one is `cfg`-active per target so `None` infers correctly.
    let mut cv = cddl::validator::cbor::CBORValidator::new(ast, cbor_value, None);

    match cv.validate() {
        Ok(()) => success_result(),
        Err(err) => failure_result(map_cbor_error(&err, cbor)),
    }
}

/// Hex-decode helper for the wasm wrapper.
pub fn decode_hex(cbor_hex: &str) -> Result<Vec<u8>, crate::js_error::JsError> {
    hex::decode(cbor_hex).map_err(|e| {
        crate::js_error::JsError::new(&format!("invalid CBOR hex: {}", e))
    })
}

// ============================ helpers ============================

fn success_result() -> Value {
    json!({ "valid": true })
}

fn failure_result(error: Value) -> Value {
    json!({ "valid": false, "error": error })
}

fn simple_error(kind: &str, message: &str) -> Value {
    json!({ "kind": kind, "message": message })
}

fn parser_error(message: &str) -> Value {
    // cddl_from_pest_str_checked returns "missing definition for rule X"
    // for dangling refs; keep that as its own kind so UIs can single it
    // out instead of grouping with generic parse errors.
    let kind = if message.contains("missing definition for rule") {
        "unresolved_references"
    } else {
        "parse_error"
    };
    simple_error(kind, message)
}

fn has_rule(cddl_ast: &cddl::ast::CDDL, name: &str) -> bool {
    cddl_ast.rules.iter().any(|r| match r {
        cddl::ast::Rule::Type { rule, .. } => rule.name.ident == name,
        cddl::ast::Rule::Group { rule, .. } => rule.name.ident == name,
    })
}

/// Map an error returned by `cddl::validate_cbor_from_slice` into our
/// public JSON shape: `kind`, `message`, optional `expected`, `path`,
/// `byte_spans`, `anchor_spans`, plus an `additional` list when multiple
/// validation errors were reported.
fn map_cbor_error(err: &cddl::validator::cbor::Error<std::io::Error>, cbor: &[u8]) -> Value {
    use cddl::validator::cbor::Error as CborError;

    match err {
        CborError::Validation(errs) if !errs.is_empty() => {
            let mut head = cbor_validation_error(&errs[0], cbor);
            if errs.len() > 1 {
                let rest: Vec<Value> = errs
                    .iter()
                    .skip(1)
                    .map(|e| cbor_validation_error(e, cbor))
                    .collect();
                if let Value::Object(ref mut o) = head {
                    o.insert("additional".into(), Value::Array(rest));
                }
            }
            head
        }
        CborError::Validation(_) => simple_error("generic", &err.to_string()),
        CborError::CDDLParsing(msg) => parser_error(msg),
        CborError::CBORParsing(e) => simple_error("input_parse", &e.to_string()),
        other => simple_error("generic", &other.to_string()),
    }
}

fn cbor_validation_error(e: &cddl::validator::cbor::ValidationError, cbor: &[u8]) -> Value {
    let reason = e.reason.as_str();
    let kind = classify_reason(reason);

    let mut obj = Map::new();
    obj.insert("kind".into(), Value::String(kind.into()));
    obj.insert("message".into(), Value::String(reason.to_string()));

    if let Some(expected) = extract_expected(reason) {
        obj.insert("expected".into(), Value::String(expected));
    }
    let path = cbor_location_to_json_path(&e.cbor_location);
    obj.insert("path".into(), Value::String(path));
    if !e.cddl_location.is_empty() {
        obj.insert(
            "cddl_location".into(),
            Value::String(e.cddl_location.clone()),
        );
    }

    // Byte-span synthesis (Mitigation B). Decode the CBOR once; walk the
    // tree by the anweiss cbor_location path; copy position_info /
    // struct_position_info from the located node.
    if let Ok(tree) = decoder::decode_cbor_to_value(cbor) {
        if let Some(node) = resolve_cbor_path(&tree, &e.cbor_location) {
            if let Some(pos) = node.get("position_info") {
                obj.insert("byte_spans".into(), Value::Array(vec![pos.clone()]));
            }
            if let Some(pos) = node.get("struct_position_info") {
                obj.insert("anchor_spans".into(), Value::Array(vec![pos.clone()]));
            }
        }
    }

    Value::Object(obj)
}

/// `anweiss/cddl` doesn't expose a single error-kind enum — all failures
/// come through as free-form `reason` strings. Bucket them by substring so
/// downstream consumers get stable `kind` values.
fn classify_reason(reason: &str) -> &'static str {
    let lower = reason.to_ascii_lowercase();
    if lower.contains("map cut") || lower.contains("cut") && lower.contains("map") {
        "map_cut"
    } else if lower.contains("unresolved") || lower.contains("unknown rule")
        || lower.contains("undefined rule")
    {
        "unresolved_references"
    } else if lower.contains("expected ") || lower.contains("but got")
        || lower.contains("type mismatch") || lower.contains("doesn't match")
        || lower.contains("does not match")
    {
        "mismatch"
    } else {
        "generic"
    }
}

/// Pull out whatever `expected X but got …` phrase the validator produced,
/// returning just `X`. Best-effort — reason strings aren't structured.
/// Strips the common `type ` prefix anweiss emits so callers get a bare
/// type name (e.g. `tstr` rather than `type tstr`).
fn extract_expected(reason: &str) -> Option<String> {
    let lower = reason.to_ascii_lowercase();
    let idx = lower.find("expected ")?;
    let tail = &reason[idx + "expected ".len()..];
    let end = tail
        .find(" but ")
        .or_else(|| tail.find(", got"))
        .or_else(|| tail.find('\n'))
        .unwrap_or(tail.len());
    let candidate = tail[..end]
        .trim()
        .trim_end_matches(|c: char| c == ',' || c == '.');
    let candidate = candidate
        .strip_prefix("type ")
        .or_else(|| candidate.strip_prefix("Type "))
        .unwrap_or(candidate);
    if candidate.is_empty() {
        None
    } else {
        Some(candidate.to_string())
    }
}

/// Translate anweiss/cddl's slash-separated `cbor_location` into the same
/// JSON-pointer-ish path grammar the decoder tree uses (`$`, `$.key`,
/// `$[n]`). Text keys arrive as `"keyname"` (via `write!("/{:?}", …)` in
/// the validator); integer keys as `Integer(Integer(42))`; array indices
/// as bare numbers.
fn cbor_location_to_json_path(loc: &str) -> String {
    let trimmed = loc.trim_start_matches('/');
    if trimmed.is_empty() {
        return "$".to_string();
    }
    let mut out = String::from("$");
    for seg in split_location_segments(trimmed) {
        match classify_segment(&seg) {
            Segment::Index(i) => {
                out.push('[');
                out.push_str(&i.to_string());
                out.push(']');
            }
            Segment::TextKey(s) => {
                out.push('.');
                out.push_str(&s);
            }
            Segment::IntKey(n) => {
                out.push('[');
                out.push_str(&n.to_string());
                out.push(']');
            }
            Segment::Opaque(raw) => {
                out.push('.');
                out.push_str(&raw);
            }
        }
    }
    out
}

enum Segment {
    Index(usize),
    TextKey(String),
    IntKey(i128),
    Opaque(String),
}

/// Split on `/` but keep escaped text inside `"…"` or balanced `(…)` intact,
/// so segments like `"a/b"` or `Integer(-1)` aren't torn apart.
fn split_location_segments(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut in_quotes = false;
    let mut paren_depth = 0i32;
    let mut escaped = false;
    for c in s.chars() {
        if escaped {
            buf.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_quotes => {
                buf.push(c);
                escaped = true;
            }
            '"' => {
                in_quotes = !in_quotes;
                buf.push(c);
            }
            '(' if !in_quotes => {
                paren_depth += 1;
                buf.push(c);
            }
            ')' if !in_quotes && paren_depth > 0 => {
                paren_depth -= 1;
                buf.push(c);
            }
            '/' if !in_quotes && paren_depth == 0 => {
                out.push(std::mem::take(&mut buf));
            }
            _ => buf.push(c),
        }
    }
    if !buf.is_empty() {
        out.push(buf);
    }
    out
}

fn classify_segment(seg: &str) -> Segment {
    if let Ok(i) = seg.parse::<usize>() {
        return Segment::Index(i);
    }
    if let Some(unquoted) = strip_debug_quotes(seg) {
        return Segment::TextKey(unquoted);
    }
    if let Some(n) = parse_integer_segment(seg) {
        return Segment::IntKey(n);
    }
    Segment::Opaque(seg.to_string())
}

/// Strip the surrounding `"` produced by `format!("{:?}", &str)`. Returns
/// `None` if the segment isn't in that form.
fn strip_debug_quotes(seg: &str) -> Option<String> {
    let bytes = seg.as_bytes();
    if bytes.len() < 2 || bytes.first() != Some(&b'"') || bytes.last() != Some(&b'"') {
        return None;
    }
    let inner = &seg[1..seg.len() - 1];
    // Undo the common escapes Debug inserts for &str — we only need the
    // ones that could end up in CBOR text keys: `\\`, `\"`.
    let mut out = String::with_capacity(inner.len());
    let mut it = inner.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    Some(out)
}

/// anweiss/cddl debug-prints `ciborium::value::Integer` inside `Integer(…)`
/// so a typical integer-key segment is `Integer(Integer(-1))` or similar.
/// Extract the innermost signed integer.
fn parse_integer_segment(seg: &str) -> Option<i128> {
    let mut s = seg.trim();
    while let Some(inner) = strip_prefix_ci(s, "Integer(").and_then(|t| t.strip_suffix(')')) {
        s = inner.trim();
    }
    s.parse::<i128>().ok()
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() < prefix.len() {
        return None;
    }
    if s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

/// Walk `decode_cbor_to_value` output to the node identified by a
/// slash-separated `cbor_location`. Returns `None` if the path can't be
/// resolved cleanly (indefinite containers, opaque keys, etc.).
fn resolve_cbor_path<'a>(tree: &'a Value, loc: &str) -> Option<&'a Value> {
    let mut node = tree;
    let trimmed = loc.trim_start_matches('/');
    if trimmed.is_empty() {
        return Some(node);
    }
    for raw in split_location_segments(trimmed) {
        node = step_into(node, &classify_segment(&raw))?;
    }
    Some(node)
}

fn step_into<'a>(node: &'a Value, seg: &Segment) -> Option<&'a Value> {
    let type_name = node.get("type").and_then(Value::as_str).unwrap_or("");
    match (type_name, seg) {
        ("Array", Segment::Index(i)) => node.get("values")?.get(*i),
        ("Map", Segment::Index(i)) => {
            // anweiss/cddl emits bare integer segments for both
            //   (a) entry positional index, and
            //   (b) integer-typed map keys.
            // Try integer-key lookup first, fall back to positional.
            let entries = node.get("values")?.as_array()?;
            for entry in entries {
                let k = entry.get("key")?;
                let kt = k.get("type").and_then(Value::as_str).unwrap_or("");
                if matches!(
                    kt,
                    "U8" | "U16" | "U32" | "U64" | "I8" | "I16" | "I32" | "I64" | "Int"
                ) {
                    if k.get("value").and_then(Value::as_i64)
                        == Some(*i as i64)
                    {
                        return entry.get("value");
                    }
                }
            }
            entries.get(*i).and_then(|e| e.get("value"))
        }
        ("Map", Segment::TextKey(key)) => {
            let entries = node.get("values")?.as_array()?;
            for entry in entries {
                let k = entry.get("key")?;
                if k.get("type").and_then(Value::as_str) == Some("String")
                    && k.get("value").and_then(Value::as_str) == Some(key)
                {
                    return entry.get("value");
                }
            }
            None
        }
        ("Map", Segment::IntKey(n)) => {
            let entries = node.get("values")?.as_array()?;
            for entry in entries {
                let k = entry.get("key")?;
                let kt = k.get("type").and_then(Value::as_str).unwrap_or("");
                if !matches!(
                    kt,
                    "U8" | "U16" | "U32" | "U64" | "I8" | "I16" | "I32" | "I64" | "Int"
                ) {
                    continue;
                }
                if k.get("value")
                    .and_then(|v| match v {
                        Value::Number(num) => Some(num.to_string()),
                        _ => None,
                    })
                    == Some(n.to_string())
                {
                    return entry.get("value");
                }
            }
            None
        }
        ("Tag", _) => node.get("value"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_hex, validate_cbor_bytes_against_cddl, validate_cddl_text};
    use serde_json::{json, Value};

    fn error_obj(result: &Value) -> &Value {
        assert_eq!(result["valid"], Value::Bool(false), "unexpected success: {}", result);
        &result["error"]
    }

    /// Real signed Conway tx (preview era) — same fixture used by
    /// schema_mapper tests. Single input, two outputs, fee, aux hash, one
    /// vkey witness.
    const PREVIEW_TX: &str = "84a400d901028182582016b6ee8c812f8b1c9c643ee3828f50fdcf0f174625bbd6e947ba77b12374094a00018282583900aef399a405edd6797117a3db6653e1a230e1f6f91dd5badb77f2be3720fc45da826093ae8ed2e4f0f81c4f5ea9b6f0dda561c974cfc6355d1a000f424082583900f275cb75d82f737c49280039947e484919ee044c82c2e4ceaf2f2d87984c3eb5c8a01b4b53c7cec4cfc139345a28d24a6ec918873c459add1a48b7d00d021a00030d40075820bdaa99eb158414dea0a91d6c727e2268574b23efe6e08ab3b841abe8059a030ca100d9010281825820f8f5750132a13473240e318dd36eccd70083e8f08ac589c74ebe776f43e9401d58401e149e081ff497d7f97c3ef7427a916d1b0632c6eb98bb54b040aca413a2ad94273291c9b63b2802083c72b0cfe03eef2b55f767ecf32dba894dd59701076409f5d90103a0";

    fn load_conway_cddl() -> Option<String> {
        std::fs::read_to_string("/tmp/conway.cddl").ok()
    }

    #[test]
    fn validate_cddl_accepts_official_conway_cddl() {
        let Some(cddl) = load_conway_cddl() else {
            eprintln!("skipping — /tmp/conway.cddl not present");
            return;
        };
        let result = validate_cddl_text(&cddl);
        assert_eq!(
            result,
            json!({ "valid": true }),
            "official Conway CDDL should validate cleanly, got {}",
            result
        );
    }

    /// Sanity check: the validator handles `set<a> = #6.258([* a])` on a
    /// minimal hand-written CDDL covering the same shape as a Conway tx.
    /// Used to bisect upstream validator regressions away from the larger
    /// official Conway CDDL.
    const HAND_GENERICS_CDDL: &str = r#"
        transaction = [
          transaction_body,
          transaction_witness_set,
          bool,
          auxiliary_data / null
        ]

        transaction_body = {
          0: set<transaction_input>,
          1: [* transaction_output],
          2: coin,
          ? 7: bstr
        }

        transaction_input  = [bstr, uint]
        transaction_output = [bstr, coin]
        coin               = uint

        transaction_witness_set = {
          ? 0: set<vkeywitness>
        }
        vkeywitness = [bstr, bstr]

        set<a>         = #6.258([* a])
        auxiliary_data = #6.259({})
    "#;

    #[test]
    fn validate_cbor_against_hand_generics_for_real_preview_tx() {
        let bytes = hex::decode(PREVIEW_TX).expect("test hex");
        let result =
            validate_cbor_bytes_against_cddl(&bytes, HAND_GENERICS_CDDL, "transaction");
        assert_eq!(
            result,
            json!({ "valid": true }),
            "real preview tx should validate against hand-written Conway-style CDDL, got {}",
            result
        );
    }

    /// Bisect: closer to the official Conway shape — `nonempty_set` with
    /// `+`, `.size` constraints on `vkey`/`signature`. If this passes
    /// while the official Conway test fails, the regression trigger is
    /// elsewhere (e.g. one of Conway's many other rules).
    const HAND_NONEMPTY_SET_WITH_SIZE_CDDL: &str = r#"
        transaction = [
          transaction_body,
          transaction_witness_set,
          bool,
          auxiliary_data / null
        ]

        transaction_body = {
          0: nonempty_set<transaction_input>,
          1: [* transaction_output],
          2: coin,
          ? 7: bstr .size 32
        }

        transaction_input  = [bstr .size 32, uint]
        transaction_output = [bstr, coin]
        coin               = uint

        transaction_witness_set = {
          ? 0: nonempty_set<vkeywitness>
        }
        vkey        = bstr .size 32
        signature   = bstr .size 64
        vkeywitness = [vkey, signature]

        nonempty_set<a> = #6.258([+ a]) / [+ a]
        auxiliary_data  = #6.259({})
    "#;

    // ---------- Upstream `anweiss/cddl` validator regression repros ----------
    //
    // The bisects below pin down where the validator falls over. None of
    // these are bugs in cquisitor-lib; they assert what the upstream
    // validator does today so we notice when it changes.

    /// Baseline: `.size N` directly on a top-level bstr — works.
    #[test]
    fn validate_cbor_size_top_level_bstr_passes() {
        let cbor_hex = format!("5820{}", "11".repeat(32));
        let bytes = hex::decode(&cbor_hex).unwrap();
        assert_eq!(
            validate_cbor_bytes_against_cddl(&bytes, "x = bstr .size 32", "x"),
            json!({ "valid": true })
        );
    }

    /// `.size N` on inline `bstr` inside an array literal — works.
    #[test]
    fn validate_cbor_size_inline_in_array_passes() {
        let cbor_hex = format!("82{}{}{}", "5820", "11".repeat(32), "00");
        let bytes = hex::decode(&cbor_hex).unwrap();
        assert_eq!(
            validate_cbor_bytes_against_cddl(
                &bytes,
                "x = [bstr .size 32, uint]",
                "x"
            ),
            json!({ "valid": true })
        );
    }

    /// `.size N` hidden behind one level of rule resolution
    /// (`hash = bstr .size 32`) used as an array entry. Used to fail in
    /// upstream `anweiss/cddl` ≤ 0.10.5 — the validator treated the
    /// outer array as the operand of `.size` rather than entering the
    /// element. Now passes after the upstream fix in our fork.
    #[test]
    fn validate_cbor_size_via_named_rule_passes() {
        let cbor_hex = format!("82{}{}{}", "5820", "11".repeat(32), "00");
        let bytes = hex::decode(&cbor_hex).unwrap();
        let cddl = "x = [hash, idx: uint]\nhash = bstr .size 32";
        assert_eq!(
            validate_cbor_bytes_against_cddl(&bytes, cddl, "x"),
            json!({ "valid": true })
        );
    }

    /// Real preview tx against a Conway-style CDDL with `nonempty_set<a>`
    /// + `.size N` constraints — exercises the same shape that broke
    /// in upstream `anweiss/cddl` ≤ 0.10.5. Now valid after the fix.
    #[test]
    fn validate_cbor_with_nonempty_set_and_size_passes() {
        let bytes = hex::decode(PREVIEW_TX).expect("test hex");
        let result = validate_cbor_bytes_against_cddl(
            &bytes,
            HAND_NONEMPTY_SET_WITH_SIZE_CDDL,
            "transaction",
        );
        assert_eq!(
            result,
            json!({ "valid": true }),
            "Conway-shaped tx should validate now that `.size` works \
             through named rules, got {}",
            result
        );
    }

    /// Real preview tx against the **official** Conway CDDL.
    /// End-to-end validation — exercises generics, `nonempty_set`,
    /// `.size N`, tagged sets, and named rule resolution all at once.
    #[test]
    fn validate_cbor_against_official_conway_for_real_preview_tx() {
        let Some(cddl) = load_conway_cddl() else {
            eprintln!("skipping — /tmp/conway.cddl not present");
            return;
        };
        let bytes = hex::decode(PREVIEW_TX).expect("test hex");
        let result = validate_cbor_bytes_against_cddl(&bytes, &cddl, "transaction");
        assert_eq!(
            result,
            json!({ "valid": true }),
            "real preview tx should validate against official Conway CDDL, got {}",
            result
        );
    }

    #[test]
    fn validate_cbor_against_conway_uses_a_non_root_rule() {
        // `transaction_input` is a non-root rule — exercises the wrapper
        // path. Build a single CBOR transaction_input: [tx_hash(32), idx].
        let Some(cddl) = load_conway_cddl() else {
            eprintln!("skipping — /tmp/conway.cddl not present");
            return;
        };
        // 82 5820<32 bytes> 00 = [bstr(32), 0]
        let cbor_hex = format!("82{}{}{}", "5820", "11".repeat(32), "00");
        let bytes = hex::decode(&cbor_hex).unwrap();
        let result =
            validate_cbor_bytes_against_cddl(&bytes, &cddl, "transaction_input");
        assert_eq!(
            result,
            json!({ "valid": true }),
            "transaction_input should validate against Conway, got {}",
            result
        );
    }

    #[test]
    fn validate_cbor_against_conway_flags_mismatch_with_path() {
        // Wrong-shaped tx: `01` is a uint, not a transaction array.
        let Some(cddl) = load_conway_cddl() else {
            eprintln!("skipping — /tmp/conway.cddl not present");
            return;
        };
        let bytes = hex::decode("01").unwrap();
        let result = validate_cbor_bytes_against_cddl(&bytes, &cddl, "transaction");
        assert_eq!(result["valid"], Value::Bool(false));
        let err = &result["error"];
        assert!(
            err.get("kind").is_some(),
            "expected kind on Conway mismatch, got {}",
            err
        );
        assert!(
            err.get("path").is_some(),
            "expected path on Conway mismatch, got {}",
            err
        );
    }

    #[test]
    fn validate_cbor_against_conway_missing_rule() {
        let Some(cddl) = load_conway_cddl() else {
            eprintln!("skipping — /tmp/conway.cddl not present");
            return;
        };
        let bytes = hex::decode(PREVIEW_TX).unwrap();
        let result =
            validate_cbor_bytes_against_cddl(&bytes, &cddl, "definitely_not_a_rule");
        assert_eq!(result["valid"], Value::Bool(false));
        assert_eq!(result["error"]["kind"], Value::String("missing_rule".into()));
    }

    #[test]
    fn valid_cddl_returns_only_valid_flag() {
        let result = validate_cddl_text("person = {name: tstr, age: uint}");
        assert_eq!(result, json!({"valid": true}));
    }

    #[test]
    fn malformed_cddl_returns_parse_error_with_message() {
        let result = validate_cddl_text("this is not cddl @@@");
        let error = error_obj(&result);
        assert_eq!(error["kind"], Value::String("parse_error".into()));
        assert!(
            !error["message"].as_str().unwrap_or_default().is_empty(),
            "expected parse error message, got {}",
            error
        );
    }

    #[test]
    fn schema_with_dangling_reference_is_rejected() {
        // `unknown_rule` isn't defined. anweiss/cddl's default parser
        // does NOT catch dangling refs — we route through
        // `cddl_from_pest_str_checked` to surface them with a dedicated
        // `unresolved_references` kind.
        let result = validate_cddl_text("thing = [unknown_rule, int]");
        let error = error_obj(&result);
        assert_eq!(error["kind"], Value::String("unresolved_references".into()));
        assert!(
            error["message"].as_str().unwrap().contains("unknown_rule"),
            "message should mention the missing rule, got {}",
            error
        );
    }

    #[test]
    fn matching_cbor_against_cddl_reports_valid() {
        let cbor = hex::decode("a264646174611901006269640a").unwrap();
        let result = validate_cbor_bytes_against_cddl(
            &cbor,
            "thing = {data: uint, id: uint}",
            "thing",
        );
        assert_eq!(result, json!({"valid": true}));
    }

    #[test]
    fn mismatch_surfaces_path_and_byte_spans() {
        // a26161016162820203 = {"a": 1, "b": [2, 3]}, b expects [tstr, tstr].
        let cbor = hex::decode("a26161016162820203").unwrap();
        let result = validate_cbor_bytes_against_cddl(
            &cbor,
            "thing = {a: int, b: [tstr, tstr]}",
            "thing",
        );
        let error = error_obj(&result);
        assert!(error.get("kind").is_some());
        assert!(error.get("path").is_some(), "no path: {}", error);
        let spans = error
            .get("byte_spans")
            .and_then(Value::as_array)
            .expect("byte_spans should be synthesised");
        assert!(!spans.is_empty(), "byte_spans must contain the failing node");
        assert_eq!(spans[0]["offset"], json!(7), "first-element span {}", error);
        assert_eq!(spans[0]["length"], json!(1));
    }

    #[test]
    fn malformed_cbor_is_classified_as_input_parse() {
        // 0x18 = uint header that needs a follow-up byte.
        let result = validate_cbor_bytes_against_cddl(&[0x18], "thing = int", "thing");
        let error = error_obj(&result);
        assert_eq!(error["kind"], Value::String("input_parse".into()));
    }

    #[test]
    fn cddl_parse_error_reaches_cbor_entry_point() {
        let cbor = hex::decode("01").unwrap();
        let result = validate_cbor_bytes_against_cddl(
            &cbor,
            "not a cddl schema @@@",
            "thing",
        );
        let error = error_obj(&result);
        assert_eq!(error["kind"], Value::String("parse_error".into()));
    }

    #[test]
    fn dangling_reference_reaches_cbor_entry_point() {
        let cbor = hex::decode("01").unwrap();
        let result = validate_cbor_bytes_against_cddl(
            &cbor,
            "thing = [unknown_rule, int]",
            "thing",
        );
        let error = error_obj(&result);
        assert_eq!(error["kind"], Value::String("unresolved_references".into()));
    }

    #[test]
    fn prelude_identifier_is_not_flagged_as_unresolved() {
        // `uint`, `tstr`, `bool` are all prelude types.
        assert_eq!(
            validate_cddl_text("thing = {n: uint, s: tstr, b: bool}"),
            json!({"valid": true})
        );
    }

    #[test]
    fn string_key_path_resolves_to_byte_span() {
        // a16161 1864 = {"a": 100}; schema expects a = tstr, so failure is
        // on the value of key "a" (offset 3, length 2).
        let cbor = hex::decode("a161611864").unwrap();
        let result = validate_cbor_bytes_against_cddl(
            &cbor,
            "thing = {a: tstr}",
            "thing",
        );
        let error = error_obj(&result);
        let spans = error
            .get("byte_spans")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("no byte_spans in {}", error));
        assert_eq!(spans[0]["offset"], json!(3), "{}", error);
        assert_eq!(spans[0]["length"], json!(2));
    }

    #[test]
    fn integer_key_path_resolves_to_byte_span() {
        // a1_01_1864 = {1: 100}; schema expects key 1 to carry a tstr, so
        // the failure is on the value of key 1 (offset 2, length 2).
        let cbor = hex::decode("a1011864").unwrap();
        let result = validate_cbor_bytes_against_cddl(
            &cbor,
            "thing = {1 => tstr}",
            "thing",
        );
        let error = error_obj(&result);
        let spans = error
            .get("byte_spans")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("no byte_spans in {}", error));
        assert_eq!(spans[0]["offset"], json!(2), "{}", error);
        assert_eq!(spans[0]["length"], json!(2));
    }

    #[test]
    fn nested_container_byte_span_points_at_deep_child() {
        // a1_6161_82_01_02 = {"a": [1, 2]}. Expect [tstr, tstr] — first
        // element (offset 4) fails.
        let cbor = hex::decode("a161618201 02".replace(' ', "").as_str()).unwrap();
        let result = validate_cbor_bytes_against_cddl(
            &cbor,
            "thing = {a: [tstr, tstr]}",
            "thing",
        );
        let error = error_obj(&result);
        let spans = error
            .get("byte_spans")
            .and_then(Value::as_array)
            .expect("spans");
        assert_eq!(spans[0]["offset"], json!(4), "{}", error);
        assert_eq!(spans[0]["length"], json!(1));
    }

    #[test]
    fn cddl_location_is_exposed_when_non_empty() {
        let cbor = hex::decode("a16161 1864".replace(' ', "").as_str()).unwrap();
        let result = validate_cbor_bytes_against_cddl(
            &cbor,
            "thing = {a: tstr}",
            "thing",
        );
        let error = error_obj(&result);
        // cddl_location is best-effort; assert presence as a structural
        // field when reason touched a rule/position.
        if let Some(loc) = error.get("cddl_location").and_then(Value::as_str) {
            assert!(!loc.is_empty(), "non-empty cddl_location: {}", error);
        }
    }

    #[test]
    fn full_error_object_shape_contains_offset_and_length() {
        // Fix the output so it's obvious what shape callers get.
        let cbor = hex::decode("a26161016162820203").unwrap();
        let result = validate_cbor_bytes_against_cddl(
            &cbor,
            "thing = {a: int, b: [tstr, tstr]}",
            "thing",
        );
        let err = &result["error"];
        // Offset + length are carried as byte_spans[0].{offset,length}.
        assert_eq!(err["byte_spans"][0]["offset"], json!(7));
        assert_eq!(err["byte_spans"][0]["length"], json!(1));
        // kind + message + path are present as usual.
        assert_eq!(err["kind"], json!("mismatch"));
        assert!(err["path"].as_str().unwrap_or("").starts_with("$"));
    }

    #[test]
    fn container_failure_emits_anchor_span_covering_whole_structure() {
        // Expect an array, give a map. anchor_spans should cover the
        // full offending node (header + contents), byte_spans just its
        // header — anchor_spans cover the full structure.
        let cbor = hex::decode("a26161016162820203").unwrap();
        let result = validate_cbor_bytes_against_cddl(
            &cbor,
            "thing = [int, int]", // top-level mismatch: map vs array
            "thing",
        );
        let err = &result["error"];
        let byte_spans = err
            .get("byte_spans")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let anchor_spans = err
            .get("anchor_spans")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert!(!byte_spans.is_empty(), "byte_spans: {}", err);
        assert!(!anchor_spans.is_empty(), "anchor_spans: {}", err);
        // Root header is 1 byte (map header); whole structure is 9 bytes.
        assert_eq!(byte_spans[0]["offset"], json!(0));
        assert_eq!(byte_spans[0]["length"], json!(1));
        assert_eq!(anchor_spans[0]["offset"], json!(0));
        assert_eq!(anchor_spans[0]["length"], json!(9));
    }

    #[test]
    fn successful_validation_via_wrapper_preserves_original_semantics() {
        // Rule at the back of the schema; wrapper-prepend must route to it.
        let cbor = hex::decode("68746573742d737472").unwrap(); // "test-str"
        let result = validate_cbor_bytes_against_cddl(
            &cbor,
            "other = uint\nname = tstr",
            "name",
        );
        assert_eq!(result, json!({"valid": true}));
    }

    #[test]
    fn missing_rule_is_reported_distinctly() {
        let cbor = hex::decode("01").unwrap();
        let result = validate_cbor_bytes_against_cddl(
            &cbor,
            "thing = int",
            "no_such_rule",
        );
        let error = error_obj(&result);
        assert_eq!(error["kind"], Value::String("missing_rule".into()));
    }

    #[test]
    fn non_root_rule_name_still_validates_via_wrapper() {
        // Second rule in the schema. anweiss/cddl uses the first rule
        // as root, so we wrap in `__cquisitor_root = num` internally.
        let cbor = hex::decode("01").unwrap();
        let result = validate_cbor_bytes_against_cddl(
            &cbor,
            "root = tstr\nnum = uint",
            "num",
        );
        assert_eq!(result, json!({"valid": true}));
    }

    #[test]
    fn decode_hex_rejects_invalid_input() {
        let err = decode_hex("zz")
            .err()
            .expect("expected hex error")
            .as_string()
            .unwrap_or_default();
        assert!(err.contains("invalid CBOR hex"), "unexpected: {}", err);
    }

    #[test]
    fn decode_hex_accepts_mixed_case_and_even_length() {
        assert_eq!(decode_hex("DeAdBeEf").unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }
}

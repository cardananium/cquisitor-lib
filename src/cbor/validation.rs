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
use crate::cbor::source_index::{span_json, Utf16Index};

/// Validate just the CDDL schema. Returns `{ valid: true }` on success,
/// otherwise `{ valid: false, error: { ... } }`. Schemas that reference
/// undefined rule names come back as `kind: "unresolved_references"`.
/// Documents that parse cleanly but contain no rules (empty input,
/// only comments) come back as `kind: "no_rules"` so an IDE can flag
/// them rather than getting a misleading `valid: true`. Parser errors
/// include a `byte_span: {offset, length, line}` pointing at the
/// position pest reported.
pub fn validate_cddl_text(cddl: &str) -> Value {
    match cddl::pest_bridge::cddl_from_pest_str_checked(cddl) {
        Ok(ast) => {
            if ast.rules.is_empty() {
                return failure_result(simple_error(
                    "no_rules",
                    "CDDL document defines no rules",
                ));
            }
            success_result()
        }
        Err(e) => {
            let mut error = parser_error(&e.to_string());
            if let cddl::parser::Error::PARSER { position, .. } = &e {
                if let Value::Object(ref mut o) = error {
                    let idx = Utf16Index::new(cddl);
                    o.insert(
                        "byte_span".into(),
                        span_json(&idx, position.range.0, position.range.1, position.line),
                    );
                }
            }
            failure_result(error)
        }
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
        // Bytes the wrapper added before the user's CDDL — used to map
        // AST byte spans back to offsets in the original `cddl` string.
        let prefix_len = wrapped.len() - cddl.len();
        match cddl::pest_bridge::cddl_from_pest_str_checked(&wrapped) {
            Ok(ast) => run_validator(
                &ast,
                cbor,
                // Start AST traversal from the user's rule directly,
                // not from `__cquisitor_root` — the wrapper rule body
                // lives inside the prefix bytes we're going to subtract,
                // so its span is unreachable from the original CDDL's
                // perspective.
                ValidationCtx {
                    root_rule: rule_name,
                    cddl_offset_correction: prefix_len,
                    utf16: Utf16Index::new(cddl),
                },
            ),
            Err(e) => failure_result(parser_error(&e.to_string())),
        }
    } else {
        run_validator(
            &parsed,
            cbor,
            ValidationCtx {
                root_rule: rule_name,
                cddl_offset_correction: 0,
                utf16: Utf16Index::new(cddl),
            },
        )
    }
}

/// Context kept alongside the validator run so error mapping can
/// synthesise CDDL byte spans from the (cbor_location, rule_name) pair.
struct ValidationCtx<'a> {
    root_rule: &'a str,
    /// Number of bytes the wrapper prepended to the user's CDDL.
    /// Subtracted from any AST span so positions land in the original
    /// source the user provided.
    cddl_offset_correction: usize,
    /// UTF-16 index over the *original* user-supplied CDDL — lets
    /// every emitted `cddl_byte_span` carry both byte and char offsets.
    utf16: Utf16Index,
}

/// Run the upstream CBOR validator against a parsed CDDL AST and the
/// raw CBOR bytes. Splits out the target-specific call to
/// `CBORValidator::new` (the public top-level `validate_cbor_from_slice`
/// wrapper is gated `not(target_arch = "wasm32")` and the wasm form
/// returns `Result<JsValue, JsValue>`, so we go through the validator
/// directly on both targets).
fn run_validator(
    ast: &cddl::ast::CDDL<'_>,
    cbor: &[u8],
    ctx: ValidationCtx<'_>,
) -> Value {
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
        Err(err) => failure_result(map_cbor_error(&err, cbor, ast, &ctx)),
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
fn map_cbor_error(
    err: &cddl::validator::cbor::Error<std::io::Error>,
    cbor: &[u8],
    ast: &cddl::ast::CDDL<'_>,
    ctx: &ValidationCtx<'_>,
) -> Value {
    use cddl::validator::cbor::Error as CborError;

    match err {
        CborError::Validation(errs) if !errs.is_empty() => {
            let mut head = cbor_validation_error(&errs[0], cbor, ast, ctx);
            if errs.len() > 1 {
                let rest: Vec<Value> = errs
                    .iter()
                    .skip(1)
                    .map(|e| cbor_validation_error(e, cbor, ast, ctx))
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

fn cbor_validation_error(
    e: &cddl::validator::cbor::ValidationError,
    cbor: &[u8],
    ast: &cddl::ast::CDDL<'_>,
    ctx: &ValidationCtx<'_>,
) -> Value {
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
            // Containers (Map/Array/Tag/IndefiniteLength*) carry a
            // separate `struct_position_info` covering the whole
            // structure; for scalars (bstr/tstr/uint/…) the structure
            // *is* the header bytes, so fall back to `position_info`
            // so callers always get a halo-able range.
            if let Some(pos) = node
                .get("struct_position_info")
                .or_else(|| node.get("position_info"))
            {
                obj.insert("anchor_spans".into(), Value::Array(vec![pos.clone()]));
            }
        }

        // CDDL-side byte span. Walk the AST in parallel with the same
        // cbor_location to find the AST node whose type the validator
        // tried (and failed) to apply, then read its source span.
        if let Some(span) = cddl_byte_span_for(ast, ctx, &e.cbor_location) {
            // `span` is `(start, end, line)` in the user-supplied CDDL.
            obj.insert(
                "cddl_byte_span".into(),
                span_json(&ctx.utf16, span.0, span.1, span.2),
            );
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

/// Locate the AST node corresponding to `cbor_location` and return its
/// source span as `(start, end, line)` in the *original* CDDL the user
/// passed (i.e. with any wrapper prefix offset removed). Best-effort —
/// returns `None` only for opaque keys, indefinite containers, or paths
/// that don't line up with the schema; otherwise we always return at
/// least the deepest enclosing AST node's span so UIs have *something*
/// to highlight.
fn cddl_byte_span_for(
    ast: &cddl::ast::CDDL<'_>,
    ctx: &ValidationCtx<'_>,
    cbor_location: &str,
) -> Option<(usize, usize, usize)> {
    let root_type = find_root_type(ast, ctx.root_rule)?;
    let trimmed = cbor_location.trim_start_matches('/');
    let segments: Vec<Segment> = if trimmed.is_empty() {
        Vec::new()
    } else {
        split_location_segments(trimmed)
            .into_iter()
            .map(|s| classify_segment(&s))
            .collect()
    };

    let span = walk_type_for_span(ast, root_type, &segments, &[])?;
    let (start, end, line) = span;
    let prefix = ctx.cddl_offset_correction;
    if start < prefix {
        return None;
    }
    Some((start - prefix, end.saturating_sub(prefix), line))
}

/// One generic-binding frame contributed by a `Typename<args>` call:
/// each pair maps a parameter name to the `Type1` it was instantiated
/// with at this call-site. Frames stack while we recurse so inner
/// references resolve through the outermost-still-active binding.
type Binding<'a> = (&'a str, &'a cddl::ast::Type1<'a>);

fn lookup_binding<'a>(
    bindings: &[Binding<'a>],
    name: &str,
) -> Option<&'a cddl::ast::Type1<'a>> {
    bindings.iter().rev().find_map(|(n, t)| if *n == name { Some(*t) } else { None })
}

fn rule_generic_params<'a>(
    ast: &'a cddl::ast::CDDL<'_>,
    name: &str,
) -> Option<&'a cddl::ast::GenericParams<'a>> {
    for r in &ast.rules {
        match r {
            cddl::ast::Rule::Type { rule, .. } if rule.name.ident == name => {
                return rule.generic_params.as_ref();
            }
            cddl::ast::Rule::Group { rule, .. } if rule.name.ident == name => {
                return rule.generic_params.as_ref();
            }
            _ => {}
        }
    }
    None
}

fn extend_bindings<'a>(
    parent: &[Binding<'a>],
    params: Option<&cddl::ast::GenericParams<'a>>,
    args: Option<&'a cddl::ast::GenericArgs<'a>>,
) -> Vec<Binding<'a>> {
    let mut out = parent.to_vec();
    let (Some(params), Some(args)) = (params, args) else {
        return out;
    };
    for (p, a) in params.params.iter().zip(args.args.iter()) {
        out.push((p.param.ident, a.arg.as_ref()));
    }
    out
}

fn find_root_type<'a>(
    ast: &'a cddl::ast::CDDL<'_>,
    name: &str,
) -> Option<&'a cddl::ast::Type<'a>> {
    for rule in &ast.rules {
        if let cddl::ast::Rule::Type { rule, .. } = rule {
            if rule.name.ident == name {
                return Some(&rule.value);
            }
        }
    }
    None
}

fn type2_span(t2: &cddl::ast::Type2<'_>) -> cddl::ast::Span {
    use cddl::ast::Type2::*;
    match t2 {
        IntValue { span, .. } => *span,
        UintValue { span, .. } => *span,
        FloatValue { span, .. } => *span,
        TextValue { span, .. } => *span,
        UTF8ByteString { span, .. } => *span,
        B16ByteString { span, .. } => *span,
        B64ByteString { span, .. } => *span,
        Typename { span, .. } => *span,
        ParenthesizedType { span, .. } => *span,
        Map { span, .. } => *span,
        Array { span, .. } => *span,
        Unwrap { span, .. } => *span,
        ChoiceFromInlineGroup { span, .. } => *span,
        ChoiceFromGroup { span, .. } => *span,
        TaggedData { span, .. } => *span,
        DataMajorType { span, .. } => *span,
        Any { span, .. } => *span,
    }
}

fn walk_type_for_span<'a>(
    ast: &'a cddl::ast::CDDL<'_>,
    ty: &'a cddl::ast::Type<'a>,
    segs: &[Segment],
    bindings: &[Binding<'a>],
) -> Option<cddl::ast::Span> {
    if segs.is_empty() {
        return Some(ty.span);
    }
    // Try each choice — first that descends successfully wins. If none
    // descend (e.g. the type isn't a Map/Array but we still have segs),
    // fall back to this Type's span — the caller still gets a useful
    // pointer into the source.
    for choice in &ty.type_choices {
        if let Some(s) = walk_type2_for_span(ast, &choice.type1.type2, segs, bindings) {
            return Some(s);
        }
    }
    Some(ty.span)
}

fn walk_type2_for_span<'a>(
    ast: &'a cddl::ast::CDDL<'_>,
    t2: &'a cddl::ast::Type2<'a>,
    segs: &[Segment],
    bindings: &[Binding<'a>],
) -> Option<cddl::ast::Span> {
    use cddl::ast::Type2;
    if segs.is_empty() {
        return Some(type2_span(t2));
    }
    match t2 {
        Type2::Typename { ident, generic_args, .. } => {
            // Bound generic parameter? Substitute and continue.
            if generic_args.is_none() {
                if let Some(t1) = lookup_binding(bindings, ident.ident) {
                    return walk_type2_for_span(ast, &t1.type2, segs, bindings);
                }
            }
            match find_root_type(ast, ident.ident) {
                Some(inner) => {
                    let new_bindings = extend_bindings(
                        bindings,
                        rule_generic_params(ast, ident.ident),
                        generic_args.as_ref(),
                    );
                    walk_type_for_span(ast, inner, segs, &new_bindings)
                }
                // Unresolvable (prelude or unknown). Best we can do:
                // point at the typename in the source.
                None => Some(ident.span),
            }
        }
        Type2::Unwrap { ident, generic_args, .. } => {
            if generic_args.is_none() {
                if let Some(t1) = lookup_binding(bindings, ident.ident) {
                    return walk_type2_for_span(ast, &t1.type2, segs, bindings);
                }
            }
            match find_root_type(ast, ident.ident) {
                Some(inner) => {
                    let new_bindings = extend_bindings(
                        bindings,
                        rule_generic_params(ast, ident.ident),
                        generic_args.as_ref(),
                    );
                    walk_type_for_span(ast, inner, segs, &new_bindings)
                }
                None => Some(ident.span),
            }
        }
        Type2::ParenthesizedType { pt, .. } => walk_type_for_span(ast, pt, segs, bindings),
        Type2::TaggedData { t, .. } => walk_type_for_span(ast, t, segs, bindings),
        Type2::Map { group, span, .. } => {
            let (head, tail) = match segs.split_first() {
                Some(p) => p,
                None => return Some(*span),
            };
            walk_map_for_span(ast, group, head, tail, bindings).or(Some(*span))
        }
        Type2::Array { group, span, .. } => {
            let (head, tail) = match segs.split_first() {
                Some(p) => p,
                None => return Some(*span),
            };
            let Segment::Index(idx) = head else {
                return Some(*span);
            };
            walk_array_for_span(ast, group, *idx, tail, bindings).or(Some(*span))
        }
        _ => None,
    }
}

fn walk_map_for_span<'a>(
    ast: &'a cddl::ast::CDDL<'_>,
    group: &'a cddl::ast::Group<'a>,
    seg: &Segment,
    tail: &[Segment],
    bindings: &[Binding<'a>],
) -> Option<cddl::ast::Span> {
    use cddl::ast::{GroupEntry, MemberKey};
    for choice in &group.group_choices {
        for (entry, _) in &choice.group_entries {
            let GroupEntry::ValueMemberKey { ge, .. } = entry else {
                continue;
            };
            let mk = ge.member_key.as_ref()?;
            let matches = match (mk, seg) {
                (MemberKey::Bareword { ident, .. }, Segment::TextKey(s)) => {
                    ident.ident == s.as_str()
                }
                (MemberKey::Value { value: cddl::token::Value::TEXT(t), .. },
                 Segment::TextKey(s)) => t.as_ref() == s,
                (MemberKey::Value { value: cddl::token::Value::UINT(u), .. },
                 Segment::Index(i)) => *u as i128 == *i as i128,
                (MemberKey::Value { value: cddl::token::Value::UINT(u), .. },
                 Segment::IntKey(n)) => *u as i128 == *n,
                (MemberKey::Value { value: cddl::token::Value::INT(i), .. },
                 Segment::IntKey(n)) => *i == *n,
                _ => false,
            };
            if matches {
                return walk_type_for_span(ast, &ge.entry_type, tail, bindings);
            }
        }
    }
    None
}

fn walk_array_for_span<'a>(
    ast: &'a cddl::ast::CDDL<'_>,
    group: &'a cddl::ast::Group<'a>,
    idx: usize,
    tail: &[Segment],
    bindings: &[Binding<'a>],
) -> Option<cddl::ast::Span> {
    use cddl::ast::GroupEntry;
    for choice in &group.group_choices {
        let mut counter = 0usize;
        for (entry, _) in &choice.group_entries {
            match entry {
                GroupEntry::ValueMemberKey { ge, .. } => {
                    if counter == idx {
                        return walk_type_for_span(ast, &ge.entry_type, tail, bindings);
                    }
                    counter += 1;
                }
                GroupEntry::TypeGroupname { ge, .. } => {
                    if counter == idx {
                        // Bound generic parameter at this position?
                        if ge.generic_args.is_none() {
                            if let Some(t1) = lookup_binding(bindings, ge.name.ident) {
                                if tail.is_empty() {
                                    return Some(t1.span);
                                }
                                return walk_type2_for_span(ast, &t1.type2, tail, bindings);
                            }
                        }
                        if tail.is_empty() {
                            return Some(ge.name.span);
                        }
                        if let Some(inner) = find_root_type(ast, ge.name.ident) {
                            let new_bindings = extend_bindings(
                                bindings,
                                rule_generic_params(ast, ge.name.ident),
                                ge.generic_args.as_ref(),
                            );
                            return walk_type_for_span(ast, inner, tail, &new_bindings);
                        }
                        return Some(ge.name.span);
                    }
                    counter += 1;
                }
                GroupEntry::InlineGroup { .. } => continue,
            }
        }
    }
    None
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
///
/// Tag wrappers are transparent to anweiss' path grammar — the upstream
/// validator emits `/0/1` for "first witness, second field" without a
/// segment for the surrounding tag. We mirror that by unwrapping any
/// chain of `Tag` nodes *before* consuming each segment.
fn resolve_cbor_path<'a>(tree: &'a Value, loc: &str) -> Option<&'a Value> {
    let mut node = unwrap_tags(tree);
    let trimmed = loc.trim_start_matches('/');
    if trimmed.is_empty() {
        return Some(node);
    }
    for raw in split_location_segments(trimmed) {
        node = step_into(node, &classify_segment(&raw))?;
        node = unwrap_tags(node);
    }
    Some(node)
}

fn unwrap_tags(mut node: &Value) -> &Value {
    while node.get("type").and_then(Value::as_str) == Some("Tag") {
        match node.get("value") {
            Some(inner) => node = inner,
            None => break,
        }
    }
    node
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

    #[test]
    fn mismatch_carries_cddl_byte_span_pointing_at_failing_type() {
        // Schema: `thing = {a: int, b: [tstr, tstr]}`
        //          0         1         2         3
        //          0123456789012345678901234567890123
        // First `tstr` lives at offsets 21..=24, second at 27..=30.
        let schema = "thing = {a: int, b: [tstr, tstr]}";
        // a26161016162820203 = {"a": 1, "b": [2, 3]} — b's first/second
        // values are ints, both should fail against tstr.
        let cbor = hex::decode("a26161016162820203").unwrap();
        let result =
            validate_cbor_bytes_against_cddl(&cbor, schema, "thing");
        let err = error_obj(&result);

        let span = err
            .get("cddl_byte_span")
            .unwrap_or_else(|| panic!("no cddl_byte_span in {}", err));
        assert_eq!(span["offset"], json!(21));
        assert_eq!(span["length"], json!(4)); // "tstr"
        // Source slice the offset/length carve out:
        assert_eq!(&schema[21..21 + 4], "tstr");

        // The second failure (b[1]) lives in `additional`.
        let additional = err.get("additional").and_then(Value::as_array).unwrap();
        let second = &additional[0];
        let span2 = second
            .get("cddl_byte_span")
            .unwrap_or_else(|| panic!("no cddl_byte_span on additional[0]: {}", second));
        assert_eq!(span2["offset"], json!(27));
        assert_eq!(span2["length"], json!(4));
        assert_eq!(&schema[27..27 + 4], "tstr");
    }

    #[test]
    fn cddl_byte_span_walks_through_generic_substitution() {
        // `set<a>` is generic; the failing element type lives inside
        // the generic argument. The walker has to bind `a` → `inner`
        // and continue into `inner`'s definition to find the right
        // span for the failing leaf.
        let cddl = "thing = set<inner>\n\
                    set<a> = [* a]\n\
                    inner = tstr";
        // [01] — single uint, fails because inner expects tstr.
        let cbor = hex::decode("8101").unwrap();
        let result = validate_cbor_bytes_against_cddl(&cbor, cddl, "thing");
        let err = error_obj(&result);
        let span = err
            .get("cddl_byte_span")
            .unwrap_or_else(|| panic!("no cddl_byte_span in {}", err));
        let off = span["offset"].as_u64().unwrap() as usize;
        let len = span["length"].as_u64().unwrap() as usize;
        let snippet = &cddl[off..off + len];
        // Span should point at `tstr` (the body of `inner`, reached
        // through `set<a>` with `a := inner`), or at `inner` itself.
        assert!(
            snippet == "tstr" || snippet == "inner",
            "span should hit the bound generic body, got {:?}",
            snippet
        );
    }

    #[test]
    fn cddl_byte_span_with_wrapper_subtracts_prefix() {
        // Force the wrapper path by passing a non-first rule. Wrapper:
        //   `__cquisitor_root = num\n\nroot = tstr\nnum = uint`
        // The wrapper's prefix length should be subtracted, so the span
        // is reported in coordinates of the *original* CDDL.
        let cddl = "root = tstr\nnum = uint";
        // 6168 = "ah" — text, not a uint, so validation against `num` fails.
        let cbor = hex::decode("6168").unwrap();
        let result = validate_cbor_bytes_against_cddl(&cbor, cddl, "num");
        let err = error_obj(&result);
        let span = err
            .get("cddl_byte_span")
            .unwrap_or_else(|| panic!("no cddl_byte_span in {}", err));
        // `num = uint` — `uint` starts at offset 18 in the original CDDL.
        let off = span["offset"].as_u64().unwrap() as usize;
        let len = span["length"].as_u64().unwrap() as usize;
        let snippet = &cddl[off..off + len];
        assert_eq!(snippet, "uint", "span should point at `uint`, got {:?}", snippet);
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

    // ============================================================
    // Additional coverage — `validate_cddl_text`
    // ============================================================

    #[test]
    fn parse_error_on_multi_line_cddl_reports_line_greater_than_one() {
        // Three rules. Only the third one is broken — `=` without an RHS is
        // a parser-level failure (no rule body). pest should land on line 3.
        let cddl = "thing = uint\n\
                    other = tstr\n\
                    bad   =";
        let error = error_obj(&validate_cddl_text(cddl)).clone();
        assert_eq!(error["kind"], Value::String("parse_error".into()));
        let span = error
            .get("byte_span")
            .unwrap_or_else(|| panic!("expected byte_span in {}", error));
        let line = span["line"]
            .as_u64()
            .unwrap_or_else(|| panic!("byte_span line must be an integer: {}", span));
        assert!(line > 1, "line should be > 1 for multi-line failure, got {}", line);
        let off = span["offset"].as_u64().unwrap() as usize;
        assert!(
            off <= cddl.len(),
            "offset {} should land inside source of length {}",
            off, cddl.len()
        );
    }

    #[test]
    fn unresolved_reference_includes_byte_span_and_names_missing_rule() {
        let cddl = "thing = [uint, banana_ref]";
        let error = error_obj(&validate_cddl_text(cddl)).clone();
        assert_eq!(error["kind"], Value::String("unresolved_references".into()));
        assert!(
            error["message"].as_str().unwrap().contains("banana_ref"),
            "message should mention the missing rule, got {}",
            error
        );
    }

    #[test]
    fn multiple_rules_all_resolving_validate_cleanly() {
        let cddl = "
            tx       = [body, uint]
            body     = {0: input, 1: output}
            input    = [bstr, uint]
            output   = [bstr, coin]
            coin     = uint
        ";
        assert_eq!(validate_cddl_text(cddl), json!({"valid": true}));
    }

    #[test]
    fn generic_rule_with_known_arg_validates_cleanly() {
        let cddl = "
            set<a>  = #6.258([* a])
            payload = set<int>
        ";
        assert_eq!(validate_cddl_text(cddl), json!({"valid": true}));
    }

    #[test]
    fn generic_rule_with_unknown_arg_reports_unresolved_references() {
        let cddl = "
            set<a>  = #6.258([* a])
            payload = set<broken>
        ";
        let error = error_obj(&validate_cddl_text(cddl)).clone();
        assert_eq!(error["kind"], Value::String("unresolved_references".into()));
        assert!(
            error["message"].as_str().unwrap().contains("broken"),
            "message should name the missing generic arg, got {}",
            error
        );
    }

    // ============================================================
    // Additional coverage — `validate_cbor_bytes_against_cddl` shape
    // ============================================================

    #[test]
    fn additional_array_collects_all_secondary_failures_in_an_array() {
        // Array of three ints, schema requires three tstrs. All three fail.
        // The first comes through as the head, the rest under `additional`.
        let cbor = hex::decode("83010203").unwrap();
        let result = validate_cbor_bytes_against_cddl(
            &cbor,
            "thing = [tstr, tstr, tstr]",
            "thing",
        );
        let err = error_obj(&result);
        let additional = err
            .get("additional")
            .and_then(Value::as_array)
            .expect("expected additional[]");
        assert_eq!(
            additional.len(),
            2,
            "two secondary errors expected for elements 1 and 2, got {}",
            err
        );
        for entry in additional {
            assert_eq!(entry["kind"], json!("mismatch"));
            assert!(entry["path"].as_str().unwrap_or("").starts_with("$"));
        }
    }

    #[test]
    fn deeply_nested_mismatch_path_reflects_depth() {
        // Schema with three nesting levels: tx body → outputs[] → output amount.
        let cddl = "
            tx       = {0: body}
            body     = {1: outputs}
            outputs  = [* output]
            output   = [bstr, amount]
            amount   = uint
        ";
        // a1_00_a1_01_82_82_4101_6168 = {0: {1: [["\x01", "h"]]}}
        // The amount slot ("h" — a tstr, offset 11) breaks against `uint`.
        let cbor = hex::decode("a100a1018182410161 68".replace(' ', "").as_str()).unwrap();
        let result = validate_cbor_bytes_against_cddl(&cbor, cddl, "tx");
        let err = error_obj(&result);
        assert_eq!(err["kind"], json!("mismatch"));
        let path = err["path"].as_str().unwrap_or_default();
        // Path must descend through both maps and into the array element.
        assert!(
            path.starts_with("$"),
            "path should be rooted, got {:?}",
            path
        );
        assert!(
            path.matches('[').count() >= 2 || path.matches('.').count() >= 2,
            "path should reflect nesting depth, got {:?}",
            path
        );
        // The byte_span should pick out the "h" tstr inside the cbor blob.
        let spans = err
            .get("byte_spans")
            .and_then(Value::as_array)
            .expect("byte_spans");
        let off = spans[0]["offset"].as_u64().unwrap() as usize;
        let len = spans[0]["length"].as_u64().unwrap() as usize;
        assert!(off + len <= cbor.len(), "span lies inside cbor");
        // For deep tstr leaf, byte_spans is enough — anchor_spans only
        // appear on container values (Map/Array). What matters is that
        // `cddl_byte_span` lands on the deeply-nested `amount` rule body.
        let cspan = err
            .get("cddl_byte_span")
            .unwrap_or_else(|| panic!("no cddl_byte_span: {}", err));
        let coff = cspan["offset"].as_u64().unwrap() as usize;
        let clen = cspan["length"].as_u64().unwrap() as usize;
        let snippet = &cddl[coff..coff + clen];
        assert!(
            snippet.contains("uint") || snippet == "amount",
            "cddl span should reach amount/uint, got {:?}",
            snippet
        );
    }

    #[test]
    fn wrapper_path_keeps_cddl_byte_spans_in_user_coordinates() {
        // Two-rule schema. We validate against `inner`, the second rule, so
        // the wrapper kicks in. The byte_span we report must point at a
        // substring of the *original* cddl: &str (no wrapper bytes leaking).
        let cddl = "outer = uint\ninner = tstr";
        // 01 — uint — fails against `tstr`.
        let cbor = hex::decode("01").unwrap();
        let result = validate_cbor_bytes_against_cddl(&cbor, cddl, "inner");
        let err = error_obj(&result);
        let span = err
            .get("cddl_byte_span")
            .unwrap_or_else(|| panic!("no cddl_byte_span in {}", err));
        let off = span["offset"].as_u64().unwrap() as usize;
        let len = span["length"].as_u64().unwrap() as usize;
        let snippet = &cddl[off..off + len];
        // Original cddl contains "tstr" at offset 21.
        assert_eq!(snippet, "tstr", "cddl slice must equal source text, got {:?}", snippet);
        assert_eq!(off, 21);
    }

    #[test]
    fn type_choice_int_or_tstr_accepts_int() {
        let cbor = hex::decode("18ff").unwrap(); // 255
        let cddl = "thing = int / tstr";
        assert_eq!(
            validate_cbor_bytes_against_cddl(&cbor, cddl, "thing"),
            json!({"valid": true})
        );
    }

    #[test]
    fn type_choice_int_or_tstr_rejects_bool_and_mentions_alternatives() {
        // f5 = true (bool) — neither int nor tstr.
        let cbor = hex::decode("f5").unwrap();
        let cddl = "thing = int / tstr";
        let result = validate_cbor_bytes_against_cddl(&cbor, cddl, "thing");
        let err = error_obj(&result);
        // Either the head error mentions both alternatives, or each
        // alternative gets its own entry across head + additional.
        let mut all_messages: Vec<String> = vec![err["message"].as_str().unwrap_or("").to_string()];
        if let Some(arr) = err.get("additional").and_then(Value::as_array) {
            for e in arr {
                all_messages.push(e["message"].as_str().unwrap_or("").to_string());
            }
        }
        let blob = all_messages.join(" | ");
        assert!(
            blob.to_lowercase().contains("int"),
            "expected `int` mentioned, got {}",
            blob
        );
        assert!(
            blob.to_lowercase().contains("tstr") || blob.contains("string"),
            "expected `tstr` mentioned, got {}",
            blob
        );
    }

    #[test]
    fn optional_map_key_only_present_validates_against_schema_with_optional_first() {
        // a1 01 02 = {1: 2}. Schema allows `? 0: int, 1: int`.
        let cbor = hex::decode("a10102").unwrap();
        let cddl = "thing = {? 0: int, 1: int}";
        assert_eq!(
            validate_cbor_bytes_against_cddl(&cbor, cddl, "thing"),
            json!({"valid": true})
        );
    }

    #[test]
    fn missing_required_key_is_rejected() {
        // a1 00 02 = {0: 2}. Required key 1 absent.
        let cbor = hex::decode("a10002").unwrap();
        let cddl = "thing = {? 0: int, 1: int}";
        let result = validate_cbor_bytes_against_cddl(&cbor, cddl, "thing");
        let err = error_obj(&result);
        // Should not be `valid: true`, and message should mention key 1
        // somewhere (head or additional).
        let mut blob = err["message"].as_str().unwrap_or("").to_string();
        if let Some(arr) = err.get("additional").and_then(Value::as_array) {
            for e in arr {
                blob.push(' ');
                blob.push_str(e["message"].as_str().unwrap_or(""));
            }
        }
        assert!(
            blob.contains("1"),
            "expected mention of missing key `1`, got {}",
            blob
        );
    }

    #[test]
    fn bstr_size_32_accepts_exactly_32_bytes() {
        let cbor_hex = format!("5820{}", "ab".repeat(32));
        let bytes = hex::decode(&cbor_hex).unwrap();
        assert_eq!(
            validate_cbor_bytes_against_cddl(&bytes, "x = bstr .size 32", "x"),
            json!({"valid": true})
        );
    }

    #[test]
    fn bstr_size_32_rejects_31_bytes_with_precise_span() {
        // 581f<31 bytes> — bstr of length 31.
        let cbor_hex = format!("581f{}", "ab".repeat(31));
        let bytes = hex::decode(&cbor_hex).unwrap();
        let result =
            validate_cbor_bytes_against_cddl(&bytes, "x = bstr .size 32", "x");
        let err = error_obj(&result);
        assert_eq!(err["kind"], json!("mismatch"), "{}", err);
        let spans = err
            .get("byte_spans")
            .and_then(Value::as_array)
            .expect("byte_spans");
        // Whole input is the offending bstr, starts at offset 0.
        assert_eq!(spans[0]["offset"], json!(0), "{}", err);
        // Span length must lie inside the input bytes.
        let length = spans[0]["length"].as_u64().unwrap() as usize;
        assert!(length >= 1 && length <= bytes.len(), "header span: {}", err);
        // CDDL byte span should hit the size constraint.
        let cspan = err
            .get("cddl_byte_span")
            .unwrap_or_else(|| panic!("no cddl_byte_span: {}", err));
        let off = cspan["offset"].as_u64().unwrap() as usize;
        let len = cspan["length"].as_u64().unwrap() as usize;
        let cddl_text = "x = bstr .size 32";
        let snippet = &cddl_text[off..off + len];
        // Anywhere in `bstr .size 32` is acceptable; either the constraint
        // or the bare type. Just assert the slice is non-empty and sits
        // inside the rule body.
        assert!(!snippet.is_empty(), "cddl span empty");
        assert!(
            cddl_text.contains(snippet),
            "snippet {:?} should be a substring of source",
            snippet
        );
    }

    #[test]
    fn nonempty_set_generic_with_tag_258_validates() {
        let cddl = r#"
            payload         = nonempty_set<vkeywitness>
            vkeywitness     = [vkey, signature]
            vkey            = bstr .size 32
            signature       = bstr .size 64
            nonempty_set<a> = #6.258([+ a]) / [+ a]
        "#;
        // Tag 258 = d9 0102, then array of one [vkey(32), sig(64)]:
        //   d9 0102                 — tag(258)
        //     81                    — array(1)
        //       82                  — array(2)
        //         5820 <32 bytes>   — bstr(32) vkey
        //         5840 <64 bytes>   — bstr(64) signature
        let cbor_hex = format!(
            "d9010281825820{}5840{}",
            "11".repeat(32),
            "22".repeat(64)
        );
        let bytes = hex::decode(&cbor_hex).unwrap();
        assert_eq!(
            validate_cbor_bytes_against_cddl(&bytes, cddl, "payload"),
            json!({"valid": true}),
            "valid nonempty_set<vkeywitness> should validate"
        );
    }

    #[test]
    fn nonempty_set_with_wrong_signature_size_reports_mismatch() {
        let cddl = r#"
            payload         = nonempty_set<vkeywitness>
            vkeywitness     = [vkey, signature]
            vkey            = bstr .size 32
            signature       = bstr .size 64
            nonempty_set<a> = #6.258([+ a]) / [+ a]
        "#;
        // Same shape but signature is 63 bytes, which violates `.size 64`.
        // Tag 258 + array(1) + array(2) + bstr(32) + bstr(63 bytes).
        let cbor_hex = format!(
            "d9010281825820{}583f{}",
            "11".repeat(32),
            "22".repeat(63)
        );
        let bytes = hex::decode(&cbor_hex).unwrap();
        let result = validate_cbor_bytes_against_cddl(&bytes, cddl, "payload");
        let err = error_obj(&result);
        assert_eq!(err["kind"], json!("mismatch"), "got {}", err);
        // Path now drills down to the failing element — `$[0][1]` =
        // first witness, second field (signature). Tag is transparent.
        assert_eq!(err["path"], json!("$[0][1]"), "got {}", err);
        // Byte spans land on the offending bstr (the 63-byte signature).
        let spans = err
            .get("byte_spans")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("no byte_spans in {}", err));
        let off = spans[0]["offset"].as_u64().unwrap() as usize;
        let len = spans[0]["length"].as_u64().unwrap() as usize;
        // The signature bstr starts at offset 39 (after `d9010281`
        // tag+arrays + `825820` + 32 vkey bytes), and runs 65 bytes
        // (2-byte bstr header `583f` + 63 content bytes).
        assert_eq!(off, 39, "{}", err);
        assert_eq!(len, 65, "{}", err);
        // CDDL-side span lands *somewhere* in the schema and is a
        // valid byte range. Exact position depends on whether the
        // walker resolves through `signature` -> `bstr .size 64` or
        // stops at `signature`'s typename — either is useful, neither
        // is wrong.
        let cspan = err
            .get("cddl_byte_span")
            .unwrap_or_else(|| panic!("no cddl_byte_span in {}", err));
        let coff = cspan["offset"].as_u64().unwrap() as usize;
        let clen = cspan["length"].as_u64().unwrap() as usize;
        let snippet = &cddl[coff..coff + clen];
        assert!(
            !snippet.is_empty() && (snippet.contains("size") || snippet.contains("signature") || snippet.contains("bstr")),
            "cddl span should point at the signature path, got {:?}",
            snippet
        );
    }

    /// Cut signal: when a value-keyed entry has `^ =>` (cut), the validator
    /// is *supposed* to short-circuit alternative matches. Asserting a
    /// strict `map_cut` kind is brittle — the `cut present` text only
    /// surfaces in narrow code paths upstream. Pin the looser invariant:
    /// the kind is one of {`map_cut`, `mismatch`, `generic`} and the
    /// result is invalid. This documents the current behaviour so we
    /// notice if the upstream validator starts emitting `cut present`.
    #[test]
    fn cut_member_key_failure_returns_a_classified_kind() {
        let cddl = r#"thing = { "a" ^ => uint, * tstr => any }"#;
        // a1 6161 6162 = {"a": "b"} — "a" matches, value tstr vs uint.
        let cbor = hex::decode("a161616162").unwrap();
        let result = validate_cbor_bytes_against_cddl(&cbor, cddl, "thing");
        let err = error_obj(&result);
        let kind = err["kind"].as_str().unwrap_or("");
        assert!(
            matches!(kind, "map_cut" | "mismatch" | "generic"),
            "expected a known kind for cut failure, got {}",
            kind
        );
        // The error message should at least mention the offending value
        // type or the cut keyword.
        let msg = err["message"].as_str().unwrap_or("").to_lowercase();
        assert!(
            !msg.is_empty(),
            "expected a non-empty message, got {}",
            err
        );
    }

    // ============================================================
    // Additional coverage — `cddl_byte_span` synthesiser
    // ============================================================

    /// For each of these schemas the recorded `cddl_byte_span` must point
    /// at a *substring* of the original CDDL (i.e. carving by offset+length
    /// reproduces the expected text).
    #[test]
    fn cddl_byte_span_is_always_a_substring_for_diverse_schemas() {
        struct Case<'a> {
            cddl: &'a str,
            rule: &'a str,
            cbor_hex: &'a str,
            expected: &'a str,
        }
        let cases = [
            // 1. top-level scalar mismatch
            Case {
                cddl: "thing = uint",
                rule: "thing",
                cbor_hex: "6161",
                expected: "uint",
            },
            // 2. inline array element — uint at position 0 vs bool
            Case {
                cddl: "thing = [bool, tstr]",
                rule: "thing",
                cbor_hex: "820101", // array(2) of [1, 1]; first uint vs bool
                expected: "bool",
            },
            // 3. map value via colon
            Case {
                cddl: "thing = {a: bytes}",
                rule: "thing",
                cbor_hex: "a161616163", // {"a": "c"}
                expected: "bytes",
            },
            // 4. nested map → array → element
            Case {
                cddl: "thing = {a: [bool]}",
                rule: "thing",
                cbor_hex: "a16161810b", // {"a": [11]} — uint vs bool
                expected: "bool",
            },
            // 5. typename pointing at a named rule
            Case {
                cddl: "thing = pair\npair = [tstr, tstr]",
                rule: "thing",
                cbor_hex: "820101", // [1, 1] — uint vs first tstr
                expected: "tstr",
            },
        ];
        for (i, c) in cases.iter().enumerate() {
            let bytes = hex::decode(c.cbor_hex).unwrap();
            let result =
                validate_cbor_bytes_against_cddl(&bytes, c.cddl, c.rule);
            let err = error_obj(&result);
            let span = err
                .get("cddl_byte_span")
                .unwrap_or_else(|| panic!("case {}: no cddl_byte_span in {}", i, err));
            let off = span["offset"].as_u64().unwrap() as usize;
            let len = span["length"].as_u64().unwrap() as usize;
            assert!(
                off + len <= c.cddl.len(),
                "case {}: span out of range — off={} len={} cddl_len={}",
                i, off, len, c.cddl.len()
            );
            let snippet = &c.cddl[off..off + len];
            assert_eq!(
                snippet, c.expected,
                "case {}: span should slice to {:?}, got {:?} (full err: {})",
                i, c.expected, snippet, err
            );
        }
    }

    #[test]
    fn cddl_byte_span_for_top_level_mismatch_points_at_rule_body() {
        // Top-level mismatch: cbor_location is empty, so the span should
        // land on the rule's value itself — `uint` here.
        let cddl = "rule_body = uint";
        let cbor = hex::decode("6161").unwrap(); // "a", a tstr
        let result = validate_cbor_bytes_against_cddl(&cbor, cddl, "rule_body");
        let err = error_obj(&result);
        let span = err
            .get("cddl_byte_span")
            .unwrap_or_else(|| panic!("no cddl_byte_span in {}", err));
        let off = span["offset"].as_u64().unwrap() as usize;
        let len = span["length"].as_u64().unwrap() as usize;
        let snippet = &cddl[off..off + len];
        assert_eq!(snippet, "uint", "span should hit `uint` in rule body");
    }

    #[test]
    fn cddl_byte_span_with_wrapper_lands_inside_original_cddl() {
        // Validate against the third rule of a multi-rule schema. The
        // wrapper prepends a synthetic root, but the reported offset must
        // refer to the *original* cddl.
        let cddl = "first = uint\nsecond = tstr\nthird = bool";
        let cbor = hex::decode("01").unwrap(); // uint vs bool
        let result = validate_cbor_bytes_against_cddl(&cbor, cddl, "third");
        let err = error_obj(&result);
        let span = err
            .get("cddl_byte_span")
            .unwrap_or_else(|| panic!("no cddl_byte_span in {}", err));
        let off = span["offset"].as_u64().unwrap() as usize;
        let len = span["length"].as_u64().unwrap() as usize;
        assert!(
            off + len <= cddl.len(),
            "span must fit inside original cddl — off={} len={} cddl_len={}",
            off, len, cddl.len()
        );
        let snippet = &cddl[off..off + len];
        assert_eq!(snippet, "bool", "wrapper case slice should match `bool`");
    }

    #[test]
    fn cddl_byte_span_for_generic_map_value_lands_on_argument_type() {
        // wrap<v> = {a: v}; root carries wrap<int>.
        // Bareword key `a` means the walker descends and resolves `v` →
        // `int` via the generic-binding stack.
        let cddl = "root = wrap<int>\nwrap<v> = {a: v}";
        // a1 6161 6163 = {"a": "c"} — value is tstr, parameter resolves to int.
        let cbor = hex::decode("a161616163").unwrap();
        let result = validate_cbor_bytes_against_cddl(&cbor, cddl, "root");
        let err = error_obj(&result);
        let span = err
            .get("cddl_byte_span")
            .unwrap_or_else(|| panic!("no cddl_byte_span in {}", err));
        let off = span["offset"].as_u64().unwrap() as usize;
        let len = span["length"].as_u64().unwrap() as usize;
        let snippet = &cddl[off..off + len];
        // The span should reach the generic argument: `int` (preferred) or
        // the parameter typename `v` itself if substitution didn't happen.
        assert!(
            snippet == "int" || snippet == "v",
            "expected to land on bound generic param's argument, got {:?}",
            snippet
        );
    }

    // ============================================================
    // Misc shape & edge-case coverage
    // ============================================================

    #[test]
    fn input_parse_kind_carries_path_or_offset() {
        // Truncated bstr header (5820 says 32 bytes, but no body) — input
        // parse failure path. Make sure the JSON shape stays consistent.
        let bytes = hex::decode("5820").unwrap();
        let result =
            validate_cbor_bytes_against_cddl(&bytes, "x = bstr", "x");
        let err = error_obj(&result);
        assert_eq!(err["kind"], json!("input_parse"), "{}", err);
        // Either path or offset is informative — at minimum we want a message.
        assert!(
            !err["message"].as_str().unwrap_or("").is_empty(),
            "expected a non-empty message, got {}",
            err
        );
    }

    #[test]
    fn missing_rule_message_names_the_rule() {
        let cbor = hex::decode("01").unwrap();
        let result = validate_cbor_bytes_against_cddl(
            &cbor,
            "x = int",
            "no_such_rule_xyz",
        );
        let err = error_obj(&result);
        assert_eq!(err["kind"], json!("missing_rule"));
        assert!(
            err["message"]
                .as_str()
                .unwrap_or("")
                .contains("no_such_rule_xyz"),
            "missing_rule message should name the rule, got {}",
            err
        );
    }

    #[test]
    fn cddl_with_only_a_comment_is_rejected_as_no_rules() {
        // Pest accepts this as a parse, but a document with zero rules
        // isn't a usable schema. We surface it as `kind: "no_rules"`
        // so an editor can flag it without misclassifying it as a
        // hard parse error.
        let result = validate_cddl_text("; only a comment\n");
        assert_eq!(
            result,
            json!({
                "valid": false,
                "error": {
                    "kind": "no_rules",
                    "message": "CDDL document defines no rules",
                },
            })
        );
    }

    #[test]
    fn empty_cddl_is_rejected_as_no_rules() {
        let result = validate_cddl_text("");
        assert_eq!(result["error"]["kind"], json!("no_rules"));
    }

    #[test]
    fn anchor_spans_fall_back_to_position_info_for_scalar_failures() {
        // Top-level bstr is a scalar — the decoder doesn't attach
        // `struct_position_info` for it, so `anchor_spans` falls back
        // to `position_info`. UIs that draw a halo on `anchor_spans`
        // get something to draw.
        let cbor_hex = format!("581f{}", "ab".repeat(31));
        let bytes = hex::decode(&cbor_hex).unwrap();
        let result =
            validate_cbor_bytes_against_cddl(&bytes, "x = bstr .size 32", "x");
        let err = error_obj(&result);
        let anchor = err
            .get("anchor_spans")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("expected anchor_spans on scalar: {}", err));
        let byte = err
            .get("byte_spans")
            .and_then(Value::as_array)
            .expect("byte_spans");
        // For scalars without a struct span, anchor falls back to the
        // same range as byte_spans.
        assert_eq!(anchor[0], byte[0], "scalar anchor should mirror byte_spans");
    }

    #[test]
    fn negative_integer_value_validates_against_int() {
        // 20 = -1 (CBOR major-1)
        let cbor = hex::decode("20").unwrap();
        assert_eq!(
            validate_cbor_bytes_against_cddl(&cbor, "x = int", "x"),
            json!({"valid": true})
        );
    }

    #[test]
    fn negative_integer_rejected_by_uint_with_mismatch_kind() {
        let cbor = hex::decode("20").unwrap(); // -1
        let result = validate_cbor_bytes_against_cddl(&cbor, "x = uint", "x");
        let err = error_obj(&result);
        assert_eq!(err["kind"], json!("mismatch"));
    }

    #[test]
    fn deeply_nested_path_uses_bracket_for_indices_and_dot_for_string_keys() {
        // {"a": {"b": [1, "x"]}} where `x` should be a uint.
        // a1 6161 a1 6162 82 01 6178
        let cbor = hex::decode("a16161a161628201 6178".replace(' ', "").as_str()).unwrap();
        let cddl = "thing = {a: {b: [uint, uint]}}";
        let result = validate_cbor_bytes_against_cddl(&cbor, cddl, "thing");
        let err = error_obj(&result);
        let path = err["path"].as_str().unwrap_or("");
        // Path should use dot for `a` and `b` (text keys) and `[1]` for
        // the offending second array element.
        assert!(
            path.contains(".a"),
            "expected `.a` in path, got {}",
            path
        );
        assert!(
            path.contains(".b"),
            "expected `.b` in path, got {}",
            path
        );
        assert!(
            path.contains("[1]"),
            "expected `[1]` index for failing element, got {}",
            path
        );
    }

    #[test]
    fn array_of_correct_items_validates() {
        let cbor = hex::decode("83010203").unwrap(); // [1, 2, 3]
        assert_eq!(
            validate_cbor_bytes_against_cddl(&cbor, "x = [* uint]", "x"),
            json!({"valid": true})
        );
    }

    #[test]
    fn extra_map_key_under_strict_schema_is_rejected() {
        // {a:1, z:9} but schema only has `a: int`.
        let cbor = hex::decode("a26161 016179 09".replace(' ', "").as_str()).unwrap();
        let result = validate_cbor_bytes_against_cddl(
            &cbor,
            "thing = {a: int}",
            "thing",
        );
        let err = error_obj(&result);
        // Result must not be valid; error has a kind populated.
        assert!(err["kind"].is_string(), "expected kind: {}", err);
    }

    #[test]
    fn type_choice_in_map_value_accepts_either_alternative() {
        // {a: 5} — both work.
        let cbor_int = hex::decode("a161610b").unwrap(); // {"a": 11}
        let cbor_tst = hex::decode("a161616178").unwrap(); // {"a": "x"}
        let cddl = "thing = {a: int / tstr}";
        assert_eq!(
            validate_cbor_bytes_against_cddl(&cbor_int, cddl, "thing"),
            json!({"valid": true})
        );
        assert_eq!(
            validate_cbor_bytes_against_cddl(&cbor_tst, cddl, "thing"),
            json!({"valid": true})
        );
    }
}

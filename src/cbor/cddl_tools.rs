//! IDE-grade primitives for CDDL: outline, references, symbol-at-offset,
//! and format. Built on top of the same `anweiss/cddl` AST the validator
//! and decoder use, so byte spans line up with everything else.

use std::collections::HashSet;

use cddl::ast::{
    GenericArgs, GenericParams, Group, GroupChoice, GroupEntry, Identifier, MemberKey,
    NonMemberKey, Rule, Type, Type1, Type2, CDDL,
};
use serde_json::{json, Value};

use crate::cbor::document_cache;
use crate::cbor::source_index::{span_json, Utf16Index};
use crate::js_error::JsError;

// ============================================================
// Outline — list of top-level rules with their source spans.
// ============================================================

/// `[{name, kind, is_alternate, span, name_span}]` for top-level rules.
///
/// `/=` / `//=` alternates share a name; `is_alternate` marks extensions.
pub fn outline(cddl: &str) -> Result<Value, JsError> {
    with_parsed(cddl, |ast| Ok(outline_ast(ast, cddl)))
}

fn outline_ast(ast: &CDDL<'_>, cddl: &str) -> Value {
    let idx = Utf16Index::new(cddl);
    let rules = ast
        .rules
        .iter()
        .map(|r| {
            let (kind, is_alternate) = match r {
                Rule::Type { rule, .. } => ("type", rule.is_type_choice_alternate),
                Rule::Group { rule, .. } => ("group", rule.is_group_choice_alternate),
            };
            json!({
                "name": rule_name(r),
                "kind": kind,
                "is_alternate": is_alternate,
                "span": span_to_json(&idx, rule_span(r)),
                "name_span": span_to_json(&idx, rule_name_span(r)),
            })
        })
        .collect();
    Value::Array(rules)
}

fn rule_span(r: &Rule<'_>) -> cddl::ast::Span {
    match r {
        Rule::Type { span, .. } => *span,
        Rule::Group { span, .. } => *span,
    }
}

/// Rule name including `$`/`&` sigil (matches `name_span` text).
fn rule_name(r: &Rule<'_>) -> String {
    match r {
        Rule::Type { rule, .. } => rule.name.to_string(),
        Rule::Group { rule, .. } => rule.name.to_string(),
    }
}

fn rule_name_span(r: &Rule<'_>) -> cddl::ast::Span {
    match r {
        Rule::Type { rule, .. } => rule.name.span,
        Rule::Group { rule, .. } => rule.name.span,
    }
}

// ============================================================
// References — definition span + every use of a rule name.
// ============================================================

/// Returns `{definition: span | null, uses: span[]}` for `name`. Walks
/// every Typename / Unwrap / ChoiceFromGroup / TypeGroupname and
/// matches by the identifier's full text, sigil included.
pub fn references(cddl: &str, name: &str) -> Result<Value, JsError> {
    with_parsed(cddl, |ast| Ok(references_ast(ast, cddl, name)))
}

fn references_ast(ast: &CDDL<'_>, cddl: &str, name: &str) -> Value {
    let definition = ast
        .rules
        .iter()
        .find(|r| rule_name(r) == name)
        .map(rule_name_span);

    let mut uses: Vec<cddl::ast::Span> = Vec::new();
    for rule in &ast.rules {
        walk_rule(rule, &mut |ident: &Identifier<'_>, _role| {
            if ident.to_string() == name {
                uses.push(ident.span);
            }
        });
    }

    let idx = Utf16Index::new(cddl);
    json!({
        "definition": definition.map(|s| span_to_json(&idx, s)).unwrap_or(Value::Null),
        "uses": uses.into_iter().map(|s| span_to_json(&idx, s)).collect::<Vec<_>>(),
    })
}

// ============================================================
// Symbol at offset — what's under the cursor?
// ============================================================

/// Identifier at `offset`, or `null` (with `definition_span` for uses).
pub fn symbol_at(cddl: &str, offset: usize) -> Result<Value, JsError> {
    with_parsed(cddl, |ast| Ok(symbol_at_ast(ast, cddl, offset)))
}

fn symbol_at_ast(ast: &CDDL<'_>, cddl: &str, offset: usize) -> Value {
    let idx = Utf16Index::new(cddl);

    // First, see if offset lands on a rule name (definition).
    for rule in &ast.rules {
        let name_span = rule_name_span(rule);
        if span_contains(name_span, offset) {
            let kind = match rule {
                Rule::Type { .. } => "type",
                Rule::Group { .. } => "group",
            };
            return json!({
                "name": rule_name(rule),
                "kind": kind,
                "role": "definition",
                "span": span_to_json(&idx, name_span),
                "definition_span": span_to_json(&idx, name_span),
                "rule_span": span_to_json(&idx, rule_span(rule)),
            });
        }
    }

    // Otherwise look for a use whose ident span contains the offset.
    let mut found: Option<Identifier<'_>> = None;
    for rule in &ast.rules {
        walk_rule(rule, &mut |ident: &Identifier<'_>, _role| {
            if found.is_none() && span_contains(ident.span, offset) {
                found = Some(ident.clone());
            }
        });
        if found.is_some() {
            break;
        }
    }

    let Some(ident) = found else {
        return Value::Null;
    };
    let name = ident.to_string();

    let definition = ast
        .rules
        .iter()
        .find(|r| rule_name(r) == name)
        .map(|r| (rule_name_span(r), rule_span(r)));

    let (definition_span, rule_span_value) = match definition {
        Some((d, r)) => (Some(d), Some(r)),
        None => (None, None),
    };

    json!({
        "name": name,
        "kind": if rule_span_value.is_some() { "rule_reference" } else { "prelude_or_unknown" },
        "role": "use",
        "span": span_to_json(&idx, ident.span),
        "definition_span": definition_span.map(|s| span_to_json(&idx, s)).unwrap_or(Value::Null),
        "rule_span": rule_span_value.map(|s| span_to_json(&idx, s)).unwrap_or(Value::Null),
    })
}

// ============================================================
// Format — pretty-print via the AST's Display impl.
// ============================================================

/// Reformat via parse + `Display` (format-on-save).
///
/// Preserves comments (text and order) and literal denotation — float
/// fractions stay, since floats and ints match different CBOR. Same
/// nesting bound as the other IDE primitives.
pub fn format(cddl: &str) -> Result<String, JsError> {
    with_parsed(cddl, |ast| Ok(format!("{}", ast)))
}

// ============================================================
// Unresolved references
// ============================================================

/// The RFC 8610 Appendix D prelude. A name in this list resolves without a rule
/// defining it. Kept in step with the parser's own list — a name missing
/// here is reported as unresolved even though the schema is valid.
const STANDARD_PRELUDE: &[&str] = &[
    "any",
    "uint",
    "nint",
    "int",
    "bstr",
    "bytes",
    "tstr",
    "text",
    "tdate",
    "time",
    "number",
    "biguint",
    "bignint",
    "bigint",
    "integer",
    "unsigned",
    "decfrac",
    "bigfloat",
    "eb64url",
    "eb64legacy",
    "eb16",
    "encoded-cbor",
    "uri",
    "b64url",
    "b64legacy",
    "regexp",
    "mime-message",
    "cbor-any",
    "float16",
    "float32",
    "float64",
    "float16-32",
    "float32-64",
    "float",
    "false",
    "true",
    "bool",
    "nil",
    "null",
    "undefined",
];

/// Unresolved references in source order (all occurrences).
///
/// Enrichment only — the AST can miss some refs (e.g. `#6.<name>`); the
/// parser remains authoritative for resolve/fail.
pub(crate) fn unresolved_references(ast: &CDDL<'_>) -> Vec<(String, cddl::ast::Span)> {
    let defined: HashSet<&str> = ast
        .rules
        .iter()
        .map(|r| match r {
            Rule::Type { rule, .. } => rule.name.ident,
            Rule::Group { rule, .. } => rule.name.ident,
        })
        .collect();

    let mut unresolved = Vec::new();
    for rule in &ast.rules {
        let generic_params = match rule {
            Rule::Type { rule, .. } => &rule.generic_params,
            Rule::Group { rule, .. } => &rule.generic_params,
        };
        // Generic parameters are scoped to the rule that binds them.
        let in_scope: HashSet<&str> = generic_params
            .iter()
            .flat_map(|gp| gp.params.iter().map(|p| p.param.ident))
            .collect();

        walk_rule(rule, &mut |ident: &Identifier<'_>, role| {
            if role != IdentRole::Reference {
                return;
            }
            // Socket/plug names are resolved by whatever plugs into them,
            // which may live in another document.
            if ident.socket.is_some() || ident.ident.starts_with('$') {
                return;
            }
            if defined.contains(ident.ident)
                || in_scope.contains(ident.ident)
                || STANDARD_PRELUDE.contains(&ident.ident)
            {
                return;
            }
            unresolved.push((ident.to_string(), ident.span));
        });
    }
    unresolved
}

// ============================================================
// Helpers
// ============================================================

/// Parse without resolving refs (IDE mid-edit). Parse / nesting → throw.
fn with_parsed<R>(
    cddl: &str,
    f: impl FnOnce(&CDDL<'_>) -> Result<R, JsError>,
) -> Result<R, JsError> {
    document_cache::with_ast_unchecked(cddl, |parsed| match parsed {
        Ok(ast) => f(ast),
        Err(e) => Err(e.to_js_error()),
    })
}

fn span_to_json(idx: &Utf16Index, s: cddl::ast::Span) -> Value {
    let (start, end, line) = s;
    span_json(idx, start, end, line)
}

fn span_contains(s: cddl::ast::Span, offset: usize) -> bool {
    let (start, end, _line) = s;
    offset >= start && offset < end
}

// ----- Identifier walker -----

/// What an identifier is doing where the walker found it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum IdentRole {
    /// A name used in type or group position. Resolves to a rule, a
    /// generic parameter in scope, or a prelude type.
    Reference,
    /// A generic parameter binder in a rule head. Introduces a name for
    /// the rule body rather than referring to one.
    GenericParamBinder,
}

/// Callback invoked once per identifier, in source order.
type IdentVisitor<'a, 'v> = &'v mut dyn FnMut(&Identifier<'a>, IdentRole);

fn walk_rule<'a>(rule: &Rule<'a>, visit: IdentVisitor<'a, '_>) {
    match rule {
        Rule::Type { rule, .. } => {
            walk_generic_params(&rule.generic_params, visit);
            walk_type(&rule.value, visit);
        }
        Rule::Group { rule, .. } => {
            walk_generic_params(&rule.generic_params, visit);
            walk_group_entry(&rule.entry, visit);
        }
    }
}

fn walk_generic_params<'a>(gp: &Option<GenericParams<'a>>, visit: IdentVisitor<'a, '_>) {
    if let Some(gp) = gp {
        for p in &gp.params {
            visit(&p.param, IdentRole::GenericParamBinder);
        }
    }
}

fn walk_generic_args<'a>(args: &Option<GenericArgs<'a>>, visit: IdentVisitor<'a, '_>) {
    if let Some(args) = args {
        for a in &args.args {
            walk_type1(&a.arg, visit);
        }
    }
}

fn walk_type<'a>(ty: &Type<'a>, visit: IdentVisitor<'a, '_>) {
    for choice in &ty.type_choices {
        walk_type1(&choice.type1, visit);
    }
}

fn walk_type1<'a>(t1: &Type1<'a>, visit: IdentVisitor<'a, '_>) {
    walk_type2(&t1.type2, visit);
    // Control operator targets and range bounds are types in their own
    // right: `bstr .size limit` and `0..maxv` both reference a rule.
    if let Some(operator) = &t1.operator {
        walk_type2(&operator.type2, visit);
    }
}

fn walk_type2<'a>(t2: &Type2<'a>, visit: IdentVisitor<'a, '_>) {
    match t2 {
        Type2::Typename {
            ident,
            generic_args,
            ..
        }
        | Type2::Unwrap {
            ident,
            generic_args,
            ..
        }
        | Type2::ChoiceFromGroup {
            ident,
            generic_args,
            ..
        } => {
            visit(ident, IdentRole::Reference);
            walk_generic_args(generic_args, visit);
        }
        Type2::ParenthesizedType { pt, .. } => walk_type(pt, visit),
        Type2::TaggedData { t, .. } => walk_type(t, visit),
        Type2::Map { group, .. }
        | Type2::Array { group, .. }
        | Type2::ChoiceFromInlineGroup { group, .. } => walk_group(group, visit),
        _ => {}
    }
}

fn walk_group<'a>(g: &Group<'a>, visit: IdentVisitor<'a, '_>) {
    for choice in &g.group_choices {
        walk_group_choice(choice, visit);
    }
}

fn walk_group_choice<'a>(gc: &GroupChoice<'a>, visit: IdentVisitor<'a, '_>) {
    for (entry, _) in &gc.group_entries {
        walk_group_entry(entry, visit);
    }
}

fn walk_group_entry<'a>(ge: &GroupEntry<'a>, visit: IdentVisitor<'a, '_>) {
    match ge {
        GroupEntry::ValueMemberKey { ge, .. } => {
            if let Some(mk) = &ge.member_key {
                walk_member_key(mk, visit);
            }
            walk_type(&ge.entry_type, visit);
        }
        GroupEntry::TypeGroupname { ge, .. } => {
            visit(&ge.name, IdentRole::Reference);
            walk_generic_args(&ge.generic_args, visit);
        }
        GroupEntry::InlineGroup { group, .. } => walk_group(group, visit),
    }
}

fn walk_member_key<'a>(mk: &MemberKey<'a>, visit: IdentVisitor<'a, '_>) {
    match mk {
        MemberKey::Type1 { t1, .. } => walk_type1(t1, visit),
        // A non-member key wraps a whole group or type in key position;
        // whatever it holds is an ordinary reference.
        MemberKey::NonMemberKey { non_member_key, .. } => match non_member_key {
            NonMemberKey::Group(group) => walk_group(group, visit),
            NonMemberKey::Type(ty) => walk_type(ty, visit),
        },
        // A bareword key is a literal text key, not a reference, and a
        // value key is a literal.
        MemberKey::Bareword { .. } | MemberKey::Value { .. } => {}
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Keep `bareword : type` — rewriting to `=>` breaks the bareword.
    #[test]
    fn format_keeps_bareword_key_form_when_value_is_map() {
        let src = "block = [aux: {* int => uint}]";
        let formatted = format(src).expect("input parses");
        assert!(
            formatted.contains("aux:") && !formatted.contains("aux =>"),
            "bareword member key must stay in `:` form, got {:?}",
            formatted
        );
        // The formatted text must still resolve every reference.
        let reparse = validate_cddl_text_via_super(&formatted);
        assert_eq!(
            reparse,
            json!({ "valid": true }),
            "formatted output should re-validate cleanly, got {}",
            reparse
        );
    }

    /// `format()` must be an identity on validity for a schema the size
    /// of a real protocol's: whatever goes in valid comes out valid.
    #[test]
    fn ledger_cddl_round_trips_through_format() {
        let src = crate::cbor::test_fixtures::ledger_cddl();
        let formatted = format(src).expect("the ledger schema itself parses and formats");
        let reparse = validate_cddl_text_via_super(&formatted);
        assert_eq!(
            reparse,
            json!({ "valid": true }),
            "formatted ledger schema should re-validate cleanly, got {}",
            reparse
        );
    }

    /// Formatting must not discard comments: a schema's documentation is
    /// part of its content, and `format` is offered as a non-destructive
    /// rewrite.
    #[test]
    fn format_preserves_every_comment_in_a_large_schema() {
        let src = crate::cbor::test_fixtures::ledger_cddl();
        let formatted = format(src).expect("input parses");
        let before = src.matches(';').count();
        assert!(
            before > 0,
            "the fixture schema carries no comments to preserve"
        );
        let after = formatted.matches(';').count();
        assert_eq!(
            after,
            before,
            "format dropped {} of {} comment markers",
            before.saturating_sub(after),
            before
        );
    }

    /// Every schema version: comments survive format (and a second pass)
    /// in order.
    #[test]
    fn format_preserves_comment_text_and_order_in_every_schema_version() {
        for (version, src) in crate::cbor::test_fixtures::schema_suite() {
            let formatted =
                format(src).unwrap_or_else(|e| panic!("{} should format: {:?}", version, e));
            assert_eq!(
                comment_payloads(&formatted),
                comment_payloads(src),
                "{} schema lost or altered a comment",
                version
            );

            let again = format(&formatted)
                .unwrap_or_else(|e| panic!("{} should re-format: {:?}", version, e));
            assert_eq!(
                comment_payloads(&again),
                comment_payloads(src),
                "{} schema lost a comment on the second pass",
                version
            );
            assert_eq!(again, formatted, "{} schema formats unstably", version);
        }
    }

    /// The comment payloads of a CDDL document, in source order. A semicolon
    /// inside a text or byte-string literal does not start a comment.
    fn comment_payloads(cddl: &str) -> Vec<String> {
        let bytes = cddl.as_bytes();
        let mut payloads = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b';' => {
                    let start = i;
                    i += 1;
                    while i < bytes.len() && bytes[i] != b'\n' {
                        i += 1;
                    }
                    payloads.push(cddl[start + 1..i].trim_end().to_string());
                }
                quote @ (b'"' | b'\'') => {
                    i += 1;
                    while i < bytes.len() && bytes[i] != quote {
                        if bytes[i] == b'\\' {
                            i += 1;
                        }
                        i += 1;
                    }
                    i += 1;
                }
                _ => i += 1,
            }
        }

        payloads
    }

    /// Every version of the ledger schema survives a format round-trip.
    #[test]
    fn every_schema_version_round_trips_through_format() {
        for (version, src) in crate::cbor::test_fixtures::schema_suite() {
            let formatted =
                format(src).unwrap_or_else(|e| panic!("{} schema should format: {:?}", version, e));
            let reparse = validate_cddl_text_via_super(&formatted);
            assert_eq!(
                reparse,
                json!({ "valid": true }),
                "formatted {} schema should re-validate cleanly, got {}",
                version,
                reparse
            );
        }
    }

    /// Format must keep float fractions so validation verdicts stay put.
    #[test]
    fn format_preserves_the_verdicts_of_a_schema_with_float_literals() {
        // f93c00 = 1.0, f93e00 = 1.5, f94000 = 2.0, f94200 = 3.0.
        for (schema, cbor_hex, expected) in [
            ("start = 2.0", "f94000", true),
            ("start = 2.0", "02", false),
            ("start = 1.0..2.0", "f93e00", true),
            ("start = 1.0..2.0", "01", false),
            ("start = float .eq 3.0", "f94200", true),
            ("start = { 1.0 => int }", "a1f93c0001", true),
            ("start = { 1.0 => int }", "a10101", false),
        ] {
            let bytes = hex::decode(cbor_hex).expect("test vector is hex");
            let before =
                crate::cbor::validation::validate_cbor_bytes_against_cddl(&bytes, schema, "start");
            assert_eq!(
                before["valid"],
                json!(expected),
                "{} against {} answered unexpectedly: {}",
                schema,
                cbor_hex,
                before
            );

            let formatted =
                format(schema).unwrap_or_else(|e| panic!("{} should format: {:?}", schema, e));
            let after = crate::cbor::validation::validate_cbor_bytes_against_cddl(
                &bytes, &formatted, "start",
            );
            assert_eq!(
                after["valid"], before["valid"],
                "{} answers differently once formatted to {}",
                schema, formatted
            );
        }
    }

    fn validate_cddl_text_via_super(cddl: &str) -> Value {
        crate::cbor::validation::validate_cddl_text(cddl)
    }

    #[test]
    fn format_preserves_leading_and_trailing_comments() {
        // Now that the `ast-comments` feature is enabled and the
        // upstream `Display` impls thread comments through, both the
        // standalone `; leading` and the inline trailing `; trailing`
        // survive a round-trip.
        let src = "; leading comment\nalpha = uint ; trailing\n";
        let formatted = format(src).unwrap();
        assert!(
            formatted.contains("; leading comment"),
            "leading comment dropped: {:?}",
            formatted
        );
        assert!(
            formatted.contains("; trailing"),
            "trailing comment dropped: {:?}",
            formatted
        );
        // The output must still parse.
        outline(&formatted).expect("formatted output should re-parse");
    }

    #[test]
    fn outline_emits_char_offsets_alongside_byte_offsets_for_non_ascii() {
        // `; кириллица\nalpha = uint`
        // The leading comment (`; кириллица`) is 20 bytes / 11 UTF-16
        // units. Adding `\n` brings us to byte 21 / char 12 — that's
        // where `alpha` starts.
        let src = "; кириллица\nalpha = uint";
        let v = outline(src).unwrap();
        let arr = v.as_array().unwrap();
        let span = &arr[0]["span"];
        assert_eq!(span["offset"], 21);
        assert_eq!(span["char_offset"], 12);
        // `alpha = uint` is 12 bytes / 12 chars (all ASCII).
        assert_eq!(span["length"], 12);
        assert_eq!(span["char_length"], 12);
        // name_span hits just `alpha`.
        let name_span = &arr[0]["name_span"];
        assert_eq!(name_span["offset"], 21);
        assert_eq!(name_span["char_offset"], 12);
        assert_eq!(name_span["length"], 5);
        assert_eq!(name_span["char_length"], 5);
    }

    #[test]
    fn outline_lists_every_rule_with_kind_and_name() {
        let src = "alpha = uint\nbeta = (a: int)\ngamma = [* tstr]";
        let v = outline(src).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0]["name"], "alpha");
        assert_eq!(arr[0]["kind"], "type");
        assert_eq!(arr[1]["name"], "beta");
        // `(a: int)` declares a *group* rule, not a type rule.
        assert_eq!(arr[1]["kind"], "group");
        assert_eq!(arr[2]["name"], "gamma");
    }

    #[test]
    fn outline_spans_match_source_substrings() {
        let src = "alpha = uint";
        let v = outline(src).unwrap();
        let span = &v[0]["span"];
        let off = span["offset"].as_u64().unwrap() as usize;
        let len = span["length"].as_u64().unwrap() as usize;
        assert_eq!(&src[off..off + len], "alpha = uint");
        let nspan = &v[0]["name_span"];
        let off = nspan["offset"].as_u64().unwrap() as usize;
        let len = nspan["length"].as_u64().unwrap() as usize;
        assert_eq!(&src[off..off + len], "alpha");
    }

    #[test]
    fn references_finds_definition_and_each_use() {
        // `coin` defined once, used twice.
        let src = "coin = uint\noutput = [bstr, coin]\nfee = coin";
        let v = references(src, "coin").unwrap();
        assert!(v["definition"].is_object(), "no definition: {}", v);
        let uses = v["uses"].as_array().unwrap();
        assert_eq!(uses.len(), 2, "expected 2 uses, got {}", v);
        // Each use should point at the literal `coin` in the source.
        for u in uses {
            let off = u["offset"].as_u64().unwrap() as usize;
            let len = u["length"].as_u64().unwrap() as usize;
            assert_eq!(&src[off..off + len], "coin");
        }
    }

    #[test]
    fn references_for_unknown_returns_null_definition() {
        let v = references("a = int", "nope").unwrap();
        assert_eq!(v["definition"], Value::Null);
        assert_eq!(v["uses"], json!([]));
    }

    #[test]
    fn references_walks_into_tagged_data_and_unwrap_and_choice_from_group() {
        let src = "set<a> = #6.258([* a])\n\
                   wrapped = ~set<int>\n\
                   tagged = #6.0(uint)\n\
                   payload = set<int>";
        let v = references(src, "set").unwrap();
        let uses = v["uses"].as_array().unwrap();
        // Two `set<…>` uses: one Unwrap (`~set<int>`) and one Typename (`payload = set<int>`).
        assert_eq!(uses.len(), 2, "got {}", v);
    }

    #[test]
    fn symbol_at_finds_definition_when_cursor_on_rule_name() {
        let src = "alpha = uint";
        // Offset 2 lands on `alpha`.
        let v = symbol_at(src, 2).unwrap();
        assert_eq!(v["name"], "alpha");
        assert_eq!(v["role"], "definition");
        assert_eq!(v["kind"], "type");
    }

    #[test]
    fn symbol_at_finds_use_with_definition_span() {
        let src = "coin = uint\nfee = coin";
        // Offset of the `coin` inside `fee = coin`. `fee = ` is 6 chars.
        let off = src.find("fee = coin").unwrap() + "fee = ".len();
        let v = symbol_at(src, off).unwrap();
        assert_eq!(v["name"], "coin");
        assert_eq!(v["role"], "use");
        assert_eq!(v["kind"], "rule_reference");
        // Definition span should point at the `coin` of `coin = uint`.
        let dspan = &v["definition_span"];
        let doff = dspan["offset"].as_u64().unwrap() as usize;
        let dlen = dspan["length"].as_u64().unwrap() as usize;
        assert_eq!(&src[doff..doff + dlen], "coin");
        assert_eq!(doff, 0);
    }

    #[test]
    fn symbol_at_returns_null_off_any_symbol() {
        let src = "alpha = uint";
        // Offset 6 lands on the `=`.
        let v = symbol_at(src, 6).unwrap();
        assert_eq!(v, Value::Null);
    }

    #[test]
    fn symbol_at_returns_prelude_or_unknown_when_no_definition() {
        let src = "alpha = uint";
        // `uint` is a prelude — no definition in this file.
        let off = src.find("uint").unwrap();
        let v = symbol_at(src, off).unwrap();
        assert_eq!(v["name"], "uint");
        assert_eq!(v["role"], "use");
        assert_eq!(v["kind"], "prelude_or_unknown");
        assert_eq!(v["definition_span"], Value::Null);
    }

    #[test]
    fn format_round_trips_a_minimal_schema() {
        // `Display` on the AST produces canonical output.
        let formatted = format("alpha = uint").unwrap();
        // Parser should accept it back.
        outline(&formatted).expect("formatted output should re-parse");
        // And contain `alpha` and `uint`.
        assert!(formatted.contains("alpha"));
        assert!(formatted.contains("uint"));
    }

    #[test]
    fn format_returns_parse_error_on_garbage() {
        let err = format("not a cddl @@@")
            .err()
            .expect("expected parse error");
        let msg = err.as_string().unwrap_or_default();
        assert!(
            msg.to_lowercase().contains("cddl parse error"),
            "got: {}",
            msg
        );
    }

    #[test]
    fn outline_orders_rules_by_appearance() {
        let src = "z_last = uint\na_first = tstr";
        let v = outline(src).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr[0]["name"], "z_last");
        assert_eq!(arr[1]["name"], "a_first");
    }

    #[test]
    fn outline_emits_parse_error_with_source_message() {
        let err = outline("not a cddl @@@")
            .err()
            .expect("expected parse error");
        assert!(err
            .as_string()
            .unwrap_or_default()
            .contains("CDDL parse error"));
    }

    // ============================================================
    // Test helpers (used by the additions below)
    // ============================================================

    fn span_substr<'a>(src: &'a str, span: &Value) -> &'a str {
        let off = span["offset"].as_u64().unwrap() as usize;
        let len = span["length"].as_u64().unwrap() as usize;
        &src[off..off + len]
    }

    fn span_offset(span: &Value) -> usize {
        span["offset"].as_u64().unwrap() as usize
    }

    fn span_length(span: &Value) -> usize {
        span["length"].as_u64().unwrap() as usize
    }

    // ============================================================
    // outline — additional cases
    // ============================================================

    #[test]
    fn outline_handles_empty_input_as_empty_array() {
        // Documented behaviour: empty / whitespace / comment-only inputs
        // produce no rules but no parse error either.
        let v = outline("").unwrap();
        assert_eq!(v, json!([]));
    }

    #[test]
    fn outline_handles_whitespace_only_input_as_empty_array() {
        let v = outline("   \n\t  \n\n").unwrap();
        assert_eq!(v, json!([]));
    }

    #[test]
    fn outline_handles_comment_only_input_as_empty_array() {
        let v = outline("; just a comment\n; another comment\n").unwrap();
        assert_eq!(v, json!([]));
    }

    #[test]
    fn outline_distinguishes_type_and_group_rules_in_same_doc() {
        // Type rules vs group rules — group rule is parenthesised body.
        let src = "tval = uint\ngval = (a: int, b: tstr)\nanother_t = bstr";
        let arr = outline(src).unwrap();
        let arr = arr.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0]["kind"], "type");
        assert_eq!(arr[0]["name"], "tval");
        assert_eq!(arr[1]["kind"], "group");
        assert_eq!(arr[1]["name"], "gval");
        assert_eq!(arr[2]["kind"], "type");
        assert_eq!(arr[2]["name"], "another_t");
    }

    #[test]
    fn outline_generic_rule_span_covers_angle_bracket_params() {
        // The full rule span should encompass the `<a>` parameter list as
        // well as the body.
        let src = "set<a> = [* a]";
        let arr = outline(src).unwrap();
        let span = &arr[0]["span"];
        let substr = span_substr(src, span);
        // Must include the angle brackets and the parameter binder.
        assert!(
            substr.starts_with("set<a>"),
            "span substr was: {:?}",
            substr
        );
        assert!(substr.contains("[* a]"), "span substr was: {:?}", substr);
        // name_span is just `set`, *not* `set<a>`.
        let name_span = &arr[0]["name_span"];
        assert_eq!(span_substr(src, name_span), "set");
    }

    #[test]
    fn outline_preserves_source_order_when_names_are_unsorted() {
        // The outline must reflect document order, not alphabetical order.
        let src = "zeta = uint\nalpha = tstr\nmu = bytes";
        let arr = outline(src).unwrap();
        let names: Vec<_> = arr
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["name"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(names, vec!["zeta", "alpha", "mu"]);
    }

    #[test]
    fn outline_handles_multibyte_comment_without_offset_drift() {
        // CDDL idents are ASCII, but a non-ASCII comment before the rule
        // exercises the byte-offset arithmetic in `span_to_json`.
        let src = "; héllo wörld\nalpha = uint";
        let arr = outline(src).unwrap();
        let r = &arr[0];
        // `name_span` and `span` should both byte-slice cleanly to the
        // expected substrings.
        assert_eq!(span_substr(src, &r["name_span"]), "alpha");
        let rule_text = span_substr(src, &r["span"]);
        assert!(rule_text.starts_with("alpha"), "got: {:?}", rule_text);
        assert!(rule_text.contains("uint"), "got: {:?}", rule_text);
    }

    #[test]
    fn outline_handles_rule_with_newline_between_name_and_body() {
        // `thing =\n  {a: int, b: int}`. The rule starts on line 1 and
        // both name_span.line and span.line reflect that.
        let src = "thing =\n  {a: int, b: int}";
        let arr = outline(src).unwrap();
        let r = &arr[0];
        assert_eq!(r["name"], "thing");
        // The rule begins on line 1 — that's where the name lives.
        assert_eq!(r["name_span"]["line"], 1);
        assert_eq!(r["span"]["line"], 1);
        // And the rule span covers everything from `thing` to `}`.
        let text = span_substr(src, &r["span"]);
        assert!(text.contains("{a: int, b: int}"), "got: {:?}", text);
    }

    #[test]
    fn outline_single_rule_has_one_entry() {
        let v = outline("only = int").unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["name"], "only");
        assert_eq!(arr[0]["kind"], "type");
    }

    #[test]
    fn outline_name_spans_match_source_substrings_for_every_rule() {
        // Ledger-flavoured fragment.
        let src = "transaction_body = { 0: inputs, 1: outputs }\n\
                   inputs = [* transaction_input]\n\
                   outputs = [* transaction_output]\n\
                   transaction_input = [tstr, uint]\n\
                   transaction_output = [bstr, uint]";
        let arr = outline(src).unwrap();
        for rule in arr.as_array().unwrap() {
            let expected_name = rule["name"].as_str().unwrap();
            assert_eq!(span_substr(src, &rule["name_span"]), expected_name);
            // And the rule span starts with the name.
            let rule_text = span_substr(src, &rule["span"]);
            assert!(
                rule_text.starts_with(expected_name),
                "rule_text {:?} did not start with name {:?}",
                rule_text,
                expected_name
            );
        }
    }

    // ============================================================
    // references — additional cases
    // ============================================================

    #[test]
    fn references_finds_use_in_generic_arg_position() {
        // `inner` is defined as a top-level rule and used only inside
        // `set<inner>`.
        let src = "inner = uint\nset<a> = [* a]\npayload = set<inner>";
        let v = references(src, "inner").unwrap();
        // Definition exists.
        assert!(v["definition"].is_object(), "no definition: {}", v);
        let uses = v["uses"].as_array().unwrap();
        assert_eq!(uses.len(), 1, "got: {}", v);
        assert_eq!(span_substr(src, &uses[0]), "inner");
    }

    #[test]
    fn references_finds_uses_in_every_walked_position() {
        // grp is referenced as: Unwrap (`~grp`), ChoiceFromGroup (`&grp`),
        // generic-arg, MemberKey::Type1 (`grp =>`), TypeGroupname (`* grp`).
        let src = "grp = (tag: uint)\n\
                   wrapped = ~grp\n\
                   pick = &grp\n\
                   gen<x> = #6.258([* x])\n\
                   used = gen<grp>\n\
                   m = { grp => any }\n\
                   hosts = (* grp)";
        let v = references(src, "grp").unwrap();
        let uses = v["uses"].as_array().unwrap();
        // 5 uses, one per position above.
        assert_eq!(uses.len(), 5, "got: {}", v);
        for u in uses {
            assert_eq!(span_substr(src, u), "grp");
        }
    }

    #[test]
    fn references_picks_up_recursive_self_reference() {
        // `tree` is recursive — references should report 1 use (the body
        // occurrence), with the definition span pointing at the rule name.
        let src = "tree = [tree] / int";
        let v = references(src, "tree").unwrap();
        let def_span = &v["definition"];
        assert_eq!(span_substr(src, def_span), "tree");
        assert_eq!(span_offset(def_span), 0);
        let uses = v["uses"].as_array().unwrap();
        assert_eq!(uses.len(), 1, "got: {}", v);
        // The body use must NOT overlap with the definition name span.
        let use_off = span_offset(&uses[0]);
        let def_len = span_length(def_span);
        assert!(
            use_off >= def_len,
            "body use at {} overlaps name span 0..{}",
            use_off,
            def_len
        );
        assert_eq!(span_substr(src, &uses[0]), "tree");
    }

    #[test]
    fn references_for_generic_param_returns_null_definition_with_param_and_body_uses() {
        // `a` is *only* a generic parameter — there's no top-level rule
        // for it. The walker still records the param-binding span and the
        // body-use span as `uses`.
        let src = "set<a> = [* a]";
        let v = references(src, "a").unwrap();
        assert_eq!(v["definition"], Value::Null);
        let uses = v["uses"].as_array().unwrap();
        assert_eq!(uses.len(), 2, "got: {}", v);
        for u in uses {
            assert_eq!(span_substr(src, u), "a");
        }
        // The two spans should be at distinct byte offsets.
        assert_ne!(span_offset(&uses[0]), span_offset(&uses[1]));
    }

    #[test]
    fn references_for_prelude_name_returns_null_definition() {
        // `uint` is prelude — no definition in the document, but every
        // use site should still be reported.
        let src = "alpha = uint\nbeta = uint\ngamma = [* uint]";
        let v = references(src, "uint").unwrap();
        assert_eq!(v["definition"], Value::Null);
        let uses = v["uses"].as_array().unwrap();
        assert_eq!(uses.len(), 3, "got: {}", v);
        for u in uses {
            assert_eq!(span_substr(src, u), "uint");
        }
    }

    #[test]
    fn references_for_prelude_tstr_finds_only_actual_uses() {
        let src = "label = tstr\npair = [tstr, uint]";
        let v = references(src, "tstr").unwrap();
        assert_eq!(v["definition"], Value::Null);
        let uses = v["uses"].as_array().unwrap();
        assert_eq!(uses.len(), 2);
        for u in uses {
            assert_eq!(span_substr(src, u), "tstr");
        }
    }

    #[test]
    fn references_byte_ranges_slice_cleanly_for_every_span() {
        // Cross-cutting: for any rule we ask about, both definition and
        // every use span must byte-slice cleanly to the literal name.
        let src = "transaction_body = { 0: set<transaction_input>, 1: [* transaction_output] }\n\
                   transaction_input = [tstr, uint]\n\
                   transaction_output = [bstr, uint]\n\
                   set<a> = #6.258([* a])";
        for name in ["transaction_input", "transaction_output", "set"] {
            let v = references(src, name).unwrap();
            // Definition: must slice cleanly.
            let def = &v["definition"];
            assert!(def.is_object(), "{} has no definition", name);
            assert_eq!(span_substr(src, def), name);
            // Each use: same.
            for u in v["uses"].as_array().unwrap() {
                assert_eq!(span_substr(src, u), name);
            }
        }
    }

    #[test]
    fn references_finds_use_in_member_key_type1_position() {
        // `grp` in member-key position: `{ grp => any }`.
        let src = "grp = uint\nm = { grp => any }";
        let v = references(src, "grp").unwrap();
        let uses = v["uses"].as_array().unwrap();
        assert_eq!(uses.len(), 1);
        assert_eq!(span_substr(src, &uses[0]), "grp");
    }

    #[test]
    fn references_walks_into_parenthesised_type_choices() {
        // `inner` referenced inside a parenthesised type choice.
        let src = "inner = uint\nthing = (inner / tstr)";
        let v = references(src, "inner").unwrap();
        let uses = v["uses"].as_array().unwrap();
        assert_eq!(uses.len(), 1);
        assert_eq!(span_substr(src, &uses[0]), "inner");
    }

    // ============================================================
    // symbol_at — additional cases
    // ============================================================

    #[test]
    fn symbol_at_returns_null_on_equals_sign() {
        let src = "alpha = uint";
        let off = src.find('=').unwrap();
        let v = symbol_at(src, off).unwrap();
        assert_eq!(v, Value::Null);
    }

    #[test]
    fn symbol_at_returns_null_inside_string_literal() {
        // A `tstr` literal that happens to contain text resembling an ident.
        let src = r#"thing = "alpha""#;
        // Land the cursor in the middle of `alpha`.
        let off = src.find("alpha").unwrap() + 2;
        let v = symbol_at(src, off).unwrap();
        assert_eq!(v, Value::Null);
    }

    #[test]
    fn symbol_at_returns_null_on_control_operator_keyword() {
        // `.size` is a CDDL control operator, not an ident.
        let src = "thing = bstr .size 32";
        let off = src.find(".size").unwrap() + 1; // on the `s`
        let v = symbol_at(src, off).unwrap();
        assert_eq!(v, Value::Null);
    }

    #[test]
    fn symbol_at_finds_use_on_generic_argument() {
        // Cursor on `inner` (the generic argument) inside `set<inner>`.
        let src = "inner = uint\nset<a> = [* a]\npayload = set<inner>";
        let off = src.find("set<inner>").unwrap() + "set<".len();
        let v = symbol_at(src, off).unwrap();
        assert_eq!(v["name"], "inner");
        assert_eq!(v["role"], "use");
        assert_eq!(v["kind"], "rule_reference");
        // definition_span must point at the literal `inner` of `inner = uint`.
        let dspan = &v["definition_span"];
        assert_eq!(span_substr(src, dspan), "inner");
        assert_eq!(span_offset(dspan), 0);
    }

    /// Documented behaviour: when the cursor lands on a generic
    /// *parameter* binder (the `a` in `set<a> = [* a]`), `symbol_at`
    /// reports it as a `use` with `kind: "prelude_or_unknown"` rather
    /// than as a definition. Generic params are not top-level rules, so
    /// no rule-level definition can exist. This test pins the behaviour
    /// down so future refactors can catch a change.
    #[test]
    fn symbol_at_on_generic_param_binder_returns_use_with_no_definition() {
        let src = "set<a> = [* a]";
        let off = src.find("<a>").unwrap() + 1; // on `a` inside `<a>`
        let v = symbol_at(src, off).unwrap();
        assert_eq!(v["name"], "a");
        assert_eq!(v["role"], "use");
        assert_eq!(v["kind"], "prelude_or_unknown");
        assert_eq!(v["definition_span"], Value::Null);
        assert_eq!(v["rule_span"], Value::Null);
        // The reported span still matches the literal `a` at the binder.
        assert_eq!(span_substr(src, &v["span"]), "a");
    }

    #[test]
    fn symbol_at_offset_zero_lands_on_first_rule_definition() {
        // Edge case: offset 0 should not panic; it should land on the
        // first character of the first rule name.
        let src = "alpha = uint";
        let v = symbol_at(src, 0).unwrap();
        assert_eq!(v["name"], "alpha");
        assert_eq!(v["role"], "definition");
        assert_eq!(v["kind"], "type");
    }

    #[test]
    fn symbol_at_past_end_of_source_returns_null_without_panic() {
        let src = "alpha = uint";
        let v = symbol_at(src, src.len() + 10_000).unwrap();
        assert_eq!(v, Value::Null);
    }

    #[test]
    fn symbol_at_in_whitespace_between_rules_returns_null() {
        // `\n\n` between two rules is purely whitespace.
        let src = "alpha = uint\n\nbeta = tstr";
        let off = src.find("\n\n").unwrap();
        let v = symbol_at(src, off).unwrap();
        assert_eq!(v, Value::Null);
        let v2 = symbol_at(src, off + 1).unwrap();
        assert_eq!(v2, Value::Null);
    }

    #[test]
    fn symbol_at_inside_a_comment_returns_null() {
        // Comments are skipped by the parser; a cursor inside one is on
        // no symbol.
        let src = "; this is a comment\nalpha = uint";
        // Offset 5 is in the middle of the comment text.
        let v = symbol_at(src, 5).unwrap();
        assert_eq!(v, Value::Null);
    }

    #[test]
    fn symbol_at_on_unwrap_target_resolves_to_the_unwrapped_rule() {
        // `~payload` — cursor on `payload` should resolve to the rule.
        let src = "wrapped = ~payload\npayload = uint";
        let off = src.find("~payload").unwrap() + 1; // on the first `p`
        let v = symbol_at(src, off).unwrap();
        assert_eq!(v["name"], "payload");
        assert_eq!(v["role"], "use");
        assert_eq!(v["kind"], "rule_reference");
        assert_eq!(span_substr(src, &v["definition_span"]), "payload");
        // Rule span covers the whole `payload = uint` definition.
        let rule_text = span_substr(src, &v["rule_span"]);
        assert!(rule_text.starts_with("payload"));
        assert!(rule_text.contains("uint"));
    }

    #[test]
    fn symbol_at_on_recursive_reference_resolves_back_to_owning_rule() {
        // `tree = [tree] / int` — cursor on the inner `tree`.
        let src = "tree = [tree] / int";
        let off = src.find("[tree]").unwrap() + 1;
        let v = symbol_at(src, off).unwrap();
        assert_eq!(v["name"], "tree");
        assert_eq!(v["role"], "use");
        assert_eq!(v["kind"], "rule_reference");
        // Definition span is the rule name at offset 0.
        assert_eq!(span_offset(&v["definition_span"]), 0);
    }

    #[test]
    fn symbol_at_on_member_key_type1_resolves_the_rule() {
        // `grp` used as a Type1 member key.
        let src = "m = { grp => any }\ngrp = uint";
        let off = src.find("grp =>").unwrap() + 1;
        let v = symbol_at(src, off).unwrap();
        assert_eq!(v["name"], "grp");
        assert_eq!(v["role"], "use");
        assert_eq!(v["kind"], "rule_reference");
    }

    #[test]
    fn symbol_at_on_brace_or_punctuation_returns_null() {
        let src = "alpha = { a: uint, b: tstr }";
        let off = src.find('{').unwrap();
        let v = symbol_at(src, off).unwrap();
        assert_eq!(v, Value::Null);
    }

    // ============================================================
    // format — additional cases
    // ============================================================

    #[test]
    fn format_is_idempotent_on_nontrivial_schema() {
        let src = "transaction_body = { 0: set<transaction_input>, ? 1: [* output] }\n\
                   set<a> = #6.258([* a])\n\
                   transaction_input = [tstr, uint]\n\
                   output = [bstr, uint]";
        let f1 = format(src).unwrap();
        let f2 = format(&f1).unwrap();
        assert_eq!(f1, f2, "format should be idempotent");
    }

    #[test]
    fn format_output_reparses_via_outline() {
        let src = "alpha = uint\nbeta = (a: int)\ngamma = [* tstr]";
        let formatted = format(src).unwrap();
        // Outline should accept the formatted output and report the same
        // set of rule names.
        let arr = outline(&formatted).unwrap();
        let names: Vec<_> = arr
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["name"].as_str().unwrap().to_string())
            .collect();
        assert!(names.contains(&"alpha".to_string()), "got: {:?}", names);
        assert!(names.contains(&"beta".to_string()), "got: {:?}", names);
        assert!(names.contains(&"gamma".to_string()), "got: {:?}", names);
    }

    #[test]
    fn format_is_stable_across_invocations() {
        let src = "alpha = uint\nbeta = tstr\ngamma = bytes";
        let f1 = format(src).unwrap();
        let f2 = format(src).unwrap();
        assert_eq!(f1, f2, "format must be deterministic");
    }

    #[test]
    fn format_preserves_rule_order_from_source() {
        // Source order is z, a, m — formatted output must match.
        let src = "zeta = uint\nalpha = tstr\nmu = bytes";
        let formatted = format(src).unwrap();
        let arr = outline(&formatted).unwrap();
        let names: Vec<_> = arr
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["name"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(names, vec!["zeta", "alpha", "mu"]);
    }

    #[test]
    fn format_handles_single_rule_schema() {
        let f = format("only = int").unwrap();
        // Must be non-empty and re-parse.
        assert!(!f.trim().is_empty());
        let arr = outline(&f).unwrap();
        let arr = arr.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["name"], "only");
    }

    #[test]
    fn format_reproduces_rule_names_for_a_ledger_fragment() {
        let src = "transaction = [body, witnesses]\n\
                   body = { 0: inputs, 1: outputs }\n\
                   inputs = [* input]\n\
                   outputs = [* output]\n\
                   input = [tstr, uint]\n\
                   output = [bstr, uint]\n\
                   witnesses = { ? 0: [* tstr] }";
        let formatted = format(src).unwrap();
        let arr = outline(&formatted).unwrap();
        let names: Vec<_> = arr
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["name"].as_str().unwrap().to_string())
            .collect();
        let expected = vec![
            "transaction",
            "body",
            "inputs",
            "outputs",
            "input",
            "output",
            "witnesses",
        ];
        assert_eq!(names, expected);
    }

    // ============================================================
    // Cross-cutting integration tests
    // ============================================================

    #[test]
    fn integration_outline_then_references_for_each_rule_finds_consistent_uses() {
        let src = "transaction_body = { 0: input, 1: output }\n\
                   input = [tstr, uint]\n\
                   output = [bstr, uint]\n\
                   top = transaction_body";
        let arr = outline(src).unwrap();
        // For each rule, ask for references and verify each use byte-slices
        // back to the rule name.
        let mut total_uses = 0usize;
        for rule in arr.as_array().unwrap() {
            let name = rule["name"].as_str().unwrap();
            let refs = references(src, name).unwrap();
            // Definition matches the outline's name_span.
            assert_eq!(refs["definition"], rule["name_span"]);
            for u in refs["uses"].as_array().unwrap() {
                assert_eq!(span_substr(src, u), name);
                total_uses += 1;
            }
        }
        // Sanity floor: there are at least 3 inter-rule uses
        // (`input`, `output`, `transaction_body`).
        assert!(total_uses >= 3, "got {} uses", total_uses);
    }

    #[test]
    fn integration_symbol_at_each_byte_search_offset_returns_matching_name() {
        // Pick a target ident, find every standalone byte occurrence in the
        // source, call symbol_at at each, and assert the returned name matches.
        let src = "input = [tstr, uint]\n\
                   list_of_inputs = [* input]\n\
                   pair = [input, input]";
        let target = "input";
        let mut offsets = Vec::new();
        let mut i = 0usize;
        let is_ident_byte =
            |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-';
        while let Some(pos) = src[i..].find(target) {
            let abs = i + pos;
            let after = src.as_bytes().get(abs + target.len()).copied();
            let prev = if abs > 0 {
                src.as_bytes().get(abs - 1).copied()
            } else {
                None
            };
            let starts_word = match prev {
                None => true,
                Some(b) => !is_ident_byte(b),
            };
            let ends_word = match after {
                None => true,
                Some(b) => !is_ident_byte(b),
            };
            if starts_word && ends_word {
                offsets.push(abs);
            }
            i = abs + target.len();
        }
        assert!(offsets.len() >= 4, "expected at least 4 occurrences");
        for off in offsets {
            let v = symbol_at(src, off).unwrap();
            assert!(v.is_object(), "null at offset {}", off);
            assert_eq!(v["name"], target, "at offset {}: {}", off, v);
        }
    }

    #[test]
    fn integration_format_then_outline_preserves_rule_set_and_order() {
        let src = "z = uint\na = tstr\nm = [* uint]\np = (key: int)";
        let arr_before = outline(src).unwrap();
        let names_before: Vec<_> = arr_before
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["name"].as_str().unwrap().to_string())
            .collect();
        let formatted = format(src).unwrap();
        let arr_after = outline(&formatted).unwrap();
        let names_after: Vec<_> = arr_after
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["name"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(names_before, names_after);
    }

    #[test]
    fn integration_outline_spans_align_with_references_definition() {
        // For every rule reported by outline, references(rule_name).definition
        // must equal outline's name_span for that rule.
        let src = "alpha = uint\n\
                   beta = (a: int, b: tstr)\n\
                   gamma = [* alpha]\n\
                   delta = beta";
        let arr = outline(src).unwrap();
        for rule in arr.as_array().unwrap() {
            let name = rule["name"].as_str().unwrap();
            let refs = references(src, name).unwrap();
            assert_eq!(
                refs["definition"], rule["name_span"],
                "definition span mismatch for {}",
                name,
            );
        }
    }

    #[test]
    fn integration_symbol_at_definition_matches_outline_name_span() {
        // For each rule, place the cursor on every byte of the name span
        // and assert symbol_at returns a definition with the same span.
        let src = "first = uint\nsecond = tstr\nthird = [* first]";
        let arr = outline(src).unwrap();
        for rule in arr.as_array().unwrap() {
            let name = rule["name"].as_str().unwrap();
            let span = &rule["name_span"];
            let off = span_offset(span);
            let len = span_length(span);
            for byte in 0..len {
                let v = symbol_at(src, off + byte).unwrap();
                assert!(v.is_object(), "null at {}", off + byte);
                assert_eq!(v["name"], name);
                assert_eq!(v["role"], "definition");
                assert_eq!(v["span"], *span);
                assert_eq!(v["definition_span"], *span);
            }
        }
    }

    // ============================================================
    // Mid-edit documents — a dangling reference must not silence the
    // IDE primitives.
    // ============================================================

    /// A schema typed top-down has dangling references most of the time
    /// it is being edited. Every primitive still has to answer.
    const MID_EDIT: &str = "transaction = [body, witnesses]\n\
                            body = { 0: inputs }\n\
                            witnesses = { ? 0: [* bstr] }\n";

    #[test]
    fn outline_lists_rules_while_a_reference_is_still_dangling() {
        let arr = outline(MID_EDIT).expect("dangling reference must not fail the outline");
        let names: Vec<_> = arr
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["name"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(names, vec!["transaction", "body", "witnesses"]);
    }

    #[test]
    fn symbol_at_reports_unknown_kind_for_a_dangling_reference() {
        let off = MID_EDIT.find("inputs").unwrap();
        let v = symbol_at(MID_EDIT, off).expect("dangling reference must not fail symbol_at");
        assert_eq!(v["name"], "inputs");
        assert_eq!(v["role"], "use");
        assert_eq!(v["kind"], "prelude_or_unknown");
        assert_eq!(v["definition_span"], Value::Null);
        assert_eq!(v["rule_span"], Value::Null);
        assert_eq!(span_substr(MID_EDIT, &v["span"]), "inputs");
    }

    #[test]
    fn references_returns_uses_with_null_definition_for_a_dangling_name() {
        let v =
            references(MID_EDIT, "inputs").expect("dangling reference must not fail references");
        assert_eq!(v["definition"], Value::Null);
        let uses = v["uses"].as_array().unwrap();
        assert_eq!(uses.len(), 1, "got: {}", v);
        assert_eq!(span_substr(MID_EDIT, &uses[0]), "inputs");
    }

    #[test]
    fn format_round_trips_a_document_with_a_dangling_reference() {
        let formatted = format(MID_EDIT).expect("dangling reference must not fail format");
        assert!(formatted.contains("inputs"), "got: {:?}", formatted);
        let arr = outline(&formatted).unwrap();
        let names: Vec<_> = arr
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["name"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(names, vec!["transaction", "body", "witnesses"]);
    }

    /// Acceptance widened for dangling references only. Text that does
    /// not parse still fails, on every entry point.
    #[test]
    fn ide_primitives_still_reject_a_syntax_error() {
        for src in [
            "Person = {\n  name: tstr,\n  age: ",
            "A = uint\nB = {\n  x: ",
            "A = [",
            "not a cddl @@@",
        ] {
            let errors = [
                outline(src)
                    .err()
                    .map(|e| e.as_string().unwrap_or_default()),
                references(src, "A")
                    .err()
                    .map(|e| e.as_string().unwrap_or_default()),
                symbol_at(src, 0)
                    .err()
                    .map(|e| e.as_string().unwrap_or_default()),
                format(src).err().map(|e| e.as_string().unwrap_or_default()),
            ];
            for (i, err) in errors.iter().enumerate() {
                let msg = err
                    .as_ref()
                    .unwrap_or_else(|| panic!("entry point {} accepted {:?}", i, src));
                assert!(
                    msg.contains("CDDL parse error"),
                    "entry point {} on {:?} gave {:?}",
                    i,
                    src,
                    msg
                );
            }
        }
    }

    /// Rules the largest ledger schema declares. Pinned so a rename or a
    /// dropped rule in the fixture is noticed here, not in a downstream
    /// count.
    const LEDGER_RULE_COUNT: usize = 212;

    /// Whole-word occurrences of `name` in `src`, definition included.
    fn word_occurrences(src: &str, name: &str) -> usize {
        let bytes = src.as_bytes();
        let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
        src.match_indices(name)
            .filter(|(at, _)| {
                let before = at.checked_sub(1).map(|i| bytes[i]);
                let after = bytes.get(at + name.len()).copied();
                !before.is_some_and(is_word) && !after.is_some_and(is_word)
            })
            .count()
    }

    #[test]
    fn outline_of_the_ledger_schema_lists_every_rule_in_source_order() {
        let src = crate::cbor::test_fixtures::ledger_cddl();
        let arr = outline(src).unwrap();
        let names: Vec<&str> = arr
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["name"].as_str().unwrap())
            .collect();
        assert_eq!(names.len(), LEDGER_RULE_COUNT);
        // The roots come first, in the order the schema declares them.
        assert_eq!(&names[..2], ["record", "record_body"]);
        for root in [
            "record_witness",
            "datum",
            "payload",
            "amount",
            "stock",
            "widgets",
        ] {
            assert!(names.contains(&root), "{} missing from {:?}", root, names);
        }
        // A name repeats only for a `/=` alternate; a socket may open with
        // one, so an alternate need not follow a plain definition.
        let mut seen = std::collections::HashSet::new();
        for rule in arr.as_array().unwrap() {
            let name = rule["name"].as_str().unwrap();
            let is_alternate = rule["is_alternate"].as_bool().unwrap();
            let is_new = seen.insert(name);
            assert!(is_new || is_alternate, "{} outlined twice", name);
            // Each entry's name slices out of its own name span.
            assert_eq!(span_substr(src, &rule["name_span"]), name);
        }
        assert!(seen.contains("$extension_kind"), "{:?}", names);
    }

    #[test]
    fn every_schema_version_outlines_the_same_roots() {
        let mut previous = 0;
        for (version, src) in crate::cbor::test_fixtures::schema_suite() {
            let arr = outline(src).unwrap_or_else(|e| panic!("{} outlines: {:?}", version, e));
            let names: Vec<&str> = arr
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["name"].as_str().unwrap())
                .collect();
            for root in [
                "record",
                "record_body",
                "record_witness",
                "datum",
                "payload",
            ] {
                assert!(names.contains(&root), "{}: {} missing", version, root);
            }
            // Versions only add rules.
            assert!(
                names.len() > previous,
                "{} shrank to {} rules",
                version,
                names.len()
            );
            previous = names.len();
        }
        assert_eq!(previous, LEDGER_RULE_COUNT);
    }

    #[test]
    fn references_in_the_ledger_schema_find_the_definition_and_every_use() {
        let src = crate::cbor::test_fixtures::ledger_cddl();
        let v = references(src, "amount").unwrap();
        assert_eq!(span_substr(src, &v["definition"]), "amount");
        let def_offset = span_offset(&v["definition"]);
        assert_eq!(
            &src[def_offset..src[def_offset..].find('\n').unwrap() + def_offset],
            "amount = uint"
        );

        let uses = v["uses"].as_array().unwrap();
        // `amount` is read in the body, in `value` and in a certificate;
        // every whole-word occurrence but the definition is a use.
        assert_eq!(uses.len(), word_occurrences(src, "amount") - 1);
        assert!(uses.len() >= 5, "only {} uses: {}", uses.len(), v);
        let mut offsets: Vec<usize> = uses.iter().map(span_offset).collect();
        for (u, off) in uses.iter().zip(&offsets) {
            assert_eq!(span_substr(src, u), "amount");
            assert_ne!(*off, def_offset, "the definition is listed as a use");
        }
        offsets.sort_unstable();
        offsets.dedup();
        assert_eq!(offsets.len(), uses.len(), "a use is listed twice");
    }

    #[test]
    fn ledger_schema_with_a_renamed_rule_still_outlines_every_rule() {
        let src = crate::cbor::test_fixtures::ledger_cddl();
        let renamed = src.replacen("\namount = ", "\namount_renamed = ", 1);
        assert_ne!(renamed, src, "fixture no longer defines `amount`");

        let arr = outline(&renamed).expect("renaming a rule must not fail the outline");
        assert_eq!(arr.as_array().unwrap().len(), LEDGER_RULE_COUNT);

        // Every `amount` use is now dangling; the cursor on one of them
        // still reports the name, just with no definition to jump to.
        let ast = cddl::pest_bridge::cddl_from_pest_str(&renamed).unwrap();
        let dangling = unresolved_references(&ast);
        assert!(!dangling.is_empty(), "expected dangling `amount` uses");
        assert_eq!(dangling[0].0, "amount");
        let v = symbol_at(&renamed, dangling[0].1 .0).unwrap();
        assert_eq!(v["name"], "amount");
        assert_eq!(v["kind"], "prelude_or_unknown");
        assert_eq!(v["definition_span"], Value::Null);
    }

    // ============================================================
    // Socket / plug names
    // ============================================================

    /// `Identifier::ident` drops the `$` sigil while the span keeps it,
    /// so the emitted name has to be the identifier's full text or it no
    /// longer slices out of the source range it is paired with.
    #[test]
    fn outline_name_for_a_socket_rule_slices_out_of_its_own_name_span() {
        let src = "$sock /= uint\nthing = $sock\n";
        let arr = outline(src).unwrap();
        let entry = &arr.as_array().unwrap()[0];
        assert_eq!(entry["name"], "$sock");
        assert_eq!(span_substr(src, &entry["name_span"]), "$sock");
    }

    #[test]
    fn references_finds_a_socket_rule_under_its_full_name() {
        let src = "$sock /= uint\nthing = $sock\n";
        let v = references(src, "$sock").unwrap();
        assert_eq!(span_substr(src, &v["definition"]), "$sock");
        let uses = v["uses"].as_array().unwrap();
        assert_eq!(uses.len(), 1, "got: {}", v);
        assert_eq!(span_substr(src, &uses[0]), "$sock");
        // And the sigil-less spelling is a different name.
        let bare = references(src, "sock").unwrap();
        assert_eq!(bare["definition"], Value::Null);
        assert_eq!(bare["uses"], json!([]));
    }

    #[test]
    fn symbol_at_on_a_socket_use_resolves_to_the_socket_rule() {
        let src = "$sock /= uint\nthing = $sock\n";
        let off = src.rfind("$sock").unwrap() + 1;
        let v = symbol_at(src, off).unwrap();
        assert_eq!(v["name"], "$sock");
        assert_eq!(v["kind"], "rule_reference");
        assert_eq!(span_substr(src, &v["definition_span"]), "$sock");
    }

    // ============================================================
    // Choice alternates
    // ============================================================

    #[test]
    fn outline_marks_a_type_choice_alternate() {
        let src = "a = uint\na /= tstr\n";
        let arr = outline(src).unwrap();
        let arr = arr.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["name"], "a");
        assert_eq!(arr[0]["is_alternate"], json!(false));
        assert_eq!(arr[1]["name"], "a");
        assert_eq!(arr[1]["is_alternate"], json!(true));
        // The two entries are distinguishable by span, not just by flag.
        assert_ne!(arr[0]["span"], arr[1]["span"]);
    }

    #[test]
    fn outline_marks_a_group_choice_alternate() {
        let src = "g = (a: uint)\ng //= (b: tstr)\n";
        let arr = outline(src).unwrap();
        let arr = arr.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["kind"], "group");
        assert_eq!(arr[0]["is_alternate"], json!(false));
        assert_eq!(arr[1]["is_alternate"], json!(true));
    }

    #[test]
    fn outline_flags_no_alternates_in_a_plain_schema() {
        let src = "alpha = uint\nbeta = (a: int)\n";
        let arr = outline(src).unwrap();
        for entry in arr.as_array().unwrap() {
            assert_eq!(entry["is_alternate"], json!(false), "got {}", entry);
        }
    }

    // ============================================================
    // Unresolved-reference collector
    // ============================================================

    fn collect_unresolved(src: &str) -> Vec<(String, usize)> {
        let ast = cddl::pest_bridge::cddl_from_pest_str(src)
            .unwrap_or_else(|e| panic!("{:?} should parse: {}", src, e));
        unresolved_references(&ast)
            .into_iter()
            .map(|(name, span)| (name, span.0))
            .collect()
    }

    /// What the reference-checking parser makes of a document.
    #[derive(Debug, PartialEq)]
    enum Checked {
        Resolved,
        Unresolved(String, usize),
        SyntaxError,
    }

    fn checked_outcome(src: &str) -> Checked {
        match cddl::pest_bridge::cddl_from_pest_str_checked(src) {
            Ok(_) => Checked::Resolved,
            Err(cddl::parser::Error::PARSER { position, msg }) => {
                match msg.short.strip_prefix("missing definition for rule ") {
                    Some(name) => Checked::Unresolved(name.to_string(), position.range.0),
                    None => Checked::SyntaxError,
                }
            }
            Err(_) => Checked::SyntaxError,
        }
    }

    #[test]
    fn unresolved_references_finds_every_occurrence_in_source_order() {
        let src = "a = [alpha, beta]\nb = { k: gamma }\n";
        assert_eq!(
            collect_unresolved(src),
            vec![
                ("alpha".to_string(), 5),
                ("beta".to_string(), 12),
                ("gamma".to_string(), 27),
            ]
        );
    }

    #[test]
    fn unresolved_references_covers_control_range_generic_unwrap_and_group_positions() {
        let cases: &[(&str, &[(&str, usize)])] = &[
            (
                "a = bstr .size limit\nb = 0..maxv\n",
                &[("limit", 15), ("maxv", 28)],
            ),
            ("set<a> = [* a]\nuse = set<nope>\n", &[("nope", 25)]),
            (
                "a = ~missing3\nb = &missing4\n",
                &[("missing3", 5), ("missing4", 19)],
            ),
            (
                "g = (x: missing1)\nh = [g, missing2]\n",
                &[("missing1", 8), ("missing2", 26)],
            ),
            ("a = #6.24(missing5)\n", &[("missing5", 10)]),
            ("a = [* missing6]\n", &[("missing6", 7)]),
            (
                "a = { k => { j => missing7 } }\nk = uint\nj = uint\n",
                &[("missing7", 18)],
            ),
        ];
        for (src, expected) in cases {
            let expected: Vec<(String, usize)> =
                expected.iter().map(|(n, o)| (n.to_string(), *o)).collect();
            assert_eq!(collect_unresolved(src), expected, "for {:?}", src);
        }
    }

    #[test]
    fn unresolved_references_ignores_prelude_generics_sockets_and_barewords() {
        // A generic argument that resolves, a generic parameter used in
        // the body it is bound in, a socket/plug name, and a bareword
        // member key — which is a literal text key, not a reference.
        let mut prelude_doc = String::new();
        for (i, name) in STANDARD_PRELUDE.iter().enumerate() {
            prelude_doc.push_str(&format!("r{} = {}\n", i, name));
        }
        for src in [
            "set<a> = [* a]\nuse = set<uint>\n",
            "$sock /= uint\nthing = $sock\n",
            "m = { nope: uint }\n",
            &prelude_doc,
        ] {
            assert_eq!(
                collect_unresolved(src),
                Vec::<(String, usize)>::new(),
                "for {:?}",
                src
            );
            assert_eq!(checked_outcome(src), Checked::Resolved, "for {:?}", src);
        }
    }

    /// The negative half of the prelude case: a name that merely looks
    /// prelude-ish is still unresolved.
    #[test]
    fn unresolved_references_does_not_treat_a_near_prelude_name_as_known() {
        assert_eq!(
            collect_unresolved("a = uintish\n"),
            vec![("uintish".to_string(), 4)]
        );
    }

    /// A generic parameter is bound only in the rule that declares it.
    #[test]
    fn unresolved_references_scopes_generic_parameters_to_their_own_rule() {
        let src = "gen<x> = [x]\nq = gen<uint>\nr = x\n";
        assert_eq!(collect_unresolved(src), vec![("x".to_string(), 31)]);
    }

    #[test]
    fn unresolved_reference_spans_carry_the_right_line_and_slice_cleanly() {
        let src =
            "a = uint\nb = tstr\nc = [missingX, uint]\nd = { k: missingY }\ne = uint\nk = uint\n";
        let ast = cddl::pest_bridge::cddl_from_pest_str(src).unwrap();
        let found = unresolved_references(&ast);
        assert_eq!(found.len(), 2, "got {:?}", found);
        assert_eq!(found[0], ("missingX".to_string(), (23, 31, 3)));
        assert_eq!(found[1], ("missingY".to_string(), (48, 56, 4)));
        for (name, span) in &found {
            assert_eq!(&src[span.0..span.1], name);
        }

        // Byte offsets stay byte offsets when the source is not ASCII.
        let src = "; кириллица\nx = [missingZ]\n";
        let ast = cddl::pest_bridge::cddl_from_pest_str(src).unwrap();
        let found = unresolved_references(&ast);
        assert_eq!(found, vec![("missingZ".to_string(), (26, 34, 2))]);
        assert_eq!(&src[26..34], "missingZ");
    }

    /// A tag constraint keeps only its source text in the AST — no
    /// identifier, no span — so a reference written there is invisible
    /// to this walker. That is why the reference-checking parser, not
    /// this walker, decides whether a schema resolves.
    #[test]
    fn unresolved_references_cannot_see_inside_a_tag_constraint() {
        let src = "a = #6.<missing>(uint)\n";
        assert_eq!(collect_unresolved(src), Vec::<(String, usize)>::new());
        assert_eq!(
            checked_outcome(src),
            Checked::Unresolved("missing".to_string(), 8)
        );
    }

    /// The collector must never report resolved where the parser reports
    /// unresolved, and must agree with it on the first offender.
    #[test]
    fn unresolved_reference_collector_agrees_with_the_checked_parser() {
        let mut documents: Vec<String> = Vec::new();
        for (version, src) in crate::cbor::test_fixtures::schema_suite() {
            documents.push(src.to_string());
            let renamed = src.replacen("\namount = ", "\namount_renamed = ", 1);
            assert_ne!(renamed, src, "{} no longer defines `amount`", version);
            documents.push(renamed);
        }
        for src in [
            MID_EDIT,
            "a = [alpha, beta]\nb = { k: gamma }\n",
            "a = bstr .size limit\nb = 0..maxv\n",
            "set<a> = [* a]\nuse = set<nope>\n",
            "set<a> = [* a]\nuse = set<uint>\n",
            "a = ~missing3\nb = &missing4\n",
            "g = (x: missing1)\nh = [g, missing2]\n",
            "a = #6.24(missing5)\n",
            "a = [* missing6]\n",
            "a = { k => { j => missing7 } }\nk = uint\nj = uint\n",
            "m = { nope: uint }\n",
            "$sock /= uint\nthing = $sock\n",
            "gen<x> = [x]\nq = gen<uint>\nr = x\n",
            "a = uint\na /= tstr\n",
            "; кириллица\nx = [missingZ]\n",
            "a = uint\nb = tstr\nc = [missingX, uint]\nd = { k: missingY }\ne = uint\nk = uint\n",
            "a = missing .size 4\n",
            "m = { * missingK => uint }\n",
            "a = &(x: missingG)\n",
            "tree = [tree] / int\n",
        ] {
            documents.push(src.to_string());
        }

        for src in &documents {
            let head = collect_unresolved(src).into_iter().next();
            let excerpt: String = src.chars().take(60).collect();
            match checked_outcome(src) {
                Checked::Resolved => assert_eq!(
                    head, None,
                    "walker reported {:?} where the parser resolved everything, in {:?}",
                    head, excerpt
                ),
                Checked::Unresolved(name, offset) => assert_eq!(
                    head,
                    Some((name.clone(), offset)),
                    "walker disagreed with the parser (expected {:?} at {}) in {:?}",
                    name,
                    offset,
                    excerpt
                ),
                Checked::SyntaxError => {
                    panic!("parity document {:?} does not parse", excerpt)
                }
            }
        }
    }
}

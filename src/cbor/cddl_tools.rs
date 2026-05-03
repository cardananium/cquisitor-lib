//! IDE-grade primitives for CDDL: outline, references, symbol-at-offset,
//! and format. Built on top of the same `anweiss/cddl` AST the validator
//! and decoder use, so byte spans line up with everything else.

use cddl::ast::{
    GenericArgs, GenericParams, Group, GroupChoice, GroupEntry, MemberKey, Operator, Rule, Type,
    Type1, Type2, CDDL,
};
use serde_json::{json, Value};

use crate::cbor::source_index::{span_json, Utf16Index};
use crate::js_error::JsError;

// ============================================================
// Outline — list of top-level rules with their source spans.
// ============================================================

/// Returns `[{name, kind, span: {offset, length, line}}]` for every
/// top-level rule. Used by editor outline / breadcrumbs / Cmd+P.
pub fn outline(cddl: &str) -> Result<Value, JsError> {
    let ast = parse(cddl)?;
    let idx = Utf16Index::new(cddl);
    let rules = ast
        .rules
        .iter()
        .map(|r| {
            let (kind, name, name_span) = match r {
                Rule::Type { rule, .. } => {
                    ("type", rule.name.ident.to_string(), rule.name.span)
                }
                Rule::Group { rule, .. } => {
                    ("group", rule.name.ident.to_string(), rule.name.span)
                }
            };
            json!({
                "name": name,
                "kind": kind,
                "span": span_to_json(&idx, rule_span(r)),
                "name_span": span_to_json(&idx, name_span),
            })
        })
        .collect();
    Ok(Value::Array(rules))
}

fn rule_span(r: &Rule<'_>) -> cddl::ast::Span {
    match r {
        Rule::Type { span, .. } => *span,
        Rule::Group { span, .. } => *span,
    }
}

// ============================================================
// References — definition span + every use of a rule name.
// ============================================================

/// Returns `{definition: span | null, uses: span[]}` for `name`. Walks
/// every Typename / Unwrap / ChoiceFromGroup / TypeGroupname and
/// matches by ident.
pub fn references(cddl: &str, name: &str) -> Result<Value, JsError> {
    let ast = parse(cddl)?;

    let definition = ast.rules.iter().find_map(|r| match r {
        Rule::Type { rule, .. } if rule.name.ident == name => Some(rule.name.span),
        Rule::Group { rule, .. } if rule.name.ident == name => Some(rule.name.span),
        _ => None,
    });

    let mut uses: Vec<cddl::ast::Span> = Vec::new();
    for rule in &ast.rules {
        match rule {
            Rule::Type { rule, .. } => {
                walk_generic_params(&rule.generic_params, name, &mut uses);
                walk_type(&rule.value, name, &mut uses);
            }
            Rule::Group { rule, .. } => {
                walk_generic_params(&rule.generic_params, name, &mut uses);
                walk_group_entry(&rule.entry, name, &mut uses);
            }
        }
    }

    let idx = Utf16Index::new(cddl);
    Ok(json!({
        "definition": definition.map(|s| span_to_json(&idx, s)).unwrap_or(Value::Null),
        "uses": uses.into_iter().map(|s| span_to_json(&idx, s)).collect::<Vec<_>>(),
    }))
}

// ============================================================
// Symbol at offset — what's under the cursor?
// ============================================================

/// Returns a description of the identifier at `offset`, or `null`. For
/// uses, includes a pointer back to the rule's definition span (the
/// "go to definition" target). For definitions, the same span is both
/// `span` and `definition_span`.
pub fn symbol_at(cddl: &str, offset: usize) -> Result<Value, JsError> {
    let ast = parse(cddl)?;
    let idx = Utf16Index::new(cddl);

    // First, see if offset lands on a rule name (definition).
    for rule in &ast.rules {
        let name_span = match rule {
            Rule::Type { rule, .. } => rule.name.span,
            Rule::Group { rule, .. } => rule.name.span,
        };
        if span_contains(name_span, offset) {
            let (name, kind) = match rule {
                Rule::Type { rule, .. } => (rule.name.ident.to_string(), "type"),
                Rule::Group { rule, .. } => (rule.name.ident.to_string(), "group"),
            };
            return Ok(json!({
                "name": name,
                "kind": kind,
                "role": "definition",
                "span": span_to_json(&idx, name_span),
                "definition_span": span_to_json(&idx, name_span),
                "rule_span": span_to_json(&idx, rule_span(rule)),
            }));
        }
    }

    // Otherwise look for a use whose ident span contains the offset.
    let mut found: Option<cddl::ast::Identifier<'_>> = None;
    for rule in &ast.rules {
        match rule {
            Rule::Type { rule, .. } => {
                find_use_at_in_generic_params(&rule.generic_params, offset, &mut found);
                find_use_at_in_type(&rule.value, offset, &mut found);
            }
            Rule::Group { rule, .. } => {
                find_use_at_in_generic_params(&rule.generic_params, offset, &mut found);
                find_use_at_in_group_entry(&rule.entry, offset, &mut found);
            }
        }
        if found.is_some() {
            break;
        }
    }

    let Some(ident) = found else { return Ok(Value::Null) };

    let definition = ast.rules.iter().find_map(|r| match r {
        Rule::Type { rule, .. } if rule.name.ident == ident.ident => {
            Some((rule.name.span, rule_span(r)))
        }
        Rule::Group { rule, .. } if rule.name.ident == ident.ident => {
            Some((rule.name.span, rule_span(r)))
        }
        _ => None,
    });

    let (definition_span, rule_span_value) = match definition {
        Some((d, r)) => (Some(d), Some(r)),
        None => (None, None),
    };

    Ok(json!({
        "name": ident.ident.to_string(),
        "kind": if rule_span_value.is_some() { "rule_reference" } else { "prelude_or_unknown" },
        "role": "use",
        "span": span_to_json(&idx, ident.span),
        "definition_span": definition_span.map(|s| span_to_json(&idx, s)).unwrap_or(Value::Null),
        "rule_span": rule_span_value.map(|s| span_to_json(&idx, s)).unwrap_or(Value::Null),
    }))
}

// ============================================================
// Format — pretty-print via the AST's Display impl.
// ============================================================

/// Reformat the input by parsing it and serialising via `Display`.
/// Round-trips canonically — useful for `format on save`.
pub fn format(cddl: &str) -> Result<String, JsError> {
    let ast = parse(cddl)?;
    Ok(format!("{}", ast))
}

// ============================================================
// Helpers
// ============================================================

fn parse<'a>(cddl: &'a str) -> Result<CDDL<'a>, JsError> {
    cddl::pest_bridge::cddl_from_pest_str_checked(cddl)
        .map_err(|e| JsError::new(&format!("CDDL parse error: {}", e)))
}

fn span_to_json(idx: &Utf16Index, s: cddl::ast::Span) -> Value {
    let (start, end, line) = s;
    span_json(idx, start, end, line)
}

fn span_contains(s: cddl::ast::Span, offset: usize) -> bool {
    let (start, end, _line) = s;
    offset >= start && offset < end
}

// ----- Reference walker (collect spans where ident == name) -----

fn walk_generic_params(
    gp: &Option<GenericParams<'_>>,
    name: &str,
    uses: &mut Vec<cddl::ast::Span>,
) {
    if let Some(gp) = gp {
        for p in &gp.params {
            if p.param.ident == name {
                uses.push(p.param.span);
            }
        }
    }
}

fn walk_generic_args(args: &Option<GenericArgs<'_>>, name: &str, uses: &mut Vec<cddl::ast::Span>) {
    if let Some(args) = args {
        for a in &args.args {
            walk_type1(&a.arg, name, uses);
        }
    }
}

fn walk_type(ty: &Type<'_>, name: &str, uses: &mut Vec<cddl::ast::Span>) {
    for choice in &ty.type_choices {
        walk_type1(&choice.type1, name, uses);
    }
}

fn walk_type1(t1: &Type1<'_>, name: &str, uses: &mut Vec<cddl::ast::Span>) {
    walk_type2(&t1.type2, name, uses);
    if let Some(operator) = &t1.operator {
        walk_operator(operator, name, uses);
    }
}

fn walk_operator(op: &Operator<'_>, name: &str, uses: &mut Vec<cddl::ast::Span>) {
    walk_type2(&op.type2, name, uses);
}

fn walk_type2(t2: &Type2<'_>, name: &str, uses: &mut Vec<cddl::ast::Span>) {
    match t2 {
        Type2::Typename { ident, generic_args, .. } => {
            if ident.ident == name {
                uses.push(ident.span);
            }
            walk_generic_args(generic_args, name, uses);
        }
        Type2::Unwrap { ident, generic_args, .. } => {
            if ident.ident == name {
                uses.push(ident.span);
            }
            walk_generic_args(generic_args, name, uses);
        }
        Type2::ChoiceFromGroup { ident, generic_args, .. } => {
            if ident.ident == name {
                uses.push(ident.span);
            }
            walk_generic_args(generic_args, name, uses);
        }
        Type2::ParenthesizedType { pt, .. } => walk_type(pt, name, uses),
        Type2::TaggedData { t, .. } => walk_type(t, name, uses),
        Type2::Map { group, .. } => walk_group(group, name, uses),
        Type2::Array { group, .. } => walk_group(group, name, uses),
        Type2::ChoiceFromInlineGroup { group, .. } => walk_group(group, name, uses),
        _ => {}
    }
}

fn walk_group(g: &Group<'_>, name: &str, uses: &mut Vec<cddl::ast::Span>) {
    for choice in &g.group_choices {
        walk_group_choice(choice, name, uses);
    }
}

fn walk_group_choice(gc: &GroupChoice<'_>, name: &str, uses: &mut Vec<cddl::ast::Span>) {
    for (entry, _) in &gc.group_entries {
        walk_group_entry(entry, name, uses);
    }
}

fn walk_group_entry(ge: &GroupEntry<'_>, name: &str, uses: &mut Vec<cddl::ast::Span>) {
    match ge {
        GroupEntry::ValueMemberKey { ge, .. } => {
            if let Some(mk) = &ge.member_key {
                walk_member_key(mk, name, uses);
            }
            walk_type(&ge.entry_type, name, uses);
        }
        GroupEntry::TypeGroupname { ge, .. } => {
            if ge.name.ident == name {
                uses.push(ge.name.span);
            }
            walk_generic_args(&ge.generic_args, name, uses);
        }
        GroupEntry::InlineGroup { group, .. } => walk_group(group, name, uses),
    }
}

fn walk_member_key(mk: &MemberKey<'_>, name: &str, uses: &mut Vec<cddl::ast::Span>) {
    if let MemberKey::Type1 { t1, .. } = mk {
        walk_type1(t1, name, uses);
    }
}

// ----- Symbol-at-offset walker (find first ident whose span covers offset) -----

fn find_use_at_in_generic_params<'a>(
    gp: &'a Option<GenericParams<'a>>,
    offset: usize,
    found: &mut Option<cddl::ast::Identifier<'a>>,
) {
    if found.is_some() {
        return;
    }
    if let Some(gp) = gp {
        for p in &gp.params {
            if span_contains(p.param.span, offset) {
                *found = Some(p.param.clone());
                return;
            }
        }
    }
}

fn find_use_at_in_generic_args<'a>(
    args: &'a Option<GenericArgs<'a>>,
    offset: usize,
    found: &mut Option<cddl::ast::Identifier<'a>>,
) {
    if found.is_some() {
        return;
    }
    if let Some(args) = args {
        for a in &args.args {
            find_use_at_in_type1(&a.arg, offset, found);
        }
    }
}

fn find_use_at_in_type<'a>(
    ty: &'a Type<'a>,
    offset: usize,
    found: &mut Option<cddl::ast::Identifier<'a>>,
) {
    for choice in &ty.type_choices {
        find_use_at_in_type1(&choice.type1, offset, found);
        if found.is_some() {
            return;
        }
    }
}

fn find_use_at_in_type1<'a>(
    t1: &'a Type1<'a>,
    offset: usize,
    found: &mut Option<cddl::ast::Identifier<'a>>,
) {
    find_use_at_in_type2(&t1.type2, offset, found);
    if found.is_some() {
        return;
    }
    if let Some(operator) = &t1.operator {
        find_use_at_in_type2(&operator.type2, offset, found);
    }
}

fn find_use_at_in_type2<'a>(
    t2: &'a Type2<'a>,
    offset: usize,
    found: &mut Option<cddl::ast::Identifier<'a>>,
) {
    if found.is_some() {
        return;
    }
    match t2 {
        Type2::Typename { ident, generic_args, .. }
        | Type2::Unwrap { ident, generic_args, .. }
        | Type2::ChoiceFromGroup { ident, generic_args, .. } => {
            if span_contains(ident.span, offset) {
                *found = Some(ident.clone());
                return;
            }
            find_use_at_in_generic_args(generic_args, offset, found);
        }
        Type2::ParenthesizedType { pt, .. } => find_use_at_in_type(pt, offset, found),
        Type2::TaggedData { t, .. } => find_use_at_in_type(t, offset, found),
        Type2::Map { group, .. } | Type2::Array { group, .. } => {
            find_use_at_in_group(group, offset, found)
        }
        Type2::ChoiceFromInlineGroup { group, .. } => {
            find_use_at_in_group(group, offset, found)
        }
        _ => {}
    }
}

fn find_use_at_in_group<'a>(
    g: &'a Group<'a>,
    offset: usize,
    found: &mut Option<cddl::ast::Identifier<'a>>,
) {
    for choice in &g.group_choices {
        for (entry, _) in &choice.group_entries {
            find_use_at_in_group_entry(entry, offset, found);
            if found.is_some() {
                return;
            }
        }
    }
}

fn find_use_at_in_group_entry<'a>(
    ge: &'a GroupEntry<'a>,
    offset: usize,
    found: &mut Option<cddl::ast::Identifier<'a>>,
) {
    if found.is_some() {
        return;
    }
    match ge {
        GroupEntry::ValueMemberKey { ge, .. } => {
            if let Some(mk) = &ge.member_key {
                if let MemberKey::Type1 { t1, .. } = mk {
                    find_use_at_in_type1(t1, offset, found);
                    if found.is_some() {
                        return;
                    }
                }
            }
            find_use_at_in_type(&ge.entry_type, offset, found);
        }
        GroupEntry::TypeGroupname { ge, .. } => {
            if span_contains(ge.name.span, offset) {
                *found = Some(ge.name.clone());
                return;
            }
            find_use_at_in_generic_args(&ge.generic_args, offset, found);
        }
        GroupEntry::InlineGroup { group, .. } => find_use_at_in_group(group, offset, found),
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Documents an upstream `Display` bug: when a `bareword : type`
    /// member key has a Map type as its value (e.g. Conway's
    /// `auxiliary_data_set : {* transaction_index => auxiliary_data}`),
    /// the formatter outputs `bareword => {...}` instead — converting
    /// the bareword into a type1 expression, which then dangles as a
    /// reference to a rule that doesn't exist.
    ///
    /// Minimal repro and full Conway-CDDL round-trip both fail. When
    /// upstream fixes the Display impl, both halves should flip back
    /// to `valid: true`.
    #[test]
    fn format_breaks_bareword_key_when_value_is_map() {
        let src = "block = [aux: {* int => uint}]";
        let formatted = format(src).expect("input parses");
        // Pinning the bug: the bareword `aux:` becomes `aux =>`.
        assert!(
            formatted.contains("aux =>") && !formatted.contains("aux:"),
            "if this trips, the upstream `:` -> `=>` Display bug is fixed; \
             flip this test to assert {:?}.contains('aux:')",
            formatted
        );
        // Direct consequence: re-parsing the formatted output now
        // treats `aux` as a reference to a non-existent rule.
        let reparse = validate_cddl_text_via_super(&formatted);
        assert_eq!(
            reparse["error"]["kind"], json!("unresolved_references"),
            "formatted output should fail with unresolved_references for `aux`",
        );
    }

    /// Wider check: the entire Conway CDDL becomes unparseable after
    /// `format()`. Skipped when the cached fixture isn't present.
    #[test]
    fn conway_cddl_round_trip_through_format_documents_break() {
        let Ok(src) = std::fs::read_to_string("/tmp/conway.cddl") else {
            eprintln!("skipping — /tmp/conway.cddl not present");
            return;
        };
        let formatted =
            format(&src).expect("Conway CDDL itself parses and formats");
        // The formatter mangles bareword-keyed map values — re-parsing
        // produces unresolved-reference errors. When upstream fixes
        // this, flip to `valid: true` and re-enable the full
        // round-trip checks.
        let reparse = validate_cddl_text_via_super(&formatted);
        assert_eq!(reparse["valid"], json!(false));
        assert_eq!(
            reparse["error"]["kind"], json!("unresolved_references"),
            "Conway round-trip currently breaks via unresolved_references; got {}",
            reparse,
        );
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
        assert!(msg.to_lowercase().contains("cddl parse error"), "got: {}", msg);
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
        assert!(err.as_string().unwrap_or_default().contains("CDDL parse error"));
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
        assert!(substr.starts_with("set<a>"), "span substr was: {:?}", substr);
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
        // Cardano-flavoured fragment.
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
    fn format_reproduces_rule_names_for_cardano_fragment() {
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
            let prev = if abs > 0 { src.as_bytes().get(abs - 1).copied() } else { None };
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
                "definition span mismatch for {}", name,
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
}

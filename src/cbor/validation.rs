//! CDDL / CBOR validation via `anweiss/cddl`.
//!
//! * [`validate_cddl_text`] — schema check (unresolved refs + unproductive cycles).
//! * [`validate_cbor_bytes_against_cddl`] — CBOR vs named rule; spans from a parallel
//!   `decoder::decode_cbor_to_value` walk.
//! * [`decode_hex`] — hex helper.
//!
//! Refs via `cddl_from_pest_str_checked` (+ `unresolved_references` for the rest).
//! Schemas from `document_cache`. Non-root type rules rotate to front; group roots
//! refused; generic type roots use a synthetic wrapper (span correction). Failures
//! ranked by deepest CBOR location, folded, capped. Decode + rule index once per set.

use std::collections::HashSet;
use std::rc::Rc;

use cddl::ast::{Group, GroupEntry, Rule, Type, Type2};
use cddl::validator::Validator;
use serde_json::{json, Map, Value};

use crate::cbor::cddl_tools;
use crate::cbor::decoder;
use crate::cbor::diagnostic;
use crate::cbor::document_cache::{self, SchemaError, SchemaErrorKind};
use crate::cbor::limits;
use crate::cbor::schema_mapper;
use crate::cbor::source_index::{span_json, Utf16Index};
use crate::cbor::tags;

/// Prefix the parser puts on an unresolved rule name.
const MISSING_RULE_PREFIX: &str = "missing definition for rule ";

/// Cap on `unresolved` entries; extras are dropped for the editor buffer.
const MAX_UNRESOLVED_REPORTED: usize = 200;

/// Cap on `additional` after dedup; dropped count goes in `additional_truncated`.
const MAX_ADDITIONAL: usize = 200;

/// Cap on distinct `expected` strings folded into `alternatives`.
const MAX_ALTERNATIVES: usize = 5;

/// Cap on `message`; upstream reasons embed kilobyte `Debug` dumps.
const MAX_MESSAGE_LEN: usize = 400;

/// Cap on rendered `expected`.
const MAX_EXPECTED_LEN: usize = 120;

/// Validate CDDL only. Success: `{ valid: true }`; else `{ valid: false, error }`.
///
/// Undefined names → `unresolved_references` with per-occurrence spans. Empty
/// documents → `no_rules`. Parser errors carry `byte_span` when placeable;
/// omitted (never empty-at-0) when the parser could not locate the fault.
pub fn validate_cddl_text(cddl: &str) -> Value {
    document_cache::with_ast_checked(cddl, |parsed| match parsed {
        Ok(ast) => {
            if ast.rules.is_empty() {
                return failure_result(simple_error("no_rules", "CDDL document defines no rules"));
            }
            // Refs already resolved; this checks whether resolution reaches data.
            if let Some(error) = unproductive_reference_error(cddl, ast) {
                return failure_result(error);
            }
            success_result()
        }
        Err(e) => failure_result(schema_error(cddl, e)),
    })
}

/// Schema-side error object for a parser rejection.
///
/// `message` is the parser text only (strip `Display`'s position prefix —
/// `byte_span` already carries that). Shared with both mappers.
pub(crate) fn schema_error(cddl: &str, e: &SchemaError) -> Value {
    let message = e.message.clone();
    let idx = Utf16Index::new(cddl);

    let name = match e.kind {
        SchemaErrorKind::Unresolved => message
            .strip_prefix(MISSING_RULE_PREFIX)
            .map(str::to_string)
            .unwrap_or_default(),
        kind => {
            let mut error = simple_error(kind.as_str(), &message);
            if let (Value::Object(o), Some(span)) = (&mut error, e.span) {
                o.insert("byte_span".into(), span_json(&idx, span.0, span.1, span.2));
            }
            return error;
        }
    };

    // What the parser itself found: one occurrence, the first.
    let reported: Option<(String, cddl::ast::Span)> = e.span.map(|span| (name, span));

    // Collect every occurrence when the AST walker agrees with the parser on
    // the first offender; otherwise keep the parser's single finding.
    let collected = document_cache::with_ast_unchecked(cddl, |parsed| {
        parsed
            .map(cddl_tools::unresolved_references)
            .unwrap_or_default()
    });
    let agrees = match (collected.first(), &reported) {
        (Some((found, span)), Some((first, first_span))) => {
            found == first && span.0 == first_span.0
        }
        _ => false,
    };
    let occurrences = if agrees {
        collected
    } else {
        reported.into_iter().collect()
    };

    let truncated = occurrences.len() > MAX_UNRESOLVED_REPORTED;
    let unresolved: Vec<Value> = occurrences
        .into_iter()
        .take(MAX_UNRESOLVED_REPORTED)
        .map(|(found, span)| {
            json!({
                "name": found,
                "byte_span": span_json(&idx, span.0, span.1, span.2),
            })
        })
        .collect();

    let mut error = Map::new();
    error.insert("kind".into(), Value::String("unresolved_references".into()));
    error.insert("message".into(), Value::String(message));
    // First occurrence for consumers that only read `byte_span`.
    if let Some(first) = unresolved.first() {
        error.insert("byte_span".into(), first["byte_span"].clone());
    }
    error.insert("unresolved".into(), Value::Array(unresolved));
    error.insert("truncated".into(), Value::Bool(truncated));
    Value::Object(error)
}

/// Validate CBOR bytes against a named CDDL rule.
///
/// Upstream roots at the first non-generic type rule; other type rules are
/// rotated to the front. Generic type roots use a synthetic wrapper.
/// `missing_rule` and `group_rule_root` are refused before that.
pub fn validate_cbor_bytes_against_cddl(cbor: &[u8], cddl: &str, rule_name: &str) -> Value {
    // Checked parse so unresolved refs surface early; AST also answers
    // `missing_rule` / rule kind.
    document_cache::with_ast_checked(cddl, |parsed| {
        let parsed = match parsed {
            Ok(ast) => ast,
            // Same schema-error shape as `validate_cddl_text`.
            Err(e) => return failure_result(schema_error(cddl, e)),
        };

        // Same schema errors as `validate_cddl_text`.
        if let Some(error) = unproductive_reference_error(cddl, parsed) {
            return failure_result(error);
        }

        // Group rules are not data items; refuse rather than wrap (wrapper accepts
        // wrong arity). The same resolution decides the root of every export.
        let root = match resolve_root_rule(parsed, rule_name) {
            Ok(root) => root,
            Err(refusal) => return failure_result(simple_error(refusal.kind, &refusal.message)),
        };
        // The root as written (`$m` for a socket, however it was named).
        let root_name = RuleKey::of(root).to_string();

        // Pre-decode with our decoder for `input_parse` spans/path before the
        // upstream validator sees the bytes.
        if let Err(e) = decoder::decode_cbor_to_value(cbor) {
            return failure_result(input_parse_error(&e, cbor.len()));
        }

        // Same nesting pre-scan as the mappers; refuse before the recursive
        // upstream decoder.
        if limits::NestingBudget::for_document(cbor).is_none() {
            return failure_result(simple_error(
                "nesting_too_deep",
                &limits::cbor_nesting_message(),
            ));
        }

        if let Some(rooted) = with_root_first(parsed, root) {
            return run_validator(
                &rooted,
                cbor,
                ValidationCtx {
                    root_rule: &root_name,
                    cddl,
                    cddl_offset_correction: 0,
                    utf16: Utf16Index::new(cddl),
                },
            );
        }

        // Generic type rules cannot be rotated into root; wrap and re-parse.
        let wrapped = format!(
            "{root} = {rule}\n\n{body}",
            root = synthetic_root_name(cddl),
            rule = root_name,
            body = cddl,
        );
        // Wrapper prefix length — subtract from AST spans back to original CDDL.
        let prefix_len = wrapped.len() - cddl.len();
        document_cache::with_ast_checked(&wrapped, |wrapped_ast| match wrapped_ast {
            Ok(ast) => run_validator(
                ast,
                cbor,
                // Walk from the user rule, not `__cquisitor_root` (wrapper span is in the prefix).
                ValidationCtx {
                    root_rule: &root_name,
                    cddl,
                    cddl_offset_correction: prefix_len,
                    utf16: Utf16Index::new(cddl),
                },
            ),
            Err(e) => failure_result(parser_error(&e.message)),
        })
    })
}

// ============================================================
// Productivity
// ============================================================

/// What a rule body contributes to productivity.
struct RuleFacts<'a> {
    /// Byte span of the rule's name, for an editor to point at.
    span: cddl::ast::Span,
    /// Body reaches data (map, array, tag, literal, prelude) on its own.
    describes_data: bool,
    /// Names the body stands for where standing-for is an alternative, not a
    /// requirement (choices / group entries).
    stands_for: Vec<&'a str>,
}

/// Rules whose resolution never reaches data, with name spans in document order.
///
/// `a = b` / `b = a` passes the ref check but matches nothing. A rule is
/// productive iff it describes data or reaches one that does (backwards from
/// data-describing rules). Choices never make a rule unproductive via a peer.
fn unproductive_rules(ast: &cddl::ast::CDDL<'_>) -> Vec<(String, cddl::ast::Span)> {
    use std::collections::{HashMap, HashSet};

    // `a /=` / `a //=` merge under one name; alternatives only add productivity.
    let defined: HashSet<&str> = ast
        .rules
        .iter()
        .map(|rule| match rule {
            Rule::Type { rule, .. } => rule.name.ident,
            Rule::Group { rule, .. } => rule.name.ident,
        })
        .collect();

    let mut order: Vec<&str> = Vec::new();
    let mut facts: HashMap<&str, RuleFacts> = HashMap::new();
    for rule in &ast.rules {
        let (name, span, generic_params) = match rule {
            Rule::Type { rule, .. } => (rule.name.ident, rule.name.span, &rule.generic_params),
            Rule::Group { rule, .. } => (rule.name.ident, rule.name.span, &rule.generic_params),
        };
        // Generic params stand for the caller's argument, not a same-named rule.
        let bound: HashSet<&str> = generic_params
            .iter()
            .flat_map(|gp| gp.params.iter().map(|p| p.param.ident))
            .collect();

        let mut collector = BodyFacts {
            defined: &defined,
            bound: &bound,
            describes_data: false,
            stands_for: Vec::new(),
        };
        match rule {
            Rule::Type { rule, .. } => collector.ty(&rule.value),
            Rule::Group { rule, .. } => collector.group_entry(&rule.entry),
        }

        match facts.get_mut(name) {
            Some(existing) => {
                existing.describes_data |= collector.describes_data;
                existing.stands_for.extend(collector.stands_for);
            }
            None => {
                order.push(name);
                facts.insert(
                    name,
                    RuleFacts {
                        span,
                        describes_data: collector.describes_data,
                        stands_for: collector.stands_for,
                    },
                );
            }
        }
    }

    // Backwards edges: which rules stand for each name.
    let mut stood_for_by: HashMap<&str, Vec<&str>> = HashMap::new();
    for name in &order {
        for target in &facts[name].stands_for {
            stood_for_by.entry(target).or_default().push(name);
        }
    }

    // Reach backwards from the rules that describe data on their own.
    let mut productive: HashSet<&str> = HashSet::new();
    let mut queue: Vec<&str> = order
        .iter()
        .copied()
        .filter(|name| facts[name].describes_data)
        .collect();
    productive.extend(queue.iter().copied());
    while let Some(name) = queue.pop() {
        for &dependent in stood_for_by.get(name).into_iter().flatten() {
            if productive.insert(dependent) {
                queue.push(dependent);
            }
        }
    }

    order
        .into_iter()
        .filter(|name| !productive.contains(name))
        .map(|name| (name.to_string(), facts[name].span))
        .collect()
}

/// Two productivity facts from one rule body.
struct BodyFacts<'a, 'b> {
    defined: &'b HashSet<&'a str>,
    bound: &'b HashSet<&'a str>,
    describes_data: bool,
    stands_for: Vec<&'a str>,
}

impl<'a> BodyFacts<'a, '_> {
    fn ty(&mut self, ty: &Type<'a>) {
        for choice in &ty.type_choices {
            // Operator constrains its target; the target must describe data.
            self.type2(&choice.type1.type2);
        }
    }

    fn type2(&mut self, t2: &Type2<'a>) {
        match t2 {
            // Bare name stands for the named rule.
            Type2::Typename { ident, .. } | Type2::Unwrap { ident, .. } => self.name(ident.ident),
            Type2::ParenthesizedType { pt, .. } => self.ty(pt),
            // Map/array/tag/literal/`any`/range — describes data.
            _ => self.describes_data = true,
        }
    }

    fn group(&mut self, group: &Group<'a>) {
        for choice in &group.group_choices {
            // Empty group is a terminal (productive stop), not a cycle.
            if choice.group_entries.is_empty() {
                self.describes_data = true;
            }
            for (entry, _) in &choice.group_entries {
                self.group_entry(entry);
            }
        }
    }

    fn group_entry(&mut self, entry: &GroupEntry<'a>) {
        match entry {
            GroupEntry::ValueMemberKey { ge, .. } => {
                // Member key is data regardless of value.
                if ge.member_key.is_some() {
                    self.describes_data = true;
                } else {
                    self.ty(&ge.entry_type);
                }
            }
            GroupEntry::TypeGroupname { ge, .. } => self.name(ge.name.ident),
            GroupEntry::InlineGroup { group, .. } => self.group(group),
        }
    }

    /// A name in a position where standing for something is all it
    /// does.
    fn name(&mut self, ident: &'a str) {
        // Params, sockets, and prelude types count as data.
        if self.bound.contains(ident) || ident.starts_with('$') || !self.defined.contains(ident) {
            self.describes_data = true;
            return;
        }
        self.stands_for.push(ident);
    }
}

/// `unresolved_references` when refs resolve but never reach data; `None` if
/// every rule describes data. Same kind so consumers reuse that handling.
fn unproductive_reference_error(cddl: &str, ast: &cddl::ast::CDDL<'_>) -> Option<Value> {
    let found = unproductive_rules(ast);
    let (first, _) = found.first()?;
    let idx = Utf16Index::new(cddl);
    let message = format!(
        "rule {} resolves only to rules that resolve back to it: following it never reaches \
         a type that describes data",
        first
    );

    let truncated = found.len() > MAX_UNRESOLVED_REPORTED;
    let unresolved: Vec<Value> = found
        .iter()
        .take(MAX_UNRESOLVED_REPORTED)
        .map(|(name, span)| {
            json!({
                "name": name,
                "byte_span": span_json(&idx, span.0, span.1, span.2),
            })
        })
        .collect();

    let mut error = Map::new();
    error.insert("kind".into(), Value::String("unresolved_references".into()));
    error.insert("message".into(), Value::String(message));
    if let Some(first) = unresolved.first() {
        error.insert("byte_span".into(), first["byte_span"].clone());
    }
    error.insert("unresolved".into(), Value::Array(unresolved));
    error.insert("truncated".into(), Value::Bool(truncated));
    Some(Value::Object(error))
}

/// Synthetic root name that cannot already appear in the document.
///
/// A fixed name can collide and yield a parse error the author never wrote.
/// One pass: longer underscore run than any in the source (avoids quadratic grow).
fn synthetic_root_name(cddl: &str) -> String {
    let mut longest_run = 0usize;
    let mut run = 0usize;
    for byte in cddl.bytes() {
        run = if byte == b'_' { run + 1 } else { 0 };
        longest_run = longest_run.max(run);
    }
    format!("{}cquisitor_root", "_".repeat(longest_run + 1))
}

/// AST with the type rule named `root` rotated to the front for upstream's
/// first-type-rule root.
///
/// `None` for group rules or generic type rules. Cheap vs re-parse; spans stay
/// on the original source.
fn with_root_first<'a>(
    ast: &cddl::ast::CDDL<'a>,
    root: &cddl::ast::Identifier<'_>,
) -> Option<cddl::ast::CDDL<'a>> {
    let root = RuleKey::of(root);
    let at = ast.rules.iter().position(|r| {
        matches!(
            r,
            cddl::ast::Rule::Type { rule, .. }
                if RuleKey::of(&rule.name) == root && rule.generic_params.is_none()
        )
    })?;
    let mut rules = ast.rules.clone();
    // Prefix rotate keeps relative order of other rules (type-choice extends).
    rules[..=at].rotate_right(1);
    Some(cddl::ast::CDDL {
        rules,
        comments: ast.comments.clone(),
    })
}

/// Context kept with the validator run for span synthesis from
/// `(cbor_location, rule_name)`.
struct ValidationCtx<'a> {
    root_rule: &'a str,
    /// Original user CDDL (for reading synthesised spans as source).
    cddl: &'a str,
    /// Bytes the wrapper prepended; subtracted so AST spans map to user source.
    cddl_offset_correction: usize,
    /// UTF-16 index over original CDDL for byte/char offsets and line numbers.
    utf16: Utf16Index,
}

/// Run upstream `CBORValidator` on a parsed AST + CBOR bytes.
///
/// Bypasses `validate_cbor_from_slice` (native-only / wasm `JsValue` Result).
fn run_validator(ast: &cddl::ast::CDDL<'_>, cbor: &[u8], ctx: ValidationCtx<'_>) -> Value {
    let cbor_value = match cddl::validator::cbor_value::decode_cbor(cbor) {
        Ok(v) => v,
        // Our decoder accepted bytes upstream rejected — same `input_parse` shape.
        Err(e) => {
            return failure_result(json!({
                "kind": "input_parse",
                "message": e.to_string(),
                "path": "$",
            }))
        }
    };

    // `enabled_features` types differ native vs wasm; `None` infers per target.
    let mut cv = cddl::validator::cbor::CBORValidator::new(ast, cbor_value, None);
    // Set nesting bound explicitly to the crate-documented depth.
    cv.set_max_nesting_depth(limits::MAX_CBOR_VALIDATION_NESTING_DEPTH);
    // Set descent cost bound (levels + rule hops) to documented limits.
    cv.set_max_descent_cost(limits::MAX_CBOR_VALIDATION_DESCENT_COST);
    // Descent budget weights in bytes, matching documented constants.
    cv.set_descent_weights(
        limits::VALIDATOR_LEVEL_COST,
        limits::VALIDATOR_RULE_HOP_COST,
    );
    // Cap open `.cbor` / `.cborseq` payloads (native stack) like the mappers.
    cv.set_max_embedded_depth(limits::MAX_EMBEDDED_DEPTH);
    // Set work bound; choice alternatives can be exponential in nesting.
    cv.set_max_validation_work(limits::MAX_CBOR_VALIDATION_WORK);
    // RFC 8610 sizes a string as a whole, and so does every Cardano decoder
    // but one: Plutus data byte strings (`bounded_bytes = bytes .size (0..64)`)
    // are bounded one chunk at a time, so a longer value is written as an
    // indefinite-length string of chunks of at most 64 bytes. Only a string
    // matched against a rule named in `PER_CHUNK_SIZE_RULES` takes that
    // reading, and there only the upper bound of a `.size` range applies
    // per chunk; an exact size and a lower bound hold the whole string.
    // Every other string, metadata strings (bounded as a whole, chunked or
    // not) and text strings included, is sized as a whole.
    cv.set_size_control_per_chunk(true);
    cv.set_size_control_per_chunk_rules(Some(
        PER_CHUNK_SIZE_RULES
            .iter()
            .map(|rule| rule.to_string())
            .collect(),
    ));

    match cv.validate() {
        Ok(()) => success_result(),
        Err(err) => failure_result(map_cbor_error(&err, cbor, ast, &ctx)),
    }
}

/// The type rules whose strings are held to a `.size` range's upper bound
/// one chunk at a time when written in indefinite length: the Plutus data
/// byte string, which the ledger bounds per chunk. Every other string is
/// sized as a whole (RFC 8610). The schema mapper applies the same reading
/// when it chooses between alternatives.
pub(crate) const PER_CHUNK_SIZE_RULES: &[&str] = &["bounded_bytes"];

/// Hex-decode helper for the wasm wrapper.
pub fn decode_hex(cbor_hex: &str) -> Result<Vec<u8>, crate::js_error::JsError> {
    hex::decode(cbor_hex)
        .map_err(|e| crate::js_error::JsError::new(&format!("invalid CBOR hex: {}", e)))
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
    let message = strip_parser_position(message);
    // Keep "missing definition for rule X" as its own kind for UIs.
    let kind = if message.contains("missing definition for rule") {
        "unresolved_references"
    } else {
        "parse_error"
    };
    simple_error(kind, message)
}

/// Strip the parser `Display` position prefix; positional data belongs in
/// `byte_span`.
fn strip_parser_position(message: &str) -> &str {
    let Some(rest) = message.strip_prefix("parsing error: ") else {
        return message;
    };
    if let Some(i) = rest.find(", msg: ") {
        return &rest[i + ", msg: ".len()..];
    }
    rest.strip_prefix("msg: ").unwrap_or(message)
}

/// Public error for CBOR that did not decode.
///
/// Cursor-only failures get a one-byte span at the stop offset. Shared with
/// both mappers; nesting-limit keeps its own kind.
pub(crate) fn input_parse_error(
    e: &crate::cbor::errors::CborDecodeError,
    cbor_len: usize,
) -> Value {
    // Implementation limits keep their own kind, not `input_parse`.
    let kind = match e.kind {
        crate::cbor::errors::ErrorKind::NestingTooDeep => "nesting_too_deep",
        _ => "input_parse",
    };
    let mut obj = Map::new();
    obj.insert("kind".into(), Value::String(kind.into()));
    obj.insert("message".into(), Value::String(e.message.clone()));
    obj.insert("path".into(), Value::String(e.path.clone()));
    if let Some(off) = e.offset {
        obj.insert("offset".into(), Value::Number(off.into()));
    }
    let span = e.byte_span.or_else(|| {
        let off = e.offset?;
        if cbor_len == 0 {
            return None;
        }
        let start = off.min(cbor_len - 1);
        Some((start, 1))
    });
    if let Some((off, len)) = span {
        obj.insert(
            "byte_spans".into(),
            Value::Array(vec![json!({"offset": off, "length": len})]),
        );
    }
    Value::Object(obj)
}

/// The rule `name` names as the root, with its kind; `None` if undefined.
///
/// `name` is the rule's name as written and as `cddl_outline` reports it:
/// a socket with its prefix (`$m`, `$$g`), so `m` and `$m` are two rules. A
/// socket may also be named by its identifier alone (`m` for `$m`) when no
/// rule is written `m`. A type rule wins over a group rule of the same
/// name (usable as root).
pub(crate) fn find_root_rule<'a>(
    cddl_ast: &'a cddl::ast::CDDL<'a>,
    name: &str,
) -> Option<(&'a cddl::ast::Identifier<'a>, RootRuleKind)> {
    let named = |matches: &dyn Fn(RuleKey<'a>) -> bool| {
        let mut found = None;
        for rule in &cddl_ast.rules {
            match rule {
                cddl::ast::Rule::Type { rule, .. } if matches(RuleKey::of(&rule.name)) => {
                    return Some((&rule.name, RootRuleKind::Type))
                }
                cddl::ast::Rule::Group { rule, .. }
                    if found.is_none() && matches(RuleKey::of(&rule.name)) =>
                {
                    found = Some((&rule.name, RootRuleKind::Group))
                }
                _ => {}
            }
        }
        found
    };
    named(&|key| key.is_written(name)).or_else(|| {
        if name.starts_with('$') {
            return None;
        }
        named(&|key| key.is_socket() && key.ident == name)
    })
}

/// Why a name cannot be the root of a walk: `kind` is `missing_rule` or
/// `group_rule_root`.
#[derive(Clone, Debug)]
pub(crate) struct RootRefusal {
    pub(crate) kind: &'static str,
    pub(crate) message: String,
}

/// The type rule the name `name` roots a walk at, as every export resolves
/// it (validate, decode and map alike): the rule [`find_root_rule`] finds,
/// refused when it is undefined or a group rule. A group rule describes
/// entries, never a data item, so a group socket is never a root; the
/// identifier of a socket written without its prefix (`m`) stands for its
/// type socket (`$m`) whenever there is one.
pub(crate) fn resolve_root_rule<'a>(
    cddl_ast: &'a cddl::ast::CDDL<'a>,
    name: &str,
) -> Result<&'a cddl::ast::Identifier<'a>, RootRefusal> {
    match find_root_rule(cddl_ast, name) {
        None => Err(RootRefusal {
            kind: "missing_rule",
            message: schema_mapper::missing_rule_message(name),
        }),
        Some((_, RootRuleKind::Group)) => Err(RootRefusal {
            kind: "group_rule_root",
            message: schema_mapper::group_rule_root_message(name),
        }),
        Some((root, RootRuleKind::Type)) => Ok(root),
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum RootRuleKind {
    Type,
    Group,
}

/// Map upstream CBOR validator errors to public JSON (`kind`, `message`,
/// `expected`, `path`, spans, `additional`).
///
/// Schema faults stay CDDL-side; decode faults → `input_parse`.
fn map_cbor_error(
    err: &cddl::validator::cbor::Error<std::io::Error>,
    cbor: &[u8],
    ast: &cddl::ast::CDDL<'_>,
    ctx: &ValidationCtx<'_>,
) -> Value {
    use cddl::validator::cbor::Error as CborError;

    match err {
        CborError::Validation(errs) if !errs.is_empty() => {
            // Decode once for the whole error set.
            let tree = decoder::decode_cbor_to_value(cbor).ok();
            // Index rules once for typename hops.
            let rules = RuleIndex::new(ast, ctx.root_rule);
            // One budget for every span walked in the report.
            let spans = SpanWalkBudget::new();
            // Map errors head-first until location-segment budget is spent; count the rest
            // as dropped.
            let ranked = rank_errors(errs);
            let mut walked = 0usize;
            let mut mapped: Vec<Value> = Vec::new();
            // Resolve each distinct location once (tags transparent → chain cost per location).
            let mut located = LocatedNodes::new();
            for i in ranked.iter().copied() {
                walked += location_depth(&errs[i].cbor_location).max(1);
                if !mapped.is_empty() && walked > MAX_MAPPED_LOCATION_SEGMENTS {
                    break;
                }
                mapped.push(cbor_validation_error(
                    &errs[i],
                    cbor,
                    tree.as_deref(),
                    &mut located,
                    &rules,
                    &spans,
                    ctx,
                ));
            }
            let unmapped = ranked.len() - mapped.len();
            fold_errors(mapped, unmapped)
        }
        CborError::Validation(_) => simple_error("generic", &err.to_string()),
        // Schema control-operator fault (no value) — own kind, not a data mismatch.
        CborError::InvalidSchema(e) => simple_error(
            "invalid_schema",
            &truncate_ellipsis(&e.reason, MAX_MESSAGE_LEN),
        ),
        CborError::CDDLParsing(msg) => parser_error(msg),
        // Document-decode channels must not fall through to CDDL/`generic` kinds.
        CborError::CBORParsing(e) => simple_error("input_parse", &e.to_string()),
        // Upstream decoder nesting stop is a limit, not malformed input.
        CborError::CBORDecoding(cddl::validator::cbor_value::DecodeError::NestedTooDeeply) => {
            simple_error("nesting_too_deep", &err.to_string())
        }
        CborError::CBORDecoding(e) => simple_error("input_parse", &e.to_string()),
        other => simple_error("generic", &other.to_string()),
    }
}

/// Order reported errors, head first.
///
/// Rank by deepest CBOR location (not schema order). Limits outrank depth.
/// `is_multi_*_choice` is not used for ranking but exposed as `from_type_choice`.
fn rank_errors(errs: &[cddl::validator::cbor::ValidationError]) -> Vec<usize> {
    fn depth(e: &cddl::validator::cbor::ValidationError) -> usize {
        location_depth(&e.cbor_location)
    }
    fn is_limit(e: &cddl::validator::cbor::ValidationError) -> bool {
        is_validator_limit(&e.reason.to_ascii_lowercase())
    }
    let mut head = 0usize;
    let mut best = depth(&errs[0]);
    let mut head_is_limit = is_limit(&errs[0]);
    for (i, e) in errs.iter().enumerate().skip(1) {
        let limit = is_limit(e);
        let d = depth(e);
        let better = match (head_is_limit, limit) {
            (false, true) => true,
            (true, false) => false,
            _ => d > best,
        };
        if better {
            best = d;
            head = i;
            head_is_limit = limit;
        }
    }
    let mut order = Vec::with_capacity(errs.len());
    order.push(head);
    order.extend((0..errs.len()).filter(|i| *i != head));
    order
}

/// Fold mapped errors into the public shape.
///
/// Choice alternatives that share `(path, cddl_byte_span, kind)` merge:
/// `occurrences` + distinct `expected` in `alternatives`. Cap survivors;
/// dropped count → `additional_truncated`.
fn fold_errors(mapped: Vec<Value>, unmapped: usize) -> Value {
    use std::collections::HashMap;

    struct Group {
        entry: Value,
        occurrences: usize,
        alternatives: Vec<String>,
    }

    let mut groups: Vec<Group> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    for entry in mapped {
        let key = format!(
            "{}\u{1}{}\u{1}{}",
            entry["path"], entry["cddl_byte_span"], entry["kind"]
        );
        let expected = entry
            .get("expected")
            .and_then(Value::as_str)
            .map(str::to_string);
        match index.get(&key) {
            Some(&i) => {
                groups[i].occurrences += 1;
                if let Some(x) = expected {
                    if !groups[i].alternatives.contains(&x) {
                        groups[i].alternatives.push(x);
                    }
                }
            }
            None => {
                index.insert(key, groups.len());
                groups.push(Group {
                    entry,
                    occurrences: 1,
                    alternatives: expected.into_iter().collect(),
                });
            }
        }
    }

    let mut entries: Vec<Value> = groups
        .into_iter()
        .map(|g| {
            let mut entry = g.entry;
            if let Value::Object(o) = &mut entry {
                if g.occurrences > 1 {
                    o.insert("occurrences".into(), Value::from(g.occurrences));
                }
                if g.alternatives.len() > 1 {
                    o.insert(
                        "alternatives".into(),
                        Value::Array(
                            g.alternatives
                                .into_iter()
                                .take(MAX_ALTERNATIVES)
                                .map(Value::String)
                                .collect(),
                        ),
                    );
                }
            }
            entry
        })
        .collect();

    let mut head = entries.remove(0);
    let dropped = entries.len().saturating_sub(MAX_ADDITIONAL) + unmapped;
    entries.truncate(MAX_ADDITIONAL);
    if let Value::Object(o) = &mut head {
        if !entries.is_empty() {
            o.insert("additional".into(), Value::Array(entries));
        }
        if dropped > 0 {
            o.insert("additional_truncated".into(), Value::from(dropped));
        }
    }
    head
}

fn cbor_validation_error<'t>(
    e: &cddl::validator::cbor::ValidationError,
    cbor: &[u8],
    tree: Option<&'t Value>,
    located: &mut LocatedNodes<'t>,
    rules: &RuleIndex<'_>,
    spans: &SpanWalkBudget,
    ctx: &ValidationCtx<'_>,
) -> Value {
    let reason = e.reason.as_str();
    // Classify on raw reason before condensing rewrites bucket substrings.
    let kind = classify_reason(reason);

    let mut obj = Map::new();
    obj.insert("kind".into(), Value::String(kind.into()));

    let path = match tree {
        Some(tree) => json_path_in_tree(tree, &e.cbor_location, &mut located.keys),
        None => cbor_location_to_json_path(&e.cbor_location),
    };
    obj.insert("path".into(), Value::String(path));
    if e.is_multi_type_choice {
        obj.insert("from_type_choice".into(), Value::Bool(true));
    }

    // CBOR spans from decoded tree via `cbor_location`. For tagged paths, report
    // the item the reason renders (wrapper vs content).
    let names_tag = reason_names_tagged_item(reason);
    // An unexpected key is about the whole entry: its spans are the key's,
    // then the value's, so a consumer can point at the key and shade the
    // entry.
    let about_entry = reason_is_about_map_entry(reason);
    let mut preview: Option<String> = None;
    let mut cddl_source: Option<String> = None;
    if let Some(tree) = tree {
        if let Some(located) = located.resolve(tree, &e.cbor_location, cbor.len()) {
            let views: Vec<&NodeView> = match (&located.key, about_entry) {
                // The entry is the key and the whole value, tag heads included.
                (Some(key), true) => vec![key, &located.tagged],
                _ => vec![located.view(names_tag)],
            };
            let spans: Vec<Value> = views.iter().filter_map(|v| v.span.clone()).collect();
            let anchors: Vec<Value> = views.iter().filter_map(|v| v.anchor.clone()).collect();
            let has_span = !spans.is_empty() || !anchors.is_empty();
            if !spans.is_empty() {
                obj.insert("byte_spans".into(), Value::Array(spans));
            }
            // Containers use `struct_position_info` for anchors; scalars fall back to
            // `position_info`.
            if !anchors.is_empty() {
                obj.insert("anchor_spans".into(), Value::Array(anchors));
            }
            if located.embedded && has_span {
                // Spans address an embedded payload, not the outer document.
                obj.insert("embedded_span".into(), Value::Bool(true));
            }
            preview = Some(views[0].preview.clone());
        }

        // CDDL span: AST walk on the same location. An unexpected key names
        // no member of the schema, so its span is the map type's: the walk
        // goes to the map, not on through the key, and on through the rule
        // naming the map to the map written out.
        let (schema_location, end) = if about_entry {
            (parent_location(&e.cbor_location), SpanEnd::MapHolding)
        } else {
            (e.cbor_location.clone(), SpanEnd::Item)
        };
        if let Some(span) = cddl_byte_span_for(rules, ctx, &schema_location, end, spans) {
            // `span` is `(start, end)` in user CDDL.
            cddl_source = ctx.cddl.get(span.0..span.1).map(str::to_string);
            obj.insert(
                "cddl_byte_span".into(),
                span_json(&ctx.utf16, span.0, span.1, ctx.utf16.line_at(span.0)),
            );
        }
    }

    obj.insert(
        "message".into(),
        Value::String(condense_reason(
            reason,
            preview.as_deref(),
            cddl_source.as_deref(),
        )),
    );
    if let Some(expected) = extract_expected(reason) {
        obj.insert(
            "expected".into(),
            Value::String(condense_expected(&expected, cddl_source.as_deref())),
        );
    }

    Value::Object(obj)
}

/// Bucket free-form anweiss reason strings into stable `kind` values.
fn classify_reason(reason: &str) -> &'static str {
    let lower = reason.to_ascii_lowercase();
    // Limits first — unchecked below the bound must not read as mismatch.
    if is_work_limit(&lower) {
        return "validation_too_complex";
    }
    if is_validator_limit(&lower) {
        return "nesting_too_deep";
    }
    // Cut wording only; looser "cut"+"map" false-positives on quoted text.
    if lower.contains("cut present for member key") || lower.contains("map cut") {
        "map_cut"
    } else if lower.contains("unresolved")
        || lower.contains("unknown rule")
        || lower.contains("undefined rule")
    {
        "unresolved_references"
    } else if lower.contains("expected ")
        || lower.contains("but got")
        || lower.contains("type mismatch")
        || lower.contains("doesn't match")
        || lower.contains("does not match")
    {
        "mismatch"
    } else {
        "generic"
    }
}

/// Lowercased reason names an implementation bound (nesting, rule hops,
/// descent budget, or work) rather than a data property.
///
/// Ranked ahead of mismatches; kinds differ at the call site.
fn is_validator_limit(lower: &str) -> bool {
    lower.contains("maximum supported nesting depth")
        || lower.contains("maximum supported rule nesting")
        || lower.contains("maximum supported descent budget")
        // Open `.cbor` / `.cborseq` payload chain past the hold limit.
        || lower.contains("open payloads")
        // Decoder nesting stop inside an embedded payload.
        || lower.contains("maximum supported decoding depth")
        || is_work_limit(lower)
}

/// Work-step bound (not nesting). Own kind: reachable inside nesting limits
/// when choice alternatives explode.
fn is_work_limit(lower: &str) -> bool {
    lower.contains("steps of validation work")
}

/// Max verbatim `, got …` tail; longer `Debug` dumps use the located preview.
const MAX_GOT_LEN: usize = 60;

/// Cap on location segments mapped per report.
///
/// Shallow sets map whole; deep recursive reports keep the head and deepest
/// errors that name the failing node.
const MAX_MAPPED_LOCATION_SEGMENTS: usize = 262_144;

/// Longest CDDL source snippet substituted for a collapsed AST dump.
const MAX_SNIPPET_LEN: usize = 60;

/// Rewrite a validator reason for display: replace CBOR/AST `Debug` dumps
/// with the located node preview and CDDL span text.
fn condense_reason(reason: &str, node_preview: Option<&str>, cddl_source: Option<&str>) -> String {
    let mut out = collapse_debug_structs(reason, cddl_source);
    if let Some(pos) = out.rfind(", got ") {
        let tail_start = pos + ", got ".len();
        let tail = &out[tail_start..];
        // Replace long or elided `, got` tails with the located node preview.
        if tail.len() > MAX_GOT_LEN || lost_data_item(tail) {
            let replacement = match node_preview {
                Some(p) => p.to_string(),
                None => truncate_ellipsis(tail, MAX_GOT_LEN),
            };
            out = format!("{}{}", &out[..tail_start], replacement);
        }
    }
    truncate_ellipsis(&out, MAX_MESSAGE_LEN)
}

/// How the validator's renderer opens a tagged data item.
const TAG_RENDERING_PREFIX: &str = "Tag(";

/// True when the `, got` item is a tag (`Tag(…)`), even if truncated.
fn reason_names_tagged_item(reason: &str) -> bool {
    match reason.rfind(", got ") {
        Some(pos) => reason[pos + ", got ".len()..].starts_with(TAG_RENDERING_PREFIX),
        None => false,
    }
}

/// True when the reason is about a map entry as a whole rather than about
/// the item at the location: the validator's `unexpected key <k>`, located
/// at the entry.
fn reason_is_about_map_entry(reason: &str) -> bool {
    reason.starts_with("unexpected key ")
}

/// The location of the item enclosing the one `loc` names (the map, for a
/// map entry); the root's parent is the root.
fn parent_location(loc: &str) -> String {
    let trimmed = loc.trim_start_matches('/');
    let mut segments = split_location_segments(trimmed);
    segments.pop();
    if segments.is_empty() {
        return String::new();
    }
    format!("/{}", segments.join("/"))
}

/// True when a `, got` tail only names a kind ([`ELIDED_BODY`]), not a value.
fn lost_data_item(tail: &str) -> bool {
    tail.contains(ELIDED_BODY)
}

/// Same condensation for `expected` (carved from the same reason string).
fn condense_expected(expected: &str, cddl_source: Option<&str>) -> String {
    truncate_ellipsis(
        collapse_debug_structs(expected, cddl_source).trim(),
        MAX_EXPECTED_LEN,
    )
}

/// Replace CBOR `Debug` items, `Ident { … }` dumps, and long number lists.
///
/// Data items first so nested text/bytes are not mistaken for structure.
fn collapse_debug_structs(s: &str, cddl_source: Option<&str>) -> String {
    collapse_number_lists(&collapse_struct_dumps(&collapse_data_items(s), cddl_source))
}

/// Collapse long `[171, 171, …]` byte dumps to an item count.
fn collapse_number_lists(s: &str) -> String {
    /// Below this a list is short enough to read as it stands.
    const MIN_COLLAPSED: usize = 4;

    let mut out = String::new();
    let mut rest = s;
    while let Some(open) = rest.find('[') {
        let Some(close_rel) = rest[open + 1..].find(']') else {
            break;
        };
        let close = open + 1 + close_rel;
        let body = &rest[open + 1..close];
        let items: Vec<&str> = body.split(',').map(str::trim).collect();
        let all_numeric = !body.is_empty()
            && items
                .iter()
                .all(|i| !i.is_empty() && i.bytes().all(|b| b.is_ascii_digit()));
        out.push_str(&rest[..open]);
        if all_numeric && items.len() >= MIN_COLLAPSED {
            out.push_str(&format!("[… {} items]", items.len()));
        } else {
            out.push_str(&rest[open..=close]);
        }
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    out
}

/// Max descent into a `Debug` data item; past this the text is not one.
const MAX_DATA_ITEM_DEPTH: usize = 16;

/// Longest text kept when a text data item is rendered.
const MAX_PREVIEW_TEXT_LEN: usize = 40;

/// Longest hex kept when a byte string is rendered.
const MAX_PREVIEW_HEX_LEN: usize = 32;

/// The `Debug` constructor names a CBOR data item is rendered with.
/// `Null` has no body and is matched separately.
const DATA_ITEM_CTORS: &[&str] = &[
    "Integer", "Bytes", "Float", "Text", "Bool", "Simple", "Tag", "Array", "Map",
];

/// Replace each `Debug` CBOR item with the short form from [`node_preview`].
///
/// Keyed on rendering shape (`Integer(…)` etc.), not length.
fn collapse_data_items(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::new();
    let mut pos = 0usize;
    while pos < s.len() {
        // Constructors only at identifier boundaries (`MyText("…")` left alone).
        let at_boundary = pos == 0 || !is_ident_byte(bytes[pos - 1]);
        if at_boundary {
            if let Some((rendered, next)) = parse_data_item(s, pos, 0) {
                out.push_str(&rendered);
                pos = next;
                continue;
            }
        }
        let c = s[pos..].chars().next().expect("pos is a char boundary");
        out.push(c);
        pos += c.len_utf8();
    }
    out
}

/// Read the data item rendered at `pos`, returning its short form and
/// the offset just past it.
fn parse_data_item(s: &str, pos: usize, depth: usize) -> Option<(String, usize)> {
    if depth > MAX_DATA_ITEM_DEPTH {
        return None;
    }
    let rest = &s[pos..];
    if let Some(after) = rest.strip_prefix("Null") {
        if !after.as_bytes().first().copied().is_some_and(is_ident_byte) {
            return Some(("null".to_string(), pos + "Null".len()));
        }
    }
    let name = DATA_ITEM_CTORS
        .iter()
        .find(|n| rest.starts_with(**n) && rest[n.len()..].starts_with('('))?;
    let body_start = pos + name.len() + 1;
    // Unclosed body → rendering was truncated; use the elided stand-in.
    let Some(end) = balanced_delim_end(&s[body_start..], '(', ')') else {
        return Some((elided_data_item(name), s.len()));
    };
    let close = body_start + end - 1;
    Some((
        render_data_item(name, &s[body_start..close], depth),
        close + 1,
    ))
}

/// Stand-in where the original rendering kept nothing usable.
const ELIDED_BODY: &str = "(…)";

/// Short form for a data item whose body could not be read.
fn elided_data_item(name: &str) -> String {
    format!("{}{}", name.to_ascii_lowercase(), ELIDED_BODY)
}

/// Short form for one data item, from its `Debug` body.
fn render_data_item(name: &str, body: &str, depth: usize) -> String {
    let body = body.trim();
    // How the renderer marks a level it stopped descending at.
    if body == "..." {
        return elided_data_item(name);
    }
    let rendered = match name {
        // Integer wraps another `Debug` tuple.
        "Integer" => numeric(strip_ctor(body, "Integer").unwrap_or(body).trim()),
        "Float" => numeric(body),
        "Bool" => (body == "true" || body == "false").then(|| body.to_string()),
        "Simple" => numeric(body).map(|n| format!("simple({})", n)),
        "Text" => text_literal(body)
            .map(|t| format!("text \"{}\"", truncate_ellipsis(t, MAX_PREVIEW_TEXT_LEN))),
        "Bytes" => byte_list(body).map(|b| {
            format!(
                "bytes 0x{} ({} bytes)",
                truncate_ellipsis(&hex::encode(&b), MAX_PREVIEW_HEX_LEN),
                b.len()
            )
        }),
        "Array" => list_items(body).map(|n| format!("array({} items)", n)),
        "Map" => list_items(body).map(|n| format!("map({} entries)", n)),
        "Tag" => tagged(body, depth),
        _ => None,
    };
    rendered.unwrap_or_else(|| elided_data_item(name))
}

/// `#6.<tag>(<item>)` from a `Tag` body: the tag number, then the item.
fn tagged(body: &str, depth: usize) -> Option<String> {
    let (tag, rest) = body.split_once(',')?;
    let tag = numeric(tag.trim())?;
    let rest = rest.trim();
    match parse_data_item(rest, 0, depth + 1) {
        // Partial body would silently drop the rest; treat as unread.
        Some((inner, end)) if rest[end..].trim().is_empty() => {
            Some(format!("#6.{}({})", tag, inner))
        }
        _ => Some(format!("#6.{}{}", tag, ELIDED_BODY)),
    }
}

/// `s` verbatim when it is a number, so no precision is lost rewriting
/// it; `None` when it is anything else.
fn numeric(s: &str) -> Option<String> {
    let digits = s.strip_prefix('-').unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        // Floats and the non-finite renderings of them.
        s.parse::<f64>().ok()?;
    }
    Some(s.to_string())
}

/// Contents of a `Debug` string literal, escapes left as they are.
fn text_literal(s: &str) -> Option<&str> {
    s.strip_prefix('"')?.strip_suffix('"')
}

/// The bytes of a `Debug`-rendered `Vec<u8>`.
fn byte_list(s: &str) -> Option<Vec<u8>> {
    split_top_level(s.strip_prefix('[')?.strip_suffix(']')?)?
        .into_iter()
        .map(|item| item.trim().parse::<u8>().ok())
        .collect()
}

/// How many items a `Debug`-rendered list holds.
fn list_items(s: &str) -> Option<usize> {
    Some(split_top_level(s.strip_prefix('[')?.strip_suffix(']')?)?.len())
}

/// Split on the commas of `s` that no bracket and no string literal
/// encloses. `None` when the delimiters in `s` do not balance.
fn split_top_level(s: &str) -> Option<Vec<&str>> {
    if s.trim().is_empty() {
        return Some(Vec::new());
    }
    let mut items = Vec::new();
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut start = 0usize;
    for (i, c) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_string => escaped = true,
            '"' => in_string = !in_string,
            '(' | '[' | '{' if !in_string => depth += 1,
            ')' | ']' | '}' if !in_string => depth = depth.checked_sub(1)?,
            ',' if !in_string && depth == 0 => {
                items.push(&s[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    if depth != 0 || in_string {
        return None;
    }
    items.push(&s[start..]);
    Some(items)
}

/// The body of `Ctor(…)` when `s` is exactly that, with nothing after it.
fn strip_ctor<'a>(s: &'a str, ctor: &str) -> Option<&'a str> {
    let rest = s.strip_prefix(ctor)?.strip_prefix('(')?;
    (balanced_delim_end(rest, '(', ')')? == rest.len()).then(|| &rest[..rest.len() - 1])
}

/// Replace `Ident { … }` `Debug` structs; braces inside strings ignored.
fn collapse_struct_dumps(s: &str, cddl_source: Option<&str>) -> String {
    let mut out = String::new();
    let mut rest = s;
    // Bounded: each pass consumes at least the struct it collapsed.
    for _ in 0..16 {
        let Some((before, name, body_start)) = next_debug_struct(rest) else {
            break;
        };
        out.push_str(before);
        match balanced_brace_end(&rest[body_start..]) {
            Some(end) => {
                let body = &rest[body_start..body_start + end];
                out.push_str(&compact_ast(name, body, cddl_source));
                rest = &rest[body_start + end..];
            }
            None => {
                // Unbalanced — the rest is one truncated dump.
                out.push_str(&compact_ast(name, &rest[body_start..], cddl_source));
                rest = "";
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Find the next `Ident {` in `s`. Returns the text before it, the
/// identifier, and the byte index just past the opening brace.
fn next_debug_struct(s: &str) -> Option<(&str, &str, usize)> {
    let bytes = s.as_bytes();
    let mut search = 0usize;
    while let Some(rel) = s[search..].find(" {") {
        let brace = search + rel + 1;
        // Walk back over the identifier preceding the space.
        let mut start = brace - 1;
        while start > 0 && is_ident_byte(bytes[start - 1]) {
            start -= 1;
        }
        let name = &s[start..brace - 1];
        let boundary_ok = start == 0 || !is_ident_byte(bytes[start - 1]);
        if boundary_ok
            && name
                .as_bytes()
                .first()
                .is_some_and(|c| c.is_ascii_uppercase())
        {
            return Some((&s[..start], name, brace + 1));
        }
        search = brace + 1;
    }
    None
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Byte index just past the `}` matching an already-opened brace.
fn balanced_brace_end(s: &str) -> Option<usize> {
    balanced_delim_end(s, '{', '}')
}

/// Index past matching `close`; delimiters inside string literals ignored.
fn balanced_delim_end(s: &str, open: char, close: char) -> Option<usize> {
    let mut depth = 1usize;
    let mut in_string = false;
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_string => escaped = true,
            '"' => in_string = !in_string,
            _ if in_string => {}
            _ if c == open => depth += 1,
            _ if c == close => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + c.len_utf8());
                }
            }
            _ => {}
        }
    }
    None
}

/// Compact stand-in for a collapsed AST dump.
fn compact_ast(name: &str, body: &str, cddl_source: Option<&str>) -> String {
    if name == "TaggedData" {
        if let Some(tag) = literal_tag(body) {
            return format!("#6.{}(…)", tag);
        }
    }
    match cddl_source {
        Some(src) if !src.is_empty() && src.len() <= MAX_SNIPPET_LEN && !src.contains('\n') => {
            src.to_string()
        }
        _ => format!("{}(…)", name),
    }
}

/// Read the tag number out of a `TaggedData` dump, i.e. the digits in the
/// first `Literal(<digits>)`.
fn literal_tag(body: &str) -> Option<&str> {
    let start = body.find("Literal(")? + "Literal(".len();
    let rest = &body[start..];
    let end = rest.find(|c: char| !c.is_ascii_digit())?;
    if end == 0 {
        return None;
    }
    Some(&rest[..end])
}

/// Truncate on a character boundary, marking that something was cut.
fn truncate_ellipsis(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max.saturating_sub(1);
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// Max tag wrappers named in a preview; rest elided (decoder depth is larger).
const MAX_PREVIEW_TAG_DEPTH: usize = 4;

/// One-line rendering of a decoded CBOR node, for use in place of the
/// validator's `Debug` dump of the same value.
fn node_preview(node: &Value) -> String {
    node_preview_at(node, 0)
}

fn node_preview_at(node: &Value, depth: usize) -> String {
    let type_name = node.get("type").and_then(Value::as_str).unwrap_or("value");
    // `Break` terminates an indefinite container; not an item.
    let count = |field: &str| {
        node.get(field)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter(|v| v.get("type").and_then(Value::as_str) != Some("Break"))
                    .count()
            })
            .unwrap_or(0)
    };
    // A container declares its length, or declares that it has none.
    let indefinite = node.get("items").and_then(Value::as_str) == Some("Indefinite");
    match type_name {
        // Tag by number plus wrapped item.
        "Tag" => match node
            .get("tag")
            .and_then(Value::as_str)
            .and_then(tags::tag_number)
        {
            Some(tag) => {
                let inner = match node.get("value") {
                    Some(inner) if depth < MAX_PREVIEW_TAG_DEPTH => {
                        format!("({})", node_preview_at(inner, depth + 1))
                    }
                    _ => ELIDED_BODY.to_string(),
                };
                format!("#6.{}{}", tag, inner)
            }
            // A name no tag is shown under leaves nothing to name it by.
            None => format!("tag{}", ELIDED_BODY),
        },
        "Array" if indefinite => format!("indefinite array({} items)", count("values")),
        "Array" => format!("array({} items)", count("values")),
        "Map" if indefinite => format!("indefinite map({} entries)", count("values")),
        "Map" => format!("map({} entries)", count("values")),
        "IndefiniteLengthBytes" => format!("indefinite bytes({} chunks)", count("chunks")),
        "IndefiniteLengthString" => format!("indefinite text({} chunks)", count("chunks")),
        "String" => match node.get("value").and_then(Value::as_str) {
            Some(s) => format!("text {:?}", truncate_ellipsis(s, MAX_PREVIEW_TEXT_LEN)),
            None => "text".to_string(),
        },
        "Bytes" => match node.get("value").and_then(Value::as_str) {
            Some(h) => format!(
                "bytes 0x{} ({} bytes)",
                truncate_ellipsis(h, MAX_PREVIEW_HEX_LEN),
                h.len() / 2
            ),
            None => "bytes".to_string(),
        },
        "Simple" => match node.get("value") {
            Some(v) if !v.is_null() => format!("simple({})", v),
            _ => "simple".to_string(),
        },
        "Bool" | "Null" | "Undefined" => match node.get("value") {
            Some(Value::Null) | None => type_name.to_ascii_lowercase(),
            Some(v) => format!("{}", v),
        },
        _ => match node.get("value") {
            Some(v) if !v.is_null() => truncate_ellipsis(&v.to_string(), 40),
            _ => type_name.to_string(),
        },
    }
}

/// A rule's name as written: its socket prefix (`$`, `$$` or none) and its
/// identifier. `m`, `$m` and `$$m` are three rules.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) struct RuleKey<'a> {
    prefix: &'static str,
    ident: &'a str,
}

impl<'a> RuleKey<'a> {
    /// The name `id` denotes. An identifier whose text already carries the
    /// socket prefix denotes the same rule as one written with it.
    pub(crate) fn of(id: &cddl::ast::Identifier<'a>) -> Self {
        use cddl::token::SocketPlug;
        match id.socket {
            Some(SocketPlug::TYPE) => RuleKey {
                prefix: "$",
                ident: id.ident,
            },
            Some(SocketPlug::GROUP) => RuleKey {
                prefix: "$$",
                ident: id.ident,
            },
            None => Self::parse(id.ident),
        }
    }

    /// The name `written` spells: a leading `$$` or `$` is its socket prefix.
    pub(crate) fn parse(written: &'a str) -> Self {
        if let Some(ident) = written.strip_prefix("$$") {
            RuleKey {
                prefix: "$$",
                ident,
            }
        } else if let Some(ident) = written.strip_prefix('$') {
            RuleKey { prefix: "$", ident }
        } else {
            RuleKey {
                prefix: "",
                ident: written,
            }
        }
    }

    /// Whether this is the name `written` spells.
    pub(crate) fn is_written(&self, written: &str) -> bool {
        written.len() == self.prefix.len() + self.ident.len()
            && written.starts_with(self.prefix)
            && &written[self.prefix.len()..] == self.ident
    }

    /// Whether the name is a socket's (written with `$` or `$$`).
    pub(crate) fn is_socket(&self) -> bool {
        !self.prefix.is_empty()
    }

    /// The identifier, without the socket prefix.
    pub(crate) fn ident(&self) -> &'a str {
        self.ident
    }

    /// The socket prefix: `$`, `$$`, or empty.
    pub(crate) fn prefix(&self) -> &'static str {
        self.prefix
    }
}

impl std::fmt::Display for RuleKey<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.prefix, self.ident)
    }
}

/// Parsed rules indexed by name.
///
/// Span walkers hop typenames per path segment; linear scan dominates large sets.
struct RuleIndex<'a> {
    /// Every body of each type rule, in document order: one, or several
    /// for a rule extended with `/=` (a socket).
    types: std::collections::HashMap<RuleKey<'a>, Vec<&'a cddl::ast::Type<'a>>>,
    groups: std::collections::HashMap<RuleKey<'a>, &'a cddl::ast::GroupEntry<'a>>,
    params: std::collections::HashMap<RuleKey<'a>, &'a cddl::ast::GenericParams<'a>>,
    /// The root type rule, and where it is first named.
    root: Option<(RuleKey<'a>, cddl::ast::Span)>,
}

impl<'a> RuleIndex<'a> {
    /// The rules of `ast`, rooted at the type rule written `root` (`$m`
    /// for a socket).
    fn new(ast: &'a cddl::ast::CDDL<'a>, root: &str) -> Self {
        let mut types = std::collections::HashMap::<_, Vec<_>>::new();
        // Where each type rule is first named.
        let mut type_names = std::collections::HashMap::new();
        let mut groups = std::collections::HashMap::new();
        let mut params = std::collections::HashMap::new();
        for rule in &ast.rules {
            match rule {
                // A type rule's bodies are its definition and each `/=`
                // extension, which the validator reads as one choice.
                cddl::ast::Rule::Type { rule, .. } => {
                    let name = RuleKey::of(&rule.name);
                    types.entry(name).or_default().push(&rule.value);
                    type_names.entry(name).or_insert(rule.name.span);
                    if let Some(p) = rule.generic_params.as_ref() {
                        params.entry(name).or_insert(p);
                    }
                }
                cddl::ast::Rule::Group { rule, .. } => {
                    let name = RuleKey::of(&rule.name);
                    groups.entry(name).or_insert(&rule.entry);
                    if let Some(p) = rule.generic_params.as_ref() {
                        params.entry(name).or_insert(p);
                    }
                }
            }
        }
        let root = type_names
            .iter()
            .find(|(name, _)| name.is_written(root))
            .map(|(name, span)| (*name, *span));
        RuleIndex {
            types,
            groups,
            params,
            root,
        }
    }

    /// The alternatives of the type rule `name`, named at `reference`: its
    /// body, or, for a rule extended with `/=`, all its bodies as one
    /// choice written at `reference`.
    fn type_alts(&self, name: RuleKey<'a>, reference: cddl::ast::Span) -> Option<Alts<'a>> {
        let bodies = self.types.get(&name)?;
        Some(match bodies.as_slice() {
            [only] => Alts::One(only),
            _ => Alts::Socket(name, reference),
        })
    }

    /// [`Self::type_alts`] of the root rule, which no reference names: a
    /// socket's choice is written where the rule is first named.
    fn root_alts(&self) -> Option<Alts<'a>> {
        let (name, span) = self.root?;
        self.type_alts(name, span)
    }

    fn type_bodies(&self, name: RuleKey<'a>) -> impl Iterator<Item = &'a cddl::ast::Type<'a>> + '_ {
        self.types.get(&name).into_iter().flatten().copied()
    }

    fn group_rule(&self, name: RuleKey<'a>) -> Option<&'a cddl::ast::GroupEntry<'a>> {
        self.groups.get(&name).copied()
    }

    fn generic_params(&self, name: RuleKey<'a>) -> Option<&'a cddl::ast::GenericParams<'a>> {
        self.params.get(&name).copied()
    }
}

/// AST span for `cbor_location` in original CDDL coordinates (wrapper offset
/// removed). Best-effort: opaque keys / ambiguous array slots return the
/// deepest enclosing span or `None`.
fn cddl_byte_span_for(
    rules: &RuleIndex<'_>,
    ctx: &ValidationCtx<'_>,
    cbor_location: &str,
    end: SpanEnd,
    work: &SpanWalkBudget,
) -> Option<(usize, usize)> {
    let root_type = rules.root_alts()?;
    let trimmed = cbor_location.trim_start_matches('/');
    let segments: Vec<Segment> = if trimmed.is_empty() {
        Vec::new()
    } else {
        split_location_segments(trimmed)
            .into_iter()
            .map(|s| classify_segment(&s))
            .collect()
    };

    let span = walk_span(rules, root_type, &segments, end, work)?;
    let prefix = ctx.cddl_offset_correction;
    if span.0 < prefix {
        return None;
    }
    let start = span.0 - prefix;
    let end = span.1.saturating_sub(prefix).min(ctx.cddl.len());
    // Trim AST spans that swallow trailing whitespace/comments into the next line.
    let end = start + meaningful_span_end(ctx.cddl.get(start..end)?);
    if end <= start {
        return None;
    }
    Some((start, end))
}

/// Offset past trailing whitespace/comments; `text` starts at a token boundary.
fn meaningful_span_end(text: &str) -> usize {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut in_comment = false;
    let mut last = 0usize;
    for (i, c) in text.char_indices() {
        let after = i + c.len_utf8();
        if in_comment {
            if c == '\n' {
                in_comment = false;
            }
            continue;
        }
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            last = after;
            continue;
        }
        match c {
            ';' => in_comment = true,
            '"' | '\'' => {
                quote = Some(c);
                last = after;
            }
            c if c.is_whitespace() => {}
            _ => last = after,
        }
    }
    last
}

/// Generic params in scope for one rule body: each bound to a call-site arg
/// and the scope that arg is read in (RFC 8610 §3.10).
///
/// Args are read where written — not in the callee — so `b<t> = c<t>` does not
/// bind `t` to itself inside `c`.
#[derive(Default)]
struct Scope<'a> {
    bindings: Vec<(&'a str, &'a cddl::ast::Type1<'a>, Rc<Scope<'a>>)>,
}

impl<'a> Scope<'a> {
    /// The argument bound to `name`, with the scope it is read in.
    fn lookup(&self, name: &str) -> Option<(&'a cddl::ast::Type1<'a>, Rc<Scope<'a>>)> {
        self.bindings
            .iter()
            .rev()
            .find_map(|(n, t, scope)| (*n == name).then(|| (*t, Rc::clone(scope))))
    }
}

/// Scope for a rule body entered from `caller` with `args`: params bound to
/// args in the caller scope; empty when the rule has no params.
fn enter_rule_scope<'a>(
    caller: &Rc<Scope<'a>>,
    params: Option<&cddl::ast::GenericParams<'a>>,
    args: Option<&'a cddl::ast::GenericArgs<'a>>,
) -> Rc<Scope<'a>> {
    let (Some(params), Some(args)) = (params, args) else {
        return Rc::new(Scope::default());
    };
    Rc::new(Scope {
        bindings: params
            .params
            .iter()
            .zip(args.args.iter())
            .map(|(p, a)| (p.param.ident, a.arg.as_ref(), Rc::clone(caller)))
            .collect(),
    })
}

/// Max rule refs resolved at one path position (same as validator hop bound).
/// Refs consume no segment, so chains are count-bounded.
const MAX_SPAN_RULE_HOPS: usize = cddl::validator::DEFAULT_MAX_RULE_NESTING;

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

/// Span-walk cursor: type alternatives still to try, or container about to
/// consume the next path segment.
enum SpanCursor<'a> {
    /// A type's alternatives, the scope they are read in, and how many
    /// references were resolved at this position to reach them.
    Type(Alts<'a>, Rc<Scope<'a>>, usize),
    /// A map or array type, and the scope its group is read in.
    Container(&'a cddl::ast::Type2<'a>, Rc<Scope<'a>>),
}

/// The alternatives one position of the schema offers.
#[derive(Clone, Copy)]
enum Alts<'a> {
    /// A type as written.
    One(&'a cddl::ast::Type<'a>),
    /// Every body of the type rule named here, extended with `/=` (a
    /// socket), read as one choice; the span is where the choice is written
    /// (the reference naming the rule).
    Socket(RuleKey<'a>, cddl::ast::Span),
}

impl<'a> Alts<'a> {
    fn span(self) -> cddl::ast::Span {
        match self {
            Alts::One(ty) => ty.span,
            Alts::Socket(_, reference) => reference,
        }
    }

    /// Each alternative, a socket's bodies in document order.
    fn choices<'r>(
        self,
        rules: &'r RuleIndex<'a>,
    ) -> impl Iterator<Item = &'a cddl::ast::TypeChoice<'a>> + 'r {
        let (one, socket) = match self {
            Alts::One(ty) => (Some(ty), None),
            Alts::Socket(name, _) => (None, Some(name)),
        };
        one.into_iter()
            .chain(socket.into_iter().flat_map(move |name| rules.type_bodies(name)))
            .flat_map(|ty| ty.type_choices.iter())
    }
}

/// What resolving one alternative at a position comes to, once the rule
/// references and parameter substitutions that consume no segment are
/// followed.
enum Resolved<'a> {
    /// The alternative descends: the walk continues from here.
    Into(SpanCursor<'a>),
    /// Does not descend (scalar / unresolved / past [`MAX_SPAN_RULE_HOPS`]); try next.
    Dead,
}

/// Cap on span-walk steps across one report (positions × alternatives tried).
///
/// Ambiguous array slots multiply readings; budget bounds the search for an
/// agreed span. Over budget → paths kept, spans omitted for unreached walks.
const MAX_SPAN_WALK_STEPS: usize = 1 << 22;

/// Max concurrent path readings (ambiguous array indices). Past it, report the
/// array's own span.
const MAX_SPAN_READINGS_OPEN: usize = 32;

/// What the span walks of one report have left to spend.
struct SpanWalkBudget {
    steps: std::cell::Cell<usize>,
}

impl SpanWalkBudget {
    fn new() -> Self {
        SpanWalkBudget {
            steps: std::cell::Cell::new(MAX_SPAN_WALK_STEPS),
        }
    }

    /// Take one step; `false` once the budget is spent.
    fn spend(&self) -> bool {
        let left = self.steps.get();
        if left == 0 {
            return false;
        }
        self.steps.set(left - 1);
        true
    }
}

/// Follow the rule references and parameter substitutions `t2` stands
/// for at one position of the path, none of which consumes a segment.
fn resolve_type2<'a>(
    rules: &RuleIndex<'a>,
    mut t2: &'a cddl::ast::Type2<'a>,
    mut scope: Rc<Scope<'a>>,
    mut hops: usize,
) -> Resolved<'a> {
    use cddl::ast::Type2;
    loop {
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
            } => {
                if hops >= MAX_SPAN_RULE_HOPS {
                    return Resolved::Dead;
                }
                // Bound generic param: substitute, read where written, continue.
                if generic_args.is_none() {
                    if let Some((t1, caller)) = scope.lookup(ident.ident) {
                        t2 = &t1.type2;
                        scope = caller;
                        hops += 1;
                        continue;
                    }
                }
                return match rules.type_alts(RuleKey::of(ident), type2_span(t2)) {
                    Some(inner) => {
                        let inner_scope = enter_rule_scope(
                            &scope,
                            rules.generic_params(RuleKey::of(ident)),
                            generic_args.as_ref(),
                        );
                        Resolved::Into(SpanCursor::Type(inner, inner_scope, hops + 1))
                    }
                    // Unresolvable/prelude with path left — cannot hold the failing node.
                    None => Resolved::Dead,
                };
            }
            Type2::ParenthesizedType { pt, .. } => {
                return Resolved::Into(SpanCursor::Type(Alts::One(pt), scope, hops));
            }
            Type2::TaggedData { t, .. } => {
                return Resolved::Into(SpanCursor::Type(Alts::One(t), scope, hops));
            }
            Type2::Map { .. } | Type2::Array { .. } => {
                return Resolved::Into(SpanCursor::Container(t2, scope));
            }
            _ => return Resolved::Dead,
        }
    }
}

/// Schema span for path `segs` under `ty`, or deepest settled node.
///
/// Iterative over path segments; schema recursion bounded, and by
/// [`MAX_SPAN_READINGS_OPEN`] for multi-entry array indices.
fn walk_span<'a>(
    rules: &RuleIndex<'a>,
    ty: Alts<'a>,
    segs: &[Segment],
    end: SpanEnd,
    work: &SpanWalkBudget,
) -> Option<cddl::ast::Span> {
    walk_span_from(
        rules,
        SpanCursor::Type(ty, Rc::new(Scope::default()), 0),
        segs,
        0,
        0,
        end,
        work,
    )
}

/// What the span at the end of a path is of.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SpanEnd {
    /// The type the path's last segment reaches, as written there (a rule
    /// reference stays a reference).
    Item,
    /// The map the path reaches, as written out: an error about one of the
    /// map's entries (an unexpected key) is about the map the entry sits
    /// in, which a rule reference only names. See [`map_holding_span`].
    MapHolding,
}

/// [`walk_span`] from `cursor`, with `segs[..at]` already consumed and
/// `open` readings of the path held open above this one.
fn walk_span_from<'a>(
    rules: &RuleIndex<'a>,
    mut cursor: SpanCursor<'a>,
    segs: &[Segment],
    mut at: usize,
    open: usize,
    end: SpanEnd,
    work: &SpanWalkBudget,
) -> Option<cddl::ast::Span> {
    use cddl::ast::Type2;
    if open > MAX_SPAN_READINGS_OPEN {
        return None;
    }
    loop {
        if !work.spend() {
            return None;
        }
        match cursor {
            SpanCursor::Type(ty, scope, hops) => {
                if at == segs.len() {
                    return Some(match end {
                        SpanEnd::Item => ty.span(),
                        SpanEnd::MapHolding => {
                            map_holding_span(rules, ty, scope, hops, work).unwrap_or(ty.span())
                        }
                    });
                }
                // The path goes on through the alternative whose container
                // holds its next segment: the first that holds it, else the
                // first that may, else the first that descends at all; with
                // none, this type's span.
                let mut descending = Vec::new();
                for choice in ty.choices(rules) {
                    if !work.spend() {
                        return None;
                    }
                    if let Resolved::Into(into) =
                        resolve_type2(rules, &choice.type1.type2, Rc::clone(&scope), hops)
                    {
                        descending.push(into);
                    }
                }
                if descending.is_empty() {
                    return Some(ty.span());
                }
                let mut chosen = 0;
                if descending.len() > 1 {
                    let mut best = Fit::No;
                    for (i, into) in descending.iter().enumerate() {
                        let fit = cursor_fit(rules, into, &segs[at], work, 0)?;
                        if fit > best {
                            best = fit;
                            chosen = i;
                            if fit == Fit::Holds {
                                break;
                            }
                        }
                    }
                }
                cursor = descending.swap_remove(chosen);
            }
            SpanCursor::Container(t2, scope) => {
                let span = type2_span(t2);
                let Some(head) = segs.get(at) else {
                    return Some(span);
                };
                // A name in the last slot settles on its own span, unless
                // the walk goes on to the map it names.
                let tail_empty = at + 1 == segs.len() && end == SpanEnd::Item;
                match t2 {
                    Type2::Map { group, .. } => {
                        match map_entry_target(
                            rules,
                            &group.group_choices,
                            head,
                            &scope,
                            &mut Vec::new(),
                        ) {
                            // Entry consumed a segment — reset hop count for the next position.
                            Some((entry_type, entry_scope)) => {
                                cursor = SpanCursor::Type(Alts::One(entry_type), entry_scope, 0);
                                at += 1;
                            }
                            None => return Some(span),
                        }
                    }
                    Type2::Array { group, .. } => {
                        let Segment::Index(idx) = head else {
                            return Some(span);
                        };
                        let mut readings = None;
                        for choice in &group.group_choices {
                            let mut slots = ArrayCursor::new(rules, *idx, tail_empty);
                            let start = slots.start_positions();
                            slots.walk_entries(&choice.group_entries, &start, &scope);
                            if slots.candidates.is_empty() {
                                continue;
                            }
                            readings = Some((slots.candidates, slots.bail));
                            break;
                        }
                        let Some((mut candidates, bail)) = readings else {
                            return Some(span);
                        };
                        if bail {
                            return Some(span);
                        }
                        if candidates.len() == 1 {
                            // One reading: the walk continues along it.
                            match candidates.pop() {
                                Some(SpanCandidate::Span(s)) => return Some(s),
                                Some(SpanCandidate::Type(entry_type, entry_scope, hops)) => {
                                    cursor = SpanCursor::Type(entry_type, entry_scope, hops);
                                    at += 1;
                                }
                                Some(SpanCandidate::Type2(arg, arg_scope, hops)) => {
                                    match resolve_type2(rules, arg, arg_scope, hops) {
                                        Resolved::Into(into) => {
                                            cursor = into;
                                            at += 1;
                                        }
                                        Resolved::Dead => return Some(span),
                                    }
                                }
                                None => return Some(span),
                            }
                            continue;
                        }
                        // Walk each reading to path end; report only if all agree on a span.
                        let mut agreed = None;
                        for candidate in candidates {
                            let found = match candidate {
                                SpanCandidate::Span(s) => Some(s),
                                SpanCandidate::Type(entry_type, entry_scope, hops) => {
                                    walk_span_from(
                                        rules,
                                        SpanCursor::Type(entry_type, entry_scope, hops),
                                        segs,
                                        at + 1,
                                        open + 1,
                                        end,
                                        work,
                                    )
                                }
                                SpanCandidate::Type2(arg, arg_scope, hops) => {
                                    match resolve_type2(rules, arg, arg_scope, hops) {
                                        Resolved::Into(into) => walk_span_from(
                                            rules,
                                            into,
                                            segs,
                                            at + 1,
                                            open + 1,
                                            end,
                                            work,
                                        ),
                                        Resolved::Dead => None,
                                    }
                                }
                            };
                            match (found, agreed) {
                                (None, _) => return Some(span),
                                (Some(s), None) => agreed = Some(s),
                                (Some(s), Some(a)) if s == a => {}
                                (Some(_), Some(_)) => return Some(span),
                            }
                        }
                        return agreed.or(Some(span));
                    }
                    _ => return Some(span),
                }
            }
        }
    }
}

/// The span of the map `ty` stands for, written out: the rule references,
/// parentheses and tags `ty` reaches through one alternative at a time are
/// followed to the map; where they reach a choice, its one alternative
/// that is a map, or the choice itself when several are (a socket's choice
/// is written at the reference naming it). `None` when `ty` stands for no
/// map (the caller keeps `ty`'s own span).
fn map_holding_span<'a>(
    rules: &RuleIndex<'a>,
    ty: Alts<'a>,
    scope: Rc<Scope<'a>>,
    hops: usize,
    work: &SpanWalkBudget,
) -> Option<cddl::ast::Span> {
    let (choice, scope, hops) = match single_path_to_map(rules, ty, scope, hops, work)? {
        SinglePath::Map(span) => return Some(span),
        SinglePath::Choice(choice, scope, hops) => (choice, scope, hops),
    };
    let mut maps = choice.choices(rules).filter_map(|alternative| {
        match resolve_type2(rules, &alternative.type1.type2, Rc::clone(&scope), hops) {
            Resolved::Into(SpanCursor::Container(t2, _)) => {
                matches!(t2, cddl::ast::Type2::Map { .. }).then(|| type2_span(t2))
            }
            Resolved::Into(SpanCursor::Type(inner, inner_scope, inner_hops)) => {
                match single_path_to_map(rules, inner, inner_scope, inner_hops, work)? {
                    SinglePath::Map(span) => Some(span),
                    SinglePath::Choice(..) => None,
                }
            }
            Resolved::Dead => None,
        }
    });
    match (maps.next(), maps.next()) {
        (Some(only), None) => Some(only),
        _ => Some(choice.span()),
    }
}

/// Where following `ty` one alternative at a time ends.
enum SinglePath<'a> {
    /// At a map, with its span.
    Map(cddl::ast::Span),
    /// At a type with several alternatives, read in this scope.
    Choice(Alts<'a>, Rc<Scope<'a>>, usize),
}

/// Follow `ty` while it has one alternative that is a rule reference, a
/// parenthesised type or a tag. `None` when the path ends anywhere but at
/// a map or a choice (an array, a scalar, an unresolved name), or the
/// walk's budget runs out.
fn single_path_to_map<'a>(
    rules: &RuleIndex<'a>,
    mut ty: Alts<'a>,
    mut scope: Rc<Scope<'a>>,
    mut hops: usize,
    work: &SpanWalkBudget,
) -> Option<SinglePath<'a>> {
    loop {
        if !work.spend() {
            return None;
        }
        let mut choices = ty.choices(rules);
        let (Some(only), None) = (choices.next(), choices.next()) else {
            return Some(SinglePath::Choice(ty, scope, hops));
        };
        match resolve_type2(rules, &only.type1.type2, Rc::clone(&scope), hops) {
            Resolved::Into(SpanCursor::Container(t2, _)) => {
                return matches!(t2, cddl::ast::Type2::Map { .. })
                    .then(|| SinglePath::Map(type2_span(t2)));
            }
            Resolved::Into(SpanCursor::Type(inner, inner_scope, inner_hops)) => {
                ty = inner;
                scope = inner_scope;
                hops = inner_hops;
            }
            Resolved::Dead => return None,
        }
    }
}

/// Type held by the first entry matching `seg`, with its read scope.
///
/// Recurses on schema groups (once per spliced group rule), not data.
fn map_entry_target<'a>(
    rules: &RuleIndex<'a>,
    choices: &'a [cddl::ast::GroupChoice<'a>],
    seg: &Segment,
    scope: &Rc<Scope<'a>>,
    visited: &mut Vec<RuleKey<'a>>,
) -> Option<(&'a cddl::ast::Type<'a>, Rc<Scope<'a>>)> {
    for choice in choices {
        for (entry, _) in &choice.group_entries {
            if let Some(found) = map_one_entry(rules, entry, seg, scope, visited) {
                return Some(found);
            }
        }
    }
    None
}

fn map_one_entry<'a>(
    rules: &RuleIndex<'a>,
    entry: &'a cddl::ast::GroupEntry<'a>,
    seg: &Segment,
    scope: &Rc<Scope<'a>>,
    visited: &mut Vec<RuleKey<'a>>,
) -> Option<(&'a cddl::ast::Type<'a>, Rc<Scope<'a>>)> {
    use cddl::ast::GroupEntry;
    match entry {
        GroupEntry::ValueMemberKey { ge, .. } => {
            let mk = ge.member_key.as_ref()?;
            if member_key_matches(mk, seg) {
                Some((&ge.entry_type, Rc::clone(scope)))
            } else {
                None
            }
        }
        // A group spliced into a map contributes its own entries.
        GroupEntry::InlineGroup { group, .. } => {
            map_entry_target(rules, &group.group_choices, seg, scope, visited)
        }
        GroupEntry::TypeGroupname { ge, .. } => {
            let name = RuleKey::of(&ge.name);
            let spliced = rules.group_rule(name)?;
            // Schema recursion once per spliced group rule; hop-bounded.
            if visited.contains(&name) || visited.len() >= MAX_SPAN_RULE_HOPS {
                return None;
            }
            let inner_scope =
                enter_rule_scope(scope, rules.generic_params(name), ge.generic_args.as_ref());
            visited.push(name);
            let found = map_one_entry(rules, spliced, seg, &inner_scope, visited);
            visited.pop();
            found
        }
    }
}

/// How far an alternative of a choice can hold the next segment of a path.
/// Ordered: a walk through a choice takes the first alternative of the
/// greatest fit.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Fit {
    /// No container, or one that cannot hold the segment: a map whose
    /// members all have other keys, an array too short for the index.
    No,
    /// A container that may hold it, which is not settled here: a map
    /// whose keys are types or literals of another kind, an array whose
    /// slots repeat a group.
    Maybe,
    /// A map with a member of that key, an array with a slot at that index.
    Holds,
}

/// Deepest chain of choices [`cursor_fit`] follows to a container; past
/// it an alternative may hold the segment.
const MAX_FIT_DEPTH: usize = MAX_SPAN_RULE_HOPS;

/// How far the type `cursor` resolved to can hold the path segment `seg`:
/// a container by its members or slots, a type by its best alternative.
/// `None` once the walk's budget is spent.
fn cursor_fit<'a>(
    rules: &RuleIndex<'a>,
    cursor: &SpanCursor<'a>,
    seg: &Segment,
    work: &SpanWalkBudget,
    depth: usize,
) -> Option<Fit> {
    use cddl::ast::Type2;
    if !work.spend() {
        return None;
    }
    match cursor {
        SpanCursor::Container(Type2::Map { group, .. }, _) => Some(map_group_fit(
            rules,
            &group.group_choices,
            seg,
            &mut Vec::new(),
        )),
        SpanCursor::Container(Type2::Array { group, .. }, scope) => {
            let Segment::Index(idx) = seg else {
                return Some(Fit::No);
            };
            let mut fit = Fit::No;
            for choice in &group.group_choices {
                let mut slots = ArrayCursor::new(rules, *idx, false);
                let start = slots.start_positions();
                slots.walk_entries(&choice.group_entries, &start, scope);
                if slots.bail {
                    fit = fit.max(Fit::Maybe);
                } else if !slots.candidates.is_empty() {
                    return Some(Fit::Holds);
                }
            }
            Some(fit)
        }
        SpanCursor::Container(..) => Some(Fit::No),
        SpanCursor::Type(alts, scope, hops) => {
            if depth >= MAX_FIT_DEPTH {
                return Some(Fit::Maybe);
            }
            let mut fit = Fit::No;
            for choice in alts.choices(rules) {
                if let Resolved::Into(into) =
                    resolve_type2(rules, &choice.type1.type2, Rc::clone(scope), *hops)
                {
                    fit = fit.max(cursor_fit(rules, &into, seg, work, depth + 1)?);
                    if fit == Fit::Holds {
                        break;
                    }
                }
            }
            Some(fit)
        }
    }
}

/// How far a map group (its choices, spliced groups included) can hold the
/// entry the path segment `seg` names.
fn map_group_fit<'a>(
    rules: &RuleIndex<'a>,
    choices: &'a [cddl::ast::GroupChoice<'a>],
    seg: &Segment,
    visited: &mut Vec<RuleKey<'a>>,
) -> Fit {
    let mut fit = Fit::No;
    for choice in choices {
        for (entry, _) in &choice.group_entries {
            fit = fit.max(map_entry_fit(rules, entry, seg, visited));
            if fit == Fit::Holds {
                return fit;
            }
        }
    }
    fit
}

/// [`map_group_fit`] for one entry of a map group.
fn map_entry_fit<'a>(
    rules: &RuleIndex<'a>,
    entry: &'a cddl::ast::GroupEntry<'a>,
    seg: &Segment,
    visited: &mut Vec<RuleKey<'a>>,
) -> Fit {
    use cddl::ast::GroupEntry;
    match entry {
        GroupEntry::ValueMemberKey { ge, .. } => match ge.member_key.as_ref() {
            Some(mk) => member_key_fit(mk, seg),
            None => Fit::Maybe,
        },
        GroupEntry::InlineGroup { group, .. } => {
            map_group_fit(rules, &group.group_choices, seg, visited)
        }
        GroupEntry::TypeGroupname { ge, .. } => {
            let name = RuleKey::of(&ge.name);
            let Some(spliced) = rules.group_rule(name) else {
                return Fit::Maybe;
            };
            if visited.contains(&name) || visited.len() >= MAX_SPAN_RULE_HOPS {
                return Fit::Maybe;
            }
            visited.push(name);
            let fit = map_entry_fit(rules, spliced, seg, visited);
            visited.pop();
            fit
        }
    }
}

/// How far a map member written with the key `mk` can be the entry `seg`
/// names: a text or integer key value holds a segment naming that key or
/// not; a key type, or a key value of another kind, may. An entry the
/// validator names by its position or by nothing has a key rendering past
/// its bound, which only a text key that long can be.
fn member_key_fit(mk: &cddl::ast::MemberKey<'_>, seg: &Segment) -> Fit {
    use cddl::ast::MemberKey;
    use cddl::token::Value as V;
    if member_key_matches(mk, seg) {
        return Fit::Holds;
    }
    let text_key = match mk {
        MemberKey::Bareword { ident, .. } => Some(ident.ident),
        MemberKey::Value {
            value: V::TEXT(t), ..
        } => Some(t.as_ref()),
        _ => None,
    };
    let int_key = matches!(
        mk,
        MemberKey::Value {
            value: V::UINT(_) | V::INT(_),
            ..
        }
    );
    match (text_key, seg) {
        (Some(text), Segment::Index(_) | Segment::Unnamed) => {
            if format!("{:?}", text).len() > cddl::validator::MAX_RENDERED_DATA_LENGTH {
                Fit::Maybe
            } else {
                Fit::No
            }
        }
        (Some(_), Segment::Opaque) => Fit::Maybe,
        (Some(_), _) => Fit::No,
        (None, Segment::Opaque) if int_key => Fit::Maybe,
        (None, _) if int_key => Fit::No,
        _ => Fit::Maybe,
    }
}

fn member_key_matches(mk: &cddl::ast::MemberKey<'_>, seg: &Segment) -> bool {
    use cddl::ast::MemberKey;
    match (mk, seg) {
        (MemberKey::Bareword { ident, .. }, Segment::TextKey(s)) => ident.ident == s.as_str(),
        (
            MemberKey::Value {
                value: cddl::token::Value::TEXT(t),
                ..
            },
            Segment::TextKey(s),
        ) => t.as_ref() == s,
        (
            MemberKey::Value {
                value: cddl::token::Value::UINT(u),
                ..
            },
            Segment::Index(i),
        ) => *u as i128 == *i as i128,
        (
            MemberKey::Value {
                value: cddl::token::Value::UINT(u),
                ..
            },
            Segment::IntKey(n),
        ) => *u as i128 == *n,
        (
            MemberKey::Value {
                value: cddl::token::Value::INT(i),
                ..
            },
            Segment::IntKey(n),
        ) => *i == *n,
        _ => false,
    }
}

/// Occurrence bounds of a group entry, as `(min, max)` where `None` max
/// means unbounded.
fn occurrence_bounds(occur: Option<&cddl::ast::Occurrence<'_>>) -> (usize, Option<usize>) {
    use cddl::ast::Occur;
    match occur.map(|o| &o.occur) {
        None => (1, Some(1)),
        Some(Occur::Optional { .. }) => (0, Some(1)),
        Some(Occur::ZeroOrMore { .. }) => (0, None),
        Some(Occur::OneOrMore { .. }) => (1, None),
        Some(Occur::Exact { lower, upper, .. }) => (lower.unwrap_or(0), *upper),
    }
}

/// Array-group entry that could hold the path index; continuation from the next segment.
enum SpanCandidate<'a> {
    /// The entry's type, the scope it is read in, and the references
    /// resolved at the next position to reach it.
    Type(Alts<'a>, Rc<Scope<'a>>, usize),
    /// A name bound to a generic argument: the argument, read in the
    /// scope it was written in.
    Type2(&'a cddl::ast::Type2<'a>, Rc<Scope<'a>>, usize),
    /// A span the entry settles on itself, the path ending at it.
    Span(cddl::ast::Span),
}

/// Possible array cursor positions: `positions[p]` means some reading puts
/// this entry at data index `p`. Positions after the target index are dropped.
struct ArrayCursor<'a, 'b> {
    rules: &'b RuleIndex<'a>,
    idx: usize,
    /// Whether the path ends at `idx`.
    tail_empty: bool,
    /// Every entry that could hold `idx`.
    candidates: Vec<SpanCandidate<'a>>,
    /// Unsettable shape (repeated group / refused recursion) → discard for the
    /// enclosing container span.
    bail: bool,
    visited: Vec<RuleKey<'a>>,
}

impl<'a, 'b> ArrayCursor<'a, 'b> {
    fn new(rules: &'b RuleIndex<'a>, idx: usize, tail_empty: bool) -> Self {
        ArrayCursor {
            rules,
            idx,
            tail_empty,
            candidates: Vec::new(),
            bail: false,
            visited: Vec::new(),
        }
    }

    fn start_positions(&self) -> Vec<bool> {
        let mut p = vec![false; self.idx + 1];
        p[0] = true;
        p
    }

    /// Whether an entry with this upper bound covering any live start reaches `idx`.
    fn covers(&self, positions: &[bool], max: Option<usize>) -> bool {
        match max {
            None => positions.iter().any(|live| *live),
            Some(0) => false,
            Some(m) => {
                let lo = (self.idx + 1).saturating_sub(m);
                (lo..=self.idx).any(|p| positions[p])
            }
        }
    }

    /// Positions after consuming an entry with these bounds.
    fn advance(&self, positions: &[bool], min: usize, max: Option<usize>) -> Vec<bool> {
        // Difference array so a wide or unbounded occurrence stays linear.
        let mut diff = vec![0i32; self.idx + 2];
        for (p, live) in positions.iter().enumerate() {
            if !*live {
                continue;
            }
            let lo = p + min;
            if lo > self.idx {
                continue;
            }
            let hi = match max {
                None => self.idx,
                Some(m) => (p + m).min(self.idx),
            };
            if hi < lo {
                continue;
            }
            diff[lo] += 1;
            diff[hi + 1] -= 1;
        }
        let mut out = vec![false; self.idx + 1];
        let mut running = 0i32;
        for (p, slot) in out.iter_mut().enumerate() {
            running += diff[p];
            *slot = running > 0;
        }
        out
    }

    fn any(positions: &[bool]) -> bool {
        positions.iter().any(|p| *p)
    }

    fn union(a: &[bool], b: &[bool]) -> Vec<bool> {
        a.iter().zip(b.iter()).map(|(x, y)| *x || *y).collect()
    }

    fn walk_entries(
        &mut self,
        entries: &'a [(cddl::ast::GroupEntry<'a>, cddl::ast::OptionalComma<'a>)],
        positions: &[bool],
        scope: &Rc<Scope<'a>>,
    ) -> Vec<bool> {
        let mut positions = positions.to_vec();
        for (entry, _) in entries {
            if !Self::any(&positions) || self.bail {
                return positions;
            }
            positions = self.walk_entry(entry, &positions, scope);
        }
        positions
    }

    fn walk_entry(
        &mut self,
        entry: &'a cddl::ast::GroupEntry<'a>,
        positions: &[bool],
        scope: &Rc<Scope<'a>>,
    ) -> Vec<bool> {
        use cddl::ast::GroupEntry;
        match entry {
            GroupEntry::ValueMemberKey { ge, .. } => {
                let (min, max) = occurrence_bounds(ge.occur.as_ref());
                if self.covers(positions, max) {
                    // Entry consumed a segment — reset hop count.
                    self.candidates
                        .push(SpanCandidate::Type(Alts::One(&ge.entry_type), Rc::clone(scope), 0));
                }
                self.advance(positions, min, max)
            }
            GroupEntry::InlineGroup { occur, group, .. } => {
                if occur.is_some() {
                    // Repeated group: no fixed arity for the cursor.
                    self.bail = true;
                    return positions.to_vec();
                }
                self.walk_choices(&group.group_choices, positions, scope)
            }
            // Array name splices if it is a group rule; else one slot.
            GroupEntry::TypeGroupname { ge, .. } => {
                let name = RuleKey::of(&ge.name);
                match self.rules.group_rule(name) {
                    Some(spliced) => {
                        if ge.occur.is_some()
                            || self.visited.contains(&name)
                            || self.visited.len() >= MAX_SPAN_RULE_HOPS
                        {
                            self.bail = true;
                            return positions.to_vec();
                        }
                        let inner_scope = enter_rule_scope(
                            scope,
                            self.rules.generic_params(name),
                            ge.generic_args.as_ref(),
                        );
                        self.visited.push(name);
                        let after = self.walk_entry(spliced, positions, &inner_scope);
                        self.visited.pop();
                        after
                    }
                    None => {
                        let (min, max) = occurrence_bounds(ge.occur.as_ref());
                        if self.covers(positions, max) {
                            let candidate = self.groupname_candidate(ge, scope);
                            self.candidates.push(candidate);
                        }
                        self.advance(positions, min, max)
                    }
                }
            }
        }
    }

    fn walk_choices(
        &mut self,
        choices: &'a [cddl::ast::GroupChoice<'a>],
        positions: &[bool],
        scope: &Rc<Scope<'a>>,
    ) -> Vec<bool> {
        let mut out = vec![false; self.idx + 1];
        for choice in choices {
            let after = self.walk_entries(&choice.group_entries, positions, scope);
            out = Self::union(&out, &after);
        }
        out
    }

    /// Continuation from a name occupying one array slot.
    fn groupname_candidate(
        &self,
        ge: &'a cddl::ast::TypeGroupnameEntry<'a>,
        scope: &Rc<Scope<'a>>,
    ) -> SpanCandidate<'a> {
        if ge.generic_args.is_none() {
            if let Some((t1, caller)) = scope.lookup(ge.name.ident) {
                if self.tail_empty {
                    return SpanCandidate::Span(t1.span);
                }
                return SpanCandidate::Type2(&t1.type2, caller, 1);
            }
        }
        if self.tail_empty {
            return SpanCandidate::Span(ge.name.span);
        }
        if let Some(inner) = self.rules.type_alts(RuleKey::of(&ge.name), ge.name.span) {
            let inner_scope = enter_rule_scope(
                scope,
                self.rules.generic_params(RuleKey::of(&ge.name)),
                ge.generic_args.as_ref(),
            );
            return SpanCandidate::Type(inner, inner_scope, 1);
        }
        SpanCandidate::Span(ge.name.span)
    }
}

/// Pull `expected X` from a free-form reason; strip leading `type `.
fn extract_expected(reason: &str) -> Option<String> {
    // A map that lacks an entry the group names: the key is what was
    // expected. `map missing key: <key>`, `map requires entry key of type
    // <T>`, `map requires entry with key of type <T>` / `in range <R>`, and
    // the occurrence forms (`map requires at least one entry with key …`,
    // `map must contain no more than N entries with key …`). Only the
    // validator's own map reasons are read this way: another reason may
    // quote data holding the same words.
    if let Some(rest) = reason
        .strip_prefix("map ")
        .or_else(|| reason.strip_prefix("object "))
    {
        for marker in [
            "missing key: ",
            "requires entry key of type ",
            " with key of type ",
            " with key in range ",
            " with key ",
        ] {
            let at = if marker.starts_with(' ') {
                rest.find(marker)
            } else {
                rest.starts_with(marker).then_some(0)
            };
            if let Some(idx) = at {
                let key = rest[idx + marker.len()..].trim();
                return (!key.is_empty()).then(|| key.to_string());
            }
        }
    }
    let lower = reason.to_ascii_lowercase();
    // `unexpected key` names the data item, not an expected type.
    let idx = lower
        .match_indices("expected ")
        .map(|(i, _)| i)
        .find(|i| *i == 0 || !is_ident_byte(lower.as_bytes()[i - 1]))?;
    let tail = &reason[idx + "expected ".len()..];
    let end = expected_end(tail);
    let candidate = tail[..end].trim();
    // Trim trailing sentence punctuation; keep validator elision markers.
    let candidate = if candidate.ends_with("...") {
        candidate
    } else {
        candidate.trim_end_matches(|c: char| c == ',' || c == '.')
    };
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

/// End of the expected type in text after `expected `: first ` but `, `, got`,
/// ` got ` (a text literal mismatch reads `expected value "foo" got "…"`),
/// or newline outside brackets/quotes. Unclosed brackets read as plain text.
fn expected_end(tail: &str) -> usize {
    let mut i = 0;
    while i < tail.len() {
        let rest = &tail[i..];
        if rest.starts_with('\n')
            || rest.starts_with(" but ")
            || rest.starts_with(", got")
            || rest.starts_with(" got ")
        {
            return i;
        }
        let c = rest.chars().next().expect("a char boundary");
        let skipped = match c {
            '{' => balanced_delim_end(&rest[1..], '{', '}'),
            '[' => balanced_delim_end(&rest[1..], '[', ']'),
            '(' => balanced_delim_end(&rest[1..], '(', ')'),
            '"' => quoted_end(&rest[1..]),
            _ => None,
        };
        i += c.len_utf8() + skipped.unwrap_or(0);
    }
    tail.len()
}

/// Byte index just past the `"` closing an already-opened text literal,
/// escapes honoured.
fn quoted_end(s: &str) -> Option<usize> {
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '"' => return Some(i + 1),
            _ => {}
        }
    }
    None
}

/// anweiss `cbor_location` → decoder path (`$`, `$.key`, `$[n]`), in the
/// grammar of `ts/cddl/cborPath.ts`.
///
/// A text key is `.key` when it is an identifier (ASCII
/// `[A-Za-z_][A-Za-z0-9_-]*`) and `["key"]` otherwise, with `\` written
/// `\\` and `"` written `\"` and nothing else escaped. Integer keys and
/// indices are `[n]`, composite keys `[<diagnostic notation>]`, float keys
/// `[1.5]` and a component naming no entry (`...`) `[...]`; byte string,
/// boolean and null keys keep their CDDL literal form (`.h'…'`, `.true`,
/// `.null`).
fn cbor_location_to_json_path(loc: &str) -> String {
    let trimmed = loc.trim_start_matches('/');
    if trimmed.is_empty() {
        return "$".to_string();
    }
    let mut out = String::from("$");
    for seg in split_location_segments(trimmed) {
        push_path_segment(&mut out, &seg, &classify_segment(&seg));
    }
    out
}

/// Longest key rendering [`json_path_in_tree`] writes out for an entry the
/// validator named by its position or by nothing (a key past the
/// validator's own rendering bound); past it the validator's component is
/// kept.
const MAX_PATH_KEY_LEN: usize = 1024;

/// How the validator names an entry whose key renders past its bound when
/// the entry's position would read as an integer key of the same map.
const UNNAMED_ENTRY: &str = "...";

/// [`cbor_location_to_json_path`], with the components that name a map
/// entry by its position or by nothing resolved against the decoded `tree`.
///
/// The validator names an entry whose key renders past its bound by the
/// entry's position (a bare index, when the map holds no integer key of
/// that value) or by nothing (`...`, when it does). A path reader takes a
/// bare index for an integer key, or for the text key of the same digits,
/// and `[...]` for the text key `...`; so where the entry is known (its
/// position; for `...`, the one entry of the map whose key can be the
/// unnamed one) and its key is a text or byte string, the path writes that
/// key out (up to [`MAX_PATH_KEY_LEN`]). Any other such entry keeps the
/// validator's component, which its byte spans tell apart.
///
/// Only those components are looked up: the tree is walked no further than
/// the last of them, and not at all when the location has none, so a report
/// on many entries of one large map costs no second walk per error.
fn json_path_in_tree<'t>(tree: &'t Value, loc: &str, keys: &mut MapKeyIndex<'t>) -> String {
    let trimmed = loc.trim_start_matches('/');
    let mut out = String::from("$");
    if trimmed.is_empty() {
        return out;
    }
    let segments: Vec<(String, Segment)> = split_location_segments(trimmed)
        .into_iter()
        .map(|seg| {
            let classified = classify_segment(&seg);
            (seg, classified)
        })
        .collect();
    let last_resolved = segments
        .iter()
        .rposition(|(_, classified)| matches!(classified, Segment::Unnamed | Segment::Index(_)));
    let mut node: Option<&Value> = last_resolved.map(|_| tree);
    for (at, (seg, classified)) in segments.iter().enumerate() {
        let item = node.map(unwrap_tags);
        let step = item.and_then(|item| keys.step_into(item, classified));
        let unnamed_or_positional = match (classified, item) {
            (Segment::Unnamed | Segment::Index(_), Some(item)) => node_type(item) == "Map",
            _ => false,
        };
        let written = step
            .as_ref()
            .and_then(|step| step.key)
            .filter(|key| unnamed_or_positional && !is_integer_node(key))
            .and_then(written_key_segment);
        match written {
            Some(written) => out.push_str(&written),
            None => push_path_segment(&mut out, seg, classified),
        }
        node = match last_resolved {
            Some(last) if at < last => step.map(|step| step.value),
            _ => None,
        };
    }
    out
}

/// Whether a decoded node is an integer.
fn is_integer_node(node: &Value) -> bool {
    matches!(
        node_type(node),
        "U8" | "U16" | "U32" | "U64" | "I8" | "I16" | "I32" | "I64" | "Int"
    )
}

/// The path component naming the entry under the decoded map key `key`,
/// when it is a text or byte string whose rendering fits
/// [`MAX_PATH_KEY_LEN`].
fn written_key_segment(key: &Value) -> Option<String> {
    if let Some(text) = diagnostic::string_payload(key, "String", "IndefiniteLengthString") {
        let mut out = String::new();
        push_text_key(&mut out, &text);
        return (out.len() <= MAX_PATH_KEY_LEN).then_some(out);
    }
    let hex = diagnostic::string_payload(key, "Bytes", "IndefiniteLengthBytes")?;
    let out = format!(".h'{}'", hex);
    (out.len() <= MAX_PATH_KEY_LEN).then_some(out)
}

/// The entry of a decoded map the validator names by nothing
/// ([`UNNAMED_ENTRY`]): the one entry whose key renders past the
/// validator's bound. `None` when that is not one entry for certain: no
/// text or byte string key renders past it, several do, or a composite key
/// (whose rendering is not measured here) may.
fn unnamed_entry(map: &Value) -> Option<&Value> {
    let bound = cddl::validator::MAX_RENDERED_DATA_LENGTH;
    let mut found = None;
    for entry in map.get("values")?.as_array()? {
        let Some(key) = entry.get("key") else {
            continue;
        };
        let rendered_past_bound =
            if let Some(text) = diagnostic::string_payload(key, "String", "IndefiniteLengthString") {
                format!("{:?}", text).len() > bound
            } else if let Some(hex) =
                diagnostic::string_payload(key, "Bytes", "IndefiniteLengthBytes")
            {
                hex.len() + 3 > bound
            } else if is_integer_node(key)
                || matches!(
                    node_type(key),
                    "F16" | "F32" | "F64" | "Bool" | "Null" | "Undefined"
                )
            {
                false
            } else {
                return None;
            };
        if rendered_past_bound {
            if found.is_some() {
                return None;
            }
            found = Some(entry);
        }
    }
    found
}

/// Append the path component for the location component `seg`.
fn push_path_segment(out: &mut String, seg: &str, classified: &Segment) {
    match classified {
        Segment::Index(i) => {
            out.push('[');
            out.push_str(&i.to_string());
            out.push(']');
        }
        Segment::TextKey(s) => push_text_key(out, s),
        Segment::IntKey(n) => {
            out.push('[');
            out.push_str(&n.to_string());
            out.push(']');
        }
        // A composite key is written in the bracket form, as its
        // diagnostic notation reads: `$[[2, h'0102']]`, `$[{1: 2}]`.
        Segment::CompositeKey(_) => {
            out.push('[');
            out.push_str(seg);
            out.push(']');
        }
        // A float literal holds a `.`, and a component naming no entry
        // may hold anything: both in the bracket form.
        Segment::FloatKey(_) | Segment::Unnamed | Segment::Opaque => {
            out.push('[');
            out.push_str(seg);
            out.push(']');
        }
        Segment::BytesKey(_) | Segment::BoolKey(_) | Segment::NullKey => {
            out.push('.');
            out.push_str(seg);
        }
    }
}

/// Append the path segment of the text key `key`: `.key` for an identifier,
/// `["key"]` (`\` and `"` escaped) for any other text.
fn push_text_key(out: &mut String, key: &str) {
    let mut chars = key.chars();
    let identifier = matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if identifier {
        out.push('.');
        out.push_str(key);
        return;
    }
    out.push_str("[\"");
    for c in key.chars() {
        if c == '\\' || c == '"' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push_str("\"]");
}

enum Segment {
    Index(usize),
    TextKey(String),
    IntKey(i128),
    /// A key written as a CDDL float literal, e.g. `1.5`.
    FloatKey(f64),
    /// A key written as a CDDL byte string literal, e.g. `h'0102'`.
    BytesKey(Vec<u8>),
    /// A key written as `true` or `false`.
    BoolKey(bool),
    /// A key written as `null`.
    NullKey,
    /// An array, map, tagged or simple-value key, written in CBOR
    /// diagnostic notation (`[2, h'0102']`, `{1: 2}`, `24(0)`, `simple(32)`).
    CompositeKey(diagnostic::Item),
    /// The validator's name for an entry whose key renders past its bound
    /// when the entry's position would read as an integer key
    /// ([`UNNAMED_ENTRY`]).
    Unnamed,
    /// A component in no form this recognises. Its text still names the
    /// item in the path, but nothing can be looked up by it.
    Opaque,
}

/// Segment count of a location without allocating (for ranking deep reports).
fn location_depth(loc: &str) -> usize {
    let s = loc.trim_start_matches('/');
    if s.is_empty() {
        return 0;
    }
    let mut segments = 1;
    location_separators(s, |_| segments += 1);
    segments
}

/// Split on the `/` between components (see [`location_separators`]), so
/// segments like `"a/b"`, `Integer(-1)` or a composite key `[2, h'0102']`
/// aren't torn apart.
fn split_location_segments(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut from = 0;
    location_separators(s, |at| {
        out.push(s[from..at].to_string());
        from = at + 1;
    });
    if from < s.len() {
        out.push(s[from..].to_string());
    }
    out
}

/// Calls `at` with the byte index of every `/` that separates two
/// components of the location `s` (leading `/` removed).
///
/// A text is quoted with its `"` and `\` escaped, both a text key
/// component (`"a\"/b"`) and a text inside a composite key, so no `/`
/// between its quotes separates anything. A composite key keeps its
/// brackets (`(…)`, `[…]`, `{…}`) balanced. Any other component runs to the
/// next `/`.
fn location_separators(s: &str, mut at: impl FnMut(usize)) {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut depth = 0usize;
    let mut in_text = false;
    let mut escaped = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_text {
            match b {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => in_text = false,
                _ => {}
            }
        } else {
            match b {
                b'"' => in_text = true,
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' if depth > 0 => depth -= 1,
                b'/' if depth == 0 => at(i),
                _ => {}
            }
        }
        i += 1;
    }
}

fn classify_segment(seg: &str) -> Segment {
    if seg == UNNAMED_ENTRY {
        return Segment::Unnamed;
    }
    if let Ok(i) = seg.parse::<usize>() {
        return Segment::Index(i);
    }
    if let Some(unquoted) = strip_debug_quotes(seg) {
        return Segment::TextKey(unquoted);
    }
    if let Some(n) = parse_integer_segment(seg) {
        return Segment::IntKey(n);
    }
    // Non-text/int keys keep CDDL literal notation in the path.
    if let Some(b) = parse_base16_segment(seg) {
        return Segment::BytesKey(b);
    }
    match seg {
        "true" => return Segment::BoolKey(true),
        "false" => return Segment::BoolKey(false),
        "null" => return Segment::NullKey,
        _ => {}
    }
    if let Some(f) = parse_float_segment(seg) {
        return Segment::FloatKey(f);
    }
    if let Some(item) = diagnostic::parse_composite(seg) {
        return Segment::CompositeKey(item);
    }
    Segment::Opaque
}

/// The bytes a base16 byte string literal `h'…'` denotes.
fn parse_base16_segment(seg: &str) -> Option<Vec<u8>> {
    let inner = seg.strip_prefix("h'")?.strip_suffix('\'')?;
    hex::decode(inner).ok()
}

/// Float literal value. Bare digits are never floats (those are int keys/indices).
/// Unrepresentable values are spelled out, not approximated.
fn parse_float_segment(seg: &str) -> Option<f64> {
    let is_literal = seg.contains(['.', 'e', 'E']);
    if !is_literal && !matches!(seg, "NaN" | "Infinity" | "-Infinity") {
        return None;
    }
    seg.parse::<f64>().ok()
}

/// The text of a text-key component: the validator quotes the key with its
/// quotes, backslashes and control characters escaped, as text inside a
/// composite key. `None` if the segment isn't in that form.
fn strip_debug_quotes(seg: &str) -> Option<String> {
    diagnostic::parse_text(seg)
}

/// Innermost signed int from `Integer(Integer(…))` key segments.
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

/// Decoded node for an error: outer-input spans plus a short rendering.
struct NodeView {
    /// `position_info` — the node's own header (and, for scalars, body).
    span: Option<Value>,
    /// `struct_position_info` where the node has one, else `position_info`
    /// — the whole structure, for a halo highlight.
    anchor: Option<Value>,
    /// Short rendering of the node, e.g. `array(3 items)`.
    preview: String,
}

/// Per-report location → node cache (resolve each location once), with
/// the text keys of the large maps the locations go through.
struct LocatedNodes<'t> {
    by_location: std::collections::HashMap<String, Option<LocatedNode>>,
    keys: MapKeyIndex<'t>,
}

impl<'t> LocatedNodes<'t> {
    fn new() -> Self {
        LocatedNodes {
            by_location: std::collections::HashMap::new(),
            keys: MapKeyIndex::default(),
        }
    }

    /// Node for `loc` in `tree`, memoised including failed lookups.
    fn resolve(&mut self, tree: &'t Value, loc: &str, cbor_len: usize) -> Option<&LocatedNode> {
        if !self.by_location.contains_key(loc) {
            let node = locate_cbor_node(tree, loc, cbor_len, Some(&mut self.keys));
            self.by_location.insert(loc.to_string(), node);
        }
        self.by_location.get(loc).and_then(Option::as_ref)
    }
}

/// Fewest entries a decoded map has for [`MapKeyIndex`] to index its keys;
/// a smaller map is searched entry by entry.
const INDEXED_MAP_ENTRIES: usize = 16;

/// The keys of the large decoded maps one report looks entries up in, each
/// map indexed on its first lookup. A report on many entries of one map
/// (every value of a large map of the wrong type) then costs one pass over
/// the map, not one per entry.
#[derive(Default)]
struct MapKeyIndex<'t> {
    maps: std::collections::HashMap<*const Value, MapKeys<'t>>,
}

/// The first entry of each key of one decoded map, by kind of key.
struct MapKeys<'t> {
    /// Definite text keys; `None` when a key is a text of indefinite length
    /// (the map's text keys are then searched entry by entry, as such a key
    /// is not held as one text).
    text: Option<std::collections::HashMap<&'t str, usize>>,
    /// Integer keys, by value.
    ints: std::collections::HashMap<i64, usize>,
}

impl<'t> MapKeys<'t> {
    fn of(entries: &'t [Value]) -> Self {
        let mut text = Some(std::collections::HashMap::with_capacity(entries.len()));
        let mut ints = std::collections::HashMap::new();
        for (at, entry) in entries.iter().enumerate() {
            let Some(key) = entry.get("key") else {
                continue;
            };
            match node_type(key) {
                "String" => {
                    if let (Some(index), Some(t)) =
                        (text.as_mut(), key.get("value").and_then(Value::as_str))
                    {
                        index.entry(t).or_insert(at);
                    }
                }
                "IndefiniteLengthString" => text = None,
                _ if is_integer_node(key) => {
                    if let Some(n) = key.get("value").and_then(Value::as_i64) {
                        ints.entry(n).or_insert(at);
                    }
                }
                _ => {}
            }
        }
        MapKeys { text, ints }
    }
}

impl<'t> MapKeyIndex<'t> {
    /// [`step_into`], through the index for a text key or a bare integer
    /// of a large map.
    fn step_into(&mut self, node: &'t Value, seg: &Segment) -> Option<Step<'t>> {
        if matches!(seg, Segment::TextKey(_) | Segment::Index(_)) && node_type(node) == "Map" {
            if let Some(entries) = node.get("values").and_then(Value::as_array) {
                if entries.len() >= INDEXED_MAP_ENTRIES {
                    let keys = self
                        .maps
                        .entry(node as *const Value)
                        .or_insert_with(|| MapKeys::of(entries));
                    match (seg, &keys.text) {
                        (Segment::TextKey(key), Some(text)) => {
                            return text
                                .get(key.as_str())
                                .and_then(|&at| Step::entry(&entries[at]));
                        }
                        // A bare integer is an integer key when the map has
                        // one of that value, else the entry at that position.
                        (Segment::Index(i), _) => {
                            let at = std::convert::TryFrom::try_from(*i)
                                .ok()
                                .and_then(|n: i64| keys.ints.get(&n).copied())
                                .unwrap_or(*i);
                            return entries.get(at).and_then(Step::entry);
                        }
                        _ => {}
                    }
                }
            }
        }
        step_into(node, seg)
    }
}

/// What the CBOR-side lookup produced for one error.
struct LocatedNode {
    /// The data item the path names, tag wrappers included.
    tagged: NodeView,
    /// Item with tag wrappers removed, if any.
    ///
    /// Paths are tag-transparent; [`reason_names_tagged_item`] picks wrapper vs content.
    untagged: Option<NodeView>,
    /// The key of the map entry the path's last segment selected, when the
    /// item is a map entry's value: an error about the entry itself (an
    /// unexpected key) is anchored on it.
    key: Option<NodeView>,
    /// True when the node lives inside an embedded CBOR payload, so the
    /// spans address bytes the outer schema describes only as a byte
    /// string.
    embedded: bool,
}

impl LocatedNode {
    /// The view to report: the wrapper when the reason renders a tag, the
    /// content otherwise.
    fn view(&self, names_tag: bool) -> &NodeView {
        match &self.untagged {
            Some(untagged) if !names_tag => untagged,
            _ => &self.tagged,
        }
    }
}

/// Max `.cbor` / `.cborseq` re-entries (matches validator open-payload bound).
const MAX_EMBEDDED_DEPTH: usize = limits::MAX_EMBEDDED_DEPTH;

/// Upper bound on the number of items read out of a `.cborseq` payload.
const MAX_SEQUENCE_ITEMS: usize = 4096;

/// Walk decoded tree by slash `cbor_location`. `None` for indefinite/opaque paths.
///
/// Unwrap `Tag` chains before each segment (anweiss omits tag segments); return
/// wrapped and unwrapped forms. Leftover segments into a bstr → decode `.cbor` /
/// `.cborseq` and continue (offsets rebased to the outer document).
fn locate_cbor_node<'t>(
    tree: &'t Value,
    loc: &str,
    cbor_len: usize,
    keys: Option<&mut MapKeyIndex<'t>>,
) -> Option<LocatedNode> {
    let trimmed = loc.trim_start_matches('/');
    let segments: Vec<Segment> = if trimmed.is_empty() {
        Vec::new()
    } else {
        split_location_segments(trimmed)
            .into_iter()
            .map(|s| classify_segment(&s))
            .collect()
    };
    locate_in(tree, &segments, 0, 0, cbor_len, keys)
}

/// [`locate_cbor_node`] from `tree`, with `keys` indexing its large maps
/// (none inside an embedded payload, which is decoded per lookup).
fn locate_in<'t>(
    tree: &'t Value,
    segs: &[Segment],
    rebase: usize,
    depth: usize,
    cbor_len: usize,
    mut keys: Option<&mut MapKeyIndex<'t>>,
) -> Option<LocatedNode> {
    // Only stepping in unwraps tags; the terminal item keeps them.
    let mut node = tree;
    let mut key: Option<&Value> = None;
    for (i, seg) in segs.iter().enumerate() {
        let item = unwrap_tags(node);
        let step = match keys.as_deref_mut() {
            Some(keys) => keys.step_into(item, seg),
            None => step_into(item, seg),
        };
        match step {
            Some(step) => {
                node = step.value;
                key = step.key;
            }
            // An entry the location names but this lookup cannot find (a
            // key too long for the validator to write out, say): the map
            // holding it is the nearest item the error is about.
            None if node_type(item) == "Map" => {
                return Some(LocatedNode {
                    tagged: node_view(item, rebase, cbor_len),
                    untagged: None,
                    key: None,
                    embedded: rebase > 0,
                });
            }
            None => return locate_embedded(item, &segs[i..], rebase, depth, cbor_len),
        }
    }
    let untagged = unwrap_tags(node);
    Some(LocatedNode {
        tagged: node_view(node, rebase, cbor_len),
        untagged: (!std::ptr::eq(untagged, node)).then(|| node_view(untagged, rebase, cbor_len)),
        key: key.map(|k| node_view(k, rebase, cbor_len)),
        embedded: rebase > 0,
    })
}

/// Read one node's spans and rendering, with every offset rebased onto
/// the outer input.
fn node_view(node: &Value, rebase: usize, cbor_len: usize) -> NodeView {
    NodeView {
        span: rebased_span(node.get("position_info"), rebase, cbor_len),
        anchor: rebased_span(
            node.get("struct_position_info")
                .or_else(|| node.get("position_info")),
            rebase,
            cbor_len,
        ),
        preview: node_preview(node),
    }
}

/// Continue inside a bstr payload (definite length only — indefinite chunks
/// do not map linearly onto input offsets).
fn locate_embedded(
    node: &Value,
    segs: &[Segment],
    rebase: usize,
    depth: usize,
    cbor_len: usize,
) -> Option<LocatedNode> {
    if depth >= MAX_EMBEDDED_DEPTH || segs.is_empty() {
        return None;
    }
    if node.get("type").and_then(Value::as_str) != Some("Bytes") {
        return None;
    }
    let payload = hex::decode(node.get("value")?.as_str()?).ok()?;
    let pos = node.get("position_info")?;
    let start = pos.get("offset")?.as_u64()? as usize;
    let length = pos.get("length")?.as_u64()? as usize;
    // `position_info` is header+content; content starts after the header.
    let content_start = rebase + start + length.checked_sub(payload.len())?;
    if content_start + payload.len() > cbor_len {
        return None;
    }

    if let Ok(inner) = decoder::decode_cbor_to_value(&payload) {
        return locate_in(&inner, segs, content_start, depth + 1, cbor_len, None);
    }
    // `.cborseq` presented as an array; next segment indexes it.
    let Segment::Index(i) = segs[0] else {
        return None;
    };
    let items = decode_cbor_sequence(&payload)?;
    let (item_start, item) = items.get(i)?;
    locate_in(
        item,
        &segs[1..],
        content_start + item_start,
        depth + 1,
        cbor_len,
        None,
    )
}

/// Split a CBOR sequence (RFC 8742) into its items, each with the byte
/// offset it starts at. `None` when the payload is not a clean sequence.
fn decode_cbor_sequence(payload: &[u8]) -> Option<Vec<(usize, Value)>> {
    use crate::cbor::errors::ErrorKind;

    let mut out = Vec::new();
    let mut start = 0usize;
    while start < payload.len() {
        if out.len() >= MAX_SEQUENCE_ITEMS {
            return None;
        }
        match decoder::decode_cbor_to_value(&payload[start..]) {
            Ok(v) => {
                out.push((start, v.into_inner()));
                return Some(out);
            }
            Err(e) if e.kind == ErrorKind::TrailingData => {
                // Decoder offset after the first complete item = item boundary.
                let end = e.offset?;
                if end == 0 {
                    return None;
                }
                let item = decoder::decode_cbor_to_value(&payload[start..start + end]).ok()?;
                out.push((start, item.into_inner()));
                start += end;
            }
            Err(_) => return None,
        }
    }
    Some(out)
}

/// Rebase a decoder span onto the outer input; drop if out of range.
fn rebased_span(span: Option<&Value>, offset: usize, cbor_len: usize) -> Option<Value> {
    let span = span?;
    if offset == 0 {
        return Some(span.clone());
    }
    let start = span.get("offset")?.as_u64()? as usize + offset;
    let length = span.get("length")?.as_u64()? as usize;
    if start.checked_add(length)? > cbor_len {
        return None;
    }
    Some(json!({ "offset": start, "length": length }))
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

/// The kind the decoder gave a node, or `""` for a node carrying none.
fn node_type(node: &Value) -> &str {
    node.get("type").and_then(Value::as_str).unwrap_or("")
}

/// One step along a location: the node it reaches, and the key of the map
/// entry it went through when it stepped into a map.
struct Step<'a> {
    value: &'a Value,
    key: Option<&'a Value>,
}

impl<'a> Step<'a> {
    fn item(value: &'a Value) -> Step<'a> {
        Step { value, key: None }
    }

    /// The step into a decoded map entry `{key, value}`.
    fn entry(entry: &'a Value) -> Option<Step<'a>> {
        Some(Step {
            value: entry.get("value")?,
            key: entry.get("key"),
        })
    }
}

/// The first entry of a decoded map whose key satisfies `is_key`.
fn map_entry<'a>(node: &'a Value, is_key: impl Fn(&Value) -> bool) -> Option<Step<'a>> {
    node.get("values")?
        .as_array()?
        .iter()
        .find(|entry| entry.get("key").map(&is_key).unwrap_or(false))
        .and_then(Step::entry)
}

fn step_into<'a>(node: &'a Value, seg: &Segment) -> Option<Step<'a>> {
    let type_name = node_type(node);
    match (type_name, seg) {
        ("Array", Segment::Index(i)) => node.get("values")?.get(*i).map(Step::item),
        ("Map", Segment::Index(i)) => {
            // Bare int segments are entry indices or integer map keys; try key first.
            let entries = node.get("values")?.as_array()?;
            for entry in entries {
                // An indefinite-length map ends in its break, which is no entry.
                let Some(k) = entry.get("key") else {
                    continue;
                };
                let kt = k.get("type").and_then(Value::as_str).unwrap_or("");
                if matches!(
                    kt,
                    "U8" | "U16" | "U32" | "U64" | "I8" | "I16" | "I32" | "I64" | "Int"
                ) {
                    if k.get("value").and_then(Value::as_i64) == Some(*i as i64) {
                        return Step::entry(entry);
                    }
                }
            }
            entries.get(*i).and_then(Step::entry)
        }
        // A string key of indefinite length is the text its chunks spell.
        ("Map", Segment::TextKey(key)) => map_entry(node, |k| {
            diagnostic::string_payload_is(k, "String", "IndefiniteLengthString", key)
        }),
        ("Map", Segment::FloatKey(f)) => map_entry(node, |k| {
            matches!(node_type(k), "F16" | "F32" | "F64")
                && k.get("value").and_then(Value::as_f64) == Some(*f)
        }),
        ("Map", Segment::BytesKey(b)) => {
            // Decoder shows bstr content as lowercase hex (literal form).
            let want = hex::encode(b);
            map_entry(node, |k| {
                diagnostic::string_payload_is(k, "Bytes", "IndefiniteLengthBytes", &want)
            })
        }
        ("Map", Segment::BoolKey(b)) => map_entry(node, |k| {
            node_type(k) == "Bool" && k.get("value").and_then(Value::as_bool) == Some(*b)
        }),
        // The validator reads `undefined` as `null`, and names it so.
        ("Map", Segment::NullKey) => {
            map_entry(node, |k| matches!(node_type(k), "Null" | "Undefined"))
        }
        ("Map", Segment::IntKey(n)) => map_entry(node, |k| diagnostic::int_node_is(k, *n)),
        ("Map", Segment::CompositeKey(item)) => {
            map_entry(node, |k| diagnostic::node_matches(k, item))
        }
        // An entry the validator names by nothing, when it can only be one.
        ("Map", Segment::Unnamed) => unnamed_entry(node).and_then(Step::entry),
        ("Tag", _) => node.get("value").map(Step::item),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_hex, document_cache, limits, validate_cbor_bytes_against_cddl, validate_cddl_text,
        with_root_first,
    };
    use serde_json::{json, Value};

    fn error_obj(result: &Value) -> &Value {
        assert_eq!(
            result["valid"],
            Value::Bool(false),
            "unexpected success: {}",
            result
        );
        &result["error"]
    }

    /// Signed Conway preview tx fixture (same as schema_mapper tests).
    const PREVIEW_TX: &str = "84a400d901028182582016b6ee8c812f8b1c9c643ee3828f50fdcf0f174625bbd6e947ba77b12374094a00018282583900aef399a405edd6797117a3db6653e1a230e1f6f91dd5badb77f2be3720fc45da826093ae8ed2e4f0f81c4f5ea9b6f0dda561c974cfc6355d1a000f424082583900f275cb75d82f737c49280039947e484919ee044c82c2e4ceaf2f2d87984c3eb5c8a01b4b53c7cec4cfc139345a28d24a6ec918873c459add1a48b7d00d021a00030d40075820bdaa99eb158414dea0a91d6c727e2268574b23efe6e08ab3b841abe8059a030ca100d9010281825820f8f5750132a13473240e318dd36eccd70083e8f08ac589c74ebe776f43e9401d58401e149e081ff497d7f97c3ef7427a916d1b0632c6eb98bb54b040aca413a2ad94273291c9b63b2802083c72b0cfe03eef2b55f767ecf32dba894dd59701076409f5d90103a0";

    fn load_ledger_cddl() -> &'static str {
        crate::cbor::test_fixtures::ledger_cddl()
    }

    #[test]
    fn validate_cddl_accepts_the_ledger_schema() {
        let cddl = load_ledger_cddl();
        let result = validate_cddl_text(cddl);
        assert_eq!(
            result,
            json!({ "valid": true }),
            "the ledger schema should validate cleanly, got {}",
            result
        );
    }

    /// Every version of the ledger schema must parse and resolve all of its
    /// references.
    #[test]
    fn validate_cddl_accepts_every_schema_version() {
        for (version, cddl) in crate::cbor::test_fixtures::schema_suite() {
            let result = validate_cddl_text(cddl);
            assert_eq!(
                result,
                json!({ "valid": true }),
                "{} schema should validate cleanly, got {}",
                version,
                result
            );
        }
    }

    /// Minimal `set<a> = #6.258([* a])` shape — bisect upstream vs full Conway CDDL.
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
        let result = validate_cbor_bytes_against_cddl(&bytes, HAND_GENERICS_CDDL, "transaction");
        assert_eq!(
            result,
            json!({ "valid": true }),
            "real preview tx should validate against hand-written Conway-style CDDL, got {}",
            result
        );
    }

    /// Closer Conway shape (`nonempty_set`, `.size` on vkey/signature) for bisect.
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

    // ---------- CDDL engine behaviour, isolated ----------
    // One construct at a time — regressions show up here, not only in full-schema tests.

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
            validate_cbor_bytes_against_cddl(&bytes, "x = [bstr .size 32, uint]", "x"),
            json!({ "valid": true })
        );
    }

    /// Generic args read where written; hop-bounded so non-arriving chains decline.
    #[test]
    fn cddl_byte_span_walks_through_a_generic_argument_passed_on() {
        // Deep alias chains need more stack than a default test thread on debug builds.
        crate::cbor::test_fixtures::on_large_stack(|| {
            for hops in [2usize, 3, 8] {
                let mut schema = String::from("x = [* b0<x>] / uint\n");
                for hop in 0..hops - 1 {
                    schema.push_str(&format!("b{}<t> = b{}<t>\n", hop, hop + 1));
                }
                schema.push_str(&format!("b{}<t> = t\n", hops - 1));

                // [["a"]]: the text at /0/0 is neither an array nor a uint.
                let cbor = hex::decode("81816161").unwrap();
                let result = validate_cbor_bytes_against_cddl(&cbor, &schema, "x");
                let err = error_obj(&result);
                assert_eq!(err["kind"], json!("mismatch"), "{}", err);
                assert_eq!(err["path"], json!("$[0][0]"), "{}", err);
                // Entry through which the failing item was reached (`b0` in `x = [* b0<x>]`).
                let span = err
                    .get("cddl_byte_span")
                    .unwrap_or_else(|| panic!("no cddl_byte_span in {}", err));
                assert_eq!(span["offset"], json!(7), "{} hops: {}", hops, err);
                assert_eq!(span["length"], json!(2), "{} hops: {}", hops, err);
            }
        });
    }

    #[test]
    fn mismatch_carries_cddl_byte_span_pointing_at_failing_type() {
        // Schema `thing = {a: int, b: [tstr, tstr]}`; first `tstr` @21..=24, second @27..=30.
        let schema = "thing = {a: int, b: [tstr, tstr]}";
        // a26161016162820203 = {"a":1,"b":[2,3]} — both `b` elems fail `tstr`.
        let cbor = hex::decode("a26161016162820203").unwrap();
        let result = validate_cbor_bytes_against_cddl(&cbor, schema, "thing");
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
        // Failing leaf inside generic arg: bind `a` → `inner` and continue for the span.
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
        // Span at `tstr` (via `inner`) or at `inner` itself.
        assert!(
            snippet == "tstr" || snippet == "inner",
            "span should hit the bound generic body, got {:?}",
            snippet
        );
    }

    #[test]
    fn cddl_byte_span_with_wrapper_subtracts_prefix() {
        // Non-first rule → wrapper path; span coords must be original CDDL.
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
        assert_eq!(
            snippet, "uint",
            "span should point at `uint`, got {:?}",
            snippet
        );
    }

    /// `.size N` behind one rule hop as array entry — fixed in our anweiss fork
    /// (≤0.10.5 treated the outer array as `.size` operand).
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

    /// Preview tx vs Conway-style CDDL with `nonempty_set` + `.size` (fork fix).
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

    /// The record doc vs the full ledger schema (generics, sets, `.size`, tags).
    #[test]
    fn validate_cbor_against_the_ledger_schema_for_the_record_doc() {
        let cddl = load_ledger_cddl();
        let bytes = crate::cbor::test_fixtures::record_doc();
        let result = validate_cbor_bytes_against_cddl(&bytes, cddl, "record");
        assert_eq!(
            result,
            json!({ "valid": true }),
            "the record doc should validate against the ledger schema, got {}",
            result
        );
    }

    #[test]
    fn validate_cbor_against_the_ledger_schema_uses_a_non_root_rule() {
        // Non-root `ref`; CBOR `[hash(32), idx]`.
        let cddl = load_ledger_cddl();
        // 82 5820<32 bytes> 00 = [bstr(32), 0]
        let cbor_hex = format!("82{}{}{}", "5820", "11".repeat(32), "00");
        let bytes = hex::decode(&cbor_hex).unwrap();
        let result = validate_cbor_bytes_against_cddl(&bytes, cddl, "ref");
        assert_eq!(
            result,
            json!({ "valid": true }),
            "ref should validate against the ledger schema, got {}",
            result
        );
    }

    #[test]
    fn validate_cbor_against_the_ledger_schema_flags_mismatch_with_path() {
        // Wrong-shaped record: `01` is a uint, not a record array.
        let cddl = load_ledger_cddl();
        let bytes = hex::decode("01").unwrap();
        let result = validate_cbor_bytes_against_cddl(&bytes, cddl, "record");
        assert_eq!(result["valid"], Value::Bool(false));
        let err = &result["error"];
        assert!(
            err.get("kind").is_some(),
            "expected kind on ledger mismatch, got {}",
            err
        );
        assert!(
            err.get("path").is_some(),
            "expected path on ledger mismatch, got {}",
            err
        );
    }

    /// A root rule is asked for by its name as written, which is how
    /// `cddl_outline` reports it: `$m` for a socket (its identifier alone
    /// still names it when no rule is written so). `m` and `$m` are two
    /// rules, on every export that takes a root.
    #[test]
    fn a_root_socket_is_named_as_the_outline_names_it() {
        use crate::cbor::{cbor_cddl_map, cddl_tools, schema_mapper};
        let valid = |hex: &str, cddl: &str, rule: &str| {
            validate_cbor_bytes_against_cddl(&hex::decode(hex).unwrap(), cddl, rule)["valid"]
                == json!(true)
        };
        let kind = |hex: &str, cddl: &str, rule: &str| {
            validate_cbor_bytes_against_cddl(&hex::decode(hex).unwrap(), cddl, rule)["error"]
                ["kind"]
                .clone()
        };
        let socket = "$m /= {1: uint}\n$m /= {3: tstr}";
        let outline = cddl_tools::outline(socket).ok().unwrap();
        assert_eq!(outline[0]["name"], json!("$m"));
        for rule in ["$m", "m"] {
            // {3: "x"} is the second body's; {3: 1} is neither's.
            assert!(valid("a1036178", socket, rule), "{}", rule);
            assert!(!valid("a10301", socket, rule), "{}", rule);
            let bytes = hex::decode("a1036178").unwrap();
            assert!(
                schema_mapper::decode_cbor_against_cddl(&bytes, socket, rule).is_ok(),
                "{}",
                rule
            );
            assert!(
                cbor_cddl_map::map_cbor_to_cddl(&bytes, socket, rule).is_ok(),
                "{}",
                rule
            );
        }
        // Both written: each name is its own rule.
        let both = "m = uint\n$m /= {1: uint}";
        assert!(valid("05", both, "m"));
        assert!(!valid("05", both, "$m"));
        assert!(valid("a10102", both, "$m"));
        assert!(!valid("a10102", both, "m"));
        // A socket named nowhere, and a group socket, are refused as any
        // other name is.
        assert_eq!(kind("05", socket, "$x"), json!("missing_rule"));
        assert_eq!(kind("05", socket, "$$m"), json!("missing_rule"));
        let group = "t = [$$g]\n$$g //= (1, uint)";
        assert_eq!(kind("820101", group, "$$g"), json!("group_rule_root"));
        assert!(
            schema_mapper::decode_cbor_against_cddl(&hex::decode("05").unwrap(), socket, "$x")
                .is_err()
        );
    }

    #[test]
    fn validate_cbor_against_the_ledger_schema_missing_rule() {
        let cddl = load_ledger_cddl();
        let bytes = crate::cbor::test_fixtures::record_doc();
        let result = validate_cbor_bytes_against_cddl(&bytes, cddl, "definitely_not_a_rule");
        assert_eq!(result["valid"], Value::Bool(false));
        assert_eq!(
            result["error"]["kind"],
            Value::String("missing_rule".into())
        );
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
        // Dangling refs via `cddl_from_pest_str_checked` → `unresolved_references`.
        let result = validate_cddl_text("thing = [unknown_rule, int]");
        let error = error_obj(&result);
        assert_eq!(error["kind"], Value::String("unresolved_references".into()));
        assert!(
            error["message"].as_str().unwrap().contains("unknown_rule"),
            "message should mention the missing rule, got {}",
            error
        );
    }

    /// Mutual aliases pass the ref check but describe nothing matchable.
    #[test]
    fn a_schema_whose_rules_only_resolve_to_each_other_is_rejected() {
        for schema in [
            "a = b\nb = a",
            "a = a",
            "a = b\nb = c\nc = a",
            // Unwrap/parens pass a name along without describing data.
            "a = ~b\nb = ~a",
            "a = (b)\nb = (a)",
            // The same through group rules.
            "g = (h)\nh = (g)\nx = [g]",
        ] {
            let error = error_obj(&validate_cddl_text(schema)).clone();
            assert_eq!(
                error["kind"],
                Value::String("unresolved_references".into()),
                "{}",
                schema
            );
            // Every rule in the cycle is named, with a span to point at.
            let unresolved = error["unresolved"].as_array().expect("an unresolved list");
            assert!(!unresolved.is_empty(), "{}", schema);
            for entry in unresolved {
                let span = &entry["byte_span"];
                let offset = span["offset"].as_u64().unwrap() as usize;
                let length = span["length"].as_u64().unwrap() as usize;
                assert_eq!(
                    &schema[offset..offset + length],
                    entry["name"].as_str().unwrap(),
                    "{}",
                    schema
                );
            }
        }
    }

    /// Productive if any path reaches data; cycles alone are not defects.
    #[test]
    fn a_rule_that_reaches_a_type_describing_data_is_accepted() {
        for schema in [
            // Recursion through an array: the array describes data.
            "a = [a]",
            "a = [* a] / uint",
            "a = [b]\nb = a",
            // One data alternative (or a rule standing for one) is enough.
            "a = b / int\nb = a",
            "a = b / int\nb = a\nc = b",
            // A member key describes its entry whatever the value does.
            "a = { k: b }\nb = a",
            // A generic parameter is filled in by the caller.
            "a<t> = t\nb = a<int>",
            // A socket is filled in by another document.
            "a = $$sock",
            "a = uint",
        ] {
            assert_eq!(
                validate_cddl_text(schema),
                json!({ "valid": true }),
                "{}",
                schema
            );
        }
    }

    /// Every version of the ledger schema must stay productive.
    #[test]
    fn every_schema_version_is_productive() {
        for (version, cddl) in crate::cbor::test_fixtures::schema_suite() {
            assert_eq!(
                validate_cddl_text(cddl),
                json!({ "valid": true }),
                "{}",
                version
            );
        }
    }

    /// Schema errors identical across entry points.
    #[test]
    fn validating_data_against_an_unproductive_schema_reports_the_same_error() {
        let schema = "a = b\nb = a";
        let from_data = validate_cbor_bytes_against_cddl(&hex::decode("01").unwrap(), schema, "a");
        assert_eq!(from_data, validate_cddl_text(schema));
    }

    /// Synthetic root name must not collide with any name in the schema.
    #[test]
    fn a_schema_defining_the_wrapper_name_still_validates() {
        // `g<t>` is generic → wrapper path.
        for schema in [
            "g<t> = uint",
            "__cquisitor_root = tstr\ng<t> = uint",
            "g<t> = uint\n__cquisitor_root = tstr",
            // A longer run of underscores, in a rule and in a comment.
            "________cquisitor_root = tstr\ng<t> = uint",
            "g<t> = uint\n; ____________cquisitor_root\n",
        ] {
            assert_eq!(
                validate_cbor_bytes_against_cddl(&hex::decode("01").unwrap(), schema, "g"),
                json!({ "valid": true }),
                "{}",
                schema
            );
            // Wrapper still validates; mismatches stay data-side.
            let error = error_obj(&validate_cbor_bytes_against_cddl(
                &hex::decode("6161").unwrap(),
                schema,
                "g",
            ))
            .clone();
            assert_eq!(
                error["kind"],
                Value::String("mismatch".into()),
                "{}",
                schema
            );
        }
    }

    #[test]
    fn the_synthetic_root_name_is_absent_from_the_schema() {
        for schema in [
            "a = uint".to_string(),
            "__cquisitor_root = uint".to_string(),
            format!("{}cquisitor_root = uint", "_".repeat(64)),
            format!("; {}\na = uint", "_".repeat(200)),
            String::new(),
        ] {
            let name = super::synthetic_root_name(&schema);
            assert!(
                !schema.contains(&name),
                "{:?} contains its own wrapper name {:?}",
                schema,
                name
            );
        }
    }

    #[test]
    fn matching_cbor_against_cddl_reports_valid() {
        let cbor = hex::decode("a264646174611901006269640a").unwrap();
        let result =
            validate_cbor_bytes_against_cddl(&cbor, "thing = {data: uint, id: uint}", "thing");
        assert_eq!(result, json!({"valid": true}));
    }

    #[test]
    fn mismatch_surfaces_path_and_byte_spans() {
        // a26161016162820203 = {"a": 1, "b": [2, 3]}, b expects [tstr, tstr].
        let cbor = hex::decode("a26161016162820203").unwrap();
        let result =
            validate_cbor_bytes_against_cddl(&cbor, "thing = {a: int, b: [tstr, tstr]}", "thing");
        let error = error_obj(&result);
        assert!(error.get("kind").is_some());
        assert!(error.get("path").is_some(), "no path: {}", error);
        let spans = error
            .get("byte_spans")
            .and_then(Value::as_array)
            .expect("byte_spans should be synthesised");
        assert!(
            !spans.is_empty(),
            "byte_spans must contain the failing node"
        );
        assert_eq!(spans[0]["offset"], json!(7), "first-element span {}", error);
        assert_eq!(spans[0]["length"], json!(1));
    }

    /// Non-text/int map keys keep CDDL literal form in the path (a float in the
    /// bracket form, as its `.` would read as a separator); value spans locate.
    #[test]
    fn non_text_map_key_is_located_in_the_document() {
        // (member key, document, path, failing value offset/length)
        let cases: [(&str, &str, &str, u64, u64); 5] = [
            // a1 f93e00 6178 = {1.5: "x"}
            ("1.5", "a1f93e006178", "$[1.5]", 4, 2),
            // a1 f93c00 6178 = {1.0: "x"}
            ("1.0", "a1f93c006178", "$[1.0]", 4, 2),
            // a1 420102 6178 = {h'0102': "x"}
            ("h'0102'", "a14201026178", "$.h'0102'", 4, 2),
            // a1 f5 6178 = {true: "x"}
            ("true", "a1f56178", "$.true", 2, 2),
            // a1 f6 6178 = {null: "x"}
            ("null", "a1f66178", "$.null", 2, 2),
        ];

        for (member_key, doc, path, offset, length) in cases {
            let cddl = format!("thing = {{ {} => uint }}", member_key);
            let cbor = hex::decode(doc).unwrap();
            let result = validate_cbor_bytes_against_cddl(&cbor, &cddl, "thing");
            let error = error_obj(&result);
            assert_eq!(error["path"], json!(path), "{} names {}", member_key, error);
            let spans = error
                .get("byte_spans")
                .and_then(Value::as_array)
                .unwrap_or_else(|| panic!("no byte_spans for {}: {}", member_key, error));
            assert_eq!(spans[0]["offset"], json!(offset), "{}", error);
            assert_eq!(spans[0]["length"], json!(length), "{}", error);
        }

        // The same documents holding a value of the declared type are admitted.
        for (member_key, doc) in [
            ("1.5", "a1f93e0001"),
            ("1.0", "a1f93c0001"),
            ("h'0102'", "a142010201"),
            ("true", "a1f501"),
            ("null", "a1f601"),
        ] {
            let cddl = format!("thing = {{ {} => uint }}", member_key);
            let cbor = hex::decode(doc).unwrap();
            assert_eq!(
                validate_cbor_bytes_against_cddl(&cbor, &cddl, "thing"),
                json!({"valid": true}),
                "{} holds 1",
                member_key
            );
        }

        // Int vs float keys are distinct; a1 01 01 vs a1 f93c00 01.
        let by_int = hex::decode("a10101").unwrap();
        let by_float = hex::decode("a1f93c0001").unwrap();
        assert_eq!(
            validate_cbor_bytes_against_cddl(&by_int, "thing = { 1 => uint }", "thing"),
            json!({"valid": true})
        );
        assert_eq!(
            validate_cbor_bytes_against_cddl(&by_float, "thing = { 1 => uint }", "thing")["valid"],
            json!(false)
        );
        assert_eq!(
            validate_cbor_bytes_against_cddl(&by_int, "thing = { 1.0 => uint }", "thing")["valid"],
            json!(false)
        );
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
        let result = validate_cbor_bytes_against_cddl(&cbor, "not a cddl schema @@@", "thing");
        let error = error_obj(&result);
        assert_eq!(error["kind"], Value::String("parse_error".into()));
    }

    /// Schema vs document faults use different `kind`s; decode failures stay
    /// `input_parse`, never CDDL-side.
    #[test]
    fn undecodable_document_and_unparseable_schema_report_different_kinds() {
        let schema = "thing = uint";

        // Malformed CBOR shapes: reserved AI, bare break, truncated head, short array,
        // trailing bytes.
        for document in [
            &[0x1c][..],
            &[0xff][..],
            &[0x18][..],
            &[0x82, 0x01][..],
            &[0x01, 0x01][..],
        ] {
            let result = validate_cbor_bytes_against_cddl(document, schema, "thing");
            let error = error_obj(&result);
            assert_eq!(
                error["kind"],
                json!("input_parse"),
                "{:?} is a fault in the document: {}",
                document,
                error
            );
        }

        // Bad document under bad schema → schema fault kind wins.
        let result = validate_cbor_bytes_against_cddl(&[0x01, 0x01], "thing = = uint", "thing");
        let error = error_obj(&result);
        assert_eq!(error["kind"], json!("parse_error"), "{}", error);

        // The boundary: a schema that parses and a document that decodes.
        assert_eq!(
            validate_cbor_bytes_against_cddl(&[0x01], schema, "thing"),
            json!({ "valid": true })
        );
    }

    #[test]
    fn dangling_reference_reaches_cbor_entry_point() {
        let cbor = hex::decode("01").unwrap();
        let result =
            validate_cbor_bytes_against_cddl(&cbor, "thing = [unknown_rule, int]", "thing");
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
        // a16161 1864 = {"a":100}; expect tstr value @3 len 2.
        let cbor = hex::decode("a161611864").unwrap();
        let result = validate_cbor_bytes_against_cddl(&cbor, "thing = {a: tstr}", "thing");
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
        // a1 01 1864 = {1:100}; expect tstr @2 len 2.
        let cbor = hex::decode("a1011864").unwrap();
        let result = validate_cbor_bytes_against_cddl(&cbor, "thing = {1 => tstr}", "thing");
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
        // a1 6161 82 01 02 = {"a":[1,2]}; first elem @4 fails tstr.
        let cbor = hex::decode("a161618201 02".replace(' ', "").as_str()).unwrap();
        let result = validate_cbor_bytes_against_cddl(&cbor, "thing = {a: [tstr, tstr]}", "thing");
        let error = error_obj(&result);
        let spans = error
            .get("byte_spans")
            .and_then(Value::as_array)
            .expect("spans");
        assert_eq!(spans[0]["offset"], json!(4), "{}", error);
        assert_eq!(spans[0]["length"], json!(1));
    }

    #[test]
    fn schema_side_position_is_reported_as_a_span_not_a_location_string() {
        let cbor = hex::decode("a16161 1864".replace(' ', "").as_str()).unwrap();
        let cddl = "thing = {a: tstr}";
        let result = validate_cbor_bytes_against_cddl(&cbor, cddl, "thing");
        let error = error_obj(&result);
        // No upstream schema location — synthesised `cddl_byte_span` is what consumers get.
        assert!(error.get("cddl_location").is_none(), "{}", error);
        let span = error
            .get("cddl_byte_span")
            .unwrap_or_else(|| panic!("no cddl_byte_span: {}", error));
        assert_eq!(span_substr(cddl, span), "tstr");
    }

    #[test]
    fn full_error_object_shape_contains_offset_and_length() {
        // Fix the output so it's obvious what shape callers get.
        let cbor = hex::decode("a26161016162820203").unwrap();
        let result =
            validate_cbor_bytes_against_cddl(&cbor, "thing = {a: int, b: [tstr, tstr]}", "thing");
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
        // Map vs array: `anchor_spans` = whole node, `byte_spans` = header.
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
        let result = validate_cbor_bytes_against_cddl(&cbor, "other = uint\nname = tstr", "name");
        assert_eq!(result, json!({"valid": true}));
    }

    #[test]
    fn missing_rule_is_reported_distinctly() {
        let cbor = hex::decode("01").unwrap();
        let result = validate_cbor_bytes_against_cddl(&cbor, "thing = int", "no_such_rule");
        let error = error_obj(&result);
        assert_eq!(error["kind"], Value::String("missing_rule".into()));
    }

    #[test]
    fn non_root_rule_name_still_validates_via_wrapper() {
        // Second rule → internal `__cquisitor_root` wrapper.
        let cbor = hex::decode("01").unwrap();
        let result = validate_cbor_bytes_against_cddl(&cbor, "root = tstr\nnum = uint", "num");
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
        assert_eq!(
            decode_hex("DeAdBeEf").unwrap(),
            vec![0xDE, 0xAD, 0xBE, 0xEF]
        );
    }

    // ============================================================
    // Additional coverage — `validate_cddl_text`
    // ============================================================

    #[test]
    fn parse_error_on_multi_line_cddl_reports_line_greater_than_one() {
        // Parse error on line 3 (`=` without RHS).
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
        assert!(
            line > 1,
            "line should be > 1 for multi-line failure, got {}",
            line
        );
        let off = span["offset"].as_u64().unwrap() as usize;
        assert!(
            off <= cddl.len(),
            "offset {} should land inside source of length {}",
            off,
            cddl.len()
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
        // Three failing elems → head + `additional`.
        let cbor = hex::decode("83010203").unwrap();
        let result = validate_cbor_bytes_against_cddl(&cbor, "thing = [tstr, tstr, tstr]", "thing");
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
        // Nested map; amount slot tstr "h" @11 breaks `uint`.
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
        // Deep tstr leaf: `cddl_byte_span` on `amount`; anchors only on containers.
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
        // Validate `inner` (2nd rule); span must be substring of original CDDL.
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
        assert_eq!(
            snippet, "tstr",
            "cddl slice must equal source text, got {:?}",
            snippet
        );
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
        // Same-node choice failures fold; tried types survive in `alternatives`.
        assert_eq!(err["occurrences"], json!(2), "{}", err);
        let mut all_text: Vec<String> = vec![err["message"].as_str().unwrap_or("").to_string()];
        for e in err
            .get("alternatives")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            all_text.push(e.as_str().unwrap_or("").to_string());
        }
        if let Some(arr) = err.get("additional").and_then(Value::as_array) {
            for e in arr {
                all_text.push(e["message"].as_str().unwrap_or("").to_string());
            }
        }
        let blob = all_text.join(" | ");
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
        // Invalid; message mentions key 1 (head or additional).
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
        let result = validate_cbor_bytes_against_cddl(&bytes, "x = bstr .size 32", "x");
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
        // Span somewhere in `bstr .size 32` / rule body — non-empty, in-bounds.
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
        // Tag 258 + one [vkey(32), sig(64)] witness.
        let cbor_hex = format!("d9010281825820{}5840{}", "11".repeat(32), "22".repeat(64));
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
        // Same shape; signature 63 bytes (violates `.size 64`).
        let cbor_hex = format!("d9010281825820{}583f{}", "11".repeat(32), "22".repeat(63));
        let bytes = hex::decode(&cbor_hex).unwrap();
        let result = validate_cbor_bytes_against_cddl(&bytes, cddl, "payload");
        let err = error_obj(&result);
        assert_eq!(err["kind"], json!("mismatch"), "got {}", err);
        // Path `$[0][1]` (sig); tag transparent.
        assert_eq!(err["path"], json!("$[0][1]"), "got {}", err);
        // Byte spans land on the offending bstr (the 63-byte signature).
        let spans = err
            .get("byte_spans")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("no byte_spans in {}", err));
        let off = spans[0]["offset"].as_u64().unwrap() as usize;
        let len = spans[0]["length"].as_u64().unwrap() as usize;
        // Sig bstr @39, 65 bytes (`583f` + 63 content).
        assert_eq!(off, 39, "{}", err);
        assert_eq!(len, 65, "{}", err);
        // CDDL span somewhere valid in schema (`signature` or `bstr .size 64`).
        let cspan = err
            .get("cddl_byte_span")
            .unwrap_or_else(|| panic!("no cddl_byte_span in {}", err));
        let coff = cspan["offset"].as_u64().unwrap() as usize;
        let clen = cspan["length"].as_u64().unwrap() as usize;
        let snippet = &cddl[coff..coff + clen];
        assert!(
            !snippet.is_empty()
                && (snippet.contains("size")
                    || snippet.contains("signature")
                    || snippet.contains("bstr")),
            "cddl span should point at the signature path, got {:?}",
            snippet
        );
    }

    /// Control operator with no usable operand → schema fault kind, not mismatch.
    #[test]
    fn broken_control_operand_is_reported_as_a_schema_fault() {
        // `03` is the integer 3, which the sound form of each schema admits.
        let cbor = hex::decode("03").unwrap();

        // Undefined/self-only operands caught before validate; validator sees a named
        // productive rule that still supplies no operator value.
        for (label, cddl) in [
            (
                "operand of the wrong kind",
                "thing = int .eq (1 .plus a)\na = tstr",
            ),
            // A matching alternative must not bury a schema fault.
            (
                "broken operand in one alternative of a type choice",
                "thing = int .eq (1 .plus a) / int\na = tstr",
            ),
            (
                "broken operand of a computed controller",
                "thing = int .lt (1 .plus a)\na = tstr",
            ),
        ] {
            let result = validate_cbor_bytes_against_cddl(&cbor, cddl, "thing");
            let err = error_obj(&result);
            assert_eq!(err["kind"], json!("invalid_schema"), "{}: {}", label, err);
            assert!(
                err["message"].as_str().unwrap_or("").contains(".plus"),
                "{}: {}",
                label,
                err
            );
        }
    }

    /// Defined operands stay on the data channel (mismatch or valid).
    #[test]
    fn sound_control_operand_is_not_reported_as_a_schema_fault() {
        let cddl = "thing = int .eq (1 .plus 2)";

        let matching = hex::decode("03").unwrap();
        let result = validate_cbor_bytes_against_cddl(&matching, cddl, "thing");
        assert_eq!(result["valid"], json!(true), "{}", result);

        let mismatching = hex::decode("04").unwrap();
        let result = validate_cbor_bytes_against_cddl(&mismatching, cddl, "thing");
        let err = error_obj(&result);
        assert_ne!(err["kind"], json!("invalid_schema"), "{}", err);
    }

    /// Map cut (`^ =>`): kind in {`map_cut`,`mismatch`,`generic`}, always invalid.
    /// Avoid brittle exact-kind asserts on upstream wording.
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
        // Message mentions offending value type or cut.
        let msg = err["message"].as_str().unwrap_or("").to_lowercase();
        assert!(!msg.is_empty(), "expected a non-empty message, got {}", err);
    }

    // ============================================================
    // Additional coverage — `cddl_byte_span` synthesiser
    // ============================================================

    /// Recorded `cddl_byte_span` must slice the expected substring from original CDDL.
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
            let result = validate_cbor_bytes_against_cddl(&bytes, c.cddl, c.rule);
            let err = error_obj(&result);
            let span = err
                .get("cddl_byte_span")
                .unwrap_or_else(|| panic!("case {}: no cddl_byte_span in {}", i, err));
            let off = span["offset"].as_u64().unwrap() as usize;
            let len = span["length"].as_u64().unwrap() as usize;
            assert!(
                off + len <= c.cddl.len(),
                "case {}: span out of range — off={} len={} cddl_len={}",
                i,
                off,
                len,
                c.cddl.len()
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
        // Empty location → span on the rule value (`uint`).
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
        // Third rule + wrapper; offsets refer to original CDDL.
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
            off,
            len,
            cddl.len()
        );
        let snippet = &cddl[off..off + len];
        assert_eq!(snippet, "bool", "wrapper case slice should match `bool`");
    }

    #[test]
    fn cddl_byte_span_for_generic_map_value_lands_on_argument_type() {
        // Generic `wrap<v>`; descend key `a` and resolve `v` → `int`.
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
        // Span at `int` (preferred) or param `v`.
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
        // Truncated bstr header → stable `input_parse` JSON shape.
        let bytes = hex::decode("5820").unwrap();
        let result = validate_cbor_bytes_against_cddl(&bytes, "x = bstr", "x");
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
        let result = validate_cbor_bytes_against_cddl(&cbor, "x = int", "no_such_rule_xyz");
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
        // Parses but zero rules → `no_rules` (not a hard parse error).
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
        // Scalar top-level bstr: `anchor_spans` fall back to `position_info`.
        let cbor_hex = format!("581f{}", "ab".repeat(31));
        let bytes = hex::decode(&cbor_hex).unwrap();
        let result = validate_cbor_bytes_against_cddl(&bytes, "x = bstr .size 32", "x");
        let err = error_obj(&result);
        let anchor = err
            .get("anchor_spans")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("expected anchor_spans on scalar: {}", err));
        let byte = err
            .get("byte_spans")
            .and_then(Value::as_array)
            .expect("byte_spans");
        // Scalar without struct span: anchor == byte_spans.
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
        // {"a":{"b":[1,"x"]}}; a1 6161 a1 6162 82 01 6178
        let cbor = hex::decode("a16161a161628201 6178".replace(' ', "").as_str()).unwrap();
        let cddl = "thing = {a: {b: [uint, uint]}}";
        let result = validate_cbor_bytes_against_cddl(&cbor, cddl, "thing");
        let err = error_obj(&result);
        let path = err["path"].as_str().unwrap_or("");
        // Path uses `$.a.b[1]` for text keys + array index.
        assert!(path.contains(".a"), "expected `.a` in path, got {}", path);
        assert!(path.contains(".b"), "expected `.b` in path, got {}", path);
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
        let result = validate_cbor_bytes_against_cddl(&cbor, "thing = {a: int}", "thing");
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

    // ============================================================
    // Additional coverage — unresolved references reported in full
    // ============================================================

    fn span_substr<'a>(src: &'a str, span: &Value) -> &'a str {
        let off = span["offset"].as_u64().unwrap() as usize;
        let len = span["length"].as_u64().unwrap() as usize;
        &src[off..off + len]
    }

    #[test]
    fn validate_cddl_lists_every_unresolved_reference_with_a_span() {
        let cddl = "a = [alpha, beta]\nb = { k: gamma }\n";
        let error = error_obj(&validate_cddl_text(cddl)).clone();
        assert_eq!(error["kind"], Value::String("unresolved_references".into()));

        let unresolved = error["unresolved"]
            .as_array()
            .unwrap_or_else(|| panic!("expected an unresolved array in {}", error));
        let names: Vec<_> = unresolved
            .iter()
            .map(|u| u["name"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(names, vec!["alpha", "beta", "gamma"]);
        for u in unresolved {
            assert_eq!(
                span_substr(cddl, &u["byte_span"]),
                u["name"].as_str().unwrap()
            );
        }
        assert_eq!(error["truncated"], json!(false));
        // `byte_span` stays the first occurrence.
        assert_eq!(error["byte_span"], unresolved[0]["byte_span"]);
    }

    /// A resolving schema must not grow an `unresolved` array.
    #[test]
    fn validate_cddl_reports_nothing_unresolved_for_a_resolving_schema() {
        assert_eq!(
            validate_cddl_text("a = [alpha, beta]\nalpha = uint\nbeta = tstr\n"),
            json!({"valid": true})
        );
    }

    #[test]
    fn validate_cddl_message_no_longer_leaks_debug_position() {
        let cddl = "a = [alpha, beta]\nb = { k: gamma }\n";
        let error = error_obj(&validate_cddl_text(cddl)).clone();
        assert_eq!(
            error["message"],
            Value::String("missing definition for rule alpha".into())
        );
        assert!(
            !error["message"].as_str().unwrap().contains("Position {"),
            "message still carries debug position: {}",
            error
        );
    }

    #[test]
    fn validate_cddl_parse_error_message_no_longer_leaks_debug_position() {
        let error = error_obj(&validate_cddl_text("thing = uint\nother = tstr\nbad   =")).clone();
        assert_eq!(error["kind"], Value::String("parse_error".into()));
        let message = error["message"].as_str().unwrap();
        assert!(!message.is_empty(), "empty parse error message");
        assert!(
            !message.contains("Position {") && !message.contains("parsing error:"),
            "message still carries debug position: {}",
            error
        );
        // The positional information is still reported, structurally.
        assert!(error["byte_span"].is_object(), "no byte_span in {}", error);
    }

    #[test]
    fn validate_cddl_still_reports_no_rules_and_parse_error() {
        for src in ["", "; only a comment\n"] {
            assert_eq!(
                error_obj(&validate_cddl_text(src))["kind"],
                json!("no_rules"),
                "for {:?}",
                src
            );
        }
        let error = error_obj(&validate_cddl_text("thing = uint\nother = tstr\nbad   =")).clone();
        assert_eq!(error["kind"], Value::String("parse_error".into()));
        assert!(
            error["byte_span"]["line"].as_u64().unwrap() > 1,
            "expected a line past the first, got {}",
            error
        );
        assert!(
            error.get("unresolved").is_none(),
            "a syntax error is not an unresolved reference: {}",
            error
        );
    }

    /// Duplicate rule rejected at the redefining declaration's span.
    #[test]
    fn duplicate_rule_definition_is_reported_at_the_redefinition() {
        for (src, redefinition) in [
            (
                "Person = { name: tstr }\nPerson = { age: uint }\n",
                "Person = { age: uint }",
            ),
            ("a = uint\nb = tstr\na = bstr\n", "a = bstr"),
            ("a = uint ; a comment\na = bstr", "a = bstr"),
            ("g = (a: uint)\ng = (b: uint)\n", "g = (b: uint)"),
        ] {
            let error = error_obj(&validate_cddl_text(src)).clone();
            assert_eq!(error["kind"], json!("parse_error"), "{}", error);
            assert!(
                error["message"]
                    .as_str()
                    .unwrap()
                    .contains("is already defined"),
                "{}",
                error
            );
            let span = &error["byte_span"];
            let offset = span["offset"].as_u64().unwrap() as usize;
            let length = span["length"].as_u64().unwrap() as usize;
            assert_eq!(&src[offset..offset + length], redefinition, "{}", error);
            assert_eq!(
                span["line"].as_u64().unwrap() as usize,
                src[..offset].matches('\n').count() + 1,
                "{}",
                error
            );
            // The CBOR entry point reports the schema the same way.
            let via_cbor = error_obj(&validate_cbor_bytes_against_cddl(b"\x01", src, "a")).clone();
            assert_eq!(via_cbor["byte_span"], error["byte_span"], "{}", via_cbor);
        }
    }

    /// A rule that adds a choice to an earlier one redefines nothing.
    #[test]
    fn choice_alternates_are_not_duplicate_definitions() {
        for src in ["a = uint\na /= tstr\n", "g = (a: uint)\ng //= (b: uint)\n"] {
            assert_eq!(
                validate_cddl_text(src),
                json!({"valid": true}),
                "rejected a choice alternate: {:?}",
                src
            );
        }
    }

    #[test]
    fn every_schema_version_validates_cleanly_through_the_new_path() {
        for (version, src) in crate::cbor::test_fixtures::schema_suite() {
            assert_eq!(
                validate_cddl_text(src),
                json!({"valid": true}),
                "{} schema should validate cleanly",
                version
            );
        }
    }

    /// Renaming one rule → all dangling uses listed with name spans.
    #[test]
    fn ledger_schema_with_a_renamed_rule_reports_all_of_its_dangling_uses() {
        let src = crate::cbor::test_fixtures::ledger_cddl();
        let renamed = src.replacen("\namount = ", "\namount_renamed = ", 1);
        assert_ne!(renamed, src, "fixture no longer defines `amount`");

        let error = error_obj(&validate_cddl_text(&renamed)).clone();
        assert_eq!(error["kind"], Value::String("unresolved_references".into()));
        let unresolved = error["unresolved"].as_array().unwrap();
        assert!(
            unresolved.len() > 1,
            "expected every dangling use, got {}",
            error
        );
        for u in unresolved {
            assert_eq!(u["name"], "amount");
            assert_eq!(span_substr(&renamed, &u["byte_span"]), "amount");
        }
    }

    /// AST walker misses tag-constraint idents; parser still rejects the schema.
    #[test]
    fn validate_cddl_rejects_a_reference_the_walker_cannot_see() {
        let error = error_obj(&validate_cddl_text("a = #6.<missing>(uint)\n")).clone();
        assert_eq!(error["kind"], Value::String("unresolved_references".into()));
        assert_eq!(
            error["message"],
            Value::String("missing definition for rule missing".into())
        );
        let unresolved = error["unresolved"].as_array().unwrap();
        assert_eq!(unresolved.len(), 1, "got {}", error);
        assert_eq!(unresolved[0]["name"], "missing");
        assert_eq!(error["byte_span"], unresolved[0]["byte_span"]);
    }

    #[test]
    fn validate_cddl_caps_the_unresolved_list_and_says_it_did() {
        let cap = super::MAX_UNRESOLVED_REPORTED;
        let names: Vec<String> = (0..cap + 5).map(|i| format!("missing{}", i)).collect();
        let cddl = format!("a = [{}]\n", names.join(", "));

        let error = error_obj(&validate_cddl_text(&cddl)).clone();
        assert_eq!(error["kind"], Value::String("unresolved_references".into()));
        let unresolved = error["unresolved"].as_array().unwrap();
        assert_eq!(unresolved.len(), cap);
        assert_eq!(error["truncated"], json!(true));
        assert_eq!(unresolved[0]["name"], "missing0");
        assert_eq!(error["byte_span"], unresolved[0]["byte_span"]);
        for u in unresolved {
            assert_eq!(
                span_substr(&cddl, &u["byte_span"]),
                u["name"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn unresolved_reference_spans_carry_utf16_offsets_for_non_ascii_sources() {
        let cddl = "; кириллица\nx = [missingZ]\n";
        let error = error_obj(&validate_cddl_text(cddl)).clone();
        let span = &error["unresolved"][0]["byte_span"];
        assert_eq!(span["offset"], json!(26));
        assert_eq!(span["line"], json!(2));
        assert_eq!(span_substr(cddl, span), "missingZ");
        // Multi-byte comment → UTF-16 offset ≠ byte offset.
        assert_ne!(span["char_offset"], span["offset"], "got {}", span);
    }

    // ============================================================
    // Error-set shape: one decode, ranked head, folded duplicates
    // ============================================================

    /// The head error plus every entry under `additional`.
    fn all_entries(err: &Value) -> Vec<Value> {
        let mut out = vec![err.clone()];
        out.extend(
            err.get("additional")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
        );
        out
    }

    /// `[1, 1, …]` — an array of `n` uints — as hex.
    fn uint_array_hex(n: usize) -> String {
        let mut h = format!("9a{:08x}", n);
        for _ in 0..n {
            h.push_str("01");
        }
        h
    }

    fn cddl_span_text<'a>(cddl: &'a str, err: &Value) -> &'a str {
        let span = err
            .get("cddl_byte_span")
            .unwrap_or_else(|| panic!("no cddl_byte_span in {}", err));
        span_substr(cddl, span)
    }

    #[test]
    fn error_mapping_decodes_the_input_once() {
        // 1600 failing elems / 3.2 KB: the input is decoded once, so this stays under budget.
        let bytes = hex::decode(uint_array_hex(1600)).unwrap();
        let started = std::time::Instant::now();
        let result = validate_cbor_bytes_against_cddl(&bytes, "root = [* tstr]", "root");
        let elapsed = started.elapsed();
        let err = error_obj(&result);
        assert_eq!(
            err["additional"].as_array().map(Vec::len),
            Some(super::MAX_ADDITIONAL),
            "{}",
            err["additional_truncated"]
        );
        assert_eq!(
            err["additional_truncated"],
            json!(1600 - 1 - super::MAX_ADDITIONAL)
        );
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "mapping 1600 errors took {:?}",
            elapsed
        );
    }

    #[test]
    fn error_mapping_resolves_each_location_once() {
        // Recursive tagged choice fails at every level, all at root path; each
        // location is resolved once, not once per level.
        const LEVELS: usize = limits::MAX_CBOR_NESTING_DEPTH;
        let hex = format!("{}6161", "d863".repeat(LEVELS));
        let bytes = hex::decode(hex).unwrap();
        let started = std::time::Instant::now();
        let result = validate_cbor_bytes_against_cddl(&bytes, "x = #6.99(x) / uint", "x");
        let elapsed = started.elapsed();
        let err = error_obj(&result);
        assert_eq!(err["kind"], json!("mismatch"));
        assert_eq!(err["path"], json!("$"));
        // The leaf under the chain is what the spans name.
        assert_eq!(
            err["byte_spans"][0],
            json!({ "offset": 2 * LEVELS, "length": 2 })
        );
        assert_eq!(err["occurrences"], json!(LEVELS + 2));
        assert!(
            elapsed < std::time::Duration::from_secs(60),
            "mapping {} errors under {} tags took {:?}",
            LEVELS + 2,
            LEVELS,
            elapsed
        );
    }

    #[test]
    fn large_input_with_many_errors_stays_under_a_size_budget() {
        let bytes = crate::cbor::test_fixtures::record_doc();
        let result = validate_cbor_bytes_against_cddl(&bytes, load_ledger_cddl(), "datum");
        assert_eq!(result["valid"], json!(false));
        let payload = serde_json::to_string(&result).unwrap();
        assert!(
            payload.len() < 100_000,
            "result payload is {} bytes",
            payload.len()
        );
    }

    #[test]
    fn message_does_not_embed_a_cbor_debug_dump() {
        let bytes = crate::cbor::test_fixtures::record_doc();
        let result = validate_cbor_bytes_against_cddl(&bytes, "root = tstr", "root");
        let err = error_obj(&result);
        let msg = err["message"].as_str().unwrap();
        assert!(msg.len() < 500, "message is {} chars: {}", msg.len(), msg);
        assert!(!msg.contains("Integer(Integer("), "{}", msg);
        assert!(!msg.contains("Bytes(["), "{}", msg);
        assert_eq!(err["expected"], json!("tstr"));
        // The value that was actually there is still described.
        assert!(msg.contains("array"), "{}", msg);
    }

    #[test]
    fn short_message_keeps_what_was_there_but_not_how_it_was_rendered() {
        // Short reason keeps the value as a description, not `Debug` type names.
        // ["a","b"] vs [tstr, uint].
        let bytes = hex::decode("8261616162").unwrap();
        let result = validate_cbor_bytes_against_cddl(&bytes, "root = [tstr, uint]", "root");
        let err = error_obj(&result);
        assert_eq!(
            err["message"],
            json!("expected type uint, got text \"b\""),
            "{}",
            err
        );
    }

    #[test]
    fn message_does_not_embed_a_cddl_ast_dump() {
        let bytes = hex::decode("81f6").unwrap();
        let result = validate_cbor_bytes_against_cddl(&bytes, load_ledger_cddl(), "datum");
        let err = error_obj(&result);
        let entries = all_entries(err);
        for e in &entries {
            let msg = e["message"].as_str().unwrap();
            assert!(!msg.contains("TaggedData {"), "{}", msg);
            assert!(!msg.contains("type_choices:"), "{}", msg);
            assert!(msg.len() <= super::MAX_MESSAGE_LEN, "{}", msg);
        }
        // The tag the schema wanted is still named.
        assert!(
            entries
                .iter()
                .any(|e| e["message"].as_str().unwrap().contains("#6.")),
            "{:?}",
            entries
        );
    }

    /// A size mismatch names the lengths, not the data: the data is not what
    /// was expected there, and a long byte string would only swamp the report.
    #[test]
    fn size_mismatch_names_lengths_not_data() {
        let cbor_hex = format!("581f{}", "ab".repeat(31));
        let bytes = hex::decode(&cbor_hex).unwrap();
        let result = validate_cbor_bytes_against_cddl(&bytes, "x = bstr .size 32", "x");
        let err = error_obj(&result);
        assert_eq!(err["kind"], json!("mismatch"), "{}", err);
        assert_eq!(
            err["message"],
            json!("expected byte string of size 32 bytes, got 31 bytes"),
            "{}",
            err
        );
        assert_eq!(err["expected"], json!("byte string of size 32 bytes"), "{}", err);
        assert!(!err.to_string().contains("abab"), "{}", err);

        // Text strings are sized in bytes of UTF-8, as RFC 8610 sizes them.
        let text = hex::decode("63c2a261").unwrap();
        let err = error_obj(&validate_cbor_bytes_against_cddl(&text, "x = tstr .size 2", "x")).clone();
        assert_eq!(
            err["message"],
            json!("expected text string of size 2 bytes, got 3 bytes"),
            "{}",
            err
        );
        // Ranges name the range and the length.
        let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, "x = bstr .size (0..4)", "x")).clone();
        assert_eq!(
            err["message"],
            json!("expected byte string length to be in the range 0 <= value <= 4, got 31"),
            "{}",
            err
        );
    }

    /// Cardano bounds Plutus data byte strings per chunk: a chunked string
    /// whose chunks each fit passes, a definite-length one past the bound
    /// fails, and a chunk past the bound is named with its index. Only the
    /// upper bound reads per chunk: an exact size and a lower bound hold
    /// the whole string, and an indefinite-length string with no chunks is
    /// the empty string.
    #[test]
    fn size_control_holds_indefinite_strings_per_chunk() {
        let cddl = crate::cbor::test_fixtures::ledger_cddl();
        // 100 bytes as one definite-length string, then as 64 + 36 chunks.
        let payload = "ab".repeat(100);
        let definite = hex::decode(format!("5864{}", payload)).unwrap();
        let chunked = hex::decode(format!("5f5840{}5824{}ff", "ab".repeat(64), "ab".repeat(36))).unwrap();
        let wide = hex::decode(format!("5f5846{}581e{}ff", "ab".repeat(70), "ab".repeat(30))).unwrap();

        assert_eq!(
            validate_cbor_bytes_against_cddl(&chunked, cddl, "bounded_bytes"),
            json!({ "valid": true })
        );
        let err = error_obj(&validate_cbor_bytes_against_cddl(&definite, cddl, "bounded_bytes")).clone();
        assert_eq!(
            err["message"],
            json!("expected byte string length to be in the range 0 <= value <= 64, got 100"),
            "{}",
            err
        );
        let err = error_obj(&validate_cbor_bytes_against_cddl(&wide, cddl, "bounded_bytes")).clone();
        assert_eq!(
            err["message"],
            json!("expected each chunk of the indefinite-length byte string to be at most 64 bytes, got 70 bytes in chunk 0"),
            "{}",
            err
        );
        assert_eq!(err["kind"], json!("mismatch"), "{}", err);
        // The same string inside Plutus data, where the schema reaches it
        // through a choice.
        let datum = [&[0x81u8][..], &chunked[..]].concat();
        assert_eq!(
            validate_cbor_bytes_against_cddl(&datum, cddl, "datum"),
            json!({ "valid": true })
        );
        let datum = [&[0x81u8][..], &definite[..]].concat();
        assert_eq!(
            validate_cbor_bytes_against_cddl(&datum, cddl, "datum")["valid"],
            json!(false)
        );

        // An exact size holds the whole string: two 32-byte chunks are not
        // a 32-byte hash, and neither is an indefinite-length string with
        // no chunks.
        let two_hashes = hex::decode(format!("5f5820{}5820{}ff", "ab".repeat(32), "cd".repeat(32))).unwrap();
        let err = error_obj(&validate_cbor_bytes_against_cddl(&two_hashes, "hash32 = bytes .size 32", "hash32")).clone();
        assert_eq!(
            err["message"],
            json!("expected byte string of size 32 bytes, got 64 bytes"),
            "{}",
            err
        );
        let no_chunks = hex::decode("5fff").unwrap();
        let err = error_obj(&validate_cbor_bytes_against_cddl(&no_chunks, "hash32 = bytes .size 32", "hash32")).clone();
        assert_eq!(
            err["message"],
            json!("expected byte string of size 32 bytes, got 0 bytes"),
            "{}",
            err
        );
        // A lower bound holds the whole string too.
        let err = error_obj(&validate_cbor_bytes_against_cddl(&no_chunks, "min8 = bytes .size (8..64)", "min8")).clone();
        assert_eq!(
            err["message"],
            json!("expected byte string length to be in the range 8 <= value <= 64, got 0"),
            "{}",
            err
        );
        assert_eq!(
            validate_cbor_bytes_against_cddl(&no_chunks, cddl, "bounded_bytes"),
            json!({ "valid": true })
        );
        // 4 + 4 bytes: within (8..64) as a whole, past (0..4) as a whole
        // but not per chunk. Per chunk only under `bounded_bytes`.
        let quarters = hex::decode("5f44010203044401020304ff").unwrap();
        assert_eq!(
            validate_cbor_bytes_against_cddl(&quarters, "min8 = bytes .size (8..64)", "min8"),
            json!({ "valid": true })
        );
        assert_eq!(
            validate_cbor_bytes_against_cddl(&quarters, "bounded_bytes = bytes .size (0..4)", "bounded_bytes"),
            json!({ "valid": true })
        );
        assert_eq!(
            validate_cbor_bytes_against_cddl(&quarters, "small = bytes .size (0..4)", "small")["valid"],
            json!(false)
        );
        // Text strings: two 2-byte chunks are not `text .size 2`.
        let text = hex::decode("7f6261626263 64ff".replace(' ', "")).unwrap();
        let err = error_obj(&validate_cbor_bytes_against_cddl(&text, "txt = text .size 2", "txt")).clone();
        assert_eq!(
            err["message"],
            json!("expected text string of size 2 bytes, got 4 bytes"),
            "{}",
            err
        );
    }

    /// Only `bounded_bytes` reads a `.size` range per chunk. The ledger
    /// bounds a metadatum string as a whole whether or not it is chunked,
    /// and RFC 8610 sizes every other string as a whole: a 100-byte string
    /// in 64 + 36 byte chunks is not transaction metadata, bytes or text,
    /// nor does it fit a user rule's range, but it is a Plutus byte string.
    #[test]
    fn only_bounded_bytes_reads_size_per_chunk() {
        const SCHEMA: &str = "
            metadata = {* metadatum_label => metadatum}
            metadatum_label = uint .size 8
            metadatum = {* metadatum => metadatum} / [* metadatum] / int
                      / bytes .size (0 .. 64) / text .size (0 .. 64)
            plutus_data = [* plutus_data] / int / bounded_bytes
            bounded_bytes = bytes .size (0 .. 64)
            name = tstr .size (1 .. 10)
        ";
        let chunked_bytes = format!("5f5840{}5824{}ff", "ab".repeat(64), "cd".repeat(36));
        let chunked_text = format!("7f7840{}7824{}ff", "61".repeat(64), "62".repeat(36));
        for chunked in [&chunked_bytes, &chunked_text] {
            let metadata = hex::decode(format!("a101{chunked}")).unwrap();
            let result = validate_cbor_bytes_against_cddl(&metadata, SCHEMA, "metadata");
            assert_eq!(result["valid"], json!(false), "{}: {}", chunked, result);
        }
        // Each chunk within the bound is still a whole string past it.
        let metadata = hex::decode(format!("a101{chunked_bytes}")).unwrap();
        let err = error_obj(&validate_cbor_bytes_against_cddl(&metadata, SCHEMA, "metadata")).clone();
        assert!(
            err["message"].as_str().unwrap().contains("metadatum"),
            "{}",
            err
        );

        let bytes = hex::decode(&chunked_bytes).unwrap();
        assert_eq!(
            validate_cbor_bytes_against_cddl(&bytes, SCHEMA, "bounded_bytes"),
            json!({ "valid": true })
        );
        let datum = hex::decode(format!("81{chunked_bytes}")).unwrap();
        assert_eq!(
            validate_cbor_bytes_against_cddl(&datum, SCHEMA, "plutus_data"),
            json!({ "valid": true })
        );

        // A 30-character text in 10-byte chunks is not `tstr .size (1..10)`.
        let name = hex::decode(format!("7f6a{0}6a{0}6a{0}ff", "61".repeat(10))).unwrap();
        assert_eq!(
            validate_cbor_bytes_against_cddl(&name, SCHEMA, "name")["valid"],
            json!(false)
        );
    }

    /// The error for an entry the map type does not name is anchored on the
    /// entry: the key first, the value second, so a consumer points at the
    /// key and shades the entry.
    #[test]
    fn unexpected_key_is_anchored_on_the_entry() {
        // {1: 0, 2: 5} against a map naming only key 1.
        let bytes = hex::decode("a201000205").unwrap();
        let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, "root = { 1: uint }", "root")).clone();
        assert_eq!(err["message"], json!("unexpected key 2"), "{}", err);
        assert_eq!(err["path"], json!("$[2]"), "{}", err);
        assert_eq!(
            err["byte_spans"],
            json!([{ "offset": 3, "length": 1 }, { "offset": 4, "length": 1 }]),
            "{}",
            err
        );
        assert_eq!(err["anchor_spans"], err["byte_spans"], "{}", err);
        assert!(err.get("expected").is_none(), "{}", err);

        // A text key, with a structured value: the value's anchor is the
        // whole structure.
        let bytes = hex::decode("a26161006162820102").unwrap();
        let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, "root = { a: uint }", "root")).clone();
        assert_eq!(err["path"], json!("$.b"), "{}", err);
        assert_eq!(
            err["byte_spans"],
            json!([{ "offset": 4, "length": 2 }, { "offset": 6, "length": 1 }]),
            "{}",
            err
        );
        assert_eq!(
            err["anchor_spans"],
            json!([{ "offset": 4, "length": 2 }, { "offset": 6, "length": 3 }]),
            "{}",
            err
        );
    }

    /// An unexpected key's value is spanned from its tag head: the entry is
    /// the key and the whole value.
    #[test]
    fn unexpected_key_spans_a_tagged_value_from_its_tag_head() {
        // {1: 1, 2: 24(h'00')}
        let bytes = hex::decode("a2010102d8184100").unwrap();
        let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, "root = { 1: uint }", "root")).clone();
        assert_eq!(err["message"], json!("unexpected key 2"), "{}", err);
        assert_eq!(
            err["byte_spans"],
            json!([{ "offset": 3, "length": 1 }, { "offset": 4, "length": 2 }]),
            "{}",
            err
        );
        assert_eq!(
            err["anchor_spans"],
            json!([{ "offset": 3, "length": 1 }, { "offset": 4, "length": 4 }]),
            "{}",
            err
        );
        // {1: 1, 2: 258([1])}
        let bytes = hex::decode("a2010102d901028101").unwrap();
        let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, "root = { 1: uint }", "root")).clone();
        assert_eq!(
            err["anchor_spans"],
            json!([{ "offset": 3, "length": 1 }, { "offset": 4, "length": 5 }]),
            "{}",
            err
        );
    }

    /// A type rule extended with `/=` (a socket) is one choice of all its
    /// bodies, as the validator reads it: an unexpected key lands on the one
    /// map among them, or on the reference naming the socket when several
    /// could hold it (the choice, as `a / b` is for a written choice), and a
    /// path descends through whichever body holds it.
    #[test]
    fn a_socket_is_one_choice_of_its_bodies_in_cddl_spans() {
        let errors = |cddl: &str, rule: &str, hex: &str| -> Vec<Value> {
            let bytes = hex::decode(hex).unwrap();
            let result = validate_cbor_bytes_against_cddl(&bytes, cddl, rule);
            let head = error_obj(&result).clone();
            let mut all = vec![head.clone()];
            all.extend(head["additional"].as_array().cloned().unwrap_or_default());
            all
        };
        let unexpected_key_spans = |cddl: &str, rule: &str, hex: &str| -> Vec<(usize, String)> {
            errors(cddl, rule, hex)
                .iter()
                .filter(|e| e["message"].as_str().unwrap().starts_with("unexpected key"))
                .map(|e| {
                    let span = &e["cddl_byte_span"];
                    let at = span["offset"].as_u64().unwrap() as usize;
                    (at, span_substr(cddl, span).to_string())
                })
                .collect()
        };
        // {1: 1, 2: 2} against two map bodies: `unexpected key 2` from the
        // first and `unexpected key 1` from the second both land on `$m`.
        let two_maps = "start = $m\n$m /= {1: uint}\n$m /= {3: uint}";
        let spans = unexpected_key_spans(two_maps, "start", "a201010202");
        assert_eq!(spans.len(), 2, "{:?}", spans);
        for (at, text) in &spans {
            assert_eq!((*at, text.as_str()), (8, "$m"), "{:?}", spans);
        }
        // Referenced from an array slot: the reference there.
        let in_array = "start = [$m]\n$m /= {1: uint}\n$m /= {3: uint}";
        for (at, text) in unexpected_key_spans(in_array, "start", "81a201010202") {
            assert_eq!((at, text.as_str()), (9, "$m"));
        }
        // One map among the bodies: that map.
        let one_map = "start = $m\n$m /= [* uint]\n$m /= {1: uint}";
        let spans = unexpected_key_spans(one_map, "start", "a201010202");
        assert!(!spans.is_empty());
        for (_, text) in &spans {
            assert_eq!(text, "{1: uint}", "{:?}", spans);
        }
        // One body: the map it writes out.
        let spans = unexpected_key_spans("start = $m\n$m /= {1: uint}", "start", "a201010202");
        assert_eq!(spans, vec![(17, "{1: uint}".to_string())]);
        // A socket at the root: written where it is first named, whether
        // the root is asked for as `cddl_outline` names it (`$m`) or by
        // its identifier alone.
        let root = "$m /= {1: uint}\n$m /= {3: uint}";
        for rule in ["$m", "m"] {
            let spans = unexpected_key_spans(root, rule, "a201010202");
            assert_eq!(spans.len(), 2, "{}: {:?}", rule, spans);
            for (at, text) in spans {
                assert_eq!((at, text.as_str()), (0, "$m"), "{}", rule);
            }
        }
        // {1: ["x"]}: the path descends through the second body, whose
        // array holds the text where a uint belongs.
        let descends = "start = $m\n$m /= uint\n$m /= {1: [uint]}";
        let mismatch = errors(descends, "start", "a1018161 78".replace(' ', "").as_str())
            .into_iter()
            .find(|e| e["path"] == json!("$[1][0]"))
            .expect("an error at $[1][0]");
        let span = &mismatch["cddl_byte_span"];
        assert_eq!(span_substr(descends, span), "uint");
        assert_eq!(span["offset"].as_u64(), Some(descends.rfind("uint").unwrap() as u64));
    }

    /// A path through a choice (`/`, a socket's bodies, an inline choice)
    /// goes on through the alternative whose container holds its next
    /// segment, not through the first container among the alternatives.
    #[test]
    fn a_span_walks_through_the_alternative_holding_the_next_segment() {
        let all_errors = |cddl: &str, hex: &str| -> Vec<Value> {
            let bytes = hex::decode(hex).unwrap();
            let result = validate_cbor_bytes_against_cddl(&bytes, cddl, "start");
            let head = error_obj(&result).clone();
            let mut all = vec![head.clone()];
            all.extend(head["additional"].as_array().cloned().unwrap_or_default());
            all
        };
        let span_at = |cddl: &str, hex: &str, path: &str, message: &str| -> (usize, String) {
            let errors = all_errors(cddl, hex);
            let e = errors
                .iter()
                .find(|e| {
                    e["path"] == json!(path) && e["message"].as_str().unwrap().starts_with(message)
                })
                .unwrap_or_else(|| panic!("no `{}` at {} in {:?}", message, path, errors));
            let span = &e["cddl_byte_span"];
            (
                span["offset"].as_u64().unwrap() as usize,
                span_substr(cddl, span).to_string(),
            )
        };
        // {3: {5: 1, 6: 2}} / {3: {5: "x"}}: the key 3 is b's, so both the
        // unexpected key 6 and the mismatch at 5 are in b's inner map.
        let extra_key = "a103a20501 0602".replace(' ', "");
        let wrong_value = "a103a1056178";
        for cddl in [
            "start = a / b\na = {1: uint}\nb = {3: {5: uint}}",
            "start = {1: uint} / {3: {5: uint}}",
            "start = $m\n$m /= {1: uint}\n$m /= {3: {5: uint}}",
            "start = $m\n$m /= {1: uint}\n$m /= [uint]\n$m /= {3: {5: uint}}",
            "start = a\na = {1: uint} / b\nb = {3: {5: uint}}",
        ] {
            let inner = cddl.find("{5: uint}").unwrap();
            assert_eq!(
                span_at(cddl, &extra_key, "$[3][6]", "unexpected key"),
                (inner, "{5: uint}".to_string()),
                "{}",
                cddl
            );
            assert_eq!(
                span_at(cddl, wrong_value, "$[3][5]", "expected"),
                (cddl.rfind("uint").unwrap(), "uint".to_string()),
                "{}",
                cddl
            );
        }
        // An array too short for the index is passed over: [1, ["x"]].
        let arrays = "start = [uint] / [uint, [uint]]";
        assert_eq!(
            span_at(arrays, "8201816178", "$[1][0]", "expected"),
            (arrays.rfind("uint").unwrap(), "uint".to_string())
        );
        // A map whose keys are a type may hold a key the literal keys of
        // another map do not: {"k": {5: "x"}} goes through the second.
        let typed = "start = {1: uint} / {* tstr => {5: uint}}";
        let (at, text) = span_at(typed, "a1616ba1056178", "$.k[5]", "expected");
        assert!(at >= typed.find("{*").unwrap(), "{} at {}", text, at);
    }

    /// An unexpected key names no member of the schema: its CDDL span is the
    /// map it sits in, written out (through the rules naming it), or the
    /// choice between maps when several could hold it, never a member
    /// reached through another alternative.
    #[test]
    fn unexpected_key_cddl_span_is_the_map_type() {
        let cddl_text = |cddl: &str, hex: &str| {
            let bytes = hex::decode(hex).unwrap();
            let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, cddl, "start")).clone();
            assert!(
                err["message"].as_str().unwrap().starts_with("unexpected key"),
                "{}",
                err
            );
            let span = &err["cddl_byte_span"];
            let at = span["offset"].as_u64().unwrap() as usize;
            let len = span["length"].as_u64().unwrap() as usize;
            cddl[at..at + len].to_string()
        };
        // {1: 1, 2: 2}: the one map among the alternatives.
        assert_eq!(
            cddl_text("start = [* uint] / {1: uint}", "a201010202"),
            "{1: uint}"
        );
        // Two maps could hold it: the choice.
        assert_eq!(
            cddl_text("start = {1: uint} / {3: uint}", "a201010202"),
            "{1: uint} / {3: uint}"
        );
        // A map named by a rule: the map as the rule writes it out.
        assert_eq!(cddl_text("start = x\nx = {1: uint}", "a201010202"), "{1: uint}");
        assert_eq!(
            cddl_text("start = [x]\nx = {1: uint}", "81a201010202"),
            "{1: uint}"
        );
        assert_eq!(
            cddl_text("start = [x]\nx = y\ny = (#6.30({1: uint}))", "81d81ea201010202"),
            "{1: uint}"
        );
        assert_eq!(
            cddl_text("start = [x]\nx = {1: uint} / {3: uint}", "81a201010202"),
            "{1: uint} / {3: uint}"
        );
        // Nested choices, written out or named.
        assert_eq!(
            cddl_text("start = [inner]\ninner = [* uint] / {1: uint}", "81a201010202"),
            "{1: uint}"
        );
        assert_eq!(
            cddl_text("start = [inner]\ninner = [* uint] / m\nm = {1: uint}", "81a201010202"),
            "{1: uint}"
        );
        assert_eq!(
            cddl_text("start = [[* uint] / {1: uint}]", "81a201010202"),
            "{1: uint}"
        );
        // The map form of Conway redeemers: an entry under a key no redeemer
        // key matches lands on the map form, not on the array form.
        const WITNESSES: &str = "
            start = { ? 5 : redeemers }
            redeemers = [ + redeemer ]
                      / { + [ tag : redeemer_tag, index : uint .size 4 ]
                          => [ data : int, ex_units : ex_units ] }
            redeemer = [ tag : redeemer_tag, index : uint .size 4, data : int, ex_units : ex_units ]
            redeemer_tag = 0 / 1 / 2 / 3 / 4 / 5
            ex_units = [mem : uint, steps : uint]
        ";
        // {5: {[0, 0]: [0, [1, 1]], [9, 0]: [0, [1, 1]]}}
        let doc = "a105a282000082008201018209008200820101";
        let bytes = hex::decode(doc).unwrap();
        let result = validate_cbor_bytes_against_cddl(&bytes, WITNESSES, "start");
        let err = error_obj(&result).clone();
        assert_eq!(err["message"], json!("unexpected key [9, 0]"), "{}", err);
        assert_eq!(
            cddl_text(WITNESSES, doc),
            "{ + [ tag : redeemer_tag, index : uint .size 4 ]
                          => [ data : int, ex_units : ex_units ] }"
        );
        // The ledger's shape: a transaction array naming its body and
        // witness set maps by rule. An unexpected key in each lands on the
        // map the rule writes out, not on the reference in `transaction`.
        const LEDGER_SHAPE: &str = "
            transaction = [transaction_body, transaction_witness_set, bool, any]
            transaction_body = { 0 : set<uint>, ? 2 : uint }
            transaction_witness_set = { ? 0 : [* uint], ? 5 : redeemers }
            set<a> = #6.258([* a]) / [* a]
            redeemers = [* uint] / { * uint => uint }
        ";
        // [{0: [1], 30: 0}, {9: 0}, true, null]
        let bytes = hex::decode("84a200810118 1e00a10900f5f6".replace(' ', "")).unwrap();
        let result = validate_cbor_bytes_against_cddl(&bytes, LEDGER_SHAPE, "transaction");
        let head = error_obj(&result);
        let errors: Vec<&Value> = std::iter::once(head)
            .chain(head["additional"].as_array().into_iter().flatten())
            .collect();
        for (path, map) in [
            ("$[0][30]", "{ 0 : set<uint>, ? 2 : uint }"),
            ("$[1][9]", "{ ? 0 : [* uint], ? 5 : redeemers }"),
        ] {
            let err = errors
                .iter()
                .find(|e| e["path"] == json!(path))
                .unwrap_or_else(|| panic!("no error at {}: {}", path, result));
            assert!(err["message"].as_str().unwrap().starts_with("unexpected key"), "{}", err);
            let span = &err["cddl_byte_span"];
            let at = span["offset"].as_u64().unwrap() as usize;
            let len = span["length"].as_u64().unwrap() as usize;
            assert_eq!(&LEDGER_SHAPE[at..at + len], map, "{}", err);
        }
        // An error at the value, not the key, still lands on the value type.
        let bytes = hex::decode("a1016178").unwrap();
        let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, "start = {1: uint}", "start")).clone();
        let span = &err["cddl_byte_span"];
        let at = span["offset"].as_u64().unwrap() as usize;
        assert_eq!(&"start = {1: uint}"[at..at + 4], "uint", "{}", err);
    }

    /// A member key written out as an array, map or tag type answers for
    /// every entry whose key it matches, up to its occurrence, as a named key
    /// type does.
    #[test]
    fn an_inline_composite_member_key_answers_for_every_entry() {
        let run = |cddl: &str, hex: &str| {
            validate_cbor_bytes_against_cddl(&hex::decode(hex).unwrap(), cddl, "start")
        };
        let valid = |cddl: &str, hex: &str| {
            let result = run(cddl, hex);
            assert_eq!(result["valid"], json!(true), "{} against {}: {}", hex, cddl, result);
        };
        // The head error and the ones after it, as `(path, message)`.
        let reported = |result: &Value| -> Vec<(String, String)> {
            let head = error_obj(result);
            std::iter::once(head)
                .chain(head["additional"].as_array().into_iter().flatten())
                .map(|e| {
                    (
                        e["path"].as_str().unwrap_or_default().to_string(),
                        e["message"].as_str().unwrap_or_default().to_string(),
                    )
                })
                .collect()
        };
        // The map form of Conway redeemers.
        const WITNESSES: &str = "
            start = { ? 5 : redeemers }
            redeemers = [ + redeemer ]
                      / { + [ tag : redeemer_tag, index : uint .size 4 ]
                          => [ data : int, ex_units : ex_units ] }
            redeemer = [ tag : redeemer_tag, index : uint .size 4, data : int, ex_units : ex_units ]
            redeemer_tag = 0 / 1 / 2 / 3 / 4 / 5
            ex_units = [mem : uint, steps : uint]
        ";
        // {5: {[0, 0]: [0, [1, 1]], [1, 0]: [0, [1, 1]]}}
        valid(WITNESSES, "a105a282000082008201018201008200820101");
        // {5: {[0, 0]: …, [1, 0]: …, [3, 2]: …}}
        valid(
            WITNESSES,
            "a105a3820000820082010182010082008201018203028200820101",
        );
        // {[0, 1]: 1, [0, 2]: 2}
        valid("start = {+ [uint, uint] => uint}", "a28200010182000202");
        valid(
            "start = {+ [tag: uint, index: uint] => [uint, uint]}",
            "a2820000820102820100820304",
        );
        // {24(1): 1, 24(2): 2}
        valid("start = {* #6.24(uint) => uint}", "a2d8180101d8180202");
        // {{1: 2}: 1, {3: 4}: 2}
        valid("start = {* {* uint => uint} => uint}", "a2a1010201a1030402");
        // {0: 1, [0, 1]: 1, [0, 2]: 2}
        valid(
            "start = {0: uint, * [uint, uint] => uint}",
            "a300018200010182000202",
        );

        // A bad value under a later entry is reported at that value, and no
        // key is refused. {5: {[0, 0]: [0, [1, 1]], [1, 0]: [0, [1, "x"]]}}
        let errors = reported(&run(
            WITNESSES,
            "a105a28200008200820101820100820082016178",
        ));
        assert!(
            errors.iter().any(|(path, message)| path == "$[5][[1, 0]][1][1]"
                && message.starts_with("expected type uint")),
            "{:?}",
            errors
        );
        assert!(
            errors.iter().all(|(_, message)| !message.starts_with("unexpected key")),
            "{:?}",
            errors
        );
        // The occurrence still bounds the entries: `?` admits one, `1*2` two.
        let errors = reported(&run("start = {? [uint, uint] => uint}", "a28200010182000202"));
        assert_eq!(errors, vec![("$[[0, 2]]".to_string(), "unexpected key [0, 2]".to_string())]);
        let errors = reported(&run(
            "start = {1*2 [uint, uint] => uint}",
            "a3820001018200020282000303",
        ));
        assert!(
            errors.iter().any(|(_, message)| message.contains("no more than 2 entries")),
            "{:?}",
            errors
        );
    }

    /// Keys that are hard to locate (indefinite-length strings, arrays
    /// and maps, `undefined`, text holding `"`) are located like any other,
    /// and an entry that cannot be found at all falls back to its map.
    #[test]
    fn entries_under_every_key_encoding_are_located() {
        let spans = |cddl: &str, hex: &str| {
            let bytes = hex::decode(hex).unwrap();
            let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, cddl, "start")).clone();
            (err["path"].clone(), err["byte_spans"].clone(), err["anchor_spans"].clone())
        };
        let map = "start = { 1: uint }";
        // (_ "a"): 1
        let (path, bs, anchors) = spans(map, "a17f6161ff01");
        assert_eq!(path, json!("$.a"));
        assert_eq!(bs, json!([{ "offset": 1, "length": 1 }, { "offset": 5, "length": 1 }]));
        assert_eq!(anchors, json!([{ "offset": 1, "length": 4 }, { "offset": 5, "length": 1 }]));
        // (_ h'01'): 1
        let (_, bs, _) = spans(map, "a15f4101ff01");
        assert_eq!(bs, json!([{ "offset": 1, "length": 1 }, { "offset": 5, "length": 1 }]));
        // undefined: 1
        let (path, bs, _) = spans(map, "a1f701");
        assert_eq!(path, json!("$.null"));
        assert_eq!(bs, json!([{ "offset": 1, "length": 1 }, { "offset": 2, "length": 1 }]));
        // [_ 1, 2]: 1 and {_ 1: 2}: 1
        let (path, bs, _) = spans(map, "a19f0102ff01");
        assert_eq!(path, json!("$[[1, 2]]"));
        assert_eq!(bs, json!([{ "offset": 1, "length": 1 }, { "offset": 5, "length": 1 }]));
        let (_, bs, _) = spans(map, "a1bf0102ff01");
        assert_eq!(bs, json!([{ "offset": 1, "length": 1 }, { "offset": 5, "length": 1 }]));
        // 121([_ 1]): 1, the usual Plutus constructor encoding.
        let (path, bs, _) = spans(map, "a1d8799f01ff01");
        assert_eq!(path, json!("$[121([1])]"));
        assert_eq!(bs, json!([{ "offset": 1, "length": 2 }, { "offset": 6, "length": 1 }]));
        // A bad value under such a key is located too.
        let (path, bs, _) = spans("start = { * [* uint] => uint }", "a19f01ff6178");
        assert_eq!(path, json!("$[[1]]"));
        assert_eq!(bs, json!([{ "offset": 4, "length": 2 }]));
        // {"a\"b": {1: 1, 2: 2}}: the text key holds a quote.
        let (path, bs, _) = spans("start = { * tstr => { 1: uint } }", "a163612262a201010202");
        assert_eq!(path, json!("$[\"a\\\"b\"][2]"));
        assert_eq!(bs, json!([{ "offset": 8, "length": 1 }, { "offset": 9, "length": 1 }]));
        // {"a/b": 1}: a `/` inside a text key separates nothing.
        let (path, _, _) = spans(map, "a163612f6201");
        assert_eq!(path, json!("$[\"a/b\"]"));
        // A key holding `"` then `/`, which the validator escapes: the path
        // names the key, and the entry is spanned (key, then value).
        for (key, path) in [
            ("x\"/", "$[\"x\\\"/\"]"),
            ("a\"/b", "$[\"a\\\"/b\"]"),
            ("\"a\"/", "$[\"\\\"a\\\"/\"]"),
            ("\"/", "$[\"\\\"/\"]"),
            ("a\nb", "$[\"a\nb\"]"),
        ] {
            let text = format!("{:02x}{}", 0x60 + key.len(), hex::encode(key));
            let value_at = 1 + text.len() / 2;
            // {key: "x"} against `{* tstr => uint}`: the value is wrong.
            let (p, bs, _) = spans("start = { * tstr => uint }", &format!("a1{text}6178"));
            assert_eq!(p, json!(path), "{:?}", key);
            assert_eq!(bs, json!([{ "offset": value_at, "length": 2 }]), "{:?}", key);
            // {key: {1: 1, 2: 2}}: an unexpected key under it.
            let (p, bs, _) = spans(
                "start = { * tstr => { 1: uint } }",
                &format!("a1{text}a201010202"),
            );
            assert_eq!(p, json!(format!("{path}[2]")), "{:?}", key);
            assert_eq!(
                bs,
                json!([{ "offset": value_at + 3, "length": 1 }, { "offset": value_at + 4, "length": 1 }]),
                "{:?}",
                key
            );
        }

        // {1: 1, <300-byte text>: 2}: the validator names the long key by
        // nothing (`...`, the integer key 1 holds position 1); it is the one
        // key that renders past the validator's bound, so the path writes it
        // out and the entry is spanned.
        let long_text = "a".repeat(300);
        let long = format!("79012c{}", "61".repeat(300));
        let (path, bs, _) = spans(map, &format!("a20101{long}02"));
        assert_eq!(path, json!(format!("$.{long_text}")));
        assert_eq!(bs, json!([{ "offset": 3, "length": 303 }, { "offset": 306, "length": 1 }]));
        // With a sibling text key `...` the path names the long key, not
        // that sibling. {1: 1, <300-byte text>: "x", "...": 5}
        let (path, bs, _) = spans(
            "start = { 1: uint, * tstr => uint }",
            &format!("a30101{long}6178632e2e2e05"),
        );
        assert_eq!(path, json!(format!("$.{long_text}")));
        assert_eq!(bs, json!([{ "offset": 306, "length": 2 }]));
        // Two keys past the bound: which one the validator left unnamed is
        // not known, so the component and the spans stay the map's.
        let other = format!("79012c{}", "62".repeat(300));
        let (path, bs, _) = spans(map, &format!("a30101{long}02{other}03"));
        assert_eq!(path, json!("$[...]"));
        assert_eq!(bs, json!([{ "offset": 0, "length": 1 }]));
        // {0: 1, <300-byte text>: 2}: by its position, 1, which the path
        // writes as the key itself, not as `[1]` (an integer key, or the
        // text key "1").
        let (path, bs, _) = spans("start = { 0: uint }", &format!("a20001{long}02"));
        assert_eq!(path, json!(format!("$.{long_text}")));
        assert_eq!(bs, json!([{ "offset": 3, "length": 303 }, { "offset": 306, "length": 1 }]));
        // {"1": 0, <300-byte text>: "x"}: the text key "1" is not named.
        let (path, bs, _) = spans(
            "start = { * tstr => uint }",
            &format!("a2613100{long}6178"),
        );
        assert_eq!(path, json!(format!("$.{long_text}")));
        assert_eq!(bs, json!([{ "offset": 307, "length": 2 }]));
        // A long byte string key the same way; one past the path's own bound
        // keeps the validator's positional component, the spans the entry.
        let long_bytes = format!("59012c{}", "ab".repeat(300));
        let (path, _, _) = spans("start = { 0: uint }", &format!("a20001{long_bytes}02"));
        assert_eq!(path, json!(format!("$.h'{}'", "ab".repeat(300))));
        let huge = format!("790800{}", "61".repeat(2048));
        let (path, bs, _) = spans("start = { 0: uint }", &format!("a20001{huge}02"));
        assert_eq!(path, json!("$[1]"));
        assert_eq!(bs, json!([{ "offset": 3, "length": 2051 }, { "offset": 2054, "length": 1 }]));
        // A composite key past the bound keeps its positional component.
        // {0: 1, [0, 1, …, 199]: 2}
        let composite: String = (0..200u32)
            .map(|i| if i < 24 { format!("{:02x}", i) } else { format!("18{:02x}", i) })
            .collect();
        let (path, _, _) = spans("start = { 0: uint }", &format!("a2000198c8{composite}02"));
        assert_eq!(path, json!("$[1]"));
    }

    /// Text keys that are not identifiers are written `["…"]`, `\` and `"`
    /// escaped, so a path reader cannot take them for nested keys, an index
    /// or an integer key.
    #[test]
    fn text_keys_that_are_not_identifiers_are_written_in_the_bracket_form() {
        let path_of = |key: &str| {
            // {key: "x"} against `{* tstr => uint}`: the value is wrong.
            let mut bytes = vec![0xa1, 0x60 + key.len() as u8];
            bytes.extend_from_slice(key.as_bytes());
            bytes.extend_from_slice(&[0x61, b'x']);
            let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, "start = { * tstr => uint }", "start")).clone();
            err["path"].as_str().unwrap().to_string()
        };
        assert_eq!(path_of("name"), "$.name");
        assert_eq!(path_of("_a-b9"), "$._a-b9");
        assert_eq!(path_of("a.b"), "$[\"a.b\"]");
        assert_eq!(path_of("v1.0"), "$[\"v1.0\"]");
        assert_eq!(path_of("[1]"), "$[\"[1]\"]");
        assert_eq!(path_of("1"), "$[\"1\"]");
        assert_eq!(path_of("a b"), "$[\"a b\"]");
        assert_eq!(path_of("a\"b"), "$[\"a\\\"b\"]");
        assert_eq!(path_of("a\\b"), "$[\"a\\\\b\"]");
        assert_eq!(path_of("é"), "$[\"é\"]");
        assert_eq!(path_of(""), "$[\"\"]");
        // A float key is written in the bracket form too.
        let bytes = hex::decode("a1f93e006178").unwrap();
        let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, "start = { * float => uint }", "start")).clone();
        assert_eq!(err["path"], json!("$[1.5]"), "{}", err);
    }

    /// The expected key of a missing entry is read only from the validator's
    /// own map reasons: data quoted in another reason may hold the same words.
    #[test]
    fn expected_is_not_read_from_the_data_a_reason_quotes() {
        let expected = |cddl: &str, text: &str| {
            let mut bytes = vec![0x78, text.len() as u8];
            bytes.extend_from_slice(text.as_bytes());
            let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, cddl, "start")).clone();
            err["expected"].clone()
        };
        assert_eq!(expected("start = uint", "user missing key: 42"), json!("uint"));
        assert_eq!(expected("start = uint", "requires entry with key of type x"), json!("uint"));
        assert_eq!(expected("start = uint", "map missing key: 7"), json!("uint"));
        // A text literal mismatch has no comma before `got`; the data it
        // quotes is not part of what was expected.
        assert_eq!(expected("start = \"foo\"", "sign in with key abc"), json!("value \"foo\""));
        assert_eq!(expected("start = \"a got b\"", "x got y"), json!("value \"a got b\""));
    }

    /// A missing entry has nothing in the document to point at, so the error
    /// stays on the map, and names the key it expected.
    #[test]
    fn missing_key_names_the_expected_key() {
        let bytes = hex::decode("a10200").unwrap();
        let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, "root = { 1: uint, 2: uint }", "root")).clone();
        assert_eq!(err["message"], json!("map missing key: 1"), "{}", err);
        assert_eq!(err["expected"], json!("1"), "{}", err);
        assert_eq!(err["path"], json!("$"), "{}", err);
        assert_eq!(err["byte_spans"], json!([{ "offset": 0, "length": 1 }]), "{}", err);

        let bytes = hex::decode("a0").unwrap();
        let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, "root = { \"name\": tstr }", "root")).clone();
        assert_eq!(err["expected"], json!("\"name\""), "{}", err);
        let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, "root = { tstr => int }", "root")).clone();
        assert_eq!(err["message"], json!("map requires entry with key of type tstr"), "{}", err);
        assert_eq!(err["expected"], json!("tstr"), "{}", err);
    }

    /// A composite map key is written in diagnostic notation inside the
    /// path's bracket form, and its entry gets spans like any other.
    #[test]
    fn composite_keys_are_located_and_written_in_diagnostic_notation() {
        // {1: 0, [2, h'0102']: 5}
        let bytes = hex::decode("a201008202420102 05".replace(' ', "")).unwrap();
        let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, "root = { 1: uint }", "root")).clone();
        assert_eq!(err["message"], json!("unexpected key [2, h'0102']"), "{}", err);
        assert_eq!(err["path"], json!("$[[2, h'0102']]"), "{}", err);
        assert_eq!(
            err["byte_spans"],
            json!([{ "offset": 3, "length": 1 }, { "offset": 8, "length": 1 }]),
            "{}",
            err
        );
        assert_eq!(
            err["anchor_spans"],
            json!([{ "offset": 3, "length": 5 }, { "offset": 8, "length": 1 }]),
            "{}",
            err
        );
        assert!(!err.to_string().contains("Integer("), "{}", err);

        // A value under a composite key: the path steps through the key and
        // the value is located.
        let bytes = hex::decode("a1a1010263616263").unwrap(); // {{1: 2}: "abc"}
        let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, "root = { {1: 2} => uint }", "root")).clone();
        assert_eq!(err["path"], json!("$[{1: 2}]"), "{}", err);
        assert_eq!(err["byte_spans"], json!([{ "offset": 4, "length": 4 }]), "{}", err);
        assert_eq!(err["message"], json!("expected type uint, got text \"abc\""), "{}", err);
    }

    /// An empty array held to a map or tag rule is a mismatch naming the
    /// rule's type, not a count of the array's items.
    #[test]
    fn empty_array_against_map_or_tag_is_a_mismatch() {
        let bytes = hex::decode("80").unwrap();
        for (schema, expected) in [
            ("root = { 1: uint }", "map { 1: uint }"),
            ("root = #6.24(bstr)", "tagged data #6.24(bstr)"),
            ("root = uint", "type uint"),
        ] {
            let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, schema, "root")).clone();
            assert_eq!(err["kind"], json!("mismatch"), "{}: {}", schema, err);
            // `expected` drops the `type` noun, as it does for every mismatch.
            assert_eq!(
                err["expected"],
                json!(expected.strip_prefix("type ").unwrap_or(expected)),
                "{}: {}",
                schema,
                err
            );
            assert_eq!(
                err["message"],
                json!(format!("expected {}, got array(0 items)", expected)),
                "{}: {}",
                schema,
                err
            );
            assert_eq!(err["byte_spans"], json!([{ "offset": 0, "length": 1 }]), "{}", err);
        }
    }

    #[test]
    fn cbor_entry_point_parse_error_carries_a_byte_span() {
        let schema = "a = [int";
        let err = error_obj(&validate_cbor_bytes_against_cddl(b"\x01", schema, "a")).clone();
        assert_eq!(err["kind"], json!("parse_error"));
        assert!(
            !err["message"].as_str().unwrap().contains("Position {"),
            "{}",
            err
        );
        let span = err
            .get("byte_span")
            .unwrap_or_else(|| panic!("no byte_span: {}", err));
        // Byte-for-byte the shape the schema-only entry point emits.
        let schema_only = error_obj(&validate_cddl_text(schema)).clone();
        assert_eq!(span, &schema_only["byte_span"]);
        assert_eq!(err["message"], schema_only["message"]);
    }

    #[test]
    fn cbor_entry_point_unresolved_reference_matches_the_schema_entry_point() {
        let schema = "a = [b, b]";
        let err = error_obj(&validate_cbor_bytes_against_cddl(b"\x01", schema, "a")).clone();
        assert_eq!(err["kind"], json!("unresolved_references"));
        assert_eq!(err, *error_obj(&validate_cddl_text(schema)));
        assert!(err["unresolved"].as_array().unwrap().len() >= 1, "{}", err);
    }

    #[test]
    fn additional_is_deduplicated_by_path_and_cddl_span() {
        // {4:[null]} — one bad field, one failing alt per datum shape.
        let bytes = hex::decode("a10481f6").unwrap();
        let result = validate_cbor_bytes_against_cddl(&bytes, load_ledger_cddl(), "record_witness");
        let err = error_obj(&result);
        let entries = all_entries(err);
        assert!(
            entries.len() <= 4,
            "{} entries survived the fold",
            entries.len()
        );
        // `datum` has fourteen leaf alternatives (eight constructors, map, list,
        // three integer forms, bytes); each fails `null` at the same node, so
        // one entry carries them all.
        assert!(
            entries
                .iter()
                .any(|e| e["occurrences"].as_u64().unwrap_or(0) == 14),
            "no entry recorded the collapsed count: {:?}",
            entries
        );
        // Each surviving entry describes a distinct failing node.
        let mut keys: Vec<String> = entries
            .iter()
            .map(|e| format!("{}|{}|{}", e["path"], e["cddl_byte_span"], e["kind"]))
            .collect();
        keys.sort();
        let before = keys.len();
        keys.dedup();
        assert_eq!(keys.len(), before, "duplicate entries left after folding");
    }

    #[test]
    fn distinct_failures_are_not_merged_by_the_fold() {
        // Three different nodes fail: folding must leave all three.
        let bytes = hex::decode("83010203").unwrap();
        let result =
            validate_cbor_bytes_against_cddl(&bytes, "thing = [tstr, tstr, tstr]", "thing");
        let err = error_obj(&result);
        let entries = all_entries(err);
        assert_eq!(entries.len(), 3, "{:?}", entries);
        let mut paths: Vec<&str> = entries
            .iter()
            .map(|e| e["path"].as_str().unwrap())
            .collect();
        paths.sort();
        assert_eq!(paths, vec!["$[0]", "$[1]", "$[2]"]);
        for e in &entries {
            assert!(e.get("occurrences").is_none(), "{}", e);
            assert!(e.get("alternatives").is_none(), "{}", e);
        }
        assert!(err.get("additional_truncated").is_none(), "{}", err);
    }

    /// Deep recursive refusals: map head-first until [`MAX_MAPPED_LOCATION_SEGMENTS`];
    /// unreached errors counted as dropped, with spans on those mapped.
    #[test]
    fn deep_errors_are_mapped_until_the_segment_budget_is_spent() {
        let levels = 3000;
        let mut hex_bytes = "81".repeat(levels);
        hex_bytes.push_str("60");
        let bytes = hex::decode(hex_bytes).unwrap();
        let result = validate_cbor_bytes_against_cddl(&bytes, "x = [* x] / uint", "x");
        let err = error_obj(&result);
        assert_eq!(err["kind"], json!("mismatch"), "{}", err["kind"]);
        assert_eq!(err["path"], json!(format!("${}", "[0]".repeat(levels))));
        assert!(err["byte_spans"].is_array() && err["cddl_byte_span"].is_object());

        let additional = err["additional"].as_array().unwrap();
        // Budget bounds how many are mapped, not span quality.
        assert!(additional
            .iter()
            .all(|e| e["byte_spans"].is_array() && e["cddl_byte_span"].is_object()));
        // Segment budget binds before the count cap; deepest locations preferred.
        let mapped = 1 + additional.len();
        assert!(
            mapped < super::MAX_ADDITIONAL + 1
                && mapped <= super::MAX_MAPPED_LOCATION_SEGMENTS / (levels - mapped) + 1,
            "{} mapped, truncated {}",
            mapped,
            err["additional_truncated"]
        );
        assert!(additional.iter().all(|e| {
            e["path"].as_str().map_or(0, |p| p.matches("[0]").count()) >= levels - mapped
        }));
        // Unmapped errors are counted, not silently dropped.
        assert!(
            err["additional_truncated"].as_u64().unwrap_or(0) >= 10 * mapped as u64,
            "{}",
            err["additional_truncated"]
        );
    }

    #[test]
    fn additional_is_capped_with_a_truncation_count() {
        let bytes = hex::decode(uint_array_hex(1000)).unwrap();
        let result = validate_cbor_bytes_against_cddl(&bytes, "root = [* tstr]", "root");
        let err = error_obj(&result);
        let additional = err["additional"].as_array().unwrap();
        assert!(additional.len() <= 200, "{} entries", additional.len());
        assert!(
            err["additional_truncated"].as_u64().unwrap_or(0) >= 799,
            "{}",
            err["additional_truncated"]
        );
    }

    #[test]
    fn head_error_is_the_deepest_failure_whatever_the_choice_order() {
        // ["a",["b","c"]] vs choice whose 2nd alt fails two levels down.
        let bytes = hex::decode("8261618261626163").unwrap();
        for cddl in [
            "root = alt_a / alt_b\nalt_a = uint\nalt_b = [tstr, [tstr, uint]]\n",
            "root = alt_b / alt_a\nalt_a = uint\nalt_b = [tstr, [tstr, uint]]\n",
        ] {
            let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, cddl, "root")).clone();
            assert_eq!(
                err["path"],
                json!("$[1][1]"),
                "schema {:?} gave {}",
                cddl,
                err
            );
            assert_eq!(cddl_span_text(cddl, &err), "uint");
            // The shallow alternative is still reported, just not first.
            assert!(
                all_entries(&err).iter().any(|e| e["path"] == json!("$")),
                "{}",
                err
            );
        }
    }

    #[test]
    fn head_error_for_a_map_form_output_points_at_the_datum() {
        // {0:addr,1:10,2:[0,"bogus"]} — datum hash must be 32-byte.
        let cbor_hex = format!("a300581de0{}010a02820065626f677573", "11".repeat(28));
        let bytes = hex::decode(&cbor_hex).unwrap();
        let cddl = load_ledger_cddl();
        let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, cddl, "entry")).clone();
        assert_eq!(err["path"], json!("$[2][1]"), "{}", err);
        let line = err["cddl_byte_span"]["line"].as_u64().unwrap() as usize;
        let line_text = cddl.lines().nth(line - 1).unwrap();
        assert!(
            line_text.contains("hash32"),
            "head span points at line {} ({:?}), not the hash rule",
            line,
            line_text
        );
    }

    // ============================================================
    // CDDL span: line numbers, element slots, trailing whitespace
    // ============================================================

    #[test]
    fn cddl_byte_span_line_matches_the_offset_on_the_wrapper_path() {
        // Non-first rule + leading trivia: span lines/offsets must stay correct.
        let cases = [
            "root = tstr\nnum = uint\n",
            "; c1\n; c2\n\nroot = tstr\n\n\nnum = uint\n",
            "root = tstr\nnum = uint",
            "; head\nroot = tstr\nmid = bool\n\n\n\nnum = uint\n",
            "root = tstr\n\nnum = uint\n\n; trailer\n",
        ];
        let bytes = hex::decode("6161").unwrap();
        for cddl in cases {
            let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, cddl, "num")).clone();
            let span = &err["cddl_byte_span"];
            let off = span["offset"].as_u64().unwrap() as usize;
            assert_eq!(
                span["line"].as_u64().unwrap() as usize,
                cddl[..off].matches('\n').count() + 1,
                "schema {:?} gave {}",
                cddl,
                err
            );
            assert_eq!(span_substr(cddl, span), "uint", "schema {:?}", cddl);
        }
    }

    #[test]
    fn cddl_byte_span_line_matches_the_offset_without_a_wrapper() {
        let cases = [
            "root = tstr\n",
            "; c\n\nroot = tstr\n",
            "root = tstr",
            "\n\n\nroot = tstr\nother = uint\n",
        ];
        let bytes = hex::decode("01").unwrap();
        for cddl in cases {
            let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, cddl, "root")).clone();
            let span = &err["cddl_byte_span"];
            let off = span["offset"].as_u64().unwrap() as usize;
            assert_eq!(
                span["line"].as_u64().unwrap() as usize,
                cddl[..off].matches('\n').count() + 1,
                "schema {:?} gave {}",
                cddl,
                err
            );
            assert_eq!(span_substr(cddl, span), "tstr", "schema {:?}", cddl);
        }
    }

    #[test]
    fn homogeneous_array_element_span_points_at_the_element_type() {
        // ["a","a",1] — 3rd elem fails; schema declares element type once.
        let bytes = hex::decode("836161616101").unwrap();
        let cddl = "root = [* tstr]";
        let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, cddl, "root")).clone();
        assert_eq!(err["path"], json!("$[2]"), "{}", err);
        assert_eq!(cddl_span_text(cddl, &err), "tstr");
    }

    #[test]
    fn homogeneous_array_of_a_named_rule_resolves_into_the_element_rule() {
        let cddl = format!(
            "root = [* ref]\n\n{}",
            crate::cbor::test_fixtures::ledger_cddl()
        );
        // [valid, [null, 10]] — second hash is null.
        let bytes = hex::decode(
            "8282582000112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0082f60a",
        )
        .unwrap();
        let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, &cddl, "root")).clone();
        assert_eq!(err["path"], json!("$[1][0]"), "{}", err);
        let line = err["cddl_byte_span"]["line"].as_u64().unwrap() as usize;
        let line_text = cddl.lines().nth(line - 1).unwrap();
        assert!(
            line_text.starts_with("ref ="),
            "span landed on line {} ({:?}), not the element rule",
            line,
            line_text
        );
    }

    #[test]
    fn inline_group_array_slot_gets_its_own_span() {
        // [1,2,3] — inline group fills 0..1; slot 2 is `tstr`.
        let bytes = hex::decode("83010203").unwrap();
        let cddl = "root = [(a: uint, b: uint), tstr]";
        let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, cddl, "root")).clone();
        assert_eq!(err["path"], json!("$[2]"), "{}", err);
        assert_eq!(cddl_span_text(cddl, &err), "tstr");
    }

    #[test]
    fn group_rule_reference_in_an_array_is_spliced_for_the_span_lookup() {
        let bytes = hex::decode("83010203").unwrap();
        let cddl = "root = [g, tstr]\ng = (uint, uint)\n";
        let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, cddl, "root")).clone();
        assert_eq!(err["path"], json!("$[2]"), "{}", err);
        assert_eq!(cddl_span_text(cddl, &err), "tstr");
    }

    #[test]
    fn array_slot_after_an_optional_entry_resolves() {
        // [1,"x",1] — optional present; slot 2 must be `bstr`.
        let bytes = hex::decode("8301617801").unwrap();
        let cddl = "root = [uint, ? tstr, bstr]";
        let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, cddl, "root")).clone();
        assert_eq!(err["path"], json!("$[2]"), "{}", err);
        assert_eq!(cddl_span_text(cddl, &err), "bstr");
    }

    #[test]
    fn ambiguous_array_slot_falls_back_to_the_container_span() {
        // [1,2] — slot 1 ambiguous (optional tstr vs bstr); do not claim certainty.
        let bytes = hex::decode("820102").unwrap();
        let cddl = "root = [uint, ? tstr, bstr]";
        let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, cddl, "root")).clone();
        assert_eq!(err["path"], json!("$[1]"), "{}", err);
        assert_eq!(cddl_span_text(cddl, &err), "[uint, ? tstr, bstr]");
    }

    #[test]
    fn cddl_byte_span_never_includes_trailing_whitespace() {
        struct Case<'a> {
            cddl: &'a str,
            rule: &'a str,
            cbor_hex: &'a str,
        }
        let cases = [
            Case {
                cddl: "thing = uint\n",
                rule: "thing",
                cbor_hex: "6161",
            },
            Case {
                cddl: "thing = [bool, tstr]\n\n",
                rule: "thing",
                cbor_hex: "820101",
            },
            Case {
                cddl: "thing = {a: bytes}\n",
                rule: "thing",
                cbor_hex: "a161616163",
            },
            Case {
                cddl: "root = tstr\nnum = uint\n",
                rule: "num",
                cbor_hex: "6161",
            },
            Case {
                cddl: "root = tstr\npair = [tstr, tstr]\n",
                rule: "pair",
                cbor_hex: "820101",
            },
            Case {
                cddl: "thing = [* tstr]  \n",
                rule: "thing",
                cbor_hex: "8101",
            },
            Case {
                cddl: "; lead\n\nthing = {a: [bool]}\n\n\n",
                rule: "thing",
                cbor_hex: "a16161810b",
            },
        ];
        for c in cases {
            let bytes = hex::decode(c.cbor_hex).unwrap();
            let result = validate_cbor_bytes_against_cddl(&bytes, c.cddl, c.rule);
            let err = error_obj(&result);
            for entry in all_entries(err) {
                let Some(span) = entry.get("cddl_byte_span") else {
                    continue;
                };
                let text = span_substr(c.cddl, span);
                assert_eq!(text, text.trim_end(), "schema {:?} span {}", c.cddl, span);
                assert!(
                    span["length"].as_u64().unwrap() > 0,
                    "schema {:?} span {}",
                    c.cddl,
                    span
                );
            }
        }
    }

    #[test]
    fn every_emitted_cddl_span_is_a_substring_of_the_user_schema() {
        struct Case<'a> {
            cddl: &'a str,
            rule: &'a str,
            cbor_hex: &'a str,
        }
        let cases = [
            Case {
                cddl: "thing = uint",
                rule: "thing",
                cbor_hex: "6161",
            },
            Case {
                cddl: "thing = [bool, tstr]",
                rule: "thing",
                cbor_hex: "820101",
            },
            Case {
                cddl: "a = uint\nb = [tstr, tstr]\n",
                rule: "b",
                cbor_hex: "820101",
            },
            Case {
                cddl: "root = int\nchoice = uint / [tstr]\n",
                rule: "choice",
                cbor_hex: "8101",
            },
            Case {
                cddl: "first = uint\nwrap<v> = {a: v}\nuses = wrap<int>\n",
                rule: "uses",
                cbor_hex: "a161616163",
            },
            Case {
                cddl: "head = tstr\nnested = {0: [* inner]}\ninner = [uint, tstr]\n",
                rule: "nested",
                cbor_hex: "a10081820102",
            },
        ];
        for c in cases {
            let bytes = hex::decode(c.cbor_hex).unwrap();
            let result = validate_cbor_bytes_against_cddl(&bytes, c.cddl, c.rule);
            let err = error_obj(&result);
            for entry in all_entries(err) {
                let Some(span) = entry.get("cddl_byte_span") else {
                    continue;
                };
                let off = span["offset"].as_u64().unwrap() as usize;
                let len = span["length"].as_u64().unwrap() as usize;
                assert!(
                    off + len <= c.cddl.len(),
                    "schema {:?}: span {} runs past the source",
                    c.cddl,
                    span
                );
                let text = span_substr(c.cddl, span);
                assert!(!text.is_empty(), "schema {:?}: empty span", c.cddl);
                assert!(c.cddl.contains(text));
            }
        }
    }

    // ============================================================
    // CBOR-side spans: parse failures and embedded payloads
    // ============================================================

    #[test]
    fn cbor_parse_error_carries_a_byte_span() {
        for hex_str in ["82", "5f", "a1", "6241", "bf0102"] {
            let bytes = hex::decode(hex_str).unwrap();
            let result = validate_cbor_bytes_against_cddl(&bytes, "root = any", "root");
            let err = error_obj(&result);
            assert_eq!(err["kind"], json!("input_parse"), "{}", err);
            let span = &err["byte_spans"][0];
            let off = span["offset"].as_u64().unwrap() as usize;
            let len = span["length"].as_u64().unwrap() as usize;
            assert!(len >= 1, "{} gave {}", hex_str, err);
            assert!(
                off + len <= bytes.len(),
                "{} gave a span outside the input: {}",
                hex_str,
                err
            );
        }
    }

    #[test]
    fn cbor_parse_error_keeps_a_span_the_decoder_pinpointed() {
        // Trailing-data range must not become a one-byte cursor mark.
        let bytes = hex::decode("83010203040506").unwrap();
        let result = validate_cbor_bytes_against_cddl(&bytes, "root = any", "root");
        let err = error_obj(&result);
        assert_eq!(err["byte_spans"][0]["offset"], json!(4), "{}", err);
        assert_eq!(err["byte_spans"][0]["length"], json!(3), "{}", err);
    }

    const EMBEDDED_CDDL: &str =
        "root = {0: tstr, 1: payload}\npayload = bytes .cbor inner\ninner = [tstr, {k: uint}]";

    #[test]
    fn embedded_cbor_error_byte_span_lands_inside_the_payload() {
        // Embedded map key `k` holds "z" where uint expected.
        let bytes = hex::decode("a2006268690148826161a1616b617a").unwrap();
        let result = validate_cbor_bytes_against_cddl(&bytes, EMBEDDED_CDDL, "root");
        let err = error_obj(&result);
        assert_eq!(err["embedded_span"], json!(true), "{}", err);
        let span = &err["byte_spans"][0];
        let off = span["offset"].as_u64().unwrap() as usize;
        let len = span["length"].as_u64().unwrap() as usize;
        // The byte string's content runs from offset 7 to the end.
        assert!(off >= 7 && off + len <= bytes.len(), "{}", err);
        assert_eq!(hex::encode(&bytes[off..off + len]), "617a", "{}", err);
    }

    #[test]
    fn embedded_cborseq_error_byte_span_lands_inside_the_payload() {
        // h'0102' as a CBOR sequence of two uints, wanted as two tstrs.
        let bytes = hex::decode("420102").unwrap();
        let cddl = "root = bytes .cborseq inner\ninner = [tstr, tstr]";
        let result = validate_cbor_bytes_against_cddl(&bytes, cddl, "root");
        let err = error_obj(&result);
        let entries = all_entries(err);
        assert_eq!(entries.len(), 2, "{:?}", entries);
        for (i, entry) in entries.iter().enumerate() {
            assert_eq!(entry["embedded_span"], json!(true), "{}", entry);
            let span = &entry["byte_spans"][0];
            let off = span["offset"].as_u64().unwrap() as usize;
            let len = span["length"].as_u64().unwrap() as usize;
            // Payload content starts at offset 1; item i is one byte.
            assert_eq!(off, 1 + i, "{}", entry);
            assert!(off + len <= bytes.len(), "{}", entry);
        }
    }

    /// Chain of `levels` `.cbor` arrays around `["a"]` vs uint; mismatch at depth.
    /// Payload of level `n` starts at byte `2n+1`.
    fn payload_chain(levels: usize) -> (String, Vec<u8>) {
        let mut cddl = String::from("a0 = [uint]\n");
        for level in 1..=levels {
            cddl.push_str(&format!("a{} = [bstr .cbor a{}]\n", level, level - 1));
        }
        let mut bytes = vec![0x81, 0x61, 0x61];
        for _ in 0..levels {
            let mut outer = vec![0x81, 0x58, bytes.len() as u8];
            outer.extend(bytes);
            bytes = outer;
        }
        (cddl, bytes)
    }

    /// Spans follow mismatches through every payload depth the validator walks.
    #[test]
    fn embedded_spans_follow_a_mismatch_through_every_payload_the_validator_walks() {
        let bound = limits::MAX_EMBEDDED_DEPTH;
        for levels in 1..=bound {
            let (cddl, bytes) = payload_chain(levels);
            let result = validate_cbor_bytes_against_cddl(&bytes, &cddl, &format!("a{}", levels));
            let err = error_obj(&result);
            assert_eq!(
                err["kind"],
                json!("mismatch"),
                "{} payloads: {}",
                levels,
                err
            );
            assert_eq!(
                err["path"],
                json!(format!("${}", "[0]".repeat(levels + 1))),
                "{} payloads: {}",
                levels,
                err
            );
            assert_eq!(
                err["embedded_span"],
                json!(true),
                "{} payloads: {}",
                levels,
                err
            );
            let span = &err["byte_spans"][0];
            let off = span["offset"].as_u64().unwrap() as usize;
            let len = span["length"].as_u64().unwrap() as usize;
            assert_eq!(
                (off, len),
                (3 * levels + 1, 2),
                "{} payloads: {}",
                levels,
                err
            );
            assert_eq!(
                &bytes[off..off + len],
                b"\x61\x61",
                "{} payloads: {}",
                levels,
                err
            );
        }

        let (cddl, bytes) = payload_chain(bound + 1);
        let result = validate_cbor_bytes_against_cddl(&bytes, &cddl, &format!("a{}", bound + 1));
        assert_eq!(
            error_obj(&result)["kind"],
            json!("nesting_too_deep"),
            "{}",
            result
        );
    }

    #[test]
    fn embedded_span_is_omitted_for_indefinite_byte_strings() {
        // Indefinite chunked payload — no linear offset rebase; omit spans.
        let bytes = hex::decode("a200626869015f48826161a1616b617aff").unwrap();
        let result = validate_cbor_bytes_against_cddl(&bytes, EMBEDDED_CDDL, "root");
        let err = error_obj(&result);
        assert_eq!(err["path"], json!("$[1][1].k"), "{}", err);
        assert!(err.get("byte_spans").is_none(), "{}", err);
        assert!(err.get("anchor_spans").is_none(), "{}", err);
        assert!(err.get("embedded_span").is_none(), "{}", err);
    }

    #[test]
    fn every_emitted_cbor_span_lies_inside_the_input() {
        struct Case<'a> {
            cddl: &'a str,
            rule: &'a str,
            cbor_hex: &'a str,
        }
        let doc = crate::cbor::test_fixtures::RECORD_DOC_HEX.as_str();
        let mut cases: Vec<Case> = vec![
            Case {
                cddl: "root = tstr",
                rule: "root",
                cbor_hex: doc,
            },
            Case {
                cddl: "root = [* tstr]",
                rule: "root",
                cbor_hex: "836161616101",
            },
            Case {
                cddl: "root = {a: uint}",
                rule: "root",
                cbor_hex: "a161616163",
            },
            Case {
                cddl: "root = [uint, ? tstr, bstr]",
                rule: "root",
                cbor_hex: "820102",
            },
            Case {
                cddl: EMBEDDED_CDDL,
                rule: "root",
                cbor_hex: "a2006268690148826161a1616b617a",
            },
            Case {
                cddl: "root = bytes .cborseq inner\ninner = [tstr, tstr]",
                rule: "root",
                cbor_hex: "420102",
            },
            Case {
                cddl: "root = #6.24(tstr)",
                rule: "root",
                cbor_hex: "d8184482010203",
            },
            Case {
                cddl: load_ledger_cddl(),
                rule: "datum",
                cbor_hex: doc,
            },
        ];
        for (_, version) in crate::cbor::test_fixtures::schema_suite() {
            cases.push(Case {
                cddl: version,
                rule: "record",
                cbor_hex: "81f6",
            });
        }
        for c in cases {
            let Ok(bytes) = hex::decode(c.cbor_hex) else {
                continue;
            };
            let result = validate_cbor_bytes_against_cddl(&bytes, c.cddl, c.rule);
            if result["valid"] == json!(true) {
                continue;
            }
            for entry in all_entries(&result["error"]) {
                for field in ["byte_spans", "anchor_spans"] {
                    for span in entry
                        .get(field)
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        let off = span["offset"].as_u64().unwrap() as usize;
                        let len = span["length"].as_u64().unwrap() as usize;
                        assert!(
                            off + len <= bytes.len(),
                            "rule {} {}: span {} outside a {}-byte input",
                            c.rule,
                            field,
                            span,
                            bytes.len()
                        );
                    }
                }
            }
        }
    }

    // ============================================================
    // Upstream behaviour pinned here
    // ============================================================

    #[test]
    fn type_choice_with_a_single_map_alternative_rejects_a_bad_map_value() {
        // Control: map alternative alone rejects this data.
        let bytes = hex::decode("826178a161616179").unwrap();
        let result = validate_cbor_bytes_against_cddl(&bytes, "root = [tstr, {a: uint}]", "root");
        assert_eq!(result["valid"], json!(false), "{}", result);
    }

    #[test]
    fn type_choice_with_a_map_alternative_rejects_data_no_alternative_accepts() {
        // Choice discards map-entry errors when retrying alternatives → false valid.
        let bytes = hex::decode("826178a161616179").unwrap();
        let result = validate_cbor_bytes_against_cddl(
            &bytes,
            "root = [tstr, tstr] / [tstr, {a: uint}]",
            "root",
        );
        assert_eq!(result["valid"], json!(false), "{}", result);
    }

    // ============================================================
    // Helper units
    // ============================================================

    #[test]
    fn parser_position_prefix_is_stripped_only_when_present() {
        assert_eq!(
            super::strip_parser_position(
                "parsing error: position Position { line: 3 }, msg: expected one of: x"
            ),
            "expected one of: x"
        );
        assert_eq!(
            super::strip_parser_position("parsing error: msg: missing definition for rule b"),
            "missing definition for rule b"
        );
        // Anything else is passed through untouched.
        assert_eq!(
            super::strip_parser_position("plain message"),
            "plain message"
        );
        assert_eq!(
            super::strip_parser_position("lexer error: position 3"),
            "lexer error: position 3"
        );
    }

    #[test]
    fn debug_dumps_are_collapsed_but_plain_text_is_not() {
        assert_eq!(
            super::collapse_debug_structs(
                "expected tagged data TaggedData { tag: Some(Literal(121)), t: Type { x: 1 } }",
                None
            ),
            "expected tagged data #6.121(…)"
        );
        assert_eq!(
            super::collapse_debug_structs("expected value .size ([1, 2, 3]), got 4", None),
            "expected value .size ([1, 2, 3]), got 4"
        );
        assert_eq!(
            super::collapse_debug_structs("got [1, 2, 3, 4, 5]", None),
            "got [… 5 items]"
        );
        assert_eq!(
            super::collapse_debug_structs("expected type uint, got Text(\"c\")", None),
            "expected type uint, got text \"c\""
        );
        // Prose that merely mentions a type name is left alone.
        assert_eq!(
            super::collapse_debug_structs("expected type uint, got a negative value", None),
            "expected type uint, got a negative value"
        );
    }

    /// Messages describe values, never Rust `Debug` type names.
    #[test]
    fn every_data_item_shape_is_rendered_short() {
        for (debug, short) in [
            ("Integer(Integer(-178130))", "-178130"),
            ("Integer(Integer(0))", "0"),
            ("Integer(-2)", "-2"),
            ("Float(1.5)", "1.5"),
            ("Float(inf)", "inf"),
            ("Bool(true)", "true"),
            ("Null", "null"),
            ("Simple(32)", "simple(32)"),
            ("Text(\"abc\")", "text \"abc\""),
            ("Bytes([])", "bytes 0x (0 bytes)"),
            ("Bytes([1, 2, 255])", "bytes 0x0102ff (3 bytes)"),
            ("Array([])", "array(0 items)"),
            ("Array([Bytes([0])])", "array(1 items)"),
            (
                "Map([(Text(\"a\"), Integer(Integer(1)))])",
                "map(1 entries)",
            ),
            ("Tag(121, Map([]))", "#6.121(map(0 entries))"),
            ("Tag(2, Bytes([1, 0]))", "#6.2(bytes 0x0100 (2 bytes))"),
            // How the renderer marks a level it stopped descending at.
            ("Array(...)", "array(…)"),
            ("Map(...)", "map(…)"),
            ("Tag(121, ...)", "#6.121(…)"),
            // A rendering the length bound cut mid-item.
            ("Array([Integer(Integer(1)), Integer(Inte", "array(…)"),
        ] {
            assert_eq!(
                super::collapse_debug_structs(&format!("got {}", debug), None),
                format!("got {}", short),
                "rendering {}",
                debug
            );
        }
    }

    /// Elided stand-in names kind only; distinct from a length-truncated value.
    #[test]
    fn a_stand_in_for_an_unread_body_is_recognised() {
        for tail in [
            "bytes(…)",
            "array(…)",
            "map(…)",
            "tag(…)",
            "#6.121(…)",
            "#6.121(array(…))",
            "#6.139(#6.138(…))",
        ] {
            assert!(super::lost_data_item(tail), "not detected: {}", tail);
        }
        for tail in [
            "bytes 0xabab… (48 bytes)",
            "text \"zzzz…\"",
            "array(500 items)",
            "map(20 entries)",
            "#6.121(array(50 items))",
            "-178130",
            "null",
        ] {
            assert!(!super::lost_data_item(tail), "wrongly detected: {}", tail);
        }
    }

    /// Upstream length-truncated renderings → message from located node (len/count/tag).
    #[test]
    fn a_rendering_cut_short_by_the_length_bound_is_replaced_by_the_node() {
        // Each of these renders past the bound the validator writes under.
        for (name, cbor_hex, want) in [
            (
                "32-byte hash",
                format!("5820{}", "ab".repeat(32)),
                "bytes 0xabababababababababababababababa… (32 bytes)",
            ),
            (
                "64-byte hash",
                format!("5840{}", "ab".repeat(64)),
                "bytes 0xabababababababababababababababa… (64 bytes)",
            ),
            (
                "long text",
                format!("7818{}", "7a".repeat(24)),
                "text \"zzzzzzzzzzzzzzzzzzzzzzzz\"",
            ),
            (
                // 0x9828: an array of 40 items.
                "wide array",
                format!("9828{}", "01".repeat(40)),
                "array(40 items)",
            ),
            (
                // 0xb828: a map of 40 entries, each `<uint key> 01`.
                "wide map",
                format!(
                    "b828{}",
                    (0..40)
                        .map(|k| format!("18{:02x}01", k))
                        .collect::<String>()
                ),
                "map(40 entries)",
            ),
            (
                // 0xd879: tag 121, the first constructor tag.
                "constructor over a wide array",
                format!("d8799828{}", "01".repeat(40)),
                "#6.121(array(40 items))",
            ),
            (
                "constructor over a hash",
                format!("d8795840{}", "ab".repeat(64)),
                "#6.121(bytes 0xabababababababababababababababa… (64 bytes))",
            ),
        ] {
            let bytes = hex::decode(&cbor_hex).unwrap();
            let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, "x = uint", "x")).clone();
            assert_eq!(
                err["message"],
                json!(format!("expected type uint, got {}", want)),
                "{}",
                name
            );
        }
    }

    /// Indefinite containers described as such; `Break` is a terminator.
    #[test]
    fn an_indefinite_container_is_named_as_one_and_its_break_is_not_counted() {
        for (cbor_hex, want) in [
            (
                format!("9f{}ff", "01".repeat(200)),
                "indefinite array(200 items)",
            ),
            (
                format!("bf{}ff", "0101".repeat(100)),
                "indefinite map(100 entries)",
            ),
            (
                format!("5f{}ff", "41ab".repeat(200)),
                "indefinite bytes(200 chunks)",
            ),
            (
                format!("7f{}ff", "647a7a7a7a".repeat(200)),
                "indefinite text(200 chunks)",
            ),
        ] {
            let bytes = hex::decode(&cbor_hex).unwrap();
            let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, "x = uint", "x")).clone();
            assert_eq!(
                err["message"],
                json!(format!("expected type uint, got {}", want)),
                "{}",
                err
            );
        }
    }

    /// Tag chains named by head tags; failure is the outermost item.
    #[test]
    fn a_chain_of_tags_is_named_by_its_tags() {
        // 40 tags around the integer 1.
        let mut bytes = vec![0x01];
        for tag in 100u8..140 {
            let mut wrapped = vec![0xd8, tag];
            wrapped.extend_from_slice(&bytes);
            bytes = wrapped;
        }
        let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, "x = uint", "x")).clone();
        assert_eq!(
            err["message"],
            json!("expected type uint, got #6.139(#6.138(#6.137(#6.136(#6.135(…)))))"),
            "{}",
            err
        );
        // Spans match the message: outermost tag header + whole chain.
        assert_eq!(err["byte_spans"], json!([{ "offset": 0, "length": 2 }]));
        assert_eq!(
            err["anchor_spans"],
            json!([{ "offset": 0, "length": bytes.len() }])
        );
    }

    /// Tagged path: message and spans follow the item the reason named.
    #[test]
    fn a_failure_inside_a_tag_reports_the_content_and_one_on_it_reports_the_tag() {
        // #6.2(3): schema asks for tag → reject content.
        let err = error_obj(&validate_cbor_bytes_against_cddl(
            &hex::decode("c203").unwrap(),
            "x = #6.2(bstr)",
            "x",
        ))
        .clone();
        assert_eq!(
            err["message"],
            json!("expected type bstr, got 3"),
            "{}",
            err
        );
        assert_eq!(err["byte_spans"], json!([{ "offset": 1, "length": 1 }]));

        // Schema asks for something else → tag itself fails.
        let err = error_obj(&validate_cbor_bytes_against_cddl(
            &hex::decode("c203").unwrap(),
            "x = uint",
            "x",
        ))
        .clone();
        assert_eq!(
            err["message"],
            json!("expected type uint, got #6.2(3)"),
            "{}",
            err
        );
        assert_eq!(err["byte_spans"], json!([{ "offset": 0, "length": 1 }]));
        assert_eq!(err["anchor_spans"], json!([{ "offset": 0, "length": 2 }]));
    }

    /// `expected` is the schema type; `unexpected` does not invent one.
    #[test]
    fn an_unexpected_key_reports_no_expected_type() {
        assert_eq!(
            super::extract_expected("expected type uint, got 3"),
            Some("uint".to_string())
        );
        assert_eq!(super::extract_expected("unexpected key bytes(…)"), None);
    }

    /// Rewrite keys on `Debug` shape; lookalikes and text inside dumps pass through.
    #[test]
    fn text_that_only_resembles_a_data_item_is_left_alone() {
        for s in [
            // Not a constructor: name does not start at an ident boundary.
            "got MyText(\"a\")",
            "got notInteger(1)",
            // A control target, not a data item.
            "expected value .size (3), got 4",
            "target for .ne operator must be a numerical data type, got any",
        ] {
            assert_eq!(super::collapse_debug_structs(s, None), s, "rewrote {:?}", s);
        }
        // Quoted `)` cannot end an item; literals stay inside strings.
        assert_eq!(
            super::collapse_debug_structs("got Text(\"Integer(1) )\")", None),
            "got text \"Integer(1) )\""
        );
    }

    /// Map type of `entries` fields `f0: uint, …`, one entry per line with a comment.
    fn wide_map_schema(entries: usize) -> String {
        let mut schema = String::from("root = {\n");
        for i in 0..entries {
            schema.push_str(&format!("  f{}: uint, ; field {}\n", i, i));
        }
        schema.push_str("}\n");
        schema
    }

    /// Corpus: mutated real docs, whole-doc mismatches, and reason-family schemas.
    fn failing_corpus_messages() -> Vec<String> {
        let mut messages: Vec<String> = Vec::new();
        let mut collect = |result: &Value| {
            if result["valid"] == Value::Bool(true) {
                return;
            }
            for entry in all_entries(&result["error"]) {
                for field in ["message", "expected"] {
                    if let Some(s) = entry[field].as_str() {
                        messages.push(s.to_string());
                    }
                }
                for alt in entry["alternatives"].as_array().unwrap_or(&Vec::new()) {
                    if let Some(s) = alt.as_str() {
                        messages.push(s.to_string());
                    }
                }
            }
        };

        // Byte-mutated record doc — every item kind reaches a reason somewhere.
        let record = crate::cbor::test_fixtures::record_doc();
        for i in (0..record.len()).step_by(11) {
            for delta in [0x20u8, 0x01, 0x80, 0x60, 0x40] {
                let mut mutated = record.clone();
                mutated[i] ^= delta;
                collect(&validate_cbor_bytes_against_cddl(
                    &mutated,
                    load_ledger_cddl(),
                    "record",
                ));
            }
        }
        // Whole-document mismatches (offending item is the whole record).
        for rule in ["record", "datum", "amount"] {
            collect(&validate_cbor_bytes_against_cddl(
                &record,
                load_ledger_cddl(),
                rule,
            ));
            collect(&validate_cbor_bytes_against_cddl(
                &record,
                "root = tstr",
                "root",
            ));
        }
        // Recursive rule tag alts — reasons render tag+item (not flat docs).
        for doc in ["f879", "d9799fd87981f5"] {
            collect(&validate_cbor_bytes_against_cddl(
                &hex::decode(doc).unwrap(),
                load_ledger_cddl(),
                "datum",
            ));
        }
        // Reasons naming items outside `, got` (unclaimed key, bad control, tag mismatch).
        for (schema, docs) in [
            (
                "root = {1 => uint}",
                &["a2010102616101", "a1c1820102f6"][..],
            ),
            (
                "root = {* tstr => uint}",
                &["a1440102030401", "a1f60101"][..],
            ),
            ("root = #6.42(uint)", &["d87901", "d87980", "d8794101"][..]),
            (
                "root = bstr .cbor inner\ninner = uint",
                &["43810102", "42f5f5", "43820102", "41f5"][..],
            ),
            (
                "root = tstr .regexp \"^a+$\"",
                &["626162", "4101", "80"][..],
            ),
            (
                "root = uint .bits ab\nab = &(a: 0, b: 1)",
                &["07", "6161"][..],
            ),
            ("root = 1..10", &["20", "6161", "82616101"][..]),
            ("root = [tstr, uint]", &["8261616162", "82f5d87980"][..]),
            ("root = bstr .size 32", &["4101", "6161"][..]),
            ("root = float", &["01", "d87980", "a1616101"][..]),
            // Container type vs array/scalar/empty map — reason renders the type.
            (
                "root = { name: tstr, age: uint, ? nickname: tstr }",
                &[TWO_PERSONS, "05", "a0"][..],
            ),
            (
                "root = [name: tstr, age: uint]",
                &[TWO_PERSONS, "05", "a0"][..],
            ),
            (
                "root = #6.121([a: int, b: int, c: int, d: int, e: int, f: int])",
                &["05", "d87a80"][..],
            ),
            (
                "root = {a: int} / {b: int} / [c: int]",
                &[TWO_PERSONS, "05"][..],
            ),
            // Inline map under occurrence vs non-maps / extra entry.
            (
                "root = [* {a: int}]",
                &["818101", "8180", "8105", "81a2616101616202", "81f6"][..],
            ),
            (
                "root = [+ {a: int, b: tstr}]",
                &["8182016178", "81a1616101"][..],
            ),
            ("root = [* {? a: int}]", &["8180", "81a1616201"][..]),
            (
                "root = [* {* tstr => int}]",
                &["818101", "81a161616178"][..],
            ),
            (
                "root = [* {name: tstr}]",
                &[TWO_PERSONS, "82a1646e616d6565416c6963658101"][..],
            ),
        ] {
            for doc in docs {
                let bytes = hex::decode(doc).unwrap();
                collect(&validate_cbor_bytes_against_cddl(&bytes, schema, "root"));
            }
        }
        // Group past rendering bound; comment on every schema line.
        let wide = wide_map_schema(20);
        for doc in [TWO_PERSONS, "05", "a0"] {
            let bytes = hex::decode(doc).unwrap();
            collect(&validate_cbor_bytes_against_cddl(&bytes, &wide, "root"));
        }
        // The largest group in the schema against the whole record.
        collect(&validate_cbor_bytes_against_cddl(
            &record,
            load_ledger_cddl(),
            "record_body",
        ));

        assert!(
            messages.len() > 300,
            "corpus produced only {} messages",
            messages.len()
        );
        messages
    }

    /// No message may carry a Rust-debug `Ctor(…)` / `Ctor[…]` rendering.
    #[test]
    fn no_message_carries_a_rust_debug_rendering() {
        /// Byte offset of a Rust-debug rendering: UpperIdent + `(` or `[` with no space.
        fn debug_shape(msg: &str) -> Option<&str> {
            let bytes = msg.as_bytes();
            for (i, b) in bytes.iter().enumerate() {
                if *b != b'(' && *b != b'[' {
                    continue;
                }
                let mut start = i;
                while start > 0 && super::is_ident_byte(bytes[start - 1]) {
                    start -= 1;
                }
                if start < i && bytes[start].is_ascii_uppercase() {
                    return Some(&msg[start..]);
                }
            }
            None
        }

        // Detector fires on guarded renderings (green ≠ unchecked).
        assert!(debug_shape("got Integer(Integer(-1))").is_some());
        assert!(debug_shape("got Array([Bytes([0])])").is_some());
        assert!(debug_shape("got array(2 items)").is_none());
        assert!(debug_shape("got #6.121(…)").is_none());

        let messages = failing_corpus_messages();
        let leaked: Vec<&String> = messages
            .iter()
            .filter(|m| debug_shape(m).is_some())
            .collect();
        assert!(
            leaked.is_empty(),
            "{} of {} messages carry a Debug rendering, e.g. {:?}",
            leaked.len(),
            messages.len(),
            &leaked[..leaked.len().min(5)]
        );
    }

    /// `message` / `expected` / alternatives stay one line (schema layout stripped).
    #[test]
    fn no_message_or_expected_spans_more_than_one_line() {
        let messages = failing_corpus_messages();
        let broken: Vec<&String> = messages
            .iter()
            .filter(|m| m.contains(['\n', '\t']))
            .collect();
        assert!(
            broken.is_empty(),
            "{} of {} messages span more than one line, e.g. {:?}",
            broken.len(),
            messages.len(),
            &broken[..broken.len().min(5)]
        );
    }

    /// `[{name: "Alice", age: 30, nickname: "Ali"}, {…same…}]`.
    const TWO_PERSONS: &str = "82a3646e616d6565416c69636563616765181e686e69636b6e616d6563416c69a3646e616d6565416c69636563616765181e686e69636b6e616d6563416c69";

    /// Map type vs array: expected is the schema map wording; spans point at both.
    #[test]
    fn a_map_type_refusing_an_array_names_the_type_as_written() {
        let cddl = "Person = {\n  name: tstr,\n  age: uint,\n  ? nickname: tstr,\n}\nPersons = [+Person]\n";
        let bytes = hex::decode(TWO_PERSONS).unwrap();

        let result = validate_cbor_bytes_against_cddl(&bytes, cddl, "Person");
        let err = error_obj(&result).clone();
        assert_eq!(
            err["message"],
            json!("expected map { name: tstr, age: uint, ? nickname: tstr }, got array(2 items)"),
            "{}",
            err
        );
        assert_eq!(
            err["expected"],
            json!("map { name: tstr, age: uint, ? nickname: tstr }"),
            "{}",
            err
        );
        assert_eq!(err["kind"], json!("mismatch"));
        assert_eq!(err["path"], json!("$"));
        assert_eq!(err["byte_spans"], json!([{ "offset": 0, "length": 1 }]));
        assert_eq!(err["anchor_spans"], json!([{ "offset": 0, "length": 63 }]));
        assert_eq!(err["cddl_byte_span"]["offset"], json!(9));
        assert_eq!(err["cddl_byte_span"]["length"], json!(50));
        assert!(err.get("additional").is_none(), "{}", err);

        // The same type against a scalar and against an empty map.
        let err = error_obj(&validate_cbor_bytes_against_cddl(
            &hex::decode("05").unwrap(),
            cddl,
            "Person",
        ))
        .clone();
        assert_eq!(
            err["message"],
            json!("expected map { name: tstr, age: uint, ? nickname: tstr }, got 5"),
            "{}",
            err
        );
        let err = error_obj(&validate_cbor_bytes_against_cddl(
            &hex::decode("a0").unwrap(),
            cddl,
            "Person",
        ))
        .clone();
        assert_eq!(
            err["message"],
            json!("map missing key: \"name\""),
            "{}",
            err
        );

        // An array type refusing a map is named the same way.
        let err = error_obj(&validate_cbor_bytes_against_cddl(
            &hex::decode("a3646e616d6565416c69636563616765181e686e69636b6e616d6563416c69").unwrap(),
            "Pair = [name: tstr, age: uint]",
            "Pair",
        ))
        .clone();
        assert_eq!(
            err["message"],
            json!("expected array [ name: tstr, age: uint ], got map(3 entries)"),
            "{}",
            err
        );
        assert_eq!(err["expected"], json!("array [ name: tstr, age: uint ]"));

        // The rule the array does match is what it matches.
        assert_eq!(
            validate_cbor_bytes_against_cddl(&bytes, cddl, "Persons"),
            json!({ "valid": true })
        );
    }

    /// Inline map under occurrence: non-map items and extra keys refused like a
    /// named map type.
    #[test]
    fn an_occurrence_indicated_inline_map_type_holds_each_array_item_to_the_map() {
        let bytes = hex::decode(TWO_PERSONS).unwrap();

        // Items carry `age`/`nickname` the map type does not name.
        for schema in ["root = [* {name: tstr}]", "root = [+ {name: tstr}]"] {
            let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, schema, "root")).clone();
            assert_eq!(err["message"], json!("unexpected key \"age\""), "{}", err);
            // Located at the entry, with the key's span first.
            assert_eq!(err["path"], json!("$[0].age"), "{}", err);
            assert_eq!(err["byte_spans"].as_array().map(Vec::len), Some(2), "{}", err);
        }

        // Array item is not the map (any occurrence / reach form).
        let nested = hex::decode("818101").unwrap();
        for (schema, rule) in [
            ("root = [* {a: int}]", "root"),
            ("root = [+ {a: int}]", "root"),
            ("root = [? {a: int}]", "root"),
            ("root = [{a: int}]", "root"),
            ("root = [* m]\nm = {a: int}", "root"),
        ] {
            let err = error_obj(&validate_cbor_bytes_against_cddl(&nested, schema, rule)).clone();
            assert_eq!(
                err["message"],
                json!("expected map { a: int }, got array(1 items)"),
                "{} against {}",
                err,
                schema
            );
            assert_eq!(err["expected"], json!("map { a: int }"), "{}", err);
            assert_eq!(err["kind"], json!("mismatch"), "{}", err);
            assert_eq!(err["path"], json!("$[0]"), "{}", err);
            assert_eq!(
                err["byte_spans"],
                json!([{ "offset": 1, "length": 1 }]),
                "{}",
                err
            );
        }

        // Extra entry and empty map where an entry is required.
        let extra = hex::decode("81a2616101616202").unwrap();
        let err = error_obj(&validate_cbor_bytes_against_cddl(
            &extra,
            "root = [* {a: int}]",
            "root",
        ))
        .clone();
        assert_eq!(err["message"], json!("unexpected key \"b\""), "{}", err);
        assert_eq!(err["path"], json!("$[0].b"), "{}", err);
        let empty = hex::decode("81a0").unwrap();
        let err = error_obj(&validate_cbor_bytes_against_cddl(
            &empty,
            "root = [* {a: int}]",
            "root",
        ))
        .clone();
        assert_eq!(err["message"], json!("map missing key: \"a\""), "{}", err);

        // Admitted maps stay valid at every occurrence and length.
        for (schema, doc) in [
            ("root = [* {a: int}]", "80"),
            ("root = [* {a: int}]", "81a1616101"),
            ("root = [+ {a: int}]", "82a1616101a1616102"),
            ("root = [? {a: int}]", "81a1616101"),
            ("root = [* {? a: int}]", "82a0a1616101"),
            ("root = [* {* tstr => int}]", "81a2616101616202"),
            (
                "root = [* {name: tstr, age: uint, ? nickname: tstr}]",
                TWO_PERSONS,
            ),
        ] {
            assert_eq!(
                validate_cbor_bytes_against_cddl(&hex::decode(doc).unwrap(), schema, "root"),
                json!({ "valid": true }),
                "{} against {}",
                doc,
                schema
            );
        }
    }

    /// Long group cut to head by validator; `, got` kept; `expected` within its cap.
    #[test]
    fn a_long_group_keeps_its_got_side() {
        let record = crate::cbor::test_fixtures::record_doc();
        let err = error_obj(&validate_cbor_bytes_against_cddl(
            &record,
            load_ledger_cddl(),
            "record_body",
        ))
        .clone();
        let message = err["message"].as_str().unwrap();
        let expected = err["expected"].as_str().unwrap();

        assert_eq!(
            message,
            "expected map { 0: set<ref>, 1: [ * entry ], 2: amount, ? 3: uint, … 13 more }, got array(4 items)",
            "{}",
            err
        );
        assert_eq!(
            expected,
            "map { 0: set<ref>, 1: [ * entry ], 2: amount, ? 3: uint, … 13 more }"
        );
        assert!(expected.len() < super::MAX_EXPECTED_LEN);
        assert!(message.len() < super::MAX_MESSAGE_LEN);

        // A group of twenty entries written with a comment on every line.
        let err = error_obj(&validate_cbor_bytes_against_cddl(
            &hex::decode(TWO_PERSONS).unwrap(),
            &wide_map_schema(20),
            "root",
        ))
        .clone();
        assert_eq!(
            err["message"],
            json!("expected map { f0: uint, f1: uint, f2: uint, f3: uint, … 16 more }, got array(2 items)"),
            "{}",
            err
        );
        assert_eq!(
            err["expected"],
            json!("map { f0: uint, f1: uint, f2: uint, f3: uint, … 16 more }")
        );
    }

    /// Expected type ends at outer `, got` / `but`, not a member key spelled that way.
    #[test]
    fn expected_is_cut_at_the_got_clause_outside_the_type() {
        for (cddl, expected) in [
            (
                "M = {name: tstr, got: uint}",
                "map { name: tstr, got: uint }",
            ),
            (
                "M = {name: tstr, but: uint}",
                "map { name: tstr, but: uint }",
            ),
            (
                "M = [\"a, got\", \" but \"]",
                "array [ \"a, got\", \" but \" ]",
            ),
            (
                "M = {name: tstr, k: [got: int, but: int]}",
                "map { name: tstr, k: [ got: int, but: int ] }",
            ),
        ] {
            let err = error_obj(&validate_cbor_bytes_against_cddl(
                &hex::decode("05").unwrap(),
                cddl,
                "M",
            ))
            .clone();
            assert_eq!(err["expected"], json!(expected), "{}", err);
            assert_eq!(
                err["message"],
                json!(format!("expected {}, got 5", expected)),
                "{}",
                err
            );
        }

        // Flat cuts still apply; unclosed bracket from length bound does not swallow the clause.
        assert_eq!(
            super::extract_expected(
                "expected array element at index 1, but array only has 1 elements"
            ),
            Some("array element at index 1".to_string())
        );
        assert_eq!(
            super::extract_expected("expected uint .bits ab, got 7. Bit 3 is set but is not a member of the control type"),
            Some("uint .bits ab".to_string())
        );
        assert_eq!(
            super::extract_expected("expected map { a: int, b: {..., got 5"),
            Some("map { a: int, b: {...".to_string())
        );
        assert_eq!(
            super::extract_expected("expected value \"x, got y\", got 5"),
            Some("value \"x, got y\"".to_string())
        );
    }

    /// Choice of containers → each alt in `alternatives`; kind is mismatch.
    #[test]
    fn alternatives_of_a_choice_of_maps_read_as_types() {
        let err = error_obj(&validate_cbor_bytes_against_cddl(
            &hex::decode(TWO_PERSONS).unwrap(),
            "root = {a: int} / {b: int}",
            "root",
        ))
        .clone();
        assert_eq!(
            err["alternatives"],
            json!(["map { a: int }", "map { b: int }"]),
            "{}",
            err
        );
        assert_eq!(err["kind"], json!("mismatch"));
        assert_eq!(
            err["message"],
            json!("expected map { a: int }, got array(2 items)")
        );

        assert_eq!(
            super::classify_reason("expected map { a: int }, got Array([])"),
            "mismatch"
        );
        assert_eq!(
            super::classify_reason("expected array [ int ], got Map([])"),
            "mismatch"
        );
        assert_eq!(
            super::extract_expected("expected map { a: int, ? b: [ c: int ] }, got Array([])"),
            Some("map { a: int, ? b: [ c: int ] }".to_string())
        );
        assert_eq!(
            super::extract_expected("expected array [ int ], got Map([])"),
            Some("array [ int ]".to_string())
        );
        assert_eq!(
            super::extract_expected(
                "expected tagged data #6.121([ a: int, … 2 more ]), got Integer(Integer(5))"
            ),
            Some("tagged data #6.121([ a: int, … 2 more ])".to_string())
        );
    }

    #[test]
    fn tag_wrapped_embedded_payload_error_lands_inside_the_payload() {
        // #6.24(h'82…') — tag transparent; failure inside bstr content.
        let cddl = "root = #6.24(bytes .cbor inner)\ninner = [tstr, uint]";
        let bytes = hex::decode("d818458261616162").unwrap();
        let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, cddl, "root")).clone();
        assert_eq!(err["path"], json!("$[1]"), "{}", err);
        assert_eq!(err["embedded_span"], json!(true), "{}", err);
        let span = &err["byte_spans"][0];
        let off = span["offset"].as_u64().unwrap() as usize;
        let len = span["length"].as_u64().unwrap() as usize;
        assert_eq!(hex::encode(&bytes[off..off + len]), "6162", "{}", err);
    }

    // ========================================================
    // Root rule selection
    // ========================================================

    /// Non-first type rule rooted by reordering, not re-parsing a wrapper.
    #[test]
    fn non_first_rule_validates_without_a_second_parse() {
        let cddl = load_ledger_cddl();
        let first = super::document_cache::with_ast_checked(cddl, |parsed| {
            match parsed.expect("ledger schema must resolve").rules.first() {
                Some(cddl::ast::Rule::Type { rule, .. }) => rule.name.ident.to_string(),
                other => panic!("unexpected first rule: {:?}", other.is_some()),
            }
        });
        assert_ne!(first, "record_body", "fixture no longer exercises the path");

        // The body map of the record `[body, witness, bool, aux]`, on its own.
        let record: ciborium::value::Value =
            ciborium::from_reader(crate::cbor::test_fixtures::record_doc().as_slice()).unwrap();
        let mut bytes = Vec::new();
        ciborium::into_writer(&record.as_array().unwrap()[0], &mut bytes).unwrap();
        let result = validate_cbor_bytes_against_cddl(&bytes, cddl, "record_body");
        assert_eq!(result, json!({ "valid": true }), "{}", result);

        // Control: same bytes vs a non-matching rule → reordered root took effect.
        let result = validate_cbor_bytes_against_cddl(&bytes, cddl, "ref");
        let err = error_obj(&result);
        assert_eq!(err["kind"], json!("mismatch"), "{}", err);
    }

    /// Group rule roots refused (not wrapped).
    ///
    /// Wrapper ignored arity (e.g. two-entry group accepted 3-arrays) and disagreed
    /// with mappers; same refusal wording on every export.
    #[test]
    fn a_group_rule_is_refused_as_a_root_by_every_export() {
        let cddl = "first = [tstr]\npair = (a: int, b: int)\n";
        for hex in ["820102", "8101", "83010203"] {
            let bytes = hex::decode(hex).unwrap();
            let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, cddl, "pair")).clone();
            assert_eq!(err["kind"], json!("group_rule_root"), "{}: {}", hex, err);
            let message = err["message"].as_str().unwrap_or_default().to_string();
            assert!(
                message.contains("pair") && message.contains("group rule"),
                "{}",
                message
            );

            // The same rule, the same words, from the other two exports.
            for other in [
                crate::cbor::schema_mapper::decode_cbor_against_cddl(&bytes, cddl, "pair").err(),
                crate::cbor::cbor_cddl_map::map_cbor_to_cddl(&bytes, cddl, "pair").err(),
            ] {
                let other = other.expect("expected a refusal");
                assert_eq!(other.kind(), "group_rule_root", "{}", other);
                assert_eq!(other.to_string(), message);
            }
        }

        // As a type rule, group arity is enforced — shows wrapper's accept was wrong.
        let cddl = "use = [pair]\npair = (a: int, b: int)\n";
        assert_eq!(
            validate_cbor_bytes_against_cddl(&hex::decode("820102").unwrap(), cddl, "use"),
            json!({ "valid": true })
        );
        let err = error_obj(&validate_cbor_bytes_against_cddl(
            &hex::decode("83010203").unwrap(),
            cddl,
            "use",
        ))
        .clone();
        assert_eq!(err["kind"], json!("mismatch"), "{}", err);
    }

    /// Generic type-rule roots still use the synthetic wrapper.
    #[test]
    fn a_generic_rule_root_still_goes_through_the_wrapper() {
        // Unbound param cannot validate — must report against the requested rule.
        let cddl = "first = tstr\nholder<t> = [t]\n";
        let bytes = hex::decode("8101").unwrap();
        let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, cddl, "holder")).clone();
        assert!(
            err["message"].as_str().unwrap_or_default().contains('t')
                && !err["message"].as_str().unwrap_or_default().contains("tstr"),
            "expected the generic root, not the first rule: {}",
            err
        );
    }

    /// Reordering adds no prefix; spans need no wrapper correction.
    #[test]
    fn cddl_spans_are_unshifted_for_a_non_first_rule() {
        let cddl = "first = uint\nsecond = [label: tstr]\n";
        let bytes = hex::decode("8101").unwrap();
        let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, cddl, "second")).clone();
        let span = &err["cddl_byte_span"];
        let off = span["offset"].as_u64().unwrap() as usize;
        let len = span["length"].as_u64().unwrap() as usize;
        assert_eq!(&cddl[off..off + len], "tstr", "{}", err);
        assert_eq!(span["line"], json!(2), "{}", err);
    }

    /// Rule after a generic is still selectable among root-eligible rules.
    #[test]
    fn a_root_after_a_generic_rule_is_reordered_not_wrapped() {
        let cddl = "boxed<t> = [t]\nfirst = uint\ntarget = [label: tstr]\n";
        let bytes = hex::decode("816161").unwrap();
        let result = validate_cbor_bytes_against_cddl(&bytes, cddl, "target");
        assert_eq!(result, json!({ "valid": true }), "{}", result);

        let bytes = hex::decode("8101").unwrap();
        let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, cddl, "target")).clone();
        let span = &err["cddl_byte_span"];
        let off = span["offset"].as_u64().unwrap() as usize;
        let len = span["length"].as_u64().unwrap() as usize;
        assert_eq!(&cddl[off..off + len], "tstr", "{}", err);
    }

    /// Type-choice extends keep both halves after rotating the base forward.
    #[test]
    fn a_reordered_root_keeps_its_type_choice_alternates() {
        let cddl = "first = uint\ntarget = tstr\ntarget /= uint\n";
        for hex_bytes in ["6161", "01"] {
            let bytes = hex::decode(hex_bytes).unwrap();
            let result = validate_cbor_bytes_against_cddl(&bytes, cddl, "target");
            assert_eq!(
                result,
                json!({ "valid": true }),
                "{}: {}",
                hex_bytes,
                result
            );
        }
        // The control: a value neither alternative accepts still fails.
        let bytes = hex::decode("f5").unwrap();
        let result = validate_cbor_bytes_against_cddl(&bytes, cddl, "target");
        assert_eq!(result["valid"], json!(false), "{}", result);
    }

    /// Past decoder nesting bound → own kind; one level shallower still validates.
    #[test]
    fn cbor_nested_past_the_limit_is_refused_by_the_validator() {
        crate::cbor::test_fixtures::on_large_stack(|| {
            let cddl = "x = [* x] / uint";
            // Depth inside all bounds — accepted control for the refusal below.
            let mut hex_at = "81".repeat(24);
            hex_at.push_str("05");
            let bytes = hex::decode(&hex_at).unwrap();
            let result = validate_cbor_bytes_against_cddl(&bytes, cddl, "x");
            assert_eq!(result, json!({ "valid": true }), "{}", result);

            let mut hex_past = "81".repeat(crate::cbor::limits::MAX_CBOR_NESTING_DEPTH + 1);
            hex_past.push_str("05");
            let bytes = hex::decode(&hex_past).unwrap();
            let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, cddl, "x")).clone();
            assert_eq!(err["kind"], json!("nesting_too_deep"), "{}", err);
        });
    }

    /// Validator nesting bound: at the limit validates; one deeper refuses as a
    /// limit (not mismatch). Past [`limits::MAX_CBOR_NESTING_DEPTH`] the pre-scan
    /// refuses first.
    ///
    /// `[* x]` + `uint` leaf is valid CDDL at every depth here.
    #[test]
    fn the_validators_own_nesting_bound_is_a_limit_not_a_mismatch() {
        let cddl = "x = [* x] / uint";
        let nest = |levels: usize, leaf: &str| {
            let mut hex_bytes = "81".repeat(levels);
            hex_bytes.push_str(leaf);
            hex::decode(hex_bytes).unwrap()
        };

        let level_bound = crate::cbor::limits::MAX_CBOR_VALIDATION_NESTING_DEPTH;
        let at = validate_cbor_bytes_against_cddl(&nest(level_bound, "00"), cddl, "x");
        assert_eq!(at, json!({ "valid": true }), "{}", at);

        // Leaf no alt admits → mismatch at its location.
        let err = error_obj(&validate_cbor_bytes_against_cddl(
            &nest(level_bound, "60"),
            cddl,
            "x",
        ))
        .clone();
        assert_eq!(err["kind"], json!("mismatch"), "{}", err["kind"]);
        assert_eq!(
            err["path"],
            json!(format!("${}", "[0]".repeat(level_bound)))
        );

        // Past document-sizing count → pre-scan refuses before walkers.
        let past = nest(crate::cbor::limits::MAX_CBOR_NESTING_DEPTH + 1, "00");
        assert!(crate::cbor::limits::NestingBudget::for_document(&past).is_none());
        let err = error_obj(&validate_cbor_bytes_against_cddl(&past, cddl, "x")).clone();
        assert_eq!(err["kind"], json!("nesting_too_deep"), "{}", err);
        let message = err["message"].as_str().unwrap_or_default();
        assert!(
            message.contains(&crate::cbor::limits::MAX_CBOR_NESTING_DEPTH.to_string()),
            "the refusal must name the bound: {}",
            message
        );
    }

    /// Embedded payload over nesting bound → limit kind (pre-scan does not read
    /// bstr contents).
    #[test]
    fn an_embedded_payload_past_the_decoding_bound_is_a_limit_not_a_generic_error() {
        crate::cbor::test_fixtures::on_large_stack(|| {
            let payload = |levels: usize| {
                let mut hex_bytes = "81".repeat(levels);
                hex_bytes.push_str("05");
                let bytes = hex::decode(hex_bytes).unwrap();
                let mut doc = vec![0x5a];
                doc.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                doc.extend(bytes);
                doc
            };
            let bound = cddl::validator::cbor_value::MAX_DECODE_NESTING_DEPTH;
            for cddl in [
                "x = bstr .cbor y\ny = [* y] / uint\n",
                "x = bstr .cborseq y\ny = [* y] / uint\n",
            ] {
                let within = validate_cbor_bytes_against_cddl(&payload(20), cddl, "x");
                assert_eq!(within, json!({ "valid": true }), "{}", within);

                let err = error_obj(&validate_cbor_bytes_against_cddl(
                    &payload(bound + 1),
                    cddl,
                    "x",
                ))
                .clone();
                assert_eq!(err["kind"], json!("nesting_too_deep"), "{}", err);
                let message = err["message"].as_str().unwrap_or_default();
                assert!(
                    message.contains(&bound.to_string()),
                    "the refusal must name the bound: {}",
                    message
                );
            }
        });
    }

    /// Descent-cost bound (levels + rule hops): alias chains hold more than a
    /// level count. Refusal is a limit, not a data finding.
    ///
    /// `x = [* r0]` with aliases back to `x` is valid at every depth; depths are
    /// spaced so a levels-only charge would pass both.
    #[test]
    fn the_cost_of_a_descent_is_bounded_and_reported_as_a_limit() {
        crate::cbor::test_fixtures::on_large_stack(|| {
            let hops = 63;
            let mut cddl = String::from("x = [* r0]\n");
            for alias in 0..hops - 1 {
                cddl.push_str(&format!("r{} = r{}\n", alias, alias + 1));
            }
            cddl.push_str(&format!("r{} = x\n", hops - 1));

            let nest = |levels: usize| {
                let mut hex_bytes = "81".repeat(levels);
                hex_bytes.push_str("80");
                hex::decode(hex_bytes).unwrap()
            };

            let within = validate_cbor_bytes_against_cddl(&nest(40), &cddl, "x");
            assert_eq!(within, json!({ "valid": true }), "{}", within);

            let past = nest(2500);
            // Inside both counts — only descent hold can refuse.
            assert!(2500 < crate::cbor::limits::MAX_CBOR_VALIDATION_NESTING_DEPTH);
            assert!(crate::cbor::limits::NestingBudget::for_document(&past).is_some());

            let err = error_obj(&validate_cbor_bytes_against_cddl(&past, &cddl, "x")).clone();
            assert_eq!(err["kind"], json!("nesting_too_deep"), "{}", err);
            let message = err["message"].as_str().unwrap_or_default();
            assert!(
                message
                    .contains(&crate::cbor::limits::MAX_CBOR_VALIDATION_DESCENT_COST.to_string()),
                "the refusal must name the bound: {}",
                message
            );
        });
    }

    /// Choice alts that each descend → work exponential in nesting; refuse with a
    /// bound rather than hanging (caller-supplied schema+doc).
    #[test]
    fn a_walk_exponential_in_the_nesting_is_refused_as_a_limit() {
        crate::cbor::test_fixtures::on_large_stack(|| {
            // Two descending alts + rejected leaf → each level walked twice.
            let cddl = "x = a / b / uint\na = [x]\nb = [x]";
            let levels = 24;
            assert!(levels < crate::cbor::limits::MAX_CBOR_VALIDATION_NESTING_DEPTH);

            // Same schema on admitted data at same depth still answers.
            let mut admitted = "81".repeat(levels);
            admitted.push_str("05");
            let bytes = hex::decode(admitted).unwrap();
            let out = validate_cbor_bytes_against_cddl(&bytes, cddl, "x");
            assert_eq!(out, json!({ "valid": true }), "{}", out);

            // Two to the twenty-fourth steps: only the work bound stops it.
            let mut refused = "81".repeat(levels);
            refused.push_str("60");
            let bytes = hex::decode(refused).unwrap();
            let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, cddl, "x")).clone();
            assert_eq!(err["kind"], json!("validation_too_complex"), "{}", err);
            let message = err["message"].as_str().unwrap_or_default();
            assert!(
                message.contains(&crate::cbor::limits::MAX_CBOR_VALIDATION_WORK.to_string()),
                "the refusal must name the bound: {}",
                message
            );
        });
    }

    /// Work limit outranks mismatches from the same walk (like nesting limits).
    #[test]
    fn the_work_bound_outranks_a_mismatch_as_the_head_error() {
        crate::cbor::test_fixtures::on_large_stack(|| {
            // First alt mismatches every level before descending alts; leaf admitted by none.
            let cddl = "x = uint / a / b\na = [x]\nb = [x]";
            let mut hex_bytes = "81".repeat(24);
            hex_bytes.push_str("60");
            let bytes = hex::decode(hex_bytes).unwrap();
            let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, cddl, "x")).clone();
            assert_eq!(err["kind"], json!("validation_too_complex"), "{}", err);
        });
    }

    /// An array of `items` copies of one hex-encoded data item, as the
    /// CBOR bytes of that array.
    fn array_of(items: usize, item_hex: &str) -> Vec<u8> {
        let mut out = if items < 65536 {
            format!("99{:04x}", items)
        } else {
            format!("9a{:08x}", items)
        };
        for _ in 0..items {
            out.push_str(item_hex);
        }
        hex::decode(out).unwrap()
    }

    /// Whether a run reaches any verdict within `work` steps.
    ///
    /// Same construction as `run_validator`, varying the work bound — probes cost
    /// without spending [`limits::MAX_CBOR_VALIDATION_WORK`].

    /// `datum` with a wide constructor choice: the eight small tags plus the
    /// run 1280..=1400, 129 alternatives probed in turn before a leaf
    /// matches `bounded_bytes`. The densest shape the work bound is sized for.
    fn wide_constr_datum_schema() -> String {
        let mut schema = String::from(
            "datum = constr<datum> / {* datum => datum} / [* datum] / big_int / bounded_bytes\n\
             big_int = int / big_uint / big_nint\n\
             big_uint = #6.2(bounded_bytes)\n\
             big_nint = #6.3(bounded_bytes)\n\
             bounded_bytes = bytes .size (0..64)\n\
             constr<a> = #6.102([uint, [* a]])\n",
        );
        for tag in (121..=127).chain(1280..=1400) {
            schema.push_str(&format!("  / #6.{tag}([* a])\n"));
        }
        schema
    }

    fn reaches_a_verdict_within(cbor: &[u8], cddl: &str, rule_name: &str, work: usize) -> bool {
        use cddl::validator::Validator;

        document_cache::with_ast_checked(cddl, |parsed| {
            let ast = parsed.expect("schema parses");
            let (root, _) = super::find_root_rule(ast, rule_name).expect("rule is defined");
            let rooted = with_root_first(ast, root).expect("rule can be a root");
            let value = cddl::validator::cbor_value::decode_cbor(cbor).expect("document decodes");

            let mut cv = cddl::validator::cbor::CBORValidator::new(&rooted, value, None);
            cv.set_max_nesting_depth(limits::MAX_CBOR_VALIDATION_NESTING_DEPTH);
            cv.set_max_descent_cost(limits::MAX_CBOR_VALIDATION_DESCENT_COST);
            cv.set_descent_weights(
                limits::VALIDATOR_LEVEL_COST,
                limits::VALIDATOR_RULE_HOP_COST,
            );
            cv.set_max_validation_work(work);
            match cv.validate() {
                Ok(()) => true,
                Err(e) => !e.to_string().contains("steps of validation work"),
            }
        })
    }

    /// The ledger documents stay far inside the work bound.
    #[test]
    fn ledger_documents_stay_far_inside_the_work_bound() {
        crate::cbor::test_fixtures::on_large_stack(|| {
            let record = crate::cbor::test_fixtures::record_doc();
            let out = validate_cbor_bytes_against_cddl(
                &record,
                crate::cbor::test_fixtures::ledger_cddl(),
                "record",
            );
            assert_eq!(out, json!({ "valid": true }), "{}", out);

            // Deep dearest shape under a real-sized schema still answers (not bound-limited).
            let validates = |levels: usize| {
                let mut hex_bytes = "a100".repeat(levels);
                hex_bytes.push_str("05");
                let bytes = hex::decode(hex_bytes).unwrap();
                validate_cbor_bytes_against_cddl(
                    &bytes,
                    crate::cbor::test_fixtures::ledger_cddl(),
                    "datum",
                ) == json!({ "valid": true })
            };
            assert!(validates(512));

            // ~0.25 MB datum list of max `bounded_bytes` still answers — bound must cover
            // sizes this crate is handed.
            let bytes = array_of(3971, &format!("5840{}", "ab".repeat(64)));
            assert_eq!(bytes.len(), 262_089);
            let out = validate_cbor_bytes_against_cddl(
                &bytes,
                crate::cbor::test_fixtures::ledger_cddl(),
                "datum",
            );
            assert_eq!(out, json!({ "valid": true }), "{}", out);
        });
    }

    /// Densest shape (leaf array under a wide-constructor `datum`) step/byte density.
    ///
    /// Measured at ~1 KiB (short walk); see [`limits::MAX_CBOR_VALIDATION_WORK`] doc
    /// for reach (~28 KB of this shape).
    #[test]
    fn the_work_bound_carries_the_densest_shape_to_the_documented_size() {
        crate::cbor::test_fixtures::on_large_stack(|| {
            let cddl = wide_constr_datum_schema();
            let bytes = array_of(1021, "40");
            let size = bytes.len();
            assert_eq!(size, 1024);

            let within = |steps_per_byte: usize| {
                reaches_a_verdict_within(&bytes, &cddl, "datum", size * steps_per_byte)
            };

            // Density bracket: >139 and ≤142 steps/byte.
            let least = 139usize;
            let most = 142usize;
            assert!(within(most));
            assert!(!within(least));

            // Bound reach ~24–32 KiB of this shape; dearer → limit. Ledger docs far cheaper.
            let nearest = limits::MAX_CBOR_VALIDATION_WORK / most;
            let furthest = limits::MAX_CBOR_VALIDATION_WORK / least;
            assert!(nearest > 24 * 1024, "{}", nearest);
            assert!(furthest < 32 * 1024, "{}", furthest);
        });
    }

    /// Text-conversion payloads share the document work budget (not a fresh budget
    /// per payload — that would not bound nested cost). Probed via budget carry,
    /// not by spending [`limits::MAX_CBOR_VALIDATION_WORK`].
    #[test]
    fn text_conversion_payloads_share_the_documents_work_budget() {
        crate::cbor::test_fixtures::on_large_stack(|| {
            let cddl = "root = [* (tstr .hex inner)]\ninner = bstr .cbor [* uint]\n";

            // One `.hex`/`.cbor` payload: eight-int array as hex text.
            let payload = hex::encode([0x88u8, 0, 1, 2, 3, 4, 5, 6, 7]);
            let item = format!("72{}", hex::encode(payload.as_bytes()));
            let document = |payloads: usize| {
                hex::decode(format!("{:02x}{}", 0x80 + payloads, item.repeat(payloads))).unwrap()
            };

            let within = |payloads: usize, work: usize| {
                reaches_a_verdict_within(&document(payloads), cddl, "root", work)
            };

            // The smallest budget that carries one payload.
            let mut cost = 1;
            while !within(1, cost) {
                cost += 1;
                assert!(cost < 10_000, "one payload costs more than the search");
            }

            // Second same-size payload exceeds what carried one exactly.
            assert!(!within(2, cost));

            // That is the shared budget, not payloads beyond any budget.
            assert!(within(2, cost * 3));
        });
    }

    /// Limit reached deep must be the head error — mismatches below were unchecked.
    #[test]
    fn a_limit_outranks_a_mismatch_as_the_head_error() {
        crate::cbor::test_fixtures::on_large_stack(|| {
            let cddl = "x = [* x] / uint";
            let mut hex_bytes =
                "81".repeat(crate::cbor::limits::MAX_CBOR_VALIDATION_NESTING_DEPTH + 1);
            // Rejected tstr also yields mismatches competing with the limit.
            hex_bytes.push_str("6161");
            let bytes = hex::decode(hex_bytes).unwrap();
            let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, cddl, "x")).clone();
            assert_eq!(err["kind"], json!("nesting_too_deep"), "{}", err);
        });
    }

    /// Declared lengths must not size allocations before bytes exist (abort on
    /// 32/64-bit overflow). Headers claiming 2^64-1 with no body must error.
    #[test]
    fn a_declared_length_no_input_could_carry_is_an_error_not_an_abort() {
        for hex_bytes in [
            // bstr/tstr/array/map headers declaring 2^64-1 with nothing after.
            "5bffffffffffffffff",
            "7bffffffffffffffff",
            "9bffffffffffffffff",
            "bbffffffffffffffff",
            // Representable but unbacked lengths: 2 GiB and 4 GiB.
            "5a7fffffff",
            "5b0000000100000000",
            // The same, one level inside a container.
            "815bffffffffffffffff",
        ] {
            let bytes = hex::decode(hex_bytes).unwrap();
            let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, "x = any", "x")).clone();
            assert_eq!(err["kind"], json!("input_parse"), "{}: {}", hex_bytes, err);

            assert!(
                crate::cbor::schema_mapper::decode_cbor_against_cddl(&bytes, "x = any", "x")
                    .is_err(),
                "{}",
                hex_bytes
            );
            assert!(
                crate::cbor::cbor_cddl_map::map_cbor_to_cddl(&bytes, "x = any", "x").is_err(),
                "{}",
                hex_bytes
            );
        }
    }

    /// Control for the masking defect: same-shape / array-only choices still report.
    #[test]
    fn a_tag_alternative_reports_its_failure_when_nothing_masks_it() {
        // d8 79 81 61 61 = tag(121)(["a"]) — not `#6.121([* uint])`.
        let bytes = hex::decode("d8798161 61".replace(' ', "")).unwrap();

        let err = error_obj(&validate_cbor_bytes_against_cddl(
            &bytes,
            "x = #6.121([* uint])",
            "x",
        ))
        .clone();
        assert_eq!(err["path"], json!("$[0]"), "{}", err);

        let result = validate_cbor_bytes_against_cddl(
            &bytes,
            "x = #6.121([* uint]) / #6.122([* uint])",
            "x",
        );
        assert_eq!(result["valid"], json!(false), "{}", result);

        // a1 41aa 6161 = { h'aa': "a" } against a map of bytes to bytes.
        let map_bytes = hex::decode("a141aa6161").unwrap();
        let result = validate_cbor_bytes_against_cddl(&map_bytes, "m = {* bytes => bytes}", "m");
        assert_eq!(result["valid"], json!(false), "{}", result);

        // ["a"] vs array alt beside a different shape — not masked.
        let arr_bytes = hex::decode("816161").unwrap();
        let result = validate_cbor_bytes_against_cddl(&arr_bytes, "x = [* uint] / bytes", "x");
        assert_eq!(result["valid"], json!(false), "{}", result);
    }

    /// Mixed-shape type choice can discard failures inside tagged/map-ref alts and
    /// return `valid: true` for unmatched data.
    ///
    /// Same class as the map case; `datum` has this shape (constructor guts
    /// unchecked in practice).
    #[test]
    fn type_choice_with_a_tag_alternative_rejects_data_no_alternative_accepts() {
        let bytes = hex::decode("d8798161 61".replace(' ', "")).unwrap();
        for cddl in [
            "x = #6.121([* uint]) / bytes",
            "x = bytes / #6.121([* uint])",
            "c<a> = #6.121([* a])\nx = c<uint> / bytes",
        ] {
            let result = validate_cbor_bytes_against_cddl(&bytes, cddl, "x");
            assert_eq!(result["valid"], json!(false), "{}: {}", cddl, result);
        }

        let map_bytes = hex::decode("a141aa6161").unwrap();
        let result = validate_cbor_bytes_against_cddl(
            &map_bytes,
            "m = {* bytes => y} / bytes\ny = bytes",
            "m",
        );
        assert_eq!(result["valid"], json!(false), "{}", result);
    }
    /// Crossed type-choice alts name the node they failed on, not the choice entry.
    ///
    /// `set<a0> = #6.258([* a0]) / [* a0]` from `$[0]`: tag fails on `$[0]`, array on
    /// `$[0][0]`. Checked over the full entry set (not only the ranked head).
    #[test]
    fn a_crossed_type_choice_reports_each_alternative_at_its_own_node() {
        // 82 81 4100 01 = [[h'00'], 1]
        let bytes = hex::decode("8281410001").unwrap();
        let cddl = concat!(
            "t = [a, uint]\n",
            "a = set<i>\n",
            "set<a0> = #6.258([* a0]) / [* a0]\n",
            "i = bytes .size 32\n",
        );

        let err = error_obj(&validate_cbor_bytes_against_cddl(&bytes, cddl, "t")).clone();
        let mut paths: Vec<String> = all_entries(&err)
            .iter()
            .map(|e| e["path"].as_str().unwrap().to_string())
            .collect();
        paths.sort();
        paths.dedup();
        assert_eq!(paths, vec!["$[0]", "$[0][0]"], "{}", err);

        // Size-failing bstr @2 (2 bytes); tag-alt array opens @1 len 3.
        let by_path = |p: &str| -> Value {
            all_entries(&err)
                .into_iter()
                .find(|e| e["path"] == json!(p))
                .unwrap_or_else(|| panic!("no entry at {} in {}", p, err))
        };
        let element = by_path("$[0][0]");
        assert_eq!(element["byte_spans"], json!([{ "offset": 2, "length": 2 }]));
        let inner = by_path("$[0]");
        assert_eq!(inner["byte_spans"], json!([{ "offset": 1, "length": 1 }]));
        assert_eq!(inner["anchor_spans"], json!([{ "offset": 1, "length": 3 }]));

        // Same rule from a map value and one array deeper — same naming.
        // a1 616b 81 4100 = {"k":[h'00']}
        let map_bytes = hex::decode("a1616b814100").unwrap();
        let map_cddl = concat!(
            "t = { k: a }\n",
            "a = set<i>\n",
            "set<a0> = #6.258([* a0]) / [* a0]\n",
            "i = bytes .size 32\n",
        );
        let map_err =
            error_obj(&validate_cbor_bytes_against_cddl(&map_bytes, map_cddl, "t")).clone();
        let mut map_paths: Vec<String> = all_entries(&map_err)
            .iter()
            .map(|e| e["path"].as_str().unwrap().to_string())
            .collect();
        map_paths.sort();
        map_paths.dedup();
        assert_eq!(map_paths, vec!["$.k", "$.k[0]"], "{}", map_err);

        // 82 81 81 4100 01 = [[[h'00']], 1]
        let deep_bytes = hex::decode("828181410001").unwrap();
        let deep_cddl = concat!(
            "t = [[a], uint]\n",
            "a = set<i>\n",
            "set<a0> = #6.258([* a0]) / [* a0]\n",
            "i = bytes .size 32\n",
        );
        let deep_err = error_obj(&validate_cbor_bytes_against_cddl(
            &deep_bytes,
            deep_cddl,
            "t",
        ))
        .clone();
        let mut deep_paths: Vec<String> = all_entries(&deep_err)
            .iter()
            .map(|e| e["path"].as_str().unwrap().to_string())
            .collect();
        deep_paths.sort();
        deep_paths.dedup();
        assert_eq!(deep_paths, vec!["$[0][0]", "$[0][0][0]"], "{}", deep_err);

        // Nested choice without a generic in the chain — same depths.
        // 81 81 41ff = [[h'ff']]
        let nested_bytes = hex::decode("818141ff").unwrap();
        let nested_cddl = concat!(
            "t = [outer]\n",
            "outer = inner / uint\n",
            "inner = [* i] / tstr\n",
            "i = bytes .size 32\n",
        );
        let nested_err = error_obj(&validate_cbor_bytes_against_cddl(
            &nested_bytes,
            nested_cddl,
            "t",
        ))
        .clone();
        let mut nested_paths: Vec<String> = all_entries(&nested_err)
            .iter()
            .map(|e| e["path"].as_str().unwrap().to_string())
            .collect();
        nested_paths.sort();
        nested_paths.dedup();
        assert_eq!(nested_paths, vec!["$[0]", "$[0][0]"], "{}", nested_err);
    }

    /// Data those schemas describe is still accepted via either choice alt.
    #[test]
    fn a_crossed_type_choice_still_accepts_what_it_describes() {
        let cddl = concat!(
            "t = [a, uint]\n",
            "a = set<i>\n",
            "set<a0> = #6.258([* a0]) / [* a0]\n",
            "i = bytes .size 4\n",
        );
        for hex_str in [
            // [[h'00010203'], 1]
            "8281440001020301",
            // [258([h'00010203']), 1]
            "82d9010281440001020301",
        ] {
            let bytes = hex::decode(hex_str).unwrap();
            let result = validate_cbor_bytes_against_cddl(&bytes, cddl, "t");
            assert_eq!(result["valid"], json!(true), "{}: {}", hex_str, result);
        }

        let map_cddl = concat!(
            "t = { k: a }\n",
            "a = set<i>\n",
            "set<a0> = #6.258([* a0]) / [* a0]\n",
            "i = bytes .size 4\n",
        );
        // { "k": [h'00010203'] }
        let map_bytes = hex::decode("a1616b8144000102 03".replace(' ', "")).unwrap();
        let result = validate_cbor_bytes_against_cddl(&map_bytes, map_cddl, "t");
        assert_eq!(result["valid"], json!(true), "{}", result);
    }
}

#[cfg(test)]
mod lookup_tests {
    use super::*;

    /// A map of `n` entries under text keys `k0`, `k1`, … (all values 0),
    /// then the entries `extra` (key and value hex).
    fn map_hex(n: usize, extra: &[&str]) -> Vec<u8> {
        let count = n + extra.len();
        let mut hex = if count < 24 {
            format!("{:02x}", 0xa0 + count)
        } else {
            format!("b9{:04x}", count)
        };
        for i in 0..n {
            let key = format!("k{}", i);
            hex.push_str(&format!("{:02x}{}00", 0x60 + key.len(), hex::encode(&key)));
        }
        for e in extra {
            hex.push_str(e);
        }
        hex::decode(hex).unwrap()
    }

    fn tree_of(bytes: &[u8]) -> Value {
        decoder::decode_cbor_to_value(bytes).unwrap().into_inner()
    }

    type Summary = (
        Option<Value>,
        Option<Value>,
        String,
        Option<Option<Value>>,
        bool,
    );

    fn summary(node: Option<LocatedNode>) -> Option<Summary> {
        node.map(|n| {
            (
                n.tagged.span,
                n.tagged.anchor,
                n.tagged.preview,
                n.key.map(|k| k.span),
                n.embedded,
            )
        })
    }

    /// Locating an entry through the key index finds what the search entry
    /// by entry finds, for every kind of component, and indexes the map
    /// once for all of them.
    #[test]
    fn the_key_index_finds_what_the_entry_search_finds() {
        // 40 text keys, the integer keys 7 and -2, a byte string key and a
        // text key of 300 bytes.
        let long_key = format!("79012c{}", hex::encode("x".repeat(300)));
        let bytes = map_hex(
            40,
            &["0701", "2102", "42abcd03", &format!("{}04", long_key)],
        );
        let tree = tree_of(&bytes);
        let mut keys = MapKeyIndex::default();
        for loc in [
            "/\"k0\"",
            "/\"k39\"",
            "/\"k40\"",
            "/7",
            "/0",
            "/41",
            "/43",
            "/44",
            "/Integer(-2)",
            "/h'abcd'",
            "/...",
            "/\"k1\"/0",
            "",
        ] {
            let searched = summary(locate_cbor_node(&tree, loc, bytes.len(), None));
            let indexed = summary(locate_cbor_node(&tree, loc, bytes.len(), Some(&mut keys)));
            assert_eq!(searched, indexed, "{}", loc);
        }
        assert_eq!(keys.maps.len(), 1);
        // An indefinite-length text key leaves the map's text keys to the
        // search; its integer keys and positions are still indexed.
        let chunked = map_hex(20, &["7f616b6178ff05", "0901"]);
        let tree = tree_of(&chunked);
        let mut keys = MapKeyIndex::default();
        for loc in ["/\"kx\"", "/\"k3\"", "/9", "/2"] {
            assert_eq!(
                summary(locate_cbor_node(&tree, loc, chunked.len(), None)),
                summary(locate_cbor_node(&tree, loc, chunked.len(), Some(&mut keys))),
                "{}",
                loc
            );
        }
        assert!(keys.maps.values().all(|m| m.text.is_none()));
    }

    /// The path is resolved against the document only for the components
    /// that name an entry by position or by nothing: a location without
    /// one looks nothing up.
    #[test]
    fn a_path_resolves_only_positional_components() {
        let long_key = format!("79012c{}", hex::encode("x".repeat(300)));
        let bytes = map_hex(20, &[&format!("{}f6", long_key)]);
        let tree = tree_of(&bytes);
        let mut keys = MapKeyIndex::default();
        assert_eq!(json_path_in_tree(&tree, "/\"k3\"", &mut keys), "$.k3");
        assert_eq!(
            json_path_in_tree(&Value::Null, "/\"k3\"/\"x\"", &mut keys),
            "$.k3.x"
        );
        assert!(keys.maps.is_empty());
        // The entry at position 20 is the long text key: written out.
        let path = json_path_in_tree(&tree, "/20", &mut keys);
        assert_eq!(path, format!("$.{}", "x".repeat(300)));
        assert_eq!(keys.maps.len(), 1);
    }

    /// Integer and text comparisons of decoded keys, including a text of
    /// indefinite length and an integer past 64 bits.
    #[test]
    fn decoded_keys_compare_without_copying() {
        let text_is = |node: &Value, want: &str| {
            diagnostic::string_payload_is(node, "String", "IndefiniteLengthString", want)
        };
        let chunked = tree_of(&hex::decode("7f61616162ff").unwrap());
        assert!(text_is(&chunked, "ab"));
        assert!(!text_is(&chunked, "a"));
        assert!(!text_is(&chunked, "abc"));
        let definite = tree_of(&hex::decode("626162").unwrap());
        assert!(text_is(&definite, "ab"));
        assert!(!diagnostic::string_payload_is(
            &definite,
            "Bytes",
            "IndefiniteLengthBytes",
            "ab"
        ));
        let big = tree_of(&hex::decode("3bffffffffffffffff").unwrap());
        assert!(diagnostic::int_node_is(&big, -18446744073709551616));
        assert!(!diagnostic::int_node_is(&big, -1));
        let max = tree_of(&hex::decode("1bffffffffffffffff").unwrap());
        assert!(diagnostic::int_node_is(&max, u64::MAX as i128));
        assert!(diagnostic::int_node_is(&tree_of(&[0x20]), -1));
        assert!(!diagnostic::int_node_is(&definite, 0));
    }
}

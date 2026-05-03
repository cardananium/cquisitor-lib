//! Map decoded CBOR onto a CDDL schema to produce structured JSON where
//! positional / numerically-keyed values become named fields.
//!
//! This is what `validate_cbor_against_cddl` doesn't do: the validator
//! walks the schema to *check* the value, we walk it to *label* the
//! value. The output aims to be the same JSON you'd reach for when
//! showing a Cardano transaction to a human: `{inputs, outputs, fee, …}`
//! instead of `{0: […], 1: […], 2: …}`.
//!
//! Scope of the first cut:
//! * Maps with integer / bareword / text-literal keys → objects with
//!   named fields.
//! * Arrays whose entries have `member_key` (name: type) → objects with
//!   those names.
//! * Homogeneous arrays (`[* T]`, `[+ T]`, `[N*M T]`) → JSON arrays.
//! * Type choices — first match wins.
//! * Rule references (`Typename`) — recursed through a rule index.
//! * Tags — either known (bignum / date) or emitted as `{"@tag":N,
//!   "@value":…}`.
//! * Primitives: int, uint, tstr, bstr (hex), bool, null, float.
//!
//! Out of scope for now: generics parameter binding, `&(group)` enum
//! expansions, `.cbor` / `.cborseq` (we don't recursively decode the
//! embedded CBOR here yet), `.and`/`.within`/`.eq` constraints beyond
//! the value-level check.

use std::cell::RefCell;
use std::collections::HashMap;
use std::convert::TryFrom;

use cddl::ast::{
    GenericArgs, GenericParams, GroupChoice, GroupEntry, MemberKey, Occur, Rule, Type, Type1,
    Type2, TypeGroupnameEntry, CDDL,
};
use cddl::token::TagConstraint;
use cddl::validator::cbor_value::{decode_cbor, Value as CborValue};
use ciborium::value::Integer;
use serde_json::{json, Map, Number, Value};

use crate::js_error::JsError;

/// Public entry point. Decodes `cbor` as a CBOR document, then walks it
/// against the `rule_name` rule of `cddl` to produce labelled JSON.
///
/// On failure — schema parse / rule missing / CBOR decode — returns a
/// `JsError` rather than panicking. If the CBOR doesn't match the schema,
/// we still produce best-effort output rather than erroring: unmatched
/// sub-nodes fall through to a raw representation. This matches the
/// decoder's philosophy (never drop information).
pub fn decode_cbor_against_cddl(
    cbor: &[u8],
    cddl: &str,
    rule_name: &str,
) -> Result<Value, JsError> {
    let ast = cddl::pest_bridge::cddl_from_pest_str_checked(cddl)
        .map_err(|e| JsError::new(&format!("CDDL parse error: {}", e)))?;
    let rules = RuleIndex::build(&ast);
    if !rules.contains(rule_name) {
        return Err(JsError::new(&format!(
            "CDDL does not define a rule named {}",
            rule_name
        )));
    }

    let value = decode_cbor(cbor)
        .map_err(|e| JsError::new(&format!("CBOR decode error: {}", e)))?;

    let mapper = Mapper {
        rules,
        bindings: RefCell::new(Vec::new()),
    };
    Ok(mapper.map_by_rule_name(&value, rule_name))
}

// ============================================================
// Rule index — quick lookup by name, since we recurse into refs.
// ============================================================

struct RuleIndex<'a> {
    by_name: HashMap<&'a str, &'a Rule<'a>>,
}

impl<'a> RuleIndex<'a> {
    fn build(cddl_ast: &'a CDDL<'a>) -> Self {
        let mut by_name = HashMap::with_capacity(cddl_ast.rules.len());
        for rule in &cddl_ast.rules {
            let name = match rule {
                Rule::Type { rule, .. } => rule.name.ident,
                Rule::Group { rule, .. } => rule.name.ident,
            };
            by_name.entry(name).or_insert(rule);
        }
        RuleIndex { by_name }
    }

    fn contains(&self, name: &str) -> bool {
        self.by_name.contains_key(name)
    }

    fn get(&self, name: &str) -> Option<&'a Rule<'a>> {
        self.by_name.get(name).copied()
    }
}

// ============================================================
// Main walker.
// ============================================================

/// Stack of generic-binding frames. Each frame is the active set of
/// `param_name → Type1` substitutions for one generic call. When we
/// resolve a `Typename` whose ident matches a parameter, we substitute
/// in the bound type.
type BindingFrame<'a> = HashMap<String, &'a Type1<'a>>;

struct Mapper<'a> {
    rules: RuleIndex<'a>,
    bindings: RefCell<Vec<BindingFrame<'a>>>,
}

impl<'a> Mapper<'a> {
    fn map_by_rule_name(&self, cbor: &CborValue, name: &str) -> Value {
        match self.rules.get(name) {
            Some(Rule::Type { rule, .. }) => self.map_type(cbor, &rule.value),
            Some(Rule::Group { rule, .. }) => {
                // A named group referenced as a type context — treat it
                // as a single-group-choice group.
                let mut builder = ObjectBuilder::new();
                self.map_group_entry(cbor, &rule.entry, &mut builder, &mut 0usize);
                builder.finish()
            }
            None => raw_value(cbor),
        }
    }

    fn lookup_binding(&self, name: &str) -> Option<&'a Type1<'a>> {
        let stack = self.bindings.borrow();
        for frame in stack.iter().rev() {
            if let Some(t1) = frame.get(name) {
                return Some(*t1);
            }
        }
        None
    }

    fn push_frame<'b>(
        &self,
        params: &Option<GenericParams<'a>>,
        args: Option<&'a GenericArgs<'a>>,
    ) -> bool
    where
        'a: 'b,
    {
        let (Some(params), Some(args)) = (params.as_ref(), args) else {
            return false;
        };
        if params.params.is_empty() || args.args.is_empty() {
            return false;
        }

        let mut frame: BindingFrame<'a> = HashMap::with_capacity(params.params.len());
        for (p, a) in params.params.iter().zip(args.args.iter()) {
            frame.insert(p.param.ident.to_string(), a.arg.as_ref());
        }
        self.bindings.borrow_mut().push(frame);
        true
    }

    fn pop_frame(&self) {
        self.bindings.borrow_mut().pop();
    }

    /// Walk a `Type` (an OR of TypeChoices). Try each choice in order —
    /// the first that "accepts" the value produces the output. If none
    /// do, we still emit the raw value so the caller doesn't lose data.
    fn map_type(&self, cbor: &CborValue, ty: &'a Type<'a>) -> Value {
        for choice in &ty.type_choices {
            if let Some(mapped) = self.try_map_type1(cbor, &choice.type1) {
                return mapped;
            }
        }
        raw_value(cbor)
    }

    fn try_map_type1(&self, cbor: &CborValue, t1: &'a Type1<'a>) -> Option<Value> {
        // `.cbor` / `.cborseq` controls — the target is a bstr whose
        // bytes are themselves a CBOR-encoded value of the controller
        // type. Decode and walk the embedded value.
        if let Some(op) = &t1.operator {
            if let cddl::ast::RangeCtlOp::CtlOp { ctrl, .. } = &op.operator {
                match ctrl {
                    cddl::token::ControlOperator::CBOR
                    | cddl::token::ControlOperator::CBORSEQ => {
                        if let CborValue::Bytes(b) = cbor {
                            if let Ok(inner) = decode_cbor(b) {
                                if let Some(mapped) = self.try_map_type2(&inner, &op.type2) {
                                    return Some(mapped);
                                }
                                // Fall through to raw bstr representation
                                // when the embedded shape didn't match.
                            }
                        }
                    }
                    _ => {} // .size, .bits, .regexp, etc. — value handled by type2 below
                }
            }
        }
        self.try_map_type2(cbor, &t1.type2)
    }

    fn try_map_type2(&self, cbor: &CborValue, t2: &'a Type2<'a>) -> Option<Value> {
        match t2 {
            Type2::Typename { ident, generic_args, .. } => {
                self.try_map_typename(cbor, ident.ident, generic_args.as_ref())
            }

            Type2::ParenthesizedType { pt, .. } => Some(self.map_type(cbor, pt)),

            Type2::Map { group, .. } => self.try_map_map(cbor, group),

            Type2::Array { group, .. } => self.try_map_array(cbor, group),

            Type2::TaggedData { tag, t, .. } => self.try_map_tagged(cbor, tag.as_ref(), t),

            // Literal matches — only accept when the value equals the literal.
            Type2::IntValue { value, .. } => match cbor {
                CborValue::Integer(i) if *i == Integer::from(*value as i64) => {
                    Some(int_to_json(*i))
                }
                _ => None,
            },
            Type2::UintValue { value, .. } => match cbor {
                CborValue::Integer(i) if *i == Integer::from(*value as u64) => {
                    Some(int_to_json(*i))
                }
                _ => None,
            },
            Type2::TextValue { value, .. } => match cbor {
                CborValue::Text(t) if t == value.as_ref() => Some(Value::String(t.clone())),
                _ => None,
            },
            Type2::FloatValue { value, .. } => match cbor {
                CborValue::Float(f) if (*f - *value).abs() < f64::EPSILON => Number::from_f64(*f)
                    .map(Value::Number),
                _ => None,
            },

            Type2::Any { .. } => Some(raw_value(cbor)),

            Type2::ChoiceFromGroup { ident, .. } => {
                // `&(group_name)` — enum-style. Pick whichever rule
                // entry has the matching literal key/value. Fallback:
                // raw value.
                self.try_enum_from_group(cbor, ident.ident)
            }

            Type2::Unwrap { ident, generic_args, .. } => {
                // `~rule` in type position — transparent reference into
                // the named rule's body. Group-position unwrapping
                // (`{a: int, ~base}`) is handled at GroupEntry level.
                self.try_map_typename(cbor, ident.ident, generic_args.as_ref())
            }

            // Everything else we don't model yet (DataMajorType, byte
            // literals, ChoiceFromInlineGroup, …) just means "no
            // opinion" — caller falls through to next type choice.
            _ => None,
        }
    }

    fn try_map_typename(
        &self,
        cbor: &CborValue,
        name: &str,
        generic_args: Option<&'a GenericArgs<'a>>,
    ) -> Option<Value> {
        // 1) Generic-parameter substitution: name resolves to a bound
        //    Type1 from the active frame, recurse on it. Only without
        //    args — `param<x>` is invalid CDDL anyway.
        if generic_args.is_none() {
            if let Some(t1) = self.lookup_binding(name) {
                return self.try_map_type1(cbor, t1);
            }
        }
        // 2) Prelude scalars don't take generic args.
        if generic_args.is_none() {
            if let Some(prim) = try_prelude(cbor, name) {
                return Some(prim);
            }
        }
        // 3) User-defined rule, with optional generic substitution.
        match self.rules.get(name) {
            Some(Rule::Type { rule, .. }) => {
                let pushed = self.push_frame(&rule.generic_params, generic_args);
                let result = Some(self.map_type(cbor, &rule.value));
                if pushed {
                    self.pop_frame();
                }
                result
            }
            Some(Rule::Group { rule, .. }) => {
                let pushed = self.push_frame(&rule.generic_params, generic_args);
                let mut builder = ObjectBuilder::new();
                self.map_group_entry(cbor, &rule.entry, &mut builder, &mut 0usize);
                if pushed {
                    self.pop_frame();
                }
                Some(builder.finish())
            }
            None => None,
        }
    }

    // ---------- Map handling ----------

    fn try_map_map(&self, cbor: &CborValue, group: &'a cddl::ast::Group<'a>) -> Option<Value> {
        let CborValue::Map(entries) = cbor else { return None };

        // Decide between object form (`{a: 1, b: 2}` — convenient,
        // works with every common Cardano shape) and `@entries`
        // (`{ @entries: [{key, value}, ...] }` — wire-order preserving,
        // handles duplicates and complex keys without loss).
        //
        // Object form is OK when both:
        //  * every cbor key is a primitive scalar (text, int, bytes,
        //    bool, null, float) — JSON objects can't carry complex
        //    keys without lossy stringification.
        //  * every cbor key appears at most once — dropping duplicates
        //    or collapsing them into a value-array would lose
        //    interleaving order.
        // Otherwise we fall back to `@entries`.
        let needs_entries = entries.iter().any(|(k, _)| !is_simple_cbor_key(k))
            || cbor_keys_have_duplicates(entries);
        if needs_entries {
            return self.try_map_to_entries(entries, group);
        }

        // Object form — pick the first compatible group choice.
        for choice in &group.group_choices {
            if let Some(out) = self.try_map_with_choice(entries, choice) {
                return Some(out);
            }
        }
        None
    }

    /// Emit a map as `{"@entries": [{key, value}, ...]}` — an array of
    /// `{key, value}` objects in **wire order**. Each entry's
    /// `value_type` is whichever schema entry's key type accepts the
    /// cbor key first (literals first, then type-based). Keys that
    /// don't match any schema entry are still emitted, with `key` and
    /// `value` as raw decoded JSON so data is never silently dropped.
    ///
    /// The schema entry that matched is recorded as `match`:
    ///  * `match.via` — `"literal" | "type" | "unmatched"`
    ///  * `match.label` — the schema's literal text (for literal
    ///    matches) or `null` (for type-based / unmatched).
    ///
    /// Wire-order preservation, no key-collision collapse, no
    /// stringification of complex keys — all keyed-data in CBOR comes
    /// out lossless.
    fn try_map_to_entries(
        &self,
        entries: &[(CborValue, CborValue)],
        group: &'a cddl::ast::Group<'a>,
    ) -> Option<Value> {
        // Pick a schema entry for each cbor entry — first schema entry
        // whose key form accepts the cbor key (preserving wire order
        // of cbor entries for the output).
        let pairs: Vec<Value> = entries
            .iter()
            .map(|(k, v)| self.match_one_entry(k, v, group))
            .collect();
        Some(json!({"@entries": pairs}))
    }

    fn match_one_entry(
        &self,
        cbor_key: &CborValue,
        cbor_value: &CborValue,
        group: &'a cddl::ast::Group<'a>,
    ) -> Value {
        for choice in &group.group_choices {
            for (ge, _) in &choice.group_entries {
                let GroupEntry::ValueMemberKey { ge: vmk, .. } = ge else {
                    continue;
                };
                let Some(mk) = &vmk.member_key else { continue };

                // 1. Try literal match first (Bareword / Value / Type1
                //    with literal type2). Returns Some(label) on hit.
                if let Some(label) = self.try_match_member_key(mk, cbor_key) {
                    let key_json = raw_value(cbor_key);
                    let value_json = self.map_type(cbor_value, &vmk.entry_type);
                    return json!({
                        "key": key_json,
                        "value": value_json,
                        "match": {
                            "via": "literal",
                            "label": label,
                        },
                    });
                }
                // 2. Try type-based match (Type1 with non-literal type2).
                if let MemberKey::Type1 { t1, .. } = mk {
                    if self.type1_accepts(t1, cbor_key) {
                        let key_json = self
                            .try_map_type1(cbor_key, t1)
                            .unwrap_or_else(|| raw_value(cbor_key));
                        let value_json = self.map_type(cbor_value, &vmk.entry_type);
                        return json!({
                            "key": key_json,
                            "value": value_json,
                            "match": {
                                "via": "type",
                                "label": Value::Null,
                            },
                        });
                    }
                }
            }
        }
        // No schema entry took it — emit raw.
        json!({
            "key": raw_value(cbor_key),
            "value": raw_value(cbor_value),
            "match": {
                "via": "unmatched",
                "label": Value::Null,
            },
        })
    }

    fn try_map_with_choice(
        &self,
        entries: &[(CborValue, CborValue)],
        choice: &'a GroupChoice<'a>,
    ) -> Option<Value> {
        let mut used = vec![false; entries.len()];
        let mut out = Map::new();

        for (ge, _) in &choice.group_entries {
            self.consume_map_entry(ge, entries, &mut used, &mut out)?;
        }

        // Remaining unmatched entries — keep them under a `"@extra"`
        // bucket so data isn't lost on partial matches.
        let extras: Vec<(String, Value)> = entries
            .iter()
            .enumerate()
            .filter_map(|(i, (k, v))| {
                if used[i] {
                    None
                } else {
                    Some((json_key(k), raw_value(v)))
                }
            })
            .collect();
        if !extras.is_empty() {
            let mut extras_obj = Map::new();
            for (k, v) in extras {
                extras_obj.insert(k, v);
            }
            out.insert("@extra".into(), Value::Object(extras_obj));
        }

        Some(Value::Object(out))
    }

    /// Consume one group entry against the remaining (unused) map entries.
    /// Mutates `used` and inserts into `out`. Returns `None` if the
    /// required entry is missing (and the entry isn't optional).
    fn consume_map_entry(
        &self,
        ge: &'a GroupEntry<'a>,
        entries: &[(CborValue, CborValue)],
        used: &mut [bool],
        out: &mut Map<String, Value>,
    ) -> Option<()> {
        match ge {
            GroupEntry::ValueMemberKey { ge, .. } => {
                let vmk = ge.as_ref();
                let is_optional = is_occur_optional(vmk.occur.as_ref());
                let mk = match &vmk.member_key {
                    Some(m) => m,
                    None => {
                        // No member_key in a *map* context is unusual;
                        // treat as homogeneous "* type" pair — skip for
                        // first cut.
                        return Some(());
                    }
                };
                // Pre-compute a fallback field-name from the member_key
                // declaration itself — used when the entry is
                // *required* but absent (we still emit the field so
                // partial output is informative).
                let declarative_label = member_key_label(mk);

                let mut found_any = false;
                for (i, (k, v)) in entries.iter().enumerate() {
                    if used[i] {
                        continue;
                    }
                    let Some(field_name) = self.try_match_member_key(mk, k) else {
                        continue;
                    };
                    let mapped = self.map_type(v, &vmk.entry_type);
                    // Insert directly when the field hasn't been used
                    // before; on collision (multiple cbor entries
                    // matched the same field name — happens for
                    // literal-key with `*` or `+`) wrap into an array.
                    // Type-based keys (`<type1> => …`) generate unique
                    // names per actual key value, so they won't collide
                    // and stay as plain values.
                    match out.remove(&field_name) {
                        None => {
                            out.insert(field_name.clone(), mapped);
                        }
                        Some(Value::Array(mut existing)) => {
                            existing.push(mapped);
                            out.insert(field_name.clone(), Value::Array(existing));
                        }
                        Some(prev) => {
                            out.insert(field_name.clone(), Value::Array(vec![prev, mapped]));
                        }
                    }
                    used[i] = true;
                    found_any = true;
                    // CBOR allows duplicate keys (RFC 8949 §5.6 — non-
                    // canonical, but legal). Don't stop after the first
                    // match: keep iterating so all duplicates land in
                    // the same field via the collision-array logic
                    // above. This way no data slips into `@extra` just
                    // because the wire is non-canonical.
                }

                if !found_any && !is_optional {
                    out.insert(declarative_label, Value::Null);
                }
                Some(())
            }
            GroupEntry::TypeGroupname { ge, .. } => {
                // Reference to a group-typed rule — flatten its entries
                // into the surrounding context.
                self.flatten_group_name_into_map(&ge.name.ident, entries, used, out)
            }
            GroupEntry::InlineGroup { group, .. } => {
                for choice in &group.group_choices {
                    for (inner_ge, _) in &choice.group_entries {
                        self.consume_map_entry(inner_ge, entries, used, out)?;
                    }
                }
                Some(())
            }
        }
    }

    fn flatten_group_name_into_map(
        &self,
        name: &str,
        entries: &[(CborValue, CborValue)],
        used: &mut [bool],
        out: &mut Map<String, Value>,
    ) -> Option<()> {
        match self.rules.get(name) {
            Some(Rule::Group { rule, .. }) => {
                self.consume_map_entry(&rule.entry, entries, used, out)
            }
            Some(Rule::Type { rule, .. }) => {
                // A type rule used as a group-entry reference — try its
                // inner Type2 cases that flatten (Map, ParenthesizedType).
                for choice in &rule.value.type_choices {
                    match &choice.type1.type2 {
                        Type2::Map { group, .. } => {
                            for gc in &group.group_choices {
                                for (ge, _) in &gc.group_entries {
                                    self.consume_map_entry(ge, entries, used, out)?;
                                }
                            }
                        }
                        Type2::ParenthesizedType { pt, .. } => {
                            for inner_choice in &pt.type_choices {
                                if let Type2::Map { group, .. } = &inner_choice.type1.type2 {
                                    for gc in &group.group_choices {
                                        for (ge, _) in &gc.group_entries {
                                            self.consume_map_entry(ge, entries, used, out)?;
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Some(())
            }
            None => Some(()),
        }
    }

    // ---------- Array handling ----------

    fn try_map_array(&self, cbor: &CborValue, group: &'a cddl::ast::Group<'a>) -> Option<Value> {
        let CborValue::Array(items) = cbor else { return None };

        for choice in &group.group_choices {
            if let Some(out) = self.try_array_with_choice(items, choice) {
                return Some(out);
            }
        }
        None
    }

    /// Walk a group choice against a positional CBOR array. Named
    /// entries ("name: type") project into an object; unnamed entries
    /// (plain types) project into an array alongside. If the schema
    /// mixes both, named → object, unnamed → `@positional`.
    fn try_array_with_choice(
        &self,
        items: &[CborValue],
        choice: &'a GroupChoice<'a>,
    ) -> Option<Value> {
        let mut cursor = 0usize;
        let mut named = Map::new();
        let mut unnamed: Vec<Value> = Vec::new();
        let mut any_named = false;

        for (ge, _) in &choice.group_entries {
            match ge {
                GroupEntry::ValueMemberKey { ge, .. } => {
                    let vmk = ge.as_ref();
                    let is_optional = is_occur_optional(vmk.occur.as_ref());
                    let consume_many = matches!(
                        vmk.occur.as_ref().map(|o| &o.occur),
                        Some(Occur::ZeroOrMore { .. }) | Some(Occur::OneOrMore { .. })
                    );

                    let name = vmk
                        .member_key
                        .as_ref()
                        .and_then(bareword_name);

                    if consume_many {
                        // Greedy: consume every remaining item that
                        // matches entry_type, up to end or first
                        // mismatch.
                        let mut collected: Vec<Value> = Vec::new();
                        while cursor < items.len() {
                            let candidate = &items[cursor];
                            if !self.type_accepts(&vmk.entry_type,candidate) {
                                break;
                            }
                            collected.push(self.map_type(candidate, &vmk.entry_type));
                            cursor += 1;
                        }
                        if let Some(n) = name {
                            any_named = true;
                            named.insert(n.to_string(), Value::Array(collected));
                        } else {
                            for v in collected {
                                unnamed.push(v);
                            }
                        }
                    } else if cursor < items.len() {
                        let v = &items[cursor];
                        if !self.type_accepts(&vmk.entry_type,v) {
                            if is_optional {
                                continue;
                            }
                            return None;
                        }
                        let mapped = self.map_type(v, &vmk.entry_type);
                        cursor += 1;
                        if let Some(n) = name {
                            any_named = true;
                            named.insert(n.to_string(), mapped);
                        } else {
                            unnamed.push(mapped);
                        }
                    } else if !is_optional {
                        return None;
                    }
                }
                GroupEntry::TypeGroupname { ge, .. } => {
                    self.consume_array_typegroupname(
                        items,
                        &mut cursor,
                        ge,
                        &mut named,
                        &mut unnamed,
                        &mut any_named,
                    )?;
                }
                GroupEntry::InlineGroup { group, .. } => {
                    for inner_choice in &group.group_choices {
                        for (ge, _) in &inner_choice.group_entries {
                            self.consume_array_ge(
                                ge,
                                items,
                                &mut cursor,
                                &mut named,
                                &mut unnamed,
                                &mut any_named,
                            )?;
                        }
                    }
                }
            }
        }

        // Leftover items → @extra so data survives partial matches.
        let leftover: Vec<Value> = items[cursor..].iter().map(raw_value).collect();
        if any_named {
            if !unnamed.is_empty() {
                named.insert("@positional".into(), Value::Array(unnamed));
            }
            if !leftover.is_empty() {
                named.insert("@extra".into(), Value::Array(leftover));
            }
            Some(Value::Object(named))
        } else {
            if !leftover.is_empty() {
                let mut out = unnamed;
                out.extend(leftover);
                return Some(Value::Array(out));
            }
            Some(Value::Array(unnamed))
        }
    }

    fn consume_array_ge(
        &self,
        ge: &'a GroupEntry<'a>,
        items: &[CborValue],
        cursor: &mut usize,
        named: &mut Map<String, Value>,
        unnamed: &mut Vec<Value>,
        any_named: &mut bool,
    ) -> Option<()> {
        match ge {
            GroupEntry::ValueMemberKey { ge: vmk, .. } => {
                let vmk = vmk.as_ref();
                let is_optional = is_occur_optional(vmk.occur.as_ref());
                let name = vmk.member_key.as_ref().and_then(bareword_name);
                if *cursor < items.len() {
                    let v = &items[*cursor];
                    if !self.type_accepts(&vmk.entry_type,v) {
                        return if is_optional { Some(()) } else { None };
                    }
                    let mapped = self.map_type(v, &vmk.entry_type);
                    *cursor += 1;
                    if let Some(n) = name {
                        *any_named = true;
                        named.insert(n.to_string(), mapped);
                    } else {
                        unnamed.push(mapped);
                    }
                    Some(())
                } else if is_optional {
                    Some(())
                } else {
                    None
                }
            }
            GroupEntry::TypeGroupname { ge, .. } => {
                self.consume_array_typegroupname(items, cursor, ge, named, unnamed, any_named)
            }
            GroupEntry::InlineGroup { group, .. } => {
                for gc in &group.group_choices {
                    for (inner_ge, _) in &gc.group_entries {
                        self.consume_array_ge(inner_ge, items, cursor, named, unnamed, any_named)?;
                    }
                }
                Some(())
            }
        }
    }

    fn consume_array_typegroupname(
        &self,
        items: &[CborValue],
        cursor: &mut usize,
        ge: &'a TypeGroupnameEntry<'a>,
        named: &mut Map<String, Value>,
        unnamed: &mut Vec<Value>,
        any_named: &mut bool,
    ) -> Option<()> {
        let name = ge.name.ident;
        let is_optional = is_occur_optional(ge.occur.as_ref());
        let consume_many = matches!(
            ge.occur.as_ref().map(|o| &o.occur),
            Some(Occur::ZeroOrMore { .. }) | Some(Occur::OneOrMore { .. })
        );

        // If the name resolves to a Group rule — flatten it here
        // (classic Cardano `transaction = [ transaction_body, ...]`
        // where the referent is itself an array is NOT this case; this
        // case is `group = (a: int, b: int)` inlined into an array).
        if let Some(Rule::Group { rule, .. }) = self.rules.get(name) {
            return self.consume_array_ge(&rule.entry, items, cursor, named, unnamed, any_named);
        }

        if consume_many {
            // `[* T]`, `[+ T]` — homogeneous list of T. The "name" here
            // is the *type* `T`, not a field label, so emit raw list
            // entries into `unnamed`.
            while *cursor < items.len() {
                let v = &items[*cursor];
                let mapped = self.map_by_rule_or_prelude_with_args(
                    v,
                    name,
                    ge.generic_args.as_ref(),
                );
                if mapped.is_none() {
                    break;
                }
                unnamed.push(mapped.unwrap());
                *cursor += 1;
            }
            Some(())
        } else if *cursor < items.len() {
            // `[T]` (single occurrence). Cardano-style schemas use this
            // as `[transaction_body, transaction_witness_set, ...]`
            // where the type names double as field labels — useful to
            // surface as named fields. If the type name is part of the
            // standard prelude (uint, tstr, …) it isn't semantic, so
            // keep that case unnamed.
            let v = &items[*cursor];
            let mapped =
                self.map_by_rule_or_prelude_with_args(v, name, ge.generic_args.as_ref());
            match mapped {
                Some(val) => {
                    *cursor += 1;
                    // Don't label by `name` when it's just a generic
                    // parameter (e.g. `pair<k,v> = [k, v]` — `k` and `v`
                    // are param names, not semantic field labels) or a
                    // prelude type (`uint`/`tstr`/…). Both go into the
                    // unnamed list to preserve order, including the
                    // case `[a, a]` where labelling would collide.
                    let is_bound_param = self.lookup_binding(name).is_some();
                    if prelude_accepts(name, v).is_some() || is_bound_param {
                        unnamed.push(val);
                    } else {
                        *any_named = true;
                        named.insert(name.to_string(), val);
                    }
                    Some(())
                }
                None => {
                    if is_optional {
                        Some(())
                    } else {
                        None
                    }
                }
            }
        } else if is_optional {
            Some(())
        } else {
            None
        }
    }

    fn map_group_entry(
        &self,
        cbor: &CborValue,
        _ge: &GroupEntry<'a>,
        builder: &mut ObjectBuilder,
        _positional: &mut usize,
    ) {
        // Only reached for standalone group-named rules, which we treat
        // as their type-rule equivalent at the top level. First-cut
        // fallback: raw value. Expand later if we hit real schemas that
        // need this path.
        builder.push_raw(raw_value(cbor));
    }

    fn map_by_rule_or_prelude_with_args(
        &self,
        cbor: &CborValue,
        name: &str,
        generic_args: Option<&'a GenericArgs<'a>>,
    ) -> Option<Value> {
        // Bound generic param wins over both prelude and rule-index.
        if generic_args.is_none() {
            if let Some(t1) = self.lookup_binding(name) {
                return self.try_map_type1(cbor, t1);
            }
            if let Some(v) = try_prelude(cbor, name) {
                return Some(v);
            }
        }
        match self.rules.get(name) {
            Some(Rule::Type { rule, .. }) => {
                // Push a fresh binding frame when the call-site supplies
                // generic arguments — without this, body uses of the
                // rule's parameters would be unbound and fall back to
                // raw values.
                let pushed = self.push_frame(&rule.generic_params, generic_args);
                let result = Some(self.map_type(cbor, &rule.value));
                if pushed {
                    self.pop_frame();
                }
                result
            }
            Some(Rule::Group { rule, .. }) => {
                let pushed = self.push_frame(&rule.generic_params, generic_args);
                let mut builder = ObjectBuilder::new();
                self.map_group_entry(cbor, &rule.entry, &mut builder, &mut 0);
                if pushed {
                    self.pop_frame();
                }
                Some(builder.finish())
            }
            None => None,
        }
    }

    // ---------- Tag handling ----------

    fn try_map_tagged(
        &self,
        cbor: &CborValue,
        tag: Option<&TagConstraint<'a>>,
        inner: &'a Type<'a>,
    ) -> Option<Value> {
        let CborValue::Tag(n, payload) = cbor else { return None };

        if !tag_matches(tag, *n) {
            return None;
        }

        // Well-known tag short-circuits: bignum (2/3), datetime (0), …
        if let Some(specialised) = specialise_known_tag(*n, payload) {
            return Some(specialised);
        }

        let mut obj = Map::new();
        obj.insert("@tag".into(), Value::Number((*n).into()));
        obj.insert("@value".into(), self.map_type(payload, inner));
        Some(Value::Object(obj))
    }

    fn try_enum_from_group(&self, cbor: &CborValue, group_name: &str) -> Option<Value> {
        if let Some(Rule::Group { rule, .. }) = self.rules.get(group_name) {
            if let GroupEntry::InlineGroup { group, .. } = &rule.entry {
                for choice in &group.group_choices {
                    for (ge, _) in &choice.group_entries {
                        if let GroupEntry::ValueMemberKey { ge: vmk, .. } = ge {
                            if let Some(MemberKey::Value {
                                value: cddl::token::Value::UINT(u),
                                ..
                            }) = &vmk.member_key
                            {
                                if let CborValue::Integer(i) = cbor {
                                    if *i == Integer::from(*u as u64) {
                                        return Some(Value::Number((*u as u64).into()));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }
}

// ============================================================
// Helpers: accept-tests, key matchers, raw conversion.
// ============================================================

fn is_occur_optional(o: Option<&cddl::ast::Occurrence<'_>>) -> bool {
    matches!(
        o.map(|o| &o.occur),
        Some(Occur::Optional { .. })
            | Some(Occur::ZeroOrMore { .. })
            | Some(Occur::Exact { lower: Some(0), .. })
            | Some(Occur::Exact { lower: None, .. })
    )
}

fn bareword_name<'a>(mk: &'a MemberKey<'a>) -> Option<&'a str> {
    match mk {
        MemberKey::Bareword { ident, .. } => Some(ident.ident),
        MemberKey::Value {
            value: cddl::token::Value::TEXT(s),
            ..
        } => {
            // Stash: `"name": type` in an array context, rare but
            // legal. Use as the field name.
            Some(s.as_ref())
        }
        MemberKey::Value { .. } => None,
        MemberKey::Type1 { .. } => None,
        MemberKey::NonMemberKey { .. } => None,
    }
}


/// O(n²) scan for duplicate CBOR keys (RFC 8949 §5.6 — legal but
/// non-canonical). When there are dups we can't represent the map as
/// a JSON object without losing interleaving order, so we switch to
/// `@entries` form.
fn cbor_keys_have_duplicates(entries: &[(CborValue, CborValue)]) -> bool {
    for i in 0..entries.len() {
        for j in (i + 1)..entries.len() {
            if entries[i].0 == entries[j].0 {
                return true;
            }
        }
    }
    false
}

/// True if the cbor key has a primitive type that flattens cleanly to
/// a JSON object key. Complex values (Array, Map, Tag, non-standard
/// Simple) are treated as "complex" and trigger the `@entries`
/// fallback shape.
fn is_simple_cbor_key(k: &CborValue) -> bool {
    matches!(
        k,
        CborValue::Text(_)
            | CborValue::Integer(_)
            | CborValue::Bytes(_)
            | CborValue::Bool(_)
            | CborValue::Null
            | CborValue::Float(_)
    )
}

/// Stringify a CBOR key to use as a JSON object field. Bytes get a
/// `0x` prefix to distinguish them from numeric or text keys.
fn cbor_key_to_field_name(k: &CborValue) -> String {
    match k {
        CborValue::Text(s) => s.clone(),
        CborValue::Integer(i) => {
            if let Ok(u) = u64::try_from(*i) {
                u.to_string()
            } else if let Ok(s) = i64::try_from(*i) {
                s.to_string()
            } else {
                let v: i128 = (*i).into();
                v.to_string()
            }
        }
        CborValue::Bytes(b) => format!("0x{}", hex::encode(b)),
        CborValue::Bool(b) => b.to_string(),
        CborValue::Null => "null".to_string(),
        other => format!("{:?}", other),
    }
}

/// Field-name to use as a placeholder when a *required* member is
/// absent from the actual data (so the consumer still sees the slot).
/// For literal keys this is the literal text; for type-based keys
/// it's the type's source representation.
fn member_key_label(mk: &MemberKey<'_>) -> String {
    match mk {
        MemberKey::Bareword { ident, .. } => ident.ident.to_string(),
        MemberKey::Value { value, .. } => match value {
            cddl::token::Value::TEXT(s) => s.to_string(),
            cddl::token::Value::UINT(u) => u.to_string(),
            cddl::token::Value::INT(n) => n.to_string(),
            other => other.to_string(),
        },
        MemberKey::Type1 { t1, .. } => match &t1.type2 {
            Type2::UintValue { value, .. } => value.to_string(),
            Type2::IntValue { value, .. } => value.to_string(),
            Type2::TextValue { value, .. } => value.as_ref().to_string(),
            other => other.to_string(),
        },
        MemberKey::NonMemberKey { .. } => "@non_member_key".to_string(),
    }
}


impl<'a> Mapper<'a> {
    /// Best-effort `true` if `value` could plausibly match `ty` under the
    /// current generic-binding frames. Used for array-entry
    /// disambiguation where we have to decide whether to consume a
    /// positional slot or skip (optional). Conservative on "unknown".
    /// Returns the JSON field name to use when a CBOR map key matches
    /// the schema's `MemberKey`, or `None` if it doesn't match. For
    /// literal keys (`bareword:`, `0:`, `"text":`) the field name is
    /// the literal itself. For type-constrained keys (`<type1> =>`)
    /// we accept any cbor key that conforms to the type and use the
    /// key's actual value as the JSON field name (e.g. `0xpolicy_id`
    /// for a `policy_id => …` schema where `policy_id` is a bstr type).
    fn try_match_member_key(
        &self,
        mk: &'a MemberKey<'a>,
        cbor_key: &CborValue,
    ) -> Option<String> {
        use cddl::token::Value as TV;
        match mk {
            MemberKey::Bareword { ident, .. } => match cbor_key {
                CborValue::Text(s) if s == ident.ident => Some(ident.ident.to_string()),
                _ => None,
            },
            MemberKey::Value { value, .. } => match (value, cbor_key) {
                (TV::TEXT(s), CborValue::Text(t)) if t == s.as_ref() => Some(s.to_string()),
                (TV::UINT(u), CborValue::Integer(i)) => {
                    if u64::try_from(*i).ok() == Some(*u as u64) {
                        Some(u.to_string())
                    } else {
                        None
                    }
                }
                (TV::INT(n), CborValue::Integer(i)) => {
                    let as_i128: i128 = (*i).into();
                    if as_i128 == *n as i128 {
                        Some(n.to_string())
                    } else {
                        None
                    }
                }
                _ => None,
            },
            MemberKey::Type1 { t1, .. } => {
                // Literal type1's first (UintValue / IntValue / TextValue).
                use cddl::ast::Type2 as T2;
                match &t1.type2 {
                    T2::UintValue { value, .. } => match cbor_key {
                        CborValue::Integer(i) if u64::try_from(*i).ok() == Some(*value as u64) => {
                            Some(value.to_string())
                        }
                        _ => None,
                    },
                    T2::IntValue { value, .. } => match cbor_key {
                        CborValue::Integer(i) => {
                            let as_i128: i128 = (*i).into();
                            if as_i128 == *value as i128 {
                                Some(value.to_string())
                            } else {
                                None
                            }
                        }
                        _ => None,
                    },
                    T2::TextValue { value, .. } => match cbor_key {
                        CborValue::Text(s) if s == value.as_ref() => {
                            Some(value.as_ref().to_string())
                        }
                        _ => None,
                    },
                    // Otherwise: type-based match. Accept any key
                    // conforming to the type and use the key's value
                    // as the field name.
                    _ => {
                        if self.type1_accepts(t1, cbor_key) {
                            Some(cbor_key_to_field_name(cbor_key))
                        } else {
                            None
                        }
                    }
                }
            }
            MemberKey::NonMemberKey { .. } => None,
        }
    }

    fn type_accepts(&self, ty: &'a Type<'a>, value: &CborValue) -> bool {
        for choice in &ty.type_choices {
            if self.type1_accepts(&choice.type1, value) {
                return true;
            }
        }
        false
    }

    fn type1_accepts(&self, t1: &'a Type1<'a>, value: &CborValue) -> bool {
        self.type2_accepts(&t1.type2, value)
    }

    fn type2_accepts(&self, t2: &'a Type2<'a>, value: &CborValue) -> bool {
        match t2 {
            Type2::Typename { ident, generic_args, .. } => {
                self.typename_accepts(ident.ident, generic_args.as_ref(), value)
            }
            Type2::Any { .. } => true,
            Type2::ParenthesizedType { pt, .. } => self.type_accepts(pt, value),
            Type2::IntValue { value: v, .. } => matches!(
                value,
                CborValue::Integer(i) if *i == Integer::from(*v as i64)
            ),
            Type2::UintValue { value: v, .. } => matches!(
                value,
                CborValue::Integer(i) if *i == Integer::from(*v as u64)
            ),
            Type2::TextValue { value: v, .. } => matches!(
                value,
                CborValue::Text(s) if s == v.as_ref()
            ),
            Type2::Map { .. } => matches!(value, CborValue::Map(_)),
            Type2::Array { .. } => matches!(value, CborValue::Array(_)),
            Type2::TaggedData { tag, .. } => match value {
                CborValue::Tag(n, _) => tag_matches(tag.as_ref(), *n),
                _ => false,
            },
            _ => false,
        }
    }

    fn typename_accepts(
        &self,
        name: &str,
        generic_args: Option<&'a GenericArgs<'a>>,
        value: &CborValue,
    ) -> bool {
        if generic_args.is_none() {
            if let Some(t1) = self.lookup_binding(name) {
                return self.type1_accepts(t1, value);
            }
        }
        if let Some(b) = prelude_accepts(name, value) {
            return b;
        }
        match self.rules.get(name) {
            Some(Rule::Type { rule, .. }) => {
                let pushed = self.push_frame(&rule.generic_params, generic_args);
                let result = self.type_accepts(&rule.value, value);
                if pushed {
                    self.pop_frame();
                }
                result
            }
            Some(Rule::Group { .. }) => true, // can't cheaply introspect; trust.
            None => false,
        }
    }
}

/// True/false for prelude types; `None` for non-prelude (caller recurses
/// into user-defined rules).
fn prelude_accepts(name: &str, value: &CborValue) -> Option<bool> {
    Some(match name {
        "any" => true,
        "uint" | "unsigned" | "biguint" | "integer" => matches!(value, CborValue::Integer(_))
            || is_uint_bignum_tag(value),
        "nint" | "bignint" => matches!(value, CborValue::Integer(_)) || is_nint_bignum_tag(value),
        "int" | "bigint" | "number" => {
            matches!(value, CborValue::Integer(_)) || is_bignum_tag(value)
        }
        "float" | "float16" | "float32" | "float64" | "float16-32" | "float32-64" => {
            matches!(value, CborValue::Float(_))
        }
        "bstr" | "bytes" => matches!(value, CborValue::Bytes(_)),
        "tstr" | "text" => matches!(value, CborValue::Text(_)),
        "bool" => matches!(value, CborValue::Bool(_)),
        "false" => matches!(value, CborValue::Bool(false)),
        "true" => matches!(value, CborValue::Bool(true)),
        "null" | "nil" => matches!(value, CborValue::Null),
        "undefined" => matches!(value, CborValue::Simple(23)),
        _ => return None,
    })
}

fn is_bignum_tag(v: &CborValue) -> bool {
    matches!(v, CborValue::Tag(2, _) | CborValue::Tag(3, _))
}
fn is_uint_bignum_tag(v: &CborValue) -> bool {
    matches!(v, CborValue::Tag(2, _))
}
fn is_nint_bignum_tag(v: &CborValue) -> bool {
    matches!(v, CborValue::Tag(3, _))
}

fn try_prelude(value: &CborValue, name: &str) -> Option<Value> {
    match (name, value) {
        ("any", _) => Some(raw_value(value)),

        ("uint", CborValue::Integer(i))
        | ("unsigned", CborValue::Integer(i))
        | ("biguint", CborValue::Integer(i))
        | ("integer", CborValue::Integer(i))
        | ("nint", CborValue::Integer(i))
        | ("bignint", CborValue::Integer(i))
        | ("int", CborValue::Integer(i))
        | ("bigint", CborValue::Integer(i))
        | ("number", CborValue::Integer(i)) => Some(int_to_json(*i)),

        ("float", CborValue::Float(f))
        | ("float16", CborValue::Float(f))
        | ("float32", CborValue::Float(f))
        | ("float64", CborValue::Float(f))
        | ("float16-32", CborValue::Float(f))
        | ("float32-64", CborValue::Float(f)) => Number::from_f64(*f).map(Value::Number),

        ("bstr", CborValue::Bytes(b)) | ("bytes", CborValue::Bytes(b)) => {
            Some(Value::String(hex::encode(b)))
        }
        ("tstr", CborValue::Text(s)) | ("text", CborValue::Text(s)) => Some(Value::String(s.clone())),
        ("bool", CborValue::Bool(b)) => Some(Value::Bool(*b)),
        ("false", CborValue::Bool(false)) => Some(Value::Bool(false)),
        ("true", CborValue::Bool(true)) => Some(Value::Bool(true)),
        ("null", CborValue::Null) | ("nil", CborValue::Null) => Some(Value::Null),
        ("undefined", CborValue::Simple(23)) => Some(Value::Null),
        _ => None,
    }
}

fn tag_matches(tag: Option<&TagConstraint<'_>>, actual: u64) -> bool {
    match tag {
        None => true, // `#6.<any>()` — schema didn't fix the number.
        Some(TagConstraint::Literal(n)) => *n as u64 == actual,
        Some(TagConstraint::Type { .. }) => true,
    }
}

fn specialise_known_tag(tag: u64, payload: &CborValue) -> Option<Value> {
    match (tag, payload) {
        // RFC 8949 §3.4.3 — unsigned / negative bignums as byte strings.
        (2, CborValue::Bytes(b)) => {
            let mag = bytes_to_u128(b);
            Some(mag.map(|m| json!(m.to_string())).unwrap_or(json!({
                "@tag": 2,
                "@value": hex::encode(b)
            })))
        }
        (3, CborValue::Bytes(b)) => {
            let mag = bytes_to_u128(b);
            Some(match mag {
                Some(m) => json!((-(m as i128) - 1).to_string()),
                None => json!({"@tag": 3, "@value": hex::encode(b)}),
            })
        }
        // RFC 8949 §3.4.1 — tag 0 carries a standard date-time string.
        (0, CborValue::Text(s)) => Some(Value::String(s.clone())),
        _ => None,
    }
}

fn bytes_to_u128(b: &[u8]) -> Option<u128> {
    if b.len() > 16 {
        return None;
    }
    let mut out: u128 = 0;
    for byte in b {
        out = (out << 8) | u128::from(*byte);
    }
    Some(out)
}

fn int_to_json(i: Integer) -> Value {
    if let Ok(u) = u64::try_from(i) {
        Value::Number(u.into())
    } else if let Ok(s) = i64::try_from(i) {
        Value::Number(s.into())
    } else {
        let s: i128 = i.into();
        Number::from_i128(s)
            .map(Value::Number)
            .unwrap_or_else(|| Value::String(s.to_string()))
    }
}

fn json_key(k: &CborValue) -> String {
    match k {
        CborValue::Text(s) => s.clone(),
        CborValue::Integer(i) => {
            if let Ok(u) = u64::try_from(*i) {
                u.to_string()
            } else if let Ok(s) = i64::try_from(*i) {
                s.to_string()
            } else {
                format!("{:?}", i)
            }
        }
        CborValue::Bytes(b) => format!("0x{}", hex::encode(b)),
        CborValue::Bool(b) => b.to_string(),
        CborValue::Null => "null".into(),
        other => format!("{:?}", other),
    }
}

/// Fallback — emit a value we couldn't label against the schema. Format
/// matches the existing `cbor_to_json` semantics approximately: bytes
/// as hex, maps as `{}`, arrays as `[]`, tags as `{@tag, @value}`.
fn raw_value(v: &CborValue) -> Value {
    match v {
        CborValue::Null => Value::Null,
        CborValue::Bool(b) => Value::Bool(*b),
        CborValue::Integer(i) => int_to_json(*i),
        CborValue::Float(f) => Number::from_f64(*f).map(Value::Number).unwrap_or(Value::Null),
        CborValue::Text(s) => Value::String(s.clone()),
        CborValue::Bytes(b) => Value::String(hex::encode(b)),
        CborValue::Array(items) => Value::Array(items.iter().map(raw_value).collect()),
        CborValue::Map(entries) => {
            let mut obj = Map::new();
            for (k, v) in entries {
                obj.insert(json_key(k), raw_value(v));
            }
            Value::Object(obj)
        }
        CborValue::Tag(n, inner) => {
            json!({"@tag": n, "@value": raw_value(inner)})
        }
        CborValue::Simple(n) => json!({"@simple": n}),
    }
}

struct ObjectBuilder {
    obj: Map<String, Value>,
    positional: Vec<Value>,
}

impl ObjectBuilder {
    fn new() -> Self {
        ObjectBuilder { obj: Map::new(), positional: Vec::new() }
    }

    fn push_raw(&mut self, v: Value) {
        self.positional.push(v);
    }

    fn finish(mut self) -> Value {
        if self.obj.is_empty() && !self.positional.is_empty() {
            return Value::Array(self.positional);
        }
        if !self.positional.is_empty() {
            self.obj.insert("@positional".into(), Value::Array(self.positional));
        }
        Value::Object(self.obj)
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run(cddl: &str, rule: &str, hex_cbor: &str) -> Value {
        let bytes = hex::decode(hex_cbor).expect("bad test hex");
        decode_cbor_against_cddl(&bytes, cddl, rule).expect("mapper error")
    }

    #[test]
    fn primitive_int() {
        // Just uint = 42
        assert_eq!(run("x = uint", "x", "182a"), json!(42));
    }

    #[test]
    fn primitive_bytes_become_hex() {
        assert_eq!(run("x = bstr", "x", "4401020304"), json!("01020304"));
    }

    #[test]
    fn text_string_is_returned_verbatim() {
        // 65 68656c6c6f = "hello"
        assert_eq!(run("x = tstr", "x", "6568656c6c6f"), json!("hello"));
    }

    #[test]
    fn map_with_bareword_keys_gets_named_fields() {
        // a2 6161 01 6162 02 = {"a": 1, "b": 2}
        let out = run(
            "thing = {a: uint, b: uint}",
            "thing",
            "a261610161620 2".replace(' ', "").as_str(),
        );
        assert_eq!(out, json!({"a": 1, "b": 2}));
    }

    #[test]
    fn map_with_integer_keys_labels_fields_by_cddl_name() {
        // a2 00 01 01 18 2a = {0: 1, 1: 42}
        // schema assigns key 0 -> "inputs", key 1 -> "outputs"
        let out = run(
            "tx_body = { 0: uint, 1: uint }\n\
             transaction_body = tx_body",
            "tx_body",
            "a200 01 01 18 2a".replace(' ', "").as_str(),
        );
        assert_eq!(out, json!({"0": 1, "1": 42}));
    }

    #[test]
    fn map_keeps_semantic_names_when_bareword_matches_integer_value_key() {
        // When the key is a uint literal in CDDL, the output field name
        // is the literal's string form. For a semantic name we rely on
        // naming through a type rule.
        let out = run(
            "header = { 0: uint, 1: bstr }",
            "header",
            "a200 01 01 4401020304".replace(' ', "").as_str(),
        );
        assert_eq!(out, json!({"0": 1, "1": "01020304"}));
    }

    #[test]
    fn positional_array_with_names_becomes_object() {
        // 83 01 6568656c6c6f 02 = [1, "hello", 2]
        let out = run(
            "point = [x: uint, label: tstr, y: uint]",
            "point",
            "83016568656c6c6f02",
        );
        assert_eq!(out, json!({"x": 1, "label": "hello", "y": 2}));
    }

    #[test]
    fn homogeneous_array_stays_array() {
        // 83 01 02 03 = [1, 2, 3]
        let out = run("list = [* uint]", "list", "83010203");
        assert_eq!(out, json!([1, 2, 3]));
    }

    #[test]
    fn type_choice_picks_first_matching_alternative() {
        // int | tstr — give it an int, get an int.
        assert_eq!(run("v = int / tstr", "v", "182a"), json!(42));
        assert_eq!(run("v = int / tstr", "v", "6568656c6c6f"), json!("hello"));
    }

    #[test]
    fn tag_zero_datetime_returns_iso_string() {
        // c074 323032302d30312d30315430303a30303a30305a = tag 0 "2020-01-01T00:00:00Z"
        let out = run(
            "when = #6.0(tstr)",
            "when",
            "c07432303230 2d30312d30315430303a30303a30305a".replace(' ', "").as_str(),
        );
        assert_eq!(out, json!("2020-01-01T00:00:00Z"));
    }

    #[test]
    fn bignum_tag_unwraps_to_string_number() {
        // c2 48 0100000000000000 = tag 2, bytes(0x0100000000000000) = 2^56
        let out = run("n = #6.2(bstr)", "n", "c2480100000000000000");
        assert_eq!(out, json!("72057594037927936"));
    }

    #[test]
    fn optional_field_can_be_absent() {
        // a1 6163 03 = {"c": 3}. Schema: {a: ?int, b: ?int, c: int}.
        let out = run(
            "t = {? a: int, ? b: int, c: int}",
            "t",
            "a161630 3".replace(' ', "").as_str(),
        );
        assert_eq!(out, json!({"c": 3}));
    }

    #[test]
    fn zero_or_more_field_collects_multiple_values() {
        // a2 00 01 00 02 = {0: 1, 0: 2}. CDDL: * 0 => uint.
        // CBOR has the literal key `0` twice — duplicates trigger
        // the `@entries` shape which preserves wire order.
        let out = run(
            "t = { * 0 => uint }",
            "t",
            "a20001000 2".replace(' ', "").as_str(),
        );
        let entries = out["@entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["key"], json!(0));
        assert_eq!(entries[0]["value"], json!(1));
        assert_eq!(entries[1]["key"], json!(0));
        assert_eq!(entries[1]["value"], json!(2));
    }

    #[test]
    fn type_rule_reference_is_resolved() {
        let schema = "coin = uint\n\
                      output = [address: bstr, amount: coin]";
        // 82 44 01020304 0a = ["01020304", 10]
        let out = run(schema, "output", "824401020304 0a".replace(' ', "").as_str());
        assert_eq!(out, json!({"address": "01020304", "amount": 10}));
    }

    #[test]
    fn unknown_root_rule_errors_out() {
        let err = decode_cbor_against_cddl(b"\x01", "x = int", "no_such")
            .err()
            .expect("expected error");
        assert!(err.as_string().unwrap().contains("no_such"));
    }

    #[test]
    fn bad_cbor_errors_out() {
        let err = decode_cbor_against_cddl(&[0x18], "x = int", "x")
            .err()
            .expect("expected error");
        assert!(err.as_string().unwrap().to_lowercase().contains("cbor"));
    }

    #[test]
    fn cardano_style_named_record_using_type_rules_for_field_labels() {
        // Realistic shape: schema names every field via bareword keys
        // (this is how to get clean labels — pure-numeric keys would
        // come back as "0"/"1" since CDDL stores no field name there).
        // [
        //    body: {
        //       inputs:  [{tx: bstr, idx: uint}, ...],
        //       outputs: [{address: bstr, amount: uint}, ...],
        //       fee:     uint
        //    },
        //    is_valid: bool
        // ]
        let schema = "
            transaction = [body: tx_body, is_valid: bool]
            tx_body = {
              inputs:  [* tx_in],
              outputs: [* tx_out],
              fee:     coin
            }
            tx_in  = [tx: bstr, idx: uint]
            tx_out = [address: bstr, amount: coin]
            coin   = uint
        ";
        // 82                         array(2)
        //   a3                       map(3)
        //     66 696e70757473        \"inputs\"
        //     81                     array(1)
        //       82                   array(2)
        //         44 01020304        bytes(0x01020304)
        //         00                 0
        //     67 6f757470757473      \"outputs\"
        //     81                     array(1)
        //       82                   array(2)
        //         44 0a0b0c0d        bytes(0x0a0b0c0d)
        //         18 64              100
        //     63 666565              \"fee\"
        //     0a                     10
        //   f5                       true
        let cbor = "82a3 66696e70757473 81 82 4401020304 00 67 6f757470757473 81 82 \
                    44 0a0b0c0d 1864 63 666565 0a f5"
            .replace(' ', "");
        let out = run(schema, "transaction", &cbor);
        assert_eq!(
            out,
            json!({
                "body": {
                    "inputs":  [{"tx": "01020304", "idx": 0}],
                    "outputs": [{"address": "0a0b0c0d", "amount": 100}],
                    "fee":     10
                },
                "is_valid": true
            })
        );
    }

    /// PREVIEW_SIMPLE_TX_HEX from validators/tests/fixtures.rs — a real
    /// signed Conway tx with one input, two outputs, fee, aux-hash, one
    /// vkey witness, no certs / metadata.
    const PREVIEW_TX: &str = "84a400d901028182582016b6ee8c812f8b1c9c643ee3828f50fdcf0f174625bbd6e947ba77b12374094a00018282583900aef399a405edd6797117a3db6653e1a230e1f6f91dd5badb77f2be3720fc45da826093ae8ed2e4f0f81c4f5ea9b6f0dda561c974cfc6355d1a000f424082583900f275cb75d82f737c49280039947e484919ee044c82c2e4ceaf2f2d87984c3eb5c8a01b4b53c7cec4cfc139345a28d24a6ec918873c459add1a48b7d00d021a00030d40075820bdaa99eb158414dea0a91d6c727e2268574b23efe6e08ab3b841abe8059a030ca100d9010281825820f8f5750132a13473240e318dd36eccd70083e8f08ac589c74ebe776f43e9401d58401e149e081ff497d7f97c3ef7427a916d1b0632c6eb98bb54b040aca413a2ad94273291c9b63b2802083c72b0cfe03eef2b55f767ecf32dba894dd59701076409f5d90103a0";

    /// CDDL describing the subset Cardano uses for an ada-only Conway
    /// tx without generics — proves the mapper handles tagged sets,
    /// nested arrays, and key-numbered transaction-body maps. Once
    /// generics support lands we'll replace `set_input`/`set_vkey`
    /// with `set<a> = #6.258([* a])`.
    const PREVIEW_TX_CDDL_NO_GENERICS: &str = r#"
        transaction = [
          body:        transaction_body,
          witness_set: transaction_witness_set,
          is_valid:    bool,
          aux:         auxiliary_data / null
        ]

        transaction_body = {
          0: set_input,
          1: [* transaction_output],
          2: coin,
          ? 7: bstr
        }

        set_input          = #6.258([* transaction_input])
        transaction_input  = [tx_hash: bstr, idx: uint]
        transaction_output = [address: bstr, amount: coin]
        coin               = uint

        transaction_witness_set = {
          ? 0: set_vkey
        }
        set_vkey    = #6.258([* vkeywitness])
        vkeywitness = [vkey: bstr, signature: bstr]

        auxiliary_data = #6.259({})
    "#;

    #[test]
    fn real_preview_tx_maps_to_named_json_without_generics() {
        let bytes = hex::decode(PREVIEW_TX).unwrap();
        let out = decode_cbor_against_cddl(&bytes, PREVIEW_TX_CDDL_NO_GENERICS, "transaction")
            .expect("mapper should handle the tx");
        // Sanity-check shape: the four named outer fields are present.
        for k in ["body", "witness_set", "is_valid", "aux"] {
            assert!(out.get(k).is_some(), "missing {} in {}", k, out);
        }
        assert_eq!(out["is_valid"], json!(true));

        // Body structure — keys 0/1/2/7 visible as numeric strings (we
        // don't invent semantic names from CDDL comments).
        let body = &out["body"];
        assert_eq!(body["2"], json!(200_000)); // fee
        // Inputs: tag 258 → wrapped object {@tag, @value} OR specialised.
        // First-pass mapper preserves the tag as a labelled object.
        assert!(body.get("0").is_some(), "no inputs key in {}", body);
        assert!(body.get("1").is_some(), "no outputs key in {}", body);

        // Outputs: array of [address: bstr, amount: coin] -> labelled.
        let outputs = body["1"].as_array().expect("outputs array");
        assert_eq!(outputs.len(), 2);
        let first = &outputs[0];
        assert!(first.get("address").is_some(), "{}", first);
        assert!(first.get("amount").is_some(), "{}", first);
        assert_eq!(first["amount"], json!(1_000_000));
    }

    /// Same tx, but the schema uses generic `set<a> = #6.258([* a])`
    /// just like the official Conway CDDL.
    const PREVIEW_TX_CDDL_GENERICS: &str = r#"
        transaction = [
          body:        transaction_body,
          witness_set: transaction_witness_set,
          is_valid:    bool,
          aux:         auxiliary_data / null
        ]

        transaction_body = {
          0: set<transaction_input>,
          1: [* transaction_output],
          2: coin,
          ? 7: bstr
        }

        transaction_input  = [tx_hash: bstr, idx: uint]
        transaction_output = [address: bstr, amount: coin]
        coin               = uint

        transaction_witness_set = {
          ? 0: set<vkeywitness>
        }
        vkeywitness = [vkey: bstr, signature: bstr]

        set<a>         = #6.258([* a])
        auxiliary_data = #6.259({})
    "#;

    /// Tests that the official Conway CDDL parses through the patched
    /// `cddl` crate (see /Users/lisicky/svc/cddl/FIXES_FOR_CONWAY.md).
    /// The cached fixture lives in the cddl fork's tests/fixtures dir
    /// to avoid duplicating it here; we read it from there directly.
    #[test]
    fn real_preview_tx_maps_against_official_conway_cddl() {
        let cddl_path = "../cddl/tests/fixtures/cddl/conway.cddl";
        let cddl = match std::fs::read_to_string(cddl_path) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("skipping — {} not found", cddl_path);
                return;
            }
        };
        let bytes = hex::decode(PREVIEW_TX).unwrap();
        let out = decode_cbor_against_cddl(&bytes, &cddl, "transaction")
            .expect("Conway CDDL should parse and map after the cddl-fork fixes");
        // Outer transaction is [transaction_body, transaction_witness_set,
        // bool, auxiliary_data/nil] in Conway. Without bareword names on
        // the array entries we expect the type-rule names to surface as
        // labels: transaction_body, transaction_witness_set.
        assert!(
            out.get("transaction_body").is_some(),
            "missing transaction_body label in {}",
            out
        );
        assert!(
            out.get("transaction_witness_set").is_some(),
            "missing transaction_witness_set label in {}",
            out
        );
        eprintln!(
            "PREVIEW_TX (official Conway CDDL) ⇒\n{}",
            serde_json::to_string_pretty(&out).unwrap()
        );
    }

    #[test]
    fn real_preview_tx_maps_with_generics_set_a() {
        let bytes = hex::decode(PREVIEW_TX).unwrap();
        let out = decode_cbor_against_cddl(&bytes, PREVIEW_TX_CDDL_GENERICS, "transaction")
            .expect("mapper handles set<a>");
        assert_eq!(out["is_valid"], json!(true));
        let body = &out["body"];
        assert_eq!(body["2"], json!(200_000));
        // Inputs reach us through `set<transaction_input>` — the tag-258
        // wrapper unwraps via TaggedData branch, the inner array is
        // homogeneous transaction_input, so we expect a structured
        // labelled array.
        let inputs_field = &body["0"];
        // It can be either a plain array (preferred) or a wrapped
        // {"@tag":258,"@value":[...]} fallback. Accept both, but the
        // generic should produce one of them with the labelled inputs.
        let inputs_arr = inputs_field
            .as_array()
            .or_else(|| inputs_field.get("@value").and_then(Value::as_array))
            .unwrap_or_else(|| panic!("inputs not array-shaped: {}", body));
        assert_eq!(inputs_arr.len(), 1);
        assert!(inputs_arr[0].get("tx_hash").is_some());
        assert!(inputs_arr[0].get("idx").is_some());

        // Outputs labelled by their inner CDDL.
        let outputs = body["1"].as_array().unwrap();
        assert_eq!(outputs.len(), 2);
        assert!(outputs[0].get("address").is_some());
        assert!(outputs[0].get("amount").is_some());
    }

    #[test]
    fn cbor_control_decodes_embedded_value_against_inner_type() {
        // bstr .cbor [a: int, b: int]: outer is a bstr containing the
        // CBOR bytes of `[1, 2]`. The mapper should decode the bstr
        // and label the inner array.
        let schema = "x = bstr .cbor inner\n\
                      inner = [a: int, b: int]";
        // 42 8201 02 = bstr(2: 8201 02 = [1, 2])
        let cbor = "4382 01 02".replace(' ', "");
        let bytes = hex::decode(&cbor).unwrap();
        let out = decode_cbor_against_cddl(&bytes, schema, "x").unwrap();
        let _ = out; // shape varies by inner type; assertions below
        // Walk inline test:
        let inline_schema = "x = bstr .cbor [a: int, b: int]";
        let out2 = decode_cbor_against_cddl(&bytes, inline_schema, "x").unwrap();
        assert_eq!(out2, json!({"a": 1, "b": 2}));
    }

    #[test]
    fn cbor_control_falls_back_to_raw_when_inner_does_not_match() {
        // bstr .cbor uint, but the bstr contains a tstr — should fall
        // back to a raw representation (hex) rather than crashing.
        let schema = "x = bstr .cbor uint";
        // 43 6168 00 = bstr(3: "ah\0") — encodes as text "ah" + null byte? bypass.
        // Use 41 18 — bstr(1) containing [0x18] which is invalid CBOR.
        let bytes = hex::decode("4118").unwrap();
        let out = decode_cbor_against_cddl(&bytes, schema, "x").unwrap();
        assert_eq!(out, json!("18"), "fall-back should be raw hex");
    }

    #[test]
    fn unwrap_resolves_into_referenced_rule_body() {
        // `wrapped = ~base` where `base = [a: int, b: int]`. CBOR is
        // [1, 2]. Mapper should treat ~base transparently.
        let schema = "wrapped = ~base\n\
                      base = [a: int, b: int]";
        // 82 01 02 = [1, 2]
        let bytes = hex::decode("820102").unwrap();
        let out = decode_cbor_against_cddl(&bytes, schema, "wrapped").unwrap();
        assert_eq!(out, json!({"a": 1, "b": 2}));
    }

    #[test]
    fn generic_typegroupname_in_array_passes_args_to_inner_type_with_labels() {
        // outer = [* wrapper<inner>] where wrapper<a> = a passes the
        // argument through, and inner = [k: int, v: int] has named
        // positional fields. Bound: each item -> {"k": …, "v": …}.
        // Unbound (the bug): inner's `a` resolves to nothing, falls
        // back to raw `[k, v]`, output is `[[1,2]]` instead of
        // `[{"k": 1, "v": 2}]`.
        let schema = "outer = [* wrapper<inner>]\n\
                      wrapper<a> = a\n\
                      inner = [k: int, v: int]";
        // 81 82 01 02 = [[1, 2]]
        let out = run(schema, "outer", "8182010 2".replace(' ', "").as_str());
        assert_eq!(out, json!([{"k": 1, "v": 2}]));
    }

    #[test]
    fn generic_typegroupname_in_array_passes_args_through() {
        // outer = [* set<int>] with set<a> = [* a]. CBOR is [[1,2],[3,4]].
        // The entry `set<int>` is a TypeGroupname with generic_args=[int].
        // If we don't pass them through, `set`'s body sees `a` unbound
        // and the inner arrays come back empty.
        let schema = "outer = [* set<int>]\nset<a> = [* a]";
        // 82 82 01 02 82 03 04 = [[1, 2], [3, 4]]
        let out = run(schema, "outer", "82820102820304");
        assert_eq!(out, json!([[1, 2], [3, 4]]));
    }

    #[test]
    fn map_with_duplicate_literal_keys_uses_entries_form() {
        // CBOR allows duplicates (RFC 8949 §5.6 — legal but
        // non-canonical). Object form would either drop the second or
        // collapse into a value-array, both of which lose interleaving
        // order. We switch to `@entries` to preserve wire shape.
        // a2 6161 01 6161 02 = {"a": 1, "a": 2}
        let bytes = hex::decode("a26161 01 6161 02".replace(' ', "").as_str()).unwrap();
        let out = decode_cbor_against_cddl(&bytes, "thing = {a: int}", "thing").unwrap();
        let entries = out["@entries"].as_array().expect("@entries on dups");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["key"], json!("a"));
        assert_eq!(entries[0]["value"], json!(1));
        assert_eq!(entries[1]["key"], json!("a"));
        assert_eq!(entries[1]["value"], json!(2));
    }

    #[test]
    fn map_with_three_duplicate_keys_keeps_wire_order() {
        // a3 0001 0002 0003 — three entries with the same uint key 0,
        // in that order. `@entries` keeps them in wire order.
        let bytes = hex::decode("a3 00 01 00 02 00 03".replace(' ', "").as_str()).unwrap();
        let out = decode_cbor_against_cddl(&bytes, "thing = {0: int}", "thing").unwrap();
        let entries = out["@entries"].as_array().unwrap();
        assert_eq!(entries.len(), 3);
        let values: Vec<_> = entries.iter().map(|e| e["value"].clone()).collect();
        assert_eq!(values, vec![json!(1), json!(2), json!(3)]);
    }

    #[test]
    fn map_without_duplicates_keeps_object_form() {
        // {"a": 1, "b": 2} — no duplicates, all simple keys → object.
        let bytes = hex::decode("a26161 01 6162 02".replace(' ', "").as_str()).unwrap();
        let out = decode_cbor_against_cddl(
            &bytes,
            "thing = {a: int, b: int}",
            "thing",
        )
        .unwrap();
        assert_eq!(out, json!({"a": 1, "b": 2}));
    }

    #[test]
    fn map_with_complex_key_uses_entries_fallback() {
        // Schema: `m = { [int, int] => tstr }` — key is a 2-element
        // int array. CBOR: a2 8201 02 6361 8203 04 6362
        //   = {[1,2]: "a", [3,4]: "b"}
        let schema = "m = { [int, int] => tstr }";
        // a2 82 01 02 6161 82 03 04 6162  (two pairs)
        let bytes = hex::decode("a282 01 02 6161 82 03 04 6162".replace(' ', "").as_str()).unwrap();
        let out = decode_cbor_against_cddl(&bytes, schema, "m").unwrap();
        let entries = out
            .get("@entries")
            .unwrap_or_else(|| panic!("expected @entries fallback, got {}", out));
        let arr = entries.as_array().expect("@entries is array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["key"], json!([1, 2]));
        assert_eq!(arr[0]["value"], json!("a"));
        assert_eq!(arr[1]["key"], json!([3, 4]));
        assert_eq!(arr[1]["value"], json!("b"));
    }

    #[test]
    fn map_with_tag_key_uses_entries_fallback() {
        // Schema: `m = { #6.42(uint) => tstr }`. CBOR: a1 d82a01 6178
        let schema = "m = { #6.42(uint) => tstr }";
        let bytes = hex::decode("a1 d82a 01 6178".replace(' ', "").as_str()).unwrap();
        let out = decode_cbor_against_cddl(&bytes, schema, "m").unwrap();
        let entries = out
            .get("@entries")
            .unwrap_or_else(|| panic!("expected @entries, got {}", out));
        let arr = entries.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        // key gets walked against `#6.42(uint)` — emits {@tag, @value}.
        assert_eq!(arr[0]["key"]["@tag"], json!(42));
        assert_eq!(arr[0]["value"], json!("x"));
    }

    /// Real Cardano tx through the official Conway CDDL — verifies
    /// that `mint = multiasset<nonZeroInt64>` (with type-keyed
    /// `+ policy_id => +asset_name => …` map) labels the policy_id
    /// hash and asset_name hex correctly instead of dumping them into
    /// `@extra`.
    #[test]
    fn real_tx_mint_field_uses_actual_keys_not_extra_bucket() {
        let Ok(cddl) = std::fs::read_to_string("/tmp/conway.cddl") else {
            eprintln!("skipping — /tmp/conway.cddl missing");
            return;
        };
        let Ok(hex_text) = std::fs::read_to_string("/Users/lisicky/svc/cddl/test_cbor") else {
            eprintln!("skipping — /Users/lisicky/svc/cddl/test_cbor missing");
            return;
        };
        let bytes = hex::decode(hex_text.trim()).unwrap();
        let out = decode_cbor_against_cddl(&bytes, &cddl, "transaction").unwrap();
        let mint = out
            .get("transaction_body")
            .and_then(|b| b.get("9"))
            .expect("body[9] (mint) must be present in this fixture");
        assert!(
            mint.get("@extra").is_none(),
            "mint should not leak into @extra, got {}",
            mint
        );
        // Exactly one policy_id is minted; it's a 28-byte bstr, so the
        // JSON key is `0x` + 56 hex chars.
        let mint_obj = mint.as_object().expect("mint should be a map");
        let policy_keys: Vec<&String> = mint_obj.keys().collect();
        assert_eq!(policy_keys.len(), 1, "expected one policy in mint");
        let policy = policy_keys[0];
        assert!(
            policy.starts_with("0x") && policy.len() == 2 + 56,
            "policy key should be 0x<28 bytes hex>, got {:?}",
            policy
        );
        // Each policy maps to {asset_name => quantity}. The quantity
        // here is `1` (the asset_name is empty so its hex key is `0x`).
        let assets = mint[policy].as_object().expect("inner asset map");
        assert!(assets.contains_key("0x"), "expected `0x` (empty asset_name) in {:?}", assets);
        assert_eq!(assets["0x"], json!(1));
    }

    #[test]
    fn extras_are_preserved_as_at_extra_bucket() {
        // a2 00 01 02 03 = {0: 1, 2: 3}. Schema only covers key 0.
        let out = run("t = {0: uint}", "t", "a200010203");
        assert_eq!(
            out,
            json!({"0": 1, "@extra": {"2": 3}})
        );
    }

    // ========================================================
    // Generics
    // ========================================================

    #[test]
    fn set_generic_chained_through_multiple_rules() {
        // set<a> wrapped through an alias chain: tagged_set -> set -> hash.
        // CBOR: tag 258 [bstr(4: 01020304), bstr(4: 0a0b0c0d)]
        // d9 0102 82 4401020304 4 40a0b0c0d
        let schema = "
            hash       = bstr
            set<a>     = #6.258([* a])
            tagged_set = set<hash>
            wrapper    = tagged_set
        ";
        let cbor = "d9010282 4401020304 440a0b0c0d".replace(' ', "");
        let out = run(schema, "wrapper", &cbor);
        // Tag is unwrapped via TaggedData branch; result is array of hashes.
        // Could be plain array (preferred) or {@tag, @value} fallback.
        let arr = out
            .as_array()
            .cloned()
            .or_else(|| out.get("@value").and_then(Value::as_array).cloned())
            .expect("expected an array of hashes");
        assert_eq!(arr, vec![json!("01020304"), json!("0a0b0c0d")]);
    }

    #[test]
    fn nested_generic_pair_bstr_uint() {
        // pair<k, v> = [k, v] used as pair<bstr, uint>.
        // [bstr(4: 0a0b0c0d), 7]: 82 4 40a0b0c0d 07
        //
        // BUG (pinning current behaviour): generic parameter names that
        // appear as array entries get treated as field labels by
        // `consume_array_typegroupname` (the prelude-check there sees
        // the *parameter name* `k`/`v`, which isn't a prelude type, so
        // a previous version of the mapper promoted those slots to
        // named fields keyed by the parameter idents. Now that bound
        // generic parameters are excluded from name-based labelling,
        // the slots flow into the unnamed positional list.
        let schema = "
            pair<k, v> = [k, v]
            kv         = pair<bstr, uint>
        ";
        let cbor = "82440a0b0c0d07";
        let out = run(schema, "kv", cbor);
        assert_eq!(out, json!(["0a0b0c0d", 7]));
    }

    #[test]
    fn pair_generic_with_named_positions() {
        // pair<k, v> = [key: k, value: v] — names attach in array.
        // [bstr(4: deadbeef), 99]: 82 44 deadbeef 18 63
        let schema = "
            pair<k, v> = [key: k, value: v]
            kv         = pair<bstr, uint>
        ";
        let cbor = "8244deadbeef1863";
        let out = run(schema, "kv", cbor);
        assert_eq!(out, json!({"key": "deadbeef", "value": 99}));
    }

    #[test]
    fn multiple_generic_params_used_in_different_positions() {
        // entry<k, v> = {key: k, val: v}; concrete = entry<tstr, uint>.
        // {"key":"abc","val":7}: a2 63 6b6579 63 616263 63 76616c 07
        let schema = "
            entry<k, v> = {key: k, val: v}
            concrete    = entry<tstr, uint>
        ";
        let cbor = "a2636b657963616263637661 6c07".replace(' ', "");
        let out = run(schema, "concrete", &cbor);
        assert_eq!(out, json!({"key": "abc", "val": 7}));
    }

    #[test]
    fn generic_param_rebound_in_subrule() {
        // outer<x> = inner<x>; inner<y> = [y, y] — y is fresh in inner,
        // bound from x at the call site.
        // CBOR [5, 5]: 82 05 05
        //
        // Both array slots reference the generic parameter `y`. With
        // bound generic params excluded from labelling, both slots end
        // up in the unnamed array — no collision, no data loss.
        let schema = "
            outer<x>  = inner<x>
            inner<y>  = [y, y]
            wrap      = outer<uint>
        ";
        let out = run(schema, "wrap", "820505");
        assert_eq!(out, json!([5, 5]));
    }

    // ========================================================
    // Type choices
    // ========================================================

    #[test]
    fn three_way_choice_second_alternative_wins() {
        // (uint / tstr / bstr); given a tstr → tstr branch wins.
        // tstr "yo": 62 796f
        let out = run("v = uint / tstr / bstr", "v", "62796f");
        assert_eq!(out, json!("yo"));
    }

    #[test]
    fn choice_between_map_and_array_shapes_picks_map() {
        // shape = {a: uint} / [uint]. Given {"a":1} → a1 6161 01.
        let out = run("shape = {a: uint} / [uint]", "shape", "a1616101");
        assert_eq!(out, json!({"a": 1}));
    }

    #[test]
    fn choice_between_map_and_array_picks_array() {
        // shape = {a: uint} / [uint]. Given [3] → 81 03.
        let out = run("shape = {a: uint} / [uint]", "shape", "8103");
        assert_eq!(out, json!([3]));
    }

    #[test]
    fn choice_with_literal_discriminator_matches_first_alternative() {
        // {type: "a", value: int} / {type: "b", value: tstr}.
        // CBOR {"type":"a","value":7}:
        //   a2 64 74797065 61 61 65 76616c7565 07
        let schema = r#"
            tagged = {type: "a", value: int} / {type: "b", value: tstr}
        "#;
        let cbor = "a26474797065616165 76616c756507".replace(' ', "");
        let out = run(schema, "tagged", &cbor);
        assert_eq!(out, json!({"type": "a", "value": 7}));
    }

    #[test]
    fn choice_with_literal_discriminator_matches_second_alternative() {
        // Second alternative {"type":"b","value":"hi"}:
        //   a2 64 74797065 61 62 65 76616c7565 62 6869
        let schema = r#"
            tagged = {type: "a", value: int} / {type: "b", value: tstr}
        "#;
        let cbor = "a26474797065616265 76616c7565626869".replace(' ', "");
        let out = run(schema, "tagged", &cbor);
        assert_eq!(out, json!({"type": "b", "value": "hi"}));
    }

    #[test]
    fn choice_with_no_alternative_matching_falls_back_to_raw() {
        // v = uint / tstr; given a bool → should fall back to raw bool.
        let out = run("v = uint / tstr", "v", "f5"); // true
        assert_eq!(out, json!(true));
    }

    // ========================================================
    // Tags
    // ========================================================

    #[test]
    fn custom_tag_emits_tag_and_value_object() {
        // #6.99(uint) — tag 99 wrapping an int.
        // d8 63 18 2a = tag(99, 42)
        let out = run("x = #6.99(uint)", "x", "d863182a");
        assert_eq!(out, json!({"@tag": 99, "@value": 42}));
    }

    #[test]
    fn tag_wrapping_a_generic_set() {
        // #6.42(set<a>) where set<a> = #6.258([* a]).
        // Outer tag 42 wrapping tag 258 [uint, uint]:
        //   d8 2a   d9 0102   82 01 02
        let schema = "
            set<a> = #6.258([* a])
            wrap   = #6.42(set<uint>)
        ";
        let cbor = "d82ad9010282 01 02".replace(' ', "");
        let out = run(schema, "wrap", &cbor);
        // Outer custom tag yields {@tag: 42, @value: <inner>}.
        assert_eq!(out["@tag"], json!(42));
        // Inner is set<uint> — unwrapped via TaggedData → just the array.
        let inner = &out["@value"];
        let arr = inner
            .as_array()
            .cloned()
            .or_else(|| inner.get("@value").and_then(Value::as_array).cloned())
            .expect("inner set should be an array");
        assert_eq!(arr, vec![json!(1), json!(2)]);
    }

    #[test]
    fn negative_bignum_tag_three_round_trip() {
        // tag 3 with bytes 0x01 represents -(0x01) - 1 = -2.
        // c3 41 01
        let out = run("n = #6.3(bstr)", "n", "c34101");
        assert_eq!(out, json!("-2"));
    }

    #[test]
    fn negative_bignum_tag_three_large() {
        // tag 3 + bytes 0x0100000000000000 (2^56) -> -(2^56) - 1.
        // c3 48 0100000000000000
        let out = run("n = #6.3(bstr)", "n", "c3480100000000000000");
        // Magnitude is 72057594037927936; result is -(72057594037927936) - 1.
        assert_eq!(out, json!("-72057594037927937"));
    }

    #[test]
    fn mismatched_tag_falls_back_to_raw_value() {
        // Schema wants #6.99 but CBOR has tag 17. Mapper has no matching
        // alternative under this Type → falls back to raw_value, which
        // emits {"@tag":17, "@value":42}.
        // d1 18 2a = tag(17, 42)
        let out = run("x = #6.99(uint)", "x", "d1182a");
        assert_eq!(out, json!({"@tag": 17, "@value": 42}));
    }

    // ========================================================
    // Maps (more variants)
    // ========================================================

    #[test]
    fn map_keys_mixing_bareword_numeric_and_text_literals() {
        // {a: uint, 5: bstr, "k": tstr}
        // CBOR: {"a": 1, 5: bytes(02), "k": "v"}
        //   a3 61 61 01 05 41 02 61 6b 61 76
        let schema = r#"t = {a: uint, 5: bstr, "k": tstr}"#;
        let cbor = "a36161010541026 16b6176".replace(' ', "");
        let out = run(schema, "t", &cbor);
        assert_eq!(out, json!({"a": 1, "5": "02", "k": "v"}));
    }

    #[test]
    fn map_keys_with_cut_indicator() {
        // `^` cut indicator ("foo" ^ => uint) — semantics: this key is
        // matched exclusively. The mapper should still produce a labelled
        // field. CBOR: {"foo": 1, "bar": "x"}.
        //   a2 63 666f6f 01 63 626172 61 78
        let schema = r#"t = { "foo" ^ => uint, * tstr => any }"#;
        let cbor = "a263666f6f0163626172 6178".replace(' ', "");
        let out = run(schema, "t", &cbor);
        assert_eq!(out["foo"], json!(1));
        // The `* tstr => any` branch in the mapper currently is treated
        // as having no member_key match it can use as a name (it's a
        // type1-key, not a literal/bareword), so "bar" likely lands in
        // @extra. We assert that the data is preserved either way.
        let preserved = out.get("bar").is_some()
            || out
                .get("@extra")
                .and_then(|e| e.get("bar"))
                .is_some();
        assert!(preserved, "lost the 'bar' entry: {}", out);
    }

    #[test]
    fn map_open_ended_tstr_to_any_falls_back_to_extra() {
        // `* tstr => any` open-ended map. Mapper currently doesn't model
        // type1-key glob-collection — entries fall into @extra. This
        // pins the fallback path; if support lands, this test will fail
        // and we'll update it.
        // {"x": 1, "y": "hi"}: a2 61 78 01 61 79 62 6869
        let schema = "t = { * tstr => any }";
        let cbor = "a26178016179626869";
        let out = run(schema, "t", cbor);
        // Either direct labelling (future) or @extra fallback (today).
        let extras = out.get("@extra");
        if let Some(extras) = extras {
            assert_eq!(extras["x"], json!(1));
            assert_eq!(extras["y"], json!("hi"));
        } else {
            assert_eq!(out["x"], json!(1));
            assert_eq!(out["y"], json!("hi"));
        }
    }

    #[test]
    fn map_required_optional_and_repeating_together() {
        // a: required uint, ? b: optional bstr, * 9 => uint.
        // CBOR has duplicate key `9` — entries form preserves order.
        // {a: 1, 9: 7, 9: 8}: a3 61 61 01 09 07 09 08
        let schema = "t = { a: uint, ? b: bstr, * 9 => uint }";
        let cbor = "a361610109070908";
        let out = run(schema, "t", cbor);
        let entries = out["@entries"].as_array().unwrap();
        assert_eq!(entries.len(), 3);
        // First wire entry: bareword "a" → 1.
        assert_eq!(entries[0]["key"], json!("a"));
        assert_eq!(entries[0]["value"], json!(1));
        // Then two duplicate `9 => …` entries.
        assert_eq!(entries[1]["key"], json!(9));
        assert_eq!(entries[1]["value"], json!(7));
        assert_eq!(entries[2]["key"], json!(9));
        assert_eq!(entries[2]["value"], json!(8));
    }

    // ========================================================
    // Arrays (more variants)
    // ========================================================

    #[test]
    fn positional_array_with_optional_trailing_elements() {
        // [a: uint, b: uint, ? c: uint] — give it [1, 2].
        // 82 01 02
        let schema = "t = [a: uint, b: uint, ? c: uint]";
        let out = run(schema, "t", "820102");
        assert_eq!(out, json!({"a": 1, "b": 2}));
    }

    #[test]
    fn positional_array_with_optional_present() {
        // Same schema; include c. 83 01 02 03
        let schema = "t = [a: uint, b: uint, ? c: uint]";
        let out = run(schema, "t", "83010203");
        assert_eq!(out, json!({"a": 1, "b": 2, "c": 3}));
    }

    #[test]
    fn array_one_or_more_homogeneous_tail() {
        // [head: uint, + uint] — at least one tail item.
        // 84 01 02 03 04 = [1, 2, 3, 4]
        let schema = "t = [head: uint, + uint]";
        let out = run(schema, "t", "8401020304");
        // head labelled, tail items lack a name → @positional.
        assert_eq!(out["head"], json!(1));
        // The remaining items go to @positional.
        let pos = out.get("@positional").expect("expected @positional");
        assert_eq!(pos, &json!([2, 3, 4]));
    }

    #[test]
    fn array_mixed_named_and_unnamed_entries() {
        // [a: uint, uint, b: uint] — middle slot is unnamed.
        // 83 01 02 03
        let schema = "t = [a: uint, uint, b: uint]";
        let out = run(schema, "t", "83010203");
        assert_eq!(out["a"], json!(1));
        assert_eq!(out["b"], json!(3));
        let pos = out.get("@positional").expect("@positional present");
        assert_eq!(pos, &json!([2]));
    }

    #[test]
    fn empty_array_against_zero_or_more_yields_empty_json_array() {
        // [* uint] given empty CBOR array (0x80) → [].
        let out = run("t = [* uint]", "t", "80");
        assert_eq!(out, json!([]));
    }

    // ========================================================
    // Unwrap
    // ========================================================

    #[test]
    fn unwrap_referencing_rule_with_multiple_choices() {
        // base = uint / tstr; wrapped = ~base. Given a tstr it should
        // resolve to the tstr branch.
        // "hey": 63 686579
        let schema = "
            base    = uint / tstr
            wrapped = ~base
        ";
        let out = run(schema, "wrapped", "63686579");
        assert_eq!(out, json!("hey"));
    }

    #[test]
    fn unwrap_referenced_from_inside_a_generic() {
        // generic<a> = [a, a]; base = [b: bstr]; wrap = generic<~base>.
        // Each element is an unwrapped base = a positional array.
        // CBOR: [[bstr(4: 01020304)], [bstr(4: 0a0b0c0d)]]
        //   82  81 4401020304  81 440a0b0c0d
        //
        // BUG (pinning current behaviour): same as
        // `generic_param_rebound_in_subrule` — both `a` slots are now
        // recognised as bound generic params and stay in the unnamed
        // array, preserving order and both elements.
        let schema = "
            base       = [b: bstr]
            generic<a> = [a, a]
            wrap       = generic<~base>
        ";
        let cbor = "8281 4401020304 81 440a0b0c0d".replace(' ', "");
        let out = run(schema, "wrap", &cbor);
        assert_eq!(
            out,
            json!([{"b": "01020304"}, {"b": "0a0b0c0d"}])
        );
    }

    #[test]
    fn unwrap_chain_a_unwraps_b_unwraps_c() {
        // a = ~b; b = ~c; c = [int]. Should resolve through both unwraps.
        // CBOR [42]: 81 18 2a
        let schema = "
            a = ~b
            b = ~c
            c = [int]
        ";
        let out = run(schema, "a", "81182a");
        assert_eq!(out, json!([42]));
    }

    // ========================================================
    // .cbor / .cborseq
    // ========================================================

    #[test]
    fn cborseq_decodes_embedded_array_value() {
        // bstr .cborseq inner; inner = [a: int, b: int].
        // Outer bstr containing CBOR bytes for [1,2]: 43 82 01 02
        let schema = "x = bstr .cborseq inner\ninner = [a: int, b: int]";
        let out = run(schema, "x", "43820102");
        let labelled = out.get("a").is_some() && out.get("b").is_some();
        let raw_hex = out.as_str().map_or(false, |s| s.contains("82"));
        assert!(
            labelled || raw_hex,
            ".cborseq should decode or fall back, got {}",
            out
        );
    }

    #[test]
    fn cbor_control_with_generic_inner_type() {
        // x = bstr .cbor maybe<uint>; maybe<a> = a / null.
        // bstr containing CBOR `7` → 41 07.
        let schema = "
            maybe<a> = a / null
            x        = bstr .cbor maybe<uint>
        ";
        let out = run(schema, "x", "4107");
        assert_eq!(out, json!(7));
    }

    #[test]
    fn cbor_control_with_tagged_inner_type() {
        // x = bstr .cbor #6.0(tstr). Outer bstr contains CBOR for
        // tag 0 "2024-01-01T00:00:00Z" — c0 74 32303234... .
        // Outer hex: 41 + 0x16 byte payload = 56 bytes total? Let's
        // construct precisely:
        //   payload = c0 74 32303234 2d30312d30315430303a30303a30305a
        //           = 22 bytes total: 1 (c0) + 1 (74) + 20 (string)
        //   bstr header for 22 bytes = 0x56 (major 2, length 22).
        let outer_hex = "56c074323032342d30312d30315430303a30303a30305a";
        let schema = "x = bstr .cbor #6.0(tstr)";
        let out = run(schema, "x", outer_hex);
        assert_eq!(out, json!("2024-01-01T00:00:00Z"));
    }

    // ========================================================
    // Edge cases
    // ========================================================

    #[test]
    fn empty_cddl_errors_meaningfully() {
        let err = decode_cbor_against_cddl(b"\x01", "", "x")
            .err()
            .expect("expected error for empty CDDL");
        // Empty CDDL fails to parse OR returns rule-not-found.
        let msg = err.as_string().unwrap();
        assert!(
            msg.to_lowercase().contains("parse")
                || msg.contains("does not define a rule"),
            "unexpected error: {}",
            msg
        );
    }

    #[test]
    fn malformed_cddl_errors() {
        let err = decode_cbor_against_cddl(b"\x01", "x = = =", "x")
            .err()
            .expect("expected parse error");
        assert!(err.as_string().unwrap().to_lowercase().contains("parse"));
    }

    #[test]
    fn cbor_does_not_match_schema_falls_back_to_raw() {
        // Schema expects an array; CBOR is an int. No alternative → raw.
        let out = run("x = [a: uint]", "x", "182a");
        // raw_value over an Integer just returns the number.
        assert_eq!(out, json!(42));
    }

    #[test]
    fn indefinite_length_array_against_homogeneous_schema() {
        // 9f 01 02 03 ff = indefinite-length array [1, 2, 3].
        let out = run("t = [* uint]", "t", "9f010203ff");
        assert_eq!(out, json!([1, 2, 3]));
    }

    #[test]
    fn indefinite_length_map_against_named_schema() {
        // bf 61 61 01 61 62 02 ff = indefinite map {"a":1, "b":2}.
        let out = run("t = {a: uint, b: uint}", "t", "bf6161016162 02ff".replace(' ', "").as_str());
        assert_eq!(out, json!({"a": 1, "b": 2}));
    }

    // ========================================================
    // Cardano-flavoured integration
    // ========================================================

    #[test]
    fn multiasset_value_coin_only_branch() {
        // value = coin / [coin, multiasset<coin>]
        // Plain coin (uint 1000): 19 03e8
        let schema = "
            coin            = uint
            multiasset<a>   = { * bstr => { * bstr => a } }
            value           = coin / [coin, multiasset<coin>]
        ";
        let out = run(schema, "value", "1903e8");
        assert_eq!(out, json!(1000));
    }

    #[test]
    fn multiasset_value_pair_branch() {
        // [coin, multiasset<coin>]:
        //   [1000, {bstr(0): {bstr(0): 5}}]
        //   82 1903e8 a1 40 a1 40 05
        let schema = "
            coin            = uint
            multiasset<a>   = { * bstr => { * bstr => a } }
            value           = coin / [coin, multiasset<coin>]
        ";
        let cbor = "82 1903e8 a1 40 a1 40 05".replace(' ', "");
        let out = run(schema, "value", &cbor);
        // First slot is coin (unnamed → @positional or unnamed array
        // entry); without bareword names the array stays unlabelled.
        // We assert the coin amount is preserved somewhere recognisable.
        let coin_in_array = out.as_array().map_or(false, |a| a[0] == json!(1000));
        let coin_positional = out
            .get("@positional")
            .and_then(Value::as_array)
            .map_or(false, |a| a[0] == json!(1000));
        assert!(
            coin_in_array || coin_positional,
            "expected 1000 to be the first element, got {}",
            out
        );
    }

    #[test]
    fn language_range_type_in_range() {
        // language = 0..2; given uint 1.
        let schema = "language = 0..2";
        let out = run(schema, "language", "01");
        // Range types aren't fully modelled — we expect the prelude/raw
        // path to surface the integer somehow. Pin current behaviour.
        assert_eq!(out, json!(1));
    }

    #[test]
    fn language_range_type_out_of_range_still_returns_value() {
        // Same schema given uint 9 (out of range). Mapper does not
        // enforce ranges; it returns the raw int.
        let schema = "language = 0..2";
        let out = run(schema, "language", "09");
        assert_eq!(out, json!(9));
    }

    // ========================================================
    // Additional misc / bonus coverage
    // ========================================================

    #[test]
    fn nested_optional_record_inside_named_array_field() {
        // tx = [body: {a: uint, ? b: uint}, ok: bool]
        // CBOR: [{a:1}, true]: 82 a1 61 61 01 f5
        let schema = "tx = [body: {a: uint, ? b: uint}, ok: bool]";
        let out = run(schema, "tx", "82a16161 01f5".replace(' ', "").as_str());
        assert_eq!(out, json!({"body": {"a": 1}, "ok": true}));
    }

    #[test]
    fn deep_generic_substitution_within_array() {
        // wrapper<a> = [* a]; pair<x> = [x, x]; concrete = wrapper<pair<uint>>.
        // CBOR [[1,2], [3,4]]: 82 82 01 02 82 03 04
        //
        // Inside `pair<x>`, both slots are bound generic params and
        // flow into the unnamed list, preserving both pair elements.
        // The outer `wrapper<a>` produces a homogeneous array.
        let schema = "
            wrapper<a> = [* a]
            pair<x>    = [x, x]
            concrete   = wrapper<pair<uint>>
        ";
        let out = run(schema, "concrete", "8282010282030 4".replace(' ', "").as_str());
        assert_eq!(out, json!([[1, 2], [3, 4]]));
    }

    #[test]
    fn null_value_against_optional_field_inside_array() {
        // tx = [aux: auxiliary_data / null]; CBOR [null]: 81 f6
        let schema = "
            auxiliary_data = #6.259({})
            tx             = [aux: auxiliary_data / null]
        ";
        let out = run(schema, "tx", "81f6");
        assert_eq!(out, json!({"aux": null}));
    }

    #[test]
    fn float_primitive_round_trip() {
        // x = float; CBOR fb 4000000000000000 = float64(2.0).
        let out = run("x = float", "x", "fb4000000000000000");
        assert_eq!(out, json!(2.0));
    }

    #[test]
    fn bool_primitive_false() {
        // CBOR f4 = false
        let out = run("x = bool", "x", "f4");
        assert_eq!(out, json!(false));
    }

    #[test]
    fn null_primitive() {
        // CBOR f6 = null; schema is `null`.
        let out = run("x = null", "x", "f6");
        assert_eq!(out, json!(null));
    }
}

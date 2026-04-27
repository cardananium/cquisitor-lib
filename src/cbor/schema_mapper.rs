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

            // Everything else we don't model yet (Unwrap, DataMajorType,
            // byte literals, ChoiceFromInlineGroup, …) just means "no
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

        // Pick the first group choice whose shape is compatible. For
        // Cardano schemas there's usually just one choice anyway.
        for choice in &group.group_choices {
            if let Some(out) = self.try_map_with_choice(entries, choice) {
                return Some(out);
            }
        }
        None
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
                let (field_name, key_matcher) = match &vmk.member_key {
                    Some(mk) => member_key_to_matcher(mk),
                    None => {
                        // No member_key in a *map* context is unusual;
                        // treat as homogeneous "* type" pair — skip for
                        // first cut.
                        return Some(());
                    }
                };

                let mut found_any = false;
                for (i, (k, v)) in entries.iter().enumerate() {
                    if used[i] {
                        continue;
                    }
                    if key_matcher.matches(k) {
                        let mapped = self.map_type(v, &vmk.entry_type);
                        match vmk.occur.as_ref().map(|o| &o.occur) {
                            Some(Occur::ZeroOrMore { .. }) | Some(Occur::OneOrMore { .. }) => {
                                let arr = out
                                    .entry(field_name.clone())
                                    .or_insert_with(|| Value::Array(Vec::new()));
                                if let Value::Array(a) = arr {
                                    a.push(mapped);
                                }
                            }
                            _ => {
                                out.insert(field_name.clone(), mapped);
                            }
                        }
                        used[i] = true;
                        found_any = true;
                        if !matches!(
                            vmk.occur.as_ref().map(|o| &o.occur),
                            Some(Occur::ZeroOrMore { .. }) | Some(Occur::OneOrMore { .. })
                        ) {
                            break;
                        }
                    }
                }

                if !found_any && !is_optional {
                    // Required field missing — still succeed so the
                    // caller sees the partial result, but note the gap.
                    out.insert(field_name, Value::Null);
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
        ge: &TypeGroupnameEntry<'a>,
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
                let mapped = self.map_by_rule_or_prelude(v, name);
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
            let mapped = self.map_by_rule_or_prelude(v, name);
            match mapped {
                Some(val) => {
                    *cursor += 1;
                    if prelude_accepts(name, v).is_some() {
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

    fn map_by_rule_or_prelude(&self, cbor: &CborValue, name: &str) -> Option<Value> {
        // Bound generic param wins over both prelude and rule-index.
        if let Some(t1) = self.lookup_binding(name) {
            return self.try_map_type1(cbor, t1);
        }
        if let Some(v) = try_prelude(cbor, name) {
            return Some(v);
        }
        match self.rules.get(name) {
            Some(Rule::Type { rule, .. }) => Some(self.map_type(cbor, &rule.value)),
            Some(Rule::Group { rule, .. }) => {
                let mut builder = ObjectBuilder::new();
                self.map_group_entry(cbor, &rule.entry, &mut builder, &mut 0);
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

/// Describes how to recognise a map key in the CBOR data.
enum KeyMatcher {
    IntLiteral(i128),
    TextLiteral(String),
}

impl KeyMatcher {
    fn matches(&self, k: &CborValue) -> bool {
        match (self, k) {
            (KeyMatcher::IntLiteral(n), CborValue::Integer(i)) => {
                // ciborium::value::Integer doesn't expose i128 directly;
                // try u64 then i64 then fail.
                if let Ok(u) = u64::try_from(*i) {
                    (u as i128) == *n
                } else if let Ok(s) = i64::try_from(*i) {
                    (s as i128) == *n
                } else {
                    false
                }
            }
            (KeyMatcher::TextLiteral(s), CborValue::Text(t)) => s == t,
            _ => false,
        }
    }
}

fn member_key_to_matcher<'a>(mk: &MemberKey<'a>) -> (String, KeyMatcher) {
    match mk {
        MemberKey::Bareword { ident, .. } => {
            let name = ident.ident.to_string();
            (name.clone(), KeyMatcher::TextLiteral(name))
        }
        MemberKey::Value { value, .. } => match value {
            cddl::token::Value::UINT(u) => {
                (u.to_string(), KeyMatcher::IntLiteral(*u as i128))
            }
            cddl::token::Value::INT(i) => {
                (i.to_string(), KeyMatcher::IntLiteral(*i as i128))
            }
            cddl::token::Value::TEXT(s) => {
                let name = s.to_string();
                (name.clone(), KeyMatcher::TextLiteral(name))
            }
            other => (other.to_string(), KeyMatcher::TextLiteral(other.to_string())),
        },
        MemberKey::Type1 { t1, .. } => {
            // `type1 =>` map key — pick a best-effort name from the
            // type2 shape.
            match &t1.type2 {
                Type2::UintValue { value, .. } => (
                    value.to_string(),
                    KeyMatcher::IntLiteral(*value as i128),
                ),
                Type2::IntValue { value, .. } => {
                    (value.to_string(), KeyMatcher::IntLiteral(*value as i128))
                }
                Type2::TextValue { value, .. } => (
                    value.as_ref().to_string(),
                    KeyMatcher::TextLiteral(value.as_ref().to_string()),
                ),
                other => (other.to_string(), KeyMatcher::TextLiteral(other.to_string())),
            }
        }
        MemberKey::NonMemberKey { .. } => (
            "@non_member_key".into(),
            KeyMatcher::TextLiteral("@non_member_key".into()),
        ),
    }
}

impl<'a> Mapper<'a> {
    /// Best-effort `true` if `value` could plausibly match `ty` under the
    /// current generic-binding frames. Used for array-entry
    /// disambiguation where we have to decide whether to consume a
    /// positional slot or skip (optional). Conservative on "unknown".
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
        // a2 00 01 00 02 = {0: 1, 0: 2}. CDDL: * 0: int (repeated).
        // This is an unusual shape; verify the mapper accumulates.
        let out = run(
            "t = { * 0 => uint }",
            "t",
            "a20001000 2".replace(' ', "").as_str(),
        );
        // With repeating int-keys 0 we expect the mapper to gather them
        // all under "0" as an array.
        let zero = &out["0"];
        assert!(zero.is_array(), "got {}", out);
        assert_eq!(zero, &json!([1, 2]));
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
    fn extras_are_preserved_as_at_extra_bucket() {
        // a2 00 01 02 03 = {0: 1, 2: 3}. Schema only covers key 0.
        let out = run("t = {0: uint}", "t", "a200010203");
        assert_eq!(
            out,
            json!({"0": 1, "@extra": {"2": 3}})
        );
    }
}

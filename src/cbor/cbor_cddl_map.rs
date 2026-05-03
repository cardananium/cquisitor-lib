//! Bidirectional CBOR ↔ CDDL position map.
//!
//! For UIs that need to highlight CDDL when the user clicks on a CBOR
//! byte (and vice versa), regardless of whether the document validates.
//! Walks the decoded CBOR positional tree and the CDDL AST in parallel,
//! emitting one entry per visited node.
//!
//! Output: a flat array of `{cbor_path, cbor_byte_span, cbor_anchor_span,
//! cddl_byte_span, rule_name?}`. Order is depth-first pre-order, so a
//! parent's entry precedes its children's. Filter / index on the
//! consumer side for whatever shape your UI needs.

use std::cell::RefCell;
use std::collections::HashMap;

use cddl::ast::{
    GenericArgs, GenericParams, GroupEntry, MemberKey, Rule, Type, Type1, Type2, CDDL,
};
use serde_json::{Map, Value};

use crate::cbor::decoder;
use crate::cbor::source_index::{span_json, Utf16Index};
use crate::js_error::JsError;

/// Entry point. Returns a JSON array of mapping entries — one per node
/// visited during the parallel walk. Empty array if the CBOR has zero
/// nodes the schema can match (rare; we always emit at least the root).
pub fn map_cbor_to_cddl(
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

    let tree = decoder::decode_cbor_to_value(cbor).map_err(|e| {
        JsError::new(&format!("CBOR decode error: {}", e.message))
    })?;

    let mapper = PosMapper {
        rules,
        bindings: RefCell::new(Vec::new()),
        entries: RefCell::new(Vec::new()),
        utf16: Utf16Index::new(cddl),
        cddl_source: cddl,
    };

    let root_type = mapper.rules.get_type_body(rule_name);
    if let Some(ty) = root_type {
        // Top-level entry uses the rule's own name span as its CDDL
        // anchor — that's the most useful "what matched the root" pointer.
        let rule_span = mapper.rules.get_rule_name_span(rule_name);
        mapper.emit(&tree, "$", "$", rule_span.unwrap_or(ty.span), Some(rule_name));
        mapper.walk_type(&tree, "$", "$", ty);
    } else if let Some(rule) = mapper.rules.get(rule_name) {
        // Group rule at the top level — uncommon, but still emit a
        // root-level entry.
        let rule_span = match rule {
            Rule::Group { rule, .. } => rule.name.span,
            Rule::Type { rule, .. } => rule.name.span,
        };
        mapper.emit(&tree, "$", "$", rule_span, Some(rule_name));
    }

    Ok(Value::Array(mapper.entries.into_inner()))
}

// ============================================================
// Rule index
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

    fn get_type_body(&self, name: &str) -> Option<&'a Type<'a>> {
        match self.by_name.get(name).copied()? {
            Rule::Type { rule, .. } => Some(&rule.value),
            _ => None,
        }
    }

    fn get_rule_name_span(&self, name: &str) -> Option<cddl::ast::Span> {
        match self.by_name.get(name).copied()? {
            Rule::Type { rule, .. } => Some(rule.name.span),
            Rule::Group { rule, .. } => Some(rule.name.span),
        }
    }

    fn rule_generic_params(&self, name: &str) -> Option<&'a GenericParams<'a>> {
        match self.by_name.get(name).copied()? {
            Rule::Type { rule, .. } => rule.generic_params.as_ref(),
            Rule::Group { rule, .. } => rule.generic_params.as_ref(),
        }
    }
}

// ============================================================
// Walker
// ============================================================

type BindingFrame<'a> = HashMap<String, &'a Type1<'a>>;

struct PosMapper<'a> {
    rules: RuleIndex<'a>,
    bindings: RefCell<Vec<BindingFrame<'a>>>,
    entries: RefCell<Vec<Value>>,
    utf16: Utf16Index,
    /// Original CDDL source — needed to tighten member-key spans
    /// (pest reports the broad `name: type` span; we trim it to just
    /// the key declaration).
    cddl_source: &'a str,
}

impl<'a> PosMapper<'a> {
    fn lookup_binding(&self, name: &str) -> Option<&'a Type1<'a>> {
        let stack = self.bindings.borrow();
        for frame in stack.iter().rev() {
            if let Some(t1) = frame.get(name) {
                return Some(*t1);
            }
        }
        None
    }

    fn push_frame(
        &self,
        params: Option<&GenericParams<'a>>,
        args: Option<&'a GenericArgs<'a>>,
    ) -> bool {
        let (Some(params), Some(args)) = (params, args) else {
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

    /// Emit one mapping entry. `cddl_span` is the span of whichever
    /// AST node best describes this CBOR position (a Type, the rule
    /// name, an Identifier, …). `rule_name` is set when we crossed a
    /// rule boundary at this point.
    fn emit(
        &self,
        cbor_node: &Value,
        cbor_path: &str,
        decoded_path: &str,
        cddl_span: cddl::ast::Span,
        rule_name: Option<&str>,
    ) {
        self.emit_with_role(cbor_node, cbor_path, decoded_path, cddl_span, rule_name, "value");
    }

    /// Emit a row for the synthetic `@tag` field. CBOR span = tag
    /// header bytes (position_info on the Tag node), not the whole
    /// tag struct — UI typically wants to highlight just `d9 0102`,
    /// not the whole `Tag(258, [...])` extent.
    fn emit_tag_label(
        &self,
        tag_node: &Value,
        cbor_path: &str,
        decoded_path: &str,
        cddl_span: cddl::ast::Span,
    ) {
        let mut entry = Map::new();
        entry.insert("cbor_path".into(), Value::String(cbor_path.to_string()));
        entry.insert("decoded_path".into(), Value::String(decoded_path.to_string()));
        entry.insert("entry_role".into(), Value::String("value".to_string()));
        if let Some(pos) = tag_node.get("position_info") {
            entry.insert("cbor_byte_span".into(), pos.clone());
            entry.insert("cbor_anchor_span".into(), pos.clone());
        }
        let (start, end, line) = cddl_span;
        entry.insert(
            "cddl_byte_span".into(),
            span_json(&self.utf16, start, end, line),
        );
        entry.insert("cbor_type".into(), Value::String("tag".to_string()));
        self.entries.borrow_mut().push(Value::Object(entry));
    }

    /// Emit a row for a synthetic wrapper key (`@entries`,
    /// `@positional`, `@extra`). These sit at decoded paths but have
    /// no direct CDDL counterpart — `cddl_byte_span` is omitted. The
    /// CBOR span covers the bytes the wrapper "represents" in the
    /// decoded JSON.
    fn emit_synthetic_wrapper(
        &self,
        cbor_path: &str,
        decoded_path: &str,
        cbor_byte_span: Value,
        cbor_anchor_span: Value,
        cbor_type_label: &str,
    ) {
        let mut entry = Map::new();
        entry.insert("cbor_path".into(), Value::String(cbor_path.to_string()));
        entry.insert("decoded_path".into(), Value::String(decoded_path.to_string()));
        entry.insert("entry_role".into(), Value::String("value".to_string()));
        entry.insert("cbor_byte_span".into(), cbor_byte_span);
        entry.insert("cbor_anchor_span".into(), cbor_anchor_span);
        entry.insert("cbor_type".into(), Value::String(cbor_type_label.to_string()));
        // `cddl_byte_span` is intentionally omitted — wrappers have
        // no schema construct that describes them.
        self.entries.borrow_mut().push(Value::Object(entry));
    }

    fn emit_with_role(
        &self,
        cbor_node: &Value,
        cbor_path: &str,
        decoded_path: &str,
        cddl_span: cddl::ast::Span,
        rule_name: Option<&str>,
        entry_role: &str,
    ) {
        let mut entry = Map::new();
        entry.insert("cbor_path".into(), Value::String(cbor_path.to_string()));
        entry.insert(
            "decoded_path".into(),
            Value::String(decoded_path.to_string()),
        );
        entry.insert("entry_role".into(), Value::String(entry_role.to_string()));
        if let Some(pos) = cbor_node.get("position_info") {
            entry.insert("cbor_byte_span".into(), pos.clone());
        }
        if let Some(pos) = cbor_node
            .get("struct_position_info")
            .or_else(|| cbor_node.get("position_info"))
        {
            entry.insert("cbor_anchor_span".into(), pos.clone());
        }
        let (start, end, line) = cddl_span;
        entry.insert(
            "cddl_byte_span".into(),
            span_json(&self.utf16, start, end, line),
        );
        if let Some(name) = rule_name {
            entry.insert("rule_name".into(), Value::String(name.to_string()));
        }
        if let Some(t) = cbor_node.get("type").and_then(Value::as_str) {
            entry.insert("cbor_type".into(), Value::String(t.to_string()));
        }
        self.entries.borrow_mut().push(Value::Object(entry));
    }

    /// Walk a `Type` (OR of choices) against `node`. Tries choices in
    /// order; the first that descends successfully wins.
    fn walk_type(
        &self,
        node: &Value,
        cbor_path: &str,
        decoded_path: &str,
        ty: &'a Type<'a>,
    ) {
        // First try matching at the current depth — e.g. when the
        // schema is itself `#6.258(...)`, we need the Tag node intact.
        for choice in &ty.type_choices {
            if self.try_walk_type2(node, cbor_path, decoded_path, &choice.type1.type2) {
                return;
            }
        }
        // Nothing matched at this depth. If we're holding a Tag,
        // transparently unwrap (anweiss-style: tags are invisible to
        // the path grammar) and retry. This lets a `[* a]` schema
        // match a `Tag(258, [* a])` value.
        let unwrapped = unwrap_tags(node);
        if !std::ptr::eq(unwrapped, node) {
            for choice in &ty.type_choices {
                if self.try_walk_type2(unwrapped, cbor_path, decoded_path, &choice.type1.type2)
                {
                    return;
                }
            }
        }
        // Fall-through: nothing matched. Still emit so the consumer
        // gets *something* for this CBOR position, pointing at the
        // type definition.
        self.emit(node, cbor_path, decoded_path, ty.span, None);
    }

    fn try_walk_type2(
        &self,
        node: &Value,
        cbor_path: &str,
        decoded_path: &str,
        t2: &'a Type2<'a>,
    ) -> bool {
        let cbor_type = node.get("type").and_then(Value::as_str).unwrap_or("");

        match t2 {
            Type2::Typename { ident, generic_args, .. } => {
                if generic_args.is_none() {
                    if let Some(t1) = self.lookup_binding(ident.ident) {
                        return self.try_walk_type2(node, cbor_path, decoded_path, &t1.type2);
                    }
                    if prelude_matches(ident.ident, cbor_type) {
                        self.emit(node, cbor_path, decoded_path, ident.span, Some(ident.ident));
                        return true;
                    }
                }
                match self.rules.get(ident.ident) {
                    Some(Rule::Type { rule, .. }) => {
                        let pushed = self.push_frame(
                            self.rules.rule_generic_params(ident.ident),
                            generic_args.as_ref(),
                        );
                        self.emit(node, cbor_path, decoded_path, rule.name.span, Some(ident.ident));
                        self.walk_type(node, cbor_path, decoded_path, &rule.value);
                        if pushed {
                            self.pop_frame();
                        }
                        true
                    }
                    Some(Rule::Group { .. }) => {
                        // Group rule referenced as a type — best
                        // effort: emit the rule name span and stop.
                        self.emit(node, cbor_path, decoded_path, ident.span, Some(ident.ident));
                        true
                    }
                    None => false,
                }
            }
            Type2::Unwrap { ident, generic_args, .. } => {
                if generic_args.is_none() {
                    if let Some(t1) = self.lookup_binding(ident.ident) {
                        return self.try_walk_type2(node, cbor_path, decoded_path, &t1.type2);
                    }
                }
                match self.rules.get(ident.ident) {
                    Some(Rule::Type { rule, .. }) => {
                        let pushed = self.push_frame(
                            self.rules.rule_generic_params(ident.ident),
                            generic_args.as_ref(),
                        );
                        self.emit(node, cbor_path, decoded_path, rule.name.span, Some(ident.ident));
                        self.walk_type(node, cbor_path, decoded_path, &rule.value);
                        if pushed {
                            self.pop_frame();
                        }
                        true
                    }
                    Some(Rule::Group { .. }) => {
                        self.emit(node, cbor_path, decoded_path, ident.span, Some(ident.ident));
                        true
                    }
                    None => false,
                }
            }
            Type2::ParenthesizedType { pt, .. } => {
                self.walk_type(node, cbor_path, decoded_path, pt);
                true
            }
            Type2::TaggedData { t, span, .. } => {
                if cbor_type != "Tag" {
                    return false;
                }
                self.emit(node, cbor_path, decoded_path, *span, None);
                if let Some(inner) = node.get("value") {
                    // Tag-side: anweiss-style transparent for cbor_path.
                    // Decoded-side: `decode_cbor_against_cddl` wraps
                    // unspecialized tags as `{@tag, @value}`. Tags 0/2/3
                    // are specialised to scalar leaves there, so we
                    // don't add `@value` for those.
                    let tag_n = node.get("tag").and_then(Value::as_str);
                    let is_specialised = matches!(
                        tag_n,
                        Some("DateTime") | Some("UnsignedBignum") | Some("NegativeBignum")
                    );
                    if !is_specialised {
                        // Synthetic `@tag` row — UI right-click on the
                        // "tag: 258" line resolves here. cbor span is
                        // just the tag header bytes (header = position_info
                        // on the Tag node).
                        let tag_path = format!(r#"{}["@tag"]"#, decoded_path);
                        self.emit_tag_label(node, cbor_path, &tag_path, *span);
                    }
                    let new_decoded = if is_specialised {
                        decoded_path.to_string()
                    } else {
                        format!(r#"{}["@value"]"#, decoded_path)
                    };
                    self.walk_type(inner, cbor_path, &new_decoded, t);
                }
                true
            }
            Type2::Map { group, span, .. } => {
                if cbor_type != "Map" {
                    return false;
                }
                self.emit(node, cbor_path, decoded_path, *span, None);
                self.walk_map_against_group(node, cbor_path, decoded_path, group);
                true
            }
            Type2::Array { group, span, .. } => {
                if cbor_type != "Array" {
                    return false;
                }
                self.emit(node, cbor_path, decoded_path, *span, None);
                self.walk_array_against_group(node, cbor_path, decoded_path, group);
                true
            }
            // Literal / scalar matchers — no recursion needed; just
            // emit the type's span as the descriptor.
            other => {
                self.emit(node, cbor_path, decoded_path, type2_span(other), None);
                true
            }
        }
    }

    /// Walk each map entry against the schema's group entries. We do
    /// a position-based parallel walk: for each schema entry whose
    /// member_key matches an unused CBOR entry's key, descend.
    ///
    /// Mirrors `decode_cbor_against_cddl`'s shape decision: object
    /// form when all keys are simple primitives and there are no
    /// duplicates; `@entries` form otherwise. Either way, every
    /// addressable JSON path the decoder produces gets a row here.
    fn walk_map_against_group(
        &self,
        map_node: &Value,
        cbor_path: &str,
        decoded_path: &str,
        group: &'a cddl::ast::Group<'a>,
    ) {
        let Some(entries) = map_node.get("values").and_then(Value::as_array) else {
            return;
        };

        // Skip the `Break` sentinel that indefinite-length maps end
        // with — it isn't a real entry.
        let real_entries: Vec<&Value> = entries
            .iter()
            .filter(|e| e.get("key").is_some() && e.get("value").is_some())
            .collect();

        let needs_entries = real_entries
            .iter()
            .any(|e| !is_simple_cbor_key_json(e.get("key").unwrap()))
            || cbor_keys_have_duplicates_json(&real_entries);

        if needs_entries {
            self.walk_map_in_entries_form(map_node, cbor_path, decoded_path, group, &real_entries);
            return;
        }

        // Object form (existing path).
        let mut used = vec![false; entries.len()];
        for choice in &group.group_choices {
            for (ge, _) in &choice.group_entries {
                self.consume_map_entry(ge, entries, &mut used, cbor_path, decoded_path);
            }
        }

        // Emit `@extra` rows for any entries the schema didn't cover.
        // First a wrapper entry at `<map>["@extra"]`, then one row per
        // leftover under `<map>["@extra"][<key>]` so right-click on
        // either resolves.
        let leftover_indices: Vec<usize> =
            (0..entries.len()).filter(|&i| !used[i] && entries[i].get("key").is_some()).collect();
        if !leftover_indices.is_empty() {
            let extra_path = format!(r#"{}["@extra"]"#, decoded_path);
            let (wrapper_byte, wrapper_anchor) =
                wrapper_span_over_entries(&entries, &leftover_indices);
            self.emit_synthetic_wrapper(
                cbor_path,
                &extra_path,
                wrapper_byte,
                wrapper_anchor,
                "map_extra",
            );
            for i in leftover_indices {
                let entry = &entries[i];
                let Some(key) = entry.get("key") else { continue };
                let Some(value) = entry.get("value") else { continue };
                let key_label = json_key_label(key);
                let pair_decoded = extend_decoded_path(&extra_path, &key_label);
                // Pair value entry — points at the leftover entry's
                // value bytes. No cddl span (no schema construct).
                self.emit_synthetic_no_cddl(
                    value,
                    cbor_path,
                    &pair_decoded,
                    "value",
                );
            }
        }
    }

    /// Emit rows that mirror the `@entries` shape produced by
    /// `decode_cbor_against_cddl` when the map has duplicate or
    /// complex keys. One wrapper row at `["@entries"]`, one per pair
    /// at `["@entries"][N]`, plus per-pair `.key` and `.value`
    /// addressable rows.
    fn walk_map_in_entries_form(
        &self,
        map_node: &Value,
        cbor_path: &str,
        decoded_path: &str,
        group: &'a cddl::ast::Group<'a>,
        entries: &[&Value],
    ) {
        let entries_path = format!(r#"{}["@entries"]"#, decoded_path);

        // Wrapper row over the whole `@entries` array. cbor span
        // covers the inner CBOR map structure (excluding the map
        // header) — fall back to map's own struct span.
        let map_anchor = map_node
            .get("struct_position_info")
            .or_else(|| map_node.get("position_info"))
            .cloned()
            .unwrap_or(Value::Null);
        let map_byte = map_node
            .get("position_info")
            .cloned()
            .unwrap_or_else(|| map_anchor.clone());
        self.emit_synthetic_wrapper(
            cbor_path,
            &entries_path,
            map_byte,
            map_anchor,
            "map_entries",
        );

        for (idx, entry) in entries.iter().enumerate() {
            let Some(key_node) = entry.get("key") else { continue };
            let Some(value_node) = entry.get("value") else { continue };
            let pair_path = format!("{}[{}]", entries_path, idx);
            let key_path = format!(r#"{}["key"]"#, pair_path);
            let value_path = format!(r#"{}["value"]"#, pair_path);

            // Find the schema entry whose member_key accepts this cbor key.
            let matched = self.find_matching_member_entry(group, key_node);

            // Pair wrapper row — covers key+value bytes combined.
            let key_anchor = key_node
                .get("struct_position_info")
                .or_else(|| key_node.get("position_info"));
            let value_anchor = value_node
                .get("struct_position_info")
                .or_else(|| value_node.get("position_info"));
            let pair_byte_span = key_node.get("position_info").cloned().unwrap_or(Value::Null);
            let pair_anchor_span = combine_span(key_anchor, value_anchor);
            let pair_cddl = matched
                .as_ref()
                .map(|(mk, _)| member_key_span(mk, self.cddl_source));
            self.emit_pair_wrapper(
                cbor_path,
                &pair_path,
                pair_byte_span,
                pair_anchor_span,
                pair_cddl,
            );

            // Key row at `["@entries"][N]["key"]`.
            let key_byte = key_node.get("position_info").cloned().unwrap_or(Value::Null);
            let key_anchor_owned = key_anchor
                .cloned()
                .unwrap_or_else(|| key_byte.clone());
            self.emit_entries_key_or_value(
                cbor_path,
                &key_path,
                key_byte,
                key_anchor_owned,
                pair_cddl,
                "key",
                key_node.get("type").and_then(Value::as_str),
            );

            // Value row at `["@entries"][N]["value"]` — walk through
            // the matched entry's value type so deeper paths resolve.
            let value_type_span = matched
                .as_ref()
                .map(|(_, vt)| vt.span);
            // Synthetic wrapper row pointing at the value bytes
            // (separate from the deep walk, which emits its own rows).
            let value_byte = value_node
                .get("position_info")
                .cloned()
                .unwrap_or(Value::Null);
            let value_anchor_owned = value_anchor
                .cloned()
                .unwrap_or_else(|| value_byte.clone());
            self.emit_entries_key_or_value(
                cbor_path,
                &value_path,
                value_byte,
                value_anchor_owned,
                value_type_span,
                "value",
                value_node.get("type").and_then(Value::as_str),
            );
            if let Some((_, vt)) = matched {
                self.walk_type(value_node, cbor_path, &value_path, vt);
            }
        }
    }

    /// Find the first schema member whose `member_key` accepts the
    /// given cbor key node (literal-text match against bareword /
    /// value literal, or accept-anything for type1 keys). Returns the
    /// matched MemberKey and value Type. Best-effort — if nothing
    /// matches, returns None.
    fn find_matching_member_entry(
        &self,
        group: &'a cddl::ast::Group<'a>,
        key_node: &Value,
    ) -> Option<(&'a MemberKey<'a>, &'a Type<'a>)> {
        for choice in &group.group_choices {
            for (ge, _) in &choice.group_entries {
                if let GroupEntry::ValueMemberKey { ge, .. } = ge {
                    let Some(mk) = &ge.member_key else { continue };
                    if member_key_matches_json(mk, key_node) {
                        return Some((mk, &ge.entry_type));
                    }
                }
            }
        }
        // Fallback: use the first entry's value type so deep walks
        // still produce paths.
        for choice in &group.group_choices {
            for (ge, _) in &choice.group_entries {
                if let GroupEntry::ValueMemberKey { ge, .. } = ge {
                    if let Some(mk) = &ge.member_key {
                        return Some((mk, &ge.entry_type));
                    }
                }
            }
        }
        None
    }

    fn emit_pair_wrapper(
        &self,
        cbor_path: &str,
        decoded_path: &str,
        cbor_byte: Value,
        cbor_anchor: Value,
        cddl_span: Option<cddl::ast::Span>,
    ) {
        let mut entry = Map::new();
        entry.insert("cbor_path".into(), Value::String(cbor_path.to_string()));
        entry.insert("decoded_path".into(), Value::String(decoded_path.to_string()));
        entry.insert("entry_role".into(), Value::String("value".to_string()));
        entry.insert("cbor_byte_span".into(), cbor_byte);
        entry.insert("cbor_anchor_span".into(), cbor_anchor);
        entry.insert("cbor_type".into(), Value::String("map_entry".to_string()));
        if let Some((s, e, l)) = cddl_span {
            entry.insert("cddl_byte_span".into(), span_json(&self.utf16, s, e, l));
        }
        self.entries.borrow_mut().push(Value::Object(entry));
    }

    fn emit_entries_key_or_value(
        &self,
        cbor_path: &str,
        decoded_path: &str,
        cbor_byte: Value,
        cbor_anchor: Value,
        cddl_span: Option<cddl::ast::Span>,
        role: &str,
        cbor_type: Option<&str>,
    ) {
        let mut entry = Map::new();
        entry.insert("cbor_path".into(), Value::String(cbor_path.to_string()));
        entry.insert("decoded_path".into(), Value::String(decoded_path.to_string()));
        entry.insert("entry_role".into(), Value::String(role.to_string()));
        entry.insert("cbor_byte_span".into(), cbor_byte);
        entry.insert("cbor_anchor_span".into(), cbor_anchor);
        if let Some(t) = cbor_type {
            entry.insert("cbor_type".into(), Value::String(t.to_string()));
        }
        if let Some((s, e, l)) = cddl_span {
            entry.insert("cddl_byte_span".into(), span_json(&self.utf16, s, e, l));
        }
        self.entries.borrow_mut().push(Value::Object(entry));
    }

    /// Emit a row whose entry has CBOR location info but no CDDL
    /// counterpart (used for `@extra` items).
    fn emit_synthetic_no_cddl(
        &self,
        cbor_node: &Value,
        cbor_path: &str,
        decoded_path: &str,
        role: &str,
    ) {
        let mut entry = Map::new();
        entry.insert("cbor_path".into(), Value::String(cbor_path.to_string()));
        entry.insert("decoded_path".into(), Value::String(decoded_path.to_string()));
        entry.insert("entry_role".into(), Value::String(role.to_string()));
        if let Some(pos) = cbor_node.get("position_info") {
            entry.insert("cbor_byte_span".into(), pos.clone());
        }
        if let Some(pos) = cbor_node
            .get("struct_position_info")
            .or_else(|| cbor_node.get("position_info"))
        {
            entry.insert("cbor_anchor_span".into(), pos.clone());
        }
        if let Some(t) = cbor_node.get("type").and_then(Value::as_str) {
            entry.insert("cbor_type".into(), Value::String(t.to_string()));
        }
        self.entries.borrow_mut().push(Value::Object(entry));
    }

    fn consume_map_entry(
        &self,
        ge: &'a GroupEntry<'a>,
        entries: &[Value],
        used: &mut [bool],
        cbor_parent: &str,
        decoded_parent: &str,
    ) {
        match ge {
            GroupEntry::ValueMemberKey { ge, .. } => {
                let mk = match &ge.member_key {
                    Some(m) => m,
                    None => return,
                };
                let matcher = key_matcher(mk);
                let mk_span = member_key_span(mk, self.cddl_source);
                for (i, entry) in entries.iter().enumerate() {
                    if used[i] {
                        continue;
                    }
                    let Some(key) = entry.get("key") else { continue };
                    let Some(value) = entry.get("value") else { continue };
                    if let Some(field_label) = matcher.matches(key) {
                        used[i] = true;
                        let cbor_p = extend_cbor_path(cbor_parent, &field_label);
                        let decoded_p = extend_decoded_path(decoded_parent, &field_label);
                        // Emit a key entry: same path as the value
                        // (both describe the same field), distinguished
                        // by `entry_role: "key"`. CBOR span points at
                        // the key's bytes; CDDL span points at the
                        // member_key declaration (`bareword:` or
                        // `<value>:` / `<type1> =>`).
                        self.emit_with_role(
                            key, &cbor_p, &decoded_p, mk_span, None, "key",
                        );
                        self.walk_type(value, &cbor_p, &decoded_p, &ge.entry_type);
                    }
                }
            }
            GroupEntry::TypeGroupname { ge, .. } => {
                if let Some(Rule::Group { rule, .. }) =
                    self.rules.get(ge.name.ident)
                {
                    self.consume_map_entry(
                        &rule.entry,
                        entries,
                        used,
                        cbor_parent,
                        decoded_parent,
                    );
                }
            }
            GroupEntry::InlineGroup { group, .. } => {
                for choice in &group.group_choices {
                    for (inner, _) in &choice.group_entries {
                        self.consume_map_entry(
                            inner,
                            entries,
                            used,
                            cbor_parent,
                            decoded_parent,
                        );
                    }
                }
            }
        }
    }

    fn walk_array_against_group(
        &self,
        arr_node: &Value,
        cbor_path: &str,
        decoded_path: &str,
        group: &'a cddl::ast::Group<'a>,
    ) {
        let Some(items) = arr_node.get("values").and_then(Value::as_array) else {
            return;
        };
        let items: Vec<&Value> = items
            .iter()
            .filter(|i| {
                i.get("type").and_then(Value::as_str) != Some("Break")
            })
            .collect();

        // Pre-scan: does this group choice contain any *named* entries
        // (bareword member key, or typename used as label)? If so, the
        // decoder produces an object — unnamed slots go to
        // `@positional`. If not, decoder produces an array.
        for choice in &group.group_choices {
            let any_named = choice.group_entries.iter().any(|(ge, _)| match ge {
                GroupEntry::ValueMemberKey { ge, .. } => {
                    ge.member_key.as_ref().and_then(bareword_label).is_some()
                }
                GroupEntry::TypeGroupname { ge, .. } => {
                    // Single-occurrence non-prelude → labelled by type name.
                    let name = ge.name.ident;
                    let is_consume_many = matches!(
                        ge.occur.as_ref().map(|o| &o.occur),
                        Some(cddl::ast::Occur::ZeroOrMore { .. })
                            | Some(cddl::ast::Occur::OneOrMore { .. })
                    );
                    !is_consume_many && !is_prelude_name(name)
                }
                _ => false,
            });

            let mut cursor = 0usize;
            let mut positional_indices: Vec<usize> = Vec::new();
            for (ge, _) in &choice.group_entries {
                self.consume_array_entry(
                    ge,
                    &items,
                    &mut cursor,
                    cbor_path,
                    decoded_path,
                    any_named,
                    &mut positional_indices,
                );
            }
            // `@positional` wrapper if any unlabelled slots were
            // consumed in a labelled group.
            if any_named && !positional_indices.is_empty() {
                let positional_path =
                    format!(r#"{}["@positional"]"#, decoded_path);
                let (byte, anchor) =
                    wrapper_span_over_items(&items, &positional_indices);
                self.emit_synthetic_wrapper(
                    cbor_path,
                    &positional_path,
                    byte,
                    anchor,
                    "array_positional",
                );
            }
            // `@extra` wrapper for items left unconsumed past schema cursor.
            if cursor < items.len() {
                let leftover_indices: Vec<usize> = (cursor..items.len()).collect();
                let extra_path = format!(r#"{}["@extra"]"#, decoded_path);
                let (byte, anchor) =
                    wrapper_span_over_items(&items, &leftover_indices);
                self.emit_synthetic_wrapper(
                    cbor_path,
                    &extra_path,
                    byte,
                    anchor,
                    "array_extra",
                );
                for i in leftover_indices {
                    let cbor_p = format!("{}[{}]", cbor_path, i);
                    let decoded_p =
                        format!(r#"{}["@extra"][{}]"#, decoded_path, i);
                    self.emit_synthetic_no_cddl(
                        items[i],
                        &cbor_p,
                        &decoded_p,
                        "value",
                    );
                }
            }
            // Pragmatic: first choice wins (producing every-choice's
            // mapping would multiply entries).
            break;
        }
    }

    fn consume_array_entry(
        &self,
        ge: &'a GroupEntry<'a>,
        items: &[&Value],
        cursor: &mut usize,
        cbor_parent: &str,
        decoded_parent: &str,
        any_named: bool,
        positional_indices: &mut Vec<usize>,
    ) {
        use cddl::ast::Occur;
        let consume_many = |occur: Option<&cddl::ast::Occurrence<'_>>| {
            matches!(
                occur.map(|o| &o.occur),
                Some(Occur::ZeroOrMore { .. }) | Some(Occur::OneOrMore { .. })
            )
        };

        match ge {
            GroupEntry::ValueMemberKey { ge, .. } => {
                let label = ge.member_key.as_ref().and_then(bareword_label);
                let many = consume_many(ge.occur.as_ref());
                let mk_paths = |cursor: usize| -> (String, String) {
                    match &label {
                        // Named entry — both paths use the bareword.
                        Some(name) => (
                            extend_cbor_path(cbor_parent, name),
                            extend_decoded_path(decoded_parent, name),
                        ),
                        // Unnamed in a labelled group → @positional in
                        // decoded output, positional `[i]` in cbor.
                        None if any_named => (
                            format!("{}[{}]", cbor_parent, cursor),
                            format!(r#"{}["@positional"][{}]"#, decoded_parent, cursor),
                        ),
                        // Pure homogeneous array → both positional.
                        None => (
                            format!("{}[{}]", cbor_parent, cursor),
                            format!("{}[{}]", decoded_parent, cursor),
                        ),
                    }
                };
                let is_positional = label.is_none() && any_named;
                if many {
                    while *cursor < items.len() {
                        if is_positional {
                            positional_indices.push(*cursor);
                        }
                        let (cbor_p, decoded_p) = mk_paths(*cursor);
                        self.walk_type(items[*cursor], &cbor_p, &decoded_p, &ge.entry_type);
                        *cursor += 1;
                    }
                } else if *cursor < items.len() {
                    if is_positional {
                        positional_indices.push(*cursor);
                    }
                    let (cbor_p, decoded_p) = mk_paths(*cursor);
                    self.walk_type(items[*cursor], &cbor_p, &decoded_p, &ge.entry_type);
                    *cursor += 1;
                }
            }
            GroupEntry::TypeGroupname { ge, .. } => {
                let many = consume_many(ge.occur.as_ref());
                let name = ge.name.ident;
                let is_label = !many
                    && !is_prelude_name(name)
                    && self.lookup_binding(name).is_none();
                let is_positional = !is_label && any_named;
                if many {
                    while *cursor < items.len() {
                        if is_positional {
                            positional_indices.push(*cursor);
                        }
                        let cbor_p = format!("{}[{}]", cbor_parent, *cursor);
                        let decoded_p = if any_named {
                            format!(r#"{}["@positional"][{}]"#, decoded_parent, *cursor)
                        } else {
                            format!("{}[{}]", decoded_parent, *cursor)
                        };
                        self.walk_typegroupname(
                            items[*cursor], &cbor_p, &decoded_p, name, ge.generic_args.as_ref(),
                        );
                        *cursor += 1;
                    }
                } else if *cursor < items.len() {
                    if is_positional {
                        positional_indices.push(*cursor);
                    }
                    let (cbor_p, decoded_p) = if is_label {
                        (
                            extend_cbor_path(cbor_parent, name),
                            extend_decoded_path(decoded_parent, name),
                        )
                    } else if any_named {
                        (
                            format!("{}[{}]", cbor_parent, *cursor),
                            format!(r#"{}["@positional"][{}]"#, decoded_parent, *cursor),
                        )
                    } else {
                        (
                            format!("{}[{}]", cbor_parent, *cursor),
                            format!("{}[{}]", decoded_parent, *cursor),
                        )
                    };
                    self.walk_typegroupname(
                        items[*cursor], &cbor_p, &decoded_p, name, ge.generic_args.as_ref(),
                    );
                    *cursor += 1;
                }
            }
            GroupEntry::InlineGroup { group, .. } => {
                for choice in &group.group_choices {
                    for (inner, _) in &choice.group_entries {
                        self.consume_array_entry(
                            inner,
                            items,
                            cursor,
                            cbor_parent,
                            decoded_parent,
                            any_named,
                            positional_indices,
                        );
                    }
                    break;
                }
            }
        }
    }

    fn walk_typegroupname(
        &self,
        node: &Value,
        cbor_path: &str,
        decoded_path: &str,
        name: &str,
        generic_args: Option<&'a GenericArgs<'a>>,
    ) {
        if generic_args.is_none() {
            if let Some(t1) = self.lookup_binding(name) {
                self.try_walk_type2(node, cbor_path, decoded_path, &t1.type2);
                return;
            }
        }
        match self.rules.get(name) {
            Some(Rule::Type { rule, .. }) => {
                let pushed = self.push_frame(
                    self.rules.rule_generic_params(name),
                    generic_args,
                );
                self.emit(node, cbor_path, decoded_path, rule.name.span, Some(name));
                self.walk_type(node, cbor_path, decoded_path, &rule.value);
                if pushed {
                    self.pop_frame();
                }
            }
            Some(Rule::Group { rule, .. }) => {
                let pushed = self.push_frame(
                    self.rules.rule_generic_params(name),
                    generic_args,
                );
                self.emit(node, cbor_path, decoded_path, rule.name.span, Some(name));
                if pushed {
                    self.pop_frame();
                }
            }
            None => {
                self.emit(node, cbor_path, decoded_path, ge_name_span(name, &self.rules), None);
            }
        }
    }
}

// ============================================================
// Helpers for synthetic-key rows (@tag, @entries, @positional,
// @extra). Operate on the JSON tree produced by `decoder::
// decode_cbor_to_value`, where each cbor node is an object with
// `type`, `position_info` (header bytes), `struct_position_info`
// (full extent for containers), and (for maps) `values: [{key,
// value}, ...]`.
// ============================================================

/// True if a cbor key flattens cleanly to a JSON object field — used
/// by `walk_map_against_group` to decide between object form and
/// `@entries` form. Mirrors `is_simple_cbor_key` in `schema_mapper`.
fn is_simple_cbor_key_json(k: &Value) -> bool {
    let t = k.get("type").and_then(Value::as_str).unwrap_or("");
    matches!(
        t,
        "String"
            | "IndefiniteLengthString"
            | "U8" | "U16" | "U32" | "U64"
            | "I8" | "I16" | "I32" | "I64" | "Int"
            | "Bytes" | "IndefiniteLengthBytes"
            | "Bool" | "Null"
            | "F16" | "F32" | "F64"
    )
}

/// O(n²) duplicate-key scan (RFC 8949 §5.6 — legal but non-canonical).
/// Triggers `@entries` form so wire order survives.
fn cbor_keys_have_duplicates_json(entries: &[&Value]) -> bool {
    for i in 0..entries.len() {
        for j in (i + 1)..entries.len() {
            let (Some(a), Some(b)) = (entries[i].get("key"), entries[j].get("key"))
            else { continue };
            if cbor_key_logical_eq(a, b) {
                return true;
            }
        }
    }
    false
}

/// Compare two cbor keys ignoring location info. Only meaningful for
/// simple keys (we call this after `is_simple_cbor_key_json` filtering).
fn cbor_key_logical_eq(a: &Value, b: &Value) -> bool {
    let ta = a.get("type").and_then(Value::as_str).unwrap_or("");
    let tb = b.get("type").and_then(Value::as_str).unwrap_or("");
    let class_a = integer_class(ta);
    let class_b = integer_class(tb);
    match (class_a, class_b) {
        (Some(x), Some(y)) if x == y => a.get("value") == b.get("value"),
        (Some(_), Some(_)) => false,
        (None, None) if ta == tb => a.get("value") == b.get("value"),
        _ => false,
    }
}

fn integer_class(t: &str) -> Option<&'static str> {
    match t {
        "U8" | "U16" | "U32" | "U64" => Some("uint"),
        "I8" | "I16" | "I32" | "I64" | "Int" => Some("nint"),
        _ => None,
    }
}

/// Best-effort: does `mk` accept this cbor key? Used to find a CDDL
/// member to anchor an `@entries` pair against. Loose on type-keyed
/// members — when the key type matches the broad cbor type class, we
/// pick that schema entry.
fn member_key_matches_json(mk: &MemberKey<'_>, k: &Value) -> bool {
    let t = k.get("type").and_then(Value::as_str).unwrap_or("");
    match mk {
        MemberKey::Bareword { ident, .. } => {
            t == "String" && k.get("value").and_then(Value::as_str) == Some(ident.ident)
        }
        MemberKey::Value { value, .. } => match value {
            cddl::token::Value::TEXT(s) => {
                t == "String"
                    && k.get("value").and_then(Value::as_str) == Some(s.as_ref())
            }
            cddl::token::Value::UINT(u) => {
                if !matches!(t, "U8" | "U16" | "U32" | "U64") {
                    return false;
                }
                k.get("value").and_then(Value::as_u64) == Some(*u as u64)
            }
            cddl::token::Value::INT(i) => {
                if !matches!(
                    t,
                    "U8" | "U16" | "U32" | "U64" | "I8" | "I16" | "I32" | "I64" | "Int"
                ) {
                    return false;
                }
                k.get("value").and_then(Value::as_i64) == Some(*i as i64)
            }
            _ => false,
        },
        MemberKey::Type1 { t1, .. } => type2_accepts_cbor_type(&t1.type2, t),
        MemberKey::NonMemberKey { .. } => false,
    }
}

fn type2_accepts_cbor_type(t2: &Type2<'_>, cbor_type: &str) -> bool {
    match t2 {
        Type2::Typename { ident, .. } => prelude_matches(ident.ident, cbor_type),
        Type2::UintValue { .. } => matches!(cbor_type, "U8" | "U16" | "U32" | "U64"),
        Type2::IntValue { .. } => matches!(
            cbor_type,
            "U8" | "U16" | "U32" | "U64" | "I8" | "I16" | "I32" | "I64" | "Int"
        ),
        Type2::TextValue { .. } => cbor_type == "String",
        Type2::Any { .. } => true,
        // Anything else (tagged, map, array, …) — accept loosely so we
        // at least try to anchor an entries pair against this member.
        _ => true,
    }
}

/// Union two `{offset, length}` JSON spans. Returns the wider of the
/// two if either is missing; `Null` if both are.
fn combine_span(a: Option<&Value>, b: Option<&Value>) -> Value {
    match (a, b) {
        (Some(x), Some(y)) => merge_spans(x, y),
        (Some(x), None) | (None, Some(x)) => x.clone(),
        (None, None) => Value::Null,
    }
}

fn merge_spans(a: &Value, b: &Value) -> Value {
    let get = |v: &Value, k: &str| v.get(k).and_then(Value::as_u64).unwrap_or(0);
    let a_off = get(a, "offset");
    let a_len = get(a, "length");
    let b_off = get(b, "offset");
    let b_len = get(b, "length");
    let start = a_off.min(b_off);
    let end = (a_off + a_len).max(b_off + b_len);
    serde_json::json!({
        "offset": start,
        "length": end.saturating_sub(start),
    })
}

/// Combined extent over selected entries (key+value bytes). Used to
/// anchor `@extra` map wrappers. Returns the same span for both
/// `cbor_byte_span` and `cbor_anchor_span` since synthetic wrappers
/// have no header/struct distinction.
fn wrapper_span_over_entries(entries: &[Value], indices: &[usize]) -> (Value, Value) {
    let mut acc: Option<Value> = None;
    for &i in indices {
        let Some(entry) = entries.get(i) else { continue };
        for field_name in ["key", "value"] {
            let Some(node) = entry.get(field_name) else { continue };
            let span = node
                .get("struct_position_info")
                .or_else(|| node.get("position_info"));
            if let Some(s) = span {
                acc = Some(match acc {
                    Some(prev) => merge_spans(&prev, s),
                    None => s.clone(),
                });
            }
        }
    }
    let combined = acc.unwrap_or(Value::Null);
    (combined.clone(), combined)
}

/// Same idea for arrays — covers selected items.
fn wrapper_span_over_items(items: &[&Value], indices: &[usize]) -> (Value, Value) {
    let mut acc: Option<Value> = None;
    for &i in indices {
        let Some(node) = items.get(i).copied() else { continue };
        let span = node
            .get("struct_position_info")
            .or_else(|| node.get("position_info"));
        if let Some(s) = span {
            acc = Some(match acc {
                Some(prev) => merge_spans(&prev, s),
                None => s.clone(),
            });
        }
    }
    let combined = acc.unwrap_or(Value::Null);
    (combined.clone(), combined)
}

/// Stringify a cbor key as a JSON-path label. Bytes get a `0x` prefix
/// to distinguish from text/numeric keys.
fn json_key_label(key: &Value) -> String {
    let t = key.get("type").and_then(Value::as_str).unwrap_or("");
    let v = key.get("value");
    match t {
        "String" | "IndefiniteLengthString" => v
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| "?".into()),
        "Bytes" | "IndefiniteLengthBytes" => v
            .and_then(Value::as_str)
            .map(|s| format!("0x{}", s))
            .unwrap_or_else(|| "?".into()),
        "Bool" => v
            .and_then(Value::as_bool)
            .map(|b| b.to_string())
            .unwrap_or_else(|| "?".into()),
        "Null" => "null".into(),
        _ => v.map(|x| x.to_string()).unwrap_or_else(|| "?".into()),
    }
}

fn is_prelude_name(name: &str) -> bool {
    matches!(
        name,
        "any"
            | "uint" | "unsigned" | "biguint" | "integer"
            | "nint" | "bignint" | "int" | "bigint" | "number"
            | "float" | "float16" | "float32" | "float64" | "float16-32" | "float32-64"
            | "bstr" | "bytes" | "tstr" | "text"
            | "bool" | "true" | "false" | "null" | "nil" | "undefined"
    )
}

fn bareword_label<'a>(mk: &'a MemberKey<'a>) -> Option<String> {
    match mk {
        MemberKey::Bareword { ident, .. } => Some(ident.ident.to_string()),
        MemberKey::Value { value: cddl::token::Value::TEXT(s), .. } => {
            Some(s.to_string())
        }
        _ => None,
    }
}

fn ge_name_span(_: &str, _: &RuleIndex<'_>) -> cddl::ast::Span {
    // Span 0..0 line 0 — we don't have access to the GroupEntry's
    // identifier span here. Treat as "unknown source position".
    (0, 0, 0)
}

fn type2_span(t2: &Type2<'_>) -> cddl::ast::Span {
    use cddl::ast::Type2::*;
    match t2 {
        IntValue { span, .. }
        | UintValue { span, .. }
        | FloatValue { span, .. }
        | TextValue { span, .. }
        | UTF8ByteString { span, .. }
        | B16ByteString { span, .. }
        | B64ByteString { span, .. }
        | Typename { span, .. }
        | ParenthesizedType { span, .. }
        | Map { span, .. }
        | Array { span, .. }
        | Unwrap { span, .. }
        | ChoiceFromInlineGroup { span, .. }
        | ChoiceFromGroup { span, .. }
        | TaggedData { span, .. }
        | DataMajorType { span, .. }
        | Any { span, .. } => *span,
    }
}

fn unwrap_tags(node: &Value) -> &Value {
    let mut cur = node;
    while cur.get("type").and_then(Value::as_str) == Some("Tag") {
        match cur.get("value") {
            Some(inner) => cur = inner,
            None => break,
        }
    }
    cur
}

/// Crude type compatibility for prelude scalars — used when we hit
/// `Typename(prelude)` and need to emit an entry without further
/// recursion.
fn prelude_matches(name: &str, cbor_type: &str) -> bool {
    match name {
        "any" => true,
        "uint" | "unsigned" | "biguint" | "integer" => {
            matches!(cbor_type, "U8" | "U16" | "U32" | "U64")
        }
        "nint" | "bignint" => matches!(cbor_type, "I8" | "I16" | "I32" | "I64" | "Int"),
        "int" | "bigint" | "number" => {
            matches!(cbor_type, "U8" | "U16" | "U32" | "U64" | "I8" | "I16" | "I32" | "I64" | "Int")
        }
        "float" | "float16" | "float32" | "float64" | "float16-32" | "float32-64" => {
            matches!(cbor_type, "F16" | "F32" | "F64")
        }
        "bstr" | "bytes" => {
            matches!(cbor_type, "Bytes" | "IndefiniteLengthBytes")
        }
        "tstr" | "text" => {
            matches!(cbor_type, "String" | "IndefiniteLengthString")
        }
        "bool" | "true" | "false" => cbor_type == "Bool",
        "null" | "nil" => cbor_type == "Null",
        "undefined" => cbor_type == "Undefined",
        _ => false,
    }
}

// ============================================================
// Member-key matching for maps
// ============================================================

enum KeyMatcher {
    IntLiteral(i128),
    TextLiteral(String),
    BarewordOrText(String),
}

impl KeyMatcher {
    /// Returns the JSON-path label to use for this key (a quoted string
    /// for text-typed keys, a number for ints) when a CBOR key matches.
    fn matches(&self, k: &Value) -> Option<String> {
        let k_type = k.get("type").and_then(Value::as_str).unwrap_or("");
        match self {
            KeyMatcher::IntLiteral(n) => {
                if matches!(k_type, "U8" | "U16" | "U32" | "U64" | "I8" | "I16" | "I32" | "I64" | "Int") {
                    let v = k.get("value")?;
                    let parsed: Option<i128> = v.as_i64().map(|x| x as i128).or_else(|| v.as_u64().map(|x| x as i128));
                    if parsed == Some(*n) {
                        return Some(n.to_string());
                    }
                }
                None
            }
            KeyMatcher::TextLiteral(s) | KeyMatcher::BarewordOrText(s) => {
                if k_type == "String"
                    && k.get("value").and_then(Value::as_str) == Some(s.as_str())
                {
                    return Some(s.clone());
                }
                None
            }
        }
    }
}

/// Compute the source span for a `MemberKey` that points *only* at the
/// key declaration (`a`, `0`, or `<type1>`), not the broader
/// `name: type` slot that pest's span happens to cover. For Bareword
/// we use the inner identifier's own span; for Type1 we use the type1
/// span; for Value we trim the broad span back to the position before
/// the `:` separator (and any trailing whitespace before it).
fn member_key_span(mk: &MemberKey<'_>, source: &str) -> cddl::ast::Span {
    match mk {
        MemberKey::Bareword { ident, .. } => ident.span,
        MemberKey::Type1 { t1, .. } => t1.span,
        MemberKey::Value { span, .. } => trim_to_key(*span, source),
        MemberKey::NonMemberKey { .. } => (0, 0, 0),
    }
}

/// Take the wider span pest reports for a value-keyed entry and trim
/// it back to just the literal key — drop the `:` / `^` / `=>`
/// separator and any whitespace before it.
fn trim_to_key(broad: cddl::ast::Span, source: &str) -> cddl::ast::Span {
    let (start, end, line) = broad;
    let end = end.min(source.len());
    if start >= end {
        return broad;
    }
    let slice = &source[start..end];
    // Find the earliest separator (`:`, `^`, or `=>`).
    let mut sep_idx = slice.len();
    for sep in [":", "^", "=>"] {
        if let Some(i) = slice.find(sep) {
            if i < sep_idx {
                sep_idx = i;
            }
        }
    }
    // Trim trailing whitespace before the separator.
    let mut len = sep_idx;
    while len > 0 {
        let last = slice[..len].chars().next_back().unwrap();
        if last.is_whitespace() {
            len -= last.len_utf8();
        } else {
            break;
        }
    }
    (start, start + len, line)
}

fn key_matcher(mk: &MemberKey<'_>) -> KeyMatcher {
    match mk {
        MemberKey::Bareword { ident, .. } => {
            KeyMatcher::BarewordOrText(ident.ident.to_string())
        }
        MemberKey::Value { value, .. } => match value {
            cddl::token::Value::UINT(u) => KeyMatcher::IntLiteral(*u as i128),
            cddl::token::Value::INT(i) => KeyMatcher::IntLiteral(*i),
            cddl::token::Value::TEXT(s) => KeyMatcher::TextLiteral(s.to_string()),
            other => KeyMatcher::TextLiteral(other.to_string()),
        },
        MemberKey::Type1 { t1, .. } => match &t1.type2 {
            Type2::UintValue { value, .. } => KeyMatcher::IntLiteral(*value as i128),
            Type2::IntValue { value, .. } => KeyMatcher::IntLiteral(*value as i128),
            Type2::TextValue { value, .. } => {
                KeyMatcher::TextLiteral(value.as_ref().to_string())
            }
            other => KeyMatcher::TextLiteral(other.to_string()),
        },
        MemberKey::NonMemberKey { .. } => KeyMatcher::TextLiteral("@non_member_key".into()),
    }
}

/// Build a CBOR-side path. Numeric segments use bare `[N]` (cbor maps
/// with integer keys present as such); textual identifier-safe keys
/// use `.name`; everything else uses bracket+quoted form.
fn extend_cbor_path(parent: &str, field: &str) -> String {
    if field.chars().all(|c| c.is_ascii_digit())
        || (field.starts_with('-')
            && field.len() > 1
            && field[1..].chars().all(|c| c.is_ascii_digit()))
    {
        format!("{}[{}]", parent, field)
    } else if field
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        format!("{}.{}", parent, field)
    } else {
        format!("{}[{:?}]", parent, field)
    }
}

/// Build a path into the JSON tree returned by
/// `decode_cbor_against_cddl`. Decoded JSON has only string keys, so
/// numeric-keyed CBOR maps come back as `$["0"]` (string keyed),
/// whereas identifier-safe keys keep dot notation for ergonomics.
fn extend_decoded_path(parent: &str, field: &str) -> String {
    let identifier_safe = !field.is_empty()
        && !field.chars().next().unwrap().is_ascii_digit()
        && field
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_');
    if identifier_safe {
        format!("{}.{}", parent, field)
    } else {
        format!("{}[{:?}]", parent, field)
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run(cddl: &str, rule: &str, hex_cbor: &str) -> Vec<Value> {
        let bytes = hex::decode(hex_cbor).unwrap();
        let v = map_cbor_to_cddl(&bytes, cddl, rule).unwrap();
        v.as_array().unwrap().clone()
    }

    fn paths(entries: &[Value]) -> Vec<String> {
        entries
            .iter()
            .map(|e| e["cbor_path"].as_str().unwrap().to_string())
            .collect()
    }

    fn entry_at<'a>(entries: &'a [Value], path: &str) -> &'a Value {
        entries
            .iter()
            .find(|e| e["cbor_path"] == json!(path))
            .unwrap_or_else(|| panic!("no entry at path {} in {:?}", path, paths(entries)))
    }

    #[test]
    fn map_emits_entry_for_root_with_rule_name() {
        // 18 64 = 100. Root is `coin = uint`.
        let entries = run("coin = uint", "coin", "1864");
        let root = &entries[0];
        assert_eq!(root["cbor_path"], json!("$"));
        assert_eq!(root["rule_name"], json!("coin"));
        assert!(root["cbor_byte_span"]["offset"].is_number());
        assert!(root["cddl_byte_span"]["offset"].is_number());
    }

    #[test]
    fn map_walks_into_named_array_entries() {
        // [bstr, uint] schema, `[0x010203, 7]` data.
        let entries = run(
            "out = [address: bstr, amount: uint]",
            "out",
            "82430102030 7".replace(' ', "").as_str(),
        );
        let p = paths(&entries);
        assert!(p.iter().any(|p| p == "$"), "{:?}", p);
        assert!(p.iter().any(|p| p == "$.address"), "{:?}", p);
        assert!(p.iter().any(|p| p == "$.amount"), "{:?}", p);
        // Address entry CBOR span lands in the input bytes (offset 1).
        let addr = entry_at(&entries, "$.address");
        assert_eq!(addr["cbor_byte_span"]["offset"], json!(1));
    }

    #[test]
    fn map_emits_key_entries_alongside_value_entries() {
        // tx_body = {a: int, b: int}; CBOR a26161016162 02 = {"a":1,"b":2}
        let entries = run(
            "tx_body = {a: int, b: int}",
            "tx_body",
            "a261610161620 2".replace(' ', "").as_str(),
        );
        // Each named field should appear twice: once with role "key"
        // pointing at the key bytes, once with role "value" pointing
        // at the value bytes.
        let a_key = entries
            .iter()
            .find(|e| e["cbor_path"] == json!("$.a") && e["entry_role"] == json!("key"))
            .unwrap_or_else(|| panic!("no key entry for $.a in {:?}", paths(&entries)));
        let a_val = entries
            .iter()
            .find(|e| e["cbor_path"] == json!("$.a") && e["entry_role"] == json!("value"))
            .unwrap_or_else(|| panic!("no value entry for $.a"));
        // Key bytes (61 61 = "a", 2 bytes at offset 1) ≠ value bytes (01 at offset 3).
        assert_eq!(a_key["cbor_byte_span"]["offset"], json!(1));
        assert_eq!(a_key["cbor_byte_span"]["length"], json!(2));
        assert_eq!(a_val["cbor_byte_span"]["offset"], json!(3));
        // Both refer to the same field via the same path.
        assert_eq!(a_key["decoded_path"], a_val["decoded_path"]);
    }

    #[test]
    fn map_emits_key_entries_for_numeric_keyed_maps() {
        // Cardano-style numeric keys.
        let entries = run(
            "body = { 0: uint, 1: uint }",
            "body",
            "a200 01 011864".replace(' ', "").as_str(),
        );
        let zero_key = entries
            .iter()
            .find(|e| e["cbor_path"] == json!("$[0]") && e["entry_role"] == json!("key"))
            .unwrap_or_else(|| panic!("no key entry for $[0]"));
        // CBOR `00` byte at offset 1 = 1 byte.
        assert_eq!(zero_key["cbor_byte_span"]["offset"], json!(1));
        assert_eq!(zero_key["cbor_byte_span"]["length"], json!(1));
        // decoded_path uses string key form because decoded JSON has
        // string keys.
        assert_eq!(zero_key["decoded_path"], json!(r#"$["0"]"#));
    }

    #[test]
    fn map_descends_through_named_record_into_nested_map() {
        // tx_body = {a: int, b: int}
        // a26161 01 6162 02 = {"a": 1, "b": 2}
        let entries = run(
            "tx_body = {a: int, b: int}",
            "tx_body",
            "a261610161620 2".replace(' ', "").as_str(),
        );
        let p = paths(&entries);
        assert!(p.iter().any(|x| x == "$.a"), "{:?}", p);
        assert!(p.iter().any(|x| x == "$.b"), "{:?}", p);
    }

    #[test]
    fn map_unwraps_tag_transparently() {
        // tag258(<array(1)>[<array(2)>[bstr32, 0]]) — same as Cardano
        // input shape; schema is `set<a> = #6.258([* a]); inputs = set<input>; input = [bstr, uint]`.
        let cddl = "
            set<a> = #6.258([* a])
            inputs = set<input>
            input = [tx: bstr, idx: uint]
        ";
        let cbor_hex = format!(
            "d9 0102 81 82 5820 {} 00",
            "ab".repeat(32)
        )
        .replace(' ', "");
        let entries = run(cddl, "inputs", &cbor_hex);
        let p = paths(&entries);
        // Tag is transparent — we get $[0].tx and $[0].idx, no $[0].@value chain.
        assert!(p.iter().any(|x| x == "$"), "{:?}", p);
        assert!(p.iter().any(|x| x == "$[0]"), "{:?}", p);
        assert!(p.iter().any(|x| x == "$[0].tx"), "{:?}", p);
        assert!(p.iter().any(|x| x == "$[0].idx"), "{:?}", p);
    }

    #[test]
    fn map_against_real_preview_tx_with_official_conway_cddl() {
        let Ok(cddl) = std::fs::read_to_string("/tmp/conway.cddl") else {
            eprintln!("skipping — /tmp/conway.cddl not present");
            return;
        };
        let preview_tx_hex = "84a400d901028182582016b6ee8c812f8b1c9c643ee3828f50fdcf0f174625bbd6e947ba77b12374094a00018282583900aef399a405edd6797117a3db6653e1a230e1f6f91dd5badb77f2be3720fc45da826093ae8ed2e4f0f81c4f5ea9b6f0dda561c974cfc6355d1a000f424082583900f275cb75d82f737c49280039947e484919ee044c82c2e4ceaf2f2d87984c3eb5c8a01b4b53c7cec4cfc139345a28d24a6ec918873c459add1a48b7d00d021a00030d40075820bdaa99eb158414dea0a91d6c727e2268574b23efe6e08ab3b841abe8059a030ca100d9010281825820f8f5750132a13473240e318dd36eccd70083e8f08ac589c74ebe776f43e9401d58401e149e081ff497d7f97c3ef7427a916d1b0632c6eb98bb54b040aca413a2ad94273291c9b63b2802083c72b0cfe03eef2b55f767ecf32dba894dd59701076409f5d90103a0";
        let bytes = hex::decode(preview_tx_hex).unwrap();
        let entries =
            map_cbor_to_cddl(&bytes, &cddl, "transaction").unwrap();
        let arr = entries.as_array().unwrap();
        let p = paths(arr);
        // Top-level slot 0/1 are typename-labelled in Conway
        // (`transaction = [transaction_body, transaction_witness_set,
        // bool, auxiliary_data/nil]`). The bool / aux slots have no
        // name so they fall through to positional [2]/[3].
        assert!(p.iter().any(|x| x == "$"));
        assert!(p.iter().any(|x| x == "$.transaction_body"), "{:?}", p);
        assert!(
            p.iter().any(|x| x == "$.transaction_witness_set"),
            "{:?}",
            p
        );
        assert!(p.iter().any(|x| x == "$[2]"), "{:?}", p);
        assert!(p.iter().any(|x| x == "$[3]"), "{:?}", p);
        // Deep paths land on real Cardano fields:
        assert!(
            p.iter().any(|x| x == "$.transaction_body[0][0].transaction_id"),
            "{:?}",
            p
        );
        assert!(
            p.iter()
                .any(|x| x == "$.transaction_witness_set[0][0].signature"),
            "{:?}",
            p
        );
    }

    #[test]
    fn map_emits_entry_for_each_uint_in_homogeneous_array() {
        // arr = [* uint]; CBOR [1, 2, 3] -> 83010203
        let entries = run("arr = [* uint]", "arr", "83010203");
        let p = paths(&entries);
        assert!(p.iter().any(|x| x == "$"), "{:?}", p);
        assert!(p.iter().any(|x| x == "$[0]"), "{:?}", p);
        assert!(p.iter().any(|x| x == "$[1]"), "{:?}", p);
        assert!(p.iter().any(|x| x == "$[2]"), "{:?}", p);
    }

    #[test]
    fn key_span_points_only_at_key_not_at_value_or_separator() {
        // For each schema/cbor pair, the entry whose `entry_role`
        // is `"key"` must have `cddl_byte_span` covering only the
        // key declaration — not the `:` separator, surrounding
        // whitespace, or the value type.
        let cases = [
            ("tx_body = {a: int}",                   "a16161 01", "a"),
            ("tx_body = {a    :    int}",            "a16161 01", "a"),
            ("tx_body = {0: int}",                   "a10001",    "0"),
            ("tx_body = {  0   :    int  }",         "a10001",    "0"),
            ("tx_body = {  abc   :    int  }",       "a163616263 01", "abc"),
        ];
        for (schema, cbor_hex, expected) in cases {
            let bytes = hex::decode(cbor_hex.replace(' ', "")).unwrap();
            let entries = map_cbor_to_cddl(&bytes, schema, "tx_body").unwrap();
            let arr = entries.as_array().unwrap();
            let key = arr
                .iter()
                .find(|e| e["entry_role"] == json!("key"))
                .unwrap_or_else(|| panic!("no key entry for schema={:?}", schema));
            let s = &key["cddl_byte_span"];
            let off = s["offset"].as_u64().unwrap() as usize;
            let len = s["length"].as_u64().unwrap() as usize;
            let snippet = &schema[off..off + len];
            assert_eq!(
                snippet, expected,
                "schema={:?} expected key span {:?}, got {:?}",
                schema, expected, snippet
            );
        }
    }

    #[test]
    fn map_emits_stacked_entries_for_each_resolution_level() {
        // Multi-level type resolution: a single CBOR position should
        // emit entries pointing at every CDDL level it traverses —
        // outer rule, generic rule, type expression, etc. UI uses
        // these for breadcrumb trails / multi-level highlighting.
        let schema = "
            inputs = nonempty_set<input>
            nonempty_set<a> = #6.258([+ a]) / [+ a]
            input = [bstr, uint]
        ";
        let cbor_hex = format!("d9 0102 81 82 5820 {} 00", "ab".repeat(32))
            .replace(' ', "");
        let bytes = hex::decode(&cbor_hex).unwrap();
        let entries = map_cbor_to_cddl(&bytes, schema, "inputs").unwrap();
        let arr = entries.as_array().unwrap();
        let snippets_at_root: Vec<String> = arr
            .iter()
            .filter(|e| e["cbor_path"] == json!("$"))
            .map(|e| {
                let s = &e["cddl_byte_span"];
                let off = s["offset"].as_u64().unwrap() as usize;
                let len = s["length"].as_u64().unwrap() as usize;
                schema[off..off + len].to_string()
            })
            .collect();
        // The full chain of CDDL spans visiting `$` should at least
        // include the outer rule, the generic rule, the tagged-data
        // expression, and the inner array expression.
        for expected in ["inputs", "nonempty_set", "#6.258([+ a])", "[+ a]"] {
            assert!(
                snippets_at_root.iter().any(|s| s == expected),
                "missing CDDL snippet {:?} in stack {:?}",
                expected,
                snippets_at_root
            );
        }
    }

    #[test]
    fn map_returns_error_for_unknown_root_rule() {
        let bytes = hex::decode("01").unwrap();
        let err = map_cbor_to_cddl(&bytes, "x = int", "no_such")
            .err()
            .expect("expected missing-rule error");
        assert!(err.as_string().unwrap().contains("no_such"));
    }

    #[test]
    fn map_returns_error_for_invalid_cbor() {
        let err = map_cbor_to_cddl(&[0x18], "x = int", "x")
            .err()
            .expect("expected decode error");
        assert!(err
            .as_string()
            .unwrap()
            .to_lowercase()
            .contains("cbor decode"));
    }

    #[test]
    fn map_emits_tag_row_for_unspecialised_tag() {
        // set<a> = #6.258([* a]) wraps an array. Decoded JSON uses
        // `@tag` + `@value`. Right-clicking on `@tag` should resolve.
        let cddl = "set<a> = #6.258([* a])\nelems = set<uint>";
        let cbor_hex = "d9010281 01".replace(' ', "");
        let entries = run(cddl, "elems", &cbor_hex);
        // Decoded path for the @tag row sits under the tag wrapper.
        let tag_row = entries
            .iter()
            .find(|e| {
                e["decoded_path"]
                    .as_str()
                    .map_or(false, |p| p.ends_with(r#"["@tag"]"#))
            })
            .unwrap_or_else(|| {
                panic!("no @tag row in {:?}", entries)
            });
        // CBOR span on the tag row covers tag header bytes (`d9 0102` =
        // 3 bytes at offset 0).
        assert_eq!(tag_row["cbor_byte_span"]["offset"], json!(0));
        assert_eq!(tag_row["cbor_byte_span"]["length"], json!(3));
        // CDDL span points at the `#6.258(...)` form on the tagged-data
        // node — must contain `#6.`.
        let s = &tag_row["cddl_byte_span"];
        let off = s["offset"].as_u64().unwrap() as usize;
        let len = s["length"].as_u64().unwrap() as usize;
        let snippet = &cddl[off..off + len];
        assert!(snippet.starts_with("#6."), "snippet was {:?}", snippet);
    }

    #[test]
    fn map_emits_positional_wrapper_for_mixed_named_array() {
        // Schema has labelled + unlabelled slots → unlabelled slots
        // bucket into `@positional` in decoded output. The wrapper row
        // must be addressable.
        let cddl = "tx = [body: int, bool, int]";
        // CBOR: [1, true, 2] = 83 01 f5 02
        let entries = run(cddl, "tx", "8301f502");
        let p_decoded: Vec<String> = entries
            .iter()
            .map(|e| e["decoded_path"].as_str().unwrap().to_string())
            .collect();
        // Both an `@positional` wrapper and per-positional decoded paths exist.
        assert!(
            p_decoded.iter().any(|x| x == r#"$["@positional"]"#),
            "no @positional wrapper in {:?}",
            p_decoded
        );
        assert!(
            p_decoded
                .iter()
                .any(|x| x == r#"$["@positional"][1]"#),
            "no positional[1] in {:?}",
            p_decoded
        );
        // Wrapper row carries cbor_type=array_positional and no cddl span.
        let wrapper = entries
            .iter()
            .find(|e| e["decoded_path"] == json!(r#"$["@positional"]"#))
            .unwrap();
        assert_eq!(wrapper["cbor_type"], json!("array_positional"));
        assert!(wrapper.get("cddl_byte_span").is_none());
    }

    #[test]
    fn map_emits_extra_wrapper_for_overlong_array() {
        // Schema accepts 2 ints; CBOR has 3 — third item ends up in @extra.
        let cddl = "pair = [int, int]";
        // [1, 2, 3] -> 83010203
        let entries = run(cddl, "pair", "83010203");
        let p_decoded: Vec<String> = entries
            .iter()
            .map(|e| e["decoded_path"].as_str().unwrap().to_string())
            .collect();
        assert!(
            p_decoded.iter().any(|x| x == r#"$["@extra"]"#),
            "no @extra wrapper in {:?}",
            p_decoded
        );
        assert!(
            p_decoded.iter().any(|x| x == r#"$["@extra"][2]"#),
            "no @extra[2] leaf in {:?}",
            p_decoded
        );
        let wrapper = entries
            .iter()
            .find(|e| e["decoded_path"] == json!(r#"$["@extra"]"#))
            .unwrap();
        assert_eq!(wrapper["cbor_type"], json!("array_extra"));
        // CBOR span covers the overflow item (`03` at offset 3).
        assert_eq!(wrapper["cbor_byte_span"]["offset"], json!(3));
    }

    #[test]
    fn map_emits_entries_form_for_complex_keyed_map() {
        // Map with array keys → entries form. CBOR:
        //   a1 8101 18 64  =  { [1] => 100 }
        let cddl = "m = { * any => uint }";
        let entries = run(cddl, "m", "a181 011864".replace(' ', "").as_str());
        let p_decoded: Vec<String> = entries
            .iter()
            .map(|e| e["decoded_path"].as_str().unwrap().to_string())
            .collect();
        assert!(
            p_decoded.iter().any(|x| x == r#"$["@entries"]"#),
            "no @entries wrapper in {:?}",
            p_decoded
        );
        assert!(
            p_decoded.iter().any(|x| x == r#"$["@entries"][0]"#),
            "no entries[0] pair in {:?}",
            p_decoded
        );
        assert!(
            p_decoded
                .iter()
                .any(|x| x == r#"$["@entries"][0]["key"]"#),
            "no entries[0].key in {:?}",
            p_decoded
        );
        assert!(
            p_decoded
                .iter()
                .any(|x| x == r#"$["@entries"][0]["value"]"#),
            "no entries[0].value in {:?}",
            p_decoded
        );
    }

    #[test]
    fn map_emits_entries_form_for_duplicate_keys() {
        // Duplicate string keys "a" → entries form so wire order survives.
        // CBOR a261610161610 2 = { "a": 1, "a": 2 }
        let cddl = "m = { * tstr => uint }";
        let entries = run(
            cddl,
            "m",
            "a261610161610 2".replace(' ', "").as_str(),
        );
        let p_decoded: Vec<String> = entries
            .iter()
            .map(|e| e["decoded_path"].as_str().unwrap().to_string())
            .collect();
        assert!(p_decoded.iter().any(|x| x == r#"$["@entries"]"#));
        assert!(
            p_decoded.iter().any(|x| x == r#"$["@entries"][0]"#),
            "{:?}",
            p_decoded
        );
        assert!(
            p_decoded.iter().any(|x| x == r#"$["@entries"][1]"#),
            "{:?}",
            p_decoded
        );
    }

    #[test]
    fn map_emits_extra_wrapper_for_unmatched_object_form_keys() {
        // Schema only knows `a:`; cbor has `a` and `b`. `b` is leftover.
        let cddl = "m = { a: uint }";
        // {"a": 1, "b": 2} -> a261610161620 2
        let entries = run(
            cddl,
            "m",
            "a261610161620 2".replace(' ', "").as_str(),
        );
        let p_decoded: Vec<String> = entries
            .iter()
            .map(|e| e["decoded_path"].as_str().unwrap().to_string())
            .collect();
        assert!(
            p_decoded.iter().any(|x| x == r#"$["@extra"]"#),
            "no @extra wrapper in {:?}",
            p_decoded
        );
        assert!(
            p_decoded.iter().any(|x| x == r#"$["@extra"].b"#),
            "no @extra.b leaf in {:?}",
            p_decoded
        );
    }
}

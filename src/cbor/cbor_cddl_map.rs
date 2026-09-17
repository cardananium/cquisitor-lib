//! Bidirectional CBOR ↔ CDDL position map for UI highlighting.
//!
//! Output: `{entries, cbor_paths, decoded_paths}`. Each entry is
//! `{cbor_path, decoded_path, entry_role, cbor_byte_span?,
//! cbor_anchor_span?, cddl_byte_span?, rule_name?}` in depth-first
//! pre-order. Path fields are indices into the path tables (prefix +
//! suffix), not full strings — see [`expand_paths`].
//!
//! `decoded_path` matches the JSON from `decode_cbor_against_cddl`.
//! This module runs `schema_mapper` first, then replays its trace
//! (does not re-decide). Prefer a missing `cddl_byte_span` over a wrong
//! highlight.
//!
//! Replay is heap-driven via `super::walk_driver`. Rows stream as JSON
//! text; tables follow `entries`. Bound: `limits::MAX_CBOR_POSITION_MAP_ROWS`.

use std::cell::{Cell, RefCell, RefMut};
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::future::Future;

use cddl::ast::{Group, MemberKey, Rule, Span, Type, Type1, Type2};
use cddl::validator::cbor_value::{decode_cbor, Value as CborValue};
use serde_json::Value;

use crate::cbor::decoder;
use crate::cbor::document_cache;
use crate::cbor::limits;
use crate::cbor::schema_mapper as sm;
use crate::cbor::schema_mapper::{ArrayTrace, EntryTrace, MapTrace, TraceId, TraceNode};
use crate::cbor::source_index::{source_span, SourceSpan, Utf16Index};
use crate::cbor::validation;
use crate::cbor::walk_driver::{run_above, run_root, Spawner};
use crate::deep_json::{write_string, DeepJson};

/// Incremental path intern: append/truncate segments; store `(prefix, suffix)`
/// so each row costs one segment, not O(depth).
///
/// Open entries track prefixes of the current path (outermost first).
/// Intern compares lengths against the innermost open entry. Re-intern while
/// still open reuses that entry; after leave/reenter a one-segment duplicate
/// is fine.
struct PathTable {
    /// Current path being built during replay.
    path: String,
    /// `(prefix, suffix)` entries in intern order; no prefix ⇒ suffix alone.
    rows: Vec<(Option<usize>, String)>,
    /// Open prefixes of `path`: `(row index, spelled length)`, outermost first.
    open: Vec<(usize, usize)>,
}

impl PathTable {
    fn new(root: &str) -> PathTable {
        PathTable {
            path: root.to_string(),
            rows: Vec::new(),
            open: Vec::new(),
        }
    }

    /// Append `segment`; return the prior path length.
    fn enter(&mut self, segment: &str) -> usize {
        let mark = self.path.len();
        self.path.push_str(segment);
        mark
    }

    /// Truncate to `mark` and close open entries past that length.
    fn leave(&mut self, mark: usize) {
        self.path.truncate(mark);
        while self.open.last().is_some_and(|&(_, len)| len > mark) {
            self.open.pop();
        }
    }

    /// Index for the current path; add a row if not already open at this length.
    fn intern(&mut self) -> usize {
        let (prefix, shared) = match self.open.last() {
            Some(&(index, len)) => (Some(index), len),
            None => (None, 0),
        };
        // Exact match ⇒ reuse open entry (path is never empty).
        if shared == self.path.len() {
            if let Some(index) = prefix {
                return index;
            }
        }
        let index = self.rows.len();
        self.rows.push((prefix, self.path[shared..].to_string()));
        self.open.push((index, self.path.len()));
        index
    }

    /// Append as a JSON array of `{prefix?, suffix}`.
    fn write_json(&self, out: &mut String) {
        out.push('[');
        for (i, (prefix, suffix)) in self.rows.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('{');
            if let Some(prefix) = prefix {
                write!(out, "\"prefix\":{},", prefix).expect("writing to a String cannot fail");
            }
            out.push_str("\"suffix\":");
            write_string(out, suffix);
            out.push('}');
        }
        out.push(']');
    }
}

/// Expand path table `field` into one full string per entry.
#[cfg(test)]
fn resolve_path_table(mapping: &Value, field: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for entry in mapping[field].as_array().into_iter().flatten() {
        let mut path = match entry.get("prefix").and_then(Value::as_u64) {
            Some(prefix) => out[prefix as usize].clone(),
            None => String::new(),
        };
        path.push_str(entry["suffix"].as_str().unwrap_or_default());
        out.push(path);
    }
    out
}

/// Expand compact path indices to full `cbor_path` / `decoded_path` strings.
#[cfg(test)]
pub(crate) fn expand_paths(mapping: &Value) -> Vec<Value> {
    let cbor_paths = resolve_path_table(mapping, "cbor_paths");
    let decoded_paths = resolve_path_table(mapping, "decoded_paths");
    mapping["entries"]
        .as_array()
        .expect("entries is an array")
        .iter()
        .map(|entry| {
            let mut row = entry.as_object().expect("an entry object").clone();
            let cbor = row["cbor_path"].as_u64().expect("a cbor path index");
            let decoded = row["decoded_path"].as_u64().expect("a decoded path index");
            row.insert(
                "cbor_path".into(),
                Value::String(cbor_paths[cbor as usize].clone()),
            );
            row.insert(
                "decoded_path".into(),
                Value::String(decoded_paths[decoded as usize].clone()),
            );
            Value::Object(row)
        })
        .collect()
}

/// Length of each path in table `field` without materialising strings.
#[cfg(test)]
pub(crate) fn path_lengths(mapping: &Value, field: &str) -> Vec<usize> {
    let mut lengths: Vec<usize> = Vec::new();
    for entry in mapping[field].as_array().into_iter().flatten() {
        let prefix = entry
            .get("prefix")
            .and_then(Value::as_u64)
            .map_or(0, |p| lengths[p as usize]);
        lengths.push(prefix + entry["suffix"].as_str().unwrap_or_default().len());
    }
    lengths
}

/// Full path string for table `field` entry `index`.
#[cfg(test)]
pub(crate) fn resolved_path(mapping: &Value, field: &str, index: usize) -> String {
    let table = mapping[field].as_array().expect("a path table");
    let mut segments: Vec<&str> = Vec::new();
    let mut at = Some(index);
    while let Some(i) = at {
        segments.push(table[i]["suffix"].as_str().unwrap_or_default());
        at = table[i]
            .get("prefix")
            .and_then(Value::as_u64)
            .map(|p| p as usize);
    }
    segments.iter().rev().copied().collect()
}

/// Whether any entry indexes `path` in table `field` (`cbor_paths` / `decoded_paths`).
#[cfg(test)]
pub(crate) fn has_path(mapping: &Value, field: &str, path: &str) -> bool {
    let lengths = path_lengths(mapping, field);
    let matching: Vec<usize> = lengths
        .iter()
        .enumerate()
        .filter(|(_, len)| **len == path.len())
        .filter(|(i, _)| resolved_path(mapping, field, *i) == path)
        .map(|(i, _)| i)
        .collect();
    let row_field = match field {
        "cbor_paths" => "cbor_path",
        _ => "decoded_path",
    };
    mapping["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .any(|e| {
            e[row_field]
                .as_u64()
                .is_some_and(|i| matching.contains(&(i as usize)))
        })
}

/// Append the mapping JSON to `out`, or append nothing and return the error.
///
/// Same [`sm::WalkError`]s as [`sm::decode_cbor_against_cddl`], plus
/// [`limits::MAX_CBOR_POSITION_MAP_ROWS`] when the row bound would be exceeded.
pub fn map_cbor_to_cddl_into(
    out: &mut String,
    cbor: &[u8],
    cddl: &str,
    rule_name: &str,
) -> Result<(), sm::WalkError> {
    document_cache::with_ast_checked(cddl, |parsed| match parsed {
        Ok(ast) => map_against_ast(out, ast, cbor, cddl, rule_name),
        Err(e) => Err(sm::WalkError::from_object(validation::schema_error(
            cddl, e,
        ))),
    })
}

/// Mapping as a standalone JSON string.
#[cfg(test)]
pub(crate) fn map_cbor_to_cddl_text(
    cbor: &[u8],
    cddl: &str,
    rule_name: &str,
) -> Result<String, sm::WalkError> {
    let mut out = String::new();
    map_cbor_to_cddl_into(&mut out, cbor, cddl, rule_name)?;
    Ok(out)
}

/// Mapping parsed to a `Value` for tests.
#[cfg(test)]
pub(crate) fn map_cbor_to_cddl(
    cbor: &[u8],
    cddl: &str,
    rule_name: &str,
) -> Result<Value, sm::WalkError> {
    let text = map_cbor_to_cddl_text(cbor, cddl, rule_name)?;
    Ok(serde_json::from_str(&text).expect("the mapping text is JSON"))
}

/// Like `map_cbor_to_cddl_into` with a pre-parsed AST; `cddl` must be its source.
/// Appends nothing to `out` on error.
pub(crate) fn map_against_ast(
    out: &mut String,
    ast: &cddl::ast::CDDL<'_>,
    cbor: &[u8],
    cddl: &str,
    rule_name: &str,
) -> Result<(), sm::WalkError> {
    let rules = sm::RuleIndex::build(ast);
    let Some(root) = rules.get(rule_name) else {
        return Err(sm::WalkError::new(
            "missing_rule",
            &sm::missing_rule_message(rule_name),
        ));
    };
    let Rule::Type {
        rule: root_rule, ..
    } = root
    else {
        // Group roots are rejected the same way on every export.
        return Err(sm::WalkError::new(
            "group_rule_root",
            &sm::group_rule_root_message(rule_name),
        ));
    };

    // Refuse oversized docs before decoding (≈1 row per item).
    let bound = limits::MAX_CBOR_POSITION_MAP_ROWS;
    if limits::cbor_item_count_capped(cbor, bound) > bound {
        return Err(sm::WalkError::new(
            "validation_too_complex",
            &limits::position_map_rows_message(bound),
        ));
    }

    // Positional tree supplies CBOR byte spans.
    let tree = decoder::decode_cbor_to_value(cbor)
        .map_err(|e| sm::WalkError::from_object(validation::input_parse_error(&e, cbor.len())))?;
    // Nesting pre-check; leftover budget is for embedded `.cbor` payloads.
    let Some(budget) = limits::NestingBudget::for_document(cbor) else {
        return Err(sm::WalkError::new(
            "nesting_too_deep",
            &limits::cbor_nesting_message(),
        ));
    };
    let value = decode_cbor(cbor).map_err(|e| sm::value_decoder_error(&e.to_string()))?;

    // schema_mapper walk for decisions; free its JSON; keep the trace.
    let mapper = sm::Mapper::new(rules, budget);
    let (decoded, root_decision) = mapper.map_by_rule_name(&value, rule_name);
    drop(DeepJson::new(decoded));
    if let Some(refusal) = mapper.refusal() {
        return Err(refusal);
    }
    let trace = mapper.take_trace();

    // Truncate `out` back to `start` if replay refuses.
    let mut text = std::mem::take(out);
    let start = text.len();
    text.push_str("{\"entries\":[");
    let pm = PosMapper {
        sm: mapper,
        trace,
        descent: limits::DescentBudget::new(limits::MAX_CBOR_POSITION_MAP_DESCENT_COST),
        out: RefCell::new(text),
        rows: limits::WorkBudget::new(
            limits::MAX_CBOR_POSITION_MAP_ROWS,
            limits::position_map_rows_message,
        ),
        cbor_paths: RefCell::new(PathTable::new("$")),
        decoded_paths: RefCell::new(PathTable::new("$")),
        utf16: Utf16Index::new(cddl),
        cddl_source: cddl,
        cddl_spans: RefCell::new(HashMap::new()),
        bias: Cell::new(Some(0)),
    };

    // Root CDDL anchor = rule name span.
    pm.emit(
        Some(&*tree),
        Some(root_rule.name.span),
        Some(rule_name),
        "value",
        None,
    );
    {
        let spawner = Spawner::new();
        let replay = Replay {
            pm: &pm,
            spawner: spawner.clone(),
        };
        let root_node: &Value = &tree;
        let root_value: &CborValue = &value;
        let root_type = &root_rule.value;
        run_root(&spawner, async move {
            replay
                .walk_decision(root_value, Some(root_node), root_type, root_decision)
                .await
        });
    }

    // Bound hit ⇒ discard partial rows.
    let refusal = pm.refusal();
    let mut text = pm.out.into_inner();
    if let Some(refusal) = refusal {
        text.truncate(start);
        *out = text;
        return Err(refusal);
    }

    text.push_str("],\"cbor_paths\":");
    pm.cbor_paths.borrow().write_json(&mut text);
    text.push_str(",\"decoded_paths\":");
    pm.decoded_paths.borrow().write_json(&mut text);
    text.push('}');
    *out = text;
    Ok(())
}

// --- walker ---

struct PosMapper<'a> {
    /// schema_mapper whose walk this replay follows.
    sm: sm::Mapper<'a>,
    /// Decisions from that walk, node by node.
    trace: sm::Trace<'a>,
    /// Replay-only nesting budget (mapper budget already returned).
    descent: limits::DescentBudget,
    /// Open `entries` JSON being appended.
    out: RefCell<String>,
    /// Remaining row slots; exhaust ⇒ refuse.
    rows: limits::WorkBudget,
    /// Path tables indexed by entry `cbor_path` / `decoded_path`.
    cbor_paths: RefCell<PathTable>,
    decoded_paths: RefCell<PathTable>,
    utf16: Utf16Index,
    cddl_source: &'a str,
    /// Cached tightened CDDL spans, keyed by parser `(start, end)`.
    cddl_spans: RefCell<HashMap<(usize, usize), Option<SourceSpan>>>,
    /// Outer-buffer bias for CBOR spans; `None` if not contiguous (indefinite bytes).
    bias: Cell<Option<usize>>,
}

/// Path lengths before entering a node.
#[derive(Clone, Copy)]
struct PathMark {
    cbor: usize,
    decoded: usize,
}

/// One `entries` row: opens with paths + role; closes on drop.
struct Row<'w> {
    out: RefMut<'w, String>,
}

impl Row<'_> {
    /// Emit a CBOR `{offset, length}` field.
    fn byte_span(&mut self, key: &str, (offset, length): (u64, u64)) {
        write!(
            self.out,
            ",\"{}\":{{\"offset\":{},\"length\":{}}}",
            key, offset, length
        )
        .expect("writing to a String cannot fail");
    }

    /// Emit a CDDL source-span field.
    fn source_span(&mut self, key: &str, span: &SourceSpan) {
        write!(
            self.out,
            ",\"{}\":{{\"offset\":{},\"length\":{},\"char_offset\":{},\"char_length\":{},\"line\":{}}}",
            key, span.offset, span.length, span.char_offset, span.char_length, span.line
        )
        .expect("writing to a String cannot fail");
    }

    /// Emit a string field.
    fn text(&mut self, key: &str, value: &str) {
        self.out.push_str(",\"");
        self.out.push_str(key);
        self.out.push_str("\":");
        write_string(&mut self.out, value);
    }
}

impl Drop for Row<'_> {
    fn drop(&mut self) {
        self.out.push('}');
    }
}

impl<'a> PosMapper<'a> {
    // --- descent ---

    /// True if walk or replay already refused (nesting or row bound).
    fn refused(&self) -> bool {
        self.sm.refused() || self.descent.exhausted() || self.rows.exhausted()
    }

    /// Error to return instead of rows after a refusal.
    fn refusal(&self) -> Option<sm::WalkError> {
        self.sm
            .refusal()
            .or_else(|| {
                self.descent
                    .refusal()
                    .map(|message| sm::WalkError::new("nesting_too_deep", &message))
            })
            .or_else(|| {
                self.rows
                    .refusal()
                    .map(|message| sm::WalkError::new("validation_too_complex", &message))
            })
    }

    /// Charge a nested data-item level.
    fn level(&self) -> Option<limits::DescentGuard<'_>> {
        self.descent.charge(limits::POSITION_MAP_DESCENT.level)
    }

    /// Charge a rule-reference hop (no nested item).
    fn hop(&self) -> Option<limits::DescentGuard<'_>> {
        self.descent.charge(limits::POSITION_MAP_DESCENT.rule_hop)
    }

    /// Charge one level of a raw subtree.
    fn raw_level(&self) -> Option<limits::DescentGuard<'_>> {
        self.descent.charge(limits::POSITION_MAP_DESCENT.raw_level)
    }

    // --- paths ---

    /// Extend both paths; return marks for [`Self::leave`].
    fn enter(&self, cbor_segment: &str, decoded_segment: &str) -> PathMark {
        PathMark {
            cbor: self.cbor_paths.borrow_mut().enter(cbor_segment),
            decoded: self.decoded_paths.borrow_mut().enter(decoded_segment),
        }
    }

    /// Restore both paths to `mark`.
    fn leave(&self, mark: PathMark) {
        self.cbor_paths.borrow_mut().leave(mark.cbor);
        self.decoded_paths.borrow_mut().leave(mark.decoded);
    }

    // --- emission ---

    /// Open a row at the current paths, or refuse past the row bound.
    /// Omit unknown fields rather than emitting nulls.
    fn row(&self, role: &str) -> Option<Row<'_>> {
        if self.refused() || !self.rows.step() {
            return None;
        }
        let cbor_path = self.cbor_paths.borrow_mut().intern();
        let decoded_path = self.decoded_paths.borrow_mut().intern();
        let mut out = self.out.borrow_mut();
        if self.rows.spent() > 1 {
            out.push(',');
        }
        write!(
            out,
            "{{\"cbor_path\":{},\"decoded_path\":{},\"entry_role\":",
            cbor_path, decoded_path
        )
        .expect("writing to a String cannot fail");
        write_string(&mut out, role);
        Some(Row { out })
    }

    /// Emit one entry at the current paths.
    fn emit(
        &self,
        node: Option<&Value>,
        cddl_span: Option<Span>,
        rule_name: Option<&str>,
        role: &str,
        type_label: Option<&str>,
    ) {
        self.emit_with_match(node, cddl_span, rule_name, role, type_label, None);
    }

    /// Like [`PosMapper::emit`], plus optional `match_via` for map keys.
    fn emit_with_match(
        &self,
        node: Option<&Value>,
        cddl_span: Option<Span>,
        rule_name: Option<&str>,
        role: &str,
        type_label: Option<&str>,
        match_via: Option<&str>,
    ) {
        let Some(mut row) = self.row(role) else {
            return;
        };
        if let Some(n) = node {
            if let Some(b) = n.get("position_info").and_then(|p| self.biased(p)) {
                row.byte_span("cbor_byte_span", b);
            }
            if let Some(b) = n
                .get("struct_position_info")
                .or_else(|| n.get("position_info"))
                .and_then(|p| self.biased(p))
            {
                row.byte_span("cbor_anchor_span", b);
            }
        }
        if let Some(span) = cddl_span.and_then(|s| self.cddl_span(s)) {
            row.source_span("cddl_byte_span", &span);
        }
        if let Some(r) = rule_name {
            row.text("rule_name", r);
        }
        match type_label {
            Some(t) => row.text("cbor_type", t),
            None => {
                if let Some(t) = node.and_then(|n| n.get("type")).and_then(Value::as_str) {
                    row.text("cbor_type", t);
                }
            }
        }
        if let Some(via) = match_via {
            row.text("match_via", via);
        }
    }

    /// Synthetic wrapper (`@entries`, `@positional`, `@extra`, repeated field).
    /// No `cddl_byte_span`; `extent` is the bytes the wrapper covers.
    fn emit_wrapper(&self, extent: Option<(u64, u64)>, type_label: &str, cddl_span: Option<Span>) {
        let Some(mut row) = self.row("value") else {
            return;
        };
        if let Some(span) = self.bias_extent(extent) {
            row.byte_span("cbor_byte_span", span);
            row.byte_span("cbor_anchor_span", span);
        }
        if let Some(span) = cddl_span.and_then(|s| self.cddl_span(s)) {
            row.source_span("cddl_byte_span", &span);
        }
        row.text("cbor_type", type_label);
    }

    /// `@tag` row of `{@tag, @value}`; CBOR span is the tag header only.
    fn emit_tag_row(&self, tag_node: Option<&Value>, cddl_span: Option<Span>) {
        let mark = self.enter("", r#"["@tag"]"#);
        if let Some(mut row) = self.row("value") {
            if let Some(b) = tag_node
                .and_then(|n| n.get("position_info"))
                .and_then(|p| self.biased(p))
            {
                row.byte_span("cbor_byte_span", b);
                row.byte_span("cbor_anchor_span", b);
            }
            if let Some(span) = cddl_span.and_then(|s| self.cddl_span(s)) {
                row.source_span("cddl_byte_span", &span);
            }
            row.text("cbor_type", "tag");
        }
        self.leave(mark);
    }

    /// `@entries` pair row spanning key+value bytes.
    fn emit_pair_row(
        &self,
        key_node: Option<&Value>,
        extent: Option<(u64, u64)>,
        cddl_span: Option<Span>,
        via: &str,
    ) {
        let Some(mut row) = self.row("value") else {
            return;
        };
        if let Some(b) = key_node
            .and_then(|k| k.get("position_info"))
            .and_then(|p| self.biased(p))
        {
            row.byte_span("cbor_byte_span", b);
        }
        if let Some(b) = self.bias_extent(extent) {
            row.byte_span("cbor_anchor_span", b);
        }
        if let Some(span) = cddl_span.and_then(|s| self.cddl_span(s)) {
            row.source_span("cddl_byte_span", &span);
        }
        row.text("cbor_type", "map_entry");
        row.text("match_via", via);
    }

    /// Raw-map `@entries` pair: unmatched; both spans are the pair extent.
    fn emit_raw_pair_row(&self, extent: Option<(u64, u64)>) {
        let Some(mut row) = self.row("value") else {
            return;
        };
        if let Some(b) = self.bias_extent(extent) {
            row.byte_span("cbor_byte_span", b);
            row.byte_span("cbor_anchor_span", b);
        }
        row.text("cbor_type", "map_entry");
        row.text("match_via", "unmatched");
    }

    /// Node `(offset, length)` rebased onto the outer document.
    fn biased(&self, span: &Value) -> Option<(u64, u64)> {
        let bias = self.bias.get()? as u64;
        let offset = span.get("offset").and_then(Value::as_u64)?;
        let length = span.get("length").and_then(Value::as_u64).unwrap_or(0);
        Some((offset + bias, length))
    }

    fn bias_extent(&self, extent: Option<(u64, u64)>) -> Option<(u64, u64)> {
        let bias = self.bias.get()? as u64;
        let (offset, length) = extent?;
        Some((offset + bias, length))
    }

    /// Tightened, cached CDDL source span for a parser span.
    fn cddl_span(&self, span: Span) -> Option<SourceSpan> {
        let (start, end, _) = span;
        *self
            .cddl_spans
            .borrow_mut()
            .entry((start, end))
            .or_insert_with(|| {
                let (start, end) = tighten(span, self.cddl_source)?;
                Some(source_span(
                    &self.utf16,
                    start,
                    end,
                    self.utf16.line_at(start),
                ))
            })
    }

    // --- raw fall-through ---

    /// Rows for a value the schema did not describe (`raw` shape).
    /// Heap-walked; charge one raw level per node; budget exhaust ends emission.
    fn emit_raw(&self, c: &CborValue, n: Option<&Value>, span: Option<Span>) {
        self.emit_raw_steps(vec![RawStep::Node {
            c,
            n,
            cbor_segment: String::new(),
            decoded_segment: String::new(),
            span,
        }]);
    }

    /// Children only — caller already emitted the value's own row.
    fn emit_raw_children(&self, c: &CborValue, n: Option<&Value>) {
        self.emit_raw_steps(vec![RawStep::Children { c, n }]);
    }

    fn emit_raw_steps<'c, 'g>(&'g self, mut pending: Vec<RawStep<'c, 'g>>) {
        while let Some(step) = pending.pop() {
            if self.refused() {
                return;
            }
            match step {
                RawStep::Node {
                    c,
                    n,
                    cbor_segment,
                    decoded_segment,
                    span,
                } => {
                    let mark = self.enter(&cbor_segment, &decoded_segment);
                    // Charge before emitting so a refused level leaves no row.
                    let Some(level) = self.raw_level() else {
                        return;
                    };
                    self.emit(n, span, None, "value", None);
                    pending.push(RawStep::Leave {
                        mark,
                        _level: level,
                    });
                    pending.push(RawStep::Children { c, n });
                }
                RawStep::Children { c, n } => self.expand_raw_children(c, n, &mut pending),
                RawStep::Pair {
                    idx,
                    key,
                    value,
                    key_node,
                    value_node,
                    extent,
                } => {
                    let mark = self.enter("", &format!("[{}]", idx));
                    self.emit_raw_pair_row(extent);
                    pending.push(RawStep::Unwind { mark });
                    pending.push(RawStep::Node {
                        c: value,
                        n: value_node,
                        cbor_segment: String::new(),
                        decoded_segment: decoded_path_segment("value"),
                        span: None,
                    });
                    pending.push(RawStep::Node {
                        c: key,
                        n: key_node,
                        cbor_segment: String::new(),
                        decoded_segment: decoded_path_segment("key"),
                        span: None,
                    });
                }
                RawStep::Leave { mark, _level } => self.leave(mark),
                RawStep::Unwind { mark } => self.leave(mark),
            }
        }
    }

    /// Queue children of one raw node (emission order).
    fn expand_raw_children<'c, 'g>(
        &'g self,
        c: &'c CborValue,
        n: Option<&'c Value>,
        pending: &mut Vec<RawStep<'c, 'g>>,
    ) {
        match c {
            CborValue::Array(items) => {
                let nodes = items_of(n);
                for (i, item) in items.iter().enumerate().rev() {
                    pending.push(RawStep::Node {
                        c: item,
                        n: item_node(&nodes, i),
                        cbor_segment: format!("[{}]", i),
                        decoded_segment: format!("[{}]", i),
                        span: None,
                    });
                }
            }
            CborValue::Map(entries) => {
                let nodes = map_entries_of(n);
                if sm::map_needs_entries(entries) {
                    let mark = self.enter("", r#"["@entries"]"#);
                    self.emit_wrapper(n.and_then(node_extent), "map_entries", None);
                    pending.push(RawStep::Unwind { mark });
                    for (idx, (key, value)) in entries.iter().enumerate().rev() {
                        pending.push(RawStep::Pair {
                            idx,
                            key,
                            value,
                            key_node: nodes.as_ref().and_then(|v| v.get(idx)).map(|(k, _)| *k),
                            value_node: nodes.as_ref().and_then(|v| v.get(idx)).map(|(_, v)| *v),
                            extent: entry_extent(&nodes, idx),
                        });
                    }
                } else {
                    for (idx, (key, value)) in entries.iter().enumerate().rev() {
                        let label = sm::json_key(key);
                        pending.push(RawStep::Node {
                            c: value,
                            n: nodes.as_ref().and_then(|v| v.get(idx)).map(|(_, v)| *v),
                            cbor_segment: cbor_path_segment(&label),
                            decoded_segment: decoded_path_segment(&label),
                            span: None,
                        });
                    }
                }
            }
            CborValue::Tag(_, inner) => {
                self.emit_tag_row(n, None);
                pending.push(RawStep::Node {
                    c: inner,
                    n: tag_payload_of(n),
                    cbor_segment: String::new(),
                    decoded_segment: r#"["@value"]"#.to_string(),
                    span: None,
                });
            }
            CborValue::Simple(_) => {
                let mark = self.enter("", r#"["@simple"]"#);
                self.emit(n, None, None, "value", None);
                self.leave(mark);
            }
            _ => {}
        }
    }
}

/// Heap step while emitting a raw subtree.
enum RawStep<'c, 'g> {
    /// Emit node row, then children, one path segment down.
    Node {
        c: &'c CborValue,
        n: Option<&'c Value>,
        cbor_segment: String,
        decoded_segment: String,
        span: Option<Span>,
    },
    /// Children only (parent row already emitted).
    Children {
        c: &'c CborValue,
        n: Option<&'c Value>,
    },
    /// `@entries` pair: pair row, then key and value.
    Pair {
        idx: usize,
        key: &'c CborValue,
        value: &'c CborValue,
        key_node: Option<&'c Value>,
        value_node: Option<&'c Value>,
        extent: Option<(u64, u64)>,
    },
    /// After children: restore paths and return the level guard.
    Leave {
        mark: PathMark,
        _level: limits::DescentGuard<'g>,
    },
    /// After a wrapper: restore paths.
    Unwind { mark: PathMark },
}

/// Replay of one schema_mapper walk via `walk_driver`.
struct Replay<'a, 'v> {
    pm: &'v PosMapper<'a>,
    spawner: Spawner<'v>,
}

impl<'a, 'v> Clone for Replay<'a, 'v> {
    fn clone(&self) -> Self {
        Replay {
            pm: self.pm,
            spawner: self.spawner.clone(),
        }
    }
}

impl<'a: 'v, 'v> Replay<'a, 'v> {
    /// Run `task` above this step (heap driver).
    fn above(&self, task: impl Future<Output = ()> + 'v) -> impl Future<Output = ()> + 'v {
        run_above(&self.spawner, task)
    }

    fn node(&self, id: TraceId) -> &'v TraceNode<'a> {
        self.pm.trace.node(id)
    }

    // --- types ---

    /// Replay the trace decision for `ty` against `c`.
    async fn walk_decision(
        &self,
        c: &'v CborValue,
        n: Option<&'v Value>,
        ty: &'a Type<'a>,
        decision: TraceId,
    ) {
        if self.pm.refused() {
            return;
        }
        match self.node(decision) {
            TraceNode::Alt { index, inner, .. } => match ty.type_choices.get(*index) {
                Some(choice) => self.walk_type1(c, n, &choice.type1, *inner).await,
                None => self.pm.emit_raw(c, n, None),
            },
            _ => self.pm.emit_raw(c, n, None),
        }
    }

    async fn walk_type1(
        &self,
        c: &'v CborValue,
        n: Option<&'v Value>,
        t1: &'a Type1<'a>,
        trace: TraceId,
    ) {
        if self.pm.refused() {
            return;
        }
        match self.node(trace) {
            // Range constrains value only; shape stays raw.
            TraceNode::Range => self.pm.emit_raw(c, n, Some(t1.span)),
            TraceNode::Embedded { inner } => match (&t1.operator, c) {
                (Some(op), CborValue::Bytes(payload)) => {
                    self.walk_embedded(payload, n, &op.type2, *inner)
                }
                _ => self.pm.emit_raw(c, n, None),
            },
            _ => self.walk_type2(c, n, &t1.type2, trace).await,
        }
    }

    /// Replay a `.cbor` / `.cborseq` payload; rebase spans or drop CBOR
    /// spans if the payload is not contiguous. Own driver until done.
    fn walk_embedded(
        &self,
        payload: &'v [u8],
        outer_node: Option<&'v Value>,
        t2: &'a Type2<'a>,
        inner: TraceId,
    ) {
        // Nesting comes from remaining document budget.
        let Some((inner_value, _guard)) = sm::decode_embedded(self.pm.sm.budget(), payload) else {
            if !self.pm.refused() {
                self.pm
                    .emit(outer_node, Some(type2_span(t2)), None, "value", None);
            }
            return;
        };
        let Ok(inner_tree) = decoder::decode_cbor_to_value(payload) else {
            self.pm
                .emit(outer_node, Some(type2_span(t2)), None, "value", None);
            return;
        };
        let Some(_level) = self.pm.level() else {
            return;
        };
        let saved = self.pm.bias.get();
        self.pm
            .bias
            .set(payload_bias(saved, outer_node, payload.len()));
        {
            let spawner = Spawner::new();
            let replay = Replay {
                pm: self.pm,
                spawner: spawner.clone(),
            };
            let inner_value: &CborValue = &inner_value;
            let inner_node: &Value = &inner_tree;
            run_root(&spawner, async move {
                replay
                    .walk_type2(inner_value, Some(inner_node), t2, inner)
                    .await
            });
        }
        self.pm.bias.set(saved);
    }

    async fn walk_type2(
        &self,
        c: &'v CborValue,
        n: Option<&'v Value>,
        t2: &'a Type2<'a>,
        trace: TraceId,
    ) {
        if self.pm.refused() {
            return;
        }
        match t2 {
            Type2::Typename { ident, .. } | Type2::Unwrap { ident, .. } => {
                self.walk_typename(c, n, ident.ident, ident.span, trace)
                    .await
            }
            Type2::ParenthesizedType { pt, .. } => match self.node(trace) {
                TraceNode::Paren { inner } => {
                    let inner = *inner;
                    let replay = self.clone();
                    self.above(async move { replay.walk_decision(c, n, pt, inner).await })
                        .await;
                }
                _ => self.pm.emit_raw(c, n, None),
            },
            Type2::Map { group, span, .. } => {
                self.pm.emit(n, Some(*span), None, "value", None);
                self.walk_map(c, n, group, trace).await;
            }
            Type2::Array { group, span, .. } => {
                self.pm.emit(n, Some(*span), None, "value", None);
                self.walk_array(c, n, group, trace).await;
            }
            Type2::TaggedData { t, span, .. } => self.walk_tagged(c, n, t, *span, trace).await,
            // `any` → raw shape.
            Type2::Any { span, .. } => self.pm.emit_raw(c, n, Some(*span)),
            other => self
                .pm
                .emit(n, Some(type2_span(other)), None, "value", None),
        }
    }

    async fn walk_typename(
        &self,
        c: &'v CborValue,
        n: Option<&'v Value>,
        name: &'a str,
        name_span: Span,
        trace: TraceId,
    ) {
        match self.node(trace) {
            TraceNode::Binding { arg, inner } => {
                // Generic arg may nest; charge as a rule hop.
                let Some(_hop) = self.pm.hop() else {
                    return;
                };
                let (arg, inner) = (*arg, *inner);
                let replay = self.clone();
                self.above(async move { replay.walk_type1(c, n, arg, inner).await })
                    .await;
            }
            TraceNode::Prelude { container } => {
                self.pm.emit(n, Some(name_span), Some(name), "value", None);
                // Prelude `any`-like containers stay addressable raw.
                if *container {
                    self.pm.emit_raw_children(c, n);
                }
            }
            TraceNode::Rule { rule, inner } => {
                let Some(_hop) = self.pm.hop() else {
                    return;
                };
                let (rule, inner) = (*rule, *inner);
                self.pm
                    .emit(n, Some(rule.name.span), Some(name), "value", None);
                let replay = self.clone();
                self.above(async move { replay.walk_decision(c, n, &rule.value, inner).await })
                    .await;
            }
            // Unknown name: keep source location, emit raw.
            _ => self.pm.emit_raw(c, n, Some(name_span)),
        }
    }

    async fn walk_tagged(
        &self,
        c: &'v CborValue,
        n: Option<&'v Value>,
        inner_ty: &'a Type<'a>,
        span: Span,
        trace: TraceId,
    ) {
        let CborValue::Tag(number, payload) = c else {
            self.pm.emit(n, Some(span), None, "value", None);
            return;
        };
        self.pm.emit(n, Some(span), None, "value", None);
        let payload_node = tag_payload_of(n);
        let TraceNode::Tagged { inner } = self.node(trace) else {
            self.pm.emit_raw_children(c, n);
            return;
        };

        let Some(inner) = *inner else {
            // Wide bignum → `{@tag,@value}`; narrow → plain scalar.
            let specialised = sm::specialise_known_tag(*number, payload);
            if specialised.is_some_and(|s| s.get("@tag").is_some()) {
                self.pm.emit_tag_row(n, Some(span));
                let mark = self.pm.enter("", r#"["@value"]"#);
                self.pm.emit(payload_node, None, None, "value", None);
                self.pm.leave(mark);
            }
            return;
        };

        self.pm.emit_tag_row(n, Some(span));
        let Some(_level) = self.pm.level() else {
            return;
        };
        // CBOR path tag-transparent; decoded path uses `{@tag,@value}`.
        let mark = self.pm.enter("", r#"["@value"]"#);
        let payload: &'v CborValue = payload;
        let replay = self.clone();
        self.above(async move {
            replay
                .walk_decision(payload, payload_node, inner_ty, inner)
                .await
        })
        .await;
        self.pm.leave(mark);
    }

    // --- maps ---

    async fn walk_map(
        &self,
        c: &'v CborValue,
        n: Option<&'v Value>,
        group: &'a Group<'a>,
        trace: TraceId,
    ) {
        let CborValue::Map(entries) = c else { return };
        let nodes = map_entries_of(n);

        match self.node(trace) {
            TraceNode::Map(MapTrace::Entries(traces)) => {
                self.walk_map_entries_form(entries, &nodes, n, traces).await
            }
            TraceNode::Map(MapTrace::Choice(plan)) => {
                self.walk_map_choice(entries, &nodes, plan).await
            }
            // Fallback: keep entries addressable.
            _ => {
                let _ = group;
                self.pm.emit_raw_children(c, n)
            }
        }
    }

    async fn walk_map_choice(
        &self,
        entries: &'v [(CborValue, CborValue)],
        nodes: &Option<Vec<(&'v Value, &'v Value)>>,
        plan: &'v sm::MapChoicePlan<'a>,
    ) {
        let mut claimed: Vec<&sm::MapSlotRef<'a>> = plan
            .claimed
            .iter()
            .filter(|s| s.wire_index.is_some())
            .collect();
        claimed.sort_by_key(|s| s.wire_index.unwrap_or(usize::MAX));

        // Repeated field names → array wrapper (mirrors decoder).
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for s in &claimed {
            *counts.entry(s.name.as_str()).or_insert(0) += 1;
        }
        let mut seen: HashMap<&str, usize> = HashMap::new();
        for s in &claimed {
            if counts.get(s.name.as_str()).copied().unwrap_or(0) > 1
                && !seen.contains_key(s.name.as_str())
            {
                seen.insert(s.name.as_str(), 0);
                let extent = claimed
                    .iter()
                    .filter(|o| o.name == s.name)
                    .filter_map(|o| o.wire_index)
                    .filter_map(|i| entry_extent(nodes, i))
                    .fold(None, |acc, e| union_extent(acc, Some(e)));
                let mark = self
                    .pm
                    .enter(&cbor_path_segment(&s.name), &decoded_path_segment(&s.name));
                self.pm.emit_wrapper(
                    extent,
                    "map_repeated",
                    member_key_span(s.member_key, self.pm.cddl_source),
                );
                self.pm.leave(mark);
            }
        }

        for s in &claimed {
            let Some(i) = s.wire_index else { continue };
            let mark = self
                .pm
                .enter(&cbor_path_segment(&s.name), &decoded_path_segment(&s.name));
            let indexed = if counts.get(s.name.as_str()).copied().unwrap_or(0) > 1 {
                let j = seen.entry(s.name.as_str()).or_insert(0);
                let idx = *j;
                *j += 1;
                let segment = format!("[{}]", idx);
                Some(self.pm.enter(&segment, &segment))
            } else {
                None
            };

            let key_node = nodes.as_ref().and_then(|v| v.get(i)).map(|(k, _)| *k);
            let value_node = nodes.as_ref().and_then(|v| v.get(i)).map(|(_, v)| *v);
            self.pm.emit_with_match(
                key_node,
                member_key_span(s.member_key, self.pm.cddl_source),
                None,
                "key",
                None,
                Some(if sm::is_literal_member_key(s.member_key) {
                    "literal"
                } else {
                    "type"
                }),
            );

            let value = &entries[i].1;
            let Some(_level) = self.pm.level() else {
                return;
            };
            if let Some(decision) = s.value {
                let entry_type = s.entry_type;
                let replay = self.clone();
                self.above(async move {
                    replay
                        .walk_decision(value, value_node, entry_type, decision)
                        .await
                })
                .await;
            }
            drop(_level);
            if let Some(indexed) = indexed {
                self.pm.leave(indexed);
            }
            self.pm.leave(mark);
        }

        // Missing optional members → null placeholders (schema, no bytes).
        let mut present: HashSet<String> = claimed.iter().map(|s| s.name.clone()).collect();
        for s in plan.claimed.iter().filter(|s| s.wire_index.is_none()) {
            if !present.insert(s.name.clone()) {
                continue;
            }
            let mark = self
                .pm
                .enter(&cbor_path_segment(&s.name), &decoded_path_segment(&s.name));
            self.pm.emit(
                None,
                member_key_span(s.member_key, self.pm.cddl_source),
                None,
                "value",
                None,
            );
            self.pm.leave(mark);
        }

        if !plan.leftover.is_empty() {
            let extent = plan
                .leftover
                .iter()
                .filter_map(|i| entry_extent(nodes, *i))
                .fold(None, |acc, e| union_extent(acc, Some(e)));
            let extra = self.pm.enter("", r#"["@extra"]"#);
            self.pm.emit_wrapper(extent, "map_extra", None);
            for i in &plan.leftover {
                let label = sm::json_key(&entries[*i].0);
                let value_node = nodes.as_ref().and_then(|v| v.get(*i)).map(|(_, v)| *v);
                let mark = self
                    .pm
                    .enter(&cbor_path_segment(&label), &decoded_path_segment(&label));
                self.pm.emit_raw(&entries[*i].1, value_node, None);
                self.pm.leave(mark);
            }
            self.pm.leave(extra);
        }
    }

    async fn walk_map_entries_form(
        &self,
        entries: &'v [(CborValue, CborValue)],
        nodes: &Option<Vec<(&'v Value, &'v Value)>>,
        map_node: Option<&'v Value>,
        traces: &'v [EntryTrace<'a>],
    ) {
        let entries_mark = self.pm.enter("", r#"["@entries"]"#);
        self.pm
            .emit_wrapper(map_node.and_then(node_extent), "map_entries", None);

        for (idx, (key, value)) in entries.iter().enumerate() {
            let pair_mark = self.pm.enter("", &format!("[{}]", idx));
            let key_node = nodes.as_ref().and_then(|v| v.get(idx)).map(|(k, _)| *k);
            let value_node = nodes.as_ref().and_then(|v| v.get(idx)).map(|(_, v)| *v);

            let matched = traces.get(idx).and_then(|t| t.member);
            let mk_span = matched.and_then(|(mk, _)| member_key_span(mk, self.pm.cddl_source));
            let via = match matched {
                Some((mk, _)) if sm::is_literal_member_key(mk) => "literal",
                Some(_) => "type",
                None => "unmatched",
            };

            // Pair row covers key + value bytes.
            self.pm
                .emit_pair_row(key_node, entry_extent(nodes, idx), mk_span, via);

            let key_mark = self.pm.enter("", &decoded_path_segment("key"));
            self.pm
                .emit_with_match(key_node, mk_span, None, "key", None, Some(via));
            // Complex keys are addressable trees.
            self.pm.emit_raw_children(key, key_node);
            self.pm.leave(key_mark);

            let Some(_level) = self.pm.level() else {
                return;
            };
            let value_mark = self.pm.enter("", &decoded_path_segment("value"));
            match (matched, traces.get(idx).and_then(|t| t.value)) {
                (Some((_, entry_type)), Some(decision)) => {
                    let replay = self.clone();
                    self.above(async move {
                        replay
                            .walk_decision(value, value_node, entry_type, decision)
                            .await
                    })
                    .await;
                }
                // Unmatched: omit CDDL span rather than guess a member.
                _ => self.pm.emit_raw(value, value_node, None),
            }
            drop(_level);
            self.pm.leave(value_mark);
            self.pm.leave(pair_mark);
        }
        self.pm.leave(entries_mark);
    }

    // --- arrays ---

    async fn walk_array(
        &self,
        c: &'v CborValue,
        n: Option<&'v Value>,
        group: &'a Group<'a>,
        trace: TraceId,
    ) {
        let CborValue::Array(items) = c else { return };
        let nodes = items_of(n);
        match self.node(trace) {
            TraceNode::Array(plan) => self.walk_array_plan(items, &nodes, plan).await,
            // Fallback: keep items addressable.
            _ => {
                let _ = group;
                self.pm.emit_raw_children(c, n)
            }
        }
    }

    async fn walk_array_plan(
        &self,
        items: &'v [CborValue],
        nodes: &Option<Vec<&'v Value>>,
        plan: &'v ArrayTrace<'a>,
    ) {
        let any_named = plan.any_named;
        // Dense positional index in emission order (not wire slot).
        let mut positional = 0usize;
        let mut positional_items: Vec<usize> = Vec::new();

        for pe in &plan.plan {
            match &pe.name {
                Some(name) if pe.repeated => {
                    let field = self
                        .pm
                        .enter(&cbor_path_segment(name), &decoded_path_segment(name));
                    let extent = (pe.start..pe.start + pe.count)
                        .filter_map(|i| item_extent(nodes, i))
                        .fold(None, |acc, e| union_extent(acc, Some(e)));
                    self.pm
                        .emit_wrapper(extent, "array_repeated", Some(slot_span(pe.slot)));
                    for j in 0..pe.count {
                        let wire = pe.start + j;
                        let segment = format!("[{}]", j);
                        let mark = self.pm.enter(&segment, &segment);
                        self.walk_slot(
                            &items[wire],
                            item_node(nodes, wire),
                            pe.slot,
                            plan.items.get(wire).copied(),
                        )
                        .await;
                        self.pm.leave(mark);
                    }
                    self.pm.leave(field);
                }
                Some(name) if pe.count >= 1 => {
                    let mark = self
                        .pm
                        .enter(&cbor_path_segment(name), &decoded_path_segment(name));
                    self.walk_slot(
                        &items[pe.start],
                        item_node(nodes, pe.start),
                        pe.slot,
                        plan.items.get(pe.start).copied(),
                    )
                    .await;
                    self.pm.leave(mark);
                }
                // Non-repeating named miss → no field in decoded output.
                Some(_) => {}
                None => {
                    for j in 0..pe.count {
                        let wire = pe.start + j;
                        let decoded_segment = if any_named {
                            format!(r#"["@positional"][{}]"#, positional)
                        } else {
                            format!("[{}]", positional)
                        };
                        positional_items.push(wire);
                        positional += 1;
                        let mark = self.pm.enter(&format!("[{}]", wire), &decoded_segment);
                        self.walk_slot(
                            &items[wire],
                            item_node(nodes, wire),
                            pe.slot,
                            plan.items.get(wire).copied(),
                        )
                        .await;
                        self.pm.leave(mark);
                    }
                }
            }
        }

        if any_named && !positional_items.is_empty() {
            let extent = positional_items
                .iter()
                .filter_map(|i| item_extent(nodes, *i))
                .fold(None, |acc, e| union_extent(acc, Some(e)));
            let mark = self.pm.enter("", r#"["@positional"]"#);
            self.pm.emit_wrapper(extent, "array_positional", None);
            self.pm.leave(mark);
        }

        let leftover: Vec<usize> = (plan.cursor..items.len()).collect();
        if leftover.is_empty() {
            return;
        }
        if any_named {
            let extent = leftover
                .iter()
                .filter_map(|i| item_extent(nodes, *i))
                .fold(None, |acc, e| union_extent(acc, Some(e)));
            let extra = self.pm.enter("", r#"["@extra"]"#);
            self.pm.emit_wrapper(extent, "array_extra", None);
            for (j, wire) in leftover.iter().enumerate() {
                let mark = self.pm.enter(&format!("[{}]", wire), &format!("[{}]", j));
                self.pm
                    .emit_raw(&items[*wire], item_node(nodes, *wire), None);
                self.pm.leave(mark);
            }
            self.pm.leave(extra);
        } else {
            // Homogeneous leftovers continue positional numbering.
            for wire in leftover {
                let mark = self
                    .pm
                    .enter(&format!("[{}]", wire), &format!("[{}]", positional));
                self.pm.emit_raw(&items[wire], item_node(nodes, wire), None);
                self.pm.leave(mark);
                positional += 1;
            }
        }
    }

    async fn walk_slot(
        &self,
        c: &'v CborValue,
        n: Option<&'v Value>,
        slot: sm::PlanSlot<'a>,
        decision: Option<TraceId>,
    ) {
        let Some(_level) = self.pm.level() else {
            return;
        };
        let Some(decision) = decision else {
            self.pm.emit_raw(c, n, None);
            return;
        };
        match slot {
            sm::PlanSlot::Ty(ty) => {
                let replay = self.clone();
                self.above(async move { replay.walk_decision(c, n, ty, decision).await })
                    .await;
            }
            sm::PlanSlot::Ref(name, span) => self.walk_typename(c, n, name, span, decision).await,
        }
    }
}

// --- positional tree ---

/// Array items with indefinite `Break` dropped so indices match decoded values.
fn items_of(n: Option<&Value>) -> Option<Vec<&Value>> {
    let n = n?;
    if n.get("type").and_then(Value::as_str)? != "Array" {
        return None;
    }
    Some(
        n.get("values")?
            .as_array()?
            .iter()
            .filter(|i| i.get("type").and_then(Value::as_str) != Some("Break"))
            .collect(),
    )
}

fn map_entries_of(n: Option<&Value>) -> Option<Vec<(&Value, &Value)>> {
    let n = n?;
    if n.get("type").and_then(Value::as_str)? != "Map" {
        return None;
    }
    Some(
        n.get("values")?
            .as_array()?
            .iter()
            .filter_map(|e| Some((e.get("key")?, e.get("value")?)))
            .collect(),
    )
}

fn tag_payload_of(n: Option<&Value>) -> Option<&Value> {
    let n = n?;
    if n.get("type").and_then(Value::as_str)? != "Tag" {
        return None;
    }
    n.get("value")
}

fn item_node<'j>(nodes: &Option<Vec<&'j Value>>, i: usize) -> Option<&'j Value> {
    nodes.as_ref().and_then(|v| v.get(i)).copied()
}

/// Byte extent of a decoded node (struct span, else header).
fn node_extent(n: &Value) -> Option<(u64, u64)> {
    let span = n
        .get("struct_position_info")
        .or_else(|| n.get("position_info"))?;
    Some((
        span.get("offset").and_then(Value::as_u64)?,
        span.get("length").and_then(Value::as_u64).unwrap_or(0),
    ))
}

fn item_extent(nodes: &Option<Vec<&Value>>, i: usize) -> Option<(u64, u64)> {
    node_extent(item_node(nodes, i)?)
}

fn entry_extent(nodes: &Option<Vec<(&Value, &Value)>>, i: usize) -> Option<(u64, u64)> {
    let (k, v) = nodes.as_ref()?.get(i)?;
    union_extent(node_extent(k), node_extent(v))
}

fn union_extent(a: Option<(u64, u64)>, b: Option<(u64, u64)>) -> Option<(u64, u64)> {
    match (a, b) {
        (Some((ao, al)), Some((bo, bl))) => {
            let start = ao.min(bo);
            let end = (ao + al).max(bo + bl);
            Some((start, end - start))
        }
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

/// Bias for `.cbor` payload spans onto the outer buffer; `None` if not contiguous.
fn payload_bias(
    outer_bias: Option<usize>,
    outer_node: Option<&Value>,
    payload_len: usize,
) -> Option<usize> {
    let bias = outer_bias?;
    let node = outer_node?;
    if node.get("type").and_then(Value::as_str)? != "Bytes" {
        return None;
    }
    let span = node.get("position_info")?;
    let offset = span.get("offset").and_then(Value::as_u64)? as usize;
    let length = span.get("length").and_then(Value::as_u64)? as usize;
    if length < payload_len {
        return None;
    }
    Some(bias + offset + (length - payload_len))
}

// --- CDDL spans ---

fn type2_span(t2: &Type2<'_>) -> Span {
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

fn slot_span(slot: sm::PlanSlot<'_>) -> Span {
    match slot {
        sm::PlanSlot::Ty(ty) => ty.span,
        sm::PlanSlot::Ref(_, span) => span,
    }
}

/// Trim pest trailing trivia (ws / comments). Keep interior comments.
/// `None` if nothing remains to highlight.
fn tighten(span: Span, source: &str) -> Option<(usize, usize)> {
    let (raw_start, raw_end, _) = span;
    if raw_start > source.len() {
        return None;
    }
    let mut start = raw_start;
    let mut end = raw_end.min(source.len());
    while start < end && !source.is_char_boundary(start) {
        start += 1;
    }
    while end > start && !source.is_char_boundary(end) {
        end -= 1;
    }
    if start >= end {
        return None;
    }
    let outer = (start, end);

    loop {
        while end > start {
            let c = source[start..end].chars().next_back()?;
            if c.is_whitespace() {
                end -= c.len_utf8();
            } else {
                break;
            }
        }
        match trailing_comment_start(&source[start..end]) {
            // Comment-only span: keep whole rather than collapse.
            Some(0) | None => break,
            Some(offset) => end = start + offset,
        }
    }
    while start < end {
        let c = source[start..end].chars().next()?;
        if c.is_whitespace() {
            start += c.len_utf8();
        } else {
            break;
        }
    }
    if start >= end {
        // All trivia — keep original (avoid zero-length at file start).
        return Some(outer);
    }
    Some((start, end))
}

/// Offset of a trailing `;` comment that runs to end of `s`, if any.
fn trailing_comment_start(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    let mut quote: Option<u8> = None;
    let mut comment: Option<usize> = None;
    while i < bytes.len() {
        let c = bytes[i];
        if comment.is_some() {
            if c == b'\n' {
                comment = None;
            }
            i += 1;
            continue;
        }
        match quote {
            Some(q) => {
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == q {
                    quote = None;
                }
            }
            None => {
                if c == b'"' || c == b'\'' {
                    quote = Some(c);
                } else if c == b';' {
                    comment = Some(i);
                }
            }
        }
        i += 1;
    }
    comment
}

/// Span of a member key only (`a`, `0`, `<type1>`), not the whole `name: type` slot.
fn member_key_span(mk: &MemberKey<'_>, source: &str) -> Option<Span> {
    match mk {
        MemberKey::Bareword { ident, .. } => Some(ident.span),
        MemberKey::Type1 { t1, .. } => Some(t1.span),
        MemberKey::Value { span, .. } => Some(trim_to_key(*span, source)),
        MemberKey::NonMemberKey { .. } => None,
    }
}

/// Trim pest value-key span to the literal (drop `:` / `^` / `=>` and ws).
fn trim_to_key(broad: Span, source: &str) -> Span {
    let (start, end, line) = broad;
    let end = end.min(source.len());
    if start >= end {
        return broad;
    }
    let slice = &source[start..end];
    let mut sep_idx = slice.len();
    for sep in [":", "^", "=>"] {
        if let Some(i) = slice.find(sep) {
            if i < sep_idx {
                sep_idx = i;
            }
        }
    }
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

// --- paths ---

/// CBOR path segment for `field`: `[N]`, `.name`, or `[quoted]`.
fn cbor_path_segment(field: &str) -> String {
    if field.chars().all(|c| c.is_ascii_digit()) && !field.is_empty()
        || (field.starts_with('-')
            && field.len() > 1
            && field[1..].chars().all(|c| c.is_ascii_digit()))
    {
        format!("[{}]", field)
    } else if !field.is_empty() && field.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        format!(".{}", field)
    } else {
        format!("[{:?}]", field)
    }
}

/// Decoded JSON path segment: `.name` or `[quoted]` (keys are always strings).
pub(crate) fn decoded_path_segment(field: &str) -> String {
    let identifier_safe = !field.is_empty()
        && !field.chars().next().unwrap().is_ascii_digit()
        && field.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if identifier_safe {
        format!(".{}", field)
    } else {
        format!("[{:?}]", field)
    }
}

/// `parent` + segment for `field` in the decoded JSON tree.
#[cfg(test)]
pub(crate) fn extend_decoded_path(parent: &str, field: &str) -> String {
    format!("{}{}", parent, decoded_path_segment(field))
}

// --- tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run(cddl: &str, rule: &str, hex_cbor: &str) -> Vec<Value> {
        let bytes = hex::decode(hex_cbor).unwrap();
        expand_paths(&map_cbor_to_cddl(&bytes, cddl, rule).unwrap())
    }

    fn paths(entries: &[Value]) -> Vec<String> {
        entries
            .iter()
            .map(|e| e["cbor_path"].as_str().unwrap().to_string())
            .collect()
    }

    fn decoded_paths(entries: &[Value]) -> Vec<String> {
        entries
            .iter()
            .map(|e| e["decoded_path"].as_str().unwrap().to_string())
            .collect()
    }

    fn entry_at<'a>(entries: &'a [Value], path: &str) -> &'a Value {
        entries
            .iter()
            .find(|e| e["cbor_path"] == json!(path))
            .unwrap_or_else(|| panic!("no entry at path {} in {:?}", path, paths(entries)))
    }

    fn snippet<'s>(cddl: &'s str, entry: &Value) -> &'s str {
        let s = &entry["cddl_byte_span"];
        let off = s["offset"].as_u64().unwrap() as usize;
        let len = s["length"].as_u64().unwrap() as usize;
        &cddl[off..off + len]
    }

    #[test]
    fn map_emits_entry_for_root_with_rule_name() {
        // uint 100; root `coin`.
        let entries = run("coin = uint", "coin", "1864");
        let root = &entries[0];
        assert_eq!(root["cbor_path"], json!("$"));
        assert_eq!(root["rule_name"], json!("coin"));
        assert!(root["cbor_byte_span"]["offset"].is_number());
        assert!(root["cddl_byte_span"]["offset"].is_number());
    }

    #[test]
    fn map_walks_into_named_array_entries() {
        let entries = run(
            "out = [address: bstr, amount: uint]",
            "out",
            "82430102030 7".replace(' ', "").as_str(),
        );
        let p = paths(&entries);
        assert!(p.iter().any(|p| p == "$"), "{:?}", p);
        assert!(p.iter().any(|p| p == "$.address"), "{:?}", p);
        assert!(p.iter().any(|p| p == "$.amount"), "{:?}", p);
        let addr = entry_at(&entries, "$.address");
        assert_eq!(addr["cbor_byte_span"]["offset"], json!(1));
    }

    #[test]
    fn map_emits_key_entries_alongside_value_entries() {
        let entries = run(
            "tx_body = {a: int, b: int}",
            "tx_body",
            "a261610161620 2".replace(' ', "").as_str(),
        );
        let a_key = entries
            .iter()
            .find(|e| e["cbor_path"] == json!("$.a") && e["entry_role"] == json!("key"))
            .unwrap_or_else(|| panic!("no key entry for $.a in {:?}", paths(&entries)));
        let a_val = entries
            .iter()
            .find(|e| e["cbor_path"] == json!("$.a") && e["entry_role"] == json!("value"))
            .unwrap_or_else(|| panic!("no value entry for $.a"));
        assert_eq!(a_key["cbor_byte_span"]["offset"], json!(1));
        assert_eq!(a_key["cbor_byte_span"]["length"], json!(2));
        assert_eq!(a_val["cbor_byte_span"]["offset"], json!(3));
        assert_eq!(a_key["decoded_path"], a_val["decoded_path"]);
    }

    #[test]
    fn map_emits_key_entries_for_numeric_keyed_maps() {
        let entries = run(
            "body = { 0: uint, 1: uint }",
            "body",
            "a200 01 011864".replace(' ', "").as_str(),
        );
        let zero_key = entries
            .iter()
            .find(|e| e["cbor_path"] == json!("$[0]") && e["entry_role"] == json!("key"))
            .unwrap_or_else(|| panic!("no key entry for $[0]"));
        assert_eq!(zero_key["cbor_byte_span"]["offset"], json!(1));
        assert_eq!(zero_key["cbor_byte_span"]["length"], json!(1));
        assert_eq!(zero_key["decoded_path"], json!(r#"$["0"]"#));
    }

    #[test]
    fn map_unwraps_tag_transparently() {
        let cddl = "
            set<a> = #6.258([* a])
            inputs = set<input>
            input = [tx: bstr, idx: uint]
        ";
        let cbor_hex = format!("d9 0102 81 82 5820 {} 00", "ab".repeat(32)).replace(' ', "");
        let entries = run(cddl, "inputs", &cbor_hex);
        let p = paths(&entries);
        // CBOR path is tag-transparent (no `@value`).
        assert!(p.iter().any(|x| x == "$"), "{:?}", p);
        assert!(p.iter().any(|x| x == "$[0]"), "{:?}", p);
        assert!(p.iter().any(|x| x == "$[0].tx"), "{:?}", p);
        assert!(p.iter().any(|x| x == "$[0].idx"), "{:?}", p);
        // Decoded path uses `{@tag, @value}`.
        let d = decoded_paths(&entries);
        assert!(d.iter().any(|x| x == r#"$["@tag"]"#), "{:?}", d);
        assert!(d.iter().any(|x| x == r#"$["@value"][0].tx"#), "{:?}", d);
    }

    #[test]
    fn map_emits_entry_for_each_uint_in_homogeneous_array() {
        let entries = run("arr = [* uint]", "arr", "83010203");
        let p = paths(&entries);
        assert!(p.iter().any(|x| x == "$"), "{:?}", p);
        assert!(p.iter().any(|x| x == "$[0]"), "{:?}", p);
        assert!(p.iter().any(|x| x == "$[1]"), "{:?}", p);
        assert!(p.iter().any(|x| x == "$[2]"), "{:?}", p);
    }

    #[test]
    fn key_span_points_only_at_key_not_at_value_or_separator() {
        let cases = [
            ("tx_body = {a: int}", "a16161 01", "a"),
            ("tx_body = {a    :    int}", "a16161 01", "a"),
            ("tx_body = {0: int}", "a10001", "0"),
            ("tx_body = {  0   :    int  }", "a10001", "0"),
            ("tx_body = {  abc   :    int  }", "a163616263 01", "abc"),
        ];
        for (schema, cbor_hex, expected) in cases {
            let bytes = hex::decode(cbor_hex.replace(' ', "")).unwrap();
            let arr = expand_paths(&map_cbor_to_cddl(&bytes, schema, "tx_body").unwrap());
            let key = arr
                .iter()
                .find(|e| e["entry_role"] == json!("key"))
                .unwrap_or_else(|| panic!("no key entry for schema={:?}", schema));
            assert_eq!(
                snippet(schema, key),
                expected,
                "schema={:?} expected key span {:?}",
                schema,
                expected
            );
        }
    }

    #[test]
    fn map_emits_stacked_entries_for_each_resolution_level() {
        let schema = "
            inputs = nonempty_set<input>
            nonempty_set<a> = #6.258([+ a]) / [+ a]
            input = [bstr, uint]
        ";
        let cbor_hex = format!("d9 0102 81 82 5820 {} 00", "ab".repeat(32)).replace(' ', "");
        let bytes = hex::decode(&cbor_hex).unwrap();
        let arr = expand_paths(&map_cbor_to_cddl(&bytes, schema, "inputs").unwrap());
        let snippets_at_root: Vec<String> = arr
            .iter()
            .filter(|e| e["cbor_path"] == json!("$") && e.get("cddl_byte_span").is_some())
            .map(|e| snippet(schema, e).to_string())
            .collect();
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
        assert_eq!(err.kind(), "missing_rule", "{}", err);
        assert!(err.message().contains("no_such"), "{}", err);
    }

    #[test]
    fn map_returns_error_for_invalid_cbor() {
        let err = map_cbor_to_cddl(&[0x18], "x = int", "x")
            .err()
            .expect("expected decode error");
        assert_eq!(err.kind(), "input_parse", "{}", err);
        assert!(err.message().to_lowercase().contains("cbor"), "{}", err);
    }

    #[test]
    fn map_returns_error_for_group_rule_as_root() {
        // Group rule roots rejected like decode_cbor_against_cddl.
        let bytes = hex::decode("820102").unwrap();
        let err = map_cbor_to_cddl(&bytes, "g = (a: uint, b: uint)", "g")
            .err()
            .expect("expected group-rule error");
        assert_eq!(err.kind(), "group_rule_root", "{}", err);
        assert!(err.message().contains("group rule"), "{}", err);
    }

    /// Follow the same type alternative as the decoder (`@entries` vs object).
    #[test]
    fn an_entries_shaped_map_is_attributed_to_the_alternative_that_fits() {
        // Array key: `alt_a` wants key `1`; `alt_b` accepts any.
        for cddl in [
            "root = alt_a / alt_b\nalt_a = { 1: uint }\nalt_b = { * any => any }\n",
            "root = alt_b / alt_a\nalt_a = { 1: uint }\nalt_b = { * any => any }\n",
        ] {
            let entries = run(cddl, "root", "a1810105");
            let named: Vec<&str> = entries
                .iter()
                .filter_map(|e| e["rule_name"].as_str())
                .collect();
            assert!(named.contains(&"alt_b"), "{:?} for {}", named, cddl);
            assert!(!named.contains(&"alt_a"), "{:?} for {}", named, cddl);
        }
    }

    #[test]
    fn map_emits_tag_row_for_unspecialised_tag() {
        let cddl = "set<a> = #6.258([* a])\nelems = set<uint>";
        let cbor_hex = "d9010281 01".replace(' ', "");
        let entries = run(cddl, "elems", &cbor_hex);
        let tag_row = entries
            .iter()
            .find(|e| {
                e["decoded_path"]
                    .as_str()
                    .is_some_and(|p| p.ends_with(r#"["@tag"]"#))
            })
            .unwrap_or_else(|| panic!("no @tag row in {:?}", entries));
        assert_eq!(tag_row["cbor_byte_span"]["offset"], json!(0));
        assert_eq!(tag_row["cbor_byte_span"]["length"], json!(3));
        assert!(snippet(cddl, tag_row).starts_with("#6."));
    }

    #[test]
    fn map_emits_positional_wrapper_for_mixed_named_array() {
        let cddl = "tx = [body: int, bool, int]";
        // [1, true, 2]
        let entries = run(cddl, "tx", "8301f502");
        let d = decoded_paths(&entries);
        assert!(
            d.iter().any(|x| x == r#"$["@positional"]"#),
            "no @positional wrapper in {:?}",
            d
        );
        // `@positional` index is dense emission order, not wire slot.
        assert!(
            d.iter().any(|x| x == r#"$["@positional"][0]"#),
            "no positional[0] in {:?}",
            d
        );
        assert!(
            d.iter().any(|x| x == r#"$["@positional"][1]"#),
            "no positional[1] in {:?}",
            d
        );
        assert!(
            !d.iter().any(|x| x == r#"$["@positional"][2]"#),
            "wire-numbered positional slot in {:?}",
            d
        );
        let wrapper = entries
            .iter()
            .find(|e| e["decoded_path"] == json!(r#"$["@positional"]"#))
            .unwrap();
        assert_eq!(wrapper["cbor_type"], json!("array_positional"));
        assert!(wrapper.get("cddl_byte_span").is_none());
    }

    #[test]
    fn overlong_unnamed_array_continues_the_same_index_space() {
        // Homogeneous leftovers stay in-array (no `@extra`).
        let cddl = "pair = [int, int]";
        let entries = run(cddl, "pair", "83010203");
        let d = decoded_paths(&entries);
        assert!(d.iter().any(|x| x == "$[2]"), "no $[2] in {:?}", d);
        assert!(
            !d.iter().any(|x| x.contains("@extra")),
            "unexpected @extra in {:?}",
            d
        );
    }

    #[test]
    fn overlong_named_array_buckets_leftovers_into_extra() {
        // Named slots → object; leftovers under `@extra`.
        let cddl = "rec = [a: int, b: int]";
        let entries = run(cddl, "rec", "83010203");
        let d = decoded_paths(&entries);
        assert!(
            d.iter().any(|x| x == r#"$["@extra"]"#),
            "no @extra wrapper in {:?}",
            d
        );
        assert!(
            d.iter().any(|x| x == r#"$["@extra"][0]"#),
            "no @extra[0] in {:?}",
            d
        );
        let wrapper = entries
            .iter()
            .find(|e| e["decoded_path"] == json!(r#"$["@extra"]"#))
            .unwrap();
        assert_eq!(wrapper["cbor_type"], json!("array_extra"));
        assert_eq!(wrapper["cbor_byte_span"]["offset"], json!(3));
    }

    #[test]
    fn map_emits_entries_form_for_complex_keyed_map() {
        let cddl = "m = { * any => uint }";
        let entries = run(cddl, "m", "a181 011864".replace(' ', "").as_str());
        let d = decoded_paths(&entries);
        for expected in [
            r#"$["@entries"]"#,
            r#"$["@entries"][0]"#,
            r#"$["@entries"][0].key"#,
            r#"$["@entries"][0].value"#,
        ] {
            assert!(
                d.iter().any(|x| x == expected),
                "no {} in {:?}",
                expected,
                d
            );
        }
    }

    #[test]
    fn map_emits_entries_form_for_duplicate_keys() {
        let cddl = "m = { * tstr => uint }";
        let entries = run(cddl, "m", "a261610161610 2".replace(' ', "").as_str());
        let d = decoded_paths(&entries);
        assert!(d.iter().any(|x| x == r#"$["@entries"]"#));
        assert!(d.iter().any(|x| x == r#"$["@entries"][0]"#), "{:?}", d);
        assert!(d.iter().any(|x| x == r#"$["@entries"][1]"#), "{:?}", d);
    }

    #[test]
    fn map_emits_extra_wrapper_for_unmatched_object_form_keys() {
        let cddl = "m = { a: uint }";
        let entries = run(cddl, "m", "a261610161620 2".replace(' ', "").as_str());
        let d = decoded_paths(&entries);
        assert!(
            d.iter().any(|x| x == r#"$["@extra"]"#),
            "no @extra wrapper in {:?}",
            d
        );
        assert!(
            d.iter().any(|x| x == r#"$["@extra"].b"#),
            "no @extra.b leaf in {:?}",
            d
        );
    }

    /// Source text of every row `cddl_byte_span`.
    fn snippets_at<'s>(cddl: &'s str, entries: &[Value], decoded_path: &str) -> Vec<&'s str> {
        entries
            .iter()
            .filter(|e| e["decoded_path"] == json!(decoded_path))
            .filter(|e| e.get("cddl_byte_span").is_some())
            .map(|e| snippet(cddl, e))
            .collect()
    }

    fn rule_names(entries: &[Value]) -> Vec<&str> {
        entries
            .iter()
            .filter_map(|e| e.get("rule_name").and_then(Value::as_str))
            .collect()
    }

    fn has_decoded(entries: &[Value], decoded_path: &str) -> bool {
        entries
            .iter()
            .any(|e| e["decoded_path"] == json!(decoded_path))
    }

    #[test]
    fn type_choice_takes_the_alternative_the_data_fits() {
        let cddl = "root = alt_a / alt_b\nalt_a = tstr\nalt_b = [x: uint, y: uint]";
        // Array fails `alt_a` → must take `alt_b`.
        let entries = run(cddl, "root", "820102");
        assert!(rule_names(&entries).contains(&"alt_b"), "{:?}", entries);
        assert!(!rule_names(&entries).contains(&"alt_a"));
        assert!(
            has_decoded(&entries, "$.x"),
            "{:?}",
            decoded_paths(&entries)
        );
        assert!(has_decoded(&entries, "$.y"));

        // First fitting alternative wins.
        let entries = run(cddl, "root", "6161");
        assert!(rule_names(&entries).contains(&"alt_a"), "{:?}", entries);
        assert!(!rule_names(&entries).contains(&"alt_b"));
    }

    #[test]
    fn parenthesized_alternative_does_not_swallow_the_later_choices() {
        let cddl = "x = (tstr) / [uint, uint]";
        let entries = run(cddl, "x", "820102");
        assert!(
            snippets_at(cddl, &entries, "$").contains(&"[uint, uint]"),
            "{:?}",
            snippets_at(cddl, &entries, "$")
        );
        let entries = run(cddl, "x", "6161");
        assert!(snippets_at(cddl, &entries, "$").contains(&"tstr"));
    }

    #[test]
    fn array_group_choice_matches_the_alternative_the_data_fits() {
        let cddl = crate::cbor::test_fixtures::ledger_cddl();
        let credential = "8200581c".to_string() + &"ab".repeat(28);
        // `[3, credential, credential, amount]` is the last `//` alt —
        // must not highlight the first. Its two `credential` slots stay
        // positional; only `amount` labels.
        let transfer = format!("8403{0}{0}1864", credential);
        let entries = run(cddl, "certificate", &transfer);
        assert!(
            has_decoded(&entries, "$.amount"),
            "{:?}",
            decoded_paths(&entries)
        );
        assert!(!has_decoded(&entries, "$.credential"));
        assert_eq!(
            snippets_at(cddl, &entries, r#"$["@positional"][0]"#),
            vec!["3"]
        );

        // First alt still wins when data fits.
        let registration = format!("8200{}", credential);
        let entries = run(cddl, "certificate", &registration);
        assert!(
            has_decoded(&entries, "$.credential"),
            "{:?}",
            decoded_paths(&entries)
        );
        assert!(!has_decoded(&entries, "$.amount"));
        assert_eq!(
            snippets_at(cddl, &entries, r#"$["@positional"][0]"#),
            vec!["0"]
        );
    }

    #[test]
    fn group_rule_referenced_from_an_array_is_expanded_into_its_entries() {
        let cddl = "t = [g, tstr]\ng = (a: uint, b: uint)";
        let entries = run(cddl, "t", "8301026161");
        assert!(
            has_decoded(&entries, "$.a"),
            "{:?}",
            decoded_paths(&entries)
        );
        assert!(has_decoded(&entries, "$.b"));
        assert!(has_decoded(&entries, r#"$["@positional"][0]"#));
    }

    #[test]
    fn tagged_data_compares_the_tag_number() {
        let cddl = "x = #6.121([* uint]) / #6.999([* uint])";
        // Tag 999 belongs to the second alternative.
        let entries = run(cddl, "x", "d903e78101");
        let at_root = snippets_at(cddl, &entries, "$");
        assert!(
            at_root.iter().any(|s| s.starts_with("#6.999")),
            "{:?}",
            at_root
        );
        assert!(
            !at_root.iter().any(|s| s.starts_with("#6.121")),
            "{:?}",
            at_root
        );

        // …and tag 121 belongs to the first.
        let entries = run(cddl, "x", "d8798101");
        let at_root = snippets_at(cddl, &entries, "$");
        assert!(
            at_root.iter().any(|s| s.starts_with("#6.121")),
            "{:?}",
            at_root
        );
        assert!(
            !at_root.iter().any(|s| s.starts_with("#6.999")),
            "{:?}",
            at_root
        );
    }

    #[test]
    fn a_tag_no_alternative_declares_is_not_attributed_to_one() {
        let cddl = crate::cbor::test_fixtures::ledger_cddl();
        // Tag 258 is outside `constr`'s declared set.
        let entries = run(cddl, "datum", "d901028101");
        assert!(
            !rule_names(&entries).contains(&"constr"),
            "{:?}",
            rule_names(&entries)
        );
        for s in snippets_at(cddl, &entries, "$") {
            assert!(!s.starts_with("#6."), "attributed to a tag form: {:?}", s);
        }
        // Declared tag gets a CDDL span.
        let entries = run(cddl, "datum", "d87980");
        assert!(
            rule_names(&entries).contains(&"constr"),
            "{:?}",
            rule_names(&entries)
        );
    }

    #[test]
    fn a_specialised_bignum_tag_gets_no_wrapper_rows() {
        // Narrow bignum renders as a scalar (no wrapper).
        let entries = run("x = #6.2(bstr)", "x", "c243010203");
        assert!(
            !decoded_paths(&entries).iter().any(|p| p.contains("@tag")),
            "{:?}",
            decoded_paths(&entries)
        );
        // Wide bignum keeps `{@tag, @value}`.
        let entries = run(
            "x = #6.2(bstr)",
            "x",
            "c2510102030405060708091011121314151617",
        );
        assert!(
            decoded_paths(&entries).iter().any(|p| p == r#"$["@tag"]"#),
            "{:?}",
            decoded_paths(&entries)
        );
    }

    #[test]
    fn type_keyed_map_member_claims_the_entries_it_accepts() {
        let cddl = "m = { * tstr => uint }";
        let entries = run(cddl, "m", "a2616101616202");
        let key_rows: Vec<&Value> = entries
            .iter()
            .filter(|e| e["entry_role"] == json!("key"))
            .collect();
        assert_eq!(key_rows.len(), 2, "{:?}", entries);
        for row in &key_rows {
            assert_eq!(snippet(cddl, row), "tstr");
            assert_eq!(row["match_via"], json!("type"));
        }
        assert!(has_decoded(&entries, "$.a"));
        assert!(has_decoded(&entries, "$.b"));
        assert!(
            !decoded_paths(&entries).iter().any(|p| p.contains("@extra")),
            "{:?}",
            decoded_paths(&entries)
        );

        // Unsatisfiable key type → entries in `@extra`.
        let entries = run("m = { * uint => uint }", "m", "a2616101616202");
        assert!(
            decoded_paths(&entries)
                .iter()
                .any(|p| p == r#"$["@extra"].a"#),
            "{:?}",
            decoded_paths(&entries)
        );
    }

    #[test]
    fn ledger_stock_keys_resolve_to_their_declaration() {
        let cddl = crate::cbor::test_fixtures::ledger_cddl();
        let bucket = "581c".to_string() + &"ab".repeat(28);
        let entries = run(cddl, "stock", &format!("a1{}a14301020301", bucket));
        let key_snippets: Vec<&str> = entries
            .iter()
            .filter(|e| e["entry_role"] == json!("key"))
            .map(|e| snippet(cddl, e))
            .collect();
        assert!(key_snippets.contains(&"bucket"), "{:?}", key_snippets);
        assert!(key_snippets.contains(&"label"), "{:?}", key_snippets);
        assert!(
            !decoded_paths(&entries).iter().any(|p| p.contains("@extra")),
            "{:?}",
            decoded_paths(&entries)
        );
    }

    #[test]
    fn an_unmatched_entries_pair_carries_no_schema_location() {
        // Complex key → `@entries`; `{0: uint}` claims nothing.
        let entries = run("m = { 0: uint }", "m", "a181011864");
        for path in [
            r#"$["@entries"][0]"#,
            r#"$["@entries"][0].key"#,
            r#"$["@entries"][0].value"#,
        ] {
            let row = entries
                .iter()
                .find(|e| e["decoded_path"] == json!(path))
                .unwrap_or_else(|| panic!("no row at {} in {:?}", path, decoded_paths(&entries)));
            assert!(
                row.get("cddl_byte_span").is_none(),
                "unmatched pair points at a declaration: {}",
                row
            );
        }
        assert_eq!(
            entries
                .iter()
                .find(|e| e["decoded_path"] == json!(r#"$["@entries"][0]"#))
                .unwrap()["match_via"],
            json!("unmatched")
        );

        // Matching member still supplies the CDDL span.
        let cddl = "m = { * any => uint }";
        let entries = run(cddl, "m", "a181011864");
        let pair = entries
            .iter()
            .find(|e| e["decoded_path"] == json!(r#"$["@entries"][0]"#))
            .unwrap();
        assert_eq!(pair["match_via"], json!("type"));
        assert_eq!(snippet(cddl, pair), "any");
    }

    #[test]
    fn a_declared_member_the_data_omits_gets_a_row_with_no_cbor_span() {
        let cddl = "m = { a: uint, b: uint }";
        let entries = run(cddl, "m", "a1616101");
        let absent = entries
            .iter()
            .find(|e| e["decoded_path"] == json!("$.b"))
            .unwrap_or_else(|| {
                panic!(
                    "no row for the absent member in {:?}",
                    decoded_paths(&entries)
                )
            });
        assert_eq!(snippet(cddl, absent), "b");
        assert!(
            absent.get("cbor_byte_span").is_none() && absent.get("cbor_anchor_span").is_none(),
            "absent member claims bytes: {}",
            absent
        );
        // Present optional member keeps its bytes.
        let present = entries
            .iter()
            .find(|e| e["decoded_path"] == json!("$.a") && e["entry_role"] == json!("key"))
            .unwrap();
        assert!(present.get("cbor_byte_span").is_some());
    }

    #[test]
    fn an_optional_array_slot_the_data_does_not_fill_is_skipped() {
        let cddl = "t = [? uint, tstr]";
        // Lone tstr fills the text slot, not optional uint.
        let entries = run(cddl, "t", "816178");
        assert_eq!(snippets_at(cddl, &entries, "$[0]"), vec!["tstr"]);
        // Both slots filled when optional uint is present.
        let entries = run(cddl, "t", "8201 6178".replace(' ', "").as_str());
        assert_eq!(snippets_at(cddl, &entries, "$[0]"), vec!["uint"]);
        assert_eq!(snippets_at(cddl, &entries, "$[1]"), vec!["tstr"]);
    }

    #[test]
    fn map_group_choice_takes_the_alternative_that_fits() {
        let cddl = "m = { 0: uint // 1: uint, 2: uint }";
        let entries = run(cddl, "m", "a201010202");
        assert!(
            has_decoded(&entries, r#"$["1"]"#),
            "{:?}",
            decoded_paths(&entries)
        );
        assert!(has_decoded(&entries, r#"$["2"]"#));
        assert!(!has_decoded(&entries, r#"$["0"]"#));
        // First alt wins when data fits.
        let entries = run(cddl, "m", "a1001864");
        assert!(
            has_decoded(&entries, r#"$["0"]"#),
            "{:?}",
            decoded_paths(&entries)
        );
        assert!(!has_decoded(&entries, r#"$["1"]"#));
    }

    #[test]
    fn a_non_repeating_member_claims_only_one_entry() {
        // Non-repeating uint member claims one entry; second is leftover.
        let cddl = "m = { 0: uint }";
        let entries = run(cddl, "m", "a2000101 02".replace(' ', "").as_str());
        assert!(
            has_decoded(&entries, r#"$["0"]"#),
            "{:?}",
            decoded_paths(&entries)
        );
        assert!(
            decoded_paths(&entries)
                .iter()
                .any(|p| p.starts_with(r#"$["@extra"]"#)),
            "{:?}",
            decoded_paths(&entries)
        );
    }

    #[test]
    fn embedded_cbor_payload_is_addressable() {
        let cddl = "outer = bstr .cbor inner\ninner = [a: uint, b: uint]";
        let entries = run(cddl, "outer", "43820102");
        assert!(
            has_decoded(&entries, "$.a"),
            "{:?}",
            decoded_paths(&entries)
        );
        assert!(has_decoded(&entries, "$.b"));
        // Embedded payload starts at offset 1.
        let a = entries
            .iter()
            .find(|e| e["decoded_path"] == json!("$.a"))
            .unwrap();
        assert_eq!(a["cbor_byte_span"]["offset"], json!(2));

        // Undescribed payload → only the byte string is addressable.
        let entries = run(cddl, "outer", "4161");
        assert!(
            !has_decoded(&entries, "$.a"),
            "{:?}",
            decoded_paths(&entries)
        );
    }

    #[test]
    fn a_repeating_named_array_slot_keeps_its_array_shape() {
        let cddl = "t = [* item: uint]";
        let entries = run(cddl, "t", "83010203");
        for path in ["$.item", "$.item[0]", "$.item[1]", "$.item[2]"] {
            assert!(
                has_decoded(&entries, path),
                "no {} in {:?}",
                path,
                decoded_paths(&entries)
            );
        }
        // Empty match still declares the field (no bytes).
        let entries = run(cddl, "t", "80");
        let field = entries
            .iter()
            .find(|e| e["decoded_path"] == json!("$.item"))
            .unwrap_or_else(|| panic!("no field row in {:?}", decoded_paths(&entries)));
        assert!(field.get("cbor_byte_span").is_none(), "{}", field);
    }

    #[test]
    fn prelude_typed_array_slots_report_their_real_source_position() {
        let cddl = "t = [int, int, int]";
        let entries = run(cddl, "t", "83010203");
        for row in &entries {
            let Some(span) = row.get("cddl_byte_span") else {
                continue;
            };
            assert!(
                span["length"].as_u64().unwrap() > 0 && span["line"].as_u64().unwrap() >= 1,
                "placeholder span emitted: {}",
                row
            );
        }
        assert_eq!(snippets_at(cddl, &entries, "$[1]"), vec!["int"]);
    }

    #[test]
    fn tighten_trims_trailing_trivia_and_keeps_interior_comments() {
        let source = "a = tstr ; trailing comment\n\nb = uint\n";
        // Pest span absorbs trailing trivia to next token.
        let (start, end) = tighten((4, 29, 1), source).unwrap();
        assert_eq!(&source[start..end], "tstr");

        // Interior comments stay inside the span.
        let source = "t = [ a: uint ; note\n    , b: uint ]\n";
        let (start, end) = tighten((4, source.len(), 1), source).unwrap();
        assert_eq!(&source[start..end], "[ a: uint ; note\n    , b: uint ]");

        // Comment-only span keeps its extent.
        let source = "; only a comment\n";
        let (start, end) = tighten((0, source.len(), 1), source).unwrap();
        assert!(end > start);

        // `;` inside a literal is not a comment.
        assert_eq!(trailing_comment_start("\"a;b\""), None);
        assert_eq!(trailing_comment_start("tstr ; c"), Some(5));
        assert_eq!(trailing_comment_start("tstr ; c\nuint"), None);
    }

    #[test]
    fn map_against_the_record_with_the_full_ledger_schema() {
        let cddl = crate::cbor::test_fixtures::ledger_cddl();
        let bytes = crate::cbor::test_fixtures::record_doc();
        let arr = expand_paths(&map_cbor_to_cddl(&bytes, cddl, "record").unwrap());
        let p = paths(&arr);
        assert!(p.iter().any(|x| x == "$"));
        // The root's named members.
        for member in ["$.body", "$.witness", "$.is_valid", "$.aux"] {
            assert!(p.iter().any(|x| x == member), "{}: {:?}", member, p);
        }
        // A reference inside the tag-258 set at body key 0, labelled by
        // the rule names of `ref = [hash32, index]`.
        assert!(p.iter().any(|x| x == "$.body[0][0].hash32"), "{:?}", p);
        assert!(p.iter().any(|x| x == "$.body[0][0].index"), "{:?}", p);
        // A signature inside the tag-258 set at witness key 0.
        assert!(
            p.iter().any(|x| x == "$.witness[0][0].public_key"),
            "{:?}",
            p
        );
    }

    // --- nesting limits ---

    fn nested_arrays_hex(levels: usize) -> String {
        let mut s = "81".repeat(levels);
        s.push_str("05");
        s
    }

    /// Flat `[* uint]` array of `items` bytes; row count = items + 2.
    fn flat_array(items: usize) -> Vec<u8> {
        let mut bytes = vec![0x9a];
        bytes.extend_from_slice(&(items as u32).to_be_bytes());
        bytes.extend(std::iter::repeat_n(0u8, items));
        bytes
    }

    /// Row count from mapping JSON text (no parse).
    fn rows_in(text: &str) -> usize {
        text.matches("{\"cbor_path\":").count()
    }

    /// Exactly `MAX_CBOR_POSITION_MAP_ROWS` succeeds; one more refuses naming the bound.
    #[test]
    fn a_map_of_more_rows_than_the_bound_is_refused_and_the_decode_is_not() {
        let bound = crate::cbor::limits::MAX_CBOR_POSITION_MAP_ROWS;
        let schema = "x = [* uint]";

        let at = flat_array(bound - 2);
        let text =
            map_cbor_to_cddl_text(&at, schema, "x").expect("a map of exactly the bound's rows");
        assert_eq!(rows_in(&text), bound);

        let past = flat_array(bound - 1);
        let err =
            map_cbor_to_cddl_text(&past, schema, "x").expect_err("a map one row past the bound");
        assert_eq!(err.kind(), "validation_too_complex", "{}", err);
        assert!(
            err.to_string()
                .contains(&format!("{} position-map rows", bound)),
            "the refusal must name the bound: {}",
            err
        );

        let decoded = sm::decode_cbor_against_cddl(&past, schema, "x").expect("the decode answers");
        assert_eq!(decoded.as_array().map(Vec::len), Some(bound - 1));
    }

    /// Row bound checked from bytes before decode (≈1 row per item).
    #[test]
    fn a_document_with_more_items_than_the_row_bound_is_refused_before_it_is_decoded() {
        let bound = crate::cbor::limits::MAX_CBOR_POSITION_MAP_ROWS;
        // Truncated array: declared size > bound, bytes only cover bound.
        let mut bytes = vec![0x9a];
        bytes.extend_from_slice(&((bound + 1) as u32).to_be_bytes());
        bytes.extend(std::iter::repeat_n(0u8, bound));
        let err = map_cbor_to_cddl_text(&bytes, "x = [* uint]", "x")
            .expect_err("a document past the bound");
        assert_eq!(err.kind(), "validation_too_complex", "{}", err);
        assert!(
            err.to_string()
                .contains(&format!("{} position-map rows", bound)),
            "{}",
            err
        );
        let fault = sm::decode_cbor_against_cddl(&bytes, "x = [* uint]", "x")
            .expect_err("the decode faults on the truncation");
        assert_eq!(fault.kind(), "input_parse", "{}", fault);
    }

    /// Refusal leaves `out` unchanged (no partial JSON).
    #[test]
    fn a_refused_map_leaves_the_text_as_it_was() {
        let bound = crate::cbor::limits::MAX_CBOR_POSITION_MAP_ROWS;
        let mut text = String::from("prefix");
        let err = map_cbor_to_cddl_into(&mut text, &flat_array(bound - 1), "x = [* uint]", "x")
            .expect_err("a map past the bound");
        assert_eq!(err.kind(), "validation_too_complex");
        assert_eq!(text, "prefix");

        map_cbor_to_cddl_into(&mut text, &[0x81, 0x05], "x = [* uint]", "x").expect("a map");
        assert!(text.starts_with("prefix{\"entries\":["), "{}", text);
        assert!(text.ends_with('}'), "{}", text);
    }

    /// Pure alias cycles never shrink input — must still terminate.
    #[test]
    fn cyclic_rules_do_not_recurse_forever() {
        for schema in ["a = b\nb = a", "a = a", "a = ~a", "a = (a)", "a = a / int"] {
            let bytes = hex::decode("05").unwrap();
            let out = map_cbor_to_cddl(&bytes, schema, "a");
            assert!(
                out.is_ok(),
                "cyclic schema {:?} did not return: {:?}",
                schema,
                out.err().map(|e| e.to_string())
            );
        }
    }

    /// Fresh generic args each hop defeat a (rule, args) visited set.
    #[test]
    fn growing_generic_arguments_do_not_recurse_forever() {
        let bytes = hex::decode("05").unwrap();
        let out = map_cbor_to_cddl(&bytes, "a<t> = a<[t]>\nb = a<int>", "b");
        assert!(
            out.is_ok(),
            "growing generic did not return: {:?}",
            out.err().map(|e| e.to_string())
        );
    }

    /// Data-consuming recursion must still walk to the bottom.
    #[test]
    fn productive_recursion_still_walks_to_the_bottom() {
        let levels = 30;
        let entries = run("x = [* x] / uint", "x", &nested_arrays_hex(levels));
        let deepest = "$".to_string() + &"[0]".repeat(levels);
        let p = paths(&entries);
        assert!(p.contains(&deepest), "no row for the deepest item: {:?}", p);
    }

    /// Nesting refusal message must name the bound.
    fn refusal_naming_the_budget(result: Result<Value, sm::WalkError>) -> String {
        let err = result.err().expect("expected a refusal");
        assert_eq!(err.kind(), "nesting_too_deep", "{}", err);
        let message = err.to_string();
        assert!(
            message.contains(&crate::cbor::limits::MAX_CBOR_MAPPING_DESCENT_COST.to_string()),
            "the refusal must name the bound: {}",
            message
        );
        message
    }

    /// Walk past `bound` refuses naming it.
    fn refusal_naming(result: Result<Value, sm::WalkError>, bound: &str) -> String {
        let err = result.expect_err("expected a refusal");
        assert_eq!(err.kind(), "nesting_too_deep", "{}", err);
        let message = err.to_string();
        assert!(
            message.contains(bound),
            "the refusal must name the bound: {}",
            message
        );
        message
    }

    /// Nesting shapes: schema + `d`-deep doc + decoded-path step for each construct.
    struct BoundaryShape {
        name: &'static str,
        schema: &'static str,
        hex_at: fn(usize) -> String,
        step: fn(&str) -> String,
        /// Extra nesting beyond the construct chain (e.g. `@entries` key array).
        extra: usize,
    }

    /// `hops` aliases `r0`…`x` so naming `r0` resolves that many references.
    fn alias_chain(hops: usize) -> String {
        assert!(hops >= 2, "the chain is at least `r0 = x`");
        let mut chain = String::new();
        for alias in 0..hops - 2 {
            chain.push_str(&format!("r{} = r{}\n", alias, alias + 1));
        }
        chain.push_str(&format!("r{} = x\n", hops - 2));
        chain
    }

    /// Nested constructs: array (ref/type), map (object/`@entries`), tag payload.
    fn boundary_shapes() -> Vec<BoundaryShape> {
        vec![
            BoundaryShape {
                name: "array item by rule name",
                schema: "x = [* x] / uint",
                hex_at: |d| "81".repeat(d) + "05",
                step: |p| format!("{}[0]", p),
                extra: 0,
            },
            BoundaryShape {
                name: "array item by member type",
                schema: "x = [* x / uint]",
                hex_at: |d| "81".repeat(d) + "05",
                step: |p| format!("{}[0]", p),
                extra: 0,
            },
            BoundaryShape {
                name: "map value in object form",
                schema: "x = {* uint => x} / uint",
                hex_at: |d| "a100".repeat(d) + "05",
                step: |p| extend_decoded_path(p, "0"),
                extra: 0,
            },
            BoundaryShape {
                name: "map value in entries form",
                schema: "x = {* [uint] => x} / uint",
                hex_at: |d| "a18100".repeat(d) + "05",
                step: |p| extend_decoded_path(&format!(r#"{}["@entries"][0]"#, p), "value"),
                extra: 1,
            },
            BoundaryShape {
                name: "tag payload",
                schema: "x = #6.1(x) / uint",
                hex_at: |d| "c1".repeat(d) + "05",
                step: |p| format!(r#"{}["@value"]"#, p),
                extra: 0,
            },
        ]
    }

    /// Deepest allowed nesting emits a deepest-item row; one more refuses.
    #[test]
    fn map_walks_every_construct_to_the_level_bound_and_refuses_the_next() {
        let bound = crate::cbor::limits::MAX_CBOR_NESTING_DEPTH;
        for BoundaryShape {
            name,
            schema,
            hex_at,
            step,
            extra,
        } in boundary_shapes()
        {
            let deepest = bound - extra;
            let bytes = hex::decode(hex_at(deepest)).unwrap();
            let mapping = DeepJson::new(
                map_cbor_to_cddl(&bytes, schema, "x").unwrap_or_else(|e| panic!("{}: {}", name, e)),
            );
            let deepest_path = (0..deepest).fold("$".to_string(), |path, _| step(&path));
            assert!(
                has_path(&mapping, "decoded_paths", &deepest_path),
                "{}: no row for the deepest item",
                name
            );

            let bytes = hex::decode(hex_at(deepest + 1)).unwrap();
            refusal_naming(
                map_cbor_to_cddl(&bytes, schema, "x"),
                &crate::cbor::limits::nesting_depth_message(bound),
            );
        }
    }

    /// Raw fall-through levels count toward the nesting bound too.
    #[test]
    fn a_raw_subtree_below_a_labelled_walk_counts_toward_the_level_bound() {
        let bound = crate::cbor::limits::MAX_CBOR_NESTING_DEPTH;
        // Map under labelled arrays is leftover → emitted raw.
        let schema = "x = [* x] / uint";
        let raw = 300;
        let document = |arrays: usize| {
            let mut hex_bytes = "81".repeat(arrays);
            hex_bytes.push_str(&"a100".repeat(raw));
            hex_bytes.push_str("05");
            hex::decode(hex_bytes).unwrap()
        };
        let labelled = bound - raw;
        let mapping = DeepJson::new(
            map_cbor_to_cddl(&document(labelled), schema, "x").expect("expected a mapping"),
        );
        let bottom = (0..raw).fold("$".to_string() + &"[0]".repeat(labelled), |path, _| {
            extend_decoded_path(&path, "0")
        });
        assert!(
            has_path(&mapping, "decoded_paths", &bottom),
            "no row for the bottom of the raw chain"
        );
        refusal_naming(
            map_cbor_to_cddl(&document(labelled + 1), schema, "x"),
            &crate::cbor::limits::nesting_depth_message(bound),
        );
    }

    /// `hops` aliases per level plus a named slot (labelled vs raw).
    fn named_alias_schema(hops: usize) -> String {
        format!("x = [a: r0] / uint\n{}", alias_chain(hops))
    }

    /// Alias chains spend descent budget; over budget refuses (no silent raw).
    #[test]
    fn a_chain_of_rule_references_spends_the_descent_budget_and_is_refused_as_a_limit() {
        let hops = crate::cbor::limits::MAX_CBOR_MAPPING_RULE_NESTING;
        let schema = named_alias_schema(hops);
        let weights = crate::cbor::limits::SCHEMA_WALKER_DESCENT;
        let per_level = weights.level + hops * weights.rule_hop;
        let deepest = crate::cbor::limits::MAX_CBOR_MAPPING_DESCENT_COST / per_level;
        assert!(
            deepest > 256 && deepest < crate::cbor::limits::MAX_CBOR_NESTING_DEPTH / 8,
            "the budget answers for this chain well inside the level bound: {}",
            deepest
        );

        let bytes = hex::decode(nested_arrays_hex(deepest)).unwrap();
        let mapping =
            DeepJson::new(map_cbor_to_cddl(&bytes, &schema, "x").expect("expected a mapping"));
        let labelled =
            (0..deepest).fold("$".to_string(), |path, _| extend_decoded_path(&path, "a"));
        assert!(
            has_path(&mapping, "decoded_paths", &labelled),
            "the deepest level is not labelled"
        );
        // Aliases `r0`…`r{hops-2}` then `x`.
        let last_alias = format!("r{}", hops - 2);
        let lengths = path_lengths(&mapping, "decoded_paths");
        let stacked = mapping["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .filter(|e| e["rule_name"] == Value::String(last_alias.clone()))
            .filter(|e| {
                e["decoded_path"]
                    .as_u64()
                    .is_some_and(|i| lengths[i as usize] == labelled.len())
            })
            .count();
        assert_eq!(stacked, 1, "the deepest level lost its stacked rule rows");

        let bytes = hex::decode(nested_arrays_hex(deepest + 1)).unwrap();
        refusal_naming_the_budget(map_cbor_to_cddl(&bytes, &schema, "x"));
    }

    /// Definite-length byte string wrapping `payload`.
    fn bstr_hex(payload: &str) -> String {
        format!("59{:04x}{}", payload.len() / 2, payload)
    }

    // --- path table ---

    /// Path table as consumer-facing JSON.
    fn table_json(table: &PathTable) -> Value {
        let mut text = String::new();
        table.write_json(&mut text);
        serde_json::from_str(&text).expect("a path table is JSON")
    }

    #[test]
    fn the_path_table_stores_each_path_as_a_prefix_and_what_it_adds() {
        let mut table = PathTable::new("$");
        assert_eq!(table.intern(), 0);
        let item = table.enter("[0]");
        assert_eq!(table.intern(), 1);
        table.enter(".name");
        assert_eq!(table.intern(), 2);
        // Sibling share: keep common prefix.
        table.leave(item);
        table.enter("[1]");
        assert_eq!(table.intern(), 3);

        assert_eq!(
            table.rows,
            vec![
                (None, "$".to_string()),
                (Some(0), "[0]".to_string()),
                (Some(1), ".name".to_string()),
                (Some(0), "[1]".to_string()),
            ]
        );
    }

    /// Same path interned twice in a row reuses the open entry.
    #[test]
    fn the_path_table_reuses_the_entry_it_is_already_at() {
        let mut table = PathTable::new("$");
        let root = table.intern();
        assert_eq!(table.intern(), root);
        table.enter("[0]");
        let child = table.intern();
        assert_eq!(table.intern(), child);
        assert_eq!(table.rows.len(), 2);
    }

    /// Prefix share only via open entries; closed siblings do not become prefixes.
    #[test]
    fn a_path_is_stored_off_the_entry_it_extends_and_not_off_a_closed_sibling() {
        let mut table = PathTable::new("$");
        table.intern();
        let item = table.enter("[1]");
        table.intern();
        let field = table.enter(".name");
        let name = table.intern();
        table.leave(field);
        table.enter(".nameplate");
        let nameplate = table.intern();
        assert_eq!(table.rows[name], (Some(1), ".name".to_string()));
        assert_eq!(table.rows[nameplate], (Some(1), ".nameplate".to_string()));

        table.leave(item);
        table.enter("[2]");
        let sibling = table.intern();
        assert_eq!(table.rows[sibling], (Some(0), "[2]".to_string()));
    }

    /// Interned indices resolve to the paths that were requested.
    #[test]
    fn every_interned_path_reconstructs_to_what_was_interned() {
        let mut table = PathTable::new("$");
        let mut interned: Vec<(String, usize)> = Vec::new();
        let mut intern = |table: &mut PathTable| {
            let index = table.intern();
            interned.push((table.path.clone(), index));
        };

        intern(&mut table);
        let first = table.enter("[0]");
        intern(&mut table);
        let inner = table.enter("[0]");
        intern(&mut table);
        table.leave(inner);
        table.enter("[1]");
        intern(&mut table);
        table.leave(inner);
        intern(&mut table);
        table.leave(first);
        let second = table.enter("[1]");
        let name = table.enter(".name");
        intern(&mut table);
        table.leave(name);
        // Lexical extension of a closed sibling is not a prefix share.
        table.enter(".nameplate");
        intern(&mut table);
        table.leave(second);
        intern(&mut table);
        table.enter("[0]");
        table.enter("[0]");
        intern(&mut table);

        let mapping = json!({ "paths": table_json(&table) });
        let resolved = resolve_path_table(&mapping, "paths");
        // Nine paths; two re-interned while still open.
        assert_eq!(interned.len(), 9);
        assert_eq!(resolved.len(), 7);
        for (path, index) in interned {
            assert_eq!(resolved[index], path);
        }
    }

    /// Intern cost is one segment, independent of depth.
    #[test]
    fn interning_a_path_copies_only_the_segment_it_adds() {
        let mut table = PathTable::new("$");
        table.intern();
        for _ in 0..10_000 {
            table.enter("[0]");
            table.intern();
        }
        let stored: usize = table.rows.iter().map(|(_, suffix)| suffix.len()).sum();
        assert_eq!(stored, 1 + 3 * 10_000);
        assert_eq!(table.open.len(), 10_001);
    }

    /// Path tables keep output ~O(nodes), not O(nodes×depth).
    #[test]
    fn the_emitted_size_grows_with_the_nodes_and_not_with_nodes_times_depth() {
        let size_at = |levels: usize| {
            let bytes = hex::decode(nested_arrays_hex(levels)).unwrap();
            let out = DeepJson::new(
                map_cbor_to_cddl(&bytes, "x = [* x] / uint", "x").expect("expected a mapping"),
            );
            // Deepest row present ⇒ smaller size is compression, not truncation.
            let deepest = "$".to_string() + &"[0]".repeat(levels);
            assert!(
                has_path(&out, "decoded_paths", &deepest),
                "no row for the deepest item at {} levels",
                levels
            );
            crate::deep_json::write_json(&out).len()
        };

        let shallow_levels = 2000;
        let shallow = size_at(shallow_levels);
        let deep = size_at(shallow_levels * 2);
        assert!(
            deep * 2 < shallow * 5,
            "doubling the nesting more than doubled the output: \
             {} chars at {} levels, {} at {}",
            shallow,
            shallow_levels,
            deep,
            shallow_levels * 2
        );
    }

    const EMBEDDED_SCHEMA: &str = "a0 = [* a0] / (bstr .cbor a1)\na1 = [* a1] / uint";

    /// `outer` nested arrays around bytes of `inner` nested arrays around `5`.
    fn embedded_arrays_hex(outer: usize, inner: usize) -> String {
        let mut hex_bytes = "81".repeat(outer);
        hex_bytes.push_str(&bstr_hex(&nested_arrays_hex(inner)));
        hex_bytes
    }

    /// Shared nesting budget for document + embedded payload.
    #[test]
    fn a_payload_filling_what_the_document_left_is_still_walked_to_the_bottom() {
        let bound = crate::cbor::limits::MAX_CBOR_NESTING_DEPTH;
        let outer = 16;
        let bytes = hex::decode(embedded_arrays_hex(outer, bound - outer)).unwrap();
        let mapping = DeepJson::new(
            map_cbor_to_cddl(&bytes, EMBEDDED_SCHEMA, "a0").expect("expected a mapping"),
        );
        let deepest = "$".to_string() + &"[0]".repeat(bound);
        assert!(
            has_path(&mapping, "decoded_paths", &deepest),
            "no row for the deepest item"
        );

        let bytes = hex::decode(embedded_arrays_hex(outer, bound - outer + 1)).unwrap();
        refusal_naming(
            map_cbor_to_cddl(&bytes, EMBEDDED_SCHEMA, "a0"),
            &crate::cbor::limits::nesting_depth_message(bound),
        );
    }

    /// Payload past leftover budget refuses before walk (shared budget).
    #[test]
    fn a_payload_one_level_past_what_the_document_left_is_refused_naming_the_level_bound() {
        crate::cbor::test_fixtures::on_large_stack(|| {
            let limit = crate::cbor::limits::MAX_CBOR_NESTING_DEPTH;
            let outer = 8;
            let mut hex_bytes = "81".repeat(outer);
            hex_bytes.push_str(&bstr_hex(&nested_arrays_hex(limit - outer + 1)));
            let bytes = hex::decode(hex_bytes).unwrap();
            let err =
                map_cbor_to_cddl(&bytes, EMBEDDED_SCHEMA, "a0").expect_err("expected a refusal");
            assert_eq!(err.kind(), "nesting_too_deep", "{}", err);
            let message = err.to_string();
            assert!(
                message.contains(&crate::cbor::limits::nesting_depth_message(limit)),
                "the refusal must name the bound: {}",
                message
            );
        });
    }

    /// Chain of `hops` generics forwarding one parameter.
    fn generic_chain_schema(head: &str, hops: usize) -> String {
        let mut schema = format!("{}\n", head);
        for hop in 0..hops - 1 {
            schema.push_str(&format!("b{}<t> = b{}<t>\n", hop, hop + 1));
        }
        schema.push_str(&format!("b{}<t> = t\n", hops - 1));
        schema
    }

    /// Generic args resolve through the chain; each hop gets a row.
    #[test]
    fn a_generic_argument_passed_on_is_read_where_it_was_written() {
        for hops in [1, 2, 3, 8] {
            let leaf = generic_chain_schema("x = b0<uint>", hops);
            let entries = run(&leaf, "x", "05");
            // One row per resolved reference at the root.
            assert!(!entries.is_empty(), "{} hops", hops);
            assert!(
                paths(&entries).iter().all(|p| p == "$"),
                "{} hops: {:?}",
                hops,
                paths(&entries)
            );

            let nested = generic_chain_schema("x = [* b0<x>] / uint", hops);
            let entries = run(&nested, "x", "818105");
            assert!(
                paths(&entries).contains(&"$[0][0]".to_string()),
                "{} hops: {:?}",
                hops,
                paths(&entries)
            );
        }

        let schema = "x = a<uint>\na<t> = b<[t]>\nb<t> = t\n";
        assert!(paths(&run(schema, "x", "8105")).contains(&"$[0]".to_string()));
    }

    /// Rule-hop chains are length-bounded; at bound succeeds, past refuses.
    #[test]
    fn a_chain_of_rule_references_past_the_bound_is_refused_naming_it() {
        let bound = crate::cbor::limits::MAX_CBOR_MAPPING_RULE_NESTING;
        let bytes = hex::decode(nested_arrays_hex(3)).unwrap();
        for (admitted, refused) in [
            (named_alias_schema(bound), named_alias_schema(bound + 1)),
            (
                generic_chain_schema("x = [a: b0<x>] / uint", bound - 1),
                generic_chain_schema("x = [a: b0<x>] / uint", bound),
            ),
        ] {
            let entries = expand_paths(
                &map_cbor_to_cddl(&bytes, &admitted, "x")
                    .expect("a chain at the bound is answered"),
            );
            assert!(decoded_paths(&entries).contains(&"$.a.a.a".to_string()));
            refusal_naming(
                map_cbor_to_cddl(&bytes, &refused, "x"),
                &crate::cbor::limits::rule_nesting_message(bound),
            );
        }
    }

    #[test]
    fn map_rejects_cbor_nested_past_the_limit() {
        crate::cbor::test_fixtures::on_large_stack(|| {
            for levels in [
                crate::cbor::limits::MAX_CBOR_NESTING_DEPTH + 1,
                2 * crate::cbor::limits::MAX_CBOR_NESTING_DEPTH,
            ] {
                let bytes = hex::decode(nested_arrays_hex(levels)).unwrap();
                let err = map_cbor_to_cddl(&bytes, "x = [* x] / uint", "x")
                    .err()
                    .unwrap_or_else(|| panic!("{} levels was not rejected", levels));
                assert_eq!(err.kind(), "nesting_too_deep", "{}", err);
                assert!(
                    err.message().contains("nesting"),
                    "unexpected message: {}",
                    err
                );
            }
        });
    }
}

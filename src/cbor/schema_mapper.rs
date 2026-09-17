//! Label decoded CBOR with CDDL names: bareword keys and unique rule
//! refs become fields; numeric keys stay numeric (CDDL has no name for
//! `0:` beyond the literal).
//!
//! Unlike validation (which checks), this walk *labels*. Strict pass
//! first (full fit); if none survive, lenient (`@extra` / nulls); else
//! raw — never drop data. Recursion is heap tasks via
//! [`super::walk_driver`]; decisions go in a [`Trace`] for replay.
//! Bounds: [`super::limits`]. Untested controls (`.regexp` / `.pcre` /
//! `.bits` / `.abnf`) accept on the target type alone.

use std::cell::{Cell, RefCell};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::fmt;
use std::future::Future;
use std::mem;
use std::rc::Rc;

use cddl::ast::{
    GenericArgs, GenericParams, Group, GroupChoice, GroupEntry, MemberKey, Occur, Occurrence,
    OptionalComma, RangeCtlOp, Rule, Span, Type, Type1, Type2, TypeGroupnameEntry, TypeRule, CDDL,
};
use cddl::token::{ControlOperator, TagConstraint};
use cddl::validator::cbor_value::{decode_cbor, Value as CborValue};
use ciborium::value::Integer;
use serde_json::{json, Map, Number, Value};

use crate::cbor::decoder;
use crate::cbor::document_cache;
use crate::cbor::limits;
use crate::cbor::validation;
use crate::cbor::walk_driver::{run_above, run_root, Spawner};
use crate::deep_json::DeepJson;

/// Shared message when a group rule is refused as a root.
pub(crate) fn group_rule_root_message(rule_name: &str) -> String {
    format!(
        "CDDL rule {} is a group rule; group rules can only be used inside an array or map, not as a root rule",
        rule_name
    )
}

/// Shared message when `rule_name` is not defined.
pub(crate) fn missing_rule_message(rule_name: &str) -> String {
    format!("CDDL does not define a rule named {}", rule_name)
}

/// Walk failure (schema / root / document / budget). Same object shape
/// as `validate_cbor_against_cddl`.
///
/// `kind`: `parse_error`, `unresolved_references`, `missing_rule`,
/// `group_rule_root`, `input_parse`, `nesting_too_deep`,
/// `validation_too_complex` (last two = budget refusals).
#[derive(Clone, Debug)]
pub(crate) struct WalkError(Value);

impl WalkError {
    /// Kind + message only.
    pub(crate) fn new(kind: &str, message: &str) -> WalkError {
        WalkError(json!({ "kind": kind, "message": message }))
    }

    /// Wrap a shared producer error object.
    pub(crate) fn from_object(error: Value) -> WalkError {
        WalkError(error)
    }

    /// Error `kind` (tests branch on it).
    #[cfg(test)]
    pub(crate) fn kind(&self) -> &str {
        self.0["kind"].as_str().unwrap_or_default()
    }

    pub(crate) fn message(&self) -> &str {
        self.0["message"].as_str().unwrap_or_default()
    }

    /// Error object as exports report it.
    pub(crate) fn into_object(self) -> Value {
        self.0
    }
}

impl fmt::Display for WalkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

/// Decode a `.cbor` / `.cborseq` payload, or `None` if nesting budget /
/// declared length fails. Hold the returned guard while walking the
/// payload so its budget share is released afterward.
pub(crate) fn decode_embedded<'b>(
    budget: &'b limits::NestingBudget,
    payload: &[u8],
) -> Option<(CborValue, limits::EmbeddedGuard<'b>)> {
    let guard = budget.enter_embedded(payload)?;
    decoder::decode_cbor_to_value(payload).ok()?;
    let value = decode_cbor(payload).ok()?;
    Some((value, guard))
}

/// Decode `cbor` and label it against `cddl`'s `rule_name`.
///
/// Schema / root / decode / budget faults → [`WalkError`]. Schema
/// mismatch still yields best-effort (raw) output. Hold the result as
/// [`DeepJson`] when freeing a deep tree.
pub fn decode_cbor_against_cddl(
    cbor: &[u8],
    cddl: &str,
    rule_name: &str,
) -> Result<Value, WalkError> {
    document_cache::with_ast_checked(cddl, |parsed| match parsed {
        Ok(ast) => decode_against_ast(ast, cbor, rule_name),
        Err(e) => Err(WalkError::from_object(validation::schema_error(cddl, e))),
    })
}

/// `decode_cbor_against_cddl` against an already-parsed schema.
pub(crate) fn decode_against_ast(
    ast: &CDDL<'_>,
    cbor: &[u8],
    rule_name: &str,
) -> Result<Value, WalkError> {
    let rules = RuleIndex::build(ast);
    let Some(root) = rules.get(rule_name) else {
        return Err(WalkError::new(
            "missing_rule",
            &missing_rule_message(rule_name),
        ));
    };
    if matches!(root, Rule::Group { .. }) {
        return Err(WalkError::new(
            "group_rule_root",
            &group_rule_root_message(rule_name),
        ));
    }

    // Positional decode first: path + byte offsets on failure.
    if let Err(e) = decoder::decode_cbor_to_value(cbor) {
        return Err(WalkError::from_object(validation::input_parse_error(
            &e,
            cbor.len(),
        )));
    }
    // Pre-scan nesting; leftover budget is for embedded `.cbor` payloads.
    let Some(budget) = limits::NestingBudget::for_document(cbor) else {
        return Err(WalkError::new(
            "nesting_too_deep",
            &limits::cbor_nesting_message(),
        ));
    };
    let value = decode_cbor(cbor).map_err(|e| value_decoder_error(&e.to_string()))?;

    let mapper = Mapper::new(rules, budget);
    let (mapped, _trace) = mapper.map_by_rule_name(&value, rule_name);
    let mapped = DeepJson::new(mapped);
    if let Some(refusal) = mapper.refusal() {
        return Err(refusal);
    }
    Ok(mapped.into_inner())
}

/// Value-decoder reject after positional accept (same shape as validator).
pub(crate) fn value_decoder_error(message: &str) -> WalkError {
    WalkError::from_object(json!({
        "kind": "input_parse",
        "message": message,
        "path": "$",
    }))
}

// ============================================================
// Rule index — quick lookup by name, since we recurse into refs.
// ============================================================

pub(crate) struct RuleIndex<'a> {
    by_name: HashMap<&'a str, &'a Rule<'a>>,
}

impl<'a> RuleIndex<'a> {
    pub(crate) fn build(cddl_ast: &'a CDDL<'a>) -> Self {
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

    pub(crate) fn get(&self, name: &str) -> Option<&'a Rule<'a>> {
        self.by_name.get(name).copied()
    }
}

// ============================================================
// Recursion guard.
// ============================================================

/// Drop: pop rule stack and release descent charge.
struct RuleGuard<'g> {
    stack: &'g RefCell<Vec<(usize, usize)>>,
    _charge: limits::DescentGuard<'g>,
}

impl Drop for RuleGuard<'_> {
    fn drop(&mut self) {
        self.stack.borrow_mut().pop();
    }
}

pub(crate) fn addr<T>(v: &T) -> usize {
    v as *const T as usize
}

// ============================================================
// The trace of a walk.
// ============================================================

/// The index of a [`TraceNode`] in a [`Trace`].
pub(crate) type TraceId = usize;

/// One schema/data decision, for position-map replay.
///
/// Children by index (arena truncate drops declined alts; deep free is
/// non-recursive).
pub(crate) enum TraceNode<'a> {
    /// No alt fitted; value emitted raw.
    Raw,
    /// Chosen type alt and its `Type1` node.
    Alt { index: usize, inner: TraceId },
    /// A `Type1` with a range operator: the value was emitted raw.
    Range,
    /// `.cbor` / `.cborseq` whose payload fitted; `inner` is payload root.
    Embedded { inner: TraceId },
    /// Generic binding: `arg` and its `Type1` walk.
    Binding { arg: &'a Type1<'a>, inner: TraceId },
    /// Prelude type; `container` is true only for `any`.
    Prelude { container: bool },
    /// Type rule; `inner` is body's `Alt`.
    Rule {
        rule: &'a TypeRule<'a>,
        inner: TraceId,
    },
    /// Parenthesized type; `inner` is inner `Alt`.
    Paren { inner: TraceId },
    /// A literal, or an enumeration from a group.
    Leaf,
    /// `any`: the value was kept whole.
    Any,
    /// A map, with how its entries were accounted for.
    Map(MapTrace<'a>),
    /// An array, with how its items were consumed.
    Array(ArrayTrace<'a>),
    /// Tag; `inner` is payload walk, or `None` if specialised.
    Tagged { inner: Option<TraceId> },
}

/// How a map's entries were accounted for.
pub(crate) enum MapTrace<'a> {
    /// The lossless `@entries` form, one record per wire entry.
    Entries(Vec<EntryTrace<'a>>),
    /// Object form: the group choice that claimed the entries.
    Choice(MapChoicePlan<'a>),
}

/// One wire entry of a map in `@entries` form.
pub(crate) struct EntryTrace<'a> {
    /// Member that accepted the key, if any.
    pub(crate) member: Option<(&'a MemberKey<'a>, &'a Type<'a>)>,
    /// Value decision when a member accepted the key.
    pub(crate) value: Option<TraceId>,
}

/// How one array group choice consumed an array's items.
pub(crate) struct ArrayTrace<'a> {
    /// Every run of items, in emission order.
    pub(crate) plan: Vec<PlanEntry<'a>>,
    /// The decision for every item consumed, by wire index.
    pub(crate) items: Vec<TraceId>,
    /// Items from here on were left over.
    pub(crate) cursor: usize,
    /// Named field present → object + `@positional` for unnamed.
    pub(crate) any_named: bool,
}

/// The arena of a walk's [`TraceNode`]s.
#[derive(Default)]
pub(crate) struct Trace<'a> {
    nodes: Vec<TraceNode<'a>>,
}

impl<'a> Trace<'a> {
    pub(crate) fn node(&self, id: TraceId) -> &TraceNode<'a> {
        &self.nodes[id]
    }
}

// ============================================================
// Main walker.
// ============================================================

/// How demanding a walk is about fitting the data.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) enum Mode {
    /// Full fit required; leftovers reject the alt.
    Strict,
    /// Best effort: `@extra` leftovers, null for missing required.
    Lenient,
}

/// Generic param bound to a call-site argument and the scope that
/// argument is read in (RFC 8610 §3.10: caller's frame, not callee's —
/// else `b<t> = c<t>` would bind `t` to itself).
#[derive(Clone, Copy)]
pub(crate) struct Binding<'a> {
    arg: &'a Type1<'a>,
    /// Frame the argument is read in; `None` outside any generic body.
    scope: Option<usize>,
}

/// The parameters of one generic rule body, each bound to its argument.
struct BindingFrame<'a> {
    params: HashMap<String, Binding<'a>>,
    /// Identity shared by frames with the same bindings/scope.
    identity: usize,
}

/// Drop: pop frame and restore call-site scope.
struct ScopeGuard<'g, 'a> {
    mapper: &'g Mapper<'a>,
    previous: Option<usize>,
    pushed: bool,
}

impl Drop for ScopeGuard<'_, '_> {
    fn drop(&mut self) {
        if self.pushed {
            self.mapper.bindings.borrow_mut().pop();
        }
        self.mapper.scope.set(self.previous);
    }
}

/// Memo key for a type/item decline (avoids redoing failed deep passes).
///
/// Outcome depends only on item, type, mode, scope, and open rules.
/// Matches are not cached (would require copying built values).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct DeclineKey {
    node: usize,
    ty: usize,
    mode: Mode,
    scope: usize,
    /// Open rules against the item (order matters for the key).
    open: u64,
}

/// What a walk decided when it stopped short of an answer.
#[derive(Clone, Copy)]
enum Refused {
    /// A chain of rule references against one item past the bound.
    RuleChain,
}

pub(crate) struct Mapper<'a> {
    pub(crate) rules: RuleIndex<'a>,
    /// Generic frames, innermost last.
    bindings: RefCell<Vec<BindingFrame<'a>>>,
    /// Frame in scope (body or call site while reading an arg).
    scope: Cell<Option<usize>>,
    /// Dedup identical frame contents.
    frame_identities: RefCell<HashMap<(usize, usize, usize), usize>>,
    /// `(rule, cbor node)` pairs currently being mapped.
    mapping: RefCell<Vec<(usize, usize)>>,
    /// `(rule, cbor node)` pairs currently being accept-tested.
    accepting: RefCell<Vec<(usize, usize)>>,
    /// Nesting budget, shared with embedded `.cbor` (and position replay).
    budget: limits::NestingBudget,
    /// Descent memory budget; exhaustion ends the walk.
    descent: limits::DescentBudget,
    /// The work the walk may still do.
    work: limits::WorkBudget,
    /// Non-budget refusal (e.g. rule-chain length).
    refused: Cell<Option<Refused>>,
    /// What the walk decided, node by node.
    trace: RefCell<Trace<'a>>,
    /// Declines already decided.
    declined: RefCell<HashSet<DeclineKey>>,
    /// The declines in the order they were decided, so the ones decided
    /// against a payload's nodes can be taken back when that payload is
    /// dropped: a decline is keyed by node address, and the next payload
    /// decoded may put a node at the same address.
    decline_log: RefCell<Vec<DeclineKey>>,
}

/// Mapped value plus its [`TraceId`].
pub(crate) type Mapped = (Value, TraceId);

impl<'a> Mapper<'a> {
    /// Mapper for one schema; share `budget` with position-map replay.
    pub(crate) fn new(rules: RuleIndex<'a>, budget: limits::NestingBudget) -> Mapper<'a> {
        Mapper {
            rules,
            bindings: RefCell::new(Vec::new()),
            scope: Cell::new(None),
            frame_identities: RefCell::new(HashMap::new()),
            mapping: RefCell::new(Vec::new()),
            accepting: RefCell::new(Vec::new()),
            budget,
            descent: limits::DescentBudget::new(limits::MAX_CBOR_MAPPING_DESCENT_COST),
            work: limits::WorkBudget::new(
                limits::MAX_CBOR_MAPPING_WORK,
                limits::mapping_work_message,
            ),
            refused: Cell::new(None),
            trace: RefCell::new(Trace::default()),
            declined: RefCell::new(HashSet::new()),
            decline_log: RefCell::new(Vec::new()),
        }
    }

    /// Shared nesting budget for this document and its payloads.
    pub(crate) fn budget(&self) -> &limits::NestingBudget {
        &self.budget
    }

    /// Take the walk [`Trace`] for position-map replay.
    pub(crate) fn take_trace(&self) -> Trace<'a> {
        mem::take(&mut *self.trace.borrow_mut())
    }

    /// True once a budget / rule-chain / embed / work limit was hit.
    pub(crate) fn refused(&self) -> bool {
        self.descent.exhausted()
            || self.budget.exhausted()
            || self.work.exhausted()
            || self.refused.get().is_some()
    }

    /// Named limit error once [`Self::refused`]; replaces walk output.
    pub(crate) fn refusal(&self) -> Option<WalkError> {
        if let Some(message) = self.descent.refusal().or_else(|| self.budget.refusal()) {
            return Some(WalkError::new("nesting_too_deep", &message));
        }
        if let Some(Refused::RuleChain) = self.refused.get() {
            return Some(WalkError::new(
                "nesting_too_deep",
                &limits::rule_nesting_message(limits::MAX_CBOR_MAPPING_RULE_NESTING),
            ));
        }
        self.work
            .refusal()
            .map(|message| WalkError::new("validation_too_complex", &message))
    }

    /// Charge one nested-data step (work + memory); hold while walking.
    fn level(&self) -> Option<limits::DescentGuard<'_>> {
        if !self.work.step() {
            return None;
        }
        self.descent.charge(limits::SCHEMA_WALKER_DESCENT.level)
    }

    /// Charge one level of a subtree emitted in its raw form.
    fn raw_level(&self) -> Option<limits::DescentGuard<'_>> {
        self.descent.charge(limits::SCHEMA_WALKER_DESCENT.raw_level)
    }

    /// Charge the `hops`th rule ref on this item; `None` if past bound.
    fn hop(&self, hops: usize) -> Option<limits::DescentGuard<'_>> {
        if hops >= limits::MAX_CBOR_MAPPING_RULE_NESTING {
            self.refused.set(Some(Refused::RuleChain));
            return None;
        }
        self.descent.charge(limits::SCHEMA_WALKER_DESCENT.rule_hop)
    }

    /// Charge a generic-arg substitution (same hold cost as a rule ref,
    /// but not counted in the rule-chain hop bound).
    fn substitute(&self) -> Option<limits::DescentGuard<'_>> {
        self.descent.charge(limits::SCHEMA_WALKER_DESCENT.rule_hop)
    }

    /// Enter a rule body for `cbor` as the `hops`th ref on that node.
    ///
    /// `None` if the `(rule, node)` pair is already open (cycle with no
    /// progress), or a bound refuses the hop. Keying by node allows
    /// productive recursion into children; the hop chain resets per level.
    fn enter<'g>(
        &'g self,
        stack: &'g RefCell<Vec<(usize, usize)>>,
        rule: usize,
        node: usize,
        hops: usize,
    ) -> Option<RuleGuard<'g>> {
        let key = (rule, node);
        if stack.borrow().contains(&key) {
            return None;
        }
        let charge = self.hop(hops)?;
        stack.borrow_mut().push(key);
        Some(RuleGuard {
            stack,
            _charge: charge,
        })
    }

    /// Binding of `name` if it is a param of the current rule body.
    fn lookup_binding(&self, name: &str) -> Option<Binding<'a>> {
        let scope = self.scope.get()?;
        self.bindings.borrow()[scope].params.get(name).copied()
    }

    /// The identity of the frame in scope, or 0 when none is.
    fn scope_identity(&self) -> usize {
        match self.scope.get() {
            Some(scope) => self.bindings.borrow()[scope].identity,
            None => 0,
        }
    }

    /// Push the rule body scope (params bound from call-site `args`).
    fn enter_scope<'g>(
        &'g self,
        params: &'a Option<GenericParams<'a>>,
        args: Option<&'a GenericArgs<'a>>,
    ) -> ScopeGuard<'g, 'a> {
        let previous = self.scope.get();
        let frame = match (params.as_ref(), args) {
            (Some(params), Some(args)) if !params.params.is_empty() && !args.args.is_empty() => {
                let mut bound: HashMap<String, Binding<'a>> =
                    HashMap::with_capacity(params.params.len());
                for (p, a) in params.params.iter().zip(args.args.iter()) {
                    let mut binding = Binding {
                        arg: a.arg.as_ref(),
                        scope: previous,
                    };
                    // Collapse bare call-site params to their binding
                    // (avoids O(n²) resolve through a self-passing chain).
                    if let (Some(name), Some(caller)) = (bare_parameter(binding.arg), previous) {
                        if let Some(passed) = self.bindings.borrow()[caller].params.get(name) {
                            binding = *passed;
                        }
                    }
                    bound.insert(p.param.ident.to_string(), binding);
                }
                let content = (self.scope_identity(), addr(params), addr(args));
                let identity = {
                    let mut identities = self.frame_identities.borrow_mut();
                    let next = identities.len() + 1;
                    *identities.entry(content).or_insert(next)
                };
                Some(BindingFrame {
                    params: bound,
                    identity,
                })
            }
            _ => None,
        };
        let pushed = frame.is_some();
        self.scope.set(frame.map(|frame| {
            let mut frames = self.bindings.borrow_mut();
            frames.push(frame);
            frames.len() - 1
        }));
        ScopeGuard {
            mapper: self,
            previous,
            pushed,
        }
    }

    /// Run `f` on `binding`'s arg in that arg's read scope.
    /// Caller charges the substitution like a rule ref.
    fn in_binding_scope<R>(&self, binding: Binding<'a>, f: impl FnOnce(&'a Type1<'a>) -> R) -> R {
        let previous = self.scope.replace(binding.scope);
        let result = f(binding.arg);
        self.scope.set(previous);
        result
    }

    // ---------- the trace ----------

    fn trace_push(&self, node: TraceNode<'a>) -> TraceId {
        let mut trace = self.trace.borrow_mut();
        trace.nodes.push(node);
        trace.nodes.len() - 1
    }

    /// Trace arena length (truncate if an alt declines).
    fn trace_mark(&self) -> usize {
        self.trace.borrow().nodes.len()
    }

    /// Discard everything recorded since `mark`.
    fn trace_discard(&self, mark: usize) {
        self.trace.borrow_mut().nodes.truncate(mark);
    }

    // ---------- strict declines ----------

    fn decline_key(&self, node: &CborValue, ty: &'a Type<'a>, mode: Mode) -> DeclineKey {
        use std::hash::{Hash, Hasher};
        let node = addr(node);
        let mut open = std::collections::hash_map::DefaultHasher::new();
        for (rule, _) in self
            .mapping
            .borrow()
            .iter()
            .rev()
            .take_while(|(_, held)| *held == node)
        {
            rule.hash(&mut open);
        }
        DeclineKey {
            node,
            ty: addr(ty),
            mode,
            scope: self.scope_identity(),
            open: open.finish(),
        }
    }

    /// Walk the root rule (driver root; nesting is heap tasks).
    pub(crate) fn map_by_rule_name<'v>(&'v self, cbor: &'v CborValue, name: &str) -> Mapped {
        match self.rules.get(name) {
            Some(Rule::Type { rule, .. }) => {
                let spawner = Spawner::new();
                let walk = Walk {
                    m: self,
                    spawner: spawner.clone(),
                };
                let ty = &rule.value;
                run_root(&spawner, async move { walk.map_type(cbor, ty, 0).await })
            }
            _ => (self.raw(cbor), self.trace_push(TraceNode::Raw)),
        }
    }
}

/// One field of a map object under construction.
struct MapSlot<'a> {
    /// Wire index, or `None` for a declared-but-absent member.
    wire_index: Option<usize>,
    name: String,
    /// Mapped value (deep; free via [`DeepJson`]).
    value: DeepJson,
    /// How the value was mapped; `None` for a placeholder.
    trace: Option<TraceId>,
    /// Claiming member (for schema source spans).
    member_key: &'a MemberKey<'a>,
    entry_type: &'a Type<'a>,
}

/// Claiming member without the mapped value.
pub(crate) struct MapSlotRef<'a> {
    pub(crate) wire_index: Option<usize>,
    pub(crate) name: String,
    pub(crate) member_key: &'a MemberKey<'a>,
    pub(crate) entry_type: &'a Type<'a>,
    /// The decision for the value; `None` for a placeholder.
    pub(crate) value: Option<TraceId>,
}

/// How one map group choice accounted for a map's entries.
pub(crate) struct MapChoicePlan<'a> {
    pub(crate) claimed: Vec<MapSlotRef<'a>>,
    /// Wire indices no member claimed, in ascending order.
    pub(crate) leftover: Vec<usize>,
}

/// Claimed map entries and filled slots for one group choice.
#[derive(Default)]
struct MapCtx<'a> {
    used: Vec<bool>,
    slots: Vec<MapSlot<'a>>,
}

/// Schema construct for one array slot (for re-walk without re-decide).
#[derive(Clone, Copy)]
pub(crate) enum PlanSlot<'a> {
    /// A `name: type` / bare type entry — walk the item against `Type`.
    Ty(&'a Type<'a>),
    /// Rule/prelude name used as an array entry, plus name span.
    Ref(&'a str, Span),
}

/// One run of array items a single group entry accounted for.
#[derive(Clone)]
pub(crate) struct PlanEntry<'a> {
    /// Projected field name, or `None` if positional.
    pub(crate) name: Option<String>,
    /// Repeating entry → keep array shape even at 0/1 items.
    pub(crate) repeated: bool,
    /// Wire index of the first item consumed.
    pub(crate) start: usize,
    pub(crate) count: usize,
    pub(crate) slot: PlanSlot<'a>,
}

/// Array group-choice accumulator: named → object, unnamed → list.
#[derive(Default)]
struct ArrayCtx<'a> {
    cursor: usize,
    /// Named fields in emit order (later same name replaces earlier).
    named: Vec<(String, DeepJson)>,
    unnamed: Vec<DeepJson>,
    any_named: bool,
    /// Every run of items, in emission order.
    plan: Vec<PlanEntry<'a>>,
    /// The decision for every item consumed, by wire index.
    traces: Vec<TraceId>,
}

/// [`ArrayCtx`] checkpoint to undo a failed group repetition.
#[derive(Clone, Copy)]
struct ArrayCheckpoint {
    cursor: usize,
    named: usize,
    unnamed: usize,
    any_named: bool,
    plan: usize,
}

impl<'a> ArrayCtx<'a> {
    fn checkpoint(&self) -> ArrayCheckpoint {
        ArrayCheckpoint {
            cursor: self.cursor,
            named: self.named.len(),
            unnamed: self.unnamed.len(),
            any_named: self.any_named,
            plan: self.plan.len(),
        }
    }

    fn rollback(&mut self, at: ArrayCheckpoint) {
        self.cursor = at.cursor;
        self.named.truncate(at.named);
        self.unnamed.truncate(at.unnamed);
        self.any_named = at.any_named;
        self.plan.truncate(at.plan);
        self.traces.truncate(at.cursor);
    }

    /// `max > 1` → keep array shape even for a single match.
    fn emit(
        &mut self,
        name: Option<&str>,
        collected: Vec<DeepJson>,
        traces: Vec<TraceId>,
        max: usize,
        start: usize,
        slot: PlanSlot<'a>,
    ) {
        self.plan.push(PlanEntry {
            name: name.map(str::to_string),
            repeated: max > 1,
            start,
            count: collected.len(),
            slot,
        });
        self.traces.extend(traces);
        match name {
            Some(n) => {
                if max > 1 {
                    self.any_named = true;
                    let items = collected.into_iter().map(DeepJson::into_inner).collect();
                    self.named
                        .push((n.to_string(), DeepJson::new(Value::Array(items))));
                } else if let Some(v) = collected.into_iter().next() {
                    self.any_named = true;
                    self.named.push((n.to_string(), v));
                }
                // Absent optional named entry: no field, stay non-object.
            }
            None => self.unnamed.extend(collected),
        }
    }
}

/// Bare name of `t1`, if any (generic-param candidate).
fn bare_parameter<'a>(t1: &'a Type1<'a>) -> Option<&'a str> {
    if t1.operator.is_some() {
        return None;
    }
    match &t1.type2 {
        Type2::Typename {
            ident,
            generic_args: None,
            ..
        } => Some(ident.ident),
        _ => None,
    }
}

/// Member entries of `ge` with inline groups spliced in place.
fn flatten_entry<'a>(ge: &'a GroupEntry<'a>, out: &mut Vec<&'a GroupEntry<'a>>) {
    type Entries<'a> = std::slice::Iter<'a, (GroupEntry<'a>, OptionalComma<'a>)>;
    let mut open: Vec<Entries<'a>> = Vec::new();
    match ge {
        GroupEntry::InlineGroup { group, .. } => {
            for choice in group.group_choices.iter().rev() {
                open.push(choice.group_entries.iter());
            }
        }
        leaf => {
            out.push(leaf);
            return;
        }
    }
    while let Some(entries) = open.last_mut() {
        match entries.next() {
            None => {
                open.pop();
            }
            Some((GroupEntry::InlineGroup { group, .. }, _)) => {
                for choice in group.group_choices.iter().rev() {
                    open.push(choice.group_entries.iter());
                }
            }
            Some((leaf, _)) => out.push(leaf),
        }
    }
}

/// Member entries of one group choice (inline groups spliced).
fn flatten_choice<'a>(choice: &'a GroupChoice<'a>) -> Vec<&'a GroupEntry<'a>> {
    let mut out = Vec::with_capacity(choice.group_entries.len());
    for (ge, _) in &choice.group_entries {
        flatten_entry(ge, &mut out);
    }
    out
}

/// One schema/data walk: mapper + driver spawner.
///
/// Recursive steps go through [`Walk::above`] (heap tasks, not native
/// frames).
struct Walk<'a, 'v> {
    m: &'v Mapper<'a>,
    spawner: Spawner<'v>,
}

impl<'a, 'v> Clone for Walk<'a, 'v> {
    fn clone(&self) -> Self {
        Walk {
            m: self.m,
            spawner: self.spawner.clone(),
        }
    }
}

impl<'a: 'v, 'v> Walk<'a, 'v> {
    /// Run `task` above this step and wait for what it produces.
    fn above<R: 'v>(&self, task: impl Future<Output = R> + 'v) -> impl Future<Output = R> + 'v {
        run_above(&self.spawner, task)
    }

    fn push(&self, node: TraceNode<'a>) -> TraceId {
        self.m.trace_push(node)
    }

    /// Always produce a value: strict → lenient → raw.
    /// `hops` = rule refs already resolved against `cbor`.
    async fn map_type(&self, cbor: &'v CborValue, ty: &'a Type<'a>, hops: usize) -> Mapped {
        if let Some(mapped) = self.try_map_type(cbor, ty, Mode::Strict, hops).await {
            return mapped;
        }
        if let Some(mapped) = self.try_map_type(cbor, ty, Mode::Lenient, hops).await {
            return mapped;
        }
        if self.m.refused() {
            return (Value::Null, self.push(TraceNode::Raw));
        }
        (self.m.raw(cbor), self.push(TraceNode::Raw))
    }

    /// Walk a type choice; decline if no alt fits (enclosing choice moves on).
    async fn try_map_type(
        &self,
        cbor: &'v CborValue,
        ty: &'a Type<'a>,
        mode: Mode,
        hops: usize,
    ) -> Option<Mapped> {
        if self.m.refused() {
            return None;
        }
        let key = self.m.decline_key(cbor, ty, mode);
        if self.m.declined.borrow().contains(&key) {
            return None;
        }
        for (index, choice) in ty.type_choices.iter().enumerate() {
            if let Some((value, inner)) = self.try_map_type1(cbor, &choice.type1, mode, hops).await
            {
                return Some((value, self.push(TraceNode::Alt { index, inner })));
            }
        }
        if !self.m.refused() && self.m.declined.borrow_mut().insert(key) {
            self.m.decline_log.borrow_mut().push(key);
        }
        None
    }

    /// Walk one alt; truncate trace if it declines.
    async fn try_map_type1(
        &self,
        cbor: &'v CborValue,
        t1: &'a Type1<'a>,
        mode: Mode,
        hops: usize,
    ) -> Option<Mapped> {
        if self.m.refused() || !self.m.work.step() {
            return None;
        }
        let mark = self.m.trace_mark();
        let mapped = self.try_map_type1_alternative(cbor, t1, mode, hops).await;
        if mapped.is_none() {
            self.m.trace_discard(mark);
        }
        mapped
    }

    async fn try_map_type1_alternative(
        &self,
        cbor: &'v CborValue,
        t1: &'a Type1<'a>,
        mode: Mode,
        hops: usize,
    ) -> Option<Mapped> {
        let Some(op) = &t1.operator else {
            return self.try_map_type2(cbor, &t1.type2, mode, hops).await;
        };
        match &op.operator {
            RangeCtlOp::RangeOp { .. } => {
                if self.m.type1_accepts(t1, cbor, hops) {
                    Some((self.m.raw(cbor), self.push(TraceNode::Range)))
                } else {
                    None
                }
            }
            RangeCtlOp::CtlOp { ctrl, .. } => match ctrl {
                // `.cbor` / `.cborseq`: decode and walk the payload.
                ControlOperator::CBOR | ControlOperator::CBORSEQ => {
                    if let CborValue::Bytes(b) = cbor {
                        // Nested walk spends leftover document budget.
                        if let Some((inner, _guard)) = decode_embedded(&self.m.budget, b) {
                            let _level = self.m.level()?;
                            let mark = self.m.trace_mark();
                            if let Some((value, inner)) =
                                self.walk_embedded(&inner, &op.type2, mode)
                            {
                                return Some((value, self.push(TraceNode::Embedded { inner })));
                            }
                            self.m.trace_discard(mark);
                        }
                    }
                    self.try_map_type2(cbor, &t1.type2, mode, hops).await
                }
                _ => {
                    if !self.m.type1_accepts(t1, cbor, hops) {
                        return None;
                    }
                    self.try_map_type2(cbor, &t1.type2, mode, hops).await
                }
            },
        }
    }

    /// Walk a `.cbor` / `.cborseq` payload on its own driver.
    /// Open payloads are bounded by [`limits::MAX_EMBEDDED_DEPTH`].
    fn walk_embedded<'p>(
        &self,
        inner: &'p CborValue,
        t2: &'a Type2<'a>,
        mode: Mode,
    ) -> Option<Mapped>
    where
        'v: 'p,
    {
        let spawner = Spawner::new();
        let walk: Walk<'a, 'p> = Walk {
            m: self.m,
            spawner: spawner.clone(),
        };
        // The payload's tree lives only for this walk, and every decline
        // decided in it is keyed by one of its nodes' addresses; the next
        // payload may reuse those addresses, so the declines go with the
        // tree.
        let mark = self.m.decline_log.borrow().len();
        let mapped = run_root(&spawner, async move {
            walk.try_map_type2(inner, t2, mode, 0).await
        });
        let mut log = self.m.decline_log.borrow_mut();
        let mut declined = self.m.declined.borrow_mut();
        for key in log.drain(mark..) {
            declined.remove(&key);
        }
        mapped
    }

    async fn try_map_type2(
        &self,
        cbor: &'v CborValue,
        t2: &'a Type2<'a>,
        mode: Mode,
        hops: usize,
    ) -> Option<Mapped> {
        if self.m.refused() {
            return None;
        }
        match t2 {
            Type2::Typename {
                ident,
                generic_args,
                ..
            } => {
                self.try_map_typename(cbor, ident.ident, generic_args.as_ref(), mode, hops)
                    .await
            }

            Type2::ParenthesizedType { pt, .. } => {
                let walk = self.clone();
                let (value, inner) = self
                    .above(async move { walk.try_map_type(cbor, pt, mode, hops).await })
                    .await?;
                Some((value, self.push(TraceNode::Paren { inner })))
            }

            Type2::Map { group, .. } => self.try_map_map(cbor, group, mode, hops).await,

            Type2::Array { group, .. } => self.try_map_array(cbor, group, mode, hops).await,

            Type2::TaggedData { tag, t, .. } => {
                self.try_map_tagged(cbor, tag.as_ref(), t, mode).await
            }

            // Literal: accept only on equality.
            Type2::IntValue { value, .. } => match cbor {
                CborValue::Integer(i) if *i == Integer::from(*value as i64) => {
                    Some((int_to_json(*i), self.push(TraceNode::Leaf)))
                }
                _ => None,
            },
            Type2::UintValue { value, .. } => match cbor {
                CborValue::Integer(i) if *i == Integer::from(*value as u64) => {
                    Some((int_to_json(*i), self.push(TraceNode::Leaf)))
                }
                _ => None,
            },
            Type2::TextValue { value, .. } => match cbor {
                CborValue::Text(t) if t == value.as_ref() => {
                    Some((Value::String(t.clone()), self.push(TraceNode::Leaf)))
                }
                _ => None,
            },
            Type2::FloatValue { value, .. } => match cbor {
                CborValue::Float(f) if (*f - *value).abs() < f64::EPSILON => Number::from_f64(*f)
                    .map(Value::Number)
                    .map(|v| (v, self.push(TraceNode::Leaf))),
                _ => None,
            },
            Type2::UTF8ByteString { value, .. }
            | Type2::B16ByteString { value, .. }
            | Type2::B64ByteString { value, .. } => match cbor {
                CborValue::Bytes(b) if b.as_slice() == value.as_ref() => {
                    Some((Value::String(hex::encode(b)), self.push(TraceNode::Leaf)))
                }
                _ => None,
            },

            Type2::Any { .. } => Some((self.m.raw(cbor), self.push(TraceNode::Any))),

            Type2::ChoiceFromGroup { ident, .. } => {
                // `&(group_name)` enum: matching literal entry.
                self.m
                    .try_enum_from_group(cbor, ident.ident)
                    .map(|v| (v, self.push(TraceNode::Leaf)))
            }

            Type2::Unwrap {
                ident,
                generic_args,
                ..
            } => {
                // `~rule` in type position; group unwrap is at GroupEntry.
                self.try_map_typename(cbor, ident.ident, generic_args.as_ref(), mode, hops)
                    .await
            }

            // Unmodelled Type2 → decline (next type choice).
            _ => None,
        }
    }

    /// Name in type/array position: generic param → prelude → type rule.
    async fn try_map_typename(
        &self,
        cbor: &'v CborValue,
        name: &'a str,
        generic_args: Option<&'a GenericArgs<'a>>,
        mode: Mode,
        hops: usize,
    ) -> Option<Mapped> {
        // Generic param (no args) → prelude scalar (no args) → rule.
        if generic_args.is_none() {
            if let Some(binding) = self.m.lookup_binding(name) {
                let _hop = self.m.substitute()?;
                let walk = self.clone();
                let (value, inner) = self
                    .above(async move {
                        let previous = walk.m.scope.replace(binding.scope);
                        let mapped = walk.try_map_type1(cbor, binding.arg, mode, hops).await;
                        walk.m.scope.set(previous);
                        mapped
                    })
                    .await?;
                return Some((
                    value,
                    self.push(TraceNode::Binding {
                        arg: binding.arg,
                        inner,
                    }),
                ));
            }
            if let Some(prim) = self.m.prelude(cbor, name) {
                let container = prim.is_array() || prim.is_object();
                return Some((prim, self.push(TraceNode::Prelude { container })));
            }
        }
        match self.m.rules.get(name) {
            Some(r) => match r {
                Rule::Type { rule, .. } => {
                    let _guard = self.m.enter(&self.m.mapping, addr(r), addr(cbor), hops)?;
                    let walk = self.clone();
                    let (value, inner) = self
                        .above(async move {
                            let _scope = walk.m.enter_scope(&rule.generic_params, generic_args);
                            walk.try_map_type(cbor, &rule.value, mode, hops + 1).await
                        })
                        .await?;
                    Some((value, self.push(TraceNode::Rule { rule, inner })))
                }
                // Group rule in type position → decline.
                Rule::Group { .. } => None,
            },
            None => None,
        }
    }

    // ---------- Map handling ----------

    async fn try_map_map(
        &self,
        cbor: &'v CborValue,
        group: &'a Group<'a>,
        mode: Mode,
        hops: usize,
    ) -> Option<Mapped> {
        let CborValue::Map(entries) = cbor else {
            return None;
        };

        // Complex/repeated/colliding keys → `@entries`. Strict still
        // accounts for fit either way (shape ≠ match).
        if map_needs_entries(entries) {
            let mut accounted = Vec::new();
            if mode == Mode::Strict {
                match self.first_choice_accounting_for(entries, group, hops).await {
                    Some(slots) => accounted = slots,
                    None => return None,
                }
            }
            return self
                .try_map_to_entries(entries, group, hops, accounted)
                .await;
        }

        for choice in &group.group_choices {
            let mark = self.m.trace_mark();
            if let Some(out) = self.try_map_with_choice(entries, choice, mode, hops).await {
                return Some(out);
            }
            self.m.trace_discard(mark);
        }
        None
    }

    /// First group choice that fully claims `entries`, or `None`.
    /// Returns mapped values so `@entries` need not re-walk them
    /// (avoids O(nesting) double work per level).
    async fn first_choice_accounting_for(
        &self,
        entries: &'v [(CborValue, CborValue)],
        group: &'a Group<'a>,
        hops: usize,
    ) -> Option<Vec<MapSlot<'a>>> {
        for choice in &group.group_choices {
            let mark = self.m.trace_mark();
            if let Some((ctx, leftover)) = self
                .claim_with_choice(entries, choice, Mode::Strict, hops)
                .await
            {
                if leftover.is_empty() {
                    return Some(ctx.slots);
                }
            }
            self.m.trace_discard(mark);
        }
        None
    }

    /// Lossless map: `{"@entries": [{key, value, match}, ...]}` in wire
    /// order. `match.via` is `"literal" | "type" | "unmatched"`;
    /// unmatched keys still emit raw key/value.
    async fn try_map_to_entries(
        &self,
        entries: &'v [(CborValue, CborValue)],
        group: &'a Group<'a>,
        hops: usize,
        accounted: Vec<MapSlot<'a>>,
    ) -> Option<Mapped> {
        let mut claimed: Vec<Option<MapSlot<'a>>> = (0..entries.len()).map(|_| None).collect();
        for slot in accounted {
            if let Some(wire) = slot.wire_index {
                claimed[wire] = Some(slot);
            }
        }
        let mut pairs: Vec<Value> = Vec::with_capacity(entries.len());
        let mut traces: Vec<EntryTrace<'a>> = Vec::with_capacity(entries.len());
        for (i, (k, v)) in entries.iter().enumerate() {
            let (pair, trace) = self
                .match_one_entry(k, v, group, hops, claimed[i].take())
                .await;
            pairs.push(pair);
            traces.push(trace);
        }
        Some((
            entries_object(pairs),
            self.push(TraceNode::Map(MapTrace::Entries(traces))),
        ))
    }

    async fn match_one_entry(
        &self,
        cbor_key: &'v CborValue,
        cbor_value: &'v CborValue,
        group: &'a Group<'a>,
        hops: usize,
        accounted: Option<MapSlot<'a>>,
    ) -> (Value, EntryTrace<'a>) {
        let _ = hops;
        if let Some((mk, entry_type, label)) = self.m.match_entry_member(group, cbor_key) {
            let key_json = self.m.raw(cbor_key);
            let already = accounted
                .filter(|slot| addr(slot.member_key) == addr(mk))
                .and_then(|slot| Some((slot.value.into_inner(), slot.trace?)));
            let (value_json, value_trace) = match already {
                Some((value, trace)) => (value, Some(trace)),
                None => match self.m.level() {
                    Some(_level) => {
                        let walk = self.clone();
                        let (value, trace) = self
                            .above(async move { walk.map_type(cbor_value, entry_type, 0).await })
                            .await;
                        (value, Some(trace))
                    }
                    None => (Value::Null, None),
                },
            };
            let via = if is_literal_member_key(mk) {
                "literal"
            } else {
                "type"
            };
            let label = if via == "literal" {
                Value::String(label)
            } else {
                Value::Null
            };
            return (
                entry_pair(key_json, value_json, via, label),
                EntryTrace {
                    member: Some((mk, entry_type)),
                    value: value_trace,
                },
            );
        }
        (
            entry_pair(
                self.m.raw(cbor_key),
                self.m.raw(cbor_value),
                "unmatched",
                Value::Null,
            ),
            EntryTrace {
                member: None,
                value: None,
            },
        )
    }

    /// Account one group choice against map entries; `None` if it cannot.
    async fn claim_with_choice(
        &self,
        entries: &'v [(CborValue, CborValue)],
        choice: &'a GroupChoice<'a>,
        mode: Mode,
        hops: usize,
    ) -> Option<(MapCtx<'a>, Vec<usize>)> {
        let mut ctx = MapCtx {
            used: vec![false; entries.len()],
            slots: Vec::new(),
        };

        for ge in flatten_choice(choice) {
            self.consume_map_entry(ge, entries, &mut ctx, mode, hops)
                .await?;
        }

        let leftover: Vec<usize> = (0..entries.len()).filter(|i| !ctx.used[*i]).collect();
        Some((ctx, leftover))
    }

    /// Walk one map group choice; record claims and leftovers.
    async fn try_map_with_choice(
        &self,
        entries: &'v [(CborValue, CborValue)],
        choice: &'a GroupChoice<'a>,
        mode: Mode,
        hops: usize,
    ) -> Option<Mapped> {
        let (ctx, leftover) = self.claim_with_choice(entries, choice, mode, hops).await?;
        if mode == Mode::Strict && !leftover.is_empty() {
            return None;
        }

        let plan_slots: Vec<MapSlotRef<'a>> = ctx
            .slots
            .iter()
            .map(|s| MapSlotRef {
                wire_index: s.wire_index,
                name: s.name.clone(),
                member_key: s.member_key,
                entry_type: s.entry_type,
                value: s.trace,
            })
            .collect();

        let (mut wire, missing): (Vec<MapSlot<'a>>, Vec<MapSlot<'a>>) =
            ctx.slots.into_iter().partition(|s| s.wire_index.is_some());
        wire.sort_by_key(|s| s.wire_index.unwrap_or(usize::MAX));

        // Repeated field name → value array (no silent overwrite).
        let mut repeats: HashMap<&str, usize> = HashMap::new();
        for s in &wire {
            *repeats.entry(s.name.as_str()).or_insert(0) += 1;
        }
        let multi: HashSet<String> = repeats
            .into_iter()
            .filter(|(_, n)| *n > 1)
            .map(|(k, _)| k.to_string())
            .collect();

        let mut out = Map::new();
        for s in wire {
            let value = s.value.into_inner();
            if multi.contains(&s.name) {
                match out.get_mut(&s.name) {
                    Some(Value::Array(existing)) => existing.push(value),
                    _ => {
                        out.insert(s.name, Value::Array(vec![value]));
                    }
                }
            } else {
                out.insert(s.name, value);
            }
        }
        for s in missing {
            if !out.contains_key(&s.name) {
                out.insert(s.name, s.value.into_inner());
            }
        }

        if !leftover.is_empty() {
            let mut extras_obj = Map::new();
            for i in &leftover {
                let (k, v) = &entries[*i];
                extras_obj.insert(json_key(k), self.m.raw(v));
            }
            out.insert("@extra".into(), Value::Object(extras_obj));
        }

        Some((
            Value::Object(out),
            self.push(TraceNode::Map(MapTrace::Choice(MapChoicePlan {
                claimed: plan_slots,
                leftover,
            }))),
        ))
    }

    /// Consume one member against unused map entries; `None` if it cannot.
    async fn consume_map_entry(
        &self,
        ge: &'a GroupEntry<'a>,
        entries: &'v [(CborValue, CborValue)],
        ctx: &mut MapCtx<'a>,
        mode: Mode,
        hops: usize,
    ) -> Option<()> {
        match ge {
            GroupEntry::ValueMemberKey { ge, .. } => {
                let vmk = ge.as_ref();
                let is_optional = is_occur_optional(vmk.occur.as_ref());
                let Some(mk) = &vmk.member_key else {
                    return Some(());
                };

                let mut found_any = false;
                for (i, (k, v)) in entries.iter().enumerate() {
                    if ctx.used[i] {
                        continue;
                    }
                    let Some(field_name) = self.m.try_match_member_key(mk, k) else {
                        continue;
                    };
                    let _level = self.m.level()?;
                    let walk = self.clone();
                    let entry_type = &vmk.entry_type;
                    let (mapped, trace) = match mode {
                        // Key matches but value type rejects → leave for another choice.
                        Mode::Strict => {
                            match self
                                .above(async move {
                                    walk.try_map_type(v, entry_type, Mode::Strict, 0).await
                                })
                                .await
                            {
                                Some(m) => m,
                                None => continue,
                            }
                        }
                        Mode::Lenient => {
                            self.above(async move { walk.map_type(v, entry_type, 0).await })
                                .await
                        }
                    };
                    ctx.slots.push(MapSlot {
                        wire_index: Some(i),
                        name: field_name,
                        value: DeepJson::new(mapped),
                        trace: Some(trace),
                        member_key: mk,
                        entry_type: &vmk.entry_type,
                    });
                    ctx.used[i] = true;
                    found_any = true;
                    // Duplicate keys are well-formed (RFC 8949 §5.3.1); claim all.
                }

                if !found_any && !is_optional {
                    if mode == Mode::Strict {
                        return None;
                    }
                    ctx.slots.push(MapSlot {
                        wire_index: None,
                        name: member_key_label(mk),
                        value: DeepJson::new(Value::Null),
                        trace: None,
                        member_key: mk,
                        entry_type: &vmk.entry_type,
                    });
                }
                Some(())
            }
            GroupEntry::TypeGroupname { ge, .. } => {
                self.flatten_group_name_into_map(
                    ge.name.ident,
                    ge.generic_args.as_ref(),
                    entries,
                    ctx,
                    mode,
                    hops,
                )
                .await
            }
            GroupEntry::InlineGroup { .. } => Some(()),
        }
    }

    /// Splice a rule body's members into the map (one hop deeper).
    async fn consume_spliced_entries(
        &self,
        spliced: Vec<&'a GroupEntry<'a>>,
        entries: &'v [(CborValue, CborValue)],
        ctx: &mut MapCtx<'a>,
        mode: Mode,
        hops: usize,
    ) -> Option<()> {
        let taken = mem::take(ctx);
        let walk = self.clone();
        let (back, out) = self
            .above(async move {
                let mut ctx = taken;
                let mut out = Some(());
                for ge in spliced {
                    if walk
                        .consume_map_entry(ge, entries, &mut ctx, mode, hops)
                        .await
                        .is_none()
                    {
                        out = None;
                        break;
                    }
                }
                (ctx, out)
            })
            .await;
        *ctx = back;
        out
    }

    async fn flatten_group_name_into_map(
        &self,
        name: &'a str,
        generic_args: Option<&'a GenericArgs<'a>>,
        entries: &'v [(CborValue, CborValue)],
        ctx: &mut MapCtx<'a>,
        mode: Mode,
        hops: usize,
    ) -> Option<()> {
        let Some(r) = self.m.rules.get(name) else {
            return Some(());
        };
        let _guard = self
            .m
            .enter(&self.m.mapping, addr(r), entries.as_ptr() as usize, hops)?;
        match r {
            Rule::Group { rule, .. } => {
                let _scope = self.m.enter_scope(&rule.generic_params, generic_args);
                let mut spliced = Vec::new();
                flatten_entry(&rule.entry, &mut spliced);
                self.consume_spliced_entries(spliced, entries, ctx, mode, hops + 1)
                    .await
            }
            Rule::Type { rule, .. } => {
                let _scope = self.m.enter_scope(&rule.generic_params, generic_args);
                // Type rule as group entry → flatten Map / ParenthesizedType.
                let mut spliced = Vec::new();
                for choice in &rule.value.type_choices {
                    match &choice.type1.type2 {
                        Type2::Map { group, .. } => {
                            for gc in &group.group_choices {
                                for (ge, _) in &gc.group_entries {
                                    flatten_entry(ge, &mut spliced);
                                }
                            }
                        }
                        Type2::ParenthesizedType { pt, .. } => {
                            for inner_choice in &pt.type_choices {
                                if let Type2::Map { group, .. } = &inner_choice.type1.type2 {
                                    for gc in &group.group_choices {
                                        for (ge, _) in &gc.group_entries {
                                            flatten_entry(ge, &mut spliced);
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                self.consume_spliced_entries(spliced, entries, ctx, mode, hops + 1)
                    .await
            }
        }
    }

    // ---------- Array handling ----------

    async fn try_map_array(
        &self,
        cbor: &'v CborValue,
        group: &'a Group<'a>,
        mode: Mode,
        hops: usize,
    ) -> Option<Mapped> {
        let CborValue::Array(items) = cbor else {
            return None;
        };

        for choice in &group.group_choices {
            let mark = self.m.trace_mark();
            if let Some(out) = self.try_array_with_choice(items, choice, mode, hops).await {
                return Some(out);
            }
            self.m.trace_discard(mark);
        }
        None
    }

    /// Array group choice: named → object fields, unnamed → list /
    /// `@positional` when mixed.
    async fn try_array_with_choice(
        &self,
        items: &'v [CborValue],
        choice: &'a GroupChoice<'a>,
        mode: Mode,
        hops: usize,
    ) -> Option<Mapped> {
        let labels = Rc::new(choice_label_counts(&self.m.rules, choice));
        let mut ctx = ArrayCtx::default();

        for ge in flatten_choice(choice) {
            self.consume_array_entry(ge, items, &mut ctx, &labels, mode, hops)
                .await?;
        }

        if mode == Mode::Strict && ctx.cursor != items.len() {
            return None;
        }

        let leftover: Vec<Value> = items[ctx.cursor..]
            .iter()
            .map(|item| self.m.raw(item))
            .collect();
        let unnamed: Vec<Value> = mem::take(&mut ctx.unnamed)
            .into_iter()
            .map(DeepJson::into_inner)
            .collect();
        let built = if ctx.any_named {
            let mut named = Map::new();
            for (name, value) in mem::take(&mut ctx.named) {
                named.insert(name, value.into_inner());
            }
            if !unnamed.is_empty() {
                named.insert("@positional".into(), Value::Array(unnamed));
            }
            if !leftover.is_empty() {
                named.insert("@extra".into(), Value::Array(leftover));
            }
            Value::Object(named)
        } else {
            let mut out = unnamed;
            out.extend(leftover);
            Value::Array(out)
        };
        Some((
            built,
            self.push(TraceNode::Array(ArrayTrace {
                plan: ctx.plan,
                items: ctx.traces,
                cursor: ctx.cursor,
                any_named: ctx.any_named,
            })),
        ))
    }

    /// Consume one member entry against the items from the cursor on.
    async fn consume_array_entry(
        &self,
        ge: &'a GroupEntry<'a>,
        items: &'v [CborValue],
        ctx: &mut ArrayCtx<'a>,
        labels: &Rc<HashMap<String, usize>>,
        mode: Mode,
        hops: usize,
    ) -> Option<()> {
        match ge {
            GroupEntry::ValueMemberKey { ge: vmk, .. } => {
                let vmk = vmk.as_ref();
                let (min, max) = occur_bounds(vmk.occur.as_ref());
                // Duplicate bareword in choice → stay positional.
                let name = vmk
                    .member_key
                    .as_ref()
                    .and_then(bareword_name)
                    .filter(|n| labels.get(*n).copied().unwrap_or(0) == 1);

                let start = ctx.cursor;
                let mut collected: Vec<DeepJson> = Vec::new();
                let mut traces: Vec<TraceId> = Vec::new();
                while collected.len() < max && ctx.cursor < items.len() {
                    let Some((mapped, trace)) = self
                        .map_array_slot(&items[ctx.cursor], &vmk.entry_type, mode)
                        .await
                    else {
                        break;
                    };
                    collected.push(DeepJson::new(mapped));
                    traces.push(trace);
                    ctx.cursor += 1;
                }
                if collected.len() < min {
                    return None;
                }
                ctx.emit(
                    name,
                    collected,
                    traces,
                    max,
                    start,
                    PlanSlot::Ty(&vmk.entry_type),
                );
                Some(())
            }
            GroupEntry::TypeGroupname { ge, .. } => {
                self.consume_array_typegroupname(items, ge, ctx, labels, mode, hops)
                    .await
            }
            GroupEntry::InlineGroup { .. } => Some(()),
        }
    }

    /// Map one array item against slot type `ty`, if it fits.
    async fn map_array_slot(
        &self,
        v: &'v CborValue,
        ty: &'a Type<'a>,
        mode: Mode,
    ) -> Option<Mapped> {
        let _level = self.m.level()?;
        let walk = self.clone();
        match mode {
            Mode::Strict => {
                self.above(async move { walk.try_map_type(v, ty, Mode::Strict, 0).await })
                    .await
            }
            Mode::Lenient => {
                if self.m.type_accepts(ty, v, 0) {
                    Some(
                        self.above(async move { walk.map_type(v, ty, 0).await })
                            .await,
                    )
                } else {
                    None
                }
            }
        }
    }

    /// Splice a group rule body into the array once.
    async fn consume_spliced_array_entries(
        &self,
        spliced: Rc<Vec<&'a GroupEntry<'a>>>,
        items: &'v [CborValue],
        ctx: &mut ArrayCtx<'a>,
        labels: &Rc<HashMap<String, usize>>,
        mode: Mode,
        hops: usize,
    ) -> bool {
        let taken = mem::take(ctx);
        let walk = self.clone();
        let labels = Rc::clone(labels);
        let (back, ok) = self
            .above(async move {
                let mut ctx = taken;
                let mut ok = true;
                for ge in spliced.iter() {
                    if walk
                        .consume_array_entry(ge, items, &mut ctx, &labels, mode, hops)
                        .await
                        .is_none()
                    {
                        ok = false;
                        break;
                    }
                }
                (ctx, ok)
            })
            .await;
        *ctx = back;
        ok
    }

    async fn consume_array_typegroupname(
        &self,
        items: &'v [CborValue],
        ge: &'a TypeGroupnameEntry<'a>,
        ctx: &mut ArrayCtx<'a>,
        labels: &Rc<HashMap<String, usize>>,
        mode: Mode,
        hops: usize,
    ) -> Option<()> {
        let name = ge.name.ident;
        let (min, max) = occur_bounds(ge.occur.as_ref());

        // Group rule splices its entries into this array.
        if let Some(r) = self.m.rules.get(name) {
            if let Rule::Group { rule, .. } = r {
                let _guard =
                    self.m
                        .enter(&self.m.mapping, addr(r), items.as_ptr() as usize, hops)?;
                let _scope = self
                    .m
                    .enter_scope(&rule.generic_params, ge.generic_args.as_ref());
                let mut spliced = Vec::new();
                flatten_entry(&rule.entry, &mut spliced);
                let spliced = Rc::new(spliced);
                let mut taken = 0usize;
                while taken < max {
                    let save = ctx.checkpoint();
                    let mark = self.m.trace_mark();
                    let before = ctx.cursor;
                    let ok = self
                        .consume_spliced_array_entries(
                            Rc::clone(&spliced),
                            items,
                            ctx,
                            labels,
                            mode,
                            hops + 1,
                        )
                        .await;
                    // Zero-width repeat would loop forever.
                    if !ok || (taken > 0 && ctx.cursor == before) {
                        ctx.rollback(save);
                        self.m.trace_discard(mark);
                        break;
                    }
                    taken += 1;
                    if ctx.cursor >= items.len() {
                        break;
                    }
                }
                return if taken >= min { Some(()) } else { None };
            }
        }

        let start = ctx.cursor;
        let mut collected: Vec<DeepJson> = Vec::new();
        let mut traces: Vec<TraceId> = Vec::new();
        while collected.len() < max && ctx.cursor < items.len() {
            let _level = self.m.level()?;
            let item = &items[ctx.cursor];
            let walk = self.clone();
            let generic_args = ge.generic_args.as_ref();
            let Some((mapped, trace)) = self
                .above(async move {
                    walk.try_map_typename(item, name, generic_args, mode, 0)
                        .await
                })
                .await
            else {
                break;
            };
            collected.push(DeepJson::new(mapped));
            traces.push(trace);
            ctx.cursor += 1;
        }
        if collected.len() < min {
            return None;
        }
        let slot = PlanSlot::Ref(name, ge.name.span);

        // Label from type name unless prelude / bound generic /
        // duplicate in choice / repeating entry.
        let labelled = max == 1
            && !is_prelude_name(name)
            && self.m.lookup_binding(name).is_none()
            && labels.get(name).copied().unwrap_or(0) == 1;
        if labelled {
            ctx.emit(Some(name), collected, traces, max, start, slot);
        } else {
            ctx.emit(None, collected, traces, max, start, slot);
        }
        Some(())
    }

    // ---------- Tag handling ----------

    async fn try_map_tagged(
        &self,
        cbor: &'v CborValue,
        tag: Option<&TagConstraint<'a>>,
        inner: &'a Type<'a>,
        mode: Mode,
    ) -> Option<Mapped> {
        let CborValue::Tag(n, payload) = cbor else {
            return None;
        };

        if !tag_matches(tag, *n) {
            return None;
        }

        // Known tags (bignum 2/3, datetime 0, …) short-circuit.
        if let Some(specialised) = specialise_known_tag(*n, payload) {
            return Some((specialised, self.push(TraceNode::Tagged { inner: None })));
        }

        let _level = self.m.level()?;
        let payload: &'v CborValue = payload;
        let walk = self.clone();
        let (value, trace) = match mode {
            Mode::Strict => {
                self.above(async move { walk.try_map_type(payload, inner, Mode::Strict, 0).await })
                    .await?
            }
            Mode::Lenient => {
                self.above(async move { walk.map_type(payload, inner, 0).await })
                    .await
            }
        };
        let mut obj = Map::new();
        obj.insert("@tag".into(), Value::Number((*n).into()));
        obj.insert("@value".into(), value);
        Some((
            Value::Object(obj),
            self.push(TraceNode::Tagged { inner: Some(trace) }),
        ))
    }
}

impl<'a> Mapper<'a> {
    /// Map prelude `name`, or `None`. `any` keeps the value whole (charged).
    fn prelude(&self, value: &CborValue, name: &str) -> Option<Value> {
        if name == "any" {
            return Some(self.raw(value));
        }
        try_prelude(value, name)
    }

    /// First member of `group` that accepts `cbor_key` (declaration order).
    fn match_entry_member(
        &self,
        group: &'a Group<'a>,
        cbor_key: &CborValue,
    ) -> Option<(&'a MemberKey<'a>, &'a Type<'a>, String)> {
        for choice in &group.group_choices {
            for (ge, _) in &choice.group_entries {
                let GroupEntry::ValueMemberKey { ge: vmk, .. } = ge else {
                    continue;
                };
                let Some(mk) = &vmk.member_key else { continue };
                if let Some(label) = self.try_match_member_key(mk, cbor_key) {
                    return Some((mk, &vmk.entry_type, label));
                }
            }
        }
        None
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
// Helpers: occurrences, labels, key matchers, raw conversion.
// ============================================================

/// Occurrence bounds `(min, max)`; absent means exactly one.
fn occur_bounds(o: Option<&Occurrence<'_>>) -> (usize, usize) {
    match o.map(|o| &o.occur) {
        None => (1, 1),
        Some(Occur::Optional { .. }) => (0, 1),
        Some(Occur::ZeroOrMore { .. }) => (0, usize::MAX),
        Some(Occur::OneOrMore { .. }) => (1, usize::MAX),
        Some(Occur::Exact { lower, upper, .. }) => {
            (lower.unwrap_or(0), upper.unwrap_or(usize::MAX))
        }
    }
}

fn is_occur_optional(o: Option<&Occurrence<'_>>) -> bool {
    occur_bounds(o).0 == 0
}

fn bareword_name<'a>(mk: &'a MemberKey<'a>) -> Option<&'a str> {
    match mk {
        MemberKey::Bareword { ident, .. } => Some(ident.ident),
        MemberKey::Value {
            value: cddl::token::Value::TEXT(s),
            ..
        } => {
            // Text literal as array field name.
            Some(s.as_ref())
        }
        MemberKey::Value { .. } => None,
        MemberKey::Type1 { .. } => None,
        MemberKey::NonMemberKey { .. } => None,
    }
}

/// True when the member key is a fixed literal, not a type constraint.
pub(crate) fn is_literal_member_key(mk: &MemberKey<'_>) -> bool {
    match mk {
        MemberKey::Bareword { .. } => true,
        MemberKey::Value { .. } => true,
        MemberKey::Type1 { t1, .. } => {
            t1.operator.is_none()
                && matches!(
                    t1.type2,
                    Type2::UintValue { .. } | Type2::IntValue { .. } | Type2::TextValue { .. }
                )
        }
        MemberKey::NonMemberKey { .. } => false,
    }
}

/// Field-name counts for one array group choice. Names claimed more
/// than once stay positional. Spliced group rules contribute once per
/// splice chain (schema walk on the heap).
fn choice_label_counts<'a>(
    rules: &RuleIndex<'a>,
    choice: &'a GroupChoice<'a>,
) -> HashMap<String, usize> {
    /// Entry run being counted, and splice source rule if any.
    struct Run<'a> {
        entries: std::vec::IntoIter<&'a GroupEntry<'a>>,
        spliced_from: Option<&'a str>,
    }

    let mut counts = HashMap::new();
    let mut open: HashSet<&'a str> = HashSet::new();
    let mut runs: Vec<Run<'a>> = vec![Run {
        entries: flatten_choice(choice).into_iter(),
        spliced_from: None,
    }];
    while let Some(run) = runs.last_mut() {
        let Some(ge) = run.entries.next() else {
            if let Some(name) = runs.pop().and_then(|run| run.spliced_from) {
                open.remove(name);
            }
            continue;
        };
        match ge {
            GroupEntry::ValueMemberKey { ge, .. } => {
                if let Some(n) = ge.member_key.as_ref().and_then(bareword_name) {
                    *counts.entry(n.to_string()).or_insert(0) += 1;
                }
            }
            GroupEntry::TypeGroupname { ge, .. } => {
                let name = ge.name.ident;
                if let Some(Rule::Group { rule, .. }) = rules.get(name) {
                    // Spliced group rule contributes its members.
                    if open.insert(name) {
                        let mut spliced = Vec::new();
                        flatten_entry(&rule.entry, &mut spliced);
                        runs.push(Run {
                            entries: spliced.into_iter(),
                            spliced_from: Some(name),
                        });
                    }
                    continue;
                }
                *counts.entry(name.to_string()).or_insert(0) += 1;
            }
            GroupEntry::InlineGroup { .. } => {}
        }
    }
    counts
}

/// True if object form would lose info (complex / repeated / colliding
/// keys) → use `@entries`.
pub(crate) fn map_needs_entries(entries: &[(CborValue, CborValue)]) -> bool {
    let mut seen: HashSet<String> = HashSet::with_capacity(entries.len());
    for (k, _) in entries {
        if !is_simple_cbor_key(k) {
            return true;
        }
        if !seen.insert(json_key(k)) {
            return true;
        }
    }
    false
}

/// True if `key` flattens to a JSON object key (else `@entries`).
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

/// Placeholder field name for an absent required member.
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

// ============================================================
// Accept tests — does a value fit a type?
// ============================================================
// Accept helpers: schema-only recursion (no data descent); native stack OK.

/// Numeric form of a CDDL literal or CBOR value (for ranges/controls).
#[derive(Clone, Copy, PartialEq, Debug)]
enum Num {
    Int(i128),
    Float(f64),
}

impl Num {
    fn as_f64(self) -> f64 {
        match self {
            Num::Int(i) => i as f64,
            Num::Float(f) => f,
        }
    }

    fn as_int(self) -> Option<i128> {
        match self {
            Num::Int(i) => Some(i),
            Num::Float(_) => None,
        }
    }
}

fn cmp_num(a: Num, b: Num) -> Option<Ordering> {
    match (a, b) {
        (Num::Int(x), Num::Int(y)) => Some(x.cmp(&y)),
        _ => a.as_f64().partial_cmp(&b.as_f64()),
    }
}

/// Numeric CBOR value as `i128`, or `None` if not comparable.
fn numeric_value(v: &CborValue) -> Option<Num> {
    match v {
        CborValue::Integer(i) => Some(Num::Int((*i).into())),
        CborValue::Float(f) => Some(Num::Float(*f)),
        CborValue::Tag(2, inner) => match inner.as_ref() {
            CborValue::Bytes(b) => bytes_to_u128(b)
                .and_then(|m| i128::try_from(m).ok())
                .map(Num::Int),
            _ => None,
        },
        CborValue::Tag(3, inner) => match inner.as_ref() {
            CborValue::Bytes(b) => bytes_to_u128(b)
                .and_then(|m| i128::try_from(m).ok())
                .map(|m| Num::Int(-m - 1)),
            _ => None,
        },
        _ => None,
    }
}

impl<'a> Mapper<'a> {
    /// JSON field name if `cbor_key` matches `mk`, else `None`.
    /// Literals use their text; type keys (`t =>`) use the key's value.
    /// Rule-ref chain against the key starts fresh.
    fn try_match_member_key(&self, mk: &'a MemberKey<'a>, cbor_key: &CborValue) -> Option<String> {
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
                // Bare literal key (not `3 .. 255 =>` range form).
                if t1.operator.is_none() {
                    use cddl::ast::Type2 as T2;
                    match &t1.type2 {
                        T2::UintValue { value, .. } => {
                            return match cbor_key {
                                CborValue::Integer(i)
                                    if u64::try_from(*i).ok() == Some(*value as u64) =>
                                {
                                    Some(value.to_string())
                                }
                                _ => None,
                            };
                        }
                        T2::IntValue { value, .. } => {
                            return match cbor_key {
                                CborValue::Integer(i) if i128::from(*i) == *value as i128 => {
                                    Some(value.to_string())
                                }
                                _ => None,
                            };
                        }
                        T2::TextValue { value, .. } => {
                            return match cbor_key {
                                CborValue::Text(s) if s == value.as_ref() => {
                                    Some(value.as_ref().to_string())
                                }
                                _ => None,
                            };
                        }
                        _ => {}
                    }
                }
                // Type-keyed: accept conforming keys; field = key value.
                if self.type1_accepts(t1, cbor_key, 0) {
                    Some(json_key(cbor_key))
                } else {
                    None
                }
            }
            MemberKey::NonMemberKey { .. } => None,
        }
    }

    fn type_accepts(&self, ty: &'a Type<'a>, value: &CborValue, hops: usize) -> bool {
        if self.refused() {
            return false;
        }
        for choice in &ty.type_choices {
            if self.type1_accepts(&choice.type1, value, hops) {
                return true;
            }
        }
        false
    }

    fn type1_accepts(&self, t1: &'a Type1<'a>, value: &CborValue, hops: usize) -> bool {
        let Some(op) = &t1.operator else {
            return self.type2_accepts(&t1.type2, value, hops);
        };
        match &op.operator {
            RangeCtlOp::RangeOp { is_inclusive, .. } => {
                self.range_accepts(&t1.type2, &op.type2, *is_inclusive, value)
            }
            RangeCtlOp::CtlOp { ctrl, .. } => {
                self.control_accepts(&t1.type2, ctrl, &op.type2, value, hops)
            }
        }
    }

    /// Range check: `..` inclusive, `...` upper-exclusive.
    fn range_accepts(
        &self,
        lower: &'a Type2<'a>,
        upper: &'a Type2<'a>,
        inclusive: bool,
        value: &CborValue,
    ) -> bool {
        let Some(v) = numeric_value(value) else {
            return false;
        };
        let (Some(lo), Some(hi)) = (self.literal_bound(lower, 0), self.literal_bound(upper, 0))
        else {
            // Unevaluable bound: still accept numerics.
            return true;
        };
        let above = matches!(
            cmp_num(v, lo),
            Some(Ordering::Greater) | Some(Ordering::Equal)
        );
        let below = match cmp_num(v, hi) {
            Some(Ordering::Less) => true,
            Some(Ordering::Equal) => inclusive,
            _ => false,
        };
        above && below
    }

    fn control_accepts(
        &self,
        target: &'a Type2<'a>,
        ctrl: &ControlOperator,
        controller: &'a Type2<'a>,
        value: &CborValue,
        hops: usize,
    ) -> bool {
        if !self.type2_accepts(target, value, hops) {
            return false;
        }
        match ctrl {
            ControlOperator::SIZE => self.size_accepts(controller, value),
            ControlOperator::LT
            | ControlOperator::LE
            | ControlOperator::GT
            | ControlOperator::GE => {
                let (Some(v), Some(b)) = (numeric_value(value), self.literal_bound(controller, 0))
                else {
                    // Unevaluable control: keep slot (target already gated).
                    return true;
                };
                match cmp_num(v, b) {
                    Some(o) => match ctrl {
                        ControlOperator::LT => o == Ordering::Less,
                        ControlOperator::LE => o != Ordering::Greater,
                        ControlOperator::GT => o == Ordering::Greater,
                        _ => o != Ordering::Less,
                    },
                    None => false,
                }
            }
            ControlOperator::EQ => self.type2_accepts(controller, value, hops),
            ControlOperator::NE => !self.type2_accepts(controller, value, hops),
            ControlOperator::AND | ControlOperator::WITHIN => {
                self.type2_accepts(controller, value, hops)
            }
            // `.cbor`/`.cborseq`/`.default` and unevaluated controls
            // (`.regexp`/…) accept on target type alone.
            _ => true,
        }
    }

    /// `.size` on bytes/text length or uint byte-width.
    fn size_accepts(&self, controller: &'a Type2<'a>, value: &CborValue) -> bool {
        let Some((min, max)) = self.size_bounds(controller) else {
            return true;
        };
        match value {
            CborValue::Bytes(b) => {
                let n = b.len() as i128;
                n >= min && n <= max
            }
            CborValue::Text(s) => {
                let n = s.len() as i128;
                n >= min && n <= max
            }
            CborValue::Integer(_) | CborValue::Tag(2, _) | CborValue::Tag(3, _) => {
                let Some(Num::Int(v)) = numeric_value(value) else {
                    return false;
                };
                if v < 0 || max < 0 {
                    return false;
                }
                if max >= 16 {
                    return true;
                }
                v < (1i128 << (8 * max as u32))
            }
            _ => false,
        }
    }

    /// `.size` controller as `(min, max)`; bare `N` means exactly N.
    fn size_bounds(&self, controller: &'a Type2<'a>) -> Option<(i128, i128)> {
        if let Type2::ParenthesizedType { pt, .. } = controller {
            if pt.type_choices.len() != 1 {
                return None;
            }
            let t1 = &pt.type_choices[0].type1;
            if let Some(op) = &t1.operator {
                if let RangeCtlOp::RangeOp { is_inclusive, .. } = &op.operator {
                    let lo = self.literal_bound(&t1.type2, 0)?.as_int()?;
                    let hi = self.literal_bound(&op.type2, 0)?.as_int()?;
                    return Some((lo, if *is_inclusive { hi } else { hi - 1 }));
                }
                return None;
            }
            let n = self.literal_bound(&t1.type2, 0)?.as_int()?;
            return Some((n, n));
        }
        let n = self.literal_bound(controller, 0)?.as_int()?;
        Some((n, n))
    }

    /// Resolve a range/control operand to a number (follow type aliases).
    fn literal_bound(&self, t2: &'a Type2<'a>, depth: usize) -> Option<Num> {
        if depth > 32 {
            return None;
        }
        match t2 {
            Type2::UintValue { value, .. } => Some(Num::Int(*value as i128)),
            Type2::IntValue { value, .. } => Some(Num::Int(*value as i128)),
            Type2::FloatValue { value, .. } => Some(Num::Float(*value)),
            Type2::ParenthesizedType { pt, .. } => self.single_choice_bound(pt, depth + 1),
            Type2::Typename {
                ident,
                generic_args,
                ..
            } => {
                if generic_args.is_none() {
                    if let Some(binding) = self.lookup_binding(ident.ident) {
                        return self.in_binding_scope(binding, |t1| {
                            if t1.operator.is_none() {
                                self.literal_bound(&t1.type2, depth + 1)
                            } else {
                                None
                            }
                        });
                    }
                }
                match self.rules.get(ident.ident) {
                    Some(Rule::Type { rule, .. }) => {
                        self.single_choice_bound(&rule.value, depth + 1)
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn single_choice_bound(&self, ty: &'a Type<'a>, depth: usize) -> Option<Num> {
        if ty.type_choices.len() != 1 {
            return None;
        }
        let t1 = &ty.type_choices[0].type1;
        if t1.operator.is_some() {
            return None;
        }
        self.literal_bound(&t1.type2, depth)
    }

    fn type2_accepts(&self, t2: &'a Type2<'a>, value: &CborValue, hops: usize) -> bool {
        match t2 {
            Type2::Typename {
                ident,
                generic_args,
                ..
            } => self.typename_accepts(ident.ident, generic_args.as_ref(), value, hops),
            Type2::Unwrap {
                ident,
                generic_args,
                ..
            } => self.typename_accepts(ident.ident, generic_args.as_ref(), value, hops),
            Type2::Any { .. } => true,
            Type2::ParenthesizedType { pt, .. } => self.type_accepts(pt, value, hops),
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
            Type2::FloatValue { value: v, .. } => matches!(
                value,
                CborValue::Float(f) if (*f - *v).abs() < f64::EPSILON
            ),
            Type2::UTF8ByteString { value: v, .. }
            | Type2::B16ByteString { value: v, .. }
            | Type2::B64ByteString { value: v, .. } => matches!(
                value,
                CborValue::Bytes(b) if b.as_slice() == v.as_ref()
            ),
            Type2::Map { .. } => matches!(value, CborValue::Map(_)),
            Type2::Array { .. } => matches!(value, CborValue::Array(_)),
            Type2::TaggedData { tag, .. } => match value {
                CborValue::Tag(n, _) => tag_matches(tag.as_ref(), *n),
                _ => false,
            },
            Type2::ChoiceFromGroup { ident, .. } => {
                self.try_enum_from_group(value, ident.ident).is_some()
            }
            _ => false,
        }
    }

    fn typename_accepts(
        &self,
        name: &str,
        generic_args: Option<&'a GenericArgs<'a>>,
        value: &CborValue,
        hops: usize,
    ) -> bool {
        if generic_args.is_none() {
            if let Some(binding) = self.lookup_binding(name) {
                let Some(_hop) = self.substitute() else {
                    return false;
                };
                return self.in_binding_scope(binding, |t1| self.type1_accepts(t1, value, hops));
            }
        }
        if let Some(b) = prelude_accepts(name, value) {
            return b;
        }
        match self.rules.get(name) {
            Some(r) => match r {
                Rule::Type { rule, .. } => {
                    let Some(_guard) = self.enter(&self.accepting, addr(r), addr(value), hops)
                    else {
                        return false;
                    };
                    let _scope = self.enter_scope(&rule.generic_params, generic_args);
                    self.type_accepts(&rule.value, value, hops + 1)
                }
                // Group rule cannot fill a type-position slot.
                Rule::Group { .. } => false,
            },
            None => false,
        }
    }
}

/// RFC 8610 prelude names (not useful as field labels).
fn is_prelude_name(name: &str) -> bool {
    matches!(
        name,
        "any"
            | "uint"
            | "unsigned"
            | "biguint"
            | "integer"
            | "nint"
            | "bignint"
            | "int"
            | "bigint"
            | "number"
            | "float"
            | "float16"
            | "float32"
            | "float64"
            | "float16-32"
            | "float32-64"
            | "bstr"
            | "bytes"
            | "tstr"
            | "text"
            | "bool"
            | "false"
            | "true"
            | "null"
            | "nil"
            | "undefined"
    )
}

/// Prelude accept; `None` → caller should try user rules.
fn prelude_accepts(name: &str, value: &CborValue) -> Option<bool> {
    Some(match name {
        "any" => true,
        "uint" | "unsigned" | "biguint" | "integer" => {
            matches!(value, CborValue::Integer(_)) || is_uint_bignum_tag(value)
        }
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

/// Prelude scalars (`any` is handled in [`Mapper::prelude`]).
fn try_prelude(value: &CborValue, name: &str) -> Option<Value> {
    match (name, value) {
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
        ("tstr", CborValue::Text(s)) | ("text", CborValue::Text(s)) => {
            Some(Value::String(s.clone()))
        }
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

pub(crate) fn specialise_known_tag(tag: u64, payload: &CborValue) -> Option<Value> {
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

/// Stringify a CBOR key for a JSON field (`0x` prefix on bytes).
/// Collisions (`1` vs `"1"`) are gated by `map_needs_entries`.
pub(crate) fn json_key(k: &CborValue) -> String {
    match k {
        CborValue::Text(s) => s.clone(),
        CborValue::Integer(i) => {
            let v: i128 = (*i).into();
            v.to_string()
        }
        CborValue::Bytes(b) => format!("0x{}", hex::encode(b)),
        CborValue::Bool(b) => b.to_string(),
        CborValue::Null => "null".into(),
        CborValue::Float(f) => f.to_string(),
        CborValue::Simple(n) => format!("simple({})", n),
        CborValue::Array(_) => "@array".into(),
        CborValue::Map(_) => "@map".into(),
        CborValue::Tag(n, _) => format!("@tag{}", n),
    }
}

/// `{"@entries": pairs}` by moving `pairs` (avoid `json!` deep copy).
fn entries_object(pairs: Vec<Value>) -> Value {
    let mut obj = Map::new();
    obj.insert("@entries".into(), Value::Array(pairs));
    Value::Object(obj)
}

/// One `@entries` pair `{key, value, match}`, moved in.
fn entry_pair(key: Value, value: Value, via: &str, label: Value) -> Value {
    let mut matched = Map::new();
    matched.insert("via".into(), Value::String(via.to_string()));
    matched.insert("label".into(), label);
    let mut obj = Map::new();
    obj.insert("key".into(), key);
    obj.insert("value".into(), value);
    obj.insert("match".into(), Value::Object(matched));
    Value::Object(obj)
}

/// The scalar a leaf of a raw subtree becomes.
fn raw_scalar(v: &CborValue) -> Value {
    match v {
        CborValue::Null => Value::Null,
        CborValue::Bool(b) => Value::Bool(*b),
        CborValue::Integer(i) => int_to_json(*i),
        CborValue::Float(f) => Number::from_f64(*f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        CborValue::Text(s) => Value::String(s.clone()),
        CborValue::Bytes(b) => Value::String(hex::encode(b)),
        CborValue::Simple(n) => json!({"@simple": n}),
        CborValue::Array(_) | CborValue::Map(_) | CborValue::Tag(..) => {
            unreachable!("containers are built by frames")
        }
    }
}

/// Open container while building a raw subtree.
enum RawFrame<'c, 'g> {
    Array {
        items: std::slice::Iter<'c, CborValue>,
        built: Vec<Value>,
        _level: limits::DescentGuard<'g>,
    },
    /// Object form: one child per entry, the value.
    MapObject {
        entries: std::slice::Iter<'c, (CborValue, CborValue)>,
        built: Map<String, Value>,
        key: Option<String>,
        _level: limits::DescentGuard<'g>,
    },
    /// `@entries` form: two children per entry, the key then the value.
    MapEntries {
        entries: std::slice::Iter<'c, (CborValue, CborValue)>,
        built: Vec<Value>,
        key: Option<Value>,
        _level: limits::DescentGuard<'g>,
    },
    Tag {
        number: u64,
        inner: Option<&'c CborValue>,
        _level: limits::DescentGuard<'g>,
    },
}

impl<'c, 'g> RawFrame<'c, 'g> {
    /// The next child to build, or `None` once every child is in.
    fn next_child(&mut self) -> Option<&'c CborValue> {
        match self {
            RawFrame::Array { items, .. } => items.next(),
            RawFrame::MapObject { entries, key, .. } => {
                let (k, v) = entries.next()?;
                *key = Some(json_key(k));
                Some(v)
            }
            RawFrame::MapEntries { entries, key, .. } => {
                if key.is_some() {
                    let (_, v) = entries.next()?;
                    Some(v)
                } else {
                    entries.as_slice().first().map(|(k, _)| k)
                }
            }
            RawFrame::Tag { inner, .. } => inner.take(),
        }
    }

    fn take(&mut self, child: Value) {
        match self {
            RawFrame::Array { built, .. } => built.push(child),
            RawFrame::MapObject { built, key, .. } => {
                built.insert(key.take().expect("a key precedes its value"), child);
            }
            RawFrame::MapEntries { built, key, .. } => match key.take() {
                None => *key = Some(child),
                Some(key) => built.push(entry_pair(key, child, "unmatched", Value::Null)),
            },
            RawFrame::Tag { .. } => unreachable!("a tag takes its payload as it closes"),
        }
    }

    fn close(self, payload: Option<Value>) -> Value {
        match self {
            RawFrame::Array { built, .. } => Value::Array(built),
            RawFrame::MapObject { built, .. } => Value::Object(built),
            RawFrame::MapEntries { built, .. } => entries_object(built),
            RawFrame::Tag { number, .. } => {
                let mut obj = Map::new();
                obj.insert("@tag".into(), Value::Number(number.into()));
                obj.insert("@value".into(), payload.unwrap_or(Value::Null));
                Value::Object(obj)
            }
        }
    }
}

impl Mapper<'_> {
    /// Unlabelled fallback (~`cbor_to_json`: hex bytes, `{@tag,@value}`).
    /// Heap-built; levels charged. Budget failure → refusal, not partial.
    fn raw(&self, root: &CborValue) -> Value {
        let mut open: Vec<RawFrame<'_, '_>> = Vec::new();
        let mut next: Option<&CborValue> = Some(root);
        loop {
            let mut built: Option<Value> = None;
            if let Some(value) = next.take() {
                let frame = match value {
                    CborValue::Array(items) => self.raw_level().map(|level| RawFrame::Array {
                        items: items.iter(),
                        built: Vec::with_capacity(items.len()),
                        _level: level,
                    }),
                    CborValue::Map(entries) => self.raw_level().map(|level| {
                        // Raw maps: colliding keys still need `@entries`.
                        if map_needs_entries(entries) {
                            RawFrame::MapEntries {
                                entries: entries.iter(),
                                built: Vec::with_capacity(entries.len()),
                                key: None,
                                _level: level,
                            }
                        } else {
                            RawFrame::MapObject {
                                entries: entries.iter(),
                                built: Map::new(),
                                key: None,
                                _level: level,
                            }
                        }
                    }),
                    CborValue::Tag(number, inner) => self.raw_level().map(|level| RawFrame::Tag {
                        number: *number,
                        inner: Some(inner),
                        _level: level,
                    }),
                    scalar => {
                        built = Some(raw_scalar(scalar));
                        None
                    }
                };
                match frame {
                    Some(frame) => open.push(frame),
                    None => built = built.or(Some(Value::Null)),
                }
            }
            loop {
                let Some(top) = open.last_mut() else {
                    return built.unwrap_or(Value::Null);
                };
                if let Some(value) = built.take() {
                    if let RawFrame::Tag { .. } = top {
                        let frame = open.pop().expect("the tag frame is open");
                        built = Some(frame.close(Some(value)));
                        continue;
                    }
                    top.take(value);
                }
                match top.next_child() {
                    Some(child) => {
                        next = Some(child);
                        break;
                    }
                    None => {
                        let frame = open.pop().expect("the frame is open");
                        built = Some(frame.close(None));
                    }
                }
            }
        }
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
        // {0:1, 1:42} with schema labels inputs/outputs.
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
        // Uint literal key → string field; semantic names need type rules.
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
            "c07432303230 2d30312d30315430303a30303a30305a"
                .replace(' ', "")
                .as_str(),
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
        // Duplicate literal key 0 → `@entries`.
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
        let out = run(
            schema,
            "output",
            "824401020304 0a".replace(' ', "").as_str(),
        );
        assert_eq!(out, json!({"address": "01020304", "amount": 10}));
    }

    #[test]
    fn unknown_root_rule_errors_out() {
        let err = decode_cbor_against_cddl(b"\x01", "x = int", "no_such")
            .err()
            .expect("expected error");
        assert_eq!(err.kind(), "missing_rule", "{}", err);
        assert!(err.message().contains("no_such"), "{}", err);
    }

    #[test]
    fn bad_cbor_errors_out() {
        let err = decode_cbor_against_cddl(&[0x18], "x = int", "x")
            .err()
            .expect("expected error");
        assert_eq!(err.kind(), "input_parse", "{}", err);
        assert!(err.message().to_lowercase().contains("cbor"), "{}", err);
    }

    #[test]
    fn cardano_style_named_record_using_type_rules_for_field_labels() {
        // Bareword-labelled body/inputs/outputs/fee + is_valid.
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
        // [body{inputs,outputs,fee}, true]
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

    /// Real Conway tx hex (one in, two out, fee, aux-hash, one vkey).
    const PREVIEW_TX: &str = "84a400d901028182582016b6ee8c812f8b1c9c643ee3828f50fdcf0f174625bbd6e947ba77b12374094a00018282583900aef399a405edd6797117a3db6653e1a230e1f6f91dd5badb77f2be3720fc45da826093ae8ed2e4f0f81c4f5ea9b6f0dda561c974cfc6355d1a000f424082583900f275cb75d82f737c49280039947e484919ee044c82c2e4ceaf2f2d87984c3eb5c8a01b4b53c7cec4cfc139345a28d24a6ec918873c459add1a48b7d00d021a00030d40075820bdaa99eb158414dea0a91d6c727e2268574b23efe6e08ab3b841abe8059a030ca100d9010281825820f8f5750132a13473240e318dd36eccd70083e8f08ac589c74ebe776f43e9401d58401e149e081ff497d7f97c3ef7427a916d1b0632c6eb98bb54b040aca413a2ad94273291c9b63b2802083c72b0cfe03eef2b55f767ecf32dba894dd59701076409f5d90103a0";

    /// Ada-only Conway subset without generics (tagged sets, nested
    /// arrays, numbered body keys).
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
        for k in ["body", "witness_set", "is_valid", "aux"] {
            assert!(out.get(k).is_some(), "missing {} in {}", k, out);
        }
        assert_eq!(out["is_valid"], json!(true));

        // Body keys stay numeric strings (no invented semantic names).
        let body = &out["body"];
        assert_eq!(body["2"], json!(200_000)); // fee
        assert!(body.get("0").is_some(), "no inputs key in {}", body);
        assert!(body.get("1").is_some(), "no outputs key in {}", body);

        // Outputs labelled as [address, amount].
        let outputs = body["1"].as_array().expect("outputs array");
        assert_eq!(outputs.len(), 2);
        let first = &outputs[0];
        assert!(first.get("address").is_some(), "{}", first);
        assert!(first.get("amount").is_some(), "{}", first);
        assert_eq!(first["amount"], json!(1_000_000));
    }

    /// Same tx with generic `set<a> = #6.258([* a])`.
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

    /// The full ledger schema parses and maps end-to-end.
    #[test]
    fn record_maps_against_the_full_ledger_schema() {
        let cddl = crate::cbor::test_fixtures::ledger_cddl();
        let bytes = crate::cbor::test_fixtures::record_doc();
        let out = decode_cbor_against_cddl(&bytes, cddl, "record")
            .expect("the ledger schema should parse and map");
        // Named members of the root array become labels.
        assert!(out.get("body").is_some(), "missing body label in {}", out);
        assert!(
            out.get("witness").is_some(),
            "missing witness label in {}",
            out
        );
        // Unnamed slots that reference a rule (`ref = [hash32, index]`)
        // are labelled by the rule's name.
        let first_ref = &out["body"]["0"]["@value"][0];
        assert!(
            first_ref.get("hash32").is_some(),
            "missing hash32 label in {}",
            first_ref
        );
        assert!(
            first_ref.get("index").is_some(),
            "missing index label in {}",
            first_ref
        );
        eprintln!(
            "record (ledger schema) ⇒\n{}",
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
        // set<transaction_input> unwraps tag 258 → labelled inputs.
        let inputs_field = &body["0"];
        // Accept unwrapped array or {"@tag":258,...} with labelled inputs.
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
        // bstr .cbor [a:int, b:int] → decode and label inner.
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
        // Inner mismatch → raw hex, not crash.
        let schema = "x = bstr .cbor uint";
        // 41 18 = bstr of invalid CBOR.
        let bytes = hex::decode("4118").unwrap();
        let out = decode_cbor_against_cddl(&bytes, schema, "x").unwrap();
        assert_eq!(out, json!("18"), "fall-back should be raw hex");
    }

    #[test]
    fn unwrap_resolves_into_referenced_rule_body() {
        // `~base` unwraps into labelled [a, b].
        let schema = "wrapped = ~base\n\
                      base = [a: int, b: int]";
        // 82 01 02 = [1, 2]
        let bytes = hex::decode("820102").unwrap();
        let out = decode_cbor_against_cddl(&bytes, schema, "wrapped").unwrap();
        assert_eq!(out, json!({"a": 1, "b": 2}));
    }

    #[test]
    fn generic_typegroupname_in_array_passes_args_to_inner_type_with_labels() {
        // wrapper<a>=a must pass args; else inner stays raw [[k,v]].
        let schema = "outer = [* wrapper<inner>]\n\
                      wrapper<a> = a\n\
                      inner = [k: int, v: int]";
        // 81 82 01 02 = [[1, 2]]
        let out = run(schema, "outer", "8182010 2".replace(' ', "").as_str());
        assert_eq!(out, json!([{"k": 1, "v": 2}]));
    }

    #[test]
    fn generic_typegroupname_in_array_passes_args_through() {
        // [* set<int>]: generic_args must reach `set`'s body.
        let schema = "outer = [* set<int>]\nset<a> = [* a]";
        // 82 82 01 02 82 03 04 = [[1, 2], [3, 4]]
        let out = run(schema, "outer", "82820102820304");
        assert_eq!(out, json!([[1, 2], [3, 4]]));
    }

    #[test]
    fn map_with_duplicate_literal_keys_uses_entries_form() {
        // Duplicate keys → `@entries` (wire order). a2 6161 01 6161 02
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
        // Three duplicate key 0 → `@entries` wire order.
        let bytes = hex::decode("a3 00 01 00 02 00 03".replace(' ', "").as_str()).unwrap();
        let out = decode_cbor_against_cddl(&bytes, "thing = {0: int}", "thing").unwrap();
        let entries = out["@entries"].as_array().unwrap();
        assert_eq!(entries.len(), 3);
        let values: Vec<_> = entries.iter().map(|e| e["value"].clone()).collect();
        assert_eq!(values, vec![json!(1), json!(2), json!(3)]);
    }

    #[test]
    fn map_without_duplicates_keeps_object_form() {
        // Simple unique keys → object form.
        let bytes = hex::decode("a26161 01 6162 02".replace(' ', "").as_str()).unwrap();
        let out = decode_cbor_against_cddl(&bytes, "thing = {a: int, b: int}", "thing").unwrap();
        assert_eq!(out, json!({"a": 1, "b": 2}));
    }

    #[test]
    fn map_with_complex_key_uses_entries_fallback() {
        // Complex array keys → `@entries`.
        let schema = "m = { [int, int] => tstr }";
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

    /// Ledger schema: the type-keyed `stock` map labels bucket/label.
    #[test]
    fn record_stock_field_uses_actual_keys_not_extra_bucket() {
        let cddl = crate::cbor::test_fixtures::ledger_cddl();
        let bytes = crate::cbor::test_fixtures::record_doc();
        let out = decode_cbor_against_cddl(&bytes, cddl, "record").unwrap();
        let stock = out
            .get("body")
            .and_then(|b| b.get("9"))
            .expect("body[9] (stock) must be present in this fixture");
        assert!(
            stock.get("@extra").is_none(),
            "stock should not leak into @extra, got {}",
            stock
        );
        // One 28-byte bucket → `0x` + 56 hex field name.
        let stock_obj = stock.as_object().expect("stock should be a map");
        let bucket_keys: Vec<&String> = stock_obj.keys().collect();
        assert_eq!(bucket_keys.len(), 1, "expected one bucket in stock");
        let bucket = bucket_keys[0];
        assert!(
            bucket.starts_with("0x") && bucket.len() == 2 + 56,
            "bucket key should be 0x<28 bytes hex>, got {:?}",
            bucket
        );
        // Empty label → quantity under key `0x`.
        let labels = stock[bucket].as_object().expect("inner label map");
        assert_eq!(labels.len(), 3, "expected three labels in {:?}", labels);
        assert!(
            labels.contains_key("0x"),
            "expected `0x` (empty label) in {:?}",
            labels
        );
        assert_eq!(labels["0x"], json!(-42));
    }

    #[test]
    fn extras_are_preserved_as_at_extra_bucket() {
        // a2 00 01 02 03 = {0: 1, 2: 3}. Schema only covers key 0.
        let out = run("t = {0: uint}", "t", "a200010203");
        assert_eq!(out, json!({"0": 1, "@extra": {"2": 3}}));
    }

    // ========================================================
    // Generics
    // ========================================================

    #[test]
    fn set_generic_chained_through_multiple_rules() {
        // Alias chain into set<a>; tag 258 over two hashes.
        let schema = "
            hash       = bstr
            set<a>     = #6.258([* a])
            tagged_set = set<hash>
            wrapper    = tagged_set
        ";
        let cbor = "d9010282 4401020304 440a0b0c0d".replace(' ', "");
        let out = run(schema, "wrapper", &cbor);
        // Tag unwrap → array of hashes (or {@tag,@value} fallback).
        let arr = out
            .as_array()
            .cloned()
            .or_else(|| out.get("@value").and_then(Value::as_array).cloned())
            .expect("expected an array of hashes");
        assert_eq!(arr, vec![json!("01020304"), json!("0a0b0c0d")]);
    }

    #[test]
    fn nested_generic_pair_bstr_uint() {
        // pair<k,v>: bound params are not field labels → positional.
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
        // pair with named slots [key, value].
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
        // outer<x>=inner<x>; inner<y>=[y,y]. Bound params stay positional.
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
        // Choice of {type,value} shapes.
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
        // Nested tags: #6.42(set<a>) with set=#6.258.
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
        // Tag mismatch → raw {"@tag":17,"@value":42}.
        let out = run("x = #6.99(uint)", "x", "d1182a");
        assert_eq!(out, json!({"@tag": 17, "@value": 42}));
    }

    // ========================================================
    // Maps (more variants)
    // ========================================================

    #[test]
    fn map_keys_mixing_bareword_numeric_and_text_literals() {
        // Mixed bareword / int / text keys.
        let schema = r#"t = {a: uint, 5: bstr, "k": tstr}"#;
        let cbor = "a36161010541026 16b6176".replace(' ', "");
        let out = run(schema, "t", &cbor);
        assert_eq!(out, json!({"a": 1, "5": "02", "k": "v"}));
    }

    #[test]
    fn map_keys_with_cut_indicator() {
        // Cut `"foo" ^ => uint` still labels; bar may be `@extra`.
        let schema = r#"t = { "foo" ^ => uint, * tstr => any }"#;
        let cbor = "a263666f6f0163626172 6178".replace(' ', "");
        let out = run(schema, "t", &cbor);
        assert_eq!(out["foo"], json!(1));
        // Type1-key glob not named yet; data must still be preserved.
        let preserved =
            out.get("bar").is_some() || out.get("@extra").and_then(|e| e.get("bar")).is_some();
        assert!(preserved, "lost the 'bar' entry: {}", out);
    }

    #[test]
    fn map_open_ended_tstr_to_any_falls_back_to_extra() {
        // `* tstr => any` not collected yet → `@extra` fallback.
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
        // Required/optional + duplicate `9 =>` → `@entries` order.
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
        // Optional c absent: [1, 2].
        let schema = "t = [a: uint, b: uint, ? c: uint]";
        let out = run(schema, "t", "820102");
        assert_eq!(out, json!({"a": 1, "b": 2}));
    }

    #[test]
    fn positional_array_with_optional_present() {
        // Optional c present.
        let schema = "t = [a: uint, b: uint, ? c: uint]";
        let out = run(schema, "t", "83010203");
        assert_eq!(out, json!({"a": 1, "b": 2, "c": 3}));
    }

    #[test]
    fn array_one_or_more_homogeneous_tail() {
        // head + repeating tail → `@positional` for unnamed.
        let schema = "t = [head: uint, + uint]";
        let out = run(schema, "t", "8401020304");
        assert_eq!(out["head"], json!(1));
        let pos = out.get("@positional").expect("expected @positional");
        assert_eq!(pos, &json!([2, 3, 4]));
    }

    #[test]
    fn array_mixed_named_and_unnamed_entries() {
        // Named/unnamed mix → `@positional` for middle.
        let schema = "t = [a: uint, uint, b: uint]";
        let out = run(schema, "t", "83010203");
        assert_eq!(out["a"], json!(1));
        assert_eq!(out["b"], json!(3));
        let pos = out.get("@positional").expect("@positional present");
        assert_eq!(pos, &json!([2]));
    }

    #[test]
    fn empty_array_against_zero_or_more_yields_empty_json_array() {
        // Empty homogeneous array.
        let out = run("t = [* uint]", "t", "80");
        assert_eq!(out, json!([]));
    }

    // ========================================================
    // Unwrap
    // ========================================================

    #[test]
    fn unwrap_referencing_rule_with_multiple_choices() {
        // `~base` unwraps type choice to tstr branch.
        let schema = "
            base    = uint / tstr
            wrapped = ~base
        ";
        let out = run(schema, "wrapped", "63686579");
        assert_eq!(out, json!("hey"));
    }

    #[test]
    fn unwrap_referenced_from_inside_a_generic() {
        // generic<a>=[a,a]; wrap=generic<~base>. Bound `a` stays positional.
        let schema = "
            base       = [b: bstr]
            generic<a> = [a, a]
            wrap       = generic<~base>
        ";
        let cbor = "8281 4401020304 81 440a0b0c0d".replace(' ', "");
        let out = run(schema, "wrap", &cbor);
        assert_eq!(out, json!([{"b": "01020304"}, {"b": "0a0b0c0d"}]));
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
        // bstr .cbor #6.0(tstr); payload = tag0 datetime.
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
        assert!(
            matches!(err.kind(), "parse_error" | "missing_rule"),
            "unexpected error: {} {}",
            err.kind(),
            err
        );
    }

    #[test]
    fn malformed_cddl_errors() {
        let err = decode_cbor_against_cddl(b"\x01", "x = = =", "x")
            .err()
            .expect("expected parse error");
        assert_eq!(err.kind(), "parse_error", "{}", err);
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
        let out = run(
            "t = {a: uint, b: uint}",
            "t",
            "bf6161016162 02ff".replace(' ', "").as_str(),
        );
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
        // [coin, multiasset<coin>] value.
        let schema = "
            coin            = uint
            multiasset<a>   = { * bstr => { * bstr => a } }
            value           = coin / [coin, multiasset<coin>]
        ";
        let cbor = "82 1903e8 a1 40 a1 40 05".replace(' ', "");
        let out = run(schema, "value", &cbor);
        // The two slots name two different rules, each used once, so
        // each one becomes a field of its own.
        assert_eq!(out, json!({"coin": 1000, "multiasset": {"0x": {"0x": 5}}}));
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
        // wrapper<pair<uint>>: bound pair slots stay positional arrays.
        let schema = "
            wrapper<a> = [* a]
            pair<x>    = [x, x]
            concrete   = wrapper<pair<uint>>
        ";
        let out = run(
            schema,
            "concrete",
            "8282010282030 4".replace(' ', "").as_str(),
        );
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

    // ========================================================
    // Labelling: a name is only a label when it is unambiguous
    // ========================================================

    fn ledger() -> &'static str {
        crate::cbor::test_fixtures::ledger_cddl()
    }

    #[test]
    fn repeated_rule_ref_slots_keep_every_value() {
        // Duplicate rule name in array → positional (no overwrite).
        let schema = "coin = uint\nt = [coin, coin]";
        assert_eq!(run(schema, "t", "820506"), json!([5, 6]));
    }

    #[test]
    fn single_rule_ref_slot_still_labelled_by_rule_name() {
        // Negative direction for the rule above: a name used once in
        // the group choice is still a label.
        let schema = "coin = uint\nflag = bool\nt = [coin, flag]";
        assert_eq!(run(schema, "t", "8205f5"), json!({"coin": 5, "flag": true}));
    }

    #[test]
    fn repeated_bareword_slots_keep_every_value() {
        // Same rule for bareword member keys inside an array.
        let schema = "t = [a: uint, a: uint]";
        assert_eq!(run(schema, "t", "820506"), json!([5, 6]));
        // A bareword used once still labels.
        let unique = "t = [a: uint, b: uint]";
        assert_eq!(run(unique, "t", "820506"), json!({"a": 5, "b": 6}));
    }

    /// Several slots of one tagged rule: the shape a table of ratios has.
    const THRESHOLDS_CDDL: &str = "
        interval = #6.30([uint, uint])
        five_intervals = [interval, interval, interval, interval, interval]
        ten_intervals = [interval, interval, interval, interval, interval,
                         interval, interval, interval, interval, interval]
        settings_update = { ? 25 : five_intervals }
    ";
    const FIVE_UNIT_INTERVALS: &str = "85d81e82010ad81e82020ad81e82030ad81e82040ad81e82050a";
    const TEN_UNIT_INTERVALS: &str = "8ad81e82010ad81e82020ad81e82030ad81e82040ad81e82050a\
                                      d81e82060ad81e82070ad81e82080ad81e82090ad81e820a0a";

    #[test]
    fn five_slots_of_one_tagged_rule_decode_five_intervals() {
        let out = run(THRESHOLDS_CDDL, "five_intervals", FIVE_UNIT_INTERVALS);
        let arr = out
            .as_array()
            .unwrap_or_else(|| panic!("expected five positional slots, got {}", out));
        assert_eq!(arr.len(), 5, "{}", out);
        assert_ne!(arr[0], arr[4], "all five slots collapsed onto one value");
    }

    #[test]
    fn ten_slots_of_one_tagged_rule_decode_ten_intervals() {
        let out = run(THRESHOLDS_CDDL, "ten_intervals", TEN_UNIT_INTERVALS);
        let arr = out
            .as_array()
            .unwrap_or_else(|| panic!("expected ten positional slots, got {}", out));
        assert_eq!(arr.len(), 10, "{}", out);
        assert_ne!(arr[0], arr[9]);
    }

    #[test]
    fn settings_update_key_25_keeps_all_five_intervals() {
        // The realistic path: the intervals arrive one map level down.
        let cbor = format!("a11819{}", FIVE_UNIT_INTERVALS);
        let out = run(THRESHOLDS_CDDL, "settings_update", &cbor);
        let arr = out["25"]
            .as_array()
            .unwrap_or_else(|| panic!("expected key 25 to be an array, got {}", out));
        assert_eq!(arr.len(), 5, "{}", out);
    }

    #[test]
    fn positional_index_is_within_at_positional_not_the_source_array() {
        // Source slots 0 and 2 are unlabelled; they land at
        // `@positional[0]` and `@positional[1]`, not at 0 and 2.
        let out = run("t = [bool, a: int, tstr, b: int]", "t", "84f505616106");
        assert_eq!(out["@positional"], json!([true, "a"]));
        assert_eq!(out["a"], json!(5));
        assert_eq!(out["b"], json!(6));
    }

    // ========================================================
    // Ranges and control operators decide slot membership
    // ========================================================

    #[test]
    fn range_slot_is_labelled() {
        let schema = "pv = [major: 0 .. 12, minor: uint]";
        assert_eq!(run(schema, "pv", "820900"), json!({"major": 9, "minor": 0}));
    }

    #[test]
    fn out_of_range_value_falls_back_to_raw() {
        // 9 is outside `0 .. 2`, so the slot must not be labelled.
        let out = run("t = [x: 0 .. 2]", "t", "8109");
        assert_eq!(out, json!([9]));
        // In range, it is.
        assert_eq!(run("t = [x: 0 .. 2]", "t", "8102"), json!({"x": 2}));
    }

    #[test]
    fn exclusive_range_excludes_its_upper_bound() {
        assert_eq!(run("t = [x: 0 ... 3]", "t", "8102"), json!({"x": 2}));
        assert_eq!(run("t = [x: 0 ... 3]", "t", "8103"), json!([3]));
    }

    #[test]
    fn range_bound_through_rule_reference() {
        let schema = "lo = 1\nhi = 9\nt = [x: lo .. hi]";
        assert_eq!(run(schema, "t", "8105"), json!({"x": 5}));
        assert_eq!(run(schema, "t", "810a"), json!([10]));
    }

    #[test]
    fn range_with_negative_lower_bound() {
        // -3 is inside `-5 .. 5`; -6 is not.
        let schema = "t = [x: -5 .. 5]";
        assert_eq!(run(schema, "t", "8122"), json!({"x": -3}));
        assert_eq!(run(schema, "t", "8125"), json!([-6]));
    }

    #[test]
    fn two_named_uint_slots_label_mem_and_steps() {
        let out = run(
            "units = [mem: uint, steps: uint]",
            "units",
            "821903e81907d0",
        );
        assert_eq!(out, json!({"mem": 1000, "steps": 2000}));
    }

    #[test]
    fn ledger_redeemer_labels_every_tag_value() {
        // `tag: 0 .. 3` — every one of the four must label.
        for tag in 0..=3u8 {
            let cbor = format!("84{:02x}0001821903e81907d0", tag);
            let out = run(ledger(), "redeemer", &cbor);
            assert_eq!(out["tag"], json!(tag), "tag {} decoded as {}", tag, out);
            assert_eq!(out["index"], json!(0), "{}", out);
            assert_eq!(out["data"], json!(1), "{}", out);
            assert_eq!(out["units"], json!([1000, 2000]), "{}", out);
        }
    }

    #[test]
    fn ledger_redeemer_rejects_a_tag_outside_the_range() {
        // 4 is past `0 .. 3`, so nothing may be labelled.
        let out = run(
            ledger(),
            "redeemer",
            "840400 01821903e81907d0".replace(' ', "").as_str(),
        );
        assert!(
            out.get("tag").is_none(),
            "out-of-range tag was labelled anyway: {}",
            out
        );
    }

    #[test]
    fn size_control_on_bytes_and_text() {
        let schema = "t = [h: bytes .size 4]";
        assert_eq!(run(schema, "t", "814401020304"), json!({"h": "01020304"}));
        assert_eq!(run(schema, "t", "814101"), json!(["01"]));

        let ranged = "t = [s: text .size (0 .. 3)]";
        assert_eq!(run(ranged, "t", "8163616263"), json!({"s": "abc"}));
        assert_eq!(run(ranged, "t", "816461626364"), json!(["abcd"]));
    }

    #[test]
    fn size_control_on_uint_bounds_the_byte_width() {
        let schema = "t = [n: uint .size 4]";
        assert_eq!(run(schema, "t", "811a0000ffff"), json!({"n": 65535}));
        // 0xff00000000 needs five bytes.
        assert_eq!(
            run(schema, "t", "811b000000ff00000000"),
            json!([1_095_216_660_480u64])
        );
    }

    #[test]
    fn comparison_control_bounds_the_value() {
        // `port = uint .le 65535` in the ledger schema.
        assert_eq!(run(ledger(), "port", "1901f4"), json!(500));
        assert_eq!(run(ledger(), "port", "1a00010000"), json!(65536));
        let schema = "t = [p: uint .le 65535]";
        assert_eq!(run(schema, "t", "811901f4"), json!({"p": 500}));
        assert_eq!(run(schema, "t", "811a00010000"), json!([65536]));
    }

    #[test]
    fn unevaluable_control_still_accepts() {
        // `.regexp` unevaluated; target type keeps the label.
        let schema = "t = [x: tstr .regexp \"^a+$\"]";
        assert_eq!(run(schema, "t", "816161"), json!({"x": "a"}));
        // The target type still applies.
        assert_eq!(run(schema, "t", "8101"), json!([1]));
    }

    #[test]
    fn range_member_key_matches_every_key_in_the_range() {
        // `* 3 .. 255 => [* int64]` — the range's lower bound is not
        // the only key it accepts.
        let schema = "tables = { * 3 .. 255 => [* int64] }\n\
                      int64 = -9223372036854775808 .. 9223372036854775807";
        let out = run(schema, "tables", "a118ff820102");
        assert_eq!(out["255"], json!([1, 2]), "{}", out);
        // A key past the range is not claimed by it.
        let out2 = run(
            schema,
            "tables",
            "a11901008201 02".replace(' ', "").as_str(),
        );
        assert_eq!(out2["@extra"]["256"], json!([1, 2]), "{}", out2);
    }

    // ========================================================
    // Occurrence bounds
    // ========================================================

    #[test]
    fn exact_occurrence_consumes_up_to_upper_bound() {
        let schema = "a = {x: uint}\nt = [2*3 a]";
        let out = run(schema, "t", "82a1617801a1617802");
        assert_eq!(out, json!([{"x": 1}, {"x": 2}]));
        assert!(out.get("@extra").is_none(), "{}", out);
    }

    #[test]
    fn exact_occurrence_below_lower_bound_declines() {
        let schema = "t = [3*3 uint, s: tstr]";
        // Three uints then the tstr — matches.
        assert_eq!(
            run(schema, "t", "8401020361 61".replace(' ', "").as_str()),
            json!({"@positional": [1, 2, 3], "s": "a"})
        );
        // Only two uints — the group does not match at all.
        assert_eq!(
            run(schema, "t", "830102616 1".replace(' ', "").as_str()),
            json!([1, 2, "a"])
        );
    }

    #[test]
    fn exact_occurrence_stops_at_its_upper_bound() {
        let schema = "t = [2*2 uint, tail: tstr]";
        assert_eq!(
            run(schema, "t", "8301026161"),
            json!({"@positional": [1, 2], "tail": "a"})
        );
        // A third uint leaves the tail unmatched, so nothing labels.
        assert_eq!(
            run(schema, "t", "84010203 6161".replace(' ', "").as_str()),
            json!([1, 2, 3, "a"])
        );
    }

    #[test]
    fn all_optional_named_entries_absent_stays_an_array() {
        // No field was emitted, so the result is not an object.
        assert_eq!(run("t = [? a: uint, ? b: tstr]", "t", "80"), json!([]));
        // One present makes it an object.
        assert_eq!(
            run("t = [? a: uint, ? b: tstr]", "t", "8101"),
            json!({"a": 1})
        );
    }

    #[test]
    fn one_or_more_requires_at_least_one() {
        let schema = "t = [+ a: uint]";
        assert_eq!(run(schema, "t", "820102"), json!({"a": [1, 2]}));
        // Zero occurrences must not satisfy `+`.
        assert_eq!(run(schema, "t", "80"), json!([]));
    }

    #[test]
    fn fixed_count_array_of_a_range_rule_is_not_split() {
        // `166*166 int64` is one array of 166 numbers, not 166 groups.
        let schema = "tables = { ? 0 : [ 166*166 int64 ], ? 1 : [ 175*175 int64 ] }\n\
                      int64 = -9223372036854775808 .. 9223372036854775807";
        let mut cbor = String::from("a10098a6");
        cbor.push_str(&"01".repeat(166));
        let out = run(schema, "tables", &cbor);
        let arr = out["0"]
            .as_array()
            .unwrap_or_else(|| panic!("cost model split up: {}", out));
        assert_eq!(arr.len(), 166);
        assert!(out.get("@extra").is_none(), "{}", out);
        assert!(
            out["0"].get("int64").is_none(),
            "element type leaked as a field name: {}",
            out["0"]
        );
    }

    // ========================================================
    // Choice strictness
    // ========================================================

    #[test]
    fn map_choice_falls_through_on_missing_key() {
        let out = run("x = { a: uint // b: tstr }", "x", "a161626161");
        assert_eq!(out, json!({"b": "a"}));
        assert!(out.get("@extra").is_none(), "{}", out);
        assert!(out.get("a").is_none(), "{}", out);
    }

    #[test]
    fn map_choice_falls_through_on_wrong_value_type() {
        // The key matches the first alternative but the value doesn't;
        // only the second alternative accounts for the whole map.
        let out = run(
            "x = { a: uint // a: tstr, b: uint }",
            "x",
            "a26161617a616201",
        );
        assert_eq!(out, json!({"a": "z", "b": 1}));
        assert!(out.get("@extra").is_none(), "{}", out);
        // A wrong-typed value must not leave the first alternative's
        // other members behind as placeholders either.
        let out2 = run("x = { a: uint, c: uint // a: tstr }", "x", "a16161617a");
        assert_eq!(out2, json!({"a": "z"}));
    }

    #[test]
    fn map_choice_takes_the_first_alternative_that_fits() {
        // Positive control for the two tests above.
        let out = run("x = { a: uint // b: tstr }", "x", "a1616101");
        assert_eq!(out, json!({"a": 1}));
    }

    #[test]
    fn map_choice_lenient_fallback_preserved() {
        // Data matching no alternative still yields the declarative
        // placeholder plus the `@extra` bucket.
        let out = run("x = { a: uint // b: tstr }", "x", "a1616301");
        assert_eq!(out, json!({"a": null, "@extra": {"c": 1}}));
    }

    #[test]
    fn array_choice_requires_full_consumption() {
        let schema = "x = [a: uint] / [a: uint, b: tstr]";
        assert_eq!(run(schema, "x", "82016161"), json!({"a": 1, "b": "a"}));
        // The shorter alternative is still taken for the shorter array.
        assert_eq!(run(schema, "x", "8101"), json!({"a": 1}));
    }

    #[test]
    fn array_group_choice_requires_full_consumption() {
        let schema = "x = [ a: uint // a: uint, b: tstr ]";
        assert_eq!(run(schema, "x", "82016161"), json!({"a": 1, "b": "a"}));
        assert_eq!(run(schema, "x", "8101"), json!({"a": 1}));
    }

    #[test]
    fn array_lenient_fallback_still_reports_extras() {
        // Nothing fits, so the lenient walk keeps the leftovers.
        let out = run("x = [a: uint]", "x", "8201616 1".replace(' ', "").as_str());
        assert_eq!(out, json!({"a": 1, "@extra": ["a"]}));
    }

    // ========================================================
    // Type choices fall through past rule references
    // ========================================================

    #[test]
    fn type_choice_falls_through_past_a_rule_ref() {
        let schema = "ta = tstr\ntb = #6.2(bstr)\nx = ta / tb";
        assert_eq!(run(schema, "x", "c24401020304"), json!("16909060"));
        // The first alternative still wins when it fits.
        assert_eq!(run(schema, "x", "6161"), json!("a"));
    }

    #[test]
    fn type_choice_fallthrough_does_not_lose_duplicate_map_entries() {
        let schema = "ta = tstr\ntb = {* uint => uint}\nx = ta / tb";
        let out = run(schema, "x", "a201010102");
        let entries = out["@entries"]
            .as_array()
            .unwrap_or_else(|| panic!("duplicate entries collapsed: {}", out));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["value"], json!(1));
        assert_eq!(entries[1]["value"], json!(2));
    }

    #[test]
    fn ledger_value_takes_the_stock_branch() {
        let mut cbor = String::from("821903e8a1581c");
        cbor.push_str(&"bb".repeat(28));
        cbor.push_str("a14005");
        let out = run(ledger(), "value", &cbor);
        assert_eq!(out["amount"], json!(1000), "{}", out);
        let bucket = format!("0x{}", "bb".repeat(28));
        assert_eq!(out["stock"][&bucket]["0x"], json!(5), "{}", out);
        // The amount-only alternative still wins for a bare amount.
        assert_eq!(run(ledger(), "value", "1903e8"), json!(1000));
    }

    // ========================================================
    // Group rules
    // ========================================================

    /// A certificate whose retirement variant is a group rule spliced
    /// into the type rule's choice.
    const RETIREMENT_CDDL: &str = "
        certificate = [ registration // retirement ]
        registration = (0, owner: hash28)
        retirement = (4, owner: hash28, epoch: uint)
        hash28 = bytes .size 28
    ";

    fn retirement_cert_cbor() -> String {
        format!("8304581c{}1864", "aa".repeat(28))
    }

    #[test]
    fn group_rule_as_root_errors() {
        let bytes = hex::decode(retirement_cert_cbor()).unwrap();
        let err = decode_cbor_against_cddl(&bytes, RETIREMENT_CDDL, "retirement")
            .err()
            .expect("a group rule cannot be a root rule");
        assert_eq!(err.kind(), "group_rule_root", "{}", err);
        let msg = err.to_string();
        assert!(msg.contains("retirement"), "{}", msg);
        assert!(msg.contains("group rule"), "{}", msg);

        // Distinguishable from the unknown-rule error.
        let unknown = decode_cbor_against_cddl(&bytes, RETIREMENT_CDDL, "no_such_rule")
            .err()
            .expect("unknown rule still errors");
        assert_eq!(unknown.kind(), "missing_rule", "{}", unknown);
        let unknown = unknown.to_string();
        assert!(unknown.contains("does not define a rule"), "{}", unknown);
        assert!(!unknown.contains("group rule"), "{}", unknown);

        // The type rule that splices it in still decodes.
        let ok = decode_cbor_against_cddl(&bytes, RETIREMENT_CDDL, "certificate").unwrap();
        assert_eq!(ok["owner"], json!("aa".repeat(28)), "{}", ok);
        assert_eq!(ok["epoch"], json!(100), "{}", ok);
    }

    #[test]
    fn group_rule_in_type_position_declines() {
        // `x: g` cannot be filled by a group rule, so nothing labels.
        let schema = "g = (0, uint)\nt = [x: g, y: uint]";
        let out = run(schema, "t", "82646e6f706507");
        assert!(
            out.get("x").is_none(),
            "group rule fabricated a value: {}",
            out
        );
        assert_eq!(out, json!(["nope", 7]));

        // In group position the same rule still splices.
        let ok = "g = (0, uint)\nt = [g, y: uint]";
        assert_eq!(
            run(ok, "t", "83000107"),
            json!({"@positional": [0, 1], "y": 7})
        );
    }

    // ========================================================
    // Wire order
    // ========================================================

    #[test]
    fn map_object_keys_follow_wire_order() {
        // Schema order is a, z; wire order is z, a. The output follows
        // the wire, and a sorted serialiser would also disagree.
        let out = run("m = {a: uint, z: uint}", "m", "a2617a01616102");
        let keys: Vec<&str> = out
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, vec!["z", "a"], "{}", out);
        // When the wire agrees with the schema, so does the output.
        let same = run("m = {a: uint, z: uint}", "m", "a2616101617a02");
        let same_keys: Vec<&str> = same
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(same_keys, vec!["a", "z"], "{}", same);
    }

    #[test]
    fn map_object_keys_follow_wire_order_for_double_digit_keys() {
        // Wire order 0, 10, 2, 1 — a lexicographic sort would slot 10
        // between 1 and 2.
        let schema = "m = { ? 0: uint, ? 1: uint, ? 2: uint, ? 10: uint }";
        let out = run(schema, "m", "a400010a0202030104");
        let keys: Vec<&str> = out
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, vec!["0", "10", "2", "1"], "{}", out);
    }

    /// `@entries` preserves wire order regardless of schema order.
    #[test]
    fn entries_form_pairs_follow_wire_order() {
        // Duplicate keys force the entries form; the two `a` values must
        // stay on the sides of `b` that the bytes put them on.
        let out = run("m = {* tstr => uint}", "m", "a3616101616202616103");
        let pairs = out["@entries"].as_array().expect("expected entries form");
        let keys: Vec<&str> = pairs.iter().map(|e| e["key"].as_str().unwrap()).collect();
        assert_eq!(keys, vec!["a", "b", "a"], "{}", out);
        let values: Vec<u64> = pairs.iter().map(|e| e["value"].as_u64().unwrap()).collect();
        assert_eq!(values, vec![1, 2, 3], "{}", out);

        // A complex key also forces the entries form; schema order
        // (a, z) still loses to wire order (z, a).
        let complex = run(
            "m = {a: uint, z: uint, * any => any}",
            "m",
            "a3617a01616102810103",
        );
        let pairs = complex["@entries"]
            .as_array()
            .unwrap_or_else(|| panic!("expected entries form: {}", complex));
        let keys: Vec<String> = pairs.iter().map(|e| e["key"].to_string()).collect();
        assert_eq!(keys, vec!["\"z\"", "\"a\"", "[1]"], "{}", complex);
    }

    /// Absent declared members follow wire entries (wire order kept).
    #[test]
    fn absent_members_follow_the_keys_the_wire_carried() {
        // Wire order mango, apple; zebra is declared but absent, so the
        // lenient pass supplies it.
        let out = run(
            "m = {apple: uint, zebra: uint, mango: uint}",
            "m",
            "a2656d616e676f01656170706c6503",
        );
        let keys: Vec<&str> = out
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, vec!["mango", "apple", "zebra"], "{}", out);
        assert_eq!(out["zebra"], json!(null), "{}", out);

        // With an unclaimed key as well, `@extra` comes last of all.
        let with_extra = run(
            "m = {apple: uint, zebra: uint}",
            "m",
            "a2656d616e676f01656170706c6503",
        );
        let keys: Vec<&str> = with_extra
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, vec!["apple", "zebra", "@extra"], "{}", with_extra);
    }

    #[test]
    fn extra_bucket_keys_follow_wire_order() {
        let out = run("t = {0: uint}", "t", "a4000109020a030104");
        let extra = out["@extra"].as_object().unwrap();
        let keys: Vec<&str> = extra.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["9", "10", "1"], "{}", out);
    }

    // ========================================================
    // Recursion
    // ========================================================

    #[test]
    fn cyclic_rule_alias_terminates() {
        for (schema, root) in [
            ("a = b\nb = a", "a"),
            ("a = a / int", "a"),
            ("a<t> = a<t>\nb = a<int>", "b"),
        ] {
            let bytes = hex::decode("01").unwrap();
            let out = decode_cbor_against_cddl(&bytes, schema, root);
            assert!(
                out.is_ok(),
                "cyclic schema {:?} should return, got {:?}",
                schema,
                out.err().map(|e| e.to_string())
            );
        }
    }

    #[test]
    fn cyclic_rule_alias_inside_an_array_terminates() {
        let schema = "a = b\nb = a\nt = [x: a, y: uint]";
        let bytes = hex::decode("820107").unwrap();
        let out = decode_cbor_against_cddl(&bytes, schema, "t").expect("should return");
        assert_eq!(out, json!([1, 7]));
    }

    #[test]
    fn productive_recursion_still_works() {
        // Nested `[* datum]` — the cycle guard keys on the CBOR node
        // too, so descending into children is untouched.
        let mut cbor = String::new();
        for _ in 0..24 {
            cbor.push_str("81");
        }
        cbor.push_str("01");
        let out = run(ledger(), "datum", &cbor);
        let mut cursor = &out;
        for depth in 0..24 {
            let arr = cursor
                .as_array()
                .unwrap_or_else(|| panic!("lost nesting at depth {}: {}", depth, out));
            assert_eq!(arr.len(), 1);
            cursor = &arr[0];
        }
        assert_eq!(cursor, &json!(1));
    }

    /// Rule-ref cycles consume no data; each shape must self-terminate.
    #[test]
    fn cyclic_rules_do_not_recurse_forever() {
        for schema in ["a = b\nb = a", "a = a", "a = ~a", "a = (a)", "a = a / int"] {
            let bytes = hex::decode("05").unwrap();
            let out = decode_cbor_against_cddl(&bytes, schema, "a");
            assert!(
                out.is_ok(),
                "cyclic schema {:?} did not return: {:?}",
                schema,
                out.err().map(|e| e.to_string())
            );
        }
    }

    /// `a<[t]>` expands to a fresh arg each time; only hop bound stops it.
    #[test]
    fn growing_generic_arguments_do_not_recurse_forever() {
        let bytes = hex::decode("05").unwrap();
        let out = decode_cbor_against_cddl(&bytes, "a<t> = a<[t]>\nb = a<int>", "b");
        assert!(
            out.is_ok(),
            "growing generic did not return: {:?}",
            out.err().map(|e| e.to_string())
        );
    }

    /// Productive recursion (consumes data) must not be hop-capped.
    #[test]
    fn productive_recursion_still_walks_to_the_bottom() {
        let levels = 30;
        let mut cbor = "81".repeat(levels);
        cbor.push_str("05");
        let out = run("x = [* x] / uint", "x", &cbor);
        let mut cursor = &out;
        for level in 0..levels {
            let arr = cursor
                .as_array()
                .unwrap_or_else(|| panic!("lost nesting at level {}: {}", level, out));
            assert_eq!(arr.len(), 1, "level {}", level);
            cursor = &arr[0];
        }
        assert_eq!(cursor, &json!(5));
    }

    // ========================================================
    // Data nesting limit
    // ========================================================

    fn nested_arrays_hex(levels: usize) -> String {
        let mut s = "81".repeat(levels);
        s.push_str("05");
        s
    }

    /// Deep result tree; free via [`DeepJson`].
    fn deep(result: Result<Value, WalkError>) -> Result<DeepJson, WalkError> {
        result.map(DeepJson::new)
    }

    /// Nesting-budget refusal message (must name the bound).
    fn refusal_naming_the_budget(result: Result<Value, WalkError>) -> String {
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

    /// Per nest-step construct: schema + `d`-deep doc + one descend step.
    struct BoundaryShape {
        name: &'static str,
        schema: &'static str,
        hex_at: fn(usize) -> String,
        step: fn(&Value) -> Option<&Value>,
        /// Extra nesting beyond the construct (`@entries` key array, etc.).
        extra: usize,
    }

    /// `hops` aliases `r0`…`x`; naming `r0` costs `hops` rule refs.
    fn alias_chain(hops: usize) -> String {
        assert!(hops >= 2, "the chain is at least `r0 = x`");
        let mut chain = String::new();
        for alias in 0..hops - 2 {
            chain.push_str(&format!("r{} = r{}\n", alias, alias + 1));
        }
        chain.push_str(&format!("r{} = x\n", hops - 2));
        chain
    }

    /// Nest-step constructs: array slots, map values, tag payload.
    fn boundary_shapes() -> Vec<BoundaryShape> {
        vec![
            BoundaryShape {
                name: "array item by rule name",
                schema: "x = [* x] / uint",
                hex_at: |d| "81".repeat(d) + "05",
                step: |v| v.as_array().and_then(|a| a.first()),
                extra: 0,
            },
            BoundaryShape {
                name: "array item by member type",
                schema: "x = [* x / uint]",
                hex_at: |d| "81".repeat(d) + "05",
                step: |v| v.as_array().and_then(|a| a.first()),
                extra: 0,
            },
            BoundaryShape {
                name: "map value in object form",
                schema: "x = {* uint => x} / uint",
                hex_at: |d| "a100".repeat(d) + "05",
                step: |v| v.get("0"),
                extra: 0,
            },
            BoundaryShape {
                name: "map value in entries form",
                schema: "x = {* [uint] => x} / uint",
                hex_at: |d| "a18100".repeat(d) + "05",
                step: |v| v.get("@entries")?.get(0)?.get("value"),
                extra: 1,
            },
            BoundaryShape {
                name: "tag payload",
                schema: "x = #6.1(x) / uint",
                hex_at: |d| "c1".repeat(d) + "05",
                step: |v| v.get("@value"),
                extra: 0,
            },
        ]
    }

    /// Heap walk: deepest admitted nesting succeeds; one more refuses.
    #[test]
    fn decode_walks_every_construct_to_the_level_bound_and_refuses_the_next() {
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
            let out = deep(decode_cbor_against_cddl(&bytes, schema, "x"))
                .unwrap_or_else(|e| panic!("{}: {}", name, e));
            let mut cursor: &Value = &out;
            for level in 0..deepest {
                cursor = step(cursor).unwrap_or_else(|| {
                    panic!("{}: lost nesting at level {} of {}", name, level, deepest)
                });
            }
            assert_eq!(cursor, &json!(5), "{}", name);

            let bytes = hex::decode(hex_at(deepest + 1)).unwrap();
            refusal_naming(
                decode_cbor_against_cddl(&bytes, schema, "x"),
                &crate::cbor::limits::nesting_depth_message(bound),
            );
        }
    }

    /// `hops` aliases per level; named slot distinguishes labelled vs raw.
    fn named_alias_schema(hops: usize) -> String {
        format!("x = [a: r0] / uint\n{}", alias_chain(hops))
    }

    /// Assert `levels` of labelled `a` fields down to `5`.
    fn descend_named(out: &Value, levels: usize) {
        let mut cursor = out;
        for level in 0..levels {
            cursor = cursor.get("a").unwrap_or_else(|| {
                panic!("level {} of {} is not labelled: {}", level, levels, cursor)
            });
        }
        assert_eq!(cursor, &json!(5));
    }

    /// Alias chains charge descent without consuming data; refusal names
    /// the budget rather than returning partially labelled output.
    #[test]
    fn a_chain_of_rule_references_spends_the_descent_budget_and_is_refused_as_a_limit() {
        // The longest chain the walker admits against one item.
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

        // Every level the budget carries is labelled, down to the leaf.
        let bytes = hex::decode(nested_arrays_hex(deepest)).unwrap();
        let out = deep(decode_cbor_against_cddl(&bytes, &schema, "x"))
            .expect("expected a mapped document");
        descend_named(&out, deepest);

        // One level more is refused, and by the budget.
        let bytes = hex::decode(nested_arrays_hex(deepest + 1)).unwrap();
        refusal_naming_the_budget(decode_cbor_against_cddl(&bytes, &schema, "x"));
    }

    /// Raw subtrees under labelled output still charge nesting; short
    /// budget → refuse, not truncated output.
    #[test]
    fn a_raw_subtree_below_a_labelled_walk_is_charged_for_its_levels() {
        let weights = crate::cbor::limits::SCHEMA_WALKER_DESCENT;
        let limit = crate::cbor::limits::MAX_CBOR_MAPPING_DESCENT_COST;
        // Alias-labelled arrays; unmatched maps below → raw.
        let hops = 32;
        let schema = format!("x = [* r0] / any\n{}", alias_chain(hops));
        let raw_levels = 60;
        let raw_cost = raw_levels * weights.raw_level;
        let per_labelled = weights.level + hops * weights.rule_hop;
        // The fewest labelled levels leaving less than the raw chain
        // costs.
        let labelled = (limit - raw_cost) / per_labelled + 1;
        assert!(labelled * per_labelled + raw_cost > limit);
        assert!((labelled - 1) * per_labelled + raw_cost <= limit);
        assert!(labelled + raw_levels < crate::cbor::limits::MAX_CBOR_NESTING_DEPTH);

        let document = |arrays: usize| {
            let mut hex_bytes = "81".repeat(arrays);
            hex_bytes.push_str(&"a100".repeat(raw_levels));
            hex_bytes.push_str("05");
            hex::decode(hex_bytes).unwrap()
        };
        refusal_naming_the_budget(decode_cbor_against_cddl(&document(labelled), &schema, "x"));

        // The same raw chain one labelled level shallower is answered,
        // and comes back raw to the bottom.
        let out = deep(decode_cbor_against_cddl(
            &document(labelled - 1),
            &schema,
            "x",
        ))
        .expect("expected a mapped document");
        let mut cursor: &Value = &out;
        for _ in 0..labelled - 1 {
            cursor = &cursor.as_array().expect("labelled level")[0];
        }
        for _ in 0..raw_levels {
            cursor = cursor.get("0").expect("raw level");
        }
        assert_eq!(cursor, &json!(5));
    }

    /// Like [`alias_chain`] as `s0`…`x` (second chain, different length).
    fn second_alias_chain(hops: usize) -> String {
        assert!(hops >= 2, "the chain is at least `s0 = x`");
        let mut chain = String::new();
        for alias in 0..hops - 2 {
            chain.push_str(&format!("s{} = s{}\n", alias, alias + 1));
        }
        chain.push_str(&format!("s{} = x\n", hops - 2));
        chain
    }

    /// Lenient `@entries` / `@extra` raw values charge the map→value
    /// level in the mapping pass (strict accounting already charged it).
    #[test]
    fn a_raw_subtree_under_an_entries_form_map_is_charged_the_level_between_them() {
        let weights = crate::cbor::limits::SCHEMA_WALKER_DESCENT;
        let limit = crate::cbor::limits::MAX_CBOR_MAPPING_DESCENT_COST;
        let (array_hops, value_hops) = (32, 24);
        // Alias-labelled arrays + `@entries` map + unmatched → `@extra` raw.
        let schema = format!(
            "x = [* r0] / {{* [uint] => s0}} / uint\n{}{}",
            alias_chain(array_hops),
            second_alias_chain(value_hops)
        );
        // `arrays` labelled levels, an `@entries` map, an object-form
        // map no member claims, and `raw` maps below it.
        let document = |arrays: usize, raw: usize| {
            let mut hex_bytes = "81".repeat(arrays);
            hex_bytes.push_str("a18100");
            hex_bytes.push_str("a100");
            hex_bytes.push_str(&"a100".repeat(raw));
            hex_bytes.push_str("05");
            hex::decode(hex_bytes).unwrap()
        };
        let per_labelled = weights.level + array_hops * weights.rule_hop;
        let between = weights.level + value_hops * weights.rule_hop;
        // Labelled levels leaving room for about four thousand raw ones.
        let arrays = (limit - 4096 * weights.raw_level - between) / per_labelled;
        // Charge = labelled levels + `@entries` step + refs into value.
        let held = arrays * per_labelled + between;
        let raw = (limit - held) / weights.raw_level + 1;
        assert!(held + raw * weights.raw_level > limit);
        assert!(held - weights.level + raw * weights.raw_level <= limit);
        assert!(arrays + 2 + raw < crate::cbor::limits::MAX_CBOR_NESTING_DEPTH);

        refusal_naming_the_budget(decode_cbor_against_cddl(
            &document(arrays, raw),
            &schema,
            "x",
        ));

        let out = deep(decode_cbor_against_cddl(
            &document(arrays, raw - 1),
            &schema,
            "x",
        ))
        .expect("expected a mapped document");
        let mut cursor: &Value = &out;
        for _ in 0..arrays {
            cursor = &cursor.as_array().expect("labelled level")[0];
        }
        cursor = cursor
            .get("@entries")
            .and_then(|e| e.get(0))
            .and_then(|pair| pair.get("value"))
            .and_then(|v| v.get("@extra"))
            .and_then(|extra| extra.get("0"))
            .expect("the entries map, its unclaimed value and the raw subtree below");
        for _ in 0..raw - 1 {
            cursor = cursor.get("0").expect("raw level");
        }
        assert_eq!(cursor, &json!(5));
    }

    /// Self-cycle without progress declines (schema fact), not a budget hit.
    #[test]
    fn a_cyclic_alias_still_declines_to_raw_without_spending_the_budget() {
        let bytes = hex::decode(nested_arrays_hex(3)).unwrap();
        let out = decode_cbor_against_cddl(&bytes, "a = b\nb = a", "a")
            .expect("a cycle is answered, not refused");
        descend(&out, 3);
    }

    #[test]
    fn decode_rejects_cbor_nested_past_the_limit() {
        crate::cbor::test_fixtures::on_large_stack(|| {
            let hex = nested_arrays_hex(crate::cbor::limits::MAX_CBOR_NESTING_DEPTH + 1);
            let bytes = hex::decode(&hex).unwrap();
            let err = decode_cbor_against_cddl(&bytes, "x = [* x] / uint", "x")
                .err()
                .expect("expected a rejection");
            assert_eq!(err.kind(), "nesting_too_deep", "{}", err);
            assert!(
                err.message().contains("nesting"),
                "unexpected message: {}",
                err
            );
        });
    }

    /// Nesting pre-scan must run before value decode (else test abort).
    #[test]
    fn decode_rejects_deep_cbor_before_decoding_it() {
        crate::cbor::test_fixtures::on_large_stack(|| {
            let bytes = hex::decode(nested_arrays_hex(
                2 * crate::cbor::limits::MAX_CBOR_NESTING_DEPTH,
            ))
            .unwrap();
            let err = decode_cbor_against_cddl(&bytes, "x = [* x] / uint", "x")
                .err()
                .expect("expected a rejection");
            assert_eq!(err.kind(), "nesting_too_deep", "{}", err);
            assert!(
                err.message().contains("nesting"),
                "unexpected message: {}",
                err
            );
        });
    }

    /// A definite-length byte string carrying `payload`.
    fn bstr_hex(payload: &str) -> String {
        let len = payload.len() / 2;
        assert!(len < 0x1_0000, "test payloads stay under a two-byte length");
        format!("59{:04x}{}", len, payload)
    }

    /// `outer` arrays around a bstr of `inner` arrays around `5`.
    fn embedded_arrays_hex(outer: usize, inner: usize) -> String {
        let mut s = "81".repeat(outer);
        s.push_str(&bstr_hex(&nested_arrays_hex(inner)));
        s
    }

    const EMBEDDED_SCHEMA: &str = "a0 = [* a0] / (bstr .cbor a1)\na1 = [* a1] / uint";

    /// Descend `levels` single-element arrays to `5`, or report stop.
    fn descend(out: &Value, levels: usize) {
        let mut cursor = out;
        for level in 0..levels {
            cursor = &cursor
                .as_array()
                .unwrap_or_else(|| panic!("lost nesting at level {} of {}", level, levels))[0];
        }
        assert_eq!(cursor, &json!(5));
    }

    /// Shared doc+payload nesting: leftover depth walked; one more refuses.
    #[test]
    fn a_payload_filling_what_the_document_left_is_still_walked_to_the_bottom() {
        let bound = crate::cbor::limits::MAX_CBOR_NESTING_DEPTH;
        let outer = 32;
        let bytes = hex::decode(embedded_arrays_hex(outer, bound - outer)).unwrap();
        let out = deep(decode_cbor_against_cddl(&bytes, EMBEDDED_SCHEMA, "a0"))
            .expect("expected a mapped document");
        descend(&out, bound);

        let bytes = hex::decode(embedded_arrays_hex(outer, bound - outer + 1)).unwrap();
        refusal_naming(
            decode_cbor_against_cddl(&bytes, EMBEDDED_SCHEMA, "a0"),
            &crate::cbor::limits::nesting_depth_message(bound),
        );
    }

    /// Embed-depth refusal message (must name the bound).
    fn refusal_naming(result: Result<Value, WalkError>, bound: &str) -> String {
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

    /// Document and payloads share one nesting budget; over-budget
    /// payloads refuse (named bound), not fall back to raw bstr.
    #[test]
    fn a_payload_one_level_past_what_the_document_left_is_refused_naming_the_level_bound() {
        crate::cbor::test_fixtures::on_large_stack(|| {
            let limit = crate::cbor::limits::MAX_CBOR_NESTING_DEPTH;
            let outer = 8;
            let inner_hex = nested_arrays_hex(limit - outer + 1);
            let mut hex_bytes = "81".repeat(outer);
            hex_bytes.push_str(&bstr_hex(&inner_hex));
            let bytes = hex::decode(hex_bytes).unwrap();
            refusal_naming(
                decode_cbor_against_cddl(&bytes, EMBEDDED_SCHEMA, "a0"),
                &crate::cbor::limits::nesting_depth_message(limit),
            );
        });
    }

    /// Open-payload chain shares budget; over embed bound → refuse.
    #[test]
    fn a_chain_of_shallow_payloads_is_refused_past_the_open_payload_bound() {
        // Each rule embeds the next; the last one is a plain byte string.
        let levels = crate::cbor::limits::MAX_EMBEDDED_DEPTH;
        let mut schema = String::new();
        for i in 0..levels {
            schema.push_str(&format!("a{} = bstr .cbor a{}\n", i, i + 1));
        }
        schema.push_str(&format!("a{} = uint\n", levels));

        // One byte string per level, `5` at the bottom.
        let mut hex_bytes = String::from("05");
        for _ in 0..levels {
            hex_bytes = bstr_hex(&hex_bytes);
        }
        let bytes = hex::decode(&hex_bytes).unwrap();
        let out = decode_cbor_against_cddl(&bytes, &schema, "a0").expect("expected a document");
        assert_eq!(out, json!(5), "every level within the bound is decoded");

        // One level more than may be open at once.
        let mut schema = String::new();
        for i in 0..=levels {
            schema.push_str(&format!("a{} = bstr .cbor a{}\n", i, i + 1));
        }
        schema.push_str(&format!("a{} = uint\n", levels + 1));
        let deeper_hex = bstr_hex(&hex_bytes);
        let bytes = hex::decode(&deeper_hex).unwrap();
        refusal_naming(
            decode_cbor_against_cddl(&bytes, &schema, "a0"),
            &crate::cbor::limits::embedded_payloads_message(levels),
        );
    }

    /// Embedded `.cbor` gets the same nesting bound as a top-level doc.
    #[test]
    fn an_embedded_payload_nested_past_the_limit_is_refused_naming_the_level_bound() {
        crate::cbor::test_fixtures::on_large_stack(|| {
            let payload = hex::decode(nested_arrays_hex(
                crate::cbor::limits::MAX_CBOR_NESTING_DEPTH + 1,
            ))
            .unwrap();
            let mut outer = Vec::new();
            // A definite-length byte string carrying that payload.
            outer.push(0x5a);
            outer.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            outer.extend_from_slice(&payload);
            refusal_naming(
                decode_cbor_against_cddl(&outer, "x = bstr .cbor any", "x"),
                &crate::cbor::limits::nesting_depth_message(
                    crate::cbor::limits::MAX_CBOR_NESTING_DEPTH,
                ),
            );
        });
    }

    /// `hops` generics under `head`, each passing its param onward.
    fn generic_chain_schema(head: &str, hops: usize) -> String {
        let mut schema = format!("{}\n", head);
        for hop in 0..hops - 1 {
            schema.push_str(&format!("b{}<t> = b{}<t>\n", hop, hop + 1));
        }
        schema.push_str(&format!("b{}<t> = t\n", hops - 1));
        schema
    }

    /// Args read in call-site scope (`b0<t>` passes `t` through, not
    /// rebound as `b1`'s own `t`).
    #[test]
    fn a_generic_argument_passed_on_is_read_where_it_was_written() {
        for hops in [1, 2, 3, 8] {
            let leaf = generic_chain_schema("x = b0<uint>", hops);
            assert_eq!(run(&leaf, "x", "05"), json!(5), "{} hops", hops);

            let nested = generic_chain_schema("x = [* b0<x>] / uint", hops);
            assert_eq!(run(&nested, "x", "818105"), json!([[5]]), "{} hops", hops);
        }

        // `b<[t]>` is read in `a`'s scope, where `t` is `uint`.
        let schema = "x = a<uint>\na<t> = b<[t]>\nb<t> = t\n";
        assert_eq!(run(schema, "x", "8105"), json!([5]));
        assert_eq!(run(schema, "x", "05"), json!(5));
    }

    /// Params are rule-local; callees do not see caller params.
    #[test]
    fn a_rule_reached_from_a_generic_body_does_not_see_the_callers_parameters() {
        // `c = t` names the rule `t`, not `a`'s parameter, so it reads as
        // `c = uint` and the document maps the same way under both.
        let through_the_name = "x = a<tstr>\na<t> = [t, c]\nc = t\nt = uint\n";
        let spelled_out = "x = a<tstr>\na<t> = [t, c]\nc = uint\n";
        let mapped = run(through_the_name, "x", "82616105");
        assert_eq!(mapped, run(spelled_out, "x", "82616105"));
        assert_eq!(mapped["c"], json!(5), "{}", mapped);
    }

    /// Rule-ref chain length is bounded like the validator; over → refuse,
    /// at bound → answer.
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
            let out = decode_cbor_against_cddl(&bytes, &admitted, "x")
                .expect("a chain at the bound is answered");
            descend_named(&out, 3);
            refusal_naming(
                decode_cbor_against_cddl(&bytes, &refused, "x"),
                &crate::cbor::limits::rule_nesting_message(bound),
            );
        }
    }

    /// Over-declared payload length: decline (value decoder would OOM).
    #[test]
    fn an_embedded_payload_with_an_impossible_declared_length_declines_to_the_raw_bytes() {
        for payload_hex in [
            "5bffffffffffffffff",
            "7bffffffffffffffff",
            "9bffffffffffffffff",
            "bbffffffffffffffff",
        ] {
            let payload = hex::decode(payload_hex).unwrap();
            let mut outer = vec![0x40 | payload.len() as u8];
            outer.extend_from_slice(&payload);
            let out = decode_cbor_against_cddl(&outer, "x = bstr .cbor any", "x")
                .expect("expected the raw byte-string form");
            assert_eq!(out, json!(payload_hex), "{}", payload_hex);
            assert!(
                crate::cbor::cbor_cddl_map::map_cbor_to_cddl(&outer, "x = bstr .cbor any", "x")
                    .is_ok(),
                "{}",
                payload_hex
            );
        }
    }

    // ========================================================
    // Key collisions
    // ========================================================

    #[test]
    fn colliding_map_keys_use_entries_form() {
        // Integer 1 and text "1" both stringify to "1".
        let out = run("m = {a: uint}", "m", "a20105613106");
        let entries = out["@entries"]
            .as_array()
            .unwrap_or_else(|| panic!("colliding keys collapsed: {}", out));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["key"], json!(1));
        assert_eq!(entries[0]["value"], json!(5));
        assert_eq!(entries[1]["key"], json!("1"));
        assert_eq!(entries[1]["value"], json!(6));

        // Bytes collide with their own hex spelling.
        let bytes_out = run("m = {a: uint}", "m", "a2410105643078303106");
        let bytes_entries = bytes_out["@entries"]
            .as_array()
            .unwrap_or_else(|| panic!("colliding keys collapsed: {}", bytes_out));
        assert_eq!(bytes_entries.len(), 2);
        assert_eq!(bytes_entries[0]["value"], json!(5));
        assert_eq!(bytes_entries[1]["value"], json!(6));

        // Keys that do not collide keep the convenient object form.
        let plain = run("m = {a: uint}", "m", "a20105616206");
        assert!(plain.get("@entries").is_none(), "{}", plain);
    }

    /// `@entries` shape still requires fit accounting (else choice is
    /// declaration order, not match).
    #[test]
    fn an_entries_shaped_map_still_has_to_fit_the_alternative_that_claims_it() {
        // Array key → `@entries`; alt_a misses, alt_b fits.
        let a_first = "root = alt_a / alt_b\nalt_a = { 1: uint }\nalt_b = { * any => any }\n";
        let b_first = "root = alt_b / alt_a\nalt_a = { 1: uint }\nalt_b = { * any => any }\n";
        for schema in [a_first, b_first] {
            let out = run(schema, "root", "a1810105");
            let entries = out["@entries"]
                .as_array()
                .unwrap_or_else(|| panic!("expected the entries form: {}", out));
            assert_eq!(entries.len(), 1, "{}", out);
            // Claimed by the member that accepts it, not left unmatched
            // against the member that does not.
            assert_eq!(entries[0]["match"]["via"], json!("type"), "{}", out);
        }

        // Repeated keys reach the entries form the same way and get the
        // same treatment: `alt_a` names a key the data never carries.
        let dup = "root = alt_a / alt_b\nalt_a = { 9: uint }\nalt_b = { * uint => uint }\n";
        let out = run(dup, "root", "a201010102");
        let entries = out["@entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2, "{}", out);
        for entry in entries {
            assert_eq!(entry["match"]["via"], json!("type"), "{}", out);
        }

        // Fitting first alt wins; repeated key → `@entries`, alt_a claims both.
        let out = run(
            "root = alt_a / alt_b\nalt_a = { 1: uint }\nalt_b = { * any => any }\n",
            "root",
            "a201050106",
        );
        let entries = out["@entries"]
            .as_array()
            .unwrap_or_else(|| panic!("expected the entries form: {}", out));
        assert_eq!(entries[0]["match"]["via"], json!("literal"), "{}", out);

        // And a map no alternative accounts for is still rendered in
        // full by the lenient pass rather than dropped.
        let out = run("root = { 9: uint }", "root", "a1810105");
        assert_eq!(out["@entries"].as_array().map(Vec::len), Some(1), "{}", out);
    }

    #[test]
    fn entries_form_distinguishes_literal_from_type_key_matches() {
        // A `<type1> =>` key is not a literal, so the match record says
        // `type` and carries no label.
        let out = run("m = { * uint => uint }", "m", "a201010102");
        let entries = out["@entries"].as_array().unwrap();
        assert_eq!(entries[0]["match"]["via"], json!("type"), "{}", out);
        assert_eq!(entries[0]["match"]["label"], json!(null), "{}", out);
        // A literal key still reports its own text.
        let lit = run("m = { a: uint }", "m", "a2616101616102");
        let lit_entries = lit["@entries"].as_array().unwrap();
        assert_eq!(lit_entries[0]["match"]["via"], json!("literal"), "{}", lit);
        assert_eq!(lit_entries[0]["match"]["label"], json!("a"), "{}", lit);
    }

    #[test]
    fn raw_fallback_does_not_drop_colliding_keys() {
        // Same maps, reached through a schema that matches nothing.
        let out = run("m = [uint]", "m", "a20105613106");
        let entries = out["@entries"]
            .as_array()
            .unwrap_or_else(|| panic!("raw fallback dropped an entry: {}", out));
        assert_eq!(entries.len(), 2);
        let bytes_out = run("m = [uint]", "m", "a2410105643078303106");
        assert_eq!(bytes_out["@entries"].as_array().unwrap().len(), 2);
        // No collision, no shape change.
        let plain = run("m = [uint]", "m", "a20105616206");
        assert!(plain.get("@entries").is_none(), "{}", plain);
    }

    // ========================================================
    // Version smoke test
    // ========================================================

    /// The fixture documents, each with the root it is valid against.
    fn corpus() -> [(&'static str, &'static str); 2] {
        [
            (
                crate::cbor::test_fixtures::RECORD_DOC_HEX.as_str(),
                "record",
            ),
            (crate::cbor::test_fixtures::DATUM_DOC_HEX.as_str(), "datum"),
        ]
    }

    #[test]
    fn every_schema_version_decodes_the_corpus_without_panicking() {
        for (version, cddl) in crate::cbor::test_fixtures::schema_suite() {
            for (hex_text, root) in corpus() {
                let bytes = hex::decode(hex_text).unwrap();
                let out = decode_cbor_against_cddl(&bytes, cddl, root)
                    .unwrap_or_else(|e| panic!("{} failed: {}", version, e));
                assert!(!out.is_null(), "{} produced nothing", version);
            }
        }
    }

    /// Any `@extra` key, at any depth.
    fn has_extra(value: &Value) -> bool {
        match value {
            Value::Object(fields) => {
                fields.contains_key("@extra") || fields.values().any(has_extra)
            }
            Value::Array(items) => items.iter().any(has_extra),
            _ => false,
        }
    }

    #[test]
    fn every_schema_version_decodes_the_corpus_without_leftovers() {
        // The documents are valid in every version, so no version may
        // leave any part of them unaccounted for.
        for (version, cddl) in crate::cbor::test_fixtures::schema_suite() {
            for (hex_text, root) in corpus() {
                let bytes = hex::decode(hex_text).unwrap();
                let out = decode_cbor_against_cddl(&bytes, cddl, root).unwrap();
                assert!(!has_extra(&out), "{} left data in @extra: {}", version, out);
            }
        }
    }
}

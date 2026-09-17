//! Implementation limits on nesting depth and work, plus the iterative
//! scanners that enforce them.
//!
//! Walkers do not recurse over data: open containers and continuations
//! live on the heap (schema steps use `super::walk_driver`). Wasm stack
//! overflow is uncatchable, so nesting is charged as heap, not stack.
//! Schema rule hops also hold memory and are charged into descent budgets.
//!
//! Time: CDDL parse cost grows ~3× per bracket level; validator/mapper
//! choice alternatives can be exponential in nesting. Bracket depth and
//! parse work are bounded up front; walk work is counted as steps.
//!
//! Input-only bounds are scanned before any walker runs. Descent and
//! work budgets are charged as the walk spends them. Exceeding a bound
//! is an implementation limit, not a data error.

use std::cell::Cell;
use std::convert::TryFrom;

/// Deepest nesting the positional decoder follows. Level 0 is the root;
/// each enclosing array, map, or tag adds one; map keys share their
/// value's level. Indefinite byte/text string chunks do not nest.
///
/// Containers are heap-held; JSON write/drop (`crate::deep_json`) is
/// iterative — this bound is memory, not stack. Measured on nested
/// single-element arrays: ~1.9 KB tree + ~135 B JSON + ~200 B host heap
/// per level. At this depth: ~31 MB tree, ~2.2 MB text, ~38 MB peak
/// linear memory (never returned once grown). Without a bound, 2 MB of
/// hex input could open ~10⁶ levels. Exceeding it is an implementation
/// limit; the decoded prefix is returned incomplete.
pub(crate) const MAX_CBOR_DECODE_NESTING_DEPTH: usize = 16_384;

/// Deepest nesting schema walkers admit, counted like
/// [`MAX_CBOR_DECODE_NESTING_DEPTH`].
///
/// Applied by an iterative byte scan before any walker runs; shared with
/// embedded `.cbor` / `.cborseq` payloads via [`NestingBudget`]. Per-level
/// memory is charged into descent budgets
/// ([`VALIDATOR_LEVEL_COST`], [`SCHEMA_WALKER_DESCENT`],
/// [`POSITION_MAP_DESCENT`]), which may bind first when many rule hops
/// resolve per level. `super::stack_calibration` checks walkers stay
/// within a small stack at this depth.
pub(crate) const MAX_CBOR_NESTING_DEPTH: usize = 16_384;

/// Validator nesting depth, counted like [`MAX_CBOR_NESTING_DEPTH`].
///
/// Levels and continuations are heap-held. Documents past
/// [`MAX_CBOR_NESTING_DEPTH`] are refused by the pre-scan;
/// [`NestingBudget`] shares the remaining depth with embedded payloads.
/// Exceeding either bound is an implementation limit, not a data mismatch.
pub(crate) const MAX_CBOR_VALIDATION_NESTING_DEPTH: usize = MAX_CBOR_NESTING_DEPTH;

/// Max memory (bytes) one validator descent path may hold, charged in
/// [`VALIDATOR_LEVEL_COST`] and [`VALIDATOR_RULE_HOP_COST`].
///
/// [`MAX_CBOR_VALIDATION_NESTING_DEPTH`] bounds data levels only. Rule
/// hops hold continuations without consuming data and restart per level
/// (up to 63 hops/item), so a level count alone can admit gigabytes.
/// Each nested item charges a level; each rule hop charges a hop; the
/// step that would exceed the budget is refused.
///
/// Sized so the level bound wins for ≤2 hops/level (~320 MiB charged).
/// Longer chains refuse shallower (~395 KB/level → ~849 levels). Failed
/// choice alternatives are charged as they accumulate. Exceeding this
/// is an implementation limit.
pub(crate) const MAX_CBOR_VALIDATION_DESCENT_COST: usize =
    (MAX_CBOR_VALIDATION_NESTING_DEPTH + 1) * (VALIDATOR_LEVEL_COST + 2 * VALIDATOR_RULE_HOP_COST);

/// Bytes charged to [`MAX_CBOR_VALIDATION_DESCENT_COST`] for entering a
/// nested data item.
///
/// Measured (counting allocator, 1k vs 3k levels, `opt-level = "s"`):
/// ~4.8–8.1 KB/level depending on shape; weight is set above the
/// dearest. Rechecked in `super::stack_calibration`.
pub(crate) const VALIDATOR_LEVEL_COST: usize = 8192;

/// Bytes charged to [`MAX_CBOR_VALIDATION_DESCENT_COST`] for a rule hop
/// against the item already held.
///
/// Measured ~2.6–2.8 KB/hop over alias chains; set to 6144 so a level
/// plus hop covers generic instantiation (~13.3 KB held → 14.3 KB charged).
pub(crate) const VALIDATOR_RULE_HOP_COST: usize = 6144;

/// Max validation steps against one document (type matches + nest steps).
///
/// Descent cost bounds depth/memory, not branching. Ambiguous choices
/// re-walk subtrees: `k` alternatives over `d` levels ≈ `k^d`. Release
/// timings for `x = a / b / uint` nested arrays: 3 ms@6 … 3.6 s@16;
/// three alternatives: 29 ms@6 … 33 s@12. No wall clock in this runtime,
/// so work is a step count.
///
/// Real docs under vendored schemas: ~558 steps (4.5 KB tx) to ~45k
/// (Plutus datum); densest shapes ~141 steps/byte. This bound covers
/// well past a megabyte of typical CBOR but only ~28 KB of the densest
/// adversarial shape. Full spend ~1.8–5.5 s release / up to ~14 s wasm;
/// callers kill calls past ~10 s, so raising it only trades a named
/// refusal for a dead instance. Exceeding it is an implementation limit.
pub(crate) const MAX_CBOR_VALIDATION_WORK: usize = 4_000_000;

/// Nesting depth for typed decoders (`decode_specific_type`,
/// `get_possible_types_for_input`), counted like [`MAX_CBOR_NESTING_DEPTH`].
///
/// Those paths recurse on the host stack; overflow can leave the wasm
/// shadow-stack pointer unrestored. Depth is scanned iteratively first;
/// past this bound is an implementation limit. On the shipped wasm the
/// dearest shape (a chain of one-entry maps decoded as Plutus data) walks
/// 256 levels on a little over 256 KB of host stack, so the bound holds
/// on a worker's ~500 KB with margin and on a main thread's ~1 MB with
/// more; the calibration test drives the same walk on the native build.
pub(crate) const MAX_TYPED_DECODER_NESTING_DEPTH: usize = 256;

/// Human-readable refusal for typed-decoder nesting past [`MAX_TYPED_DECODER_NESTING_DEPTH`].
pub(crate) fn typed_decoder_nesting_message(limit: usize) -> String {
    format!(
        "CBOR nesting is deeper than the supported limit of {} levels for typed decoding",
        limit
    )
}

/// Max simultaneously open `.cbor` / `.cborseq` payloads.
///
/// [`NestingBudget`] already caps total nesting; each open payload still
/// costs a driver frame on the stack until it finishes, so a chain of
/// shallow payloads is bounded separately.
pub(crate) const MAX_EMBEDDED_DEPTH: usize = 8;

/// Nesting remaining for one call: the root document plus every embedded
/// `.cbor` / `.cborseq` payload.
///
/// A per-document bound would let each of [`MAX_EMBEDDED_DEPTH`] payloads
/// spend [`MAX_CBOR_NESTING_DEPTH`] again. Each document charges its
/// deepest level; a payload that does not fit what remains is declined
/// (left as a byte string). Charging the document's peak depth (not the
/// embed site's depth) can over-refuse — never under-refuse.
pub(crate) struct NestingBudget {
    /// Levels of nesting not yet charged.
    remaining: Cell<usize>,
    /// Payloads currently open.
    open_payloads: Cell<usize>,
    /// Bound that refused a payload, if any (limit reached, not a data answer).
    refused: Cell<Option<EmbeddingBound>>,
}

/// Bound that refused an embedded payload.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum EmbeddingBound {
    /// [`MAX_EMBEDDED_DEPTH`] payloads already open.
    Payloads,
    /// Payload nests past remaining [`MAX_CBOR_NESTING_DEPTH`].
    Levels,
}

/// Refusal message for nesting past `limit` levels (same wording for every walker).
pub(crate) fn nesting_depth_message(limit: usize) -> String {
    format!(
        "CBOR nesting is deeper than the supported limit of {} levels",
        limit
    )
}

/// Refusal message for more than `limit` open embedded payloads.
pub(crate) fn embedded_payloads_message(limit: usize) -> String {
    format!(
        "embedded CBOR payloads are nested more deeply than the supported limit of {} open payloads",
        limit
    )
}

/// Refunds a payload's nesting charge when the walk of it ends.
pub(crate) struct EmbeddedGuard<'b> {
    budget: &'b NestingBudget,
    charged: usize,
}

impl Drop for EmbeddedGuard<'_> {
    fn drop(&mut self) {
        let budget = self.budget;
        budget.remaining.set(budget.remaining.get() + self.charged);
        budget
            .open_payloads
            .set(budget.open_payloads.get().saturating_sub(1));
    }
}

impl NestingBudget {
    /// Remaining budget after walking `bytes` as the root, or `None` if
    /// it alone exceeds [`MAX_CBOR_NESTING_DEPTH`].
    pub(crate) fn for_document(bytes: &[u8]) -> Option<NestingBudget> {
        let depth = cbor_nesting_depth_capped(bytes, MAX_CBOR_NESTING_DEPTH);
        if depth > MAX_CBOR_NESTING_DEPTH {
            return None;
        }
        Some(NestingBudget {
            remaining: Cell::new(MAX_CBOR_NESTING_DEPTH - depth),
            open_payloads: Cell::new(0),
            refused: Cell::new(None),
        })
    }

    /// Charge `payload` and open one embed level, or `None` if
    /// [`MAX_EMBEDDED_DEPTH`] is reached or nesting exceeds what remains.
    pub(crate) fn enter_embedded(&self, payload: &[u8]) -> Option<EmbeddedGuard<'_>> {
        if self.open_payloads.get() >= MAX_EMBEDDED_DEPTH {
            self.refused.set(Some(EmbeddingBound::Payloads));
            return None;
        }
        let remaining = self.remaining.get();
        // Stop once depth exceeds what remains — refusing is as cheap as reading.
        let depth = cbor_nesting_depth_capped(payload, remaining);
        if depth > remaining {
            self.refused.set(Some(EmbeddingBound::Levels));
            return None;
        }
        self.remaining.set(remaining - depth);
        self.open_payloads.set(self.open_payloads.get() + 1);
        Some(EmbeddedGuard {
            budget: self,
            charged: depth,
        })
    }

    /// Whether a payload has been refused.
    pub(crate) fn exhausted(&self) -> bool {
        self.refused.get().is_some()
    }

    /// Refusal message naming the bound that fired.
    pub(crate) fn refusal(&self) -> Option<String> {
        self.refused.get().map(|bound| match bound {
            EmbeddingBound::Payloads => embedded_payloads_message(MAX_EMBEDDED_DEPTH),
            EmbeddingBound::Levels => nesting_depth_message(MAX_CBOR_NESTING_DEPTH),
        })
    }
}

// ============================================================
// The schema walkers' descent budgets
// ============================================================

/// Max memory (bytes) one schema-walker descent path may hold, charged
/// via [`SCHEMA_WALKER_DESCENT`].
///
/// Like the validator: rule hops restart per level (capped by
/// [`MAX_CBOR_MAPPING_RULE_NESTING`]), so memory is budgeted separately
/// from [`MAX_CBOR_NESTING_DEPTH`]. Sized so ≤2 hops/level hit the level
/// bound first; longest chain ~270 KB/level → ~1000 levels. Exceeding
/// this is an implementation limit (whole call refused).
pub(crate) const MAX_CBOR_MAPPING_DESCENT_COST: usize = (MAX_CBOR_NESTING_DEPTH + 1)
    * (SCHEMA_WALKER_DESCENT.level + 2 * SCHEMA_WALKER_DESCENT.rule_hop);

/// Position-map descent budget, same construction as
/// [`MAX_CBOR_MAPPING_DESCENT_COST`], charged via [`POSITION_MAP_DESCENT`].
///
/// Replay holds emitted rows plus the positional tree, so weights are
/// larger (~552 KB/level for the longest chain → ~1300 levels).
pub(crate) const MAX_CBOR_POSITION_MAP_DESCENT_COST: usize =
    (MAX_CBOR_NESTING_DEPTH + 1) * (POSITION_MAP_DESCENT.level + 2 * POSITION_MAP_DESCENT.rule_hop);

/// Per-step charges for a [`DescentBudget`], in bytes held while open.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DescentWeights {
    /// Entering a nested item (array/map/tag/embedded `.cbor` root).
    pub(crate) level: usize,
    /// Resolving a rule hop or substituting a generic argument.
    pub(crate) rule_hop: usize,
    /// One level of a raw (schema-free) subtree.
    pub(crate) raw_level: usize,
}

/// Schema-walker [`DescentWeights`].
///
/// Measured (200 vs 600 levels): ~5.0–5.6 KB/level, ~2.5 KB/hop, ~8.5 KB
/// for generic instantiation, ~2.3 KB raw. Weights are ≥⅓ above the
/// dearest measurement; rechecked by
/// `the_schema_walker_weights_cover_what_a_level_holds`.
pub(crate) const SCHEMA_WALKER_DESCENT: DescentWeights = DescentWeights {
    level: 8192,
    rule_hop: 4096,
    raw_level: 3072,
};

/// Position-map [`DescentWeights`] (walk + replay).
///
/// Measured: ~4.9–9.2 KB/level, ~2.6 KB/hop, ~10.4 KB generic, ~2.8 KB
/// raw. Weights are >2× the dearest measurement; rechecked by
/// `the_position_map_weights_cover_what_a_level_holds`.
pub(crate) const POSITION_MAP_DESCENT: DescentWeights = DescentWeights {
    level: 28672,
    rule_hop: 8192,
    raw_level: 8192,
};

/// Descent budget for one walk (document + embedded `.cbor` payloads).
///
/// Charge on entry, refund on exit — spent is the open path cost, not
/// the whole run. After one refusal, later charges also fail.
pub(crate) struct DescentBudget {
    limit: usize,
    spent: Cell<usize>,
    exhausted: Cell<bool>,
}

/// Refunds a step's charge when the step is left.
pub(crate) struct DescentGuard<'b> {
    budget: &'b DescentBudget,
    cost: usize,
}

impl Drop for DescentGuard<'_> {
    fn drop(&mut self) {
        let budget = self.budget;
        budget
            .spent
            .set(budget.spent.get().saturating_sub(self.cost));
    }
}

impl DescentBudget {
    /// Empty budget of `limit` bytes.
    pub(crate) fn new(limit: usize) -> DescentBudget {
        DescentBudget {
            limit,
            spent: Cell::new(0),
            exhausted: Cell::new(false),
        }
    }

    /// Charge one step, or `None` if it would exceed the limit / already refused.
    pub(crate) fn charge(&self, cost: usize) -> Option<DescentGuard<'_>> {
        if self.exhausted.get() {
            return None;
        }
        let charged = self.spent.get().saturating_add(cost);
        if charged > self.limit {
            self.exhausted.set(true);
            return None;
        }
        self.spent.set(charged);
        Some(DescentGuard { budget: self, cost })
    }

    /// Whether a step has been refused.
    pub(crate) fn exhausted(&self) -> bool {
        self.exhausted.get()
    }

    /// Refusal message naming the bound.
    pub(crate) fn refusal(&self) -> Option<String> {
        self.exhausted
            .get()
            .then(|| descent_cost_message(self.limit))
    }
}

/// Refusal message for a descent holding more than `limit` bytes.
pub(crate) fn descent_cost_message(limit: usize) -> String {
    format!(
        "the descent to this data item holds more memory than the maximum supported descent budget of {} bytes",
        limit
    )
}

/// Max rule hops resolved against one data item (matches the validator's
/// [`cddl::validator::DEFAULT_MAX_RULE_NESTING`]).
///
/// Hops consume no data; shallow type probes recurse one stack frame per
/// link, so this is a schema constant, not a document one.
pub(crate) const MAX_CBOR_MAPPING_RULE_NESTING: usize = cddl::validator::DEFAULT_MAX_RULE_NESTING;

/// Refusal message for a rule-hop chain longer than `limit`.
pub(crate) fn rule_nesting_message(limit: usize) -> String {
    format!(
        "the chain of rule references resolved against one data item is longer than the maximum supported rule nesting of {} references",
        limit
    )
}

/// Max schema-walker steps against one document (same count as
/// [`MAX_CBOR_VALIDATION_WORK`]).
///
/// Nesting/descent bound depth and memory; ambiguous choices can still
/// be exponential in nesting. Strict-pass memoisation helps declining
/// subtrees; succeeding-then-failing alternatives and `@entries` maps
/// remain costly.
pub(crate) const MAX_CBOR_MAPPING_WORK: usize = 4_000_000;

/// Refusal message for more than `limit` mapping steps.
pub(crate) fn mapping_work_message(limit: usize) -> String {
    format!(
        "walking the schema against this document costs more than the maximum supported {} steps of mapping work",
        limit
    )
}

/// Max position-map rows for one document (~1–3 per visited node, plus
/// extras for `@entries` maps).
///
/// Rows are ~290 B of text each; supporting trees ~1.5 KB/node on
/// `wasm32`. At this bound ~550 MB / ~2.5 s; a full megabyte of hex nodes
/// would hold a gigabyte+. Ledger objects stay well under. Exceeding it
/// is an implementation limit (partial rows discarded).
pub(crate) const MAX_CBOR_POSITION_MAP_ROWS: usize = 500_000;

/// Refusal message for more than `limit` position-map rows.
pub(crate) fn position_map_rows_message(limit: usize) -> String {
    format!(
        "mapping this document against the schema produces more than the maximum supported {} position-map rows",
        limit
    )
}

/// Remaining walk work (steps or rows). After refusal, later steps fail too.
pub(crate) struct WorkBudget {
    limit: usize,
    left: Cell<usize>,
    exhausted: Cell<bool>,
    /// Builds the refusal message from the bound.
    message: fn(usize) -> String,
}

impl WorkBudget {
    pub(crate) fn new(limit: usize, message: fn(usize) -> String) -> WorkBudget {
        WorkBudget {
            limit,
            left: Cell::new(limit),
            exhausted: Cell::new(false),
            message,
        }
    }

    /// How much of the budget has been spent.
    pub(crate) fn spent(&self) -> usize {
        self.limit - self.left.get()
    }

    /// Take one step; `false` (and exhaust) when none remain.
    pub(crate) fn step(&self) -> bool {
        if self.exhausted.get() {
            return false;
        }
        let left = self.left.get();
        if left == 0 {
            self.exhausted.set(true);
            return false;
        }
        self.left.set(left - 1);
        true
    }

    pub(crate) fn exhausted(&self) -> bool {
        self.exhausted.get()
    }

    /// Refusal message naming the bound.
    pub(crate) fn refusal(&self) -> Option<String> {
        self.exhausted.get().then(|| (self.message)(self.limit))
    }
}

/// Max nesting of `[`, `{`, `(` in a CDDL document.
///
/// Pest RD parse time grows ~3× per nested bracket level. Measured for
/// `r = [uint, [uint, …]]`: 4 ms@6 … 968 ms@11 (~3× thereafter). Some
/// shapes are linear; the scanner cannot tell them apart, so every
/// bracket is charged worst-case. Vendored ledger schemas nest ≤3 deep.
pub(crate) const MAX_CDDL_NESTING_DEPTH: usize = 9;

/// Bracket depths charged zero work (growth is negligible here). Keeps
/// large shallow schemas free of [`MAX_CDDL_PARSE_WORK`].
const FREE_CDDL_NESTING_DEPTH: usize = 3;

/// Total CDDL parse work, in units of one outermost bracket.
///
/// Depth alone bounds one run; many deep runs multiply cost. Each
/// bracket at `depth` costs `3^(depth-1)` (0 below [`FREE_CDDL_NESTING_DEPTH`]).
/// ~7–16 µs/unit → ~70–160 ms; one run at [`MAX_CDDL_NESTING_DEPTH`] uses
/// ~9828 of 10000. The reject scan is a single iterative pass.
pub(crate) const MAX_CDDL_PARSE_WORK: u64 = 10_000;

// ============================================================
// CBOR
// ============================================================

/// Deepest nesting in `bytes` (root = 0). Stops once past `ceiling` or
/// at the first malformed header (reports depth of the valid prefix).
pub(crate) fn cbor_nesting_depth_capped(bytes: &[u8], ceiling: usize) -> usize {
    scan_cbor_shape(bytes, ceiling, usize::MAX).depth
}

/// Lower bound on position-map row items in `bytes` (excludes tag headers
/// and indefinite-string chunks). Stops past `ceiling` or at a fault.
pub(crate) fn cbor_item_count_capped(bytes: &[u8], ceiling: usize) -> usize {
    scan_cbor_shape(bytes, usize::MAX, ceiling).items
}

/// One iterative header pass over a document.
struct CborShape {
    /// Deepest level any item sits at.
    depth: usize,
    /// Items counted like [`cbor_item_count_capped`].
    items: usize,
}

/// Shared scan for [`cbor_nesting_depth_capped`] and [`cbor_item_count_capped`].
fn scan_cbor_shape(bytes: &[u8], depth_ceiling: usize, item_ceiling: usize) -> CborShape {
    /// One open container.
    struct Frame {
        /// Remaining items, or `None` for indefinite (break-closed).
        remaining: Option<usize>,
        /// Whether contents nest one level deeper (false for string chunks).
        nests: bool,
    }

    let mut stack: Vec<Frame> = Vec::new();
    let mut depth = 0usize;
    let mut max_depth = 0usize;
    let mut items = 0usize;
    let mut i = 0usize;

    loop {
        // Close every container that has taken all the items it declared.
        while matches!(
            stack.last(),
            Some(Frame {
                remaining: Some(0),
                ..
            })
        ) {
            if stack.pop().is_some_and(|f| f.nests) {
                depth -= 1;
            }
        }
        if i >= bytes.len() {
            break;
        }

        let initial = bytes[i];
        if initial == 0xff {
            i += 1;
            // A break closes the innermost indefinite container; anywhere
            // else it is malformed and the scan is done.
            if matches!(
                stack.last(),
                Some(Frame {
                    remaining: None,
                    ..
                })
            ) {
                if stack.pop().is_some_and(|f| f.nests) {
                    depth -= 1;
                }
                continue;
            }
            break;
        }

        // This byte starts an item, so it occupies one slot of the
        // container enclosing it and sits at that container's item level.
        if depth > max_depth {
            max_depth = depth;
            if max_depth > depth_ceiling {
                break;
            }
        }
        let chunk = matches!(stack.last(), Some(Frame { nests: false, .. }));
        if let Some(Frame {
            remaining: Some(remaining),
            ..
        }) = stack.last_mut()
        {
            *remaining -= 1;
        }

        let major = initial >> 5;
        let additional = initial & 0x1f;
        let (argument, header_len) = match additional {
            0..=23 => (Some(additional as u64), 1usize),
            24 => (read_be(bytes, i + 1, 1), 2),
            25 => (read_be(bytes, i + 1, 2), 3),
            26 => (read_be(bytes, i + 1, 4), 5),
            27 => (read_be(bytes, i + 1, 8), 9),
            31 => (None, 1),
            // 28..=30 are reserved: the input is malformed from here on.
            _ => break,
        };
        if (24..=27).contains(&additional) && argument.is_none() {
            // Header ran off the end of the buffer.
            break;
        }
        i += header_len;
        // The header is whole, so this is an item of the valid prefix.
        if major != 6 && !chunk {
            items += 1;
            if items > item_ceiling {
                break;
            }
        }

        let mut open = |remaining: Option<usize>, nests: bool| {
            stack.push(Frame { remaining, nests });
            if nests {
                depth += 1;
            }
        };

        match major {
            // Byte / text strings: definite forms carry an opaque payload,
            // indefinite forms carry chunks the decoder reads in place.
            2 | 3 => match argument {
                Some(len) => match usize::try_from(len).ok().and_then(|l| i.checked_add(l)) {
                    Some(end) if end <= bytes.len() => i = end,
                    _ => break,
                },
                None => open(None, false),
            },
            4 => match argument {
                Some(0) => {}
                Some(len) => match usize::try_from(len) {
                    Ok(n) => open(Some(n), true),
                    Err(_) => break,
                },
                None => open(None, true),
            },
            5 => match argument {
                Some(0) => {}
                // A map of n pairs holds 2n items, all one level down.
                Some(len) => match usize::try_from(len).ok().and_then(|n| n.checked_mul(2)) {
                    Some(n) => open(Some(n), true),
                    None => break,
                },
                None => open(None, true),
            },
            // A tag encloses exactly one item.
            6 => open(Some(1), true),
            // 0, 1 and 7 are complete in their header.
            _ => {}
        }
    }

    CborShape {
        depth: max_depth,
        items,
    }
}

/// Big-endian integer of `width` bytes at `at`, or `None` if truncated.
fn read_be(bytes: &[u8], at: usize, width: usize) -> Option<u64> {
    let end = at.checked_add(width)?;
    let slice = bytes.get(at..end)?;
    let mut value = 0u64;
    for byte in slice {
        value = (value << 8) | *byte as u64;
    }
    Some(value)
}

// ============================================================
// CDDL
// ============================================================

/// Why CDDL nesting was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum CddlNestingOverflow {
    /// One bracket run past [`MAX_CDDL_NESTING_DEPTH`].
    Depth,
    /// Total work past [`MAX_CDDL_PARSE_WORK`].
    Work,
}

/// CDDL nesting overflow: which bound, and the offending bracket offset.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct CddlOverflow {
    pub(crate) reason: CddlNestingOverflow,
    pub(crate) offset: usize,
}

impl CddlOverflow {
    /// Human-readable rejection (shared wording for every entry point).
    pub(crate) fn message(self) -> String {
        match self.reason {
            CddlNestingOverflow::Depth => format!(
                "CDDL nesting is deeper than the supported limit of {} levels of [ {{ (",
                MAX_CDDL_NESTING_DEPTH
            ),
            CddlNestingOverflow::Work => format!(
                "CDDL nests [ {{ ( too heavily to parse: nested brackets cost about three \
                 times as much per level, and this document's add up past the supported \
                 limit of {} levels' worth",
                MAX_CDDL_NESTING_DEPTH
            ),
        }
    }
}

/// First bracket taking `src` past [`MAX_CDDL_NESTING_DEPTH`] or
/// [`MAX_CDDL_PARSE_WORK`], or `None`. Brackets inside comments or
/// `"…"` / `'…'` literals (with `\` escapes) do not count.
pub(crate) fn cddl_nesting_overflow(src: &str) -> Option<CddlOverflow> {
    cddl_nesting_overflow_at(src, MAX_CDDL_NESTING_DEPTH, MAX_CDDL_PARSE_WORK)
}

/// [`cddl_nesting_overflow`] against arbitrary bounds.
pub(crate) fn cddl_nesting_overflow_at(
    src: &str,
    depth_limit: usize,
    work_limit: u64,
) -> Option<CddlOverflow> {
    let bytes = src.as_bytes();
    let mut depth = 0usize;
    let mut work = 0u64;
    let mut i = 0usize;

    while i < bytes.len() {
        match bytes[i] {
            b';' => {
                // Comment runs to the end of the line.
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            quote @ (b'"' | b'\'') => {
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == quote {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
            }
            b'[' | b'{' | b'(' => {
                depth += 1;
                if depth > depth_limit {
                    return Some(CddlOverflow {
                        reason: CddlNestingOverflow::Depth,
                        offset: i,
                    });
                }
                work = work.saturating_add(bracket_work(depth));
                if work > work_limit {
                    return Some(CddlOverflow {
                        reason: CddlNestingOverflow::Work,
                        offset: i,
                    });
                }
                i += 1;
            }
            b']' | b'}' | b')' => {
                depth = depth.saturating_sub(1);
                i += 1;
            }
            _ => i += 1,
        }
    }

    None
}

/// Work charged for one bracket at `depth` (1 = outermost), in
/// [`MAX_CDDL_PARSE_WORK`] units: `3^(depth-1)`, or 0 when shallow.
fn bracket_work(depth: usize) -> u64 {
    if depth <= FREE_CDDL_NESTING_DEPTH {
        return 0;
    }
    // Depth is ≤ MAX_CDDL_NESTING_DEPTH here; saturate for custom limits.
    3u64.checked_pow((depth - 1) as u32).unwrap_or(u64::MAX)
}

/// Refusal message for CBOR past the walkers' nesting bound.
pub(crate) fn cbor_nesting_message() -> String {
    format!(
        "CBOR nesting is deeper than the supported limit of {} levels",
        MAX_CBOR_NESTING_DEPTH
    )
}

/// Counting allocator for tests that check documented byte costs.
#[cfg(test)]
pub(crate) mod resident {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

    struct Counting;

    /// Bytes currently allocated.
    static LIVE: AtomicUsize = AtomicUsize::new(0);
    /// Peak bytes since last reset.
    static PEAK: AtomicUsize = AtomicUsize::new(0);

    fn grew(by: usize) {
        let live = LIVE.fetch_add(by, Relaxed) + by;
        PEAK.fetch_max(live, Relaxed);
    }

    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            grew(layout.size());
            System.alloc(layout)
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            grew(layout.size());
            System.alloc_zeroed(layout)
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            LIVE.fetch_sub(layout.size(), Relaxed);
            System.dealloc(ptr, layout)
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            grew(new_size);
            LIVE.fetch_sub(layout.size(), Relaxed);
            System.realloc(ptr, layout, new_size)
        }
    }

    #[global_allocator]
    static ALLOCATOR: Counting = Counting;

    /// Bytes allocated right now.
    pub(crate) fn live_bytes() -> usize {
        LIVE.load(Relaxed)
    }

    /// High-water mark since [`reset_peak`].
    pub(crate) fn peak_bytes() -> usize {
        PEAK.load(Relaxed)
    }

    pub(crate) fn reset_peak() {
        PEAK.store(LIVE.load(Relaxed), Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use std::process::{Command, Stdio};

    use super::*;

    fn depth(hex: &str) -> usize {
        let bytes = hex::decode(hex).unwrap();
        cbor_nesting_depth_capped(&bytes, usize::MAX)
    }

    fn nested_arrays(levels: usize) -> String {
        let mut s = String::new();
        for _ in 0..levels {
            s.push_str("81");
        }
        s.push_str("05");
        s
    }

    #[test]
    fn scalar_sits_at_the_root_level() {
        assert_eq!(depth("05"), 0);
        assert_eq!(depth("f6"), 0);
        assert_eq!(depth("43010203"), 0);
    }

    fn items(hex: &str) -> usize {
        cbor_item_count_capped(&hex::decode(hex).unwrap(), usize::MAX)
    }

    /// Items counted the way the position map emits rows (no tag headers /
    /// indefinite-string chunks).
    #[test]
    fn items_are_counted_the_way_the_position_map_has_rows_for_them() {
        assert_eq!(items("05"), 1);
        assert_eq!(items("80"), 1);
        assert_eq!(items("83010203"), 4);
        assert_eq!(items("a201020304"), 5);
        // A bignum: the tag header and its bytes are one item.
        assert_eq!(items("c249010000000000000000"), 1);
        // A tagged array: the array and its items.
        assert_eq!(items("d9010283010203"), 4);
        // An indefinite-length text string of two chunks is one item.
        assert_eq!(items("7f616161627fff"), 1);
        assert_eq!(items("827f6161ff05"), 3);
        // Indefinite-length containers close on a break.
        assert_eq!(items("9f0102ff"), 3);
        assert_eq!(items("bf0102ff"), 3);
    }

    /// Caps the count and stops at the first malformed header.
    #[test]
    fn the_item_count_is_capped_and_stops_at_a_fault() {
        let bytes = hex::decode("83010203").unwrap();
        assert_eq!(cbor_item_count_capped(&bytes, 2), 3);
        assert_eq!(cbor_item_count_capped(&bytes, 3), 4);
        // Reserved additional information after two valid items.
        assert_eq!(items("83011c02"), 2);
        // Truncated: two of the three declared items are there.
        assert_eq!(items("830102"), 3);
    }

    #[test]
    fn definite_arrays_count_one_level_each() {
        assert_eq!(depth("80"), 0);
        assert_eq!(depth("8105"), 1);
        assert_eq!(depth(&nested_arrays(1)), 1);
        assert_eq!(depth(&nested_arrays(7)), 7);
        assert_eq!(depth(&nested_arrays(300)), 300);
    }

    #[test]
    fn maps_tags_and_indefinite_chunks_all_count() {
        // a1 01 05 = {1: 5}
        assert_eq!(depth("a10105"), 1);
        // bf 01 05 ff = indefinite {1: 5}
        assert_eq!(depth("bf0105ff"), 1);
        // c1 05 = tag(1) 5
        assert_eq!(depth("c105"), 1);
        // c1 c1 c1 05
        assert_eq!(depth("c1c1c105"), 3);
        // 9f 05 ff = indefinite [5]
        assert_eq!(depth("9f05ff"), 1);
    }

    /// Indefinite string chunks are not a nesting level.
    #[test]
    fn indefinite_string_chunks_are_not_a_nesting_level() {
        // 5f 41 01 ff = indefinite bytes with one chunk
        assert_eq!(depth("5f4101ff"), 0);
        // 7f 61 61 ff = indefinite text with one chunk
        assert_eq!(depth("7f6161ff"), 0);
        // The same inside one array: the chunks stay at the array's level.
        assert_eq!(depth("815f4101ff"), 1);
    }

    #[test]
    fn sibling_items_do_not_stack() {
        // 83 05 05 05 = [5,5,5] — every element is at level 1, not 1,2,3.
        assert_eq!(depth("83050505"), 1);
        // 82 81 05 81 05 = [[5],[5]]
        assert_eq!(depth("8281058105"), 2);
    }

    #[test]
    fn a_definite_byte_string_payload_is_not_scanned_as_items() {
        // 43 818105 — a 3-byte string whose bytes look like nested arrays.
        assert_eq!(depth("43818105"), 0);
    }

    #[test]
    fn the_scan_stops_at_the_ceiling() {
        let bytes = hex::decode(nested_arrays(5000)).unwrap();
        assert_eq!(cbor_nesting_depth_capped(&bytes, 10), 11);
    }

    #[test]
    fn truncated_and_malformed_input_terminates_the_scan() {
        // Header promises 8 argument bytes that are not there.
        assert_eq!(depth("9b0000"), 0);
        // Reserved additional-information value.
        assert_eq!(depth("1c"), 0);
        // Array header with no elements following.
        assert_eq!(depth("83"), 0);
        // Stray break.
        assert_eq!(depth("ff"), 0);
        // Enormous declared array length: no allocation, scan still ends.
        assert_eq!(depth("9bffffffffffffffff05"), 1);
    }

    #[test]
    fn the_budget_admits_a_document_up_to_the_documented_boundary() {
        let at = hex::decode(nested_arrays(MAX_CBOR_NESTING_DEPTH)).unwrap();
        let budget = NestingBudget::for_document(&at).expect("the bound itself is admitted");
        // It filled the budget, so nothing is left for a payload.
        assert_eq!(budget.remaining.get(), 0);

        let past = hex::decode(nested_arrays(MAX_CBOR_NESTING_DEPTH + 1)).unwrap();
        assert!(NestingBudget::for_document(&past).is_none());
    }

    #[test]
    fn a_document_is_charged_the_deepest_level_it_reaches() {
        let doc = hex::decode(nested_arrays(10)).unwrap();
        let budget = NestingBudget::for_document(&doc).unwrap();
        assert_eq!(budget.remaining.get(), MAX_CBOR_NESTING_DEPTH - 10);
    }

    /// Charge while held; refund on drop — spent is one path, not the whole run.
    #[test]
    fn a_descent_step_is_charged_while_held_and_returned_when_left() {
        let budget = DescentBudget::new(1000);
        let outer = budget.charge(400).expect("fits");
        assert_eq!(budget.spent.get(), 400);
        {
            let _inner = budget.charge(600).expect("fills the budget exactly");
            assert_eq!(budget.spent.get(), 1000);
        }
        assert_eq!(budget.spent.get(), 400);
        drop(outer);
        assert_eq!(budget.spent.get(), 0);
        assert!(!budget.exhausted());
        assert_eq!(budget.refusal(), None);
    }

    /// One byte past the limit refuses; later charges stay refused after refund.
    #[test]
    fn a_descent_step_past_the_limit_is_refused_and_ends_the_walk() {
        let budget = DescentBudget::new(1000);
        let held = budget.charge(1000).expect("the limit itself is admitted");
        assert!(budget.charge(1).is_none());
        assert!(budget.exhausted());
        let message = budget.refusal().expect("a refused step is reported");
        assert!(message.contains("1000"), "{}", message);
        assert!(
            message.contains("limit") || message.contains("budget"),
            "{}",
            message
        );

        drop(held);
        assert_eq!(budget.spent.get(), 0, "the charge is still returned");
        assert!(
            budget.charge(1).is_none(),
            "a walk past a refusal is unwinding, not answering"
        );
    }

    /// Decoder bound ≥ walkers' bound and counts the same way.
    #[test]
    fn the_decoder_follows_at_least_as_deep_as_the_walkers_admit() {
        assert!(MAX_CBOR_DECODE_NESTING_DEPTH >= MAX_CBOR_NESTING_DEPTH);
        let at = hex::decode(nested_arrays(MAX_CBOR_NESTING_DEPTH)).unwrap();
        assert_eq!(
            cbor_nesting_depth_capped(&at, usize::MAX),
            MAX_CBOR_NESTING_DEPTH
        );
        assert!(crate::cbor::decoder::decode_cbor_to_value(&at).is_ok());
    }

    /// Descent budgets carry the levels their docs claim (≤2 hops/level;
    /// longest chain shallower than the nesting bound).
    #[test]
    fn the_descent_budgets_carry_the_levels_they_are_documented_to() {
        for (budget, weights) in [
            (MAX_CBOR_MAPPING_DESCENT_COST, SCHEMA_WALKER_DESCENT),
            (MAX_CBOR_POSITION_MAP_DESCENT_COST, POSITION_MAP_DESCENT),
        ] {
            for hops in 0..=2 {
                let per_level = weights.level + hops * weights.rule_hop;
                assert!(budget / per_level > MAX_CBOR_NESTING_DEPTH);
            }
            let per_level = weights.level + MAX_CBOR_MAPPING_RULE_NESTING * weights.rule_hop;
            let levels = budget / per_level;
            assert!(
                levels > 256 && levels < MAX_CBOR_NESTING_DEPTH / 8,
                "{}",
                levels
            );
            // A subtree emitted raw is charged per level as well, and
            // never binds before the count does.
            assert!(budget / weights.raw_level > MAX_CBOR_NESTING_DEPTH);
        }
        // The chain of the schema walker's example, and the position map's.
        assert_eq!(
            SCHEMA_WALKER_DESCENT.level
                + MAX_CBOR_MAPPING_RULE_NESTING * SCHEMA_WALKER_DESCENT.rule_hop,
            270_336
        );
        assert_eq!(
            POSITION_MAP_DESCENT.level
                + MAX_CBOR_MAPPING_RULE_NESTING * POSITION_MAP_DESCENT.rule_hop,
            552_960
        );
    }

    /// Work steps are not refunded; past the limit every step fails.
    #[test]
    fn a_work_step_past_the_limit_is_refused_and_ends_the_walk() {
        let budget = WorkBudget::new(3, mapping_work_message);
        assert!(budget.step() && budget.step() && budget.step());
        assert!(!budget.exhausted());
        assert_eq!(budget.spent(), 3);
        assert!(!budget.step());
        assert!(budget.exhausted());
        assert!(budget.refusal().unwrap_or_default().contains("3 steps"));
        assert!(!budget.step());
        assert_eq!(budget.spent(), 3);
    }

    /// Document nesting is not available again for an embedded payload.
    #[test]
    fn a_payload_is_charged_against_what_the_document_left() {
        let half = MAX_CBOR_NESTING_DEPTH / 2;
        let doc = hex::decode(nested_arrays(half)).unwrap();
        let budget = NestingBudget::for_document(&doc).unwrap();

        // A payload filling exactly what is left is admitted.
        let fits = hex::decode(nested_arrays(MAX_CBOR_NESTING_DEPTH - half)).unwrap();
        let guard = budget
            .enter_embedded(&fits)
            .expect("a payload that fits the rest is admitted");
        assert_eq!(budget.remaining.get(), 0);
        // Nothing nested inside it is, however shallow.
        let scalar = hex::decode(nested_arrays(1)).unwrap();
        assert!(budget.enter_embedded(&scalar).is_none());

        // Leaving the payload returns its share to the enclosing document.
        drop(guard);
        assert_eq!(budget.remaining.get(), MAX_CBOR_NESTING_DEPTH - half);
    }

    /// Exact remaining depth is admitted; one level more is declined.
    #[test]
    fn a_payload_one_level_past_what_is_left_is_declined() {
        // A byte string at the root: the document itself costs nothing.
        let budget = NestingBudget::for_document(&hex::decode("40").unwrap()).unwrap();
        let at = hex::decode(nested_arrays(MAX_CBOR_NESTING_DEPTH)).unwrap();
        assert!(budget.enter_embedded(&at).is_some());
        let past = hex::decode(nested_arrays(MAX_CBOR_NESTING_DEPTH + 1)).unwrap();
        assert!(budget.enter_embedded(&past).is_none());
    }

    /// Flat payloads still cost open frames; the chain is bounded.
    #[test]
    fn the_open_payload_count_is_bounded_on_its_own() {
        let scalar = hex::decode("05").unwrap();
        let budget = NestingBudget::for_document(&scalar).unwrap();

        let mut open = Vec::new();
        for level in 0..MAX_EMBEDDED_DEPTH {
            open.push(
                budget
                    .enter_embedded(&scalar)
                    .unwrap_or_else(|| panic!("level {} is within the bound", level)),
            );
        }
        assert_eq!(
            budget.remaining.get(),
            MAX_CBOR_NESTING_DEPTH,
            "flat payloads spend no nesting"
        );
        assert!(budget.enter_embedded(&scalar).is_none());

        // Leaving one makes room for another.
        open.pop();
        assert!(budget.enter_embedded(&scalar).is_some());
    }

    /// Bare nested brackets — the slow parse shape the bound is pinned to.
    pub(crate) fn deep_schema(levels: usize) -> String {
        wrapped_schema("x", "[", "]", levels)
    }

    fn wrapped_schema(name: &str, open: &str, close: &str, levels: usize) -> String {
        let mut s = format!("{} = ", name);
        for _ in 0..levels {
            s.push_str(open);
        }
        s.push_str("uint");
        for _ in 0..levels {
            s.push_str(close);
        }
        s
    }

    #[test]
    fn shallow_schemas_pass_the_bracket_scan() {
        assert_eq!(cddl_nesting_overflow("x = int"), None);
        assert_eq!(cddl_nesting_overflow("x = [a: {b: (int)}]"), None);
        assert_eq!(
            cddl_nesting_overflow(&deep_schema(MAX_CDDL_NESTING_DEPTH)),
            None
        );
    }

    /// Every bracket shape is charged the same (scanner cannot tell fast from slow).
    #[test]
    fn the_bound_holds_for_every_bracket_shape() {
        for (open, close) in [("[", "]"), ("{", "}"), ("[* ", "]"), ("[uint, ", "]")] {
            let at = wrapped_schema("x", open, close, MAX_CDDL_NESTING_DEPTH);
            assert_eq!(cddl_nesting_overflow(&at), None, "{}{}", open, close);
            let past = wrapped_schema("x", open, close, MAX_CDDL_NESTING_DEPTH + 1);
            assert_eq!(
                cddl_nesting_overflow(&past).map(|o| o.reason),
                Some(CddlNestingOverflow::Depth),
                "{}{}",
                open,
                close
            );
        }
    }

    #[test]
    fn deep_schemas_fail_the_bracket_scan_at_the_offending_bracket() {
        let src = deep_schema(MAX_CDDL_NESTING_DEPTH + 1);
        let overflow = cddl_nesting_overflow(&src).expect("expected an overflow");
        assert_eq!(overflow.reason, CddlNestingOverflow::Depth);
        let at = overflow.offset;
        assert_eq!(&src[at..at + 1], "[");
        // The bracket that trips it is the one after the limit is filled.
        assert_eq!(src[..at].matches('[').count(), MAX_CDDL_NESTING_DEPTH);
    }

    /// Many deep runs exhaust the work budget even when each is within depth.
    #[test]
    fn repeated_deep_runs_exhaust_the_work_budget() {
        let mut src = String::new();
        for i in 0..8 {
            src.push_str(&wrapped_schema(
                &format!("r{}", i),
                "[",
                "]",
                MAX_CDDL_NESTING_DEPTH,
            ));
            src.push('\n');
        }
        let overflow = cddl_nesting_overflow(&src).expect("expected an overflow");
        assert_eq!(overflow.reason, CddlNestingOverflow::Work);
        // Charged to a bracket, so an editor still has somewhere to point.
        assert_eq!(&src[overflow.offset..overflow.offset + 1], "[");
    }

    /// Breadth alone never exhausts the work budget.
    #[test]
    fn breadth_alone_never_exhausts_the_work_budget() {
        let mut src = String::new();
        for i in 0..5000 {
            src.push_str(&format!("r{} = [a: [b: [c: uint]]]\n", i));
        }
        assert_eq!(cddl_nesting_overflow(&src), None);
    }

    /// Depth limit matches the deepest single run the work budget admits.
    #[test]
    fn the_depth_limit_is_the_deepest_run_the_budget_admits() {
        assert_eq!(
            cddl_nesting_overflow(&deep_schema(MAX_CDDL_NESTING_DEPTH)),
            None
        );
        let past = deep_schema(MAX_CDDL_NESTING_DEPTH + 1);
        // Deeper than the depth limit *and* past the budget: raising the
        // depth limit alone would not admit it.
        assert!(cddl_nesting_overflow(&past).is_some());
        assert_eq!(
            cddl_nesting_overflow_at(&past, usize::MAX, MAX_CDDL_PARSE_WORK).map(|o| o.reason),
            Some(CddlNestingOverflow::Work)
        );
    }

    #[test]
    fn brackets_in_comments_and_literals_do_not_count() {
        let mut src = String::from("; ");
        src.push_str(&"[".repeat(200));
        src.push_str("\nx = \"");
        src.push_str(&"{".repeat(200));
        src.push_str("\"\ny = h'5b5b5b'\nz = '");
        src.push_str(&"(".repeat(200));
        src.push_str("'\n");
        assert_eq!(cddl_nesting_overflow(&src), None);
    }

    #[test]
    fn an_escaped_quote_does_not_end_a_literal_early() {
        // The `\"` keeps the literal open, so the brackets after it are
        // still payload.
        let src = format!("x = \"a\\\"{}\"\n", "[".repeat(200));
        assert_eq!(cddl_nesting_overflow(&src), None);
    }

    #[test]
    fn unbalanced_closers_do_not_underflow() {
        let src = format!("{}x = int", "]".repeat(100));
        assert_eq!(cddl_nesting_overflow(&src), None);
    }

    #[test]
    fn sibling_brackets_do_not_accumulate() {
        let src = format!("x = [{}]", "[int],".repeat(500));
        assert_eq!(cddl_nesting_overflow(&src), None);
    }

    // ============================================================
    // What a decoded level costs, measured from outside the process
    // ============================================================

    /// Env flag to run the decode resident probe.
    const RESIDENT_SPEC: &str = "CQUISITOR_DECODE_RESIDENT_PROBE";

    /// Libtest name of [`decode_resident_probe`].
    const RESIDENT_TEST: &str = "cbor::limits::tests::decode_resident_probe";

    /// Max decoded bytes/level at [`MAX_CBOR_DECODE_NESTING_DEPTH`] (~1.9 KB + margin).
    const DECODED_LEVEL_BYTES: usize = 2560;

    /// Max JSON bytes/level (~135 + margin).
    const WRITTEN_LEVEL_BYTES: usize = 180;

    /// Max peak bytes for decode+write+free at the bound (~38 MB + margin).
    const PEAK_BYTES: usize = 48 * 1024 * 1024;

    /// Decode/write/free the deepest array chain; print held/written/peak/after.
    /// Driven as an ignored child of the resident-cost test.
    #[test]
    #[ignore = "an entry point the resident-cost test drives, not a check of its own"]
    fn decode_resident_probe() {
        if std::env::var(RESIDENT_SPEC).is_err() {
            return;
        }
        let bytes = hex::decode(nested_arrays(MAX_CBOR_DECODE_NESTING_DEPTH)).unwrap();
        let before = super::resident::live_bytes();
        super::resident::reset_peak();
        let tree =
            crate::cbor::decoder::decode_cbor_to_value(&bytes).expect("decodes at the bound");
        let held = super::resident::live_bytes() - before;
        let text = crate::deep_json::write_json(&tree);
        drop(tree);
        let peak = super::resident::peak_bytes() - before;
        let written = text.len();
        drop(text);
        let after = super::resident::live_bytes() - before;
        println!(
            "held={} written={} peak={} after={}",
            held, written, peak, after
        );
    }

    /// Checks the figures documented for [`MAX_CBOR_DECODE_NESTING_DEPTH`].
    #[test]
    fn the_decoder_bound_holds_what_it_is_documented_to() {
        let output = Command::new(std::env::current_exe().expect("the test binary's own path"))
            .args([
                "--exact",
                RESIDENT_TEST,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(RESIDENT_SPEC, "1")
            .stdin(Stdio::null())
            .output()
            .expect("failed to run the measurement child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{}{}",
            stdout,
            String::from_utf8_lossy(&output.stderr)
        );
        // The child's line, under whatever prefix libtest put before it.
        let line = stdout
            .lines()
            .find_map(|l| l.find("held=").map(|at| &l[at..]))
            .unwrap_or_else(|| panic!("the child measured nothing:\n{}", stdout));
        let field = |name: &str| -> usize {
            line.split_whitespace()
                .find_map(|kv| kv.strip_prefix(name).and_then(|v| v.strip_prefix('=')))
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| panic!("no {} in {}", name, line))
        };
        let levels = MAX_CBOR_DECODE_NESTING_DEPTH;
        let (held, written, peak, after) = (
            field("held"),
            field("written"),
            field("peak"),
            field("after"),
        );
        assert!(
            held <= levels * DECODED_LEVEL_BYTES,
            "a decoded level holds {} bytes, more than the {} documented",
            held / levels,
            DECODED_LEVEL_BYTES
        );
        assert!(
            written <= levels * WRITTEN_LEVEL_BYTES,
            "a written level is {} bytes, more than the {} documented",
            written / levels,
            WRITTEN_LEVEL_BYTES
        );
        assert!(
            peak <= PEAK_BYTES,
            "the walk peaked at {} bytes, more than the {} documented",
            peak,
            PEAK_BYTES
        );
        assert_eq!(after, 0, "the walk left {} bytes allocated", after);
    }

    // ============================================================
    // What a validated level holds, measured from outside the process
    // ============================================================

    /// Env flag to run the validator resident probe.
    const VALIDATOR_RESIDENT_SPEC: &str = "CQUISITOR_VALIDATOR_RESIDENT_PROBE";

    /// Libtest name of [`validator_resident_probe`].
    const VALIDATOR_RESIDENT_TEST: &str = "cbor::limits::tests::validator_resident_probe";

    /// (name, schema, nested doc builder, rule hops per level).
    type ResidentShape = (&'static str, String, fn(usize) -> String, usize);

    /// Shapes the validator weights are stated for.
    fn validator_resident_shapes() -> Vec<ResidentShape> {
        fn arrays(levels: usize) -> String {
            format!("{}05", "81".repeat(levels))
        }
        fn maps(levels: usize) -> String {
            format!("{}05", "a100".repeat(levels))
        }
        fn empty_arrays(levels: usize) -> String {
            format!("{}80", "81".repeat(levels))
        }
        // A chain of aliases as long as the validator admits at one item,
        // resolved afresh at every level.
        let aliases = cddl::validator::DEFAULT_MAX_RULE_NESTING - 1;
        let mut chain = String::from("x = [* r0]\n");
        for alias in 0..aliases - 1 {
            chain.push_str(&format!("r{} = r{}\n", alias, alias + 1));
        }
        chain.push_str(&format!("r{} = x\n", aliases - 1));
        vec![
            ("arrays", "x = [* x] / uint".to_string(), arrays, 1),
            ("maps", "x = {* uint => x} / uint".to_string(), maps, 1),
            (
                "generic",
                "x = [* g<x>] / uint\ng<t> = t".to_string(),
                arrays,
                2,
            ),
            ("aliases", chain, empty_arrays, aliases + 1),
        ]
    }

    /// Peak memory at two depths per shape (slope = per-level cost). Child probe.
    #[test]
    #[ignore = "an entry point the resident-cost test drives, not a check of its own"]
    fn validator_resident_probe() {
        if std::env::var(VALIDATOR_RESIDENT_SPEC).is_err() {
            return;
        }
        for (name, schema, shape, _) in validator_resident_shapes() {
            let mut peaks = Vec::new();
            for levels in [VALIDATOR_RESIDENT_SHALLOW, VALIDATOR_RESIDENT_DEEP] {
                let bytes = hex::decode(shape(levels)).unwrap();
                let before = super::resident::live_bytes();
                super::resident::reset_peak();
                let out =
                    crate::cbor::validation::validate_cbor_bytes_against_cddl(&bytes, &schema, "x");
                assert_eq!(out["valid"], serde_json::Value::Bool(true), "{}", out);
                peaks.push(super::resident::peak_bytes() - before);
            }
            println!("shape={} shallow={} deep={}", name, peaks[0], peaks[1]);
        }
    }

    /// Depths used for the per-level memory slope.
    const VALIDATOR_RESIDENT_SHALLOW: usize = 200;
    const VALIDATOR_RESIDENT_DEEP: usize = 600;

    /// Measured held bytes/level ≤ charged weight for each stated shape.
    #[test]
    fn the_validator_weights_cover_what_a_level_holds() {
        let output = Command::new(std::env::current_exe().expect("the test binary's own path"))
            .args([
                "--exact",
                VALIDATOR_RESIDENT_TEST,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(VALIDATOR_RESIDENT_SPEC, "1")
            .stdin(Stdio::null())
            .output()
            .expect("failed to run the measurement child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{}{}",
            stdout,
            String::from_utf8_lossy(&output.stderr)
        );
        let field = |line: &str, name: &str| -> usize {
            line.split_whitespace()
                .find_map(|kv| kv.strip_prefix(name).and_then(|v| v.strip_prefix('=')))
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| panic!("no {} in {}", name, line))
        };
        let span = VALIDATOR_RESIDENT_DEEP - VALIDATOR_RESIDENT_SHALLOW;
        for (name, _, _, hops) in validator_resident_shapes() {
            let line = stdout
                .lines()
                .find_map(|l| l.find(&format!("shape={} ", name)).map(|at| &l[at..]))
                .unwrap_or_else(|| panic!("the child did not measure {}:\n{}", name, stdout));
            let (shallow, deep) = (field(line, "shallow"), field(line, "deep"));
            let held = deep.saturating_sub(shallow) / span;
            let charged = VALIDATOR_LEVEL_COST + hops * VALIDATOR_RULE_HOP_COST;
            assert!(
                held <= charged,
                "a level of {} holds {} bytes, more than the {} it is charged",
                name,
                held,
                charged
            );
        }
    }

    // ============================================================
    // What a level holds in the two schema walkers, measured from
    // outside the process
    // ============================================================

    /// Env flag naming which walker to measure.
    const MAPPER_RESIDENT_SPEC: &str = "CQUISITOR_MAPPER_RESIDENT_PROBE";

    /// Libtest name of [`mapper_resident_probe`].
    const MAPPER_RESIDENT_TEST: &str = "cbor::limits::tests::mapper_resident_probe";

    /// (name, schema, doc builder, hops/level, raw levels).
    type MapperShape = (&'static str, String, fn(usize) -> String, usize, usize);

    fn mapper_resident_shapes() -> Vec<MapperShape> {
        fn arrays(levels: usize) -> String {
            format!("{}05", "81".repeat(levels))
        }
        fn maps(levels: usize) -> String {
            format!("{}05", "a100".repeat(levels))
        }
        fn tags(levels: usize) -> String {
            format!("{}05", "c1".repeat(levels))
        }
        fn empty_arrays(levels: usize) -> String {
            format!("{}80", "81".repeat(levels))
        }
        /// Arrays around a rejected text string (lenient pass takes every level).
        fn lenient_arrays(levels: usize) -> String {
            format!("{}60", "81".repeat(levels))
        }
        let aliases = MAX_CBOR_MAPPING_RULE_NESTING - 1;
        let mut chain = String::from("x = [* r0]\n");
        for alias in 0..aliases - 1 {
            chain.push_str(&format!("r{} = r{}\n", alias, alias + 1));
        }
        chain.push_str(&format!("r{} = x\n", aliases - 1));
        vec![
            ("arrays", "x = [* x] / uint".to_string(), arrays, 1, 0),
            ("named", "x = [a: x] / uint".to_string(), arrays, 1, 0),
            ("maps", "x = {* uint => x} / uint".to_string(), maps, 1, 0),
            ("tags", "x = #6.1(x) / uint".to_string(), tags, 1, 0),
            (
                "lenient",
                "x = [a: x] / uint".to_string(),
                lenient_arrays,
                1,
                0,
            ),
            (
                "generic",
                "x = [* g<x>] / uint\ng<t> = t".to_string(),
                arrays,
                2,
                0,
            ),
            ("aliases", chain, empty_arrays, aliases + 1, 0),
            ("raw", "x = any".to_string(), arrays, 0, 1),
        ]
    }

    /// Peak memory at two depths for the walker named by the env var. Child probe.
    #[test]
    #[ignore = "an entry point the resident-cost tests drive, not a check of its own"]
    fn mapper_resident_probe() {
        let Ok(walker) = std::env::var(MAPPER_RESIDENT_SPEC) else {
            return;
        };
        for (name, schema, shape, _, _) in mapper_resident_shapes() {
            let mut peaks = Vec::new();
            for levels in [VALIDATOR_RESIDENT_SHALLOW, VALIDATOR_RESIDENT_DEEP] {
                let bytes = hex::decode(shape(levels)).unwrap();
                let before = super::resident::live_bytes();
                super::resident::reset_peak();
                match walker.as_str() {
                    "schema_walker" => {
                        let out = crate::cbor::schema_mapper::decode_cbor_against_cddl(
                            &bytes, &schema, "x",
                        )
                        .unwrap_or_else(|e| panic!("{}: {}", name, e));
                        drop(crate::deep_json::DeepJson::new(out));
                    }
                    "position_map" => {
                        crate::cbor::cbor_cddl_map::map_cbor_to_cddl_text(&bytes, &schema, "x")
                            .unwrap_or_else(|e| panic!("{}: {}", name, e));
                    }
                    other => panic!("no walker named {}", other),
                }
                peaks.push(super::resident::peak_bytes() - before);
            }
            println!("shape={} shallow={} deep={}", name, peaks[0], peaks[1]);
        }
    }

    /// Measured held bytes/level ≤ charged weight for `walker`.
    fn a_walkers_weights_cover_what_a_level_holds(walker: &str, weights: DescentWeights) {
        let output = Command::new(std::env::current_exe().expect("the test binary's own path"))
            .args([
                "--exact",
                MAPPER_RESIDENT_TEST,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(MAPPER_RESIDENT_SPEC, walker)
            .stdin(Stdio::null())
            .output()
            .expect("failed to run the measurement child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{}{}",
            stdout,
            String::from_utf8_lossy(&output.stderr)
        );
        let field = |line: &str, name: &str| -> usize {
            line.split_whitespace()
                .find_map(|kv| kv.strip_prefix(name).and_then(|v| v.strip_prefix('=')))
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| panic!("no {} in {}", name, line))
        };
        let span = VALIDATOR_RESIDENT_DEEP - VALIDATOR_RESIDENT_SHALLOW;
        for (name, _, _, hops, raw) in mapper_resident_shapes() {
            let line = stdout
                .lines()
                .find_map(|l| l.find(&format!("shape={} ", name)).map(|at| &l[at..]))
                .unwrap_or_else(|| panic!("the child did not measure {}:\n{}", name, stdout));
            let (shallow, deep) = (field(line, "shallow"), field(line, "deep"));
            let held = deep.saturating_sub(shallow) / span;
            let charged = if raw > 0 {
                raw * weights.raw_level
            } else {
                weights.level + hops * weights.rule_hop
            };
            assert!(
                held <= charged,
                "a level of {} holds {} bytes in the {}, more than the {} it is charged",
                name,
                held,
                walker,
                charged
            );
        }
    }

    #[test]
    fn the_schema_walker_weights_cover_what_a_level_holds() {
        a_walkers_weights_cover_what_a_level_holds("schema_walker", SCHEMA_WALKER_DESCENT);
    }

    #[test]
    fn the_position_map_weights_cover_what_a_level_holds() {
        a_walkers_weights_cover_what_a_level_holds("position_map", POSITION_MAP_DESCENT);
    }

    // ============================================================
    // What the position map holds per row, measured outside the process
    // ============================================================

    /// Env flag for the position-map row probe.
    const POSITION_MAP_ROWS_SPEC: &str = "CQUISITOR_POSITION_MAP_ROWS_PROBE";

    /// Libtest name of [`position_map_rows_resident_probe`].
    const POSITION_MAP_ROWS_TEST: &str = "cbor::limits::tests::position_map_rows_resident_probe";

    /// Widths for the per-row memory slope.
    const POSITION_MAP_ROWS_NARROW: usize = 20_000;
    const POSITION_MAP_ROWS_WIDE: usize = 60_000;

    /// Max text bytes charged per row (≤512 B text, buffer may double).
    const POSITION_MAP_ROW_TEXT_BYTES: usize = 1024;

    /// Flat array of `items` one-byte integers → `[* uint]` map has ~1 row/item.
    fn flat_array(items: usize) -> Vec<u8> {
        let mut bytes = vec![0x9a];
        bytes.extend_from_slice(&(items as u32).to_be_bytes());
        bytes.extend(std::iter::repeat_n(0u8, items));
        bytes
    }

    /// Peak memory at two widths for decoder / schema walker / position map. Child probe.
    #[test]
    #[ignore = "an entry point the per-row cost test drives, not a check of its own"]
    fn position_map_rows_resident_probe() {
        if std::env::var(POSITION_MAP_ROWS_SPEC).is_err() {
            return;
        }
        for items in [POSITION_MAP_ROWS_NARROW, POSITION_MAP_ROWS_WIDE] {
            let bytes = flat_array(items);
            let mut peaks = Vec::new();
            for walker in ["decoder", "schema_walker", "position_map"] {
                let before = super::resident::live_bytes();
                super::resident::reset_peak();
                match walker {
                    "decoder" => {
                        let tree = crate::cbor::decoder::decode_cbor_to_value(&bytes)
                            .expect("the array decodes");
                        drop(tree);
                    }
                    "schema_walker" => {
                        let out = crate::cbor::schema_mapper::decode_cbor_against_cddl(
                            &bytes,
                            "x = [* uint]",
                            "x",
                        )
                        .expect("the array decodes against the schema");
                        drop(crate::deep_json::DeepJson::new(out));
                    }
                    _ => {
                        crate::cbor::cbor_cddl_map::map_cbor_to_cddl_text(
                            &bytes,
                            "x = [* uint]",
                            "x",
                        )
                        .expect("the array maps");
                    }
                }
                peaks.push(format!(
                    "{}={}",
                    walker,
                    super::resident::peak_bytes() - before
                ));
            }
            println!("items={} {}", items, peaks.join(" "));
        }
    }

    /// Per-row growth ≤ node cost (decoder + schema walker) + row text.
    #[test]
    fn the_position_map_holds_its_rows_as_text() {
        let output = Command::new(std::env::current_exe().expect("the test binary's own path"))
            .args([
                "--exact",
                POSITION_MAP_ROWS_TEST,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(POSITION_MAP_ROWS_SPEC, "1")
            .stdin(Stdio::null())
            .output()
            .expect("failed to run the measurement child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{}{}",
            stdout,
            String::from_utf8_lossy(&output.stderr)
        );
        let field = |line: &str, name: &str| -> usize {
            line.split_whitespace()
                .find_map(|kv| kv.strip_prefix(name).and_then(|v| v.strip_prefix('=')))
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| panic!("no {} in {}", name, line))
        };
        let line_for = |items: usize| -> &str {
            stdout
                .lines()
                .find_map(|l| l.find(&format!("items={} ", items)).map(|at| &l[at..]))
                .unwrap_or_else(|| panic!("the child did not measure {} items:\n{}", items, stdout))
        };
        let (narrow, wide) = (
            line_for(POSITION_MAP_ROWS_NARROW),
            line_for(POSITION_MAP_ROWS_WIDE),
        );
        let span = POSITION_MAP_ROWS_WIDE - POSITION_MAP_ROWS_NARROW;
        let per_row = |walker: &str| (field(wide, walker) - field(narrow, walker)) / span;
        let held = per_row("position_map");
        let node = per_row("decoder") + per_row("schema_walker");
        assert!(
            held <= node + POSITION_MAP_ROW_TEXT_BYTES,
            "a row of the position map holds {} bytes, more than the {} bytes of the node it reads and the {} of its text",
            held,
            node,
            POSITION_MAP_ROW_TEXT_BYTES
        );
    }
}

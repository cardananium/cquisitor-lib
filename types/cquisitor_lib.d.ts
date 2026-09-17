/**
* @param {string} tx_hex
* @param {NetworkType} network_type
* @returns {string}
*/
export function get_necessary_data_list_js(tx_hex: string, network_type: NetworkType): string;

/**
 * Extracts all script and datum hashes from a transaction
 * @param {string} tx_hex - Hex-encoded transaction bytes
 * @returns {string} JSON string with ExtractedHashes structure
 * 
 * Schema:
 * ```typescript
 * interface ExtractedHashes {
 *   // Script hashes from witness set (native scripts) - indexed by position in witness set
 *   witness_native_script_hashes: (string | null)[];
 *   // Script info from witness set (plutus scripts) - indexed by position in witness set
 *   witness_plutus_scripts: (PlutusScriptInfo | null)[];
 *   // Datum hashes from witness set (plutus_data) - indexed by position in witness set
 *   witness_datum_hashes: (string | null)[];
 *   // Inlined script info from transaction outputs (script_ref) - indexed by output index
 *   output_inline_scripts: (InlineScriptInfo | null)[];
 *   // Inlined datum hashes from transaction outputs (inline datum) - indexed by output index
 *   output_inline_datum_hashes: (string | null)[];
 *   // Datum hashes from transaction outputs (data_hash field) - indexed by output index
 *   output_datum_hashes: (string | null)[];
 * }
 * 
 * interface PlutusScriptInfo {
 *   hash: string;
 *   version: PlutusVersion;
 * }
 * 
 * type PlutusVersion = "V1" | "V2" | "V3";
 * 
 * interface InlineScriptInfo {
 *   hash: string;
 *   script_type: InlineScriptType;
 * }
 * 
 * type InlineScriptType = "Native" | { Plutus: PlutusVersion };
 * ```
 */
export function extract_hashes_from_transaction_js(tx_hex: string): string;

  // ========== ExtractedHashes types ==========
  
export interface ExtractedHashes {
  /** Script hashes from witness set (native scripts) - indexed by position in witness set */
  witness_native_script_hashes: (string | null)[];
  /** Script info from witness set (plutus scripts) - indexed by position in witness set */
  witness_plutus_scripts: (PlutusScriptInfo | null)[];
  /** Datum hashes from witness set (plutus_data) - indexed by position in witness set */
  witness_datum_hashes: (string | null)[];
  /** Inlined script info from transaction outputs (script_ref) - indexed by output index */
  output_inline_scripts: (InlineScriptInfo | null)[];
  /** Inlined datum hashes from transaction outputs (inline datum) - indexed by output index */
  output_inline_datum_hashes: (string | null)[];
  /** Datum hashes from transaction outputs (data_hash field) - indexed by output index */
  output_datum_hashes: (string | null)[];
}

export interface PlutusScriptInfo {
  hash: string;
  version: PlutusVersion;
}

export type PlutusVersion = "V1" | "V2" | "V3";

export interface InlineScriptInfo {
  hash: string;
  script_type: InlineScriptType;
}

export type InlineScriptType = "Native" | { Plutus: PlutusVersion };

/**
* @param {string} tx_hex
* @param {ValidationInputContext} validation_context
* @returns {string}
*/
export function validate_transaction_js(tx_hex: string, validation_context: string): string;

/**
 * @returns {(string)[]}
 */
export function get_decodable_types(): (string)[];
/**
 * Decodes `input` as the named ledger type, through the serialization
 * library's own decoder for it, and answers with the object it decodes
 * to. Throws a string naming the reason when it does not decode.
 *
 * **CBOR nesting stops at 256 levels here.** The typed decoders, and
 * the walk that serialises their answer across the boundary, recurse on
 * the host's own stack, which none of the heap-walking bounds above
 * measure; so hex input is scanned for its depth first, iteratively,
 * and a document nested more than 256 levels below its root is refused
 * by a thrown message naming the limit rather than handed to a decoder.
 * An implementation limit, never a verdict on the bytes — and far above
 * any ledger document: metadata, the one ledger type whose nesting the
 * ledger leaves unbounded, nests a handful of levels in practice. Input
 * that is not hex carries no CBOR to nest and is not scanned.
 *
 * @param {string} input
 * @param {string} type_name
 * @param {any} params_json
 * @returns {any}
 */
export function decode_specific_type(input: string, type_name: string, params_json: DecodingParams): any;
/**
 * The names of the ledger types `input` decodes as, sorted. Hex input
 * nested more than 256 levels below its root decodes as none of them:
 * it is refused before any decoder sees it, for the reason
 * `decode_specific_type` gives, so the answer is the empty list.
 *
 * @param {string} input
 * @returns {(string)[]}
 */
export function get_possible_types_for_input(input: string): (string)[];
/**
 * ## Implementation limits: one contract for every walker
 *
 * Every export that walks a CBOR document or a CDDL schema is bounded —
 * in how deeply the input nests, in what the descent to an item costs
 * in stack once the schema's rule references are counted, and, for the
 * validator, in how much work one run may do — because the alternative
 * in this runtime is an exhausted stack, which takes the whole wasm
 * instance with it. Reaching a bound is a *refusal*, never a verdict:
 * what lay past it went unexamined, so nothing is claimed about the
 * input in either direction.
 *
 * A refusal is **returned, never thrown**, by every export that walks a
 * document — `cbor_to_json`, `validate_cddl`,
 * `validate_cbor_against_cddl`, `decode_cbor_against_cddl` and
 * `map_cbor_to_cddl` — as the `error` of its `ok: false` /
 * `valid: false` envelope, with `kind` one of the members of
 * `ImplementationLimitKind` and `message` naming the bound. Branch on
 * `kind`; `message` is prose and is not stable. A fault in the schema,
 * in the root rule or in the bytes comes back from the three schema
 * walkers as the same error object, since one producer builds it; a
 * bound reached inside a walk is reported by the walker that reached
 * it, under the same kind.
 *
 * The four editor primitives (`cddl_outline`, `cddl_references`,
 * `cddl_symbol_at`, `cddl_format`) take schema text only and throw for
 * text the parser is not run on, a schema nested past the bound
 * included; `validate_cddl` reports the same text as
 * `kind: "nesting_too_deep"`, and is the call to make for the kind.
 */
export type ImplementationLimitKind =
    /**
     * The input nests past what the walk follows: a CBOR document more
     * than 16384 levels below its root; CDDL text past 9 levels of
     * brackets, or past the document-wide budget on them; a descent
     * that holds more memory — the levels of the data, the rule
     * references resolved on the way to them and, for the validator,
     * what the failed alternatives of every choice on the way recorded
     * — than the budget; a chain of rule references resolved against
     * one data item longer than is supported; or more embedded `.cbor`
     * payloads open at once than are supported. Every walker reports every one of these under
     * this kind. None of the walkers spends stack on the nesting of a
     * document: every one holds its levels on the heap, so the bounds
     * are bounds on memory and on work, and a document inside them is
     * walked in full on whatever thread calls in.
     */
    | "nesting_too_deep"
    /**
     * Reported by the three schema walkers: the run reached the bound
     * on how much work one walk may do. A schema whose choice
     * alternatives each descend into the same data re-walks it once per
     * alternative at every level, so a document inside every nesting
     * bound can still cost a power of its own depth. `map_cbor_to_cddl`
     * also reports it when its answer would have more rows than the
     * supported bound (500,000): the rows are the size of that answer,
     * and the other two walkers still answer for the same document.
     */
    | "validation_too_complex";

/**
 * ## Document walkers answer in JSON text
 *
 * The four exports that walk a CBOR document — `cbor_to_json`,
 * `validate_cbor_against_cddl`, `decode_cbor_against_cddl` and
 * `map_cbor_to_cddl` — return the JSON **text** of their result rather
 * than the object: `JSON.parse` the string to get the shape each one
 * documents. A tree nests as deep as the document does, and text is the
 * one form of it that crosses every boundary on its way to a caller —
 * the wasm boundary, a `postMessage` to another thread, a
 * `structuredClone` — at a cost of bytes and never of depth, where the
 * object form fails a structured clone at a few hundred levels.
 * `JSON.parse` builds the object without recursing over its nesting.
 *
 * An integer a JavaScript number does not hold exactly is written as
 * `{"$serde_json::private::Number": "<digits>"}` wherever it occurs;
 * every other number is plain JSON digits. Convert the boxes after
 * parsing, with an explicit stack for a document that may be deep.
 *
 * Every other export returns the object it documents.
 */
export type JsonText<T> = string & { readonly __json?: T };

/**
 * Decodes a CBOR hex string into a positional JSON tree, answering with
 * the JSON text of a `CborDecodeResult` (see *Document walkers answer
 * in JSON text* above).
 *
 * Never throws on malformed input — on failure the text describes
 * `{ ok: false, error: CborDecodeError, partial? }`. Structured errors
 * carry `kind`, `offset`, a `byte_span`, a semantic `path` into the
 * failing position, and a human `message`.
 *
 * Also never throws on well-formed input that is simply nested too
 * deeply: an item more than 16384 levels below the root is refused with
 * `kind: "nesting_too_deep"` and the prefix decoded so far. That is an
 * implementation limit, not a statement about the bytes.
 *
 * A header declaring more content than the input carries — up to
 * `2^64-1`, since the number is whatever the bytes say — comes back as
 * `kind: "unexpected_eof"` at the offset where the content should have
 * begun. No buffer is ever sized from a declared length before the
 * bytes to fill it have been read.
 *
 * When anything was successfully decoded before the failure, `partial`
 * contains the prefix tree with every un-finished container flagged
 * `incomplete: true`. Node shape otherwise matches the success value, so
 * renderers can display it the same way.
 */
export function cbor_to_json(cbor_hex: string): JsonText<CborDecodeResult>;

export type CborDecodeResult =
    | { ok: true; value: CborValue }
    | { ok: false; error: CborDecodeError; partial?: CborPartialValue };

export type CborDecodeErrorKind =
    | "invalid_hex"
    | "invalid_syntax"
    | "unexpected_eof"
    | "unexpected_break"
    | "trailing_data"
    | "invalid_utf8"
    | "invalid_chunk"
    | "int_not_representable"
    | "non_finite_float"
    /**
     * The item sits more than 16384 levels below the root. An
     * implementation limit — the bytes may be valid CBOR. Every
     * enclosing array, map and tag counts one level; a map key sits at
     * the same level as its value, and the chunks of an
     * indefinite-length string are leaves rather than a level of their
     * own. The kind every other walker reports the same bound under —
     * see `ImplementationLimitKind`.
     */
    | "nesting_too_deep"
    | "io_error";

export interface CborDecodeError {
    kind: CborDecodeErrorKind;
    /** Human-readable message. Not stable — use `kind` for branching. */
    message: string;
    /** Semantic path into the decoded tree (e.g. `$.entries[1].value[0]`). */
    path: string;
    /** Byte offset where decoding failed. **Absent** on `invalid_hex`,
     *  where nothing was decoded and there are no CBOR bytes to point
     *  into, and on the rare `io_error` fallbacks the underlying reader
     *  reports without a position. Present on every other kind. */
    offset?: number;
    /** Byte range pinned by the failure, when wider than a single byte. */
    byte_span?: CborPosition;
}

/**
 * Validates a CDDL schema. Returns `{ valid: true }` if the schema parses
 * **and** every rule reference resolves *to something*; otherwise
 * `{ valid: false, error }`. Undefined rule references come back with
 * `kind: "unresolved_references"` (e.g. `thing = [unknown_rule, int]`)
 * and an `error.unresolved` array holding every occurrence, not only the
 * first.
 *
 * Reported under the same kind: a rule that resolves only back to rules
 * that resolve to it (`a = b`, `b = a`). Every name is defined, so the
 * reference check alone passes it, but following it never reaches a map,
 * array, tag, literal or prelude type — nothing can match it and nothing
 * can fail to. `error.unresolved` names every rule in the cycle.
 * Recursion through a construct that does describe data (`a = [a]`,
 * `a = b / int` with `b = a`) is productive and stays valid.
 *
 * A name two rules define comes back as `kind: "parse_error"`, with
 * `error.byte_span` covering the declaration that redefines it — the one
 * whose removal makes the document parse — rather than the definition it
 * collides with or the document as a whole. A rule that adds a choice to
 * an earlier one (`a /= tstr`, `g //= (b: uint)`) defines nothing twice
 * and stays valid.
 *
 * This is the only entry point that decides whether a schema resolves;
 * the IDE primitives (`cddl_outline` and friends) deliberately answer
 * for a document that does not.
 * @param {string} cddl
 * @returns {any}
 */
export function validate_cddl(cddl: string): CddlValidationResult;

/**
 * Validates CBOR bytes against a rule in the given CDDL schema. On failure
 * `error` describes the mismatch, including a semantic `path`, the byte
 * spans in the input that produced it, and (when several validation
 * errors fire) an `additional` array with the rest, deduplicated and
 * capped.
 *
 * `path` uses `$[n]` both for an array index and for an integer map key,
 * so `$[2][1]` may read as "element 1 of the value at map key 2". Match
 * it against a decoded tree the same way — key first, then position —
 * rather than assuming an array.
 *
 * **CBOR nesting stops at 16384 levels here**, the same depth the
 * decoding and mapping entry points allow. The validator holds its
 * levels on the heap, so what a level costs it is memory rather than
 * stack, and a document inside the bound is walked in full on whatever
 * thread calls in. Input past that comes back as
 * `kind: "nesting_too_deep"` — an implementation limit, never a
 * `"mismatch"`, because nothing below the bound was examined and no
 * claim is being made about it.
 *
 * **A level is not the whole of what reaching it costs.** The validator
 * descends the schema as well as the data: a rule reference resolved
 * against a data item holds memory without consuming any of it, and
 * the chain of them starts afresh at every level. What the alternatives
 * of a choice recorded while they failed is held as well, until the
 * choice settles — by every level opened below the item while the
 * alternatives after them are tried. The descent is bounded in what it
 * holds, all of that together, as well as in what it counts, and the
 * two bounds together decide how deep a given schema reaches. A rule
 * of a few alternatives — `x = [* x] / uint`, say — reaches the full
 * 16384 levels. `plutus_data` does not: its `constr` alternative is a
 * choice of some hundred and thirty tags, every one of which records
 * its mismatch at every level of a nested map or list before the
 * alternative that matches is reached, so the descent holds tens of
 * kilobytes a level and comes back as `kind: "nesting_too_deep"` —
 * naming the descent budget, a limit and never a verdict — a few
 * thousand levels of nested maps down, and somewhat under ten thousand
 * levels of nested lists. `decode_cbor_against_cddl` and
 * `map_cbor_to_cddl` walk the same documents to the full depth, since
 * their descent holds no such records. The bound is on the schema and
 * the document together, so it cannot be read off either alone.
 *
 * **A group rule (`g = ( … )`) is refused as a root** with
 * `kind: "group_rule_root"`: it describes a run of entries inside an
 * array or a map, not a data item, so it has no shape or arity of its
 * own to check against. The two mapping entry points refuse the same
 * rule under the same kind and message, so all three accept exactly the
 * same set of root rule names.
 *
 * Answers with the JSON text of a `CborValidationResult` (see *Document
 * walkers answer in JSON text*). Only `cbor_hex` that is not hex throws.
 *
 * @param {string} cbor_hex
 * @param {string} cddl
 * @param {string} rule_name
 * @returns {string}
 */
export function validate_cbor_against_cddl(
    cbor_hex: string,
    cddl: string,
    rule_name: string
): JsonText<CborValidationResult>;

/**
 * **CDDL spans carry both byte and char offsets.** `offset`/`length`
 * count UTF-8 bytes (what `pest` reports); `char_offset`/`char_length`
 * count UTF-16 code units — the unit JS strings, `string.slice`,
 * editor APIs, and the LSP protocol use. For ASCII-only sources the
 * two pairs are identical.
 *
 * **CBOR spans are byte offsets only** — into the decoded CBOR buffer.
 * If you have a hex string, multiply by 2 to slice the hex view:
 * `hex.slice(off*2, (off+len)*2)`.
 */
export interface SourceSpan {
    /** UTF-8 byte offset in the source. */
    offset: number;
    /** UTF-8 byte length. */
    length: number;
    /** UTF-16 code unit offset (= `string.slice`-friendly). */
    char_offset: number;
    /** UTF-16 code unit length. */
    char_length: number;
    /** 1-indexed line. */
    line: number;
}

/**
 * ## The four functions below answer for a schema mid-edit
 *
 * `cddl_outline`, `cddl_references`, `cddl_symbol_at` and `cddl_format`
 * require the document to **parse**, not to **resolve**. A name with no
 * rule defining it — the normal state while a schema is being typed —
 * is answered for, not thrown on: `cddl_symbol_at` reports it as
 * `kind: "prelude_or_unknown"`, `cddl_references` returns
 * `definition: null` alongside its uses. Only text that fails to parse
 * throws, with a message starting `CDDL parse error`. Use
 * `validate_cddl` to find out whether every reference resolves.
 *
 * ## Nesting limits
 *
 * The parser's running time multiplies by about three for every level
 * of nested `[`, `{` or `(`, and it has no bound of its own, so a few
 * dozen bytes of brackets can take minutes — in a single-threaded
 * runtime, indistinguishable from a hang. Bracket nesting is therefore
 * refused before the text reaches the parser, on two counts:
 *
 *  - **depth** — no run of brackets may nest more than **9** levels;
 *  - **total** — nesting costs the same wherever in the document it
 *    appears, so the whole document's is added up (a bracket at depth
 *    *d* counting `3^(d-1)`, the measured rate) and capped. One run of
 *    brackets at the full depth spends the budget; eight such runs in
 *    one document do not fit, even though no single run is too deep.
 *
 * All four throw for either, with a message naming which bound was
 * crossed; `validate_cddl` reports the same as
 * `kind: "nesting_too_deep"`.
 *
 * Brackets are charged by depth alone, whatever their shape: the scan
 * cannot tell the shapes the parser is fast on (`[a: … ]`, `( … )` are
 * linear in depth) from the ones it is not (`[[ … ]]`, `{{ … }}`,
 * `[* [* … ]]` all multiply) without re-deciding the grammar, so a deep
 * schema that would in fact have parsed quickly is refused too.
 *
 * Only nesting is charged, never length: the shallowest levels are
 * free, so a large but shallow schema is admitted however long it is.
 * Every vendored ledger schema nests 3 deep and spends none of the
 * budget. Brackets inside comments and inside text / byte literals are
 * not counted at all.
 *
 * `cddl_format` has no separate, tighter bound of its own: a document
 * deep enough to labour the serialiser is stopped by the parser's
 * bound first.
 *
 * `map_cbor_to_cddl` and `decode_cbor_against_cddl` carry the same
 * schema bounds, reported in their result as `kind: "nesting_too_deep"`
 * rather than thrown, and additionally refuse CBOR input nested more
 * than 16384 levels below its root. `validate_cbor_against_cddl` stops
 * at the same depth. All three bound what the descent to a level holds
 * once the schema's own rule references are counted, and the work one
 * walk may do — see their own documentation. The contract they share is
 * `ImplementationLimitKind`.
 */

/** Outline entry — one rule from `cddl_outline`. */
export interface CddlOutlineEntry {
    /**
     * Rule name (`transaction_body`, `set`, …), socket/plug sigil
     * included (`$sock`, `$$grp`), so it always slices out of
     * `name_span`. This is the spelling `cddl_references` expects.
     */
    name: string;
    /** `"type"` for `=`, `"group"` for `( … )`. */
    kind: "type" | "group";
    /**
     * True for a choice-alternate rule (`a /= tstr`, `g //= ( … )`),
     * which extends an existing rule and so repeats its name. A name
     * can therefore appear in more than one entry: group by `name` and
     * use this flag to tell the base definition from what extends it.
     */
    is_alternate: boolean;
    /** Byte range covering the whole `name = …` rule definition. */
    span: SourceSpan;
    /** Byte range of just the rule's name identifier. */
    name_span: SourceSpan;
}

/** Result of `cddl_symbol_at`. `null` when the cursor isn't on an identifier. */
export type CddlSymbolAtResult =
    | null
    | {
          /** Identifier text, socket/plug sigil included. */
          name: string;
          /**
           * `prelude_or_unknown` covers both an RFC 8610 prelude type
           * and a name nothing defines — including one that is merely
           * not typed yet.
           */
          kind: "type" | "group" | "rule_reference" | "prelude_or_unknown";
          role: "definition" | "use";
          span: SourceSpan;
          definition_span: SourceSpan | null;
          rule_span: SourceSpan | null;
      };

/** Result of `cddl_references`. */
export interface CddlReferencesResult {
    /** Null when no rule in this document defines the name. */
    definition: SourceSpan | null;
    uses: SourceSpan[];
}

/**
 * Returns one entry per top-level rule
 * (`{name, kind, is_alternate, span, name_span}`). Used for editor
 * outline view, breadcrumbs, fuzzy "go to rule".
 * @param cddl
 */
export function cddl_outline(cddl: string): CddlOutlineEntry[];

/**
 * Returns `{definition, uses[]}` byte ranges for the rule named `name`.
 * Powers find-references and rename-aware highlighting. `name` is the
 * identifier's full text, socket/plug sigil included (`$sock`, not
 * `sock`) — the spelling `cddl_outline` reports.
 * @param cddl
 * @param name
 */
export function cddl_references(cddl: string, name: string): CddlReferencesResult;

/**
 * Returns the symbol under `offset` (or `null` if none). For uses,
 * `definition_span` points at the rule's name — the "go to definition"
 * target.
 * @param cddl
 * @param offset
 */
export function cddl_symbol_at(cddl: string, offset: number): CddlSymbolAtResult;

/**
 * Pretty-prints the CDDL by parsing it and serialising via `Display`.
 * Useful for "format on save". Throws on input that does not parse.
 *
 * Comments survive: every one of them comes out, with its text unchanged
 * and in source order. A comment documenting a group entry stays with that
 * entry, and one sharing a line with an entry keeps that line.
 *
 * Values survive too: every literal comes out denoting what it denoted, so
 * the output accepts exactly what the input accepted. A float literal keeps
 * the fraction that separates it from an integer of equal value — the two
 * match different data items and name different map keys.
 *
 * A float literal may be written in any of the notations RFC 8610 gives it
 * — `1.5`, `1.5e10`, `1e300`, `0x1.5p10` — and comes back as the plain
 * decimal digits of the same value, since the value rather than the
 * notation is what the literal denotes. Digits whose magnitude no 64-bit
 * float holds (`1e400`) denote no float at all and are a parse error
 * wherever a schema is read, so no document reaches the formatter holding
 * one.
 * @param cddl
 */
export function cddl_format(cddl: string): string;

/** One entry in a `map_cbor_to_cddl` path table: an earlier entry in
 *  the same table whose text this one extends, plus the text it adds.
 *
 *  A path names every level above it, so writing one out per row would
 *  cost the depth the row sits at — and a document with a row per node
 *  at every level would cost the square of its nesting. The tables
 *  break that: a row costs one segment however deep it sits.
 *
 *  Resolving is a fold over the chain, and the tables are ordered so
 *  that `prefix` always points at an earlier index:
 *
 *  ```ts
 *  function resolvePaths(table: CborCddlPathEntry[]): string[] {
 *      const out: string[] = [];
 *      for (const entry of table) {
 *          out.push(
 *              (entry.prefix === undefined ? "" : out[entry.prefix]) +
 *                  entry.suffix
 *          );
 *      }
 *      return out;
 *  }
 *  ```
 *
 *  `prefix` is a *text* prefix, not a parent node: it is whatever entry
 *  the table was able to share with, which is usually but not always
 *  the addressed node's parent. Read the resolved string for structure,
 *  never the chain. */
export interface CborCddlPathEntry {
    /** Index, in the same table, of the entry whose resolved text this
     *  one extends. **Absent** when the entry stands for its `suffix`
     *  alone. */
    prefix?: number;
    /** Text appended to the prefix's resolved path. */
    suffix: string;
}

/** One entry from `map_cbor_to_cddl`: a single position of a CBOR
 *  node, the type that matched it, and the path it ends up at in the
 *  output of `decode_cbor_against_cddl`.
 *
 *  `cbor_path` and `decoded_path` are indices into the result's
 *  `cbor_paths` / `decoded_paths` tables, not strings — see
 *  `CborCddlPathEntry` for how to resolve them. Everything the rest of
 *  this comment says about a path is about the resolved string.
 *
 *  ## `decoded_path` conventions
 *
 *  Every node addressable in the JSON tree returned by
 *  `decode_cbor_against_cddl` has at least one entry here — including
 *  the synthetic keys the decoder inserts when the data shape doesn't
 *  fit a plain JSON object, and including a schema slot the data does
 *  not supply. Nothing else does: a path that is not in that tree never
 *  gets a row. The two are produced by the same walker, so they agree
 *  on which type choice matched, which group choice claimed an array,
 *  which member claimed a map entry, and whether a map came out in
 *  object or `@entries` form.
 *
 *  Path segments follow the same grammar as the decoded tree:
 *  identifier-safe field names use dot notation (`.name`), everything
 *  else is bracket-quoted (`["0"]`, `["@tag"]`, `["0xab…"]`); array
 *  indices are `[N]`.
 *
 *  Synthetic-key paths:
 *
 *  * `<wrapper>["@tag"]` — the tag-number row of an unspecialised
 *    tagged value (the decoder represents these as `{@tag, @value}`).
 *    `cbor_byte_span` covers just the tag header bytes (`d9 0102`,
 *    not the whole `Tag(258, …)` extent); `cddl_byte_span` covers the
 *    `#6.NNN(...)` form. Tag 0 over text and tags 2 / 3 over a byte
 *    string are specialised to scalars and get no wrapper rows — but a
 *    bignum too wide to render as a number keeps the wrapper, and so
 *    keeps these rows.
 *  * `<wrapper>["@value"]` — the inner value of an unspecialised tag.
 *    Resolves to the inner type's CDDL location.
 *  * `<arr>["@positional"]` — wrapper row over the unlabelled slots
 *    of a mixed (labelled + unlabelled) tuple. No `cddl_byte_span`.
 *    `cbor_byte_span` / `cbor_anchor_span` cover the unlabelled items'
 *    combined byte extent.
 *  * `<arr>["@positional"][N]` — one unlabelled slot, indexed by its
 *    position **within `@positional`**, NOT by its index in the source
 *    CBOR array: the decoder builds a dense list, so for
 *    `[bool, a: int, tstr, b: int]` the source slots 0 and 2 appear at
 *    `@positional[0]` and `@positional[1]`. `cbor_path` carries the
 *    wire address (`$[0]`, `$[2]`).
 *  * `<arr>["@extra"]`, `<arr>["@extra"][N]` — array items past the
 *    schema cursor, again densely indexed from zero. **Only emitted
 *    when the group choice has at least one named slot**: with no named
 *    slot the decoder appends leftovers to the same array, so they are
 *    addressed as `$[N]` continuing the positional numbering.
 *  * `<map>["@extra"]`, `<map>["@extra"].<key>` — map entries no
 *    member claimed (object form only). The key segment is the same
 *    field name the decoder's `@extra` object uses.
 *  * `<map>["@entries"]` — wrapper row over the wire-order array form
 *    used when the map has complex keys, duplicate keys, or two keys
 *    that stringify to the same field name (see
 *    `decode_cbor_against_cddl` docs). No `cddl_byte_span`.
 *  * `<map>["@entries"][N]` — each pair as a single addressable row
 *    (covers key+value bytes, `cbor_type: "map_entry"`).
 *  * `<map>["@entries"][N].key` — key bytes of the Nth pair,
 *    `entry_role: "key"`, plus rows for a complex key's own children.
 *  * `<map>["@entries"][N].value` — value bytes of the Nth pair, plus
 *    deeper rows walking the matched member's value type.
 *  * `<container>.<name>` where the schema entry repeats (`* item:
 *    uint`, or a member key several wire entries share) — a wrapper row
 *    for the array the decoder builds, with `<name>[N]` beneath it.
 *  * `<value>["@simple"]` — the payload of a non-standard CBOR simple
 *    value, which the decoder renders as `{"@simple": N}`.
 *
 *  Wrapper rows (`@entries`, `@positional`, `@extra`, and a repeating
 *  field's array) carry a `cbor_type` naming their role —
 *  `"map_entries"`, `"map_extra"`, `"array_positional"`,
 *  `"array_extra"`, `"map_entry"`, `"map_repeated"`, `"array_repeated"`
 *  — and omit `cddl_byte_span` unless the schema has a single construct
 *  that declares the whole run.
 *
 *  No field is ever emitted as `null`: a value that cannot be
 *  determined is left out of the object entirely. */
export interface CborCddlMapEntry {
    /** Index into the result's `cbor_paths` table. Resolves to a path
     *  into the *raw* CBOR tree (numeric map keys are bracketed).
     *  Tags are transparent here — `Tag(258, [...])` walked against a
     *  `[* a]`-shaped schema addresses its items as `$[0]`, `$[1]`, …
     *  with no wrapper segment — so this is the address of the bytes,
     *  while `decoded_path` is the address of the rendered value.
     *
     *  For a row describing a schema position the data does not contain,
     *  this is the address the value *would* have had; the row carries
     *  no CBOR span, so there is nothing to highlight. */
    cbor_path: number;
    /** Index into the result's `decoded_paths` table. Resolves to a
     *  path into the labelled JSON returned by
     *  `decode_cbor_against_cddl`. See the interface comment for the
     *  full list of synthetic-key segments (`@tag`, `@value`,
     *  `@positional`, `@extra`, `@entries`, `@simple`). */
    decoded_path: number;
    /** Whether this entry describes the value at `cbor_path`, or the
     *  *key* of a map entry at that path. Map entries with matched keys
     *  produce both a `"key"` entry (CBOR span = key bytes, CDDL span
     *  = the member-key declaration: `name:`, `<value>:` or
     *  `<type1> =>`) and a `"value"` entry; both carry the same
     *  `cbor_path` / `decoded_path`. Array slots, tag payloads, and
     *  root nodes are always `"value"`. */
    entry_role: "key" | "value";
    /** Header byte range of the CBOR node.
     *
     *  **Absent** when the row describes a schema position the data does
     *  not contain — a required map member the bytes omit (the decoder
     *  renders it as `null`), or a repeating field that matched nothing
     *  (rendered as `[]`) — and for rows inside a `.cbor` payload
     *  carried by an *indefinite-length* byte string, whose bytes are
     *  not one contiguous run of the document. Guard before reading
     *  `.offset`. */
    cbor_byte_span?: { offset: number; length: number };
    /** Whole-structure byte range (= `cbor_byte_span` for scalars).
     *  Absent in exactly the same cases as `cbor_byte_span`. */
    cbor_anchor_span?: { offset: number; length: number };
    /** Byte range in the CDDL source describing this position.
     *
     *  Omitted whenever the position cannot be determined: on synthetic
     *  wrapper rows, on rows the walker reached through a raw
     *  fall-through (nothing in the schema matched), and on an
     *  `@entries` pair no member claimed. No zero-length span and no
     *  `line: 0` sentinel is ever emitted — an absent field means
     *  "unknown", never "offset 0".
     *
     *  The range is trimmed to the construct it names: parser spans run
     *  to the start of the next token, so trailing whitespace and
     *  trailing comments are cut off. A comment *inside* a multi-line
     *  construct is kept, since cutting there would leave the highlight
     *  covering half a bracket. */
    cddl_byte_span?: SourceSpan;
    /** Name of the CDDL rule that matched, if a rule boundary was
     *  crossed. Prelude type names (`uint`, `bstr`, …) are reported the
     *  same way even though they are not rules. */
    rule_name?: string;
    /** CBOR node's wire type (`U8`, `Bytes`, `Map`, `Array`, `Tag`, …),
     *  or — for synthetic wrapper rows — a label describing the
     *  wrapper's role (see the interface comment). */
    cbor_type?: string;
    /** How the schema member that claimed a map entry matched its key:
     *  `"literal"` for a bareword / value key, `"type"` for a
     *  `<type1> =>` key, `"unmatched"` for an `@entries` pair no member
     *  claimed. Present on map key rows and on `@entries` pair rows;
     *  absent everywhere else. Mirrors `match.via` in the decoded
     *  tree. */
    match_via?: "literal" | "type" | "unmatched";
}

/** What `map_cbor_to_cddl` returns: the mapping entries, plus the two
 *  tables their `cbor_path` / `decoded_path` index into. In the text
 *  `entries` comes first and the tables after it. */
export interface CborCddlMap {
    /** One entry per node visited during the parallel walk, in
     *  depth-first pre-order. At most 500,000: a document whose map
     *  would have more is refused with `kind: "validation_too_complex"`
     *  rather than answered in part. */
    entries: CborCddlMapEntry[];
    /** Where every entry's `cbor_path` points. */
    cbor_paths: CborCddlPathEntry[];
    /** Where every entry's `decoded_path` points. */
    decoded_paths: CborCddlPathEntry[];
}

/**
 * Returns a flat list of mapping entries pairing each visited CBOR node
 * with the CDDL position that describes it, plus the path tables their
 * `cbor_path` / `decoded_path` index into. Use it to wire bidirectional
 * highlight between a CBOR panel and a CDDL panel without needing a
 * validation error to trigger it.
 *
 * The paths are tabled rather than written out per row because a path
 * names every level above it: a row per node at every level of a deep
 * document would otherwise cost the square of its nesting. Resolve them
 * once (see `CborCddlPathEntry`) and index the entries by the result.
 *
 * Order is depth-first pre-order, so a parent's entry precedes its
 * children's. One CBOR position usually yields several rows — one per
 * CDDL level the walk crossed (outer rule, inner rule, type expression)
 * — which is what a breadcrumb trail or multi-level highlight needs.
 *
 * Tags are transparent to `cbor_path` (anweiss-style): `Tag(258, [...])`
 * is addressed as if the tag wrapper weren't there when matching against
 * a `[* a]`-shaped schema. `decoded_path` is not: it follows the
 * `{@tag, @value}` wrapper the decoder emits.
 *
 * A `bstr .cbor T` / `bstr .cborseq T` payload is walked as part of the
 * document: rows inside it carry the schema location of `T` and CBOR
 * spans rebased onto the outer buffer. The exception is a payload
 * carried by an indefinite-length byte string, whose bytes are not one
 * contiguous run — those rows keep their paths and schema locations and
 * carry no CBOR span.
 *
 * Answers `{ok: true, value}` with the map, or `{ok: false, error}`
 * under the same conditions and with the same error object as
 * `decode_cbor_against_cddl` — the two are one walk reported two ways:
 * when the CDDL does not parse or resolve, when `rule_name` names no
 * rule or a **group** rule (`g = ( … )`, a fragment of an enclosing
 * array or map that neither function can use as a root), when the
 * bytes do not decode, and when an implementation limit is reached —
 * the document nests past the supported depth, its descent (the levels
 * of the data and the rule references resolved on the way to them,
 * together) holds more memory than the supported budget, a chain of
 * rule references against one item is longer than is supported, or the
 * walk asks for more work than the supported bound. One limit is this
 * function's alone: a map of more than 500,000 rows is refused, since
 * the rows are the size of its answer, while `decode_cbor_against_cddl`
 * and `validate_cbor_against_cddl` still answer for the same document.
 * A limit is `kind: "nesting_too_deep"`, or `kind:
 * "validation_too_complex"` for the bounds on work and on rows, never a
 * statement about the document, and the walk is refused whole rather
 * than answered with rows that stop short; see
 * `ImplementationLimitKind`. Only `cbor_hex` that is not hex throws.
 *
 * The walk holds its levels on the heap, so a document inside the
 * bounds — ten thousand levels deep, say — is mapped in full, with a
 * row for every level, on whatever thread calls in. The answer is the
 * JSON text of a `CborCddlMapResult` (see *Document walkers answer in
 * JSON text*).
 *
 * @param cbor_hex
 * @param cddl
 * @param rule_name
 */
export function map_cbor_to_cddl(
    cbor_hex: string,
    cddl: string,
    rule_name: string
): JsonText<CborCddlMapResult>;

/** What `map_cbor_to_cddl` returns. */
export type CborCddlMapResult =
    | { ok: true; value: CborCddlMap }
    | { ok: false; error: CborCddlWalkError };

/** What `decode_cbor_against_cddl` returns. */
export type CborDecodeAgainstCddlResult =
    | { ok: true; value: unknown }
    | { ok: false; error: CborCddlWalkError };

/**
 * Why `decode_cbor_against_cddl` or `map_cbor_to_cddl` produced no
 * answer. For a fault in the schema, in the root rule or in the bytes it
 * is the same object `validate_cbor_against_cddl` reports the same fault
 * with — one producer builds it — so it carries what that export
 * documents for the kind: `byte_span`, `unresolved` and `truncated` on
 * a schema fault (see `CddlErrorInfo`), `path`, `offset` and
 * `byte_spans` on a document fault (see `CborValidationErrorInfo`). A
 * bound the walk itself reached carries `kind` and `message` alone.
 */
export interface CborCddlWalkError {
    kind: CborCddlWalkErrorKind;
    /** Human-readable and not stable — branch on `kind`. */
    message: string;
    path?: string;
    offset?: number;
    byte_spans?: CborPosition[];
    byte_span?: SourceSpan;
    unresolved?: CddlUnresolvedReference[];
    truncated?: boolean;
}

/**
 *  - `"parse_error"` / `"unresolved_references"` — the CDDL does not
 *    parse, or names a rule nothing defines
 *  - `"missing_rule"` — `rule_name` names no rule
 *  - `"group_rule_root"` — `rule_name` names a group rule
 *  - `"input_parse"` — the CBOR bytes do not decode
 *  - `"nesting_too_deep"` / `"validation_too_complex"` — an
 *    implementation limit, never a claim about the input; see
 *    `ImplementationLimitKind`
 */
export type CborCddlWalkErrorKind =
    | "parse_error"
    | "unresolved_references"
    | "missing_rule"
    | "group_rule_root"
    | "input_parse"
    | ImplementationLimitKind;

/**
 * Maps decoded CBOR onto a CDDL schema and returns labelled JSON as
 * `{ok: true, value}`. Where `cbor_to_json` returns positional CBOR
 * (numeric map keys, raw arrays),
 * this walks the schema in parallel and replaces them with the named
 * fields the CDDL declares — turning Cardano shapes like
 * `[transaction_body, transaction_witness_set, bool, ...]` into
 * `{transaction_body: {...}, transaction_witness_set: {...}, ...}`.
 *
 * Answers `{ok: false, error}` (see `CborCddlWalkError`) when the CDDL
 * does not parse or resolve, when `rule_name` names no rule, when the
 * bytes do not decode, and when `rule_name` names a **group** rule
 * (`g = ( … )`). A group rule is a fragment of the array or map that
 * references it, not a data item, so it cannot be a root; the error is
 * `kind: "group_rule_root"` and its message names the rule, which
 * distinguishes it from `kind: "missing_rule"` for an unknown name.
 * `validate_cbor_against_cddl` refuses the same rule names with the
 * same kind and message.
 *
 * Also answers `{ok: false, error}` with `kind: "nesting_too_deep"`
 * when the document nests past the supported depth, when its descent
 * — the levels of the data and the rule references resolved on the way
 * to them, together — holds more memory than the supported budget, or
 * when a chain of rule references against one item is longer than is
 * supported, and with `kind: "validation_too_complex"` when the walk
 * asks for more work than the supported bound. All are implementation
 * limits named in the message, never statements about the document:
 * output is never quietly cut short or left unlabelled at the limit.
 * See `ImplementationLimitKind`. Only `cbor_hex` that is not hex
 * throws.
 *
 * The walk holds its levels on the heap, so a document inside the
 * bounds — ten thousand levels deep, say — is labelled to the bottom on
 * whatever thread calls in, and the tree comes back whole.
 *
 * **Matching runs strict first, lenient second.** The strict pass takes
 * an alternative only when every non-optional entry matched, every
 * array item was consumed and every map entry was claimed — so a type
 * or group choice lands on the alternative the data actually fits, and
 * a map member whose value has the wrong type does not swallow the
 * entry. This holds for a map whichever shape it comes back in: a map
 * rendered as `@entries` (see below) has to be accounted for by some
 * group choice of the alternative before that alternative claims it,
 * exactly as the object form does. Only if no alternative survives
 * strictly does the lenient pass run, and only the lenient pass emits
 * `@extra` buckets and `null` placeholders for absent required members.
 * A node matching nothing at all falls back to a raw representation, so
 * nothing is ever dropped.
 *
 * **Field names.** A slot is labelled when the schema names it
 * unambiguously: a bareword member key (`fee: coin`), or a rule
 * reference a group choice uses exactly once (`[transaction_body,
 * transaction_witness_set, …]`). Prelude names (`uint`, `tstr`) and
 * bound generic parameters are not labels. Neither is a name the same
 * group choice uses twice: `[coin, coin]` and `[unit_interval,
 * unit_interval, …]` emit **positional** values (a plain array, or
 * `@positional` when the choice also has named slots), because one
 * JSON key cannot hold two slots.
 *
 * **Ranges and controls** decide slot membership: `0 .. 12`,
 * `min_int64 .. max_int64` (bounds may be negative and may be rule
 * references), `.size`, `.lt` / `.le` / `.gt` / `.ge`, `.eq` / `.ne`,
 * `.and` / `.within`. `.regexp`, `.pcre`, `.bits` and `.abnf` are not
 * evaluated — a slot carrying one is accepted on its target type alone,
 * so its label survives.
 *
 * **Map output shape**: by default we emit JSON objects (`{a: 1, b: 2}`)
 * for the convenient case, with keys in **wire order** — the order the
 * bytes carried them, not schema order and not sorted.
 *
 * Wire order is what both map shapes guarantee, and it is the whole
 * ordering rule: in object form every key the document carried sits at
 * its wire position, and in `@entries` form every pair does. Only keys
 * that have no wire position of their own come out anywhere else, and
 * they come last — the `null` placeholders the lenient pass supplies
 * for declared members the data omitted follow every key the document
 * carried, in the order the schema declares them, and the `@extra`
 * bucket follows those (its own keys again in wire order). Arrays are
 * positional, so a named or `@positional` slot is already at its wire
 * index.
 *
 * We switch to the `@entries` array form
 * `{ "@entries": [{ key, value, match: { via, label } }, ...] }`
 * when the JSON object form would lose information:
 *
 *  * any cbor key is a complex value (Array / Map / Tag / non-standard
 *    Simple) — JSON objects can only have string keys.
 *  * the cbor map has duplicate keys (RFC 8949 §5.6 — non-canonical
 *    but legal). Collapsing into a value-array would drop the
 *    interleaving order with surrounding entries.
 *  * two distinct keys stringify to the same JSON field name — the
 *    integer `1` and the text `"1"`, or `h'01'` and the text `"0x01"`.
 *    One would silently overwrite the other in object form.
 *
 * In `@entries` form, each pair carries a `match` field describing how
 * the cbor key was matched against the schema:
 *  * `match.via: "literal"` — bareword / literal value match;
 *    `match.label` is the literal text.
 *  * `match.via: "type"` — `<type1> => …` schema, the key conforms
 *    to a type (e.g. `policy_id => …`); `match.label` is `null`.
 *  * `match.via: "unmatched"` — no schema entry accepted this key,
 *    `key` and `value` are raw decoded forms; `match.label` is `null`.
 *
 * Almost all Cardano maps (txbody, multiasset, witness_set) use object
 * form; the `@entries` form only kicks in for the unusual cases above.
 * The raw fallback for a map the schema did not match uses the same two
 * shapes under the same rule, with every `match.via` set to
 * `"unmatched"`.
 *
 * **Synthetic keys are not escaped.** A wire key literally spelled
 * `@extra`, `@entries`, `@positional`, `@tag`, `@value` or `@simple` is
 * indistinguishable in object form from the synthetic key of the same
 * name. If a consumer must tell them apart, read the map through
 * `cbor_to_json` (which never inserts synthetic keys) or through
 * `map_cbor_to_cddl`, whose entries carry the byte spans.
 *
 * The answer is the JSON text of a `CborDecodeAgainstCddlResult` (see
 * *Document walkers answer in JSON text*).
 * @param {string} cbor_hex
 * @param {string} cddl
 * @param {string} rule_name
 * @returns {string}
 */
export function decode_cbor_against_cddl(
    cbor_hex: string,
    cddl: string,
    rule_name: string
): JsonText<CborDecodeAgainstCddlResult>;

export function check_block_or_tx_signatures(hex_str: string): CheckSignaturesResult;

/**
 * @param {string} tx_hex
 * @returns {(string)[]}
 */
export function get_utxo_list_from_tx(tx_hex: string): string[];

/**
 * @param {string} tx_hex
 * @param {UTxO[]} utxo_json
 * @param {CostModels} cost_models_json
 * @returns {ExecuteTxScriptsResult}
 */
export function execute_tx_scripts(tx_hex: string, utxo_json: UTxO[], cost_models_json: CostModels): ExecuteTxScriptsResult;
/**
 * @param {string} hex
 * @returns {ProgramJson}
 */
export function decode_plutus_program_uplc_json(hex: string): ProgramJson;
/**
 * @param {string} hex
 * @returns {string}
 */
export function decode_plutus_program_pretty_uplc(hex: string): string;
/**
 * @param {string} tx_hex
 * @param {number} output_index
 * @returns {string}
 */
export function get_ref_script_bytes(tx_hex: string, output_index: number): string;

/**
 * Add witnesses to an already built transaction, accepting witnesses in many
 * shapes. The transaction body bytes (and therefore the transaction id and every
 * existing signature) are preserved exactly.
 *
 * Each entry of `witnesses` is auto-detected and may be a single Vkeywitness, a
 * single BootstrapWitness, a whole TransactionWitnessSet (e.g. a CIP-30 `signTx`
 * result), or a whole transaction (its vkey/bootstrap witnesses are taken) —
 * encoded as hex, base64, or a cardano-cli JSON text-envelope (`{ "cborHex": ... }`).
 * Only vkey and bootstrap witnesses are merged; duplicates are ignored.
 * @param {string} tx_hex
 * @param {string[]} witnesses
 * @returns {string}
 */
export function add_witnesses_to_tx(tx_hex: string, witnesses: string[]): string;

/**
 * Strict helper: add vkey witnesses, each the CBOR-hex of a single Vkeywitness
 * (`[ vkey, signature ]`). Use `add_witnesses_to_tx` if the input format may vary.
 * @param {string} tx_hex
 * @param {string[]} vkey_witnesses_hex
 * @returns {string}
 */
export function add_vkey_witnesses_to_tx(tx_hex: string, vkey_witnesses_hex: string[]): string;

/**
 * Strict helper: merge a whole TransactionWitnessSet (CBOR-hex) into a transaction.
 * This is the canonical shape returned by a CIP-30 `signTx`.
 * Use `add_witnesses_to_tx` if the input format may vary.
 * @param {string} tx_hex
 * @param {string} witness_set_hex
 * @returns {string}
 */
export function add_witness_set_to_tx(tx_hex: string, witness_set_hex: string): string;

/**
 * Like `add_witnesses_to_tx`, but cryptographically verifies each vkey witness
 * against the transaction body and returns a detailed report. Only valid,
 * non-duplicate vkey witnesses are inserted; a witness whose signature does not
 * match this transaction is skipped and counted as `invalid`.
 * @param {string} tx_hex
 * @param {string[]} witnesses
 * @returns {AddWitnessesReport}
 */
export function add_witnesses_to_tx_with_report(tx_hex: string, witnesses: string[]): AddWitnessesReport;

export interface AddWitnessesReport {
    /** Hex of the resulting transaction (unchanged if nothing was added). */
    tx_hex: string;
    /** Vkey witnesses newly inserted. */
    added: number;
    /** Vkey witnesses skipped because that public key was already present. */
    duplicates: number;
    /** Vkey witnesses skipped because their signature did not verify against this transaction. */
    invalid: number;
    /** blake2b-224 (hex) key hashes of each newly added vkey witness. */
    added_key_hashes: string[];
}

export interface CborPosition {
    offset: number;
    length: number;
}

export type CborSimpleType =
    | "Null"
    | "Bool"
    | "U8"
    | "U16"
    | "U32"
    | "U64"
    | "I8"
    | "I16"
    | "I32"
    | "I64"
    | "Int"
    | "F16"
    | "F32"
    | "F64"
    | "Bytes"
    | "String"
    | "Simple"
    | "Undefined"
    | "Break";

/**
 * Non-canonical / non-deterministic CBOR encoding flagged on a node. Kinds
 * mirror deviations from RFC 8949 §4.1 ("Preferred Serialization") and §4.2
 * ("Core Deterministic Encoding Requirements").
 *
 *  - `IntNotShortest`        — integer not encoded in shortest argument width (§4.2.1)
 *  - `FloatNotShortest`      — float representable in a narrower IEEE-754 width (§4.1)
 *  - `IndefiniteLength`      — indefinite-length bytes/text/array/map (§4.2.1)
 *  - `MapKeysNotSorted`      — map keys not in bytewise lexicographic order (§4.2.1)
 *  - `DuplicateMapKeys`      — duplicate encoded map keys (§5.6 / §4.2.1)
 *  - `BignumForSmallInt`     — tag 2/3 wrapping a value that fits in a native int (§3.4.3)
 *  - `BignumLeadingZeroes`   — bignum byte string has leading zero bytes (§3.4.3)
 */
export type CborOddityKind =
    | "IntNotShortest"
    | "FloatNotShortest"
    | "IndefiniteLength"
    | "MapKeysNotSorted"
    | "DuplicateMapKeys"
    | "BignumForSmallInt"
    | "BignumLeadingZeroes";

export interface CborOddity {
    kind: CborOddityKind;
    /** Human-readable context (actual value, position, narrowest alternative, ...). */
    detail?: string;
}

/**
 * Fields common to every CBOR node emitted by `cbor_to_json`.
 * `oddities` is only present when at least one non-canonical form was detected
 * on this specific node — canonical inputs omit it entirely.
 */
interface CborNodeBase {
    oddities?: CborOddity[];
}

export interface CborSimple extends CborNodeBase {
    type: CborSimpleType;
    position_info: CborPosition;
    struct_position_info?: CborPosition;
    value: any;
}

export interface CborArray extends CborNodeBase {
    type: "Array";
    position_info: CborPosition;
    struct_position_info: CborPosition;
    items: number | "Indefinite";
    values: CborValue[]; // nested
}

export interface CborMap extends CborNodeBase {
    type: "Map";
    position_info: CborPosition;
    struct_position_info: CborPosition;
    items: number | "Indefinite";
    values: {
        key: CborValue;
        value: CborValue;
    }[];
}

export interface CborTag extends CborNodeBase {
    type: "Tag";
    position_info: CborPosition;
    struct_position_info: CborPosition;
    tag: string;
    value: CborValue;
}

export interface CborIndefiniteString extends CborNodeBase {
    type: "IndefiniteLengthString";
    position_info: CborPosition;
    struct_position_info: CborPosition;
    chunks: CborValue[];
}

export interface CborIndefiniteBytes extends CborNodeBase {
    type: "IndefiniteLengthBytes";
    position_info: CborPosition;
    struct_position_info: CborPosition;
    chunks: CborValue[];
}

export type CborValue =
    | CborSimple
    | CborArray
    | CborMap
    | CborTag
    | CborIndefiniteString
    | CborIndefiniteBytes;

/**
 * Sub-tree returned alongside a decode error. Structurally identical to
 * `CborValue`, with two additional flags present **only** on nodes that
 * couldn't be finished:
 *
 *  - `incomplete: true` — on containers (Array / Map / Tag /
 *    IndefiniteLengthBytes / IndefiniteLengthString) whose body was cut
 *    short by the failure. For definite-length Array/Map the `items` field
 *    retains the wire-declared count; `values.length` shows how many slots
 *    actually decoded.
 *  - `incomplete_at: "key" | "value"` — on the single map entry where
 *    decoding stopped; at most one of `key` / `value` on that entry is
 *    populated, indicating which half had been parsed before the failure.
 */
export type CborPartialValue =
    | CborSimple
    | CborPartialArray
    | CborPartialMap
    | CborPartialTag
    | CborPartialIndefiniteString
    | CborPartialIndefiniteBytes;

export interface CborPartialArray extends Omit<CborArray, "values"> {
    values: CborPartialValue[];
    incomplete?: true;
}

export interface CborPartialMap extends Omit<CborMap, "values"> {
    values: Array<CborPartialMapEntry | { key: CborValue; value: CborValue }>;
    incomplete?: true;
}

export interface CborPartialMapEntry {
    key?: CborPartialValue;
    value?: CborPartialValue;
    incomplete: true;
    incomplete_at: "key" | "value";
}

export interface CborPartialTag extends Omit<CborTag, "value"> {
    /** Absent when the inner item could not be parsed at all. */
    value?: CborPartialValue;
    incomplete?: true;
}

export interface CborPartialIndefiniteString
    extends Omit<CborIndefiniteString, "chunks"> {
    chunks: CborValue[];
    incomplete?: true;
}

export interface CborPartialIndefiniteBytes
    extends Omit<CborIndefiniteBytes, "chunks"> {
    chunks: CborValue[];
    incomplete?: true;
}

export type CddlValidationResult =
    | { valid: true }
    | { valid: false; error: CddlErrorInfo };

/** One name in `CddlErrorInfo.unresolved`. */
export interface CddlUnresolvedReference {
    /** The undefined name, exactly as written in the source. */
    name: string;
    /** Byte range of that occurrence; slices back to `name`. */
    byte_span: SourceSpan;
}

/**
 * `kind` is one of:
 *  - `"parse_error"` — the text does not parse. Covers a document the
 *    grammar rejects and one that defines the same rule name twice
 *    (`message`: `rule "<name>" is already defined`); a rule that adds
 *    a choice to an earlier one (`/=`, `//=`) is not a redefinition
 *  - `"unresolved_references"` — it parses, but names a rule nothing
 *    defines; `unresolved` lists the occurrences
 *  - `"no_rules"` — it parses but declares no rules (empty or
 *    comment-only document)
 *  - `"nesting_too_deep"` — the text nests `[`, `{` or `(` past what
 *    the parser can be run on: either one run of brackets deeper than
 *    9 levels, or a document whose nesting adds up past the total
 *    budget. Refused before parsing, so `byte_span` marks the bracket
 *    that crossed the bound and `message` says which of the two it was.
 *    Brackets inside comments and inside text / byte literals are not
 *    counted; the deepest real ledger schema measures 3.
 */
export interface CddlErrorInfo {
    kind: string;
    /**
     * The parser's own message, e.g. `missing definition for rule coin`
     * or `expected type value`. Positional data is not repeated here —
     * read `byte_span`. Not stable; branch on `kind`.
     */
    message: string;
    /**
     * Byte range in the CDDL source the parser tripped over. Useful for
     * IDE squiggly underlines. For `unresolved_references` this is the
     * first entry of `unresolved`.
     *
     * Never a zero-length range: the field is **absent** for a rejection
     * the parser could not place, so a consumer can tell "no location"
     * from a location, instead of reading an empty span at offset 0 as
     * a claim about the first byte. Every rejection a real document can
     * provoke carries one — a rule defined twice is spanned at the
     * declaration that redefines it (not at the first definition, and
     * not at the whole document), covering exactly that declaration and
     * no trailing whitespace.
     */
    byte_span?: SourceSpan;
    /**
     * Present on `kind: "unresolved_references"`: every occurrence of a
     * name that resolves to nothing, in source order, so an editor can
     * mark them all in one pass instead of one round-trip per name.
     *
     * Empty only in the rare case where the parser located an
     * unresolved name the span walker cannot see (a reference inside a
     * tag constraint, `#6.<name>`); `message` still names it, and the
     * schema is still rejected.
     */
    unresolved?: CddlUnresolvedReference[];
    /**
     * Present alongside `unresolved`: true when the list was cut short
     * and the document holds still more unresolved names.
     */
    truncated?: boolean;
}

export type CborValidationResult =
    | { valid: true }
    | { valid: false; error: CborValidationErrorInfo };

/**
 * `kind` categorises the failure:
 *  - "parse_error" — the CDDL itself failed to parse
 *  - "unresolved_references" — the CDDL references a rule name that isn't defined
 *  - "no_rules" — the CDDL parsed but defined no rules (empty / comment-only document)
 *  - "missing_rule" — the rule name passed to `validate_cbor_against_cddl` is not in the CDDL
 *  - "group_rule_root" — the rule name resolves to a group rule
 *    (`g = ( … )`), which describes a run of entries inside a container
 *    rather than a data item and so cannot be a root
 *  - "input_parse" — the CBOR bytes themselves are malformed. Includes
 *    a header declaring more content than the input carries, which is
 *    reported as a truncated input rather than sized into a buffer
 *  - "nesting_too_deep" — an implementation limit was reached (see
 *    `ImplementationLimitKind`), never a
 *    claim about the input: the CDDL text nests brackets past what the
 *    parser can be run on, the CBOR input nests more than 16384 levels
 *    below its root, or the descent to an item holds more memory than
 *    the budget allows once the rule references the schema resolves
 *    along the way are counted as well as the levels. When a run reports one
 *    of these, it is the head error: everything below the bound went
 *    unexamined, so no other entry in the set is a complete answer
 *  - "validation_too_complex" — the other implementation limit, and
 *    likewise never a claim about the input: the run reached the bound
 *    on how much work one validation may do. How deeply a document
 *    nests is not how much walking it asks for — a schema whose choice
 *    alternatives each descend into the same data is re-walked once per
 *    alternative at every level, so a document well inside every nesting
 *    bound can cost a power of its own depth. Like the bound above it,
 *    it is the head error, and it says the run stopped rather than that
 *    the document is wrong: the same document under a schema that does
 *    not branch that way is still answered
 *  - "invalid_schema" — the CDDL parsed, but a control operator's
 *    operand stands for no value: a name that is not defined, a name
 *    defined only in terms of itself, or a name standing for a value of
 *    the wrong kind for the operator (`.plus` wants a number, `.cat`
 *    and `.det` a string). Never a claim about the data — the schema
 *    states nothing at that point, so nothing was decided about the
 *    document, and validation stops where the fault was found
 *  - "mismatch" / "map_cut" — a data mismatch; inspect `expected`, `path`,
 *    `byte_spans`, and `anchor_spans` for precise locations
 *  - "generic" — anything that didn't fit one of the buckets above
 *
 * A CDDL-side failure ("parse_error", "unresolved_references") carries
 * the same fields `validate_cddl` reports for the same schema —
 * `byte_span`, plus `unresolved` / `truncated`; see `CddlErrorInfo`.
 *
 * The head object is the failure to show first: the one reported at the
 * deepest point in the CBOR, i.e. from the choice alternative that
 * matched the most of the document, rather than the one the schema
 * happens to declare first. The rest follow in `additional`, in the
 * order the validator produced them.
 */
export interface CborValidationErrorInfo {
    kind: string;
    /**
     * Human-readable, length-capped and not stable — branch on `kind`.
     * Every rendering of the offending CBOR value and of the CDDL AST
     * node is replaced by a short equivalent, so this is a description,
     * not a serialisation: no message names a Rust type, whatever the
     * size of the value it describes.
     *
     * A data item comes through as `array(3 items)`, `map(2 entries)`,
     * `text "abc"`, `bytes 0x0102 (2 bytes)`, `simple(32)`, `null`, or
     * the number / boolean itself. An indefinite-length one adds the
     * word: `indefinite array(3 items)`, `indefinite map(2 entries)`,
     * `indefinite bytes(2 chunks)`, `indefinite text(2 chunks)`. A
     * tagged one is named by number around the item it wraps —
     * `#6.121(array(3 items))`, `#6.2(bytes 0x0102 (2 bytes))`; a chain
     * of tags is named by the tags at its head and closed with `…`,
     * e.g. `#6.139(#6.138(#6.137(#6.136(#6.135(…)))))`. An AST node
     * comes through as the CDDL source it was parsed from, or
     * `#6.121(…)` for a tag.
     *
     * Long values are cut short inside their own rendering, never
     * dropped: text and hex end in `…` with the byte count still beside
     * them, and the counts above hold however large the container is.
     * The validator renders under a length bound of its own, and where
     * that bound cuts a rendering short the description is rebuilt from
     * the decoded document instead.
     *
     * The key of an unclaimed map entry, and the key a map is missing,
     * are named in the notation the CDDL literal for the same data item
     * is written in, so that the key can be matched against the schema:
     * `unexpected key 1.5`, `unexpected key h'0102'`, `unexpected key
     * true`, `object missing key: h'0102'`. A composite key has no such
     * notation and is described the way every other data item is —
     * `unexpected key #6.1(array(2 items))`.
     *
     * A description is lost only where that rebuild has nothing to work
     * from: a data item the message names outside its `, got …` tail, or
     * one whose `path` does not resolve to a node of the document, which
     * is also when `byte_spans` is absent. The stand-in then names the
     * kind of item and nothing else — no length, no item count, no tag
     * number: `bytes(…)`, `array(…)`, `map(…)`, `text(…)`, `tag(…)`,
     * `integer(…)`, `float(…)`, `bool(…)`, `simple(…)`.
     */
    message: string;
    /**
     * The type or constraint the validator wanted, length-capped, and
     * rendered the same way as `message`. Absent where the failure names
     * no type — an unclaimed map entry, an implementation limit.
     */
    expected?: string;
    /**
     * Semantic path into the CBOR (e.g. `$.b[0]`). A map key that is
     * neither text nor an integer names its entry in the notation the
     * CDDL literal for the same data item is written in: `$.1.5`,
     * `$.h'0102'`, `$.true`, `$.null`.
     */
    path?: string;
    /**
     * Byte offset where a malformed input stopped decoding. Present on
     * `kind: "input_parse"`.
     */
    offset?: number;
    /**
     * Byte range in the CBOR input that triggered the error. On
     * `kind: "input_parse"` it is a one-byte mark at `offset` when the
     * decoder could not pinpoint a wider range.
     */
    byte_spans?: CborPosition[];
    /** Byte range covering the whole containing CBOR structure. */
    anchor_spans?: CborPosition[];
    /**
     * True when `byte_spans` / `anchor_spans` address bytes inside an
     * embedded CBOR payload (`.cbor` / `.cborseq`) rather than a node of
     * the outer document — `path` then names a position in the decoded
     * payload, which does not exist in the outer decoded tree. Omitted,
     * along with the spans themselves, when the payload is an
     * indefinite-length byte string: its content offsets do not map onto
     * the input, so no span is reported at all.
     */
    embedded_span?: boolean;
    /**
     * Byte range in the CDDL **source** pointing at the type the
     * validator tried to apply when it failed (synthesised by walking
     * the AST in parallel with `path`). Useful for highlighting the
     * offending CDDL rule in editors. Never includes trailing
     * whitespace or comments. Falls back to the enclosing container's
     * type where the schema cannot resolve the position unambiguously —
     * with occurrence indicators a schema slot and a data index are not
     * the same thing.
     */
    cddl_byte_span?: SourceSpan;
    /**
     * True when the validator attributed this error to one alternative
     * of a type choice: it says what that alternative wanted, not what
     * the document has to be.
     */
    from_type_choice?: boolean;
    /**
     * How many reported errors this entry stands for. Errors sharing
     * `path`, `cddl_byte_span` and `kind` describe the same failing node
     * — typically one per alternative of a choice — and fold into a
     * single entry. Absent means one.
     */
    occurrences?: number;
    /**
     * The distinct `expected` renderings of the folded errors, capped at
     * five: what the alternatives tried at this node. Present only when
     * more than one of them differed.
     */
    alternatives?: string[];
    /**
     * Other validation errors reported in the same run, deduplicated the
     * same way and capped at 200 entries.
     */
    additional?: CborValidationErrorInfo[];
    /**
     * Present on the head error when `additional` was cut short: how
     * many further deduplicated entries were dropped.
     */
    additional_truncated?: number;
}

export interface DecodingParams {
    plutus_script_version?: number;
    plutus_data_schema?: PlutusDataSchema;
}

export type PlutusDataSchema = "BasicConversions" | "DetailedSchema";

export interface CheckSignaturesResult {
    /** Indicates whether the transaction or block is valid. */
    valid: boolean;
    /** The transaction hash as a hexadecimal string (if available). */
    tx_hash?: string;
    /** An array of invalid Catalyst witness signatures (hex strings). */
    invalidCatalystWitnesses: string[];
    /** An array of invalid VKey witness signatures (hex strings). */
    invalidVkeyWitnesses: string[];
}

// RedeemerTag lives in the autogenerated block below (from Rust
// validators::validation_result::RedeemerTag).

// A successful redeemer evaluation contains the original execution units,
// the calculated execution units, and additional redeemer info.
export interface RedeemerSuccess {
    original_ex_units: ExUnits;
    calculated_ex_units: ExUnits;
    redeemer_index: number;
    redeemer_tag: RedeemerTag;
}

// A failed redeemer evaluation contains the original execution units,
// an error message, and additional redeemer info.
export interface RedeemerError {
    original_ex_units: ExUnits;
    error: string;
    redeemer_index: number;
    redeemer_tag: RedeemerTag;
}

// The result from executing the transaction scripts is an array of redeemer results.
// Each result can be either a success or an error.
export type RedeemerResult = RedeemerSuccess | RedeemerError;

// Type for the `execute_tx_scripts` response after JSON-parsing.
export type ExecuteTxScriptsResult = RedeemerResult[];

// The overall JSON produced by `to_json_program`:
export interface ProgramJson {
    program: {
        version: string;
        term: Term;
    };
}

// A UPLC term can be one of several forms.
export type Term =
    | VarTerm
    | DelayTerm
    | LambdaTerm
    | ApplyTerm
    | ConstantTerm
    | ForceTerm
    | ErrorTerm
    | BuiltinTerm
    | ConstrTerm
    | CaseTerm;

export interface VarTerm {
    var: string;
}

export interface DelayTerm {
    delay: Term;
}

export interface LambdaTerm {
    lambda: {
        parameter_name: string;
        body: Term;
    };
}

export interface ApplyTerm {
    apply: {
        function: Term;
        argument: Term;
    };
}

export interface ConstantTerm {
    constant: Constant;
}

export interface ForceTerm {
    force: Term;
}

export interface ErrorTerm {
    error: "error";
}

export interface BuiltinTerm {
    builtin: string;
}

export interface ConstrTerm {
    constr: {
        tag: number;
        fields: Term[];
    };
}

export interface CaseTerm {
    case: {
        constr: Term;
        branches: Term[];
    };
}

// The UPLC constant is one of several union types.
export type Constant =
    | IntegerConstant
    | ByteStringConstant
    | StringConstant
    | UnitConstant
    | BoolConstant
    | ListConstant
    | PairConstant
    | DataConstant
    | Bls12_381G1ElementConstant
    | Bls12_381G2ElementConstant;

export interface IntegerConstant {
    integer: string; // represented as a string
}

export interface ByteStringConstant {
    bytestring: string; // hex-encoded string
}

export interface StringConstant {
    string: string;
}

export interface UnitConstant {
    unit: "()";
}

export interface BoolConstant {
    bool: boolean;
}

export interface ListConstant {
    list: {
        type: Type;
        items: Constant[];
    };
}

export interface PairConstant {
    pair: {
        type_left: Type;
        type_right: Type;
        left: Constant;
        right: Constant;
    };
}

export interface DataConstant {
    data: PlutusData;
}

export interface Bls12_381G1ElementConstant {
    bls12_381_G1_element: {
        x: number;
        y: number;
        z: number;
    };
}

export interface Bls12_381G2ElementConstant {
    bls12_381_G2_element: BlstP2;
}

// The UPLC type is represented either as a string literal or an object.
export type Type =
    | "bool"
    | "integer"
    | "string"
    | "bytestring"
    | "unit"
    | "data"
    | "bls12_381_G1_element"
    | "bls12_381_G2_element"
    | "bls12_381_mlresult"
    | ListType
    | PairType;

export interface ListType {
    list: Type;
}

export interface PairType {
    pair: {
        left: Type;
        right: Type;
    };
}

// The JSON representation for a blst_p2 element: each coordinate is an array of numbers.
export interface BlstP2 {
    x: number[];
    y: number[];
    z: number[];
}

// Plutus data is also a tagged union.
export type PlutusData =
    | ConstrData
    | MapData
    | BigIntData
    | BoundedBytesData
    | ArrayData;

export interface ConstrData {
    constr: {
        tag: number;
        any_constructor: boolean;
        fields: PlutusData[];
    };
}

export interface MapData {
    map: Array<{
        key: PlutusData;
        value: PlutusData;
    }>;
}

export interface BigIntData {
    integer: string; // big integers are represented as strings
}

export interface BoundedBytesData {
    bytestring: string; // hex-encoded
}

export interface ArrayData {
    list: PlutusData[];
}

// Asset / TxInput / TxOutput / UTxO / CostModels / ExUnits are defined in the
// autogenerated block below (they come from Rust types in src/common.rs via
// schemars). Do NOT add hand-written copies here — `schema-to-ts.js` fails on
// same-name collisions between the hand-written and autogenerated halves.

///AUTOGENERATED


export interface NecessaryInputData {
  utxos: TxInput[];
  accounts: string[];
  pools: string[];
  dReps: string[];
  govActions: GovernanceActionId[];
  lastEnactedGovAction: GovernanceActionType[];
  committeeMembersCold: LocalCredential[];
  committeeMembersHot: LocalCredential[];
}

export type SerializableScriptContext =
  | {
      tx_info: SerializableTxInfo;
      purpose: SerializableScriptPurpose;
      script_context_version: "V1V2";
    }
  | {
      tx_info: SerializableTxInfo;
      redeemer: SerializablePlutusData;
      purpose: SerializableScriptInfo;
      script_context_version: "V3";
    };
export type SerializableTxInfo =
  | {
      V1: SerializableTxInfoV1;
    }
  | {
      V2: SerializableTxInfoV2;
    }
  | {
      V3: SerializableTxInfoV3;
    };
export type SerializableTransactionOutput =
  | {
      address: string;
      value: SerializableCardanoValue;
      datum_hash?: string | null;
      output_format: "Legacy";
    }
  | {
      address: string;
      value: SerializableCardanoValue;
      datum_option?: SerializableDatumOption | null;
      script_ref?: SerializableScriptRef | null;
      output_format: "PostAlonzo";
    };
export type SerializableCardanoValue =
  | {
      amount: bigint;
      value_type: "Coin";
    }
  | {
      coin: bigint;
      assets: SerializableAsset[];
      value_type: "Multiasset";
    };
export type SerializableDatumOption =
  | {
      hash: string;
      datum_type: "Hash";
    }
  | {
      data: SerializablePlutusData;
      datum_type: "Data";
    };
/**
 * Serializable version of PlutusData that can be converted to/from JSON
 */
export type SerializablePlutusData =
  | {
      type: "Constr";
      tag: bigint;
      any_constructor?: number | null;
      fields: SerializablePlutusData[];
    }
  | {
      type: "Map";
      key_value_pairs: SerializableKeyValuePair[];
    }
  | (
      | {
          Int: string;
        }
      | {
          BigUInt: string;
        }
      | {
          BigNInt: string;
        }
    )
  | {
      type: "BoundedBytes";
      value: string;
    }
  | {
      type: "Array";
      values: SerializablePlutusData[];
    };
export type SerializableScriptRef =
  | {
      script: string;
      script_type: "NativeScript";
    }
  | {
      script: string;
      script_type: "PlutusV1Script";
    }
  | {
      script: string;
      script_type: "PlutusV2Script";
    }
  | {
      script: string;
      script_type: "PlutusV3Script";
    };
export type SerializableCertificate =
  | {
      stake_credential: SerializableStakeCredential;
      certificate_type: "StakeRegistration";
    }
  | {
      stake_credential: SerializableStakeCredential;
      certificate_type: "StakeDeregistration";
    }
  | {
      stake_credential: SerializableStakeCredential;
      pool_keyhash: string;
      certificate_type: "StakeDelegation";
    }
  | {
      pool_params: SerializablePoolParams;
      certificate_type: "PoolRegistration";
    }
  | {
      pool_keyhash: string;
      epoch: bigint;
      certificate_type: "PoolRetirement";
    }
  | {
      stake_credential: SerializableStakeCredential;
      deposit: bigint;
      certificate_type: "Reg";
    }
  | {
      stake_credential: SerializableStakeCredential;
      refund: bigint;
      certificate_type: "UnReg";
    }
  | {
      stake_credential: SerializableStakeCredential;
      drep: SerializableDRep;
      certificate_type: "VoteDeleg";
    }
  | {
      stake_credential: SerializableStakeCredential;
      pool_keyhash: string;
      drep: SerializableDRep;
      certificate_type: "StakeVoteDeleg";
    }
  | {
      stake_credential: SerializableStakeCredential;
      pool_keyhash: string;
      deposit: bigint;
      certificate_type: "StakeRegDeleg";
    }
  | {
      stake_credential: SerializableStakeCredential;
      drep: SerializableDRep;
      deposit: bigint;
      certificate_type: "VoteRegDeleg";
    }
  | {
      stake_credential: SerializableStakeCredential;
      pool_keyhash: string;
      drep: SerializableDRep;
      deposit: bigint;
      certificate_type: "StakeVoteRegDeleg";
    }
  | {
      committee_cold_credential: SerializableStakeCredential;
      committee_hot_credential: SerializableStakeCredential;
      certificate_type: "AuthCommitteeHot";
    }
  | {
      committee_cold_credential: SerializableStakeCredential;
      anchor?: SerializableAnchor | null;
      certificate_type: "ResignCommitteeCold";
    }
  | {
      drep_credential: SerializableStakeCredential;
      deposit: bigint;
      anchor?: SerializableAnchor | null;
      certificate_type: "RegDRepCert";
    }
  | {
      drep_credential: SerializableStakeCredential;
      refund: bigint;
      certificate_type: "UnRegDRepCert";
    }
  | {
      drep_credential: SerializableStakeCredential;
      anchor?: SerializableAnchor | null;
      certificate_type: "UpdateDRepCert";
    };
export type SerializableStakeCredential =
  | {
      hash: string;
      credential_type: "KeyHash";
    }
  | {
      hash: string;
      credential_type: "ScriptHash";
    };
export type SerializableRelay =
  | {
      port?: number | null;
      ipv4?: string | null;
      ipv6?: string | null;
      relay_type: "SingleHostAddr";
    }
  | {
      port?: number | null;
      hostname: string;
      relay_type: "SingleHostName";
    }
  | {
      hostname: string;
      relay_type: "MultiHostName";
    };
export type SerializableDRep =
  | {
      hash: string;
      drep_type: "Key";
    }
  | {
      hash: string;
      drep_type: "Script";
    }
  | {
      drep_type: "Abstain";
    }
  | {
      drep_type: "NoConfidence";
    };
export type SerializableGovAction =
  | {
      gov_action_id?: SerializableGovActionId | null;
      protocol_params_update: SerializableProtocolParamsUpdate;
      policy_hash?: string | null;
      action_type: "ParameterChange";
    }
  | {
      gov_action_id?: SerializableGovActionId | null;
      protocol_version: ProtocolVersion;
      action_type: "HardForkInitiation";
    }
  | {
      withdrawals: [unknown, unknown][];
      policy_hash?: string | null;
      action_type: "TreasuryWithdrawals";
    }
  | {
      gov_action_id?: SerializableGovActionId | null;
      action_type: "NoConfidence";
    }
  | {
      gov_action_id?: SerializableGovActionId | null;
      members_to_remove: SerializableStakeCredential[];
      members_to_add: [unknown, unknown][];
      quorum_threshold: SubCoin;
      action_type: "UpdateCommittee";
    }
  | {
      gov_action_id?: SerializableGovActionId | null;
      constitution: SerializableConstitution;
      action_type: "NewConstitution";
    }
  | {
      action_type: "Information";
    };
export type SerializableScriptPurpose =
  | {
      policy_id: string;
      purpose_type: "Minting";
    }
  | {
      utxo_ref: SerializableTransactionInput;
      purpose_type: "Spending";
    }
  | {
      stake_credential: SerializableStakeCredential;
      purpose_type: "Rewarding";
    }
  | {
      index: bigint;
      certificate: SerializableCertificate;
      purpose_type: "Certifying";
    }
  | {
      voter: SerializableVoter;
      purpose_type: "Voting";
    }
  | {
      index: bigint;
      proposal: SerializableProposalProcedure;
      purpose_type: "Proposing";
    };
export type SerializableVoter =
  | {
      hash: string;
      voter_type: "ConstitutionalCommitteeScript";
    }
  | {
      hash: string;
      voter_type: "ConstitutionalCommitteeKey";
    }
  | {
      hash: string;
      voter_type: "DRepScript";
    }
  | {
      hash: string;
      voter_type: "DRepKey";
    }
  | {
      hash: string;
      voter_type: "StakePoolKey";
    };
export type SerializableScriptInfo =
  | {
      policy_id: string;
      script_info_type: "Minting";
    }
  | {
      utxo_ref: SerializableTransactionInput;
      datum?: SerializablePlutusData | null;
      script_info_type: "Spending";
    }
  | {
      stake_credential: SerializableStakeCredential;
      script_info_type: "Rewarding";
    }
  | {
      index: bigint;
      certificate: SerializableCertificate;
      script_info_type: "Certifying";
    }
  | {
      voter: SerializableVoter;
      script_info_type: "Voting";
    }
  | {
      index: bigint;
      proposal: SerializableProposalProcedure;
      script_info_type: "Proposing";
    };

export interface SerializableTxInfoV1 {
  inputs: SerializableTxInInfo[];
  outputs: SerializableTransactionOutput[];
  fee: SerializableCardanoValue;
  mint: SerializableMintValue;
  certificates: SerializableCertificate[];
  withdrawals: [unknown, unknown][];
  valid_range: SerializableTimeRange;
  signatories: string[];
  data: [unknown, unknown][];
  redeemers: [unknown, unknown][];
  id: string;
}
export interface SerializableTxInInfo {
  out_ref: SerializableTransactionInput;
  resolved: SerializableTransactionOutput;
}
export interface SerializableTransactionInput {
  transaction_id: string;
  index: bigint;
}
export interface SerializableAsset {
  policy_id: string;
  tokens: SerializableToken[];
}
export interface SerializableToken {
  asset_name: string;
  /**
   * Decimal string. Held as a string because the value range spans both
   *  negative mint/burn amounts and `Value` amounts up to `u64::MAX` —
   *  no fixed-width integer type covers both without loss.
   */
  quantity: string;
}
export interface SerializableKeyValuePair {
  key: SerializablePlutusData;
  value: SerializablePlutusData;
}
export interface SerializableMintValue {
  mint_value: SerializableAsset[];
}
export interface SerializablePoolParams {
  operator: string;
  vrf_keyhash: string;
  pledge: bigint;
  cost: bigint;
  margin: SubCoin;
  reward_account: string;
  pool_owners: string[];
  relays: SerializableRelay[];
  pool_metadata?: SerializablePoolMetadata | null;
}

export interface SerializablePoolMetadata {
  url: string;
  hash: string;
}
export interface SerializableAnchor {
  url: string;
  data_hash: string;
}
export interface SerializableTimeRange {
  lower_bound?: number | null;
  upper_bound?: number | null;
}
export interface SerializableTxInfoV2 {
  inputs: SerializableTxInInfo[];
  reference_inputs: SerializableTxInInfo[];
  outputs: SerializableTransactionOutput[];
  fee: SerializableCardanoValue;
  mint: SerializableMintValue;
  certificates: SerializableCertificate[];
  withdrawals: [unknown, unknown][];
  valid_range: SerializableTimeRange;
  signatories: string[];
  data: [unknown, unknown][];
  redeemers: [unknown, unknown][];
  id: string;
}
export interface SerializableTxInfoV3 {
  inputs: SerializableTxInInfo[];
  reference_inputs: SerializableTxInInfo[];
  outputs: SerializableTransactionOutput[];
  fee: bigint;
  mint: SerializableMintValue;
  certificates: SerializableCertificate[];
  withdrawals: [unknown, unknown][];
  valid_range: SerializableTimeRange;
  signatories: string[];
  data: [unknown, unknown][];
  redeemers: [unknown, unknown][];
  id: string;
  votes: [unknown, unknown][];
  proposal_procedures: SerializableProposalProcedure[];
  current_treasury_amount?: number | null;
  treasury_donation?: number | null;
}
export interface SerializableProposalProcedure {
  deposit: bigint;
  reward_account: string;
  gov_action: SerializableGovAction;
  anchor: SerializableAnchor;
}
export interface SerializableGovActionId {
  transaction_id: string;
  action_index: number;
}
export interface SerializableProtocolParamsUpdate {
  minfee_a?: number | null;
  minfee_b?: number | null;
  max_block_body_size?: number | null;
  max_transaction_size?: number | null;
  max_block_header_size?: number | null;
  key_deposit?: number | null;
  pool_deposit?: number | null;
  maximum_epoch?: number | null;
  desired_number_of_stake_pools?: number | null;
  pool_pledge_influence?: SubCoin | null;
  expansion_rate?: SubCoin | null;
  treasury_growth_rate?: SubCoin | null;
  min_pool_cost?: number | null;
  ada_per_utxo_byte?: number | null;
  cost_models_for_script_languages?: SerializableCostModels | null;
  execution_costs?: SerializableExUnitPrices | null;
  max_tx_ex_units?: ExUnits | null;
  max_block_ex_units?: ExUnits | null;
  max_value_size?: number | null;
  collateral_percentage?: number | null;
  max_collateral_inputs?: number | null;
  pool_voting_thresholds?: SerializablePoolVotingThresholds | null;
  drep_voting_thresholds?: SerializableDRepVotingThresholds | null;
  min_committee_size?: number | null;
  committee_term_limit?: number | null;
  governance_action_validity_period?: number | null;
  governance_action_deposit?: number | null;
  drep_deposit?: number | null;
  drep_inactivity_period?: number | null;
  minfee_refscript_cost_per_byte?: SubCoin | null;
}
export interface SerializableCostModels {
  plutus_v1?: number[] | null;
  plutus_v2?: number[] | null;
  plutus_v3?: number[] | null;
}
export interface SerializableExUnitPrices {
  mem_price: SubCoin;
  step_price: SubCoin;
}

export interface SerializablePoolVotingThresholds {
  motion_no_confidence: SubCoin;
  committee_normal: SubCoin;
  committee_no_confidence: SubCoin;
  hard_fork_initiation: SubCoin;
  security_voting_threshold: SubCoin;
}
export interface SerializableDRepVotingThresholds {
  motion_no_confidence: SubCoin;
  committee_normal: SubCoin;
  committee_no_confidence: SubCoin;
  update_constitution: SubCoin;
  hard_fork_initiation: SubCoin;
  pp_network_group: SubCoin;
  pp_economic_group: SubCoin;
  pp_technical_group: SubCoin;
  pp_governance_group: SubCoin;
  treasury_withdrawal: SubCoin;
}

export interface SerializableConstitution {
  anchor: SerializableAnchor;
  guardrail_script?: string | null;
}

export type GovernanceActionType =
  | "parameterChangeAction"
  | "hardForkInitiationAction"
  | "treasuryWithdrawalsAction"
  | "noConfidenceAction"
  | "updateCommitteeAction"
  | "newConstitutionAction"
  | "infoAction";

export type NetworkType = "mainnet" | "preview" | "preprod";

export interface ValidationInputContext {
  utxoSet: UtxoInputContext[];
  protocolParameters: ProtocolParameters;
  slot: bigint;
  accountContexts: AccountInputContext[];
  drepContexts: DrepInputContext[];
  poolContexts: PoolInputContext[];
  govActionContexts: GovActionInputContext[];
  lastEnactedGovAction: GovActionInputContext[];
  currentCommitteeMembers: CommitteeInputContext[];
  potentialCommitteeMembers: CommitteeInputContext[];
  treasuryValue: bigint;
  networkType: NetworkType;
  /**
   * Current constitution. When present, enables the ParameterChange /
   *  TreasuryWithdrawals guardrails-policy-hash check; when absent (older
   *  callers, or a provider that can't supply it) that check is skipped.
   */
  constitution?: ConstitutionContext | null;
}
export interface UtxoInputContext {
  utxo: UTxO;
  isSpent: boolean;
}
export interface UTxO {
  input: TxInput;
  output: TxOutput;
}

export interface TxOutput {
  address: string;
  amount: Asset[];
  dataHash?: string | null;
  plutusData?: string | null;
  scriptRef?: string | null;
  scriptHash?: string | null;
}
export interface Asset {
  unit: string;
  quantity: string;
}
export interface ProtocolParameters {
  /**
   * Linear factor for the minimum fee calculation formula
   */
  minFeeCoefficientA: bigint;
  /**
   * Constant factor for the minimum fee calculation formula
   */
  minFeeConstantB: bigint;
  /**
   * Maximum block body size in bytes
   */
  maxBlockBodySize: number;
  /**
   * Maximum transaction size in bytes
   */
  maxTransactionSize: number;
  /**
   * Maximum block header size in bytes
   */
  maxBlockHeaderSize: number;
  /**
   * Deposit amount required for registering a stake key
   */
  stakeKeyDeposit: bigint;
  /**
   * Deposit amount required for registering a stake pool
   */
  stakePoolDeposit: bigint;
  /**
   * Maximum number of epochs that can be used for pool retirement ahead
   */
  maxEpochForPoolRetirement: number;
  /**
   * Protocol version (major, minor)
   *
   * @minItems 2
   * @maxItems 2
   */
  protocolVersion: [unknown, unknown];
  /**
   * Minimum pool cost in lovelace
   */
  minPoolCost: bigint;
  /**
   * Cost per UTxO byte in lovelace
   */
  adaPerUtxoByte: bigint;
  costModels: CostModels;
  executionPrices: ExUnitPrices;
  maxTxExecutionUnits: ExUnits;
  maxBlockExecutionUnits: ExUnits;
  /**
   * Maximum size of a Value in bytes
   */
  maxValueSize: number;
  /**
   * Percentage of transaction fee required as collateral
   */
  collateralPercentage: number;
  /**
   * Maximum number of collateral inputs
   */
  maxCollateralInputs: number;
  /**
   * Deposit amount required for submitting a governance action
   */
  governanceActionDeposit: bigint;
  /**
   * Deposit amount required for registering as a DRep
   */
  drepDeposit: bigint;
  referenceScriptCostPerByte: SubCoin;
}
/**
 * Cost models for Plutus script execution
 */
export interface CostModels {
  plutusV1?: number[] | null;
  plutusV2?: number[] | null;
  plutusV3?: number[] | null;
}
/**
 * Price of execution units for script execution
 */
export interface ExUnitPrices {
  memPrice: SubCoin;
  stepPrice: SubCoin;
}
export interface SubCoin {
  numerator: bigint;
  denominator: bigint;
}
/**
 * Maximum execution units allowed for a transaction
 */

/**
 * Maximum execution units allowed for a block
 */

/**
 * Coins per byte for reference scripts
 */

export interface AccountInputContext {
  bech32Address: string;
  isRegistered: boolean;
  payedDeposit?: number | null;
  delegatedToDrep?: string | null;
  delegatedToPool?: string | null;
  balance?: number | null;
}
export interface DrepInputContext {
  bech32Drep: string;
  isRegistered: boolean;
  payedDeposit?: number | null;
}
export interface PoolInputContext {
  poolId: string;
  isRegistered: boolean;
  retirementEpoch?: number | null;
}
export interface GovActionInputContext {
  actionId: GovernanceActionId;
  actionType: GovernanceActionType;
  isActive: boolean;
}

export interface CommitteeInputContext {
  committeeMemberCold: LocalCredential;
  committeeMemberHot?: LocalCredential | null;
  isResigned: boolean;
}
/**
 * Current on-chain constitution, as far as the caller can supply it. Only the
 *  guardrails (constitution policy) script hash matters for validation.
 */
export interface ConstitutionContext {
  /**
   * Guardrails script hash (hex). `None` means the constitution defines no
   *  guardrails script.
   */
  guardrailScriptHash?: string | null;
}

/**
 * Phase 1 validation errors
 */
export type Phase1Error =
  | (
      | "GenesisKeyDelegationCertificateIsNotSupported"
      | "MoveInstantaneousRewardsCertificateIsNotSupported"
    )
  | {
      BadInputsUTxO: {
        invalid_input: TxInput;
      };
    }
  | {
      OutsideValidityIntervalUTxO: {
        current_slot: bigint;
        interval_start: bigint;
        interval_end: bigint;
      };
    }
  | {
      MaxTxSizeUTxO: {
        actual_size: bigint;
        max_size: bigint;
      };
    }
  | "InputSetEmptyUTxO"
  | {
      FeeTooSmallUTxO: {
        actual_fee: bigint;
        min_fee: bigint;
        fee_decomposition: FeeDecomposition;
      };
    }
  | {
      ValueNotConservedUTxO: {
        input_sum: Value;
        output_sum: Value;
        difference: Value;
      };
    }
  | {
      WrongNetwork: {
        wrong_addresses: string[];
      };
    }
  | {
      WrongNetworkWithdrawal: {
        wrong_addresses: string[];
      };
    }
  | {
      WrongNetworkInTxBody: {
        actual_network: number;
        expected_network: number;
      };
    }
  | {
      OutputTooSmallUTxO: {
        output_amount: number;
        min_amount: number;
      };
    }
  | {
      CollateralReturnTooSmall: {
        output_amount: number;
        min_amount: number;
      };
    }
  | {
      OutputBootAddrAttrsTooBig: {
        output: unknown;
        actual_size: bigint;
        max_size: bigint;
      };
    }
  | {
      OutputsValueTooBig: {
        actual_size: bigint;
        max_size: bigint;
      };
    }
  | {
      InsufficientCollateral: {
        total_collateral: number;
        required_collateral: number;
      };
    }
  | {
      ExUnitsTooBigUTxO: {
        actual_memory_units: bigint;
        actual_steps_units: bigint;
        max_memory_units: bigint;
        max_steps_units: bigint;
      };
    }
  | "CalculatedCollateralContainsNonAdaAssets"
  | {
      CollateralInputContainsNonAdaAssets: {
        collateral_input: string;
      };
    }
  | {
      CollateralIsLockedByScript: {
        invalid_collateral: string;
      };
    }
  | {
      TooManyCollateralInputs: {
        actual_count: number;
        max_count: number;
      };
    }
  | "NoCollateralInputs"
  | {
      IncorrectTotalCollateralField: {
        declared_total: number;
        actual_sum: number;
      };
    }
  | {
      InvalidSignature: {
        invalid_signature: string;
      };
    }
  | {
      ExtraneousSignature: {
        extraneous_signature: string;
      };
    }
  | {
      NativeScriptIsUnsuccessful: {
        native_script_hash: string;
      };
    }
  | {
      PlutusScriptIsUnsuccessful: {
        plutus_script_hash: string;
      };
    }
  | {
      MissingVKeyWitnesses: {
        missing_key_hash: string;
      };
    }
  | {
      MissingScriptWitnesses: {
        missing_script_hash: string;
      };
    }
  | {
      MissingRedeemer: {
        tag: string;
        index: bigint;
      };
    }
  | "MissingTxBodyMetadataHash"
  | "MissingTxMetadata"
  | {
      ConflictingMetadataHash: {
        expected_hash: string;
        actual_hash: string;
      };
    }
  | {
      InvalidMetadata: {
        message: string;
      };
    }
  | {
      ExtraneousScriptWitnesses: {
        extraneous_script: string;
      };
    }
  | {
      StakeAlreadyRegistered: {
        reward_address: string;
      };
    }
  | {
      StakeNotRegistered: {
        reward_address: string;
      };
    }
  | {
      StakeNonZeroAccountBalance: {
        reward_address: string;
        remaining_balance: bigint;
      };
    }
  | {
      RewardAccountNotExisting: {
        reward_address: string;
      };
    }
  | {
      WrongRequestedWithdrawalAmount: {
        expected_amount: number;
        requested_amount: bigint;
        reward_address: string;
      };
    }
  | {
      StakePoolNotRegistered: {
        pool_id: string;
      };
    }
  | {
      WrongRetirementEpoch: {
        specified_epoch: bigint;
        current_epoch: bigint;
        min_epoch: bigint;
        max_epoch: bigint;
      };
    }
  | {
      StakePoolCostTooLow: {
        specified_cost: bigint;
        min_cost: bigint;
      };
    }
  | {
      InsufficientFundsForMir: {
        requested_amount: bigint;
        available_amount: bigint;
      };
    }
  | {
      InvalidCommitteeVote: {
        voter: unknown;
        message: string;
      };
    }
  | {
      DRepIncorrectDeposit: {
        supplied_deposit: number;
        required_deposit: number;
      };
    }
  | {
      DRepDeregistrationWrongRefund: {
        supplied_refund: number;
        required_refund: number;
      };
    }
  | {
      DelegateeDRepNotRegistered: {
        drep_id: string;
        cert_index: number;
      };
    }
  | {
      StakeRegistrationWrongDeposit: {
        supplied_deposit: number;
        required_deposit: number;
      };
    }
  | {
      StakeDeregistrationWrongRefund: {
        supplied_refund: number;
        required_refund: number;
      };
    }
  | {
      PoolRegistrationWrongDeposit: {
        supplied_deposit: number;
        required_deposit: number;
      };
    }
  | {
      CommitteeHasPreviouslyResigned: {
        committee_credential: LocalCredential;
      };
    }
  | {
      TreasuryValueMismatch: {
        declared_value: bigint;
        actual_value: bigint;
      };
    }
  | {
      RefScriptsSizeTooBig: {
        actual_size: bigint;
        max_size: bigint;
      };
    }
  | {
      WithdrawalNotAllowedBecauseNotDelegatedToDRep: {
        reward_address: string;
      };
    }
  | {
      CommitteeIsUnknown: {
        /**
         * The committee key hash
         */
        committee_key_hash:
          | {
              keyHash: number[];
            }
          | {
              scriptHash: number[];
            };
      };
    }
  | {
      GovActionsDoNotExist: {
        /**
         * The list of invalid governance action IDs
         */
        invalid_action_ids: GovernanceActionId[];
      };
    }
  | {
      MalformedProposal: {
        gov_action: GovernanceActionId;
      };
    }
  | {
      ProposalProcedureNetworkIdMismatch: {
        /**
         * The reward account
         */
        reward_account: string;
        /**
         * The expected network ID
         */
        expected_network: number;
      };
    }
  | {
      TreasuryWithdrawalsNetworkIdMismatch: {
        /**
         * The set of mismatched reward accounts
         */
        mismatched_account: string;
        /**
         * The expected network ID
         */
        expected_network: number;
      };
    }
  | {
      VotingProposalIncorrectDeposit: {
        /**
         * The supplied deposit amount
         */
        supplied_deposit: number;
        /**
         * The required deposit amount
         */
        required_deposit: number;
        proposal_index: number;
      };
    }
  | {
      DisallowedVoters: {
        /**
         * List of disallowed voter and action ID pairs
         */
        disallowed_pairs: [unknown, unknown][];
      };
    }
  | {
      ConflictingCommitteeUpdate: {
        /**
         * The set of conflicting credentials
         */
        conflicting_credentials:
          | {
              keyHash: number[];
            }
          | {
              scriptHash: number[];
            };
      };
    }
  | {
      ExpirationEpochTooSmall: {
        /**
         * Map of credentials to their invalid expiration epochs
         */
        invalid_expirations: {
          [k: string]: number;
        };
      };
    }
  | {
      InvalidPrevGovActionId: {
        /**
         * The invalid proposal
         */
        proposal: {
          [k: string]: unknown;
        };
      };
    }
  | {
      VotingOnExpiredGovAction: {
        expired_gov_action: GovernanceActionId;
      };
    }
  | {
      ProposalCantFollow: {
        /**
         * Previous governance action ID
         */
        prev_gov_action_id?: GovernanceActionId | null;
        supplied_version: ProtocolVersion;
        /**
         * The expected protocol version
         */
        expected_versions: ProtocolVersion[];
      };
    }
  | {
      InvalidConstitutionPolicyHash: {
        /**
         * The supplied policy hash
         */
        supplied_hash?: string | null;
        /**
         * The expected policy hash
         */
        expected_hash?: string | null;
      };
    }
  | {
      VoterDoNotExist: {
        /**
         * List of non-existent voters
         */
        missing_voter: {
          [k: string]: unknown;
        };
      };
    }
  | {
      ZeroTreasuryWithdrawals: {
        gov_action: GovernanceActionId;
      };
    }
  | {
      ProposalReturnAccountDoesNotExist: {
        /**
         * The invalid return account
         */
        return_account: string;
      };
    }
  | {
      TreasuryWithdrawalReturnAccountsDoNotExist: {
        /**
         * List of non-existent return accounts
         */
        missing_account: string;
      };
    }
  | {
      AuxiliaryDataHashMismatch: {
        /**
         * The expected auxiliary data hash
         */
        expected_hash: string;
        /**
         * The actual auxiliary data hash
         */
        actual_hash?: string | null;
      };
    }
  | "AuxiliaryDataHashMissing"
  | "AuxiliaryDataHashPresentButNotExpected"
  | {
      UnknownError: {
        message: string;
      };
    }
  | {
      MissingDatum: {
        datum_hash: string;
      };
    }
  | {
      ExtraneousDatumWitnesses: {
        datum_hash: string;
      };
    }
  | {
      ScriptDataHashMismatch: {
        /**
         * The expected script data hash (computed from witness set)
         */
        expected_hash?: string | null;
        /**
         * The provided script data hash (from transaction body)
         */
        provided_hash?: string | null;
        /**
         * Decomposition of the expected hash computation
         */
        expected_decomposition?: ScriptDataHashDecomposition | null;
      };
    }
  | {
      ReferenceInputOverlapsWithInput: {
        input: TxInput;
      };
    };
export type LocalCredential =
  | {
      keyHash: number[];
    }
  | {
      scriptHash: number[];
    };
export type Phase1Warning =
  | (
      | "InputsAreNotSorted"
      | "WithdrawalsAreNotSorted"
      | "CollateralIsUnnecessary"
      | "TotalCollateralIsNotDeclared"
    )
  | {
      FeeIsBiggerThanMinFee: {
        actual_fee: bigint;
        min_fee: bigint;
        fee_decomposition: FeeDecomposition;
      };
    }
  | {
      InputUsesRewardAddress: {
        invalid_input: string;
      };
    }
  | {
      CollateralInputUsesRewardAddress: {
        invalid_collateral: string;
      };
    }
  | "CannotCheckStakeDeregistrationRefund"
  | "CannotCheckDRepDeregistrationRefund"
  | {
      PoolAlreadyRegistered: {
        pool_id: string;
      };
    }
  | {
      DRepAlreadyRegistered: {
        drep_id: string;
      };
    }
  | {
      CommitteeAlreadyAuthorized: {
        committee_key: string;
      };
    }
  | {
      DRepNotRegistered: {
        cert_index: number;
      };
    }
  | {
      DelegationToRetiringPool: {
        pool_id: string;
        cert_index: number;
      };
    }
  | {
      DuplicateRegistrationInTx: {
        entity_type: string;
        entity_id: string;
        cert_index: number;
      };
    }
  | {
      DuplicateCommitteeColdResignationInTx: {
        committee_credential: LocalCredential;
        cert_index: number;
      };
    }
  | {
      DuplicateCommitteeHotRegistrationInTx: {
        committee_credential: LocalCredential;
        cert_index: number;
      };
    };
/**
 * Phase 1 validation errors
 */
export type Phase2Error =
  | "NativeScriptIsReferencedByRedeemer"
  | {
      NoEnoughBudget: {
        expected_budget: ExUnits;
        actual_budget: ExUnits;
      };
    }
  | {
      InvalidRedeemerIndex: {
        tag: string;
        index: bigint;
      };
    }
  | {
      MachineError: {
        error: string;
      };
    }
  | {
      CostModelNotFound: {
        language: string;
      };
    }
  | {
      ScriptDecodeError: {
        error: string;
      };
    }
  | {
      ResolvedInputNotFound: {
        tx_hash: string;
        tx_index: bigint;
      };
    }
  | "ByronAddressNotAllowed"
  | "InlineDatumNotAllowedForPlutusV1"
  | "ReferenceInputsNotAllowedForPlutusV1"
  | {
      SlotTooFarInThePast: {
        oldest_allowed: bigint;
      };
    }
  | "NoPaymentCredential"
  | {
      ExtraneousRedeemer: {
        tag: string;
        index: bigint;
      };
    }
  | {
      BuildTxContextError: {
        error: string;
      };
    }
  | {
      RedeemerIndexOutOfBounds: {
        tag: string;
        index: bigint;
        max_index?: number | null;
      };
    }
  | {
      MissingRequiredScript: {
        script_hash: string;
      };
    }
  | {
      MissingRequiredDatum: {
        datum_hash: string;
      };
    }
  | "NonScriptWithdrawal"
  | "NonScriptCredential"
  | "UnsupportedCertificateType"
  | "NoGuardrailScriptForProcedure"
  | "MissingRequiredInlineDatumOrHash"
  | {
      ScriptLookupError: {
        error: string;
      };
    };
export type Phase2Warning = {
  BudgetIsBiggerThanExpected: {
    expected_budget: ExUnits;
    actual_budget: ExUnits;
  };
};
export type RedeemerTag = "Mint" | "Spend" | "Cert" | "Propose" | "Vote" | "Reward";

export interface ValidationResult {
  errors: ValidationPhase1Error[];
  warnings: ValidationPhase1Warning[];
  phase2_errors: ValidationPhase2Error[];
  phase2_warnings: ValidationPhase2Warning[];
  eval_redeemer_results: EvalRedeemerResult[];
}
export interface ValidationPhase1Error {
  error: Phase1Error;
  error_message: string;
  locations: string[];
  hint?: string | null;
}
/**
 * The invalid input UTxO
 */
export interface TxInput {
  outputIndex: number;
  txHash: string;
}
export interface FeeDecomposition {
  txSizeFee: bigint;
  referenceScriptsFee: bigint;
  executionUnitsFee: bigint;
}
export interface Value {
  assets: MultiAsset;
  coins: number;
}
export interface MultiAsset {
  assets: ValidatorAsset[];
}
export interface ValidatorAsset {
  policy_id: string;
  asset_name: string;
  quantity: number;
}
export interface GovernanceActionId {
  txHash: number[];
  index: bigint;
}
/**
 * The invalid governance action
 */

/**
 * The expired governance action
 */

/**
 * The supplied protocol version
 */
export interface ProtocolVersion {
  major: bigint;
  minor: bigint;
}

/**
 * The governance action with zero withdrawals
 */

/**
 * Decomposition of script_data_hash computation for debugging.
 *
 *  The script_data_hash is computed as blake2b256 of concatenated bytes in a specific format.
 *  This structure provides the raw CBOR data and explains the encoding used.
 *
 *  ## script_data_hash format (Alonzo+ ledger spec):
 *
 *  Standard: `blake2b256(redeemers || datums || used_cost_models)`
 *  Datums-only: `blake2b256(0xA0 || datums || 0xA0)` (when no redeemers)
 *
 *  All components must be serialized according to the ledger CDDL specification.
 *
 *  ### Redeemers
 *  - **Pre-Conway**: array format
 *  - **Conway+**: map format
 *  - Original format from deserialization is preserved
 *
 *  ### Datums
 *  - For hash: uses CBOR set encoding (tag 258) with deduplication
 *  - May use indefinite length encoding
 *
 *  ### Cost Models
 *
 *  **Encoding rules:**
 *  - Keys sorted by **length first**, then lexicographically
 *  - **PlutusV1 special case** (cardano-node bug workaround):
 *    - Key `0` serialized as `bytes(0x00)` instead of integer
 *    - Value wrapped in bytestring containing **indefinite length array**
 *    - Format: `{ bytes(0x00): bytes(9F cost1 cost2 ... FF) }`
 *  - **PlutusV2** (key=1) and **PlutusV3** (key=2): standard integer key with array value
 */
export interface ScriptDataHashDecomposition {
  /**
   * Which encoding format was used for script_data_hash
   *  - "standard": redeemers || datums || used_cost_models
   *  - "datums_only": 0xA0 || datums || 0xA0 (when no redeemers but has datums)
   */
  encodingFormat: string;
  /**
   * Redeemers CBOR hex (serialized per CDDL, preserves original Map or Array format)
   */
  redeemersCbor?: string | null;
  /**
   * Number of redeemers
   */
  redeemersCount: number;
  /**
   * Datums CBOR hex (standard array encoding)
   *  Note: for hash computation uses set encoding (tag 258 + deduplication)
   */
  datumsCbor?: string | null;
  /**
   * Number of datums
   */
  datumsCount?: number | null;
  /**
   * Cost models CBOR hex (standard map encoding)
   */
  costModelsCbor?: string | null;
  /**
   * Plutus versions used (e.g. ["PlutusV1", "PlutusV2", "PlutusV3"])
   */
  plutusVersionsUsed: string[];
  /**
   * Description of what is actually concatenated for hashing
   */
  hashInputDescription: string;
}

export interface ValidationPhase1Warning {
  warning: Phase1Warning;
  warning_message: string;
  locations: string[];
  hint?: string | null;
}
export interface ValidationPhase2Error {
  error: Phase2Error;
  error_message: string;
  locations: string[];
  hint?: string | null;
}
export interface ExUnits {
  mem: bigint;
  steps: bigint;
}
export interface ValidationPhase2Warning {
  warning: Phase2Warning;
  warning_message: string;
  locations: string[];
  hint?: string | null;
}
export interface EvalRedeemerResult {
  tag: RedeemerTag;
  index: bigint;
  provided_ex_units: ExUnits;
  calculated_ex_units: ExUnits;
  logs: string[];
  success: boolean;
  error?: string | null;
  script_context_bytes?: string | null;
  /**
   * The mapped script context, serialized as a JSON string.
   */
  script_context?: string | null;
  /**
   * Compiled script bytecode (CBOR hex) the redeemer resolves to — witness or reference script.
   */
  script_bytes?: string | null;
  /**
   * Plutus language version of the resolved script: "V1" | "V2" | "V3".
   */
  plutus_version?: string | null;
  /**
   * Redeemer datum as PlutusData CBOR hex (the exact bytes applied to the program).
   */
  redeemer_bytes?: string | null;
  /**
   * Spending datum as PlutusData CBOR hex, when present (V1/V2 spend); None otherwise.
   */
  datum_bytes?: string | null;
}


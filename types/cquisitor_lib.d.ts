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
 * @param {string} input
 * @param {string} type_name
 * @param {any} params_json
 * @returns {any}
 */
export function decode_specific_type(input: string, type_name: string, params_json: DecodingParams): any;
/**
 * @param {string} input
 * @returns {(string)[]}
 */
export function get_possible_types_for_input(input: string): (string)[];
/**
 * @param {string} cbor_hex
 * @returns {any}
 */
/**
 * Decodes a CBOR hex string into a positional JSON tree.
 *
 * Never throws on malformed input — on failure returns
 * `{ ok: false, error: CborDecodeError, partial? }`. Structured errors
 * carry `kind`, `offset`, a `byte_span`, a semantic `path` into the
 * failing position, and a human `message`.
 *
 * When anything was successfully decoded before the failure, `partial`
 * contains the prefix tree with every un-finished container flagged
 * `incomplete: true`. Node shape otherwise matches the success value, so
 * renderers can display it the same way.
 */
export function cbor_to_json(cbor_hex: string): CborDecodeResult;

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
    | "io_error";

export interface CborDecodeError {
    kind: CborDecodeErrorKind;
    /** Human-readable message. Not stable — use `kind` for branching. */
    message: string;
    /** Semantic path into the decoded tree (e.g. `$.entries[1].value[0]`). */
    path: string;
    /** Byte offset where decoding failed. Absent only for rare IO fallbacks. */
    offset?: number;
    /** Byte range pinned by the failure, when wider than a single byte. */
    byte_span?: CborPosition;
}

/**
 * Validates a CDDL schema. Returns `{ valid: true }` if the schema parses
 * **and** every rule reference resolves; otherwise `{ valid: false, error }`.
 * Undefined rule references come back with `kind: "unresolved_references"`
 * (e.g. `thing = [unknown_rule, int]`).
 * @param {string} cddl
 * @returns {any}
 */
export function validate_cddl(cddl: string): CddlValidationResult;

/**
 * Validates CBOR bytes against a rule in the given CDDL schema. On failure
 * `error` describes the mismatch, including a semantic `path`, the byte
 * spans in the input that produced it, and (when several validation
 * errors fire) an `additional` array with the rest.
 * @param {string} cbor_hex
 * @param {string} cddl
 * @param {string} rule_name
 * @returns {any}
 */
export function validate_cbor_against_cddl(
    cbor_hex: string,
    cddl: string,
    rule_name: string
): CborValidationResult;

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

/** Outline entry — one rule from `cddl_outline`. */
export interface CddlOutlineEntry {
    /** Rule name (`transaction_body`, `set`, …). */
    name: string;
    /** `"type"` for `=`, `"group"` for `( … )`. */
    kind: "type" | "group";
    /** Byte range covering the whole `name = …` rule definition. */
    span: SourceSpan;
    /** Byte range of just the rule's name identifier. */
    name_span: SourceSpan;
}

/** Result of `cddl_symbol_at`. `null` when the cursor isn't on an identifier. */
export type CddlSymbolAtResult =
    | null
    | {
          name: string;
          kind: "type" | "group" | "rule_reference" | "prelude_or_unknown";
          role: "definition" | "use";
          span: SourceSpan;
          definition_span: SourceSpan | null;
          rule_span: SourceSpan | null;
      };

/** Result of `cddl_references`. */
export interface CddlReferencesResult {
    definition: SourceSpan | null;
    uses: SourceSpan[];
}

/**
 * Returns one entry per top-level rule (`{name, kind, span, name_span}`).
 * Used for editor outline view, breadcrumbs, fuzzy "go to rule".
 * @param cddl
 */
export function cddl_outline(cddl: string): CddlOutlineEntry[];

/**
 * Returns `{definition, uses[]}` byte ranges for the rule named `name`.
 * Powers find-references and rename-aware highlighting.
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
 * Useful for "format on save". Throws on invalid input.
 * @param cddl
 */
export function cddl_format(cddl: string): string;

/** One entry from `map_cbor_to_cddl`: a single position of a CBOR
 *  node, the type that matched it, and the path it ends up at in the
 *  output of `decode_cbor_against_cddl`.
 *
 *  ## `decoded_path` conventions
 *
 *  Every node addressable in the JSON tree returned by
 *  `decode_cbor_against_cddl` has at least one entry here — including
 *  the synthetic keys the decoder inserts when the data shape doesn't
 *  fit a plain JSON object. UI consumers can right-click any tree row
 *  and look up `entries.find(e => e.decoded_path === path)` to find
 *  the matching CBOR + CDDL spans.
 *
 *  Synthetic-key paths:
 *
 *  * `<wrapper>["@tag"]` — the tag-number row of an unspecialised
 *    tagged value (decoder represents these as `{@tag, @value}`).
 *    `cbor_byte_span` covers just the tag header bytes (`d9 0102`,
 *    not the whole `Tag(258, …)` extent); `cddl_byte_span` covers the
 *    `#6.NNN(...)` form. Tags 0/2/3 are specialised to scalars and
 *    don't get this row.
 *  * `<wrapper>["@value"]` — the inner value of an unspecialised tag.
 *    Resolves to the inner type's CDDL location.
 *  * `<arr>["@positional"]` — wrapper row over the unlabelled slots
 *    of a mixed (labelled + unlabelled) tuple. No `cddl_byte_span`.
 *    `cbor_byte_span` / `cbor_anchor_span` cover the unlabelled items'
 *    combined byte extent.
 *  * `<arr>["@positional"][N]` — individual unlabelled slot at array
 *    index N (kept under `@positional` because the named slots
 *    occupy the object level).
 *  * `<arr>["@extra"]` — wrapper row over array items past the schema
 *    cursor (overlong arrays). No `cddl_byte_span`. `<arr>["@extra"][N]`
 *    addresses each leftover item.
 *  * `<map>["@extra"]` — wrapper row over map keys not declared in
 *    the schema (object form only). `<map>["@extra"][<key>]`
 *    addresses each leftover entry's value.
 *  * `<map>["@entries"]` — wrapper row over the wire-order array form
 *    used when the map has complex keys or duplicate keys (see
 *    `decode_cbor_against_cddl` docs). No `cddl_byte_span`.
 *  * `<map>["@entries"][N]` — each pair as a single addressable row
 *    (covers key+value bytes, `cbor_type: "map_entry"`, `cddl_byte_span`
 *    = matched MemberKey's declaration if any).
 *  * `<map>["@entries"][N]["key"]` — key bytes of the Nth pair.
 *    `entry_role: "key"`.
 *  * `<map>["@entries"][N]["value"]` — value bytes of the Nth pair,
 *    plus deeper rows under it walking the matched member's value
 *    type.
 *
 *  Wrapper rows (`@entries`, `@positional`, `@extra`) carry a
 *  `cbor_type` like `"map_entries"` / `"array_positional"` /
 *  `"map_extra"` / `"array_extra"` and intentionally omit
 *  `cddl_byte_span` — they are JSON-shape artefacts with no CDDL
 *  counterpart. */
export interface CborCddlMapEntry {
    /** Path into the *raw* CBOR tree (numeric map keys are bracketed). */
    cbor_path: string;
    /** Path into the labelled JSON returned by `decode_cbor_against_cddl`.
     *  Numeric map keys come back as bracket-quoted strings (`["0"]`)
     *  because decoded JSON has only string keys; identifier-safe keys
     *  use dot notation (`.name`). For unspecialised tags (anything
     *  except 0 / 2 / 3) the inner gets an extra `["@value"]` segment
     *  to match the `{@tag, @value}` wrapper the decoder emits.
     *
     *  See the interface comment for the full list of synthetic-key
     *  segments (`@tag`, `@value`, `@positional`, `@extra`, `@entries`). */
    decoded_path: string;
    /** Whether this entry describes the value at `cbor_path`, or the
     *  *key* of a map entry at that path. Map entries with named keys
     *  produce both a `"key"` entry (CBOR span = key bytes, CDDL span
     *  = `name:` / `<value>:` declaration) and a `"value"` entry; both
     *  carry the same `cbor_path` / `decoded_path`. Array slots, tag
     *  payloads, and root nodes are always `"value"`. */
    entry_role: "key" | "value";
    /** Header byte range of the CBOR node. */
    cbor_byte_span: { offset: number; length: number };
    /** Whole-structure byte range (= `cbor_byte_span` for scalars). */
    cbor_anchor_span: { offset: number; length: number };
    /** Byte range in the CDDL source describing this position. Omitted
     *  on synthetic wrapper rows (`@entries`, `@positional`, `@extra`)
     *  which have no CDDL counterpart. */
    cddl_byte_span?: SourceSpan;
    /** Name of the CDDL rule that matched, if a rule boundary was crossed. */
    rule_name?: string;
    /** CBOR node's wire type (`U8`, `Bytes`, `Map`, `Array`, `Tag`, …),
     *  or — for synthetic wrapper rows — a label describing the
     *  wrapper's role: `"map_entries"`, `"map_extra"`,
     *  `"array_positional"`, `"array_extra"`, `"map_entry"` (per-pair
     *  row in `@entries` form). */
    cbor_type?: string;
}

/**
 * Returns a flat list of mapping entries pairing each visited CBOR node
 * with the CDDL position that describes it. Use it to wire
 * bidirectional highlight between a CBOR panel and a CDDL panel without
 * needing a validation error to trigger it.
 *
 * Order is depth-first pre-order, so a parent's entry precedes its
 * children's. Tags in the CBOR are transparent to the path grammar
 * (anweiss-style): `Tag(258, [...])` is walked as if the tag wrapper
 * weren't there when matching against `[* a]`-shaped schemas.
 *
 * @param cbor_hex
 * @param cddl
 * @param rule_name
 */
export function map_cbor_to_cddl(
    cbor_hex: string,
    cddl: string,
    rule_name: string
): CborCddlMapEntry[];

/**
 * Maps decoded CBOR onto a CDDL schema and returns labelled JSON. Where
 * `cbor_to_json` returns positional CBOR (numeric map keys, raw arrays),
 * this walks the schema in parallel and replaces them with the named
 * fields the CDDL declares — turning Cardano shapes like
 * `[transaction_body, transaction_witness_set, bool, ...]` into
 * `{transaction_body: {...}, transaction_witness_set: {...}, ...}`.
 *
 * Sub-structures the schema doesn't cover fall back to a raw
 * representation (under `@extra` for maps / `@positional` for arrays),
 * so partial matches still yield useful output.
 *
 * **Map output shape**: by default we emit JSON objects (`{a: 1, b: 2}`)
 * for the convenient case. We switch to a wire-order-preserving array
 * form `{ "@entries": [{ key, value, match: { via, label } }, ...] }`
 * when the JSON object form would lose information:
 *
 *  * any cbor key is a complex value (Array / Map / Tag / non-standard
 *    Simple) — JSON objects can only have string keys.
 *  * the cbor map has duplicate keys (RFC 8949 §5.6 — non-canonical
 *    but legal). Collapsing into a value-array would drop the
 *    interleaving order with surrounding entries.
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
 * @param {string} cbor_hex
 * @param {string} cddl
 * @param {string} rule_name
 * @returns {any}
 */
export function decode_cbor_against_cddl(
    cbor_hex: string,
    cddl: string,
    rule_name: string
): unknown;

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

export interface CddlErrorInfo {
    kind: string;
    message: string;
    /**
     * Byte range in the CDDL source the parser tripped over, when the
     * error has positional info. Useful for IDE squiggly underlines.
     */
    byte_span?: SourceSpan;
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
 *  - "input_parse" — the CBOR bytes themselves are malformed
 *  - "mismatch" / "map_cut" — a data mismatch; inspect `expected`, `path`,
 *    `byte_spans`, and `anchor_spans` for precise locations
 *  - "generic" — anything that didn't fit one of the buckets above
 */
export interface CborValidationErrorInfo {
    kind: string;
    message: string;
    expected?: string;
    /** Semantic path into the CBOR (e.g. `$.b[0]`). */
    path?: string;
    /** Byte range in the CBOR input that triggered the error. */
    byte_spans?: CborPosition[];
    /** Byte range covering the whole containing CBOR structure. */
    anchor_spans?: CborPosition[];
    /**
     * Byte range in the CDDL **source** pointing at the type the
     * validator tried to apply when it failed (synthesised by walking
     * the AST in parallel with `path`). Useful for highlighting the
     * offending CDDL rule in editors.
     */
    cddl_byte_span?: SourceSpan;
    /** Other validation errors reported in the same run. */
    additional?: CborValidationErrorInfo[];
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
  accounts: string[];
  committeeMembersCold: LocalCredential[];
  committeeMembersHot: LocalCredential[];
  dReps: string[];
  govActions: GovernanceActionId[];
  lastEnactedGovAction: GovernanceActionType[];
  pools: string[];
  utxos: TxInput[];
}

export type SerializableScriptContext =
  | {
      purpose: SerializableScriptPurpose;
      script_context_version: "V1V2";
      tx_info: SerializableTxInfo;
    }
  | {
      purpose: SerializableScriptInfo;
      redeemer: SerializablePlutusData;
      script_context_version: "V3";
      tx_info: SerializableTxInfo;
    };
export type SerializableScriptPurpose =
  | {
      policy_id: string;
      purpose_type: "Minting";
    }
  | {
      purpose_type: "Spending";
      utxo_ref: SerializableTransactionInput;
    }
  | {
      purpose_type: "Rewarding";
      stake_credential: SerializableStakeCredential;
    }
  | {
      certificate: SerializableCertificate;
      index: bigint;
      purpose_type: "Certifying";
    }
  | {
      purpose_type: "Voting";
      voter: SerializableVoter;
    }
  | {
      index: bigint;
      proposal: SerializableProposalProcedure;
      purpose_type: "Proposing";
    };
export type SerializableStakeCredential =
  | {
      credential_type: "KeyHash";
      hash: string;
    }
  | {
      credential_type: "ScriptHash";
      hash: string;
    };
export type SerializableCertificate =
  | {
      certificate_type: "StakeRegistration";
      stake_credential: SerializableStakeCredential;
    }
  | {
      certificate_type: "StakeDeregistration";
      stake_credential: SerializableStakeCredential;
    }
  | {
      certificate_type: "StakeDelegation";
      pool_keyhash: string;
      stake_credential: SerializableStakeCredential;
    }
  | {
      certificate_type: "PoolRegistration";
      pool_params: SerializablePoolParams;
    }
  | {
      certificate_type: "PoolRetirement";
      epoch: bigint;
      pool_keyhash: string;
    }
  | {
      certificate_type: "Reg";
      deposit: bigint;
      stake_credential: SerializableStakeCredential;
    }
  | {
      certificate_type: "UnReg";
      refund: bigint;
      stake_credential: SerializableStakeCredential;
    }
  | {
      certificate_type: "VoteDeleg";
      drep: SerializableDRep;
      stake_credential: SerializableStakeCredential;
    }
  | {
      certificate_type: "StakeVoteDeleg";
      drep: SerializableDRep;
      pool_keyhash: string;
      stake_credential: SerializableStakeCredential;
    }
  | {
      certificate_type: "StakeRegDeleg";
      deposit: bigint;
      pool_keyhash: string;
      stake_credential: SerializableStakeCredential;
    }
  | {
      certificate_type: "VoteRegDeleg";
      deposit: bigint;
      drep: SerializableDRep;
      stake_credential: SerializableStakeCredential;
    }
  | {
      certificate_type: "StakeVoteRegDeleg";
      deposit: bigint;
      drep: SerializableDRep;
      pool_keyhash: string;
      stake_credential: SerializableStakeCredential;
    }
  | {
      certificate_type: "AuthCommitteeHot";
      committee_cold_credential: SerializableStakeCredential;
      committee_hot_credential: SerializableStakeCredential;
    }
  | {
      anchor?: SerializableAnchor | null;
      certificate_type: "ResignCommitteeCold";
      committee_cold_credential: SerializableStakeCredential;
    }
  | {
      anchor?: SerializableAnchor | null;
      certificate_type: "RegDRepCert";
      deposit: bigint;
      drep_credential: SerializableStakeCredential;
    }
  | {
      certificate_type: "UnRegDRepCert";
      drep_credential: SerializableStakeCredential;
      refund: bigint;
    }
  | {
      anchor?: SerializableAnchor | null;
      certificate_type: "UpdateDRepCert";
      drep_credential: SerializableStakeCredential;
    };
export type SerializableRelay =
  | {
      ipv4?: string | null;
      ipv6?: string | null;
      port?: number | null;
      relay_type: "SingleHostAddr";
    }
  | {
      hostname: string;
      port?: number | null;
      relay_type: "SingleHostName";
    }
  | {
      hostname: string;
      relay_type: "MultiHostName";
    };
export type SerializableDRep =
  | {
      drep_type: "Key";
      hash: string;
    }
  | {
      drep_type: "Script";
      hash: string;
    }
  | {
      drep_type: "Abstain";
    }
  | {
      drep_type: "NoConfidence";
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
export type SerializableGovAction =
  | {
      action_type: "ParameterChange";
      gov_action_id?: SerializableGovActionId | null;
      policy_hash?: string | null;
      protocol_params_update: SerializableProtocolParamsUpdate;
    }
  | {
      action_type: "HardForkInitiation";
      gov_action_id?: SerializableGovActionId | null;
      protocol_version: ProtocolVersion;
    }
  | {
      action_type: "TreasuryWithdrawals";
      policy_hash?: string | null;
      withdrawals: [unknown, unknown][];
    }
  | {
      action_type: "NoConfidence";
      gov_action_id?: SerializableGovActionId | null;
    }
  | {
      action_type: "UpdateCommittee";
      gov_action_id?: SerializableGovActionId | null;
      members_to_add: [unknown, unknown][];
      members_to_remove: SerializableStakeCredential[];
      quorum_threshold: SubCoin;
    }
  | {
      action_type: "NewConstitution";
      constitution: SerializableConstitution;
      gov_action_id?: SerializableGovActionId | null;
    }
  | {
      action_type: "Information";
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
export type SerializableCardanoValue =
  | {
      amount: bigint;
      value_type: "Coin";
    }
  | {
      assets: SerializableAsset[];
      coin: bigint;
      value_type: "Multiasset";
    };
export type SerializableTransactionOutput =
  | {
      address: string;
      datum_hash?: string | null;
      output_format: "Legacy";
      value: SerializableCardanoValue;
    }
  | {
      address: string;
      datum_option?: SerializableDatumOption | null;
      output_format: "PostAlonzo";
      script_ref?: SerializableScriptRef | null;
      value: SerializableCardanoValue;
    };
export type SerializableDatumOption =
  | {
      datum_type: "Hash";
      hash: string;
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
      any_constructor?: number | null;
      fields: SerializablePlutusData[];
      tag: bigint;
      type: "Constr";
    }
  | {
      key_value_pairs: SerializableKeyValuePair[];
      type: "Map";
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
export type SerializableScriptInfo =
  | {
      policy_id: string;
      script_info_type: "Minting";
    }
  | {
      datum?: SerializablePlutusData | null;
      script_info_type: "Spending";
      utxo_ref: SerializableTransactionInput;
    }
  | {
      script_info_type: "Rewarding";
      stake_credential: SerializableStakeCredential;
    }
  | {
      certificate: SerializableCertificate;
      index: bigint;
      script_info_type: "Certifying";
    }
  | {
      script_info_type: "Voting";
      voter: SerializableVoter;
    }
  | {
      index: bigint;
      proposal: SerializableProposalProcedure;
      script_info_type: "Proposing";
    };

export interface SerializableTransactionInput {
  index: bigint;
  transaction_id: string;
}
export interface SerializablePoolParams {
  cost: bigint;
  margin: SubCoin;
  operator: string;
  pledge: bigint;
  pool_metadata?: SerializablePoolMetadata | null;
  pool_owners: string[];
  relays: SerializableRelay[];
  reward_account: string;
  vrf_keyhash: string;
}

export interface SerializablePoolMetadata {
  hash: string;
  url: string;
}
export interface SerializableAnchor {
  data_hash: string;
  url: string;
}
export interface SerializableProposalProcedure {
  anchor: SerializableAnchor;
  deposit: bigint;
  gov_action: SerializableGovAction;
  reward_account: string;
}
export interface SerializableGovActionId {
  action_index: number;
  transaction_id: string;
}
export interface SerializableProtocolParamsUpdate {
  ada_per_utxo_byte?: number | null;
  collateral_percentage?: number | null;
  committee_term_limit?: number | null;
  cost_models_for_script_languages?: SerializableCostModels | null;
  desired_number_of_stake_pools?: number | null;
  drep_deposit?: number | null;
  drep_inactivity_period?: number | null;
  drep_voting_thresholds?: SerializableDRepVotingThresholds | null;
  execution_costs?: SerializableExUnitPrices | null;
  expansion_rate?: SubCoin | null;
  governance_action_deposit?: number | null;
  governance_action_validity_period?: number | null;
  key_deposit?: number | null;
  max_block_body_size?: number | null;
  max_block_ex_units?: ExUnits | null;
  max_block_header_size?: number | null;
  max_collateral_inputs?: number | null;
  max_transaction_size?: number | null;
  max_tx_ex_units?: ExUnits | null;
  max_value_size?: number | null;
  maximum_epoch?: number | null;
  min_committee_size?: number | null;
  min_pool_cost?: number | null;
  minfee_a?: number | null;
  minfee_b?: number | null;
  minfee_refscript_cost_per_byte?: SubCoin | null;
  pool_deposit?: number | null;
  pool_pledge_influence?: SubCoin | null;
  pool_voting_thresholds?: SerializablePoolVotingThresholds | null;
  treasury_growth_rate?: SubCoin | null;
}
export interface SerializableCostModels {
  plutus_v1?: number[] | null;
  plutus_v2?: number[] | null;
  plutus_v3?: number[] | null;
}
export interface SerializableDRepVotingThresholds {
  committee_no_confidence: SubCoin;
  committee_normal: SubCoin;
  hard_fork_initiation: SubCoin;
  motion_no_confidence: SubCoin;
  pp_economic_group: SubCoin;
  pp_governance_group: SubCoin;
  pp_network_group: SubCoin;
  pp_technical_group: SubCoin;
  treasury_withdrawal: SubCoin;
  update_constitution: SubCoin;
}
export interface SerializableExUnitPrices {
  mem_price: SubCoin;
  step_price: SubCoin;
}

export interface SerializablePoolVotingThresholds {
  committee_no_confidence: SubCoin;
  committee_normal: SubCoin;
  hard_fork_initiation: SubCoin;
  motion_no_confidence: SubCoin;
  security_voting_threshold: SubCoin;
}

export interface SerializableConstitution {
  anchor: SerializableAnchor;
  guardrail_script?: string | null;
}
export interface SerializableTxInfoV1 {
  certificates: SerializableCertificate[];
  data: [unknown, unknown][];
  fee: SerializableCardanoValue;
  id: string;
  inputs: SerializableTxInInfo[];
  mint: SerializableMintValue;
  outputs: SerializableTransactionOutput[];
  redeemers: [unknown, unknown][];
  signatories: string[];
  valid_range: SerializableTimeRange;
  withdrawals: [unknown, unknown][];
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
export interface SerializableTxInInfo {
  out_ref: SerializableTransactionInput;
  resolved: SerializableTransactionOutput;
}
export interface SerializableKeyValuePair {
  key: SerializablePlutusData;
  value: SerializablePlutusData;
}
export interface SerializableMintValue {
  mint_value: SerializableAsset[];
}
export interface SerializableTimeRange {
  lower_bound?: number | null;
  upper_bound?: number | null;
}
export interface SerializableTxInfoV2 {
  certificates: SerializableCertificate[];
  data: [unknown, unknown][];
  fee: SerializableCardanoValue;
  id: string;
  inputs: SerializableTxInInfo[];
  mint: SerializableMintValue;
  outputs: SerializableTransactionOutput[];
  redeemers: [unknown, unknown][];
  reference_inputs: SerializableTxInInfo[];
  signatories: string[];
  valid_range: SerializableTimeRange;
  withdrawals: [unknown, unknown][];
}
export interface SerializableTxInfoV3 {
  certificates: SerializableCertificate[];
  current_treasury_amount?: number | null;
  data: [unknown, unknown][];
  fee: bigint;
  id: string;
  inputs: SerializableTxInInfo[];
  mint: SerializableMintValue;
  outputs: SerializableTransactionOutput[];
  proposal_procedures: SerializableProposalProcedure[];
  redeemers: [unknown, unknown][];
  reference_inputs: SerializableTxInInfo[];
  signatories: string[];
  treasury_donation?: number | null;
  valid_range: SerializableTimeRange;
  votes: [unknown, unknown][];
  withdrawals: [unknown, unknown][];
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
  accountContexts: AccountInputContext[];
  currentCommitteeMembers: CommitteeInputContext[];
  drepContexts: DrepInputContext[];
  govActionContexts: GovActionInputContext[];
  lastEnactedGovAction: GovActionInputContext[];
  networkType: NetworkType;
  poolContexts: PoolInputContext[];
  potentialCommitteeMembers: CommitteeInputContext[];
  protocolParameters: ProtocolParameters;
  slot: bigint;
  treasuryValue: bigint;
  utxoSet: UtxoInputContext[];
}
export interface AccountInputContext {
  balance?: number | null;
  bech32Address: string;
  delegatedToDrep?: string | null;
  delegatedToPool?: string | null;
  isRegistered: boolean;
  payedDeposit?: number | null;
}
export interface CommitteeInputContext {
  committeeMemberCold: LocalCredential;
  committeeMemberHot?: LocalCredential | null;
  isResigned: boolean;
}
export interface DrepInputContext {
  bech32Drep: string;
  isRegistered: boolean;
  payedDeposit?: number | null;
}
export interface GovActionInputContext {
  actionId: GovernanceActionId;
  actionType: GovernanceActionType;
  isActive: boolean;
}

export interface PoolInputContext {
  isRegistered: boolean;
  poolId: string;
  retirementEpoch?: number | null;
}
export interface ProtocolParameters {
  /**
   * Cost per UTxO byte in lovelace
   */
  adaPerUtxoByte: bigint;
  /**
   * Percentage of transaction fee required as collateral
   */
  collateralPercentage: number;
  costModels: CostModels;
  /**
   * Deposit amount required for registering as a DRep
   */
  drepDeposit: bigint;
  executionPrices: ExUnitPrices;
  /**
   * Deposit amount required for submitting a governance action
   */
  governanceActionDeposit: bigint;
  /**
   * Maximum block body size in bytes
   */
  maxBlockBodySize: number;
  maxBlockExecutionUnits: ExUnits;
  /**
   * Maximum block header size in bytes
   */
  maxBlockHeaderSize: number;
  /**
   * Maximum number of collateral inputs
   */
  maxCollateralInputs: number;
  /**
   * Maximum number of epochs that can be used for pool retirement ahead
   */
  maxEpochForPoolRetirement: number;
  /**
   * Maximum transaction size in bytes
   */
  maxTransactionSize: number;
  maxTxExecutionUnits: ExUnits;
  /**
   * Maximum size of a Value in bytes
   */
  maxValueSize: number;
  /**
   * Linear factor for the minimum fee calculation formula
   */
  minFeeCoefficientA: bigint;
  /**
   * Constant factor for the minimum fee calculation formula
   */
  minFeeConstantB: bigint;
  /**
   * Minimum pool cost in lovelace
   */
  minPoolCost: bigint;
  /**
   * Protocol version (major, minor)
   *
   * @minItems 2
   * @maxItems 2
   */
  protocolVersion: [unknown, unknown];
  referenceScriptCostPerByte: SubCoin;
  /**
   * Deposit amount required for registering a stake key
   */
  stakeKeyDeposit: bigint;
  /**
   * Deposit amount required for registering a stake pool
   */
  stakePoolDeposit: bigint;
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
  denominator: bigint;
  numerator: bigint;
}
/**
 * Maximum execution units allowed for a block
 */

/**
 * Maximum execution units allowed for a transaction
 */

/**
 * Coins per byte for reference scripts
 */

export interface UtxoInputContext {
  isSpent: boolean;
  utxo: UTxO;
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
  scriptHash?: string | null;
  scriptRef?: string | null;
}
export interface Asset {
  quantity: string;
  unit: string;
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
        interval_end: bigint;
        interval_start: bigint;
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
        fee_decomposition: FeeDecomposition;
        min_fee: bigint;
      };
    }
  | {
      ValueNotConservedUTxO: {
        difference: Value;
        input_sum: Value;
        output_sum: Value;
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
        min_amount: number;
        output_amount: number;
      };
    }
  | {
      CollateralReturnTooSmall: {
        min_amount: number;
        output_amount: number;
      };
    }
  | {
      OutputBootAddrAttrsTooBig: {
        actual_size: bigint;
        max_size: bigint;
        output: unknown;
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
        required_collateral: number;
        total_collateral: number;
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
        actual_sum: number;
        declared_total: number;
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
        index: bigint;
        tag: string;
      };
    }
  | "MissingTxBodyMetadataHash"
  | "MissingTxMetadata"
  | {
      ConflictingMetadataHash: {
        actual_hash: string;
        expected_hash: string;
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
        remaining_balance: bigint;
        reward_address: string;
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
        current_epoch: bigint;
        max_epoch: bigint;
        min_epoch: bigint;
        specified_epoch: bigint;
      };
    }
  | {
      StakePoolCostTooLow: {
        min_cost: bigint;
        specified_cost: bigint;
      };
    }
  | {
      InsufficientFundsForMir: {
        available_amount: bigint;
        requested_amount: bigint;
      };
    }
  | {
      InvalidCommitteeVote: {
        message: string;
        voter: unknown;
      };
    }
  | {
      DRepIncorrectDeposit: {
        required_deposit: number;
        supplied_deposit: number;
      };
    }
  | {
      DRepDeregistrationWrongRefund: {
        required_refund: number;
        supplied_refund: number;
      };
    }
  | {
      DelegateeDRepNotRegistered: {
        cert_index: number;
        drep_id: string;
      };
    }
  | {
      StakeRegistrationWrongDeposit: {
        required_deposit: number;
        supplied_deposit: number;
      };
    }
  | {
      StakeDeregistrationWrongRefund: {
        required_refund: number;
        supplied_refund: number;
      };
    }
  | {
      PoolRegistrationWrongDeposit: {
        required_deposit: number;
        supplied_deposit: number;
      };
    }
  | {
      CommitteeHasPreviouslyResigned: {
        committee_credential: LocalCredential;
      };
    }
  | {
      TreasuryValueMismatch: {
        actual_value: bigint;
        declared_value: bigint;
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
         * The expected network ID
         */
        expected_network: number;
        /**
         * The reward account
         */
        reward_account: string;
      };
    }
  | {
      TreasuryWithdrawalsNetworkIdMismatch: {
        /**
         * The expected network ID
         */
        expected_network: number;
        /**
         * The set of mismatched reward accounts
         */
        mismatched_account: string;
      };
    }
  | {
      VotingProposalIncorrectDeposit: {
        proposal_index: number;
        /**
         * The required deposit amount
         */
        required_deposit: number;
        /**
         * The supplied deposit amount
         */
        supplied_deposit: number;
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
         * The expected protocol version
         */
        expected_versions: ProtocolVersion[];
        /**
         * Previous governance action ID
         */
        prev_gov_action_id?: GovernanceActionId | null;
        supplied_version: ProtocolVersion;
      };
    }
  | {
      InvalidConstitutionPolicyHash: {
        /**
         * The expected policy hash
         */
        expected_hash?: string | null;
        /**
         * The supplied policy hash
         */
        supplied_hash?: string | null;
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
         * The actual auxiliary data hash
         */
        actual_hash?: string | null;
        /**
         * The expected auxiliary data hash
         */
        expected_hash: string;
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
         * Decomposition of the expected hash computation
         */
        expected_decomposition?: ScriptDataHashDecomposition | null;
        /**
         * The expected script data hash (computed from witness set)
         */
        expected_hash?: string | null;
        /**
         * The provided script data hash (from transaction body)
         */
        provided_hash?: string | null;
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
export type RedeemerTag = "Mint" | "Spend" | "Cert" | "Propose" | "Vote" | "Reward";
/**
 * Phase 1 validation errors
 */
export type Phase2Error =
  | "NativeScriptIsReferencedByRedeemer"
  | {
      NoEnoughBudget: {
        actual_budget: ExUnits;
        expected_budget: ExUnits;
      };
    }
  | {
      InvalidRedeemerIndex: {
        index: bigint;
        tag: string;
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
        index: bigint;
        tag: string;
      };
    }
  | {
      BuildTxContextError: {
        error: string;
      };
    }
  | {
      RedeemerIndexOutOfBounds: {
        index: bigint;
        max_index?: number | null;
        tag: string;
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
    actual_budget: ExUnits;
    expected_budget: ExUnits;
  };
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
        fee_decomposition: FeeDecomposition;
        min_fee: bigint;
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
        cert_index: number;
        pool_id: string;
      };
    }
  | {
      DuplicateRegistrationInTx: {
        cert_index: number;
        entity_id: string;
        entity_type: string;
      };
    }
  | {
      DuplicateCommitteeColdResignationInTx: {
        cert_index: number;
        committee_credential: LocalCredential;
      };
    }
  | {
      DuplicateCommitteeHotRegistrationInTx: {
        cert_index: number;
        committee_credential: LocalCredential;
      };
    };

export interface ValidationResult {
  errors: ValidationPhase1Error[];
  eval_redeemer_results: EvalRedeemerResult[];
  phase2_errors: ValidationPhase2Error[];
  phase2_warnings: ValidationPhase2Warning[];
  warnings: ValidationPhase1Warning[];
}
export interface ValidationPhase1Error {
  error: Phase1Error;
  error_message: string;
  hint?: string | null;
  locations: string[];
}
/**
 * The invalid input UTxO
 */
export interface TxInput {
  outputIndex: number;
  txHash: string;
}
export interface FeeDecomposition {
  executionUnitsFee: bigint;
  referenceScriptsFee: bigint;
  txSizeFee: bigint;
}
export interface Value {
  assets: MultiAsset;
  coins: number;
}
export interface MultiAsset {
  assets: ValidatorAsset[];
}
export interface ValidatorAsset {
  asset_name: string;
  policy_id: string;
  quantity: number;
}
export interface GovernanceActionId {
  index: bigint;
  txHash: number[];
}
/**
 * The invalid governance action
 */

/**
 * The expired governance action
 */

export interface ProtocolVersion {
  major: bigint;
  minor: bigint;
}
/**
 * The supplied protocol version
 */

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
   * Cost models CBOR hex (standard map encoding)
   */
  costModelsCbor?: string | null;
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
   * Which encoding format was used for script_data_hash
   *  - "standard": redeemers || datums || used_cost_models
   *  - "datums_only": 0xA0 || datums || 0xA0 (when no redeemers but has datums)
   */
  encodingFormat: string;
  /**
   * Description of what is actually concatenated for hashing
   */
  hashInputDescription: string;
  /**
   * Plutus versions used (e.g. ["PlutusV1", "PlutusV2", "PlutusV3"])
   */
  plutusVersionsUsed: string[];
  /**
   * Redeemers CBOR hex (serialized per CDDL, preserves original Map or Array format)
   */
  redeemersCbor?: string | null;
  /**
   * Number of redeemers
   */
  redeemersCount: number;
}

export interface EvalRedeemerResult {
  calculated_ex_units: ExUnits;
  error?: string | null;
  index: bigint;
  logs: string[];
  provided_ex_units: ExUnits;
  /**
   * The mapped script context, serialized as a JSON string.
   */
  script_context?: string | null;
  script_context_bytes?: string | null;
  success: boolean;
  tag: RedeemerTag;
}
export interface ExUnits {
  mem: bigint;
  steps: bigint;
}
export interface ValidationPhase2Error {
  error: Phase2Error;
  error_message: string;
  hint?: string | null;
  locations: string[];
}
export interface ValidationPhase2Warning {
  hint?: string | null;
  locations: string[];
  warning: Phase2Warning;
  warning_message: string;
}
export interface ValidationPhase1Warning {
  hint?: string | null;
  locations: string[];
  warning: Phase1Warning;
  warning_message: string;
}


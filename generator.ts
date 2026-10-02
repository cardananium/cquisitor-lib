#!/usr/bin/env -S npx ts-node
//
// Regenerates src/csl_decoders/universal_decoder.rs.
//
// Discovers every CSL class with a static `from_hex` / `from_bech32` /
// `from_bytes` / `from_base58` (plus a fixed list of custom-dispatched types)
// by *parsing* @emurgo/cardano-serialization-lib-browser's .d.ts file — we do
// not import the package at runtime because it has no ESM entry point.
//
// Emits a HashMap-based dispatch so `get_decodable_types`,
// `decode_specific_type`, and `get_possible_types_for_input` all read from a
// single `BTreeMap<&'static str, DecoderFn>`. Adding a new custom case means
// editing one list (`CUSTOM_DISPATCH` below) — the generator keeps all three
// public functions in sync.

import fs from 'fs';
import path from 'path';

const CSL_DTS_PATH = path.join(
    'node_modules',
    '@emurgo',
    'cardano-serialization-lib-browser',
    'cardano_serialization_lib.d.ts'
);
const OUTPUT_PATH = path.join('src', 'csl_decoders', 'universal_decoder.rs');

// ---------------------------------------------------------------------------
// Per-type overrides
// ---------------------------------------------------------------------------

/**
 * Types that dispatch to a hand-written function in `specific_decoders.rs`
 * instead of using the standard from_hex → to_json template. The shim name is
 * emitted once; `typeNames` lists every type_name string that routes to it.
 */
type CustomDispatch = {
    shim: string;
    specificDecoder: string;
    typeNames: string[];
    extraArgs?: string; // e.g. "params.plutus_script_version"
};

const CUSTOM_DISPATCH: CustomDispatch[] = [
    {
        shim: 'decode_address_shim',
        specificDecoder: 'decode_address',
        typeNames: [
            'Address',
            'BaseAddress',
            'ByronAddress',
            'EnterpriseAddress',
            'PointerAddress',
            'RewardAddress',
        ],
    },
    {
        shim: 'decode_transaction_shim',
        specificDecoder: 'decode_transaction',
        typeNames: ['Transaction'],
    },
    {
        shim: 'decode_native_script_shim',
        specificDecoder: 'decode_native_script',
        typeNames: ['NativeScript'],
    },
    {
        shim: 'decode_plutus_data_shim',
        specificDecoder: 'decode_plutus_data',
        typeNames: ['PlutusData'],
        extraArgs: 'params.plutus_data_schema.clone()',
    },
    {
        shim: 'decode_plutus_script_shim',
        specificDecoder: 'decode_plutus_script',
        typeNames: ['PlutusScript'],
        extraArgs: 'params.plutus_script_version',
    },
];

/**
 * CSL classes whose generated code would not compile — either generated wasm
 * wrappers without the from_* methods we expect, or overlapping with fixed-*
 * variants we deliberately never expose via the universal decoder.
 *
 * Also lists degenerate sub-shapes of PlutusData: a top-level Constr / list /
 * map is already fully decodable (with a proper to_json tree) as `PlutusData`.
 * These classes lack `to_json`, so they only ever produced a stub
 * `{"hex": ...}` echo of the input and — because they parse any matching
 * top-level shape — hijacked autodetection away from `PlutusData`.
 */
const IGNORE_TYPES = new Set<string>([
    'FixedBlock',
    'FixedTransaction',
    'FixedTransactionBodies',
    'FixedTransactionBody',
    'FixedVersionedBlock',
    'FixedTxWitnessesSet',
    'ConstrPlutusData',
    'PlutusList',
    'PlutusMap',
]);

/**
 * Types whose `to_bech32()` takes no argument and returns a String directly
 * (not `Result<String, _>` requiring a prefix).
 */
const TYPES_WITH_SIMPLE_BECH32 = new Set<string>([
    'Bip32PrivateKey',
    'Bip32PublicKey',
    'Ed25519Signature',
    'PrivateKey',
    'PublicKey',
    'PlutusData',
]);

/**
 * Types whose `from_bytes` takes `&[u8]` rather than `Vec<u8>`.
 */
const TYPES_WITH_BYTES_REF = new Set<string>([
    'Bip32PrivateKey',
    'Bip32PublicKey',
    'PublicKey',
    'LegacyDaedalusPrivateKey',
]);

/**
 * CIP-5 bech32 prefix of the hash / verification-key types whose
 * `to_bech32(prefix)` needs one: every such type CIP-5 names a prefix for.
 * The other types of this kind (block, transaction, genesis, anchor,
 * auxiliary-data and pool-metadata hashes) have no CIP-5 prefix and decode
 * to `{hex}` alone (an empty prefix is an encoding error, not a value).
 */
const HASH_BECH32_PREFIX: Record<string, string> = {
    Ed25519KeyHash: 'addr_vkh',
    ScriptHash: 'script',
    VRFKeyHash: 'vrf_vkh',
    DataHash: 'datum',
    ScriptDataHash: 'script_data',
    KESVKey: 'kes_vk',
    VRFVKey: 'vrf_vk',
};

// ---------------------------------------------------------------------------
// CSL .d.ts parsing
// ---------------------------------------------------------------------------

interface ClassMethods {
    from_hex: boolean;
    from_bech32: boolean;
    from_bytes: boolean;
    from_base58: boolean;
    to_json: boolean;
    to_hex: boolean;
    to_bech32: boolean;
}

function parseCslDts(dtsText: string): Map<string, ClassMethods> {
    const result = new Map<string, ClassMethods>();
    const classRegex = /^export class (\w+)(?:\s+extends\s+\w+)?\s*\{([\s\S]*?)^\}/gm;
    for (const match of dtsText.matchAll(classRegex)) {
        const [, className, body] = match;
        result.set(className, {
            from_hex: /^\s*static\s+from_hex\s*\(/m.test(body),
            from_bech32: /^\s*static\s+from_bech32\s*\(/m.test(body),
            from_bytes: /^\s*static\s+from_bytes\s*\(/m.test(body),
            from_base58: /^\s*static\s+from_base58\s*\(/m.test(body),
            to_json: /^\s*to_json\s*\(/m.test(body),
            to_hex: /^\s*to_hex\s*\(/m.test(body),
            to_bech32: /^\s*to_bech32\s*\(/m.test(body),
        });
    }
    return result;
}

function collectCandidateTypes(methodsByClass: Map<string, ClassMethods>): string[] {
    const candidates = new Set<string>();
    for (const [name, m] of methodsByClass) {
        if (IGNORE_TYPES.has(name)) continue;
        if (m.from_hex || m.from_bech32 || m.from_bytes || m.from_base58) {
            candidates.add(name);
        }
    }
    // Always include types in CUSTOM_DISPATCH even if we missed them in parsing
    for (const entry of CUSTOM_DISPATCH) {
        for (const t of entry.typeNames) candidates.add(t);
    }
    for (const ignored of IGNORE_TYPES) candidates.delete(ignored);
    return [...candidates].sort((a, b) => a.localeCompare(b));
}

// ---------------------------------------------------------------------------
// Rust emission
// ---------------------------------------------------------------------------

const HEADER = `// AUTO-GENERATED by generator.ts — do NOT edit by hand.
// Run \`npm run generate-decoders\` (then \`rustfmt --edition 2018\` on this
// file) after changing generator.ts or after CSL adds/removes decodable
// types. Generator invariant: get_decodable_types, decode_specific_type, and
// get_possible_types_for_input are all views over the same registry, so the
// three stay in sync by construction.
`;

const PRELUDE = `use std::collections::HashMap;
use std::sync::OnceLock;

use crate::bingen::wasm_bindgen;
use crate::cbor::limits;
use crate::csl_decoders::params::DecodingParams;
use crate::csl_preflight::{self, DecoderInput, ShapeHazards};
use crate::csl_decoders::specific_decoders::{
    decode_address, decode_native_script, decode_plutus_data, decode_plutus_script,
    decode_transaction,
};
use crate::csl_decoders::{answer, Answer};
use crate::js_value::{from_js_value, JsValue};
use bech32;
use bs58;
use cardano_serialization_lib as csl;
use hex;

fn is_valid_hex(input: &str) -> bool {
    hex::decode(input).is_ok()
}

fn is_valid_base58(input: &str) -> bool {
    bs58::decode(input).into_vec().is_ok()
}

fn is_valid_bech32(input: &str) -> bool {
    bech32::decode(input).is_ok()
}

/// \`{hex, bech32}\` for a hash or verification key. The bech32 form is
/// present only for the types with a CIP-5 prefix; the others have no
/// bech32 spelling and carry \`hex\` alone.
fn hash_value(hex: String, bech32: Option<Result<String, csl::JsError>>) -> serde_json::Value {
    let mut value = serde_json::Map::new();
    value.insert("hex".to_string(), serde_json::Value::String(hex));
    if let Some(Ok(bech32)) = bech32 {
        value.insert("bech32".to_string(), serde_json::Value::String(bech32));
    }
    serde_json::Value::Object(value)
}

/// Signature every decoder in the registry must satisfy.
type DecoderFn =
    fn(&str, bool, bool, bool, &DecodingParams) -> Result<Answer, String>;

`;

function snakeCase(s: string): string {
    return s
        .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
        .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
        .toLowerCase();
}

function fnNameForType(type: string): string {
    return `decode_${snakeCase(type)}`;
}

/** The `let value = …;` statement rendering a decoded `${type}` as JSON. */
function valueStmt(type: string, methods: ClassMethods): string {
    if (methods.to_json) {
        // The rendering is passed through as text, never read back into a
        // value: reading, dropping and converting a tree recurse per level.
        return `let value = decoded
                .to_json()
                .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                .and_then(|json| crate::csl_decoders::rendered_json(&json))?;`;
    }
    // Hash / verification-key types: `to_bech32(prefix)` needs a CIP-5 prefix.
    if (methods.to_hex && methods.to_bech32 && !TYPES_WITH_SIMPLE_BECH32.has(type)) {
        const prefix = HASH_BECH32_PREFIX[type];
        const bech32 = prefix ? `Some(decoded.to_bech32("${prefix}"))` : 'None';
        return `let value = hash_value(decoded.to_hex(), ${bech32});`;
    }
    const parts: string[] = [];
    if (methods.to_hex) parts.push(`"hex": decoded.to_hex()`);
    if (methods.to_bech32) parts.push(`"bech32": decoded.to_bech32()`);
    if (parts.length === 0) {
        return `let _ = &decoded;
            let value = serde_json::Value::String(
                "Decoded, but no additional representation".to_string(),
            );`;
    }
    return `let value = serde_json::json!({
                ${parts.join(',\n                ')}
            });`;
}

function emitAttempt(type: string, methods: ClassMethods): string {
    const attempts: string[] = [];

    if (methods.from_hex) {
        attempts.push(`    if is_hex {
        if let Ok(decoded) = csl::${type}::from_hex(input) {
            ${valueStmt(type, methods)}
            return answer(value);
        }
    }`);
    }

    if (methods.from_bytes && !methods.from_hex) {
        const arg = TYPES_WITH_BYTES_REF.has(type) ? '&bytes' : 'bytes';
        attempts.push(`    if is_hex {
        if let Ok(bytes) = hex::decode(input) {
            if let Ok(decoded) = csl::${type}::from_bytes(${arg}) {
                ${valueStmt(type, methods)}
                return answer(value);
            }
        }
    }`);
    }

    if (methods.from_bech32) {
        attempts.push(`    if is_bech32 {
        if let Ok(decoded) = csl::${type}::from_bech32(input) {
            ${valueStmt(type, methods)}
            return answer(value);
        }
    }`);
    }

    if (methods.from_base58) {
        attempts.push(`    if is_base58 {
        if let Ok(decoded) = csl::${type}::from_base58(input) {
            ${valueStmt(type, methods)}
            return answer(value);
        }
    }`);
    }

    return attempts.join('\n\n');
}

function emitStandardDecoder(type: string, methods: ClassMethods): string {
    const body = emitAttempt(type, methods);
    // use the full signature even for params we don't touch so every decoder
    // matches DecoderFn without ad-hoc casts.
    return `fn ${fnNameForType(type)}(
    input: &str,
    is_hex: bool,
    is_bech32: bool,
    is_base58: bool,
    _params: &DecodingParams,
) -> Result<Answer, String> {
    let _ = (is_hex, is_bech32, is_base58);
${body}

    Err("Failed to decode".to_string())
}`;
}

function emitCustomShim(entry: CustomDispatch): string {
    const extra = entry.extraArgs ? `, ${entry.extraArgs}` : '';
    // decode_plutus_data / decode_plutus_script put the extra parameter
    // immediately after `input`, not at the end — mirror that order.
    const body =
        entry.specificDecoder === 'decode_plutus_data' ||
        entry.specificDecoder === 'decode_plutus_script'
            ? `    ${entry.specificDecoder}(input${extra}, is_hex, is_bech32, is_base58)`
            : `    ${entry.specificDecoder}(input, is_hex, is_bech32, is_base58)`;

    const paramsBind = entry.extraArgs ? 'params' : '_params';

    return `fn ${entry.shim}(
    input: &str,
    is_hex: bool,
    is_bech32: bool,
    is_base58: bool,
    ${paramsBind}: &DecodingParams,
) -> Result<Answer, String> {
${body}
}`;
}

function emitRegistry(
    standardTypes: string[],
    methodsByClass: Map<string, ClassMethods>,
    customByTypeName: Map<string, CustomDispatch>
): string {
    const entries: string[] = [];
    const allTypes = [
        ...new Set<string>([...standardTypes, ...customByTypeName.keys()]),
    ].sort((a, b) => a.localeCompare(b));

    for (const type of allTypes) {
        const custom = customByTypeName.get(type);
        if (custom) {
            entries.push(`        m.insert("${type}", ${custom.shim} as DecoderFn);`);
        } else if (methodsByClass.has(type)) {
            entries.push(
                `        m.insert("${type}", ${fnNameForType(type)} as DecoderFn);`
            );
        }
    }

    return `/// Registry of every type the universal decoder can attempt. Populated once
/// on first call via \`OnceLock\`. Iteration order is unspecified — callers
/// that need a stable list (e.g. \`get_decodable_types\`) sort explicitly.
fn decoders() -> &'static HashMap<&'static str, DecoderFn> {
    static DECODERS: OnceLock<HashMap<&'static str, DecoderFn>> = OnceLock::new();
    DECODERS.get_or_init(|| {
        let mut m: HashMap<&'static str, DecoderFn> = HashMap::with_capacity(${entries.length});
${entries.join('\n')}
        m
    })
}`;
}

const PUBLIC_FNS = `#[wasm_bindgen]
pub fn get_decodable_types() -> Vec<String> {
    let mut names: Vec<String> = decoders().keys().map(|k| (*k).to_string()).collect();
    names.sort();
    names
}

/// The shape the typed decoder of a type reads its input as. Raw-byte
/// types are measured as a plain item (a Byron address is CBOR).
fn reading_shape(decoder_input: DecoderInput) -> csl_preflight::CslShape {
    match decoder_input {
        DecoderInput::RawBytes => csl_preflight::CslShape::Item,
        DecoderInput::Cbor(shape) => shape,
    }
}

/// Why hex input may not be handed to a typed decoder reading it as
/// \`shape\` for its nesting, or \`None\`.
///
/// Parts of the decoders recurse over the document on the host's stack,
/// so the document is scanned for its depth first, iteratively, and one
/// nested past [\`limits::MAX_TYPED_DECODER_NESTING_DEPTH\`] outside the
/// native scripts \`shape\` holds (or past [\`limits::MAX_CBOR_NESTING_DEPTH\`]
/// with them) is never handed to them. Native scripts are read, cloned,
/// dropped and rendered without recursion, so their levels do not count.
/// CBOR carried under tag 24 (an inline datum, a script reference) counts
/// on top of the level it is embedded at, as the decoders parse it in
/// place (see \`csl_preflight::typed_decoder_nesting_refusal\`). Input that
/// is not hex carries no CBOR to nest.
fn typed_nesting_refusal(bytes: Option<&[u8]>, shape: csl_preflight::CslShape) -> Option<String> {
    csl_preflight::typed_decoder_nesting_refusal(bytes?, shape)
}

/// Whether \`input\` is hex whose bytes a CBOR-reading decoder may not be
/// handed: not one well-formed item, or a witness list holding a simple
/// value (see \`crate::csl_preflight\`). \`None\` when the decoder may run.
fn cbor_refusal(input: &str, is_hex: bool, decoder_input: DecoderInput) -> Option<String> {
    if !is_hex {
        return None;
    }
    let bytes = hex::decode(input).ok()?;
    csl_preflight::check_decoder_input(&bytes, decoder_input)
        .err()
        .map(|e| e.to_string())
}

/// Decode \`input\` as \`type_name\`. Answers JSON text (parse it exactly:
/// integers past 2^53 are bare literals or \`$serde_json::private::Number\`
/// boxes); a JS object tree would be built, cloned and walked level by
/// level on the host stack.
#[wasm_bindgen]
pub fn decode_specific_type(
    input: &str,
    type_name: &str,
    params_json: JsValue,
) -> Result<Answer, String> {
    let params: DecodingParams = from_js_value(&params_json)?;
    let is_hex = is_valid_hex(input);
    let is_base58 = is_valid_base58(input);
    let is_bech32 = is_valid_bech32(input);

    let decoder_input = csl_preflight::decoder_input(type_name);
    let bytes = if is_hex { hex::decode(input).ok() } else { None };
    if let Some(refusal) = typed_nesting_refusal(bytes.as_deref(), reading_shape(decoder_input)) {
        return Err(refusal);
    }

    let decoder = match decoders().get(type_name) {
        Some(decoder) => decoder,
        None => return Err(format!("Unsupported type: {}", type_name)),
    };
    if let Some(refusal) = cbor_refusal(input, is_hex, decoder_input) {
        return Err(refusal);
    }
    decoder(input, is_hex, is_bech32, is_base58, &params)
}

/// Types [\`possible_types\`] did not try because reading the input as them
/// would nest past a bound: an implementation limit, not an answer.
pub(crate) struct Unexamined {
    /// The bound: the typed decoders' nesting bound, or the walkers' bound
    /// when the input nests past that even counting native scripts.
    pub(crate) limit: usize,
    /// How deep the input nests, native scripts included, when the scan
    /// measured it (it stops past [\`limits::MAX_CBOR_NESTING_DEPTH\`]).
    pub(crate) depth: Option<usize>,
    /// The refusal text naming the bound.
    pub(crate) message: String,
    /// The types not tried, sorted.
    pub(crate) types: Vec<String>,
}

/// The types \`input\` decodes as, and the types not tried because the
/// input nests past what they follow.
pub(crate) struct PossibleTypes {
    pub(crate) types: Vec<String>,
    /// Present when some type was not tried for nesting.
    pub(crate) unexamined: Option<Unexamined>,
}

/// The names of the types \`input\` decodes as. A type whose reading of the
/// input nests past what the typed decoders follow (outside the native
/// scripts it holds) is not tried: it is refused before its decoder sees
/// the input, and listed in \`unexamined\`. Hex that is not one well-formed
/// CBOR item is offered only to the raw-byte types, and a document whose
/// witness lists hold simple values is not offered to the types that read
/// those lists (see \`crate::csl_preflight\`).
pub(crate) fn possible_types(input: &str) -> PossibleTypes {
    let params = DecodingParams::default();
    let is_hex = is_valid_hex(input);
    let is_base58 = is_valid_base58(input);
    let is_bech32 = is_valid_bech32(input);
    let bytes = if is_hex { hex::decode(input).ok() } else { None };

    // The nesting verdict per shape, each scanned once; a document whose
    // whole nesting fits the bound is admitted for every shape at once.
    let whole = bytes.as_deref().map(|bytes| {
        limits::cbor_nesting_depth_through_embedded_capped(bytes, limits::MAX_CBOR_NESTING_DEPTH)
    });
    let deep = whole.is_some_and(|depth| depth > limits::MAX_TYPED_DECODER_NESTING_DEPTH);
    let mut refusals: HashMap<csl_preflight::CslShape, Option<String>> = HashMap::new();
    let mut refusal_for = |shape: csl_preflight::CslShape| -> Option<String> {
        if !deep {
            return None;
        }
        refusals
            .entry(shape)
            .or_insert_with(|| typed_nesting_refusal(bytes.as_deref(), shape))
            .clone()
    };

    // One scan of the bytes answers well-formedness and the witness-list and
    // address hazards for every CBOR-reading type.
    let cbor_gate = bytes.as_deref().map(|bytes| {
        let well_formed = crate::cbor::well_formedness_error(bytes).is_none();
        let hazards = ShapeHazards::scan(bytes);
        move |shape| well_formed && !hazards.hazardous(shape)
    });
    let may_try = |name: &str| match (csl_preflight::decoder_input(name), &cbor_gate) {
        (DecoderInput::RawBytes, _) => true,
        (DecoderInput::Cbor(_), None) => true,
        (DecoderInput::Cbor(shape), Some(gate)) => gate(shape),
    };

    let mut names: Vec<&'static str> = decoders().keys().copied().collect();
    names.sort_unstable();
    let mut matches = Vec::new();
    let mut not_tried = Vec::new();
    let mut first_refusal: Option<String> = None;
    for name in names {
        if let Some(refusal) = refusal_for(reading_shape(csl_preflight::decoder_input(name))) {
            first_refusal.get_or_insert(refusal);
            not_tried.push(name.to_string());
            continue;
        }
        if !may_try(name) {
            continue;
        }
        let decoder = decoders()[name];
        if decoder(input, is_hex, is_bech32, is_base58, &params).is_ok() {
            matches.push(name.to_string());
        }
    }
    let unexamined = first_refusal.map(|message| {
        let depth = whole.filter(|d| *d <= limits::MAX_CBOR_NESTING_DEPTH);
        let limit = if depth.is_none() {
            limits::MAX_CBOR_NESTING_DEPTH
        } else {
            limits::MAX_TYPED_DECODER_NESTING_DEPTH
        };
        Unexamined {
            limit,
            depth,
            message,
            types: not_tried,
        }
    });
    PossibleTypes {
        types: matches,
        unexamined,
    }
}

/// The sorted names of the types \`input\` decodes as; empty when none does
/// and also when none was tried (see [\`get_possible_types_report\`], which
/// tells the two apart).
#[wasm_bindgen]
pub fn get_possible_types_for_input(input: &str) -> Vec<String> {
    possible_types(input).types
}

/// [\`get_possible_types_for_input\`] with the types not tried, as JSON
/// text: \`{"types": [...]}\`, or, when reading the input as some types
/// nests past what the typed decoders follow (outside the native scripts
/// those types hold), \`{"types": [...], "unexamined": {"kind":
/// "nesting_too_deep", "limit": <bound>, "depth": <levels>, "message":
/// <text>, "types": [<not tried>]}}\` (\`depth\` absent when the input nests
/// past what the scan measures, \`limit\` then being that bound). Every type
/// not tried is an implementation limit, not a finding that the input is
/// not of that type; \`types\` empty and \`unexamined.types\` holding every
/// type means nothing was tried.
#[wasm_bindgen]
pub fn get_possible_types_report(input: &str) -> String {
    let report = possible_types(input);
    let mut value = serde_json::json!({ "types": report.types });
    if let Some(unexamined) = report.unexamined {
        let mut reason = serde_json::json!({
            "kind": "nesting_too_deep",
            "limit": unexamined.limit,
            "message": unexamined.message,
        });
        if let Some(depth) = unexamined.depth {
            reason["depth"] = serde_json::json!(depth);
        }
        reason["types"] = serde_json::json!(unexamined.types);
        value["unexamined"] = reason;
    }
    crate::deep_json::write_json(&value)
}
`;

// ---------------------------------------------------------------------------
// Top-level orchestration
// ---------------------------------------------------------------------------

function main(): void {
    if (!fs.existsSync(CSL_DTS_PATH)) {
        console.error(`❌ CSL .d.ts not found at ${CSL_DTS_PATH}. Run \`npm install\` first.`);
        process.exit(1);
    }

    const dtsText = fs.readFileSync(CSL_DTS_PATH, 'utf8');
    const methodsByClass = parseCslDts(dtsText);
    const candidates = collectCandidateTypes(methodsByClass);

    const customByTypeName = new Map<string, CustomDispatch>();
    for (const entry of CUSTOM_DISPATCH) {
        for (const t of entry.typeNames) customByTypeName.set(t, entry);
    }

    const standardTypes = candidates.filter(t => !customByTypeName.has(t));

    // Sanity: every CUSTOM_DISPATCH typeName had better be in candidates — else
    // it means we whitelisted a type CSL doesn't export, which would compile
    // into a broken shim.
    for (const t of customByTypeName.keys()) {
        if (!candidates.includes(t)) {
            console.warn(
                `⚠️  ${t} is in CUSTOM_DISPATCH but not found in CSL .d.ts. ` +
                `Shim will still be emitted; verify specific_decoders.rs handles it.`
            );
        }
    }

    const sections: string[] = [HEADER, PRELUDE];

    // Custom shims first (small & referenced by many types).
    for (const entry of CUSTOM_DISPATCH) {
        sections.push(emitCustomShim(entry));
    }

    // Standard per-type decoders, alphabetical.
    for (const type of standardTypes) {
        const methods = methodsByClass.get(type);
        if (!methods) continue;
        sections.push(emitStandardDecoder(type, methods));
    }

    sections.push(emitRegistry(standardTypes, methodsByClass, customByTypeName));
    sections.push(PUBLIC_FNS);

    const output = sections.join('\n\n') + '\n';
    fs.writeFileSync(OUTPUT_PATH, output);

    console.log(
        `✅ Wrote ${OUTPUT_PATH} — ${candidates.length} types (` +
            `${standardTypes.length} standard, ${customByTypeName.size} custom).`
    );
}

main();

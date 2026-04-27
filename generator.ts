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
 */
const IGNORE_TYPES = new Set<string>([
    'FixedBlock',
    'FixedTransaction',
    'FixedTransactionBodies',
    'FixedTransactionBody',
    'FixedVersionedBlock',
    'FixedTxWitnessesSet',
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
// Run \`npm run generate-decoders\` after changing generator.ts or after CSL
// adds/removes decodable types. Generator invariant: get_decodable_types,
// decode_specific_type, and get_possible_types_for_input are all views over
// the same registry, so the three stay in sync by construction.
`;

const PRELUDE = `use std::collections::HashMap;
use std::sync::OnceLock;

use crate::bingen::wasm_bindgen;
use crate::csl_decoders::params::DecodingParams;
use crate::csl_decoders::specific_decoders::{
    decode_address, decode_native_script, decode_plutus_data, decode_plutus_script,
    decode_transaction,
};
use crate::js_value::{from_js_value, from_serde_json_value, JsValue};
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

/// Signature every decoder in the registry must satisfy.
type DecoderFn =
    fn(&str, bool, bool, bool, &DecodingParams) -> Result<JsValue, String>;

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

function valueExpr(type: string, methods: ClassMethods): string {
    if (methods.to_json) {
        return `decoded
                .to_json()
                .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                .and_then(|json| {
                    serde_json::from_str(&json)
                        .map_err(|e| format!("Failed to parse JSON: {}", e))
                })`;
    }
    const parts: string[] = [];
    if (methods.to_hex) parts.push(`"hex": decoded.to_hex()`);
    if (methods.to_bech32) {
        const call = TYPES_WITH_SIMPLE_BECH32.has(type)
            ? `decoded.to_bech32()`
            : `decoded
                    .to_bech32("")
                    .map_err(|e| format!("Failed to convert to bech32: {:?}", e))?`;
        parts.push(`"bech32": ${call}`);
    }
    if (parts.length === 0) {
        return `{
                let _ = &decoded;
                Ok::<serde_json::Value, String>(serde_json::Value::String(
                    "Decoded, but no additional representation".to_string(),
                ))
            }`;
    }
    return `Ok::<serde_json::Value, String>(serde_json::json!({
                ${parts.join(',\n                ')}
            }))`;
}

function emitAttempt(type: string, methods: ClassMethods): string {
    const attempts: string[] = [];

    if (methods.from_hex) {
        attempts.push(`    if is_hex {
        if let Ok(decoded) = csl::${type}::from_hex(input) {
            let value = ${valueExpr(type, methods)}?;
            return from_serde_json_value(&value)
                .map_err(|e| format!("Failed to convert to JsValue: {}", e));
        }
    }`);
    }

    if (methods.from_bytes && !methods.from_hex) {
        const arg = TYPES_WITH_BYTES_REF.has(type) ? '&bytes' : 'bytes';
        attempts.push(`    if is_hex {
        if let Ok(bytes) = hex::decode(input) {
            if let Ok(decoded) = csl::${type}::from_bytes(${arg}) {
                let value = ${valueExpr(type, methods)}?;
                return from_serde_json_value(&value)
                    .map_err(|e| format!("Failed to convert to JsValue: {}", e));
            }
        }
    }`);
    }

    if (methods.from_bech32) {
        attempts.push(`    if is_bech32 {
        if let Ok(decoded) = csl::${type}::from_bech32(input) {
            let value = ${valueExpr(type, methods)}?;
            return from_serde_json_value(&value)
                .map_err(|e| format!("Failed to convert to JsValue: {}", e));
        }
    }`);
    }

    if (methods.from_base58) {
        attempts.push(`    if is_base58 {
        if let Ok(decoded) = csl::${type}::from_base58(input) {
            let value = ${valueExpr(type, methods)}?;
            return from_serde_json_value(&value)
                .map_err(|e| format!("Failed to convert to JsValue: {}", e));
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
) -> Result<JsValue, String> {
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
) -> Result<JsValue, String> {
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

#[wasm_bindgen]
pub fn decode_specific_type(
    input: &str,
    type_name: &str,
    params_json: JsValue,
) -> Result<JsValue, String> {
    let params: DecodingParams = from_js_value(&params_json)?;
    let is_hex = is_valid_hex(input);
    let is_base58 = is_valid_base58(input);
    let is_bech32 = is_valid_bech32(input);

    match decoders().get(type_name) {
        Some(decoder) => decoder(input, is_hex, is_bech32, is_base58, &params),
        None => Err(format!("Unsupported type: {}", type_name)),
    }
}

#[wasm_bindgen]
pub fn get_possible_types_for_input(input: &str) -> Vec<String> {
    let params = DecodingParams::default();
    let is_hex = is_valid_hex(input);
    let is_base58 = is_valid_base58(input);
    let is_bech32 = is_valid_bech32(input);

    let mut matches: Vec<String> = decoders()
        .iter()
        .filter(|(_, decoder)| {
            decoder(input, is_hex, is_bech32, is_base58, &params).is_ok()
        })
        .map(|(name, _)| (*name).to_string())
        .collect();
    matches.sort();
    matches
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

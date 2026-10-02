// The wasm functions the library exposes, as a runtime allowlist that is checked
// against the generated declarations (`types/cquisitor_lib.d.ts`) at compile time.
//
// A backend receives function names over a boundary it does not control (a
// worker's postMessage, a tool call), so it must never look a bare string up in
// the wasm module: that would reach constructors and CSL classes whose instances
// cannot be cloned. Everything callable through `LibBackend.callRaw` is listed
// here, and the type-level assertions below fail the build when the list and the
// declarations drift apart (a function added on the Rust side and regenerated into
// the d.ts must be added here; one removed there must be removed here).

import type { JsonText } from "@cardananium/cquisitor-lib/wasm";

/** The wasm module as the generated declarations describe it. */
export type WasmModule = typeof import("@cardananium/cquisitor-lib/wasm");

type FunctionKeys<M> = {
  [K in keyof M]: M[K] extends (...args: never[]) => unknown ? K : never;
}[keyof M];

/** Every function the generated declarations export. */
type DeclaredWasmFunctionName = FunctionKeys<WasmModule>;

/** Every wasm function callable through a backend, in the order of the declarations. */
export const WASM_FUNCTIONS = [
  // Transactions
  "get_necessary_data_list_js",
  "extract_hashes_from_transaction_js",
  "validate_transaction_js",
  "get_utxo_list_from_tx",
  "execute_tx_scripts",
  "get_ref_script_bytes",
  "add_witnesses_to_tx",
  "add_vkey_witnesses_to_tx",
  "add_witness_set_to_tx",
  "add_witnesses_to_tx_with_report",
  "check_block_or_tx_signatures",
  // Typed decoders
  "get_decodable_types",
  "decode_specific_type",
  "get_possible_types_for_input",
  "get_possible_types_report",
  // CBOR and CDDL
  "cbor_to_json",
  "validate_cddl",
  "validate_cbor_against_cddl",
  "decode_cbor_against_cddl",
  "map_cbor_to_cddl",
  "cddl_outline",
  "cddl_references",
  "cddl_symbol_at",
  "cddl_format",
  // Plutus
  "decode_plutus_program_uplc_json",
  "decode_plutus_program_pretty_uplc",
] as const satisfies readonly DeclaredWasmFunctionName[];

export type WasmFunctionName = (typeof WASM_FUNCTIONS)[number];

// Both directions: the list may neither miss nor invent a declared function.
type MissingFromList = Exclude<DeclaredWasmFunctionName, WasmFunctionName>;
const _everyDeclaredFunctionIsListed: [MissingFromList] extends [never]
  ? true
  : { "functions declared in types/cquisitor_lib.d.ts but missing from WASM_FUNCTIONS": MissingFromList } = true;
void _everyDeclaredFunctionIsListed;

/** Parameter list of one wasm function, as declared. */
export type WasmFunctionArgs<F extends WasmFunctionName> = Parameters<WasmModule[F]>;
/** Return type of one wasm function, as declared (JSON text for the text answers). */
export type WasmFunctionResult<F extends WasmFunctionName> = ReturnType<WasmModule[F]>;
/**
 * What `callLib(fn, …)` resolves to: the declared return type with a
 * `JsonText<X>` answer read as `X`. Integers are `number | bigint` wherever the
 * declarations say so; a plain `string` answer stays a string.
 */
export type ParsedResult<F extends WasmFunctionName> =
  WasmFunctionResult<F> extends JsonText<infer X> ? X : WasmFunctionResult<F>;

/**
 * What each function does, as the object of a sentence ("did not finish
 * decoding the CBOR"): the words a message shows a person instead of the
 * export name.
 */
const WASM_FUNCTION_LABELS = {
  get_necessary_data_list_js: "listing the chain data the transaction needs",
  extract_hashes_from_transaction_js: "extracting the transaction's hashes",
  validate_transaction_js: "validating the transaction",
  get_utxo_list_from_tx: "listing the transaction's inputs",
  execute_tx_scripts: "running the transaction's scripts",
  get_ref_script_bytes: "reading the reference script",
  add_witnesses_to_tx: "adding witnesses to the transaction",
  add_vkey_witnesses_to_tx: "adding witnesses to the transaction",
  add_witness_set_to_tx: "adding a witness set to the transaction",
  add_witnesses_to_tx_with_report: "adding witnesses to the transaction",
  check_block_or_tx_signatures: "checking the signatures",
  get_decodable_types: "listing the decodable types",
  decode_specific_type: "decoding the input",
  get_possible_types_for_input: "working out what the input decodes as",
  get_possible_types_report: "working out what the input decodes as",
  cbor_to_json: "decoding the CBOR",
  validate_cddl: "checking the CDDL schema",
  validate_cbor_against_cddl: "validating the CBOR against the CDDL schema",
  decode_cbor_against_cddl: "decoding the CBOR against the CDDL schema",
  map_cbor_to_cddl: "mapping the CBOR onto the CDDL schema",
  cddl_outline: "outlining the CDDL schema",
  cddl_references: "finding references in the CDDL schema",
  cddl_symbol_at: "looking up the CDDL symbol",
  cddl_format: "formatting the CDDL schema",
  decode_plutus_program_uplc_json: "decoding the Plutus script",
  decode_plutus_program_pretty_uplc: "decoding the Plutus script",
} as const satisfies Record<WasmFunctionName, string>;

/**
 * What a call does, in words for a person (`"decoding the CBOR"`), for
 * messages that should not show an export name. Unknown names come back as
 * `"running <name>"`.
 */
export function describeWasmFunction(fn: string): string {
  return isWasmFunction(fn) ? WASM_FUNCTION_LABELS[fn] : `running ${fn}`;
}

const WASM_FUNCTION_SET: ReadonlySet<string> = new Set(WASM_FUNCTIONS);

/** True when `name` is one of the callable wasm functions. */
export function isWasmFunction(name: unknown): name is WasmFunctionName {
  return typeof name === "string" && WASM_FUNCTION_SET.has(name);
}

/**
 * Functions whose answer is JSON text written by the library rather than a JS
 * value: the document walkers and the typed decoder (a deep tree would fail
 * structured clone and be walked twice) and the `*_js` transaction functions. A backend hands the text
 * over untouched; the typed wrappers parse it once, exactly (`parseJsonExact`).
 */
const JSON_TEXT_FUNCTIONS: ReadonlySet<WasmFunctionName> = new Set<WasmFunctionName>([
  "get_necessary_data_list_js",
  "extract_hashes_from_transaction_js",
  "validate_transaction_js",
  "decode_specific_type",
  "get_possible_types_report",
  "cbor_to_json",
  "validate_cbor_against_cddl",
  "decode_cbor_against_cddl",
  "map_cbor_to_cddl",
]);

export function answersInJsonText(fn: WasmFunctionName): boolean {
  return JSON_TEXT_FUNCTIONS.has(fn);
}

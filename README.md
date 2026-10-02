# Cquisitor-lib

A Cardano transaction validation and decoding library: a Rust core compiled to WebAssembly behind a typed TypeScript API. Provides transaction validation according to ledger rules (Phase 1 and Phase 2), universal CBOR/Cardano type decoders, CDDL validation, Plutus script decoders, signature verification, chain-data providers (Koios, Blockfrost) and the helpers the [cquisitor](https://github.com/cardananium/cquisitor) app and the cardano-debug-mcp server share.

One import works in Node (>= 20), Bun and browsers, with no setup: every function is `async` and runs the wasm in the calling thread on first use. A host that wants the wasm off its main thread plugs in a worker backend (`configure({ backend })`).

## Features

### Transaction Validation

Phase 1 validation covers balance, fees, witnesses, collateral, certificates, outputs, and transaction limits. Phase 2 executes Plutus V1/V2/V3 scripts with detailed redeemer results.

### Universal Decoder

Decode 149 Cardano types (the list `decodableTypes()` answers) from hex/bech32/base58 encoding:
- Primitive types: `Address`, `PublicKey`, `PrivateKey`, `TransactionHash`, `ScriptHash`, etc.
- Complex structures: `Transaction`, `Block`, `TransactionBody`, `TransactionWitnessSet`
- Certificates: `StakeRegistration`, `PoolRegistration`, `DRepRegistration`, governance actions
- Plutus: `PlutusScript`, `PlutusData`, `Redeemer`, `ScriptRef`
- All credential types, native scripts, metadata structures

Functions:
- `decodableTypes()` - Returns list of all supported type names
- `decode(input, typeName, params?)` - Decode specific Cardano type
- `possibleTypes(input)` - Suggests types that can decode given input

### CBOR Decoder & CDDL Validation

- `cborToJson(hex)` - Converts raw CBOR to JSON with positional information, supporting indefinite arrays/maps and all CBOR types. Each node carries an optional `oddities` array flagging deviations from RFC 8949 deterministic encoding (overlong integers/floats, indefinite length, unsorted/duplicate map keys, non-canonical bignums). Never throws on malformed input — returns a `{ok, value}` / `{ok: false, error, partial?}` union where `error` is a structured `CborDecodeError` (kind / byte offset / byte span / semantic `path`) and `partial` is the sub-tree decoded before the failure, with every unfinished container flagged `incomplete: true`.
- `validateCddl(cddl)` - Parses a CDDL schema; reports parse errors (with a `byte_span` for editor squiggles) and unresolved rule references (e.g. `thing = [unknown_rule, int]` → `kind: "unresolved_references"`).
- `validateCborAgainstCddl(hex, cddl, rule)` (alias `cborValidate`) - Validates a CBOR payload against a named rule. Errors carry `kind`, `expected`, semantic `path`, byte/anchor spans, a `cddl_byte_span` pointing at the failing CDDL type, and an `additional` array when multiple violations fire.
- `decodeCborAgainstCddl(hex, cddl, rule)` - Maps decoded CBOR onto a CDDL schema and returns labelled JSON (e.g. Cardano `[body, witness_set, bool, aux]` becomes `{transaction_body, transaction_witness_set, ...}`). Handles generics (`set<a>`), tagged sets, type rules used as field labels, and a few well-known tags (bignum → string number, datetime → ISO string). Sub-structures the schema doesn't cover surface under `@extra` / `@positional` so partial matches don't lose data.
- `cddlOutline(cddl)` - Returns one `{name, kind, span, name_span}` entry per top-level rule. Editor outline view, breadcrumbs, fuzzy "go to rule".
- `cddlReferences(cddl, name)` - Returns `{definition, uses[]}` byte ranges for a rule name. Powers find-references and same-name highlighting on cursor.
- `cddlSymbolAt(cddl, offset)` - Returns the symbol under the cursor (or `null`), with `role: "definition" | "use"` and a `definition_span` pointing at its rule. Powers hover and Cmd-click go-to-definition.
- `cddlFormat(cddl)` - Pretty-prints CDDL by round-tripping through the AST. Useful for format-on-save.

### Plutus Script Decoder

- `decodePlutusProgramJson(hex)` - Decodes Plutus script to UPLC AST JSON
- `decodePlutusProgramPretty(hex)` - Decodes to human-readable UPLC format

Handles double CBOR wrapping and normalization automatically.

### Signature Verification

`checkSignatures(hex)` - Verifies all VKey and Catalyst witness signatures in transactions or entire blocks. Answers `{ valid, tx_hash?, invalidVkeyWitnesses?, invalidCatalystWitnesses? }`; each list is left out when empty.

### Script Execution

`executeTxScripts(txHex, utxos, costModels)` - Executes all Plutus scripts in a transaction independently. Per redeemer: its tag and index, the execution units the transaction declared, and either the units the script used or the error it failed with (integers as `number`, `bigint` past 2^53). Script logs come with `validateTransaction`'s `eval_redeemer_results`.

### Validation Coverage

**Phase 1 Validation:**
- Balance validation (inputs, outputs, fees, deposits, refunds)
- Fee calculation and validation (including script reference fees)
- Cryptographic witness validation (signatures, native scripts)
- Collateral validation for script transactions
- Certificate validation (stake registration, pool operations, DReps, governance)
- Output validation (minimum ADA, size limits)
- Transaction limits (size, execution units, reference scripts)
- Auxiliary data validation

**Phase 2 Validation:**
- Plutus V1, V2, and V3 script execution: the evaluator is aiken's `uplc` v1.1.24, run with the language *and* the context's protocol major (`protocolParameters.protocolVersion[0]`), as the ledger selects builtin semantics and costing: PlutusV1/V2 use semantics B at protocol 9–10 and D at 11+, PlutusV3 uses C at 9–10 and E at 11+ (A for V1/V2 before 9). The protocol-11 builtins `expModInteger`, `dropList`, the BLS12-381 `multiScalarMul` pair and the CIP-153 value builtins (V3 at 11+ only) run; the array builtins (`lengthOfArray`, `listToArray`, `indexArray`, codes 89–91) are not implemented by this `uplc` release, so a script using them fails to decode (`ScriptDecodeError`). `execute_tx_scripts` takes no protocol version and runs every script as at protocol 11.
- Redeemer validation with execution units
- Script context generation

See [WHAT-IS-COVERED.md](./WHAT-IS-COVERED.md) for a complete list of validation errors and warnings.

## Installation

```bash
npm install @cardananium/cquisitor-lib
```

The package is **ESM-only** (`"type": "module"`): `import` it from ESM, or `require()` it on Node >= 22.12 (`require(esm)`); on Node 20, `require()` throws `ERR_REQUIRE_ESM`, so use a dynamic `import()`. The raw exports under `./wasm` stay CommonJS for Node and can be `require()`d anywhere. TypeScript >= 5 with `moduleResolution: "NodeNext"`, `"Node16"` or `"bundler"` resolves every subpath and its types (legacy `node10` resolution works through `typesVersions`).

In a **bundler** the `browser` export condition selects an ESM glue that does `import * as wasm from "./cquisitor_lib_bg.wasm"` and expects the *instantiated exports* of the module, so the bundler needs wasm ESM integration: webpack 5 with `experiments.asyncWebAssembly`, Next.js/Turbopack, Vite with `vite-plugin-wasm`, or esbuild with a plugin that implements it (for example `esbuild-plugin-wasm`) — esbuild's built-in `file` / `binary` loaders hand the glue a URL or bytes instead and the bundle fails at its first call. Without a plugin, instantiate by hand and serve the module yourself. The glue's files are exported one by one under `@cardananium/cquisitor-lib/wasm/browser/*` for this:

```typescript
// lib.worker.ts
import * as bg from "@cardananium/cquisitor-lib/wasm/browser/cquisitor_lib_bg.js";
import { serveWasm } from "@cardananium/cquisitor-lib/worker";
// The .wasm as an asset URL: esbuild `--loader:.wasm=file`, webpack 5 a rule
// `{ test: /\.wasm$/, type: "asset/resource" }`, Vite `…/cquisitor_lib_bg.wasm?url`.
// TypeScript needs a `declare module "*.wasm" { const url: string; export default url; }`.
import wasmUrl from "@cardananium/cquisitor-lib/wasm/browser/cquisitor_lib_bg.wasm";

// serveWasm first, handed the instantiation as a promise: a top-level `await`
// before it would leave the host's first request with no listener to receive it.
serveWasm(
  (async () => {
    const imports = { "./cquisitor_lib_bg.js": bg as unknown as WebAssembly.ModuleImports };
    const { instance } = await WebAssembly.instantiateStreaming(fetch(wasmUrl), imports);
    bg.__wbg_set_wasm(instance.exports);
    (instance.exports as { __wbindgen_start(): void }).__wbindgen_start();
    return bg;
  })(),
  self,
);
```

This route is for bundlers without wasm ESM integration (plain esbuild, Rollup). webpack 5 has it built in: use `experiments.asyncWebAssembly` there, because with an `asset/resource` rule for `.wasm` a bundle that imports the package root fails to build — the root's lazy `import("@cardananium/cquisitor-lib/wasm")` reaches the ESM glue, whose `import * as wasm from "./cquisitor_lib_bg.wasm"` then gets a URL. (The worker file above imports only `/worker` and the glue's inner module, and builds either way.)

The wasm is only reached through a dynamic `import()`, so with ESM integration it ends up in its own lazily loaded chunk. When bundling **for Node**, mark `@cardananium/cquisitor-lib/wasm` as external: the Node glue is CommonJS and reads the `.wasm` from its own directory.

## Quick Start

```typescript
import { possibleTypes, decode, cborToJson, validateCborAgainstCddl, necessaryData, validateTransaction } from "@cardananium/cquisitor-lib";

const hex = "84a400...";                                  // any hex / bech32 / base58 input
await possibleTypes(hex);                                // ["Transaction"]
const { transaction } = await decode(hex, "Transaction"); // { transaction_hash, transaction }, exact integers
const tree = await cborToJson(hex);                      // positional CBOR tree, or {ok: false, error, partial}
const check = await validateCborAgainstCddl(hex, conwayCddl, "transaction");   // {valid: true} | {valid: false, error}

// Ledger validation: ask what the transaction needs, fetch it, validate.
const needed = await necessaryData(hex, "mainnet");     // {utxos, accounts, pools, dReps, govActions, ...}
const context = /* build a ValidationInputContext from your indexer */ ...;
const result = await validateTransaction(hex, context); // {errors, warnings, phase2_errors, phase2_warnings, eval_redeemer_results}
```

With a chain-data provider the fetching is done for you:

```typescript
import { validateTransactionOnline } from "@cardananium/cquisitor-lib";

const { result, utxoInfoMap, fetchedContext } = await validateTransactionOnline({
  txHex: hex,
  network: "mainnet",
  provider: "koios",            // or "blockfrost" (+ apiKey)
});
if (result.errors.length === 0 && result.phase2_errors.length === 0) console.log("valid");
```

Or fetch and validate in two steps (`fetchValidationData` + `buildValidationContext` + `validateTransaction`) when you want to inspect or cache the context.

### Integers

Every answer is read once, exactly: an integer that fits 2^53 is a `number`, a larger one (lovelace totals, ex-unit budgets, `u64`/`i128` fields) is a `bigint`. Fields the Rust side declares as 64/128-bit are typed `number | bigint`; `u32` and narrower fields are `number`. Inputs accept both (`validateTransaction` serialises `bigint` as bare JSON integers). `parseJsonExact` / `stringifyJsonExact` (from the root or `./util`) implement the same rule for JSON text of your own, e.g. the `script_context` string of an `EvalRedeemerResult`.

### Errors

A library answer that is an exception (bad hex, a schema that does not parse, a missing UTxO) rejects with a plain `Error` carrying the library's message. Refusals that are **not** answers are distinct classes, recognisable with `isLibRefusal(error)`: `LibInputTooLargeError` (over the per-call input budget, applied before the wasm sees the bytes — every argument counts, strings inside arrays and objects included), `LibTimeoutError` (a worker backend abandoned the call), `LibUnavailableError` (no worker could be started, or an in-process instance is poisoned by an earlier trap) and `LibResultNotTransferableError` (the answer could not cross the worker boundary). A call dropped by its caller is **not** a refusal and `isLibRefusal` answers `false` for it: `LibAbortedError`, recognisable with `isLibAbortedError(error)`, means the caller's `AbortSignal` fired while the call was still queued (a call already running in the wasm cannot be interrupted and runs to its result or its `timeoutMs`), so there is usually nothing to show. Arguments a worker cannot be handed (a function or a symbol inside them: structured clone fails) reject that one call with a `TypeError`. Every function takes a trailing `options?: { signal?, timeoutMs? }`.

## Where the wasm runs: backends

```typescript
interface LibBackend {
  callRaw<T = unknown>(fn: WasmFunctionName, args: unknown[], options?: { signal?: AbortSignal; timeoutMs?: number }): Promise<T>;
}
```

`getBackend()` answers the configured backend or the **default in-process backend**: the wasm module is `import()`ed on the first call and every function runs synchronously on the calling thread. No watchdog, and a trap (`RuntimeError: unreachable`, i.e. a Rust panic) or a stack overflow poisons that instance for good — the backend then refuses further calls with `LibUnavailableError` rather than trust a corrupted instance. Fine for scripts, tests and servers that trust their input.

For isolation, run the wasm in a worker. The worker file is one line; the host registers the backend once:

```typescript
// lib.worker.ts (browser)
import { serveWasm } from "@cardananium/cquisitor-lib/worker";
serveWasm(import("@cardananium/cquisitor-lib/wasm"), self);

// main thread
import { configure, createInProcessBackend, createWorkerBackend } from "@cardananium/cquisitor-lib";
configure({
  backend: createWorkerBackend({
    spawn: () => new Worker(new URL("./lib.worker.ts", import.meta.url), { type: "module" }),
    timeoutMs: 30_000,                                   // deadline per call, queue wait included (default 120 s)
    timeoutFor: (fn) => (fn === "validate_transaction_js" ? 120_000 : undefined),
    fallback: () => createInProcessBackend(),            // optional: where calls go when no worker can be started
  }),
});
```

```typescript
// Node: the package ships the worker entry
import { configure } from "@cardananium/cquisitor-lib";
import { createNodeWorkerBackend } from "@cardananium/cquisitor-lib/node";
configure({ backend: createNodeWorkerBackend({ timeoutMs: 30_000, resourceLimits: { maxOldGenerationSizeMb: 1024 } }) });
```

`createWorkerBackend` runs one call at a time (the wasm's CDDL schema cache is shared) and kills and replaces the worker after a timeout, a trap or a crash (`onEvent` reports each). The rest of its contract:

* **One deadline per call.** `timeoutMs` (or `timeoutFor(fn)`, or the call's own `options.timeoutMs`) is measured from the moment the call is made, so time spent queued behind other calls counts: a call still queued at its deadline is dropped and never runs (`LibTimeoutError`, "never ran"), and so is one whose turn comes with too little of it left to be worth starting: `MIN_TURN_MS` (5 ms) on a worker that has already run that function; on one that has not, a tenth of the deadline, at least `COLD_TURN_FLOOR_MS` (25 ms), at most `COLD_TURN_MS` (100 ms) and never more than the deadline itself, since a function's first run in a worker also compiles its code (on a fast machine up to some 25 ms for `possibleTypes`, `decode`, `cborToJson` and `necessaryData`, 35–55 ms for `validateTransaction` and, on a Conway-sized schema, the CDDL functions). That keeps calls queued just behind one that times out from being started on the replacement and killed with it: at any deadline for the lighter functions, from a deadline of about 600 ms for the heavier ones. The margin holds on a healthy worker too: a call whose function that worker has not run yet is refused with less than the margin left even if it would have finished in time (with a 10 s deadline, a call queued behind one that ran for over 9.9 s). A call that is started and still runs past its deadline has its worker killed. Time a fresh worker spends loading the wasm is not charged to anyone — deadlines pause until the worker reports its module loaded — and is bounded by `loadTimeoutMs` (default 60 s) instead, so a call settles within its `timeoutMs` plus any such load. `Infinity`, `0` or a negative value means no deadline, values past 2^31 - 1 ms are clamped, `NaN` is refused with a `TypeError`.
* **When workers fail.** A spawn that throws, a load that errors or a worker that dies counts as a failure; after `maxConsecutiveFailures` in a row (default 3) no worker is spawned for `retryAfterMs` (default 30 s). A load that runs out of time goes straight into that cooldown rather than download the wasm again. Refusals say "calls are refused for another N s" only while that is true.
* **`fallback`** (optional, e.g. `() => createInProcessBackend()`): built lazily, once, and used for calls that have no worker to run on because `spawn` threw or workers keep failing to load (a CSP without `worker-src`, a worker chunk that 404s, a wasm too slow to arrive). Those calls run without a deadline, since the wasm cannot be interrupted in the calling thread; after the cooldown the next call tries a worker again. A call killed for its deadline or by a trap never pushes the next one onto the fallback — it gets a fresh worker.
* `warm()` loads ahead of the first call (or prepares the fallback), `stats()` reports spawns, queue and fallback calls, and `dispose()` rejects what is outstanding and terminates the worker. A Node `worker_threads` worker is unref'd whenever nothing waits on it, so a script exits once its last answer is in without calling `dispose()`; a server calls it on shutdown.

A host with its own worker plumbing implements `LibBackend` directly — `callRaw` must resolve to **exactly** what the wasm function returns (JSON text for the `answersInJsonText` functions, the JS value otherwise); the typed wrappers parse and normalise on top.

`configure` also takes a `compressor` (brotli for `e=b` share links; `nodeBrotliCompressor` from `./node`, or brotli-wasm in a browser) and a `logger` (defaults to `console.error`). Each call merges with the previous ones; `resetConfig()` returns to the defaults.

## The typed API

Every function below is `async`, runs through `getBackend()`, and accepts a trailing `options?: LibCallOptions`.

| Function | Wasm export | Answer |
|---|---|---|
| `decode(input, typeName, params?)` | `decode_specific_type` | the type's JSON, exact integers: `DecodedTransaction` (`{ transaction_hash, transaction: TransactionData }`) for `"Transaction"`, `T` (default `unknown`) for any other name |
| `possibleTypes(input)` | `get_possible_types_for_input` | `string[]` (sorted; a type the input would make the serialization library abort on is left out, so malformed CBOR yields `[]`) |
| `decodableTypes()` | `get_decodable_types` | `string[]` |
| `cborToJson(hex)` | `cbor_to_json` | `CborDecodeResult` |
| `validateCddl(cddl)` | `validate_cddl` | `CddlValidationResult` |
| `validateCborAgainstCddl(hex, cddl, rule)` / `cborValidate` | `validate_cbor_against_cddl` | `CborValidationResult` |
| `decodeCborAgainstCddl(hex, cddl, rule)` | `decode_cbor_against_cddl` | `CborDecodeAgainstCddlResult` |
| `mapCborToCddl(hex, cddl, rule)` | `map_cbor_to_cddl` | `CborCddlMapResult` |
| `cddlOutline(cddl)` | `cddl_outline` | `CddlOutlineEntry[]` |
| `cddlReferences(cddl, name)` | `cddl_references` | `CddlReferencesResult` |
| `cddlSymbolAt(cddl, byteOffset)` | `cddl_symbol_at` | `CddlSymbolAtResult` |
| `cddlFormat(cddl)` | `cddl_format` | `string` |
| `necessaryData(txHex, network)` | `get_necessary_data_list_js` | `NecessaryInputData` |
| `validateTransaction(txHex, context)` | `validate_transaction_js` | `ValidationResult` |
| `executeTxScripts(txHex, utxos, costModels)` | `execute_tx_scripts` | `ExecuteTxScriptsResult` (the export's decimal strings read as `number` / `bigint`) |
| `extractHashes(txHex)` | `extract_hashes_from_transaction_js` | `ExtractedHashes` |
| `utxoList(txHex)` | `get_utxo_list_from_tx` | `string[]` (`txHash#index`) |
| `refScriptBytes(txHex, outputIndex)` | `get_ref_script_bytes` | `string` (hex) |
| `addWitnesses(txHex, witnesses)` | `add_witnesses_to_tx` | `string` (tx hex) |
| `addWitnessesWithReport(txHex, witnesses)` | `add_witnesses_to_tx_with_report` | `AddWitnessesReport` |
| `addVkeyWitnesses(txHex, vkeyWitnessesHex)` | `add_vkey_witnesses_to_tx` | `string` |
| `addWitnessSet(txHex, witnessSetHex)` | `add_witness_set_to_tx` | `string` |
| `checkSignatures(hex)` | `check_block_or_tx_signatures` | `CheckSignaturesResult` (the `invalid*Witnesses` lists are omitted when empty) |
| `decodePlutusProgramJson(hex)` | `decode_plutus_program_uplc_json` | `ProgramJson` |
| `decodePlutusProgramPretty(hex)` | `decode_plutus_program_pretty_uplc` | `string` |

`callLib(fn, args, options?)` runs any allowlisted wasm function with the same parsing and resolves to the declared answer type (`ParsedResult<F>`: a `JsonText<X>` declaration reads as `X`; `WASM_FUNCTIONS` is the allowlist, `WasmFunctionName` its type; both are checked against the generated declarations at build time). Every result and context type (`ValidationResult`, `ValidationInputContext`, `CborValue`, `CddlOutlineEntry`, ...) is exported from the root.

Input is checked before the serialization library sees it: hex that is not one well-formed CBOR item, a document nested deeper than 128 levels outside its native scripts (CBOR under tag 24, an output's inline datum or a script reference, counting on top of the level it sits at; the typed decoders stop at 64; native scripts, which every reader here walks without recursion, do not count and nest up to 32 768 levels with the rest of the input), a transaction whose witness lists hold a simple value where a witness array belongs, or one with an empty byte string where an address is read (an output address, a withdrawal key, a pool's or proposal's reward account, a treasury withdrawal key) is refused with an ordinary `Error` (`Malformed CBOR: <reason> (kind: <kind>, path: <path>)`, `Unsupported CBOR content: CBOR nesting is deeper than the supported limit of 128 levels …; native scripts do not count toward it …`, `Malformed witness list: a simple value or float at byte offset N …`, `Malformed address: an empty byte string at byte offset N …`, `Input is empty`) instead of trapping the wasm, on every entry point that reads a transaction, a block, a witness set, a context datum or a typed CBOR value; `possibleTypes` leaves out every type that would abort on the input. Hash and verification-key types decode to `{ hex, bech32? }` (`bech32` only where CIP-5 names a prefix). `validateTransaction` rejects a context whose asset quantities are not integers (`Invalid UTxO in the validation context: …`). The CBOR validation report locates an `unexpected key` at its entry (`path` ends in the key, `byte_spans` / `anchor_spans` hold the key's span then the value's), writes composite keys in diagnostic notation (`$[[2, h'0102']]`), names lengths in `.size` mismatches (`expected byte string of size 28 bytes, got 27 bytes`) and measures a string against `.size` whole (RFC 8610), with one exception the ledger makes: an indefinite-length byte string validated under the rule named `bounded_bytes` is held to the upper bound of its range one chunk at a time (exact sizes and lower bounds still apply to the whole string); chunked metadata text and bytes are measured whole, as the ledger's 64-byte metadatum bound is. See [API_DOCUMENTATION.md](API_DOCUMENTATION.md) ("Input checks", "CBOR validation report").

### Groups and subpaths

The root exports everything flat. Each group is also a subpath (`@cardananium/cquisitor-lib/<group>`), and every module under it (`@cardananium/cquisitor-lib/<group>/<module>`).

| Subpath | Contents |
|---|---|
| `.` (root) | the typed API, `configure`/`getBackend`/`createInProcessBackend`, the error classes, everything from `/worker`, `/chain`, `/share`, `/cddl`, `/handoff`, `/util`, the types of `/types` and of `/wasm` |
| `/wasm` | the raw wasm exports (synchronous, `snake_case`, JSON text for some answers): `cbor_to_json`, `validate_transaction_js`, ... — see [Low-level wasm exports](#low-level-wasm-exports-wasm). Loaded on demand by the default backend; a worker file imports it. `/wasm/browser/*` exports the browser glue file by file, for instantiating the wasm by hand. |
| `/node` | **Node/Bun only**: `createNodeWorkerBackend`, `NODE_WASM_WORKER_ENTRY`, `nodeBrotliCompressor`, `nodeBrotliCompress`, `nodeBrotliDecompress`. Never re-exported from the root, so browser bundles never see a `node:` import. |
| `/worker` (`/worker/serve`, `/worker/workerBackend`, `/worker/ports`) | `serveWasm(wasm, port)`, `createWorkerBackend(transport)` and its defaults (`DEFAULT_CALL_TIMEOUT_MS`, ..., `MIN_TURN_MS`, `COLD_TURN_FLOOR_MS`, `COLD_TURN_MS`), the wire protocol (`LibRequest`, `LibResponse`, `LibLoadedMessage`, `isLibResponse`, ...), the port types, the input budgets (`MAX_LIB_INPUT_BYTES`, `inputBudgetFor`, `guardInputBudget`, `formatByteSize`, ...), `describeWasmFunction(fn)` (what a call does, in words, for messages). The building blocks of a hand-rolled worker loop stay on their modules: `answer`/`reply`/`errorPayload` (`/worker/serve`), `abandonedMessage`/`neverRanMessage` (`/worker/workerBackend`), `toMessagePort`/`toWorkerHandle` (`/worker/ports`). |
| `/chain` (`/chain/koiosClient`, `/chain/blockfrostClient`, `/chain/transactionValidation`, `/chain/koiosTypes`, `/chain/scriptRefFormat`, `/chain/plutusCostModelOrder`, `/chain/cip129`) | `KoiosClient`, `BlockfrostClient` (one `BlockchainDataClient` surface), `validateTransactionOnline(config)`, `fetchValidationData(...)`, `buildValidationContext(...)`, `fetchTxCbor`, `submitTransaction`; Koios wire types; CIP-129 governance ids and pool-id helpers (`encodeGovernanceActionId`, `decodeGovernanceActionId`, `ensurePoolIdBech32`, ...; `GovActionRef`) |
| `/share` | share-link codec: `encodeValidatorLink`, `encodeCardanoCborLink`, `encodeGeneralCborLink`, `encodeCddlLink`, `parseHash`, `parse*Share`, `URL_FORMAT_VERSION`, `CTX_SCHEMA_VERSION`, base64url helpers, and the container's own JSON codec `stringifyShareJson`/`parseShareJson` (`bigint` as a `{"$bi": "<digits>"}` box — for share links and caches of their payloads only; library JSON text is read with `parseJsonExact`). `e=b` (brotli) links need `configure({ compressor })`. |
| `/cddl` (`/cddl/cborPath`, `/cddl/rootKinds`, `/cddl/ruleSelection`, `/cddl/cddlError`, `/cddl/verdict`) | pure readers of `validateCddl` / `validateCborAgainstCddl` / `cddlOutline` / `cborToJson` answers: the `$.a[0]["k"]` path grammar, root kinds a rule admits, root-rule selection, `cborDiagnostics(error)`, schema-error guidance, `verdictFor(input)` |
| `/handoff` | de-uplc links from eval results: `fieldsFromEval`, `fieldsToUrl`, `buildAllDeUplcLinks`, `DE_UPLC_BASE_URL`, ... |
| `/util` | `parseJsonExact`, `stringifyJsonExact`, `quoteUnsafeIntegers`, `parseJsonExactWithoutReviver` (the one JSON reader/writer for library text: bare digits, exact integers; the last one forces the path Node 20 takes, with the same answers); `hexToBytes`/`bytesToHex`; `convertSerdeNumbers`; address-type, input-normalisation, CBOR-depth (`nestsPastTypedDecoding`), CBOR-error, slot-time, Cardanoscan-link and transaction-field-order helpers |
| `/types` | the decoded-transaction model: `DecodedTransaction` (what `decode(hex, "Transaction")` answers, `{ transaction_hash, transaction }`), `TransactionData`, `TransactionBody`, `WitnessSet`, `Redeemer`, `Certificate`, `PlutusScript` (`{ bytes, language }`, as witness sets, auxiliary data and script references carry it), `NativeScript`, `TxVoter`, `TxGovernanceActionId`, `TxProtocolVersion`, ...; `CardanoNetwork`, `ValidationDiagnostic`, `InputUtxoInfoMap` |

## Package layout

`npm run build-all` produces `pkg/` and a tarball `pkg/cardananium-cquisitor-lib-<version>.tgz` (the version is Cargo.toml's, via wasm-pack's manifest):

```
pkg/
  package.json           "type": "module"; exports ".", "./wasm", "./node", "./<group>", "./<group>/*"
  index.js, index.d.ts   -> ./lib/index.js
  lib/**                 the TypeScript library, compiled (ESM + .d.ts + maps)
  wasm/node/             cquisitor_lib.cjs (+ .d.cts), cquisitor_lib_bg.wasm   — wasm-pack `nodejs`, glue renamed to .cjs
  wasm/browser/          cquisitor_lib.js, cquisitor_lib_bg.js, cquisitor_lib_bg.wasm (+ .d.ts, cquisitor_lib_bg.d.ts)   — wasm-pack `bundler`
  README.md, LICENSE
```

`exports["./wasm"]` is `{ node: { types: ….d.cts, default: ./wasm/node/cquisitor_lib.cjs }, browser: { types: ….d.ts, default: ./wasm/browser/cquisitor_lib.js }, default: { import: { types: ….d.ts, default: <the .cjs> }, types: ….d.cts, default: <the .cjs> } }`: each runtime file is typed by its own declarations, so TypeScript under `node16`/`nodenext` sees the CommonJS format Node loads. TypeScript under `bundler` resolution sets neither `node` nor `browser`, so it reads the `default` branch's `import` types: the ESM `.d.ts` (named exports only, which both runtime files provide), and a default import, which the browser glue lacks, fails at type-check instead of at bundle time. `exports["./wasm/browser/*"]` exposes the browser glue file by file (with `cquisitor_lib_bg.d.ts` typing the inner module) for manual instantiation. The library reaches its own wasm through that subpath (`import("@cardananium/cquisitor-lib/wasm")` in `lib/wasm/load.js`), which Node and TypeScript resolve by package self-reference inside `pkg/` and through `node_modules` once installed — hence no nested `package.json` anywhere under `pkg/`. `sideEffects` lists only the wasm glue and the Node worker entry.

## Low-level wasm exports (`/wasm`)

The typed API above is the recommended surface. The raw wasm exports remain available from `@cardananium/cquisitor-lib/wasm` (synchronous; some answer JSON text; `u64` values arrive as JS `BigInt`s or serde number boxes that the typed wrappers unbox). They are what `serveWasm` serves and what a `LibBackend` calls.


### Transaction Validation

#### `get_necessary_data_list_js(tx_hex: string, network_type: "mainnet" | "preview" | "preprod"): string`

Extracts required blockchain data for validation. `network_type` determines the bech32 prefix used when deriving stake/reward addresses for `accounts`, `pools`, and `dReps`.

```typescript
const necessaryData = JSON.parse(get_necessary_data_list_js(txHex, "mainnet"));
// Returns: { utxos, accounts, pools, dReps, govActions, ... }
```

#### `validate_transaction_js(tx_hex: string, validation_context: string): string`

Validates transaction with full ledger rules.

```typescript
const result = JSON.parse(validate_transaction_js(txHex, JSON.stringify(context)));
// Returns: { errors, warnings, phase2_errors, phase2_warnings, eval_redeemer_results }
```

#### `get_utxo_list_from_tx(tx_hex: string): string[]`

Extracts all UTxO references (inputs + collateral + reference inputs) from transaction.

#### `get_ref_script_bytes(tx_hex: string, output_index: number): string`

Returns the hex-encoded CBOR bytes of the reference script embedded in `outputs[output_index]`. Returns an empty string if the output has no reference script or the index is out of range.

```typescript
const scriptHex = get_ref_script_bytes(txHex, 0);
```

#### `extract_hashes_from_transaction_js(tx_hex: string): string`

Returns a JSON-serialized `ExtractedHashes` with every script / datum / redeemer / metadata / auxiliary-data hash referenced by the transaction (witness set, outputs with inline scripts/datums, auxiliary data). Useful for building indexers or caches.

```typescript
const hashes = JSON.parse(extract_hashes_from_transaction_js(txHex));
// { witness_native_script_hashes, witness_plutus_scripts, witness_datum_hashes, ... }
```

### Universal Decoder

#### `get_decodable_types(): string[]`

Returns the names of every decodable type (149 in this release).

```typescript
const types = get_decodable_types();
// ['Address', 'Transaction', 'PlutusScript', 'PublicKey', ...]
```

#### `decode_specific_type(input: string, type_name: string, params: DecodingParams): JsonText<unknown>`

Decodes specific Cardano type from hex/bech32/base58.

Answers JSON text (the typed `decode` parses it exactly). Hex input nested more than 64 levels below its root outside the native scripts the type holds is refused with a thrown message naming the limit rather than decoded: parts of the decoding recurse on the host's stack over Plutus data and metadata, and a WebKit Web Worker's stack is the smallest this runs on, so the document is scanned for its depth first. An implementation limit, never a verdict on the bytes. Native scripts are read and rendered without recursion: a `NativeScript`, or a transaction, witness set, output or auxiliary data holding one, decodes at any depth up to 32 768 CBOR levels for the whole input (about 16 380 `ScriptAll` levels; a maximum-size mainnet transaction holds about 5 430).

```typescript
const address = JSON.parse(decode_specific_type("addr1...", "Address", {}));

const { transaction_hash, transaction } = parseJsonExact(decode_specific_type(
    "84a400...",
    "Transaction",
    { plutus_data_schema: "DetailedSchema" }
));
```

#### `get_possible_types_for_input(input: string): string[]`

Suggests which types can decode the given input. A type whose reading of hex input nests more than 64 levels below its root outside the native scripts it holds is not tried; `get_possible_types_report(input)` (typed: `possibleTypesReport`) answers `{ types, unexamined? }` with `unexamined: { kind: "nesting_too_deep", limit, depth?, message, types }` listing the types not tried, to tell them apart from "does not decode as".

```typescript
const possibleTypes = get_possible_types_for_input("e1a...");
// ['Address', 'BaseAddress', 'EnterpriseAddress', ...]
```

### CBOR Decoder

The four exports that walk a CBOR document — `cbor_to_json`, `validate_cbor_against_cddl`, `decode_cbor_against_cddl` and `map_cbor_to_cddl` — answer with the **JSON text** of their result rather than the object: `JSON.parse` the string to get the shape documented below. A decoded tree nests as deep as the document does, and text is the one form of it that crosses every boundary on its way to a caller — the wasm boundary, a `postMessage` to another thread, a `structuredClone` — at a cost of bytes and never of depth, where the object form fails a structured clone at a few hundred levels. An integer a JavaScript number does not hold exactly is written as `{"$serde_json::private::Number": "<digits>"}`; convert the boxes after parsing, with an explicit stack if the document may be deep. Every other export returns the object it documents.

#### `cbor_to_json(cbor_hex: string): JsonText<CborDecodeResult>`

Converts CBOR to JSON with positional metadata. Each node has `position_info` (byte span of its header) and, for containers/tags, `struct_position_info` (span of the whole subtree). Non-canonical encoding deviations (per RFC 8949 §4.1/§4.2) are flagged locally on the offending node via an optional `oddities: CborOddity[]` field — canonical inputs omit the field entirely.

The function **never throws** on malformed input. On success it returns `{ ok: true, value }`; on failure `{ ok: false, error, partial? }` where `error` is a structured `CborDecodeError` and `partial` is the sub-tree decoded up to the failure point:

```typescript
const r: CborDecodeResult = JSON.parse(cbor_to_json("a26461646472..."));
if (r.ok) {
    // r.value — the full positional tree; each node may carry oddities like:
    //   { kind: "IntNotShortest",    detail: "value 15 uses 2-byte header, shortest is 1" }
    //   { kind: "IndefiniteLength",  detail: "indefinite-length map" }
    //   { kind: "MapKeysNotSorted",  detail: "key at offset 3 sorts after key at offset 5" }
    //   { kind: "DuplicateMapKeys",  detail: "duplicate key at offsets 3 and 6" }
    //   { kind: "BignumForSmallInt", detail: "unsigned bignum fits in a native CBOR integer" }
} else {
    // r.error: { kind, offset?, byte_span?, path, message }
    //   kind       — machine-readable tag ("invalid_syntax", "unexpected_eof", ...).
    //   offset     — byte where decoding stopped.
    //   byte_span  — { offset, length } when the failure pins a range.
    //   path       — structural location, e.g. "$.entries[1].value[0]".
    // r.partial (optional) — same shape as a CborValue, but every unfinished
    //   container carries `incomplete: true`, and partial map entries carry
    //   `incomplete_at: "key" | "value"` on the half that didn't parse.
}
```

See `CborOddityKind` and `CborDecodeErrorKind` in the type definitions for the full lists.

#### `validate_cddl(cddl: string): { valid: boolean, error?: object }`

Parses a CDDL schema and reports whether it is well-formed. Beyond surface parse errors this also catches **dangling rule references** at parse time, surfaced as `kind: "unresolved_references"`.

```typescript
validate_cddl("thing = {n: uint}");
// { valid: true }

validate_cddl("thing = [unknown_rule, int]");
// { valid: false, error: { kind: "unresolved_references",
//                           message: "missing definition for rule unknown_rule" } }

validate_cddl("; only a comment\n");
// { valid: false, error: { kind: "no_rules",
//                           message: "CDDL document defines no rules" } }
```

Parser errors include a `byte_span: {offset, length, line}` so editors can squiggle the exact position pest tripped on.

`error.kind` values: `"parse_error"`, `"unresolved_references"`, `"no_rules"`, `"nesting_too_deep"` (brackets nested past what the parser is run on; an implementation limit, not a verdict on the schema).

#### `validate_cbor_against_cddl(cbor_hex: string, cddl: string, rule_name: string): JsonText<CborValidationResult>`

Validates a CBOR payload against a specific rule in a CDDL schema. The rule does not have to be the first rule in the document — when it isn't, the validator wraps it in a synthetic root internally.

```typescript
JSON.parse(validate_cbor_against_cddl("01", "thing = tstr", "thing"));
// {
//   valid: false,
//   error: {
//     kind: "mismatch",
//     expected: "tstr",
//     path: "$",
//     byte_spans: [{ offset: 0, length: 1 }],
//     anchor_spans: [{ offset: 0, length: 1 }],
//     cddl_byte_span: { offset: 8, length: 4, char_offset: 8, char_length: 4, line: 1 },  // points at `tstr`
//     message: "expected type tstr, got 1"
//   }
// }
```

`error.cddl_byte_span` carries the byte range in the **CDDL source** pointing at the type the validator tried (and failed) to apply — useful for highlighting the offending rule in an editor. It's synthesised by walking the AST in parallel with `path`, so it's available for any error that has a meaningful `path`. When the `rule_name` you passed isn't the first rule of the document, the offsets are still expressed in *your* CDDL coordinates (the wrapper we use internally is invisible to callers).

`error.kind` values: `"parse_error"`, `"unresolved_references"`, `"no_rules"`, `"missing_rule"`, `"group_rule_root"` (the rule named is a group, not a data item), `"input_parse"`, `"invalid_schema"` (a control operator's operand stands for no usable value), `"nesting_too_deep"` and `"validation_too_complex"` (implementation limits, never a verdict on the data), `"mismatch"`, `"map_cut"`, `"generic"`. See `CborValidationErrorInfo` in the type definitions for each. When multiple violations fire, the headline goes in the top-level fields and the rest land in `error.additional`.

`anchor_spans` is always populated — for container values (Map / Array / Tag / indefinite strings) it covers the whole structure; for scalars it falls back to `position_info` so a UI's halo highlight always has something to draw.

#### `decode_cbor_against_cddl(cbor_hex: string, cddl: string, rule_name: string): JsonText<CborDecodeAgainstCddlResult>`

Walks the CDDL alongside the decoded CBOR and produces a JSON tree where positional/numeric-keyed structures are replaced with the names the schema declares. Useful for turning a Cardano transaction CBOR into something inspectable without hand-mapping every field.

```typescript
JSON.parse(decode_cbor_against_cddl(txHex, conwayCddl, "transaction")).value;
// {
//   transaction_body: {
//     0: { "@tag": 258, "@value": [{ transaction_id: "16b6...", index: 0 }] },
//     1: [{ address: "00ae...", amount: 1_000_000 }, ...],
//     2: 200000,
//     7: "bdaa..."
//   },
//   transaction_witness_set: {
//     0: { "@tag": 258, "@value": [{ vkey: "f8f5...", signature: "1e14..." }] }
//   },
//   "@positional": [true, { "@tag": 259, "@value": {} }]
// }
```

Recognised features: type choices (first match wins), generics (`set<a>`), tagged data (well-known tags 0/2/3 specialised to ISO date / bignum string), rule references, optionals/repetitions, prelude scalars. Sub-structures the schema doesn't cover or that don't match any choice fall back to a raw form under `@extra` (maps) or `@positional` (arrays) so data is never silently dropped.

#### CDDL editor primitives

For embedding a CDDL editor / inspector. All four functions parse the document with the same checked parser as `validate_cddl` and throw on parse errors.

```typescript
// Document outline — list every rule with its byte range.
cddl_outline("alpha = uint\nbeta = (a: int)");
// [
//   {name: "alpha", kind: "type",  span: {offset: 0,  length: 12, line: 1},
//                                  name_span: {offset: 0, length: 5, line: 1}},
//   {name: "beta",  kind: "group", span: {offset: 13, length: 14, line: 2},
//                                  name_span: {offset: 13, length: 4, line: 2}}
// ]

// Find every use of a rule — the IDE "Find references" affordance.
cddl_references("coin = uint\noutput = [bstr, coin]\nfee = coin", "coin");
// {definition: {offset: 0, length: 4, line: 1},
//  uses: [
//    {offset: 26, length: 4, line: 2},
//    {offset: 38, length: 4, line: 3}
//  ]}

// Symbol at cursor — hover info and Cmd-click target.
cddl_symbol_at("coin = uint\nfee = coin", /* offset = */ 18);
// {name: "coin", kind: "rule_reference", role: "use",
//  span: {offset: 18, length: 4, line: 2},
//  definition_span: {offset: 0, length: 4, line: 1},
//  rule_span: {offset: 0, length: 11, line: 1}}

// Re-format — round-trip via Display. Comments survive
// (both standalone `; …` and trailing `; …`).
cddl_format("; header\nalpha   =   uint ; trailing");
// "; header\nalpha = uint ; trailing\n"
```

`validate_cddl` itself returns a `byte_span` on parser errors so editor-side squiggles can underline the offending position directly:

```typescript
validate_cddl("alpha = ");
// {valid: false,
//  error: {kind: "parse_error", message: "...", byte_span: {offset: 8, length: 0, line: 1}}}
```

### Plutus Script Decoder

#### `decode_plutus_program_uplc_json(hex: string): ProgramJson`

Decodes Plutus script to UPLC AST in JSON format.

```typescript
const program = decode_plutus_program_uplc_json("59012a01000...");
// Returns: { program: { version: "1.0.0", term: { apply: { ... } } } }
```

#### `decode_plutus_program_pretty_uplc(hex: string): string`

Decodes Plutus script to human-readable UPLC.

```typescript
const code = decode_plutus_program_pretty_uplc("59012a01000...");
// Returns: "(program\n  1.0.0\n  [\n    (lam i_0 ...", indented over several lines
```

### Signature Verification

#### `check_block_or_tx_signatures(hex: string): CheckSignaturesResult`

Verifies all signatures in transaction or block.

```typescript
const result = check_block_or_tx_signatures(txHex);
// Returns: { valid, tx_hash?, invalidVkeyWitnesses?, invalidCatalystWitnesses? }
// Each list is left out when empty (so both are absent for a valid transaction).
// For a block: the first transaction with a bad signature, or
// { valid: true, tx_hash: "All block txs are valid" }.
```

### Script Execution

#### `execute_tx_scripts(tx_hex: string, utxos: UTxO[], cost_models: CostModels): ExecuteTxScriptsRawResult`

Executes all Plutus scripts in transaction, with the builtin semantics and costing of protocol version 11 (no protocol version is taken). One entry per redeemer; every integer is a decimal string here (the typed `executeTxScripts` reads them as numbers).

```typescript
const result = execute_tx_scripts(txHex, utxos, costModels);
// [{ original_ex_units: { steps: "133455086", mem: "310608" },
//    calculated_ex_units: { steps: "117002990", mem: "310608" },   // or `error: string` when the script failed
//    redeemer_index: "2", redeemer_tag: "Spend" }, ...]
```

## Data Sources

To populate the validation context, you'll need to fetch blockchain data from a Cardano indexer or node. Recommended sources:

- **[Blockfrost](https://blockfrost.io/)** - Reliable API with generous free tier
- **[Koios](https://koios.rest/)** - Community-driven API with rich queries
- **Cardano Node** - Direct access via `cardano-cli` or `cardano-db-sync`
- **Custom Indexer** - Roll your own using Pallas or similar libraries

## Consumer notes

* `moduleResolution: "NodeNext"`, `"Node16"` and `"bundler"` resolve every subpath and its types (under `node16`/`nodenext`, `./wasm` is typed by the `.d.cts` that matches the CommonJS file Node loads, so `import x = require("@cardananium/cquisitor-lib/wasm")` compiles in a `.cts`; under `bundler` it is typed by the ESM `.d.ts`, so only named imports compile, as only they work in a browser bundle); legacy `"node10"` resolution is covered by `typesVersions`. The shipped `.d.ts` type-check with `skipLibCheck: false`.
* `createNodeWorkerBackend` spawns its worker with `execArgv: []` by default — Node's default inherits the parent's flags, and `--input-type`, `--eval` & co. are illegal in a worker.

## Migrating from 0.1.0-beta.64

0.1.0-beta.64 and earlier shipped the raw wasm bindings as the whole package, at the root only: a CommonJS module for Node (the `node` and `default` conditions) and the bundler glue for browsers, every function synchronous and `snake_case`, some answering JSON text. The root is now the typed, async, ESM library described above.

| 0.1.0-beta.64 | Now |
|---|---|
| `import { cbor_to_json, validate_transaction_js, … } from "@cardananium/cquisitor-lib"` (raw wasm at the root) | the same raw exports from `@cardananium/cquisitor-lib/wasm`, unchanged; or the typed API from the root: `cborToJson`, `validateTransaction`, … (async, parsed, exact integers) |
| `const lib = require("@cardananium/cquisitor-lib")` (CommonJS root) | the root is ESM: `import` it, `require()` it on Node >= 22.12, or `await import()` it on Node 20, where `require()` now throws `ERR_REQUIRE_ESM`. `require("@cardananium/cquisitor-lib/wasm")` still works everywhere |
| `JSON.parse(cbor_to_json(hex))` and friends (integers past 2^53 rounded, serde number boxes left in) | `await cborToJson(hex)`, or `parseJsonExact(text)` (`/util`) on the raw text |
| `validate_transaction_js(txHex, JSON.stringify(context))` | `await validateTransaction(txHex, context)` (`bigint` fields serialised exactly), or `validateTransactionOnline({ txHex, network, provider })` to fetch the context too |
| `execute_tx_scripts(…)` typed `redeemer_index: number`, `ExUnits` as `bigint` (the values were decimal strings) | raw: `ExecuteTxScriptsRawResult`, strings as they are; typed `executeTxScripts(…)`: numbers (`bigint` past 2^53) |
| wasm in the calling thread only | the same by default; `configure({ backend: createWorkerBackend(…) })` (browser) or `createNodeWorkerBackend(…)` (`/node`) moves it to a worker |

## Building from Source

### Prerequisites

- Rust 1.83 or newer
- `wasm-pack`, `jq`
- Node.js >= 20 and npm (Bun for the TypeScript tests)

### Build Steps

```bash
# Clone the repository
git clone https://github.com/your-org/cquisitor-lib.git
cd cquisitor-lib

# Build for Node.js
npm run rust:build-wasm:node

# Build for browser
npm run rust:build-wasm:browser

# Build both targets, the TypeScript library and assemble pkg/ + the tarball
npm run build-all

# Generate TypeScript definitions
npm run generate-dts

# TypeScript library only
npm run lib:typecheck && npm run lib:test && npm run assemble
```

## Type Definitions

Full TypeScript type definitions ship with the package and cover every input and output type; all of them are exported from the root (and from `@cardananium/cquisitor-lib/wasm`). The main types include:

- `NecessaryInputData` - Required blockchain data for validation
- `ValidationInputContext` - Complete validation context structure
- `ValidationResult` - Validation results with errors and warnings
- `ProtocolParameters` - Cardano protocol parameters
- And many more detailed types for UTXOs, certificates, governance, etc.

See [types/cquisitor_lib.d.ts](./types/cquisitor_lib.d.ts) for the complete declarations (the half below `///AUTOGENERATED` is generated from `schemas/`).

## Performance

Written in Rust and compiled to WebAssembly for near-native performance in browsers and Node.js.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`cargo test --lib`; `npm run lib:typecheck && npm run lib:test` for the TypeScript library)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](./LICENSE) file for details.

## Acknowledgments

This library builds upon the excellent work of the Cardano community, particularly:

- [cardano-serialization-lib](https://github.com/Emurgo/cardano-serialization-lib) (18.0.0-beta.1) - For cardano structures deserialization
- [pallas](https://github.com/txpipe/pallas) - For the Plutus evaluator's view of a transaction; all pallas crates come from a fork of 0.35.1 (branch `cquisitor/stack-safe-native-script`, patched in via `[patch.crates-io]`) with a stack-safe `NativeScript` codec and an `i64` `ScriptNOfK` count
- [Pallas](https://github.com/txpipe/pallas) - Cardano primitives
- [UPLC](https://github.com/aiken-lang/aiken/tree/v1.1.24/crates/uplc) (v1.1.24) - Plutus script execution
- The Cardano Ledger specification team

## Support

For questions and support:

- 📖 Check the [API Documentation](./API_DOCUMENTATION.md)
- 🐛 Report bugs via [GitHub Issues](https://github.com/cardananium/cquisitor-lib/issues)

---

Made with ❤️ for the Cardano ecosystem


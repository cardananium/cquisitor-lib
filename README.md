# Cquisitor-lib

A Cardano transaction validation and decoding library written in Rust and compiled to WebAssembly. Provides transaction validation according to ledger rules (Phase 1 and Phase 2), universal CBOR/Cardano type decoders, Plutus script decoders, and signature verification.

## Features

### Transaction Validation

Phase 1 validation covers balance, fees, witnesses, collateral, certificates, outputs, and transaction limits. Phase 2 executes Plutus V1/V2/V3 scripts with detailed redeemer results.

### Universal Decoder

Decode 152+ Cardano types from hex/bech32/base58 encoding:
- Primitive types: `Address`, `PublicKey`, `PrivateKey`, `TransactionHash`, `ScriptHash`, etc.
- Complex structures: `Transaction`, `Block`, `TransactionBody`, `TransactionWitnessSet`
- Certificates: `StakeRegistration`, `PoolRegistration`, `DRepRegistration`, governance actions
- Plutus: `PlutusScript`, `PlutusData`, `Redeemer`, `ScriptRef`
- All credential types, native scripts, metadata structures

Functions:
- `get_decodable_types()` - Returns list of all supported type names
- `decode_specific_type(hex, type_name, params)` - Decode specific Cardano type
- `get_possible_types_for_input(hex)` - Suggests types that can decode given input

### CBOR Decoder & CDDL Validation

- `cbor_to_json(cbor_hex)` - Converts raw CBOR to JSON with positional information, supporting indefinite arrays/maps and all CBOR types. Each node carries an optional `oddities` array flagging deviations from RFC 8949 deterministic encoding (overlong integers/floats, indefinite length, unsorted/duplicate map keys, non-canonical bignums). Never throws on malformed input — returns a `{ok, value}` / `{ok: false, error, partial?}` union where `error` is a structured `CborDecodeError` (kind / byte offset / byte span / semantic `path`) and `partial` is the sub-tree decoded before the failure, with every unfinished container flagged `incomplete: true`.
- `validate_cddl(cddl)` - Parses a CDDL schema; reports parse errors (with a `byte_span` for editor squiggles) and unresolved rule references (e.g. `thing = [unknown_rule, int]` → `kind: "unresolved_references"`).
- `validate_cbor_against_cddl(cbor_hex, cddl, rule_name)` - Validates a CBOR payload against a named rule. Errors carry `kind`, `expected`, semantic `path`, byte/anchor spans, a `cddl_byte_span` pointing at the failing CDDL type, and an `additional` array when multiple violations fire.
- `decode_cbor_against_cddl(cbor_hex, cddl, rule_name)` - Maps decoded CBOR onto a CDDL schema and returns labelled JSON (e.g. Cardano `[body, witness_set, bool, aux]` becomes `{transaction_body, transaction_witness_set, ...}`). Handles generics (`set<a>`), tagged sets, type rules used as field labels, and a few well-known tags (bignum → string number, datetime → ISO string). Sub-structures the schema doesn't cover surface under `@extra` / `@positional` so partial matches don't lose data.
- `cddl_outline(cddl)` - Returns one `{name, kind, span, name_span}` entry per top-level rule. Editor outline view, breadcrumbs, fuzzy "go to rule".
- `cddl_references(cddl, name)` - Returns `{definition, uses[]}` byte ranges for a rule name. Powers find-references and same-name highlighting on cursor.
- `cddl_symbol_at(cddl, offset)` - Returns the symbol under the cursor (or `null`), with `role: "definition" | "use"` and a `definition_span` pointing at its rule. Powers hover and Cmd-click go-to-definition.
- `cddl_format(cddl)` - Pretty-prints CDDL by round-tripping through the AST. Useful for format-on-save.

### Plutus Script Decoder

- `decode_plutus_program_uplc_json(hex)` - Decodes Plutus script to UPLC AST JSON
- `decode_plutus_program_pretty_uplc(hex)` - Decodes to human-readable UPLC format

Handles double CBOR wrapping and normalization automatically.

### Signature Verification

`check_block_or_tx_signatures(hex)` - Verifies all VKey and Catalyst witness signatures in transactions or entire blocks. Returns validation results with invalid signature details.

### Script Execution

`execute_tx_scripts(tx_hex, utxos, cost_models)` - Executes all Plutus scripts in a transaction independently, returning execution units, logs, and success/failure for each redeemer.

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
- Plutus V1, V2, and V3 script execution
- Redeemer validation with execution units
- Script context generation

See [WHAT-IS-COVERED.md](./WHAT-IS-COVERED.md) for a complete list of validation errors and warnings.

## Installation

### NPM/Yarn/PNPM

```bash
npm install @cardananium/cquisitor-lib
```

```bash
yarn add @cardananium/cquisitor-lib
```

```bash
pnpm add @cardananium/cquisitor-lib
```

### Browser

For browser usage, import from the browser-specific build:

```javascript
import { get_necessary_data_list_js, validate_transaction_js } from '@cardananium/cquisitor-lib/browser';
```

### Node.js

For Node.js usage:

```javascript
import { get_necessary_data_list_js, validate_transaction_js } from '@cardananium/cquisitor-lib';
```

## Quick Start

### Basic Usage

```typescript
import { 
    get_necessary_data_list_js, 
    validate_transaction_js 
} from '@cardananium/cquisitor-lib';

// Step 1: Parse transaction and identify required data
const txHex = "84a400..."; // Your transaction in hex format
const networkType = "mainnet"; // or "preview" | "preprod"
const necessaryDataJson = get_necessary_data_list_js(txHex, networkType);
const necessaryData = JSON.parse(necessaryDataJson);

console.log('Required UTXOs:', necessaryData.utxos);
console.log('Required accounts:', necessaryData.accounts);
console.log('Required pools:', necessaryData.pools);

// Step 2: Fetch the required data from your blockchain indexer
// (e.g., Blockfrost, Koios, or your own node)
const utxos = await fetchUtxos(necessaryData.utxos);
const accounts = await fetchAccounts(necessaryData.accounts);
const pools = await fetchPools(necessaryData.pools);
const protocolParams = await getProtocolParameters();
const currentSlot = await getCurrentSlot();

// Step 3: Build validation context
const validationContext = {
    slot: currentSlot,
    networkType: "mainnet", // or "preview" or "preprod"
    protocolParameters: protocolParams,
    utxoSet: utxos,
    accountContexts: accounts,
    poolContexts: pools,
    drepContexts: [],
    govActionContexts: [],
    lastEnactedGovAction: [],
    currentCommitteeMembers: [],
    potentialCommitteeMembers: [],
    treasuryValue: 0n
};

// Step 4: Validate the transaction
const resultJson = validate_transaction_js(
    txHex, 
    JSON.stringify(validationContext)
);
const result = JSON.parse(resultJson);

// Step 5: Check validation results
if (result.errors.length > 0) {
    console.error('❌ Transaction validation failed:');
    result.errors.forEach(err => {
        console.error(`- ${err.error_message}`);
        if (err.hint) {
            console.error(`  Hint: ${err.hint}`);
        }
    });
} else if (result.phase2_errors.length > 0) {
    console.error('❌ Script execution failed:');
    result.phase2_errors.forEach(err => {
        console.error(`- ${err.error_message}`);
    });
} else {
    console.log('✅ Transaction is valid!');
}

// Check for warnings
if (result.warnings.length > 0) {
    console.warn('⚠️  Warnings:', result.warnings);
}
```

### Complete Example with Error Handling

```typescript
import { 
    get_necessary_data_list_js, 
    validate_transaction_js 
} from '@cardananium/cquisitor-lib';

async function validateTransaction(txHex: string): Promise<boolean> {
    try {
        // Parse transaction
        const necessaryDataJson = get_necessary_data_list_js(txHex, "mainnet");
        const necessaryData = JSON.parse(necessaryDataJson);
        
        // Fetch required blockchain data
        // (Implementation depends on your data source)
        const context = await buildValidationContext(necessaryData);
        
        // Validate
        const resultJson = validate_transaction_js(
            txHex, 
            JSON.stringify(context)
        );
        const result = JSON.parse(resultJson);
        
        // Log detailed results
        const hasErrors = result.errors.length > 0 || result.phase2_errors.length > 0;
        
        if (!hasErrors) {
            console.log('✅ Transaction is valid!');
            
            // Log redeemer execution details
            result.eval_redeemer_results.forEach(redeemer => {
                console.log(`Redeemer ${redeemer.tag}[${redeemer.index}]:`);
                console.log(`  Success: ${redeemer.success}`);
                console.log(`  Ex units: ${JSON.stringify(redeemer.calculated_ex_units)}`);
                if (redeemer.logs.length > 0) {
                    console.log(`  Logs: ${redeemer.logs.join(', ')}`);
                }
            });
        } else {
            console.error('❌ Validation failed');
            [...result.errors, ...result.phase2_errors].forEach(err => {
                console.error(`- ${err.error_message}`);
            });
        }
        
        return !hasErrors;
        
    } catch (error) {
        console.error('Validation error:', error);
        return false;
    }
}
```

## API Reference

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

Returns array of all 152+ decodable type names.

```typescript
const types = get_decodable_types();
// ['Address', 'Transaction', 'PlutusScript', 'PublicKey', ...]
```

#### `decode_specific_type(input: string, type_name: string, params: DecodingParams): any`

Decodes specific Cardano type from hex/bech32/base58.

```typescript
const address = decode_specific_type(
    "addr1...", 
    "Address", 
    { plutusDataSchema: "DetailedSchema" }
);

const tx = decode_specific_type(
    "84a400...", 
    "Transaction", 
    { plutusDataSchema: "DetailedSchema" }
);
```

#### `get_possible_types_for_input(input: string): string[]`

Suggests which types can decode the given input.

```typescript
const possibleTypes = get_possible_types_for_input("e1a...");
// ['Address', 'BaseAddress', 'EnterpriseAddress', ...]
```

### CBOR Decoder

#### `cbor_to_json(cbor_hex: string): CborDecodeResult`

Converts CBOR to JSON with positional metadata. Each node has `position_info` (byte span of its header) and, for containers/tags, `struct_position_info` (span of the whole subtree). Non-canonical encoding deviations (per RFC 8949 §4.1/§4.2) are flagged locally on the offending node via an optional `oddities: CborOddity[]` field — canonical inputs omit the field entirely.

The function **never throws** on malformed input. On success it returns `{ ok: true, value }`; on failure `{ ok: false, error, partial? }` where `error` is a structured `CborDecodeError` and `partial` is the sub-tree decoded up to the failure point:

```typescript
const r = cbor_to_json("a26461646472...");
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

`error.kind` values: `"parse_error"`, `"unresolved_references"`, `"no_rules"`.

#### `validate_cbor_against_cddl(cbor_hex: string, cddl: string, rule_name: string): { valid: boolean, error?: object }`

Validates a CBOR payload against a specific rule in a CDDL schema. The rule does not have to be the first rule in the document — when it isn't, the validator wraps it in a synthetic root internally.

```typescript
validate_cbor_against_cddl("01", "thing = tstr", "thing");
// {
//   valid: false,
//   error: {
//     kind: "mismatch",
//     expected: "tstr",
//     path: "$",
//     byte_spans: [{ offset: 0, length: 1 }],
//     cddl_byte_span: { offset: 8, length: 4, line: 1 },  // points at `tstr`
//     message: "expected type tstr, got Integer(Integer(1))"
//   }
// }
```

`error.cddl_byte_span` carries the byte range in the **CDDL source** pointing at the type the validator tried (and failed) to apply — useful for highlighting the offending rule in an editor. It's synthesised by walking the AST in parallel with `path`, so it's available for any error that has a meaningful `path`. When the `rule_name` you passed isn't the first rule of the document, the offsets are still expressed in *your* CDDL coordinates (the wrapper we use internally is invisible to callers).

`error.kind` values: `"parse_error"`, `"unresolved_references"`, `"no_rules"`, `"missing_rule"`, `"input_parse"`, `"mismatch"`, `"map_cut"`, `"generic"`. When multiple violations fire, the headline goes in the top-level fields and the rest land in `error.additional`.

`anchor_spans` is always populated — for container values (Map / Array / Tag / indefinite strings) it covers the whole structure; for scalars it falls back to `position_info` so a UI's halo highlight always has something to draw.

#### `decode_cbor_against_cddl(cbor_hex: string, cddl: string, rule_name: string): unknown`

Walks the CDDL alongside the decoded CBOR and produces a JSON tree where positional/numeric-keyed structures are replaced with the names the schema declares. Useful for turning a Cardano transaction CBOR into something inspectable without hand-mapping every field.

```typescript
decode_cbor_against_cddl(txHex, conwayCddl, "transaction");
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
// Returns: { version: [1,0,0], program: { ... } }
```

#### `decode_plutus_program_pretty_uplc(hex: string): string`

Decodes Plutus script to human-readable UPLC.

```typescript
const code = decode_plutus_program_pretty_uplc("59012a01000...");
// Returns: "(program 1.0.0 (lam x_0 ...))"
```

### Signature Verification

#### `check_block_or_tx_signatures(hex: string): CheckSignaturesResult`

Verifies all signatures in transaction or block.

```typescript
const result = check_block_or_tx_signatures(txHex);
// Returns: { valid, results: [{ valid, tx_hash, invalidVkeyWitnesses, invalidCatalystWitnesses }] }
```

### Script Execution

#### `execute_tx_scripts(tx_hex: string, utxos: UTxO[], cost_models: CostModels): ExecuteTxScriptsResult`

Executes all Plutus scripts in transaction.

```typescript
const result = execute_tx_scripts(txHex, utxos, costModels);
// Returns execution units, logs, and status for each redeemer
```

## Data Sources

To populate the validation context, you'll need to fetch blockchain data from a Cardano indexer or node. Recommended sources:

- **[Blockfrost](https://blockfrost.io/)** - Reliable API with generous free tier
- **[Koios](https://koios.rest/)** - Community-driven API with rich queries
- **Cardano Node** - Direct access via `cardano-cli` or `cardano-db-sync`
- **Custom Indexer** - Roll your own using Pallas or similar libraries

## Building from Source

### Prerequisites

- Rust 1.83 or newer 
- `wasm-pack` 
- Node.js and npm 

### Build Steps

```bash
# Clone the repository
git clone https://github.com/your-org/cquisitor-lib.git
cd cquisitor-lib

# Build for Node.js
npm run rust:build-wasm:node

# Build for browser
npm run rust:build-wasm:browser

# Build both targets
npm run build-all

# Generate TypeScript definitions
npm run generate-dts
```

## Type Definitions

Full TypeScript type definitions are available in the package and cover all input and output types. The main types include:

- `NecessaryInputData` - Required blockchain data for validation
- `ValidationInputContext` - Complete validation context structure
- `ValidationResult` - Validation results with errors and warnings
- `ProtocolParameters` - Cardano protocol parameters
- And many more detailed types for UTXOs, certificates, governance, etc.

See [types/cquisitor_lib.d.ts](./types/cquisitor_lib.d.ts) for the complete type definitions.

## Performance

Written in Rust and compiled to WebAssembly for near-native performance in browsers and Node.js.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`cargo test`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](./LICENSE) file for details.

## Acknowledgments

This library builds upon the excellent work of the Cardano community, particularly:

- [cardano-serialization-lib](https://github.com/Emurgo/cardano-serialization-lib) - For cardano structures deserialization
- [Pallas](https://github.com/txpipe/pallas) - Cardano primitives
- [UPLC](https://github.com/aiken-lang/aiken/tree/main/crates/uplc) - Plutus script execution
- The Cardano Ledger specification team

## Support

For questions and support:

- 📖 Check the [API Documentation](./API_DOCUMENTATION.md)
- 🐛 Report bugs via [GitHub Issues](https://github.com/cardananium/cquisitor-lib/issues)

---

Made with ❤️ for the Cardano ecosystem


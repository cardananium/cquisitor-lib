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

### CBOR Decoder

`cbor_to_json(cbor_hex)` - Converts raw CBOR to JSON with positional information, supporting indefinite arrays/maps and all CBOR types.

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
const necessaryDataJson = get_necessary_data_list_js(txHex);
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
        const necessaryDataJson = get_necessary_data_list_js(txHex);
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

#### `get_necessary_data_list_js(tx_hex: string): string`

Extracts required blockchain data for validation.

```typescript
const necessaryData = JSON.parse(get_necessary_data_list_js(txHex));
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

#### `cbor_to_json(cbor_hex: string): CborValue`

Converts CBOR to JSON with positional metadata.

```typescript
const cbor = cbor_to_json("a26461646472...");
// Returns structured JSON with position info for each element
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


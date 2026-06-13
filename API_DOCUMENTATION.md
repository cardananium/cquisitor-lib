# API Documentation

## Table of Contents
- [get_necessary_data_list_js](#get_necessary_data_list_js)
- [validate_transaction_js](#validate_transaction_js)
- [add_witnesses_to_tx](#add_witnesses_to_tx)

---

## get_necessary_data_list_js

### Overview
Extracts a list of all necessary blockchain data required to validate a Cardano transaction. This function analyzes the transaction structure and identifies all UTXOs, accounts, stake pools, DReps, governance actions, and committee members that are referenced in the transaction.

### Signature
```typescript
function get_necessary_data_list_js(
    tx_hex: string,
    network_type: "mainnet" | "preview" | "preprod"
): string
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `tx_hex` | `string` | Hexadecimal-encoded Cardano transaction in CBOR format |
| `network_type` | `string` | Target network: `"mainnet"`, `"preview"`, or `"preprod"`. Used to derive stake/reward addresses (bech32 prefix) for `accounts`, `pools`, `dReps`. |

### Returns

Returns a JSON string representing a `NecessaryInputData` object with the following structure:

```typescript
interface NecessaryInputData {
    utxos: TxInput[];
    accounts: string[];
    pools: string[];
    dReps: string[];
    govActions: GovernanceActionId[];
    lastEnactedGovAction: GovernanceActionType[];
    committeeMembersCold: LocalCredential[];
    committeeMembersHot: LocalCredential[];
}
```

#### Field Descriptions

- **`utxos`**: Array of transaction inputs that need to be resolved
  - Includes regular inputs, collateral inputs, and reference inputs
  - Each element contains `txHash` and `outputIndex`

- **`accounts`**: Array of bech32-encoded reward account addresses
  - Includes accounts from withdrawals and certificates

- **`pools`**: Array of stake pool IDs (bech32 format)
  - Includes pools from delegation certificates and pool registration/retirement certificates

- **`dReps`**: Array of DRep identifiers (bech32 format)
  - Includes DReps from vote delegation certificates and voting procedures

- **`govActions`**: Array of governance action identifiers
  - Includes actions referenced in voting procedures and proposals

- **`lastEnactedGovAction`**: Array of governance action types
  - Types of the last enacted governance actions that the transaction may depend on

- **`committeeMembersCold`**: Array of cold credentials for committee members
  - Committee members whose cold keys are referenced in the transaction

- **`committeeMembersHot`**: Array of hot credentials for committee members
  - Committee members whose hot keys are referenced in the transaction

### Example Usage

```typescript
import { get_necessary_data_list_js } from 'cquisitor-lib';

// Example transaction hex
const txHex = "84a400..."; // Your transaction hex

try {
    const necessaryDataJson = get_necessary_data_list_js(txHex, "mainnet");
    const necessaryData = JSON.parse(necessaryDataJson);
    
    console.log('Required UTXOs:', necessaryData.utxos);
    console.log('Required accounts:', necessaryData.accounts);
    console.log('Required pools:', necessaryData.pools);
    
    // Fetch the required data from your blockchain data source
    // before calling validate_transaction_js
    
} catch (error) {
    console.error('Failed to get necessary data:', error);
}
```

### Error Handling

The function throws a `JsError` if:
- The transaction hex is malformed or cannot be parsed
- The transaction CBOR structure is invalid
- Serialization of the result fails

### Use Case

This function is typically used as a first step before transaction validation:

1. Parse the transaction to identify all required data
2. Fetch the identified data from a blockchain indexer or node
3. Construct a `ValidationInputContext` with the fetched data
4. Call `validate_transaction_js` with the transaction and context

This two-step approach allows for efficient data fetching, as you only retrieve the specific blockchain state that the transaction references.

### Data Sources

The data required to populate `ValidationInputContext` based on `NecessaryInputData` can be obtained from third-party blockchain APIs such as:

- **[Blockfrost](https://blockfrost.io/)** - Provides endpoints for UTXOs, accounts, pools, governance actions, and protocol parameters
- **[Koios](https://koios.rest/)** - Provides richer API to retrieve blockchain data 
- **Cardano Node** - Direct access via cardano-cli or cardano-db-sync
- **Other indexers** - Any service that provides Cardano blockchain state data

When using these APIs, map the `NecessaryInputData` fields as follows:
- `utxos` → Query UTxO endpoints with transaction hash and output index
- `accounts` → Query stake account endpoints with reward addresses
- `pools` → Query stake pool endpoints with pool IDs
- `dReps` → Query DRep endpoints (available on supported networks)
- `govActions` → Query governance action endpoints
- Additionally fetch current `protocolParameters` and set correct `slot` and `networkType` for the validation context

---

## validate_transaction_js

### Overview
Performs comprehensive validation of a Cardano transaction according to the Cardano ledger rules. This includes both Phase 1 validation (ledger rules, balances, fees, witnesses) and Phase 2 validation (Plutus script execution). The function checks the transaction against protocol parameters, UTXOs, accounts, pools, and governance state provided in the validation context.

### Signature
```typescript
function validate_transaction_js(
    tx_hex: string, 
    validation_context: string
): string
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `tx_hex` | `string` | Hexadecimal-encoded Cardano transaction in CBOR format |
| `validation_context` | `string` | JSON-encoded `ValidationInputContext` containing all blockchain state required for validation |

### Validation Context Structure

The `validation_context` parameter must be a JSON string representing the following structure:

```typescript
interface ValidationInputContext {
    slot: bigint;                           // Current blockchain slot
    networkType: NetworkType;               // "mainnet", "preview", or "preprod"
    protocolParameters: ProtocolParameters; // Current protocol parameters
    utxoSet: UtxoInputContext[];           // Referenced UTXOs
    accountContexts: AccountInputContext[]; // Stake account states
    poolContexts: PoolInputContext[];      // Stake pool states
    drepContexts: DrepInputContext[];      // DRep states
    govActionContexts: GovActionInputContext[]; // Governance action states
    lastEnactedGovAction: GovActionInputContext[]; // Last enacted actions
    currentCommitteeMembers: CommitteeInputContext[]; // Current committee
    potentialCommitteeMembers: CommitteeInputContext[]; // Potential committee
    treasuryValue: bigint;                 // Current treasury value
}
```

See the type definitions file for detailed structures of nested types.

### Returns

Returns a JSON string representing a `ValidationResult` object:

```typescript
interface ValidationResult {
    errors: ValidationPhase1Error[];
    warnings: ValidationPhase1Warning[];
    phase2_errors: ValidationPhase2Error[];
    phase2_warnings: ValidationPhase2Warning[];
    eval_redeemer_results: EvalRedeemerResult[];
}
```

#### Result Fields

- **`errors`**: Array of Phase 1 validation errors
  - Includes balance errors, fee errors, witness errors, collateral errors, etc.
  - Any error in this array means the transaction is invalid

- **`warnings`**: Array of Phase 1 validation warnings
  - Non-critical issues (e.g., fee is higher than necessary)
  - Transaction may still be valid but might be sub-optimal

- **`phase2_errors`**: Array of Phase 2 (Plutus script) validation errors
  - Script execution failures, budget exceeded, missing cost models, etc.
  - Any error here means the transaction is invalid

- **`phase2_warnings`**: Array of Phase 2 validation warnings
  - Script budget is higher than needed, etc.

- **`eval_redeemer_results`**: Detailed results for each redeemer execution
  - Contains success/failure status, execution units, error messages, and logs

### Validation Phases

The validation process is performed in the following order:

#### Phase 1 Validation

1. **Balance Validation**
   - Verifies that total inputs equal total outputs plus fees
   - Checks value conservation for all assets (ADA and multi-assets)
   - Validates withdrawal amounts match account balances
   - Checks deposits and refunds
   - Validates treasury value if specified

2. **Fee Validation**
   - Calculates minimum required fee based on transaction size
   - Includes reference script fees and execution unit fees
   - Verifies the declared fee meets or exceeds minimum

3. **Witness Validation**
   - Checks all required VKey witnesses are present
   - Validates signature correctness
   - Executes native scripts
   - Checks for missing or extraneous witnesses
   - Validates script witnesses

4. **Collateral Validation**
   - Verifies collateral inputs are provided when Plutus scripts are present
   - Checks collateral contains only ADA (no multi-assets)
   - Validates collateral is not script-locked
   - Verifies total collateral field matches sum of collateral inputs
   - Validates collateral return output

5. **Auxiliary Data Validation**
   - Verifies auxiliary data hash matches actual auxiliary data
   - Checks metadata structure

6. **Registration Validation (Certificates)**
   - Validates stake key registration and deregistration
   - Checks stake pool registration and retirement
   - Validates DRep registration and deregistration
   - Verifies committee hot key authorization and cold key resignation
   - Checks deposit and refund amounts
   - Validates voting and proposal procedures

7. **Output Validation**
   - Checks minimum ADA requirements for each output
   - Validates output sizes don't exceed protocol limits
   - Validates network IDs in output addresses

8. **Transaction Limits Validation**
   - Checks transaction size doesn't exceed maximum
   - Validates total execution units don't exceed transaction limits
   - Checks reference script sizes
   - Validates number of collateral inputs

#### Phase 2 Validation

Phase 2 executes Plutus scripts and validates their execution:

- Collects all transaction inputs (regular, reference, and collateral)
- Resolves UTXOs for script context
- Executes each redeemer with its associated Plutus script
- Validates execution budgets
- Captures script logs and execution results
- Checks that total execution units don't exceed declared amounts

### Example Usage

```typescript
import { 
    get_necessary_data_list_js, 
    validate_transaction_js 
} from 'cquisitor-lib';

async function validateTransaction(txHex: string) {
    try {
        // Step 1: Get the list of required data
        const necessaryDataJson = get_necessary_data_list_js(txHex, "mainnet");
        const necessaryData = JSON.parse(necessaryDataJson);
        
        // Step 2: Fetch the required data from your indexer/node
        const utxos = await fetchUtxos(necessaryData.utxos);
        const accounts = await fetchAccounts(necessaryData.accounts);
        const pools = await fetchPools(necessaryData.pools);
        // ... fetch other required data
        
        // Step 3: Build the validation context
        const validationContext = {
            slot: await getCurrentSlot(),
            networkType: "mainnet",
            protocolParameters: await getProtocolParameters(),
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
        
        // Step 5: Check the results
        if (result.errors.length > 0) {
            console.error('Transaction has validation errors:');
            result.errors.forEach(err => {
                console.error(`- ${err.error_message}`);
                if (err.hint) {
                    console.error(`  Hint: ${err.hint}`);
                }
            });
            return false;
        }
        
        if (result.phase2_errors.length > 0) {
            console.error('Transaction has script execution errors:');
            result.phase2_errors.forEach(err => {
                console.error(`- ${err.error_message}`);
            });
            return false;
        }
        
        if (result.warnings.length > 0) {
            console.warn('Transaction has warnings:');
            result.warnings.forEach(warn => {
                console.warn(`- ${JSON.stringify(warn.warning)}`);
                if (warn.hint) {
                    console.warn(`  Hint: ${warn.hint}`);
                }
            });
        }
        
        if (result.phase2_warnings.length > 0) {
            console.warn('Transaction has Phase 2 warnings:');
            result.phase2_warnings.forEach(warn => {
                console.warn(`- ${JSON.stringify(warn.warning)}`);
                if (warn.hint) {
                    console.warn(`  Hint: ${warn.hint}`);
                }
            });
        }
        
        // Log redeemer execution results
        result.eval_redeemer_results.forEach(redeemer => {
            console.log(`Redeemer ${redeemer.tag}[${redeemer.index}]:`);
            console.log(`  Success: ${redeemer.success}`);
            console.log(`  Provided ex units: ${JSON.stringify(redeemer.provided_ex_units)}`);
            console.log(`  Calculated ex units: ${JSON.stringify(redeemer.calculated_ex_units)}`);
            if (redeemer.error) {
                console.log(`  Error: ${redeemer.error}`);
            }
            if (redeemer.logs.length > 0) {
                console.log(`  Logs: ${redeemer.logs.join(', ')}`);
            }
        });
        
        console.log('Transaction is valid!');
        return true;
        
    } catch (error) {
        console.error('Validation failed:', error);
        return false;
    }
}
```

### Best Practices

1. **Always call `get_necessary_data_list_js` first** to determine what data you need to fetch
2. **Provide accurate protocol parameters** matching the current epoch
3. **Include all referenced data** in the validation context
4. **Handle both errors and warnings** - warnings might indicate sub-optimal transactions
5. **Log redeemer execution results** for debugging script issues
6. **Validate transactions before submission** to avoid rejection by the network
7. **Check Phase 2 errors separately** from Phase 1 errors for better error handling

---

## add_witnesses_to_tx

### Overview
Adds witnesses to an already built transaction (e.g. signatures produced by a hardware wallet, a CIP-30 `signTx` call, or `cardano-cli`). The transaction body bytes — and therefore the transaction id and every existing signature — are preserved exactly: internally the function uses CSL's `FixedTransaction`, which keeps the original body bytes and only re-encodes the witness set. There is no need to rebuild the transaction by hand.

### Signature
```typescript
function add_witnesses_to_tx(
    tx_hex: string,
    witnesses: string[]
): string
```

There are also two strict helpers when the input format is known in advance:

```typescript
// each entry is the CBOR-hex of a single Vkeywitness ([ vkey, signature ])
function add_vkey_witnesses_to_tx(tx_hex: string, vkey_witnesses_hex: string[]): string

// witness_set_hex is the CBOR-hex of a TransactionWitnessSet (e.g. a CIP-30 signTx result)
function add_witness_set_to_tx(tx_hex: string, witness_set_hex: string): string
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `tx_hex` | `string` | Hexadecimal-encoded Cardano transaction in CBOR format |
| `witnesses` | `string[]` | List of witness inputs. Each entry is auto-detected (see below). |

### Accepted witness formats
Each entry of `witnesses` is auto-detected by both its encoding and its CBOR shape.

**Encoding** (any of):
- hex
- base64 (standard or url-safe)
- a `cardano-cli` JSON text-envelope: `{ "type": ..., "description": ..., "cborHex": "..." }`

**Shape** (any of):
- a single `Vkeywitness` (`[ vkey, signature ]`)
- a single `BootstrapWitness`
- a whole `TransactionWitnessSet` (the canonical shape returned by a CIP-30 `signTx`)
- a whole transaction (signed or not) — its vkey/bootstrap witnesses are extracted
- a `cardano-cli` key-witness wrapper: `[ 0, vkeywitness ]` (vkey) or `[ 1, bootstrap_witness ]` (bootstrap)

Only vkey and bootstrap witnesses are merged (the parts a signer can contribute). Duplicate witnesses are ignored. Other fields of the original transaction's witness set are left untouched.

### Returns
Returns the hex-encoded resulting transaction. The transaction id is unchanged.

### Example Usage
```typescript
import { add_witnesses_to_tx } from "cquisitor-lib";

// A wallet returned a witness set from signTx (CIP-30):
const signedTx = add_witnesses_to_tx(unsignedTxHex, [walletWitnessSetHex]);

// Mixing sources and encodings in one call:
const tx = add_witnesses_to_tx(unsignedTxHex, [
    vkeyWitnessHex,                          // hex Vkeywitness
    walletWitnessSetBase64,                  // base64 TransactionWitnessSet
    JSON.stringify(cardanoCliWitnessFile),   // cardano-cli text-envelope
]);
```

### Error Handling
Throws if `tx_hex` cannot be parsed as a transaction, or if any witness entry cannot be decoded as any of the accepted formats. The error message includes the index of the offending witness entry.

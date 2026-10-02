# API Documentation

The reference for the transaction functions, the typed decoders and the CBOR
validation report of `@cardananium/cquisitor-lib`. Every function is used
through the typed API of the package root (`import { necessaryData,
validateTransaction, addWitnesses, decode, validateCborAgainstCddl } from
"@cardananium/cquisitor-lib"`): each wrapper is `async`, runs through the
configured backend, and answers with the parsed object — integers as `number`
when they fit 2^53 and `bigint` above. Section headers name the wrapper and,
in parentheses, the wasm export behind it; the raw exports are reachable under
`@cardananium/cquisitor-lib/wasm` and answer exactly as the Rust side does
(JSON text for the `*_js` functions and the document walkers). See
[README.md](README.md) for the full function table, the backends and the
subpaths.

## Table of Contents
- [Input checks shared by every entry point](#input-checks-shared-by-every-entry-point)
- [`necessaryData` (`get_necessary_data_list_js`)](#necessarydata-get_necessary_data_list_js)
- [`validateTransaction` (`validate_transaction_js`)](#validatetransaction-validate_transaction_js)
- [`addWitnesses` (`add_witnesses_to_tx`)](#addwitnesses-add_witnesses_to_tx)
- [Typed decoders](#typed-decoders)
- [CBOR validation report](#cbor-validation-report)

---

## Input checks shared by every entry point

Every function that reads a transaction, a witness set, a block or a CBOR
data item checks the bytes before handing them to the serialization library,
and answers with an ordinary error (a thrown `JsError` / rejected `Result`)
instead of aborting the wasm instance:

- **Malformed CBOR** — bytes that are not one well-formed CBOR item
  (truncated, reserved header bits, a stray break, trailing bytes). The
  message is `Malformed CBOR: <what> (kind: <kind>, path: <path>)`, with the
  same `kind`/`path` vocabulary `cbor_to_json` reports
  (`unexpected_eof`, `invalid_syntax`, `trailing_data`, …). Well-formed CBOR
  the decoders cannot represent (a non-finite float) is refused as
  `Unsupported CBOR content: …`.
- **Nesting** — a document nested deeper than 128 levels *outside its
  native scripts* is refused by every entry point that hands bytes to the
  serialization library (`Unsupported CBOR content: CBOR nesting is deeper
  than the supported limit of 128 levels for decoding by the serialization
  library; native scripts do not count toward it and may nest up to 32768
  levels (kind: nesting_too_deep)`), including a transaction whose witness
  set or auxiliary data carries such a datum. The typed decoders, which also
  render what they read as JSON, stop at 64 levels outside native scripts
  (`CBOR nesting is deeper than the supported limit of 64 levels for typed
  decoding; native scripts do not count toward it …`). Bytes only pallas and
  the Plutus evaluator read are refused past 128 levels outside native
  scripts (`… supported limit of 128 levels for decoding by pallas and the
  Plutus evaluator; native scripts do not count toward it … (kind:
  nesting_too_deep)`): the transaction as `get_utxo_list_from_tx`,
  `get_ref_script_bytes`, `execute_tx_scripts` and the phase-2 part of
  validation read it, and an inline datum of the validation context. Every
  message keeps the phrase `supported limit of N levels`, N being the bound
  applied. CBOR carried in a byte string under tag 24 (an output's inline
  datum `[1, #6.24(bytes)]`, a script reference `#6.24(bytes)`, in a
  transaction or in the validation context) counts on top of the level it is
  embedded at: both libraries parse it in place while reading the document, so
  a 3 KB transaction whose inline datum nests 1 100 constructors is refused
  although the transaction itself is 8 levels deep. The libraries recurse on
  the host stack over Plutus data and metadata, so each bound is what they
  are measured to hold, with margin, on the smallest stack the library runs
  on: a WebKit (Safari) Web Worker.

  **Native scripts are exempt.** The serialization library (18) and the
  pallas-primitives this library builds with read, encode, clone, compare and drop native
  scripts without recursion, and this library evaluates them, collects
  their key hashes and renders them as JSON in one loop over a flat copy.
  Levels inside a native script the input holds where the ledger puts one
  — a `NativeScript` / `ScriptAll` / `ScriptAny` / `ScriptNOfK` value
  itself, `NativeScripts`, a witness set's key 1, auxiliary data's scripts
  (`[metadata, [* native_script]]` or tag 259's key 1), an output's script
  reference `#6.24(bytes .cbor [0, native_script])` (in a transaction, a
  block, an output, an unspent output, a validation context) — do not count
  toward the 64 and 128 bounds; only an item that is a whole native script
  counts as one. The whole input, native scripts and tag-24 payloads
  included, still nests at most 32 768 levels (`CBOR nesting is deeper than
  the supported limit of 32768 levels`), about 16 380 `ScriptAll` levels; the
  deepest native script a 16 KB mainnet transaction can carry is about
  5 430 levels. A script reference of the validation context past that bound
  does not fail the validation: its native script counts as provided (its
  hash is read from the bytes) and is reported `NativeScriptNotExamined`,
  and an inline datum past the pallas bound makes phase 2 report each
  redeemer `ScriptContextNotExamined` instead of evaluating it.
  The document walkers (`cbor_to_json`, and validating, decoding or mapping
  against a CDDL schema) keep their nesting on the heap and follow 32 768
  levels. Validation reads
  only the context UTxOs the transaction spends or references (inputs,
  reference inputs, collateral) into script contexts: another UTxO of the
  context refuses nothing there.
- **Simple values in witness lists** — a `Vkeywitnesses` /
  `BootstrapWitnesses` array holding `true`, `false`, `null`, `undefined`,
  an unassigned simple value or a float, wherever such a list sits (witness
  set keys 0 and 2, index 1 of a transaction, index 2 of a block). The
  message is `Malformed witness list: a simple value or float at byte offset
  <n> where a witness (an array) is expected`.
- **Empty addresses** — a byte string of length zero (definite, or
  indefinite with no payload) where the serialization library reads an
  address: an output's address in either output form (body keys 1 and 16),
  a withdrawal key (key 5), a pool registration's reward account (key 4),
  a proposal's reward account and a treasury withdrawal key (key 20), in a
  transaction, a transaction body, a block, or the corresponding standalone
  type (`TransactionOutput`, `Withdrawals`, `PoolParams`, `Certificate`,
  `VotingProposal`, `GovernanceAction`, …). The message is `Malformed
  address: an empty byte string at byte offset <n> where an address is
  expected`. An address given on its own with no payload bytes (hex `""` or
  a bech32 string with an empty data part) is an error the same way.
- **Empty input** — `Input is empty`.
- **Validation context** — a UTxO quantity that is not an unsigned integer
  (`"1.5 ADA"`, `"abc"`, a negative value where the ledger needs a coin), an
  asset unit shorter than a policy id, a zero token quantity, or an address /
  hash / datum that does not parse, is reported as
  `Invalid UTxO in the validation context: …` / `Invalid quantity '…' for
  asset '…'` naming the offending field.

---

## `necessaryData` (`get_necessary_data_list_js`)

### Overview
Extracts a list of all necessary blockchain data required to validate a Cardano transaction. This function analyzes the transaction structure and identifies all UTXOs, accounts, stake pools, DReps, governance actions, and committee members that are referenced in the transaction.

### Signature
```typescript
function necessaryData(
    txHex: string,
    network: "mainnet" | "preview" | "preprod",
    options?: LibCallOptions
): Promise<NecessaryInputData>
```

The wasm export `get_necessary_data_list_js(tx_hex, network_type)` answers with the same object as JSON text.

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `txHex` | `string` | Hexadecimal-encoded Cardano transaction in CBOR format |
| `network` | `NetworkType` | Target network: `"mainnet"`, `"preview"`, or `"preprod"`. Used to derive stake/reward addresses (bech32 prefix) for `accounts`, `pools`, `dReps`. |
| `options` | `LibCallOptions?` | `signal` (abort while queued) and `timeoutMs` (worker backends) |

### Returns

Resolves to a `NecessaryInputData` object with the following structure:

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
import { necessaryData } from "@cardananium/cquisitor-lib";

// Example transaction hex
const txHex = "84a400..."; // Your transaction hex

try {
    const needed = await necessaryData(txHex, "mainnet");

    console.log("Required UTXOs:", needed.utxos);
    console.log("Required accounts:", needed.accounts);
    console.log("Required pools:", needed.pools);

    // Fetch the required data from your blockchain data source
    // before calling validateTransaction (or let fetchValidationData do it)
} catch (error) {
    console.error("Failed to get necessary data:", error);
}
```

### Error Handling

The function throws a `JsError` if:
- The transaction hex is malformed or cannot be parsed (see [Input checks](#input-checks-shared-by-every-entry-point))
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

## `validateTransaction` (`validate_transaction_js`)

### Overview
Performs comprehensive validation of a Cardano transaction according to the Cardano ledger rules. This includes both Phase 1 validation (ledger rules, balances, fees, witnesses) and Phase 2 validation (Plutus script execution). The function checks the transaction against protocol parameters, UTXOs, accounts, pools, and governance state provided in the validation context.

### Signature
```typescript
function validateTransaction(
    txHex: string,
    context: ValidationInputContext,
    options?: LibCallOptions
): Promise<ValidationResult>
```

The wasm export `validate_transaction_js(tx_hex, validation_context)` takes the context as JSON text and answers with the result as JSON text; the wrapper serialises and parses exactly (`bigint` fields survive).

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `txHex` | `string` | Hexadecimal-encoded Cardano transaction in CBOR format |
| `context` | `ValidationInputContext` | All blockchain state required for validation (u64 fields may be `number` or `bigint`) |
| `options` | `LibCallOptions?` | Phase 2 cannot be interrupted from inside: bound it with `timeoutMs` on a worker backend |

### Validation Context Structure

```typescript
interface ValidationInputContext {
    slot: number | bigint;                  // Current blockchain slot (validity-interval check only; native-script timelocks are judged against the tx's validity interval)
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
    treasuryValue: number | bigint;        // Current treasury value
}
```

See the type definitions file for detailed structures of nested types.

A `GovActionInputContext` may carry `changedParameters?: string[]`: for a
`ParameterChangeAction`, the names of the protocol parameters it changes (ledger
names such as `maxBlockBodySize`, CDDL names such as `max_block_body_size`,
db-sync / Koios names such as `max_block_size` / `max_block_ex_mem`, or the CDDL
keys as text, `"2"`). A stake pool may vote on a parameter change only when it
changes a parameter of the ledger's security group (`txFeePerByte`,
`txFeeFixed`, `maxBlockBodySize`, `maxTxSize`, `maxBlockHeaderSize`,
`utxoCostPerByte`, `maxBlockExecutionUnits`, `maxValueSize`, `govActionDeposit`,
`minFeeRefScriptCostPerByte`); without `changedParameters` its vote is reported
as `DisallowedVoters`. `fetchValidationData` / `validateTransactionOnline` fill
it from Koios' `param_proposal` (its non-null fields); the Blockfrost provider
leaves it out.

### Returns

Resolves to a `ValidationResult` object:

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
   - Calculates minimum required fee based on transaction size, measured as
     the ledger measures it: the transaction as the three-element array
     `[body, witness set, auxiliary data]` of its original bytes, i.e. one
     byte less than a four-element transaction for its `is_valid` flag
     (cardano-ledger `sizeAlonzoTxF`). A transaction paying exactly
     `size × minFeeA + minFeeB` passes
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
   - Requires `100 × collateral ≥ collateralPercentage × fee`, i.e. a collateral
     balance (inputs less the collateral return) of at least
     `ceil(fee × collateralPercentage / 100)` lovelace, the amount
     `InsufficientCollateral` reports as required
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
   - Checks transaction size (the same ledger size as the fee) doesn't exceed
     `maxTransactionSize`
   - Validates total execution units don't exceed transaction limits
   - Checks reference script sizes
   - Validates number of collateral inputs

#### Phase 2 Validation

Phase 2 executes Plutus scripts and validates their execution:

- Collects all transaction inputs (regular, reference, and collateral)
- Resolves UTXOs for script context
- Executes each redeemer with its associated Plutus script; the evaluator is aiken's `uplc` v1.1.24, run with the language *and* the context's protocol major (`protocolParameters.protocolVersion[0]`), as the ledger selects builtin semantics and costing: PlutusV1/V2 use semantics B at protocol 9–10 and D at 11+, PlutusV3 uses C at 9–10 and E at 11+ (A for V1/V2 before 9). The protocol-11 builtins `expModInteger`, `dropList`, the BLS12-381 `multiScalarMul` pair and the CIP-153 value builtins (V3 at 11+ only) run; the array builtins (`lengthOfArray`, `listToArray`, `indexArray`, codes 89–91) are not implemented by this `uplc` release, so a script using them fails to decode (`ScriptDecodeError`). `execute_tx_scripts` takes no protocol version and runs every script as at protocol 11.
- Answers, as that redeemer's error, content its script context cannot be built
  from, before the evaluator sees it: an output address that does not parse
  (`UnreadableOutput`), a Byron output address (`ByronAddressNotAllowed`, the
  ledger's `ByronTxOutInContext`), a zero token quantity or a policy with no
  tokens in an array-form output (`UnreadableOutput`), a withdrawal key, a
  proposal's return account or a treasury withdrawal key that is not a stake
  address, and a rational number with denominator 0 in a proposal (quorum,
  prices, thresholds, `UnreadableTransactionField` with `field` naming it,
  e.g. `withdrawals[0]`, `proposal_procedures[0].gov_action.quorum`), and,
  next to a PlutusV1/V2 script, a Conway certificate (kinds 9–18,
  `CertificateNotSupportedInPlutusV1V2`) or Conway body field (votes,
  proposals, treasury donation, current treasury value,
  `FieldNotSupportedInPlutusV1V2`), and next to a PlutusV1 script an inline
  datum on an output (`InlineDatumNotAllowedForPlutusV1`). The Phase 1 report
  is returned with them. `execute_tx_scripts` answers the same content as
  that redeemer's `error` string. Such a redeemer never ran: its result
  carries the script (`script_bytes`, `plutus_version`) and the arguments it
  would have taken, zero `calculated_ex_units`, and no budget error or
  warning (`NoEnoughBudget` / `BudgetIsBiggerThanExpected` compare the budget
  only with a run's cost).
- `ReferenceInputsNotAllowedForPlutusV1` is the evaluator's limit, not a
  ledger rule: the evaluator cannot build a PlutusV1 context for a transaction
  with reference inputs or spending an output with a reference script, while
  the Conway ledger accepts both for PlutusV1 (it refuses only inline datums).
  The script was not run; confirm such a verdict against the chain.
- A parameter change of the cost models (protocol parameter update key 18),
  which the evaluator cannot translate, reaches every PlutusV3 script of the
  transaction (the proposal's guardrail script included) as the ledger's
  `ToPlutusData CostModels` writes it: key 18 of the changed parameters, in
  ascending key order, is a map from each language's key to its parameter
  list, languages ascending. `execute_tx_scripts` runs such scripts the same
  way, and there unknown languages (keys 3 and up, which the ledger accepts)
  are included. `validate_transaction` cannot read a transaction whose
  cost models name an unknown language (neither can `get_necessary_data_list`
  or the other exports that read a transaction with the serialization
  library, which knows languages 0-2 only): it rejects it at parse time with
  `Failed to parse transaction: the parameter change of proposal <i> carries
  a cost model for language <n>; … refuses the transaction, so it cannot be
  validated here (executeTxScripts still runs its scripts)` (`the protocol
  parameter update (body key 6) …` for a pre-Conway update). The other
  exports name the language the same way, after their own prefix, and end
  at `… refuses the transaction`.
- Validates execution budgets
- Captures script logs and execution results
- Checks that total execution units don't exceed declared amounts

### Example Usage

```typescript
import { necessaryData, validateTransaction, type ValidationInputContext } from "@cardananium/cquisitor-lib";

async function checkTransaction(txHex: string) {
    try {
        // Step 1: Get the list of required data
        const needed = await necessaryData(txHex, "mainnet");

        // Step 2: Fetch the required data from your indexer/node
        // (or use fetchValidationData + buildValidationContext from the chain layer)
        const utxos = await fetchUtxos(needed.utxos);
        const accounts = await fetchAccounts(needed.accounts);
        const pools = await fetchPools(needed.pools);
        // ... fetch other required data

        // Step 3: Build the validation context
        const validationContext: ValidationInputContext = {
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
        const result = await validateTransaction(txHex, validationContext);

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

### Error Handling

The call rejects with an `Error` (rather than resolving to a `ValidationResult`) when
the input cannot be judged at all:
- The transaction hex is not one well-formed CBOR item, nests deeper than 128 levels
  outside its native scripts (32 768 with them), holds a witness list with a simple value in it, or an empty byte string where an
  address is read (see [Input checks](#input-checks-shared-by-every-entry-point))
- The transaction does not parse as a Conway transaction
- The validation context is malformed: a UTxO quantity that is not an integer, an
  asset unit shorter than a policy id, an address or hash that does not parse
  (`Invalid UTxO in the validation context: …`)
- A referenced UTxO is missing from the context (`Can't get these UTXOs from API…`)

A redeemer whose tag and index match no script purpose in the transaction is reported
inside the result as the Phase 2 error `ExtraneousRedeemer`.

### Best Practices

1. **Always call `necessaryData` first** to determine what data you need to fetch
2. **Provide accurate protocol parameters** matching the current epoch
3. **Include all referenced data** in the validation context
4. **Handle both errors and warnings** - warnings might indicate sub-optimal transactions
5. **Log redeemer execution results** for debugging script issues
6. **Validate transactions before submission** to avoid rejection by the network
7. **Check Phase 2 errors separately** from Phase 1 errors for better error handling

---

## `addWitnesses` (`add_witnesses_to_tx`)

### Overview
Adds witnesses to an already built transaction (e.g. signatures produced by a hardware wallet, a CIP-30 `signTx` call, or `cardano-cli`). The transaction body bytes — and therefore the transaction id and every existing signature — are preserved exactly: internally the function uses CSL's `FixedTransaction`, which keeps the original body bytes and only re-encodes the witness set. There is no need to rebuild the transaction by hand.

### Signature
```typescript
function addWitnesses(txHex: string, witnesses: string[], options?: LibCallOptions): Promise<string>

// the same merge, with what was added / skipped and why
function addWitnessesWithReport(txHex: string, witnesses: string[], options?: LibCallOptions): Promise<AddWitnessesReport>
```

There are also two strict helpers when the input format is known in advance:

```typescript
// each entry is the CBOR-hex of a single Vkeywitness ([ vkey, signature ])
function addVkeyWitnesses(txHex: string, vkeyWitnessesHex: string[], options?: LibCallOptions): Promise<string>

// witnessSetHex is the CBOR-hex of a TransactionWitnessSet (e.g. a CIP-30 signTx result)
function addWitnessSet(txHex: string, witnessSetHex: string, options?: LibCallOptions): Promise<string>
```

(Wasm exports: `add_witnesses_to_tx`, `add_witnesses_to_tx_with_report`, `add_vkey_witnesses_to_tx`, `add_witness_set_to_tx`.)

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `txHex` | `string` | Hexadecimal-encoded Cardano transaction in CBOR format |
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
Resolves to the hex-encoded resulting transaction. The transaction id is unchanged.

### Example Usage
```typescript
import { addWitnesses } from "@cardananium/cquisitor-lib";

// A wallet returned a witness set from signTx (CIP-30):
const signedTx = await addWitnesses(unsignedTxHex, [walletWitnessSetHex]);

// Mixing sources and encodings in one call:
const tx = await addWitnesses(unsignedTxHex, [
    vkeyWitnessHex,                          // hex Vkeywitness
    walletWitnessSetBase64,                  // base64 TransactionWitnessSet
    JSON.stringify(cardanoCliWitnessFile),   // cardano-cli text-envelope
]);
```

### Error Handling
Rejects if `txHex` cannot be parsed as a transaction, or if any witness entry cannot be decoded as any of the accepted formats. The error message includes the index of the offending witness entry.

---

## Typed decoders

### `decodableTypes()`, `possibleTypes(input)`, `decode(input, typeName, params?)`

(Wasm exports: `get_decodable_types`, `get_possible_types_for_input`,
`decode_specific_type`.) Every type of the serialization library that has a
deserializer is offered by name. `possibleTypes` tries them all and resolves to
the names that accept the input; `decode` runs one.

- Hex input is classified before any decoder runs. Raw-byte types (fixed-length
  hashes and verification keys, key material, addresses, Plutus script bytes)
  read the bytes as they are. Every other type reads a CBOR item, and is only
  offered / run when the hex is one well-formed CBOR item; otherwise `decode`
  rejects with `Malformed CBOR: …` and `possibleTypes` leaves the type out.
  Trailing bytes after a complete item are malformed input.
- `Transaction`, `Block`, `VersionedBlock`, `TransactionWitnessSet(s)`,
  `Vkeywitnesses` and `BootstrapWitnesses` are additionally not offered for a
  document whose witness lists hold a simple value (`Malformed witness list: …`).
- The types that read an address (`Transaction`, `Block`, `VersionedBlock`,
  `TransactionBody`/`TransactionBodies`, `TransactionOutput(s)`,
  `TransactionUnspentOutput`, `Withdrawals`, `RewardAddresses`, `PoolParams`,
  `PoolRegistration`, `Certificate(s)`, `VotingProposal(s)`,
  `GovernanceAction`, `TreasuryWithdrawalsAction`) are not offered for a
  document with an empty byte string where that address sits
  (`Malformed address: …`); the same bytes are still offered to the types
  that read no address there (`824000` is a `PlutusData` list).
- Hash and verification-key types decode to `{ hex, bech32 }`, where `bech32`
  is present only for the types with a CIP-5 prefix (`Ed25519KeyHash` →
  `addr_vkh`, `ScriptHash` → `script`, `VRFKeyHash` → `vrf_vkh`, `DataHash` →
  `datum`, `ScriptDataHash` → `script_data`, `KESVKey` → `kes_vk`, `VRFVKey`
  → `vrf_vk`); the hashes CIP-5 names no prefix for (`TransactionHash`,
  `BlockHash`, `GenesisHash`, `GenesisDelegateHash`, `AuxiliaryDataHash`,
  `AnchorDataHash`, `PoolMetadataHash`) carry `hex` alone.
- A document nested deeper than 64 levels outside the native scripts the
  type holds is refused by name before the decoder sees it; a native script
  itself (and a transaction, witness set, output or auxiliary data holding
  one) decodes at any depth up to 32 768 CBOR levels.
  `possibleTypesReport` / `get_possible_types_report` lists the types not
  tried in `unexamined.types`, where `possibleTypes` simply leaves them out.
- `NativeScript` (and the other native-script types) answer
  `{script_hash, script}` with `script` in the serialization library's JSON
  schema (`{"ScriptAll":{"native_scripts":[…]}}`,
  `{"ScriptNOfK":{"n":2,"native_scripts":[…]}}`,
  `{"ScriptPubkey":{"addr_keyhash":"…"}}`, `{"TimelockStart":{"slot":"…"}}`),
  written compactly in one pass; `n` is any int64, as the ledger reads it
  (the typed `decode` gives a `number`, or a `bigint` past 2^53).
- A Plutus script, wherever a decoded value holds one (a witness set's
  `plutus_scripts`, auxiliary data's `plutus_scripts`, a script reference's
  `{"PlutusScript": …}`), is `{"bytes": "<hex>", "language": "PlutusV1" |
  "PlutusV2" | "PlutusV3"}`: the compiled script without its CBOR bytes
  header, and its language. (0.1.0-beta.64 and earlier gave the bare hex
  string.) `PlutusScript` decoded on its own answers
  `{script_hash, core_version}`.
- The answer of `decode_specific_type` is JSON text; the typed `decode`
  parses it exactly (`parseJsonExact`).

---

## CBOR validation report

### `validate_cbor_against_cddl(cbor_hex, cddl, rule_name)`

Returns `{valid: true}` or `{valid: false, error}` where `error` carries `kind`,
`message`, `path`, `expected` (when the message names an expected type or
key), `byte_spans` / `anchor_spans` (positions in the CBOR) and
`cddl_byte_span`. Points worth knowing:

- **`rule_name`** is the rule's name as written, which is how `cddl_outline`
  reports it: a socket keeps its prefix (`$m`, and `$$g` for a group socket,
  refused as `group_rule_root` like any group rule). A socket is also found
  by its identifier alone (`m` for `$m`) when no rule is written `m`: the
  type socket when the identifier has one, whatever order the rules are
  written in (with `$$m //= (1: uint)` and `$m /= uint`, `m` roots at `$m`),
  and `group_rule_root` when it has only a group socket; where a rule is
  written `m` too, `m` names that rule. `decode_cbor_against_cddl` and
  `map_cbor_to_cddl` resolve the root with the same function, so the three
  exports accept and refuse the same names and root at the same rule; the
  root row of `map_cbor_to_cddl` carries that rule's name as written (`$m`
  for `m`). Decode and map read a rule's bodies as the validator does, as the
  root and wherever the rule is referenced: a type rule's definition and each
  `/=` body are the alternatives of one choice (the first body the value
  fits wins, strictly before leniently, so with `$m /= {1: uint}` and
  `$m /= {3: tstr}` the data `{3: "x"}` decodes as `{"3": "x"}` and maps onto
  the second body), and so is a socket used as a map key type (`{* $k =>
  uint}` with `$k /= 1` and `$k /= 3` admits the keys 1 and 3). A group
  rule's definition and each `//=` body, like the alternatives of a group
  choice written out (`(A // B)`), are one choice read against a map's
  entries: of the alternatives that hold, the one accounting for the most
  entries is taken (the earliest among equals), so an optional-only body
  does not shadow a later one (`g = (? 1: uint)`, `g //= (3: tstr)` with
  `{3: "x"}` is valid and decodes as `{"3": "x"}`, not into `@extra`). Under
  `*`, `+` or `n*m` the choice repeats, each round taking the first
  alternative that accounts for a further entry (`{* $$g}` admits entries of
  every body); a group socket no plug fills matches no entry, so `{$$g}` is
  invalid and `{? $$g}` admits only what the rest of the map describes. A
  member key that is a type answers for no more entries than
  its occurrence indicator admits (`{? $k => uint}` with two such keys is
  invalid and does not decode strictly).

- **Paths** use the grammar of `joinCborPath`: `.key` for a text key that is
  an identifier (ASCII `[A-Za-z_][A-Za-z0-9_-]*`), `["key"]` for any other
  text key (`\` written `\\`, `"` written `\"`, nothing else escaped:
  `$["v1.0"]`, `$["[1]"]`, `$["1"]`), `[n]` for an index or an integer key,
  `[1.5]` for a float key, `.h'…'` / `.true` / `.null` for byte string,
  boolean and null keys, and diagnostic notation in brackets for a composite
  key (below). The validator names an entry whose key renders past 256 bytes
  by its position, `[n]`, or by nothing, `[...]`, when an integer key `n` is
  in the map. Where the entry is known (its position; for `[...]`, the one
  entry whose key can render past the bound) and its key is a text or byte
  string, the path writes that key out in full (up to 1 024 bytes of
  rendering), so it is not taken for an integer key or for the text key
  `"1"` / `"..."`. Any other such entry keeps `[n]` / `[...]`: the byte spans
  tell it apart (the entry's when the position is known, the map's when it
  is not).
- **Unexpected map entries** (`unexpected key <k>`) are located at the entry:
  `path` ends in the key (`$.foo`, `$[2]`), and `byte_spans` / `anchor_spans`
  hold two spans, the key's first and the value's second (from its tag head
  when the value is tagged). The key names no member of the schema, so
  `cddl_byte_span` is the map the entry sits in, as the schema writes it out:
  through the rule references naming it (`transaction_witness_set = { … }`,
  not the `transaction_witness_set` reference in `transaction`), and, where
  the type is a choice, its one alternative that is a map (the map form of
  `redeemers`, not `[ + redeemer ]`) or the whole choice when several are.
  A type rule extended with `/=` (a socket) is one choice of all its bodies,
  written at the reference naming it: with two map bodies (`$m /= {1: uint}`,
  `$m /= {3: uint}`) the span is the `$m` that references the socket (its
  first name when the socket is the root rule).
  A text key in a location is quoted with `"` and `\` escaped, so a key
  holding `"/` (`{"a\"/b": …}`) is located like any other.
- **Spans through a choice.** Where the path passes a choice (`a / b`, an
  inline `{…} / {…}`, a socket's bodies), `cddl_byte_span` follows the
  alternative whose container holds the path's next key or index: a map with
  a member of that key, an array with a slot at that index. Failing that, an
  alternative that may hold it (a map whose keys are a type, an array of a
  repeated group), and only then the first that is a container at all. With
  `start = a / b`, `a = {1: uint}`, `b = {3: {5: uint}}` and the data
  `{3: {5: 1, 6: 2}}`, `unexpected key 6` spans `{5: uint}` in `b`, and a
  mismatch at `$[3][5]` spans its `uint`.
  `map missing key: <k>` stays on the map (nothing in the document to point
  at) and states the key in `expected`; so does `map requires entry with key
  of type <T>`.
- **`.size`** is measured in bytes (a text string by its UTF-8 bytes). A
  mismatch reads `expected byte string of size 28 bytes, got 27 bytes` /
  `expected text string of size …` / `expected byte string length to be in the
  range 0 <= value <= 64, got 100`; the data itself is not repeated. A string
  is sized as a whole (RFC 8610), chunked or not, with one exception: a string
  matched against a rule named `bounded_bytes` (the Plutus data byte string,
  which the ledger bounds per chunk) is held to the upper bound of a `.size`
  range one chunk at a time. A chunked 100-byte string whose chunks are ≤ 64
  bytes is therefore a valid `bounded_bytes` (and Plutus datum), a
  definite-length 100-byte string is not, and an oversized chunk is named with
  its index (`expected each chunk of the indefinite-length byte string to be
  at most 64 bytes, got 70 bytes in chunk 0`); the same chunked string is not
  a metadatum (`bytes .size (0 .. 64)` / `text .size (0 .. 64)`, which the
  ledger bounds as a whole), nor any other schema's sized string. The reading
  holds while `bounded_bytes` is resolved against the string itself (directly,
  through aliases, choices, generic arguments or `#6.2(bounded_bytes)`), not
  for a string nested inside an item matched against it. An exact size and
  the lower bound of a range apply to the whole string even there: two
  32-byte chunks are not `bytes .size 32` (`… got 64 bytes`), and an
  indefinite-length string with no chunks is the empty string
  (`got 0 bytes`).
- **Composite map keys** (arrays, maps, tagged items, simple values) are written
  in CBOR diagnostic notation inside the path's bracket form —
  `$[[2, h'0102']]`, `$[{1: 2}]`, `$[24(0)]` — and their entries carry spans like
  any other, whichever encoding the key uses (indefinite-length arrays and maps,
  such as a Plutus constructor `121([_ 1])`, included). So do entries under
  indefinite-length text and byte string keys and under `undefined` (named
  `null`, as the validator reads it). `expected` is read from the validator's
  own map reasons only, never from data quoted in a reason.
- **An empty array** offered to a map, tag or scalar rule is a `mismatch` with
  `expected` set to the rule's type (`expected map { 1: uint }, got array(0
  items)`).

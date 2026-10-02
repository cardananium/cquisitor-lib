# Phase 1 Validation Errors and Warnings

DISCLAIMER: Not all of these errors exactly match those in cardano-ledger; most cover similar logic, but the "location" may differ. Additionally, warnings are not part of cardano-ledger validation—they are implemented here to highlight situations where a transaction might execute differently than you expect or it has some unnecessary things.

## Not Yet Covered

- Pre-Conway transaction validation
- Governance action proposal validation
- Voting for governance actions validation
- Byron-era address signature validation
- Plutus array builtins (`lengthOfArray`, `listToArray`, `indexArray`): a script using them fails to decode. Phase 2 otherwise follows the context's protocol major for builtin semantics and costing (`uplc` v1.1.24: V1/V2 B at protocol 9–10, D at 11+; V3 C at 9–10, E at 11+)

## Input Checks (before validation runs)

Validation only starts on input it can judge; anything else is an error returned to the caller rather than a crash of the wasm instance:

- **Malformed transaction CBOR** - the transaction hex is not one well-formed CBOR item (truncated, stray break, trailing bytes)
- **Simple value in a witness list** - the vkey / bootstrap witness list holds a simple value or float where a witness array is expected
- **Empty address** - a byte string of length zero where an address is read
- **Nesting past 128 levels** - the transaction nests deeper than the serialization library is measured to follow on a WebKit worker's stack, not counting its native scripts; CBOR under tag 24 (an output's inline datum, a script reference) counts on top of the level it is embedded at, as the decoders parse it in place. The refusal names the bound it applies: `… supported limit of 128 levels for decoding by the serialization library; native scripts do not count toward it …`, `… supported limit of 128 levels for decoding by pallas and the Plutus evaluator; …`. Native scripts (witness set, auxiliary data, script references) are read and evaluated without recursion and nest up to 32 768 levels with the rest of the input (`… supported limit of 32768 levels`); a required native script thousands of levels deep is evaluated like any other. A script reference of the validation context past that bound, or an inline datum past the pallas bound, does not refuse the transaction: the native script is counted as provided and reported not examined (`NativeScriptNotExamined`), and the redeemers are reported not evaluated (`ScriptContextNotExamined`)
- **Cost model of an unknown language** - a protocol parameter update (a parameter change proposal, or a pre-Conway update) whose cost models name a language past PlutusV3 (key 3 and up). The ledger accepts it; the transaction reader does not, so the transaction is refused at parse time, naming the proposal and the language (`executeTxScripts` still runs its scripts). The other exports that read a transaction (`necessaryData`, the witness inserters, `checkSignatures`, `extractHashes`) refuse it with the same named reason
- **Malformed validation context** - a UTxO quantity that is not an unsigned integer, an asset unit shorter than a policy id, a zero token quantity, or an address / hash / datum / script reference that does not parse; the error names the field
- **Missing UTxOs** - an input, collateral or reference input of the transaction is absent from the context

Phase 2 builds each script's context with an evaluator that panics on some content a transaction can hold. That content is answered as the redeemer's Phase 2 error, with the Phase 1 report, before the evaluator sees it:

- **Unreadable output** - an output address that does not parse, or, in an array-form output, a zero token quantity or a policy with no tokens
- **Unreadable transaction field** - a withdrawal key, a proposal's return account or a treasury withdrawal key that is not a stake address, or a rational number with denominator 0 in a proposal (committee quorum, prices, voting thresholds, rates)
- **Byron output address** - the ledger's `ByronTxOutInContext`, for any Plutus version
- **Conway certificate next to a PlutusV1/V2 script** - certificate kinds 9–18 (the ledger's `CertificateNotSupported`); kinds 0–4, 7 and 8 translate
- **Conway body field next to a PlutusV1/V2 script** - voting procedures, proposal procedures, treasury donation or current treasury value
- **Inline datum on an output next to a PlutusV1 script** - the ledger refuses inline datums on inputs, reference inputs and outputs for PlutusV1

Such a redeemer never ran: it reports zero calculated units and gets no budget error or warning.

The evaluator also refuses a PlutusV1 context for a transaction with reference inputs, or spending an output with a reference script (`ReferenceInputsNotAllowedForPlutusV1`). The Conway ledger accepts both for PlutusV1; that error is the evaluator's limit, not a ledger rule.

A parameter change of the cost models (protocol parameter update key 18), which the evaluator cannot translate, reaches every PlutusV3 script of the transaction (the proposal's guardrail script included) as the ledger writes it: key 18 of the changed parameters is a map from each language's key to its parameter list, languages ascending. Unknown languages are included by `executeTxScripts` only: a transaction naming one cannot be validated (see "Cost model of an unknown language" above).

## 1. AuxiliaryDataValidator (`auxiliary_data.rs`)

Validates auxiliary data and its hash consistency.

### Errors (3)
- **Auxiliary data hash mismatch** - The hash of the auxiliary data doesn't match the expected hash in the transaction body
- **Auxiliary data hash missing** - Transaction contains auxiliary data but the hash is missing from the transaction body
- **Auxiliary data hash present but not expected** - Transaction body contains auxiliary data hash but no auxiliary data is provided


## 2. BalanceValidator (`balance.rs`)

Validates transaction balance, deposits, refunds, and withdrawals.

### Errors (11)
- **Value not conserved** - The sum of inputs doesn't equal the sum of outputs (balance equation fails)
- **Treasury value mismatch** - The declared treasury value doesn't match the actual treasury value
- **Wrong requested withdrawal amount** - The withdrawal amount doesn't match the available reward balance
- **Withdrawal not allowed because not delegated to DRep** - Attempting withdrawal from stake credential not delegated to a DRep
- **Reward account not existing** - Attempting withdrawal from a non-existent reward account
- **Stake registration wrong deposit** - The deposit amount for stake registration doesn't match protocol parameters
- **DRep incorrect deposit** - The deposit amount for DRep registration doesn't match protocol parameters
- **Pool registration wrong deposit** - The deposit amount for pool registration doesn't match protocol parameters
- **Voting proposal incorrect deposit** - The deposit amount for governance proposal doesn't match protocol parameters
- **Stake deregistration wrong refund** - The refund amount for stake deregistration doesn't match the original deposit
- **DRep deregistration wrong refund** - The refund amount for DRep deregistration doesn't match the original deposit

### Warnings (2)
- **Cannot check stake deregistration refund** - Unable to verify the refund amount due to missing context information
- **Cannot check DRep deregistration refund** - Unable to verify the DRep refund amount due to missing context information


## 3. CollateralValidator (`collateral.rs`)

Validates collateral inputs and collateral return for script transactions.

### Errors (8)
- **Too many collateral inputs** - The number of collateral inputs exceeds the protocol maximum
- **No collateral inputs** - Transaction requires script execution but has no collateral inputs
- **Insufficient collateral** - The collateral balance (inputs less the collateral return, or the declared total) is less than required: the ledger requires `100 × collateral ≥ collateralPercentage × fee`, i.e. at least `ceil(fee × collateralPercentage / 100)`
- **Incorrect total collateral field** - The declared total collateral doesn't match the sum of collateral input values
- **Calculated collateral contains non-ADA assets** - The collateral calculation results in non-ADA assets
- **Collateral input contains non-ADA assets** - One or more collateral inputs contain native tokens
- **Collateral is locked by script** - Collateral input is controlled by a script rather than a key
- **Collateral return too small** - The collateral return output doesn't meet minimum ADA requirements

### Warnings (3)
- **Collateral is unnecessary** - Transaction provides collateral but doesn't execute any scripts
- **Total collateral is not declared** - Collateral return is present but total collateral field is missing
- **Collateral input uses reward address** - Collateral input uses a reward address (unusual but not invalid)

---

## 4. FeeValidator (`fee.rs`)

Validates transaction fees against protocol parameters.

### Errors (1)
- **Fee too small** - The transaction fee is below the minimum required fee (calculated from tx size, execution units, and reference scripts). The size is the ledger's: the transaction as `[body, witness set, auxiliary data]` from its original bytes, without the `is_valid` flag, so the exact ledger minimum passes

### Warnings (1)
- **Fee is bigger than minimum fee** - The transaction fee is significantly higher than the minimum required (>10% over minimum)

---

## 5. OutputValidator (`output.rs`)

Validates transaction outputs for size and minimum ADA requirements.

### Errors (2)
- **Output too big value** - A transaction output value exceeds the maximum allowed size in bytes
- **Output too small** - A transaction output contains less ADA than the minimum required amount

---

## 6. RegistrationValidator (`registration.rs`)

Validates certificate-based registrations, deregistrations, and delegations.

### Errors (8)
- **Stake already registered** - Attempting to register an already registered stake key
- **Stake not registered** - Attempting to use an unregistered stake key for delegation or deregistration
- **Stake non-zero account balance** - Attempting to deregister a stake key with remaining rewards
- **Stake pool not registered** - Attempting to retire or update a non-existent stake pool
- **Wrong retirement epoch** - Pool retirement epoch is invalid (too early or too late)
- **Stake pool cost too low** - Pool cost parameter is below the minimum required
- **Committee is unknown** - Referencing a committee member that doesn't exist
- **Committee has previously resigned** - Attempting to authorize a committee member who has resigned

### Warnings (5)
- **Pool already registered** - Attempting to register an already registered pool
- **DRep already registered** - Attempting to register an already registered DRep
- **Committee already authorized** - Attempting to authorize an already authorized committee member
- **DRep not registered** - Certificate references a DRep that isn't registered
- **Duplicate registration in transaction** - Same entity is registered multiple times in one transaction
- **Duplicate committee cold resignation in transaction** - Same committee member resigns multiple times in one transaction
- **Duplicate committee hot registration in transaction** - Same committee hot key is registered multiple times in one transaction

---

## 7. TransactionLimitsValidator (`transaction_limits.rs`)

Validates transaction size, execution limits, and input validity.

### Errors (7)
- **Input set empty** - Transaction has no inputs
- **Maximum transaction size exceeded** - Transaction size in bytes (the ledger's size, as for the fee) exceeds protocol limit
- **Execution units too big** - Total execution units (memory/steps) exceed protocol limits
- **Reference scripts size too big** - Total size of reference scripts exceeds the limit
- **Outside validity interval** - Current slot is outside the transaction's validity interval; the interval is half-open as in the ledger's `inInterval`: `validity_interval_start <= slot < ttl`
- **Bad inputs** - One or more inputs are already spent or don't exist
- **Reference input overlaps with input** - A reference input is also used as a regular input

### Warnings (1)
- **Inputs are not sorted** - Transaction inputs are not in canonical lexicographic order

---

## 8. WitnessValidator (`witness.rs`)

Validates cryptographic witnesses, signatures, and script execution requirements.

### Errors (10)
- **Missing verification key witnesses** - Required signatures are not provided
- **Invalid signature** - A provided signature is cryptographically invalid
- **Extraneous signature** - Unnecessary signatures are provided
- **Missing script witnesses** - Required scripts are not provided
- **Extraneous script witnesses** - Unnecessary scripts are provided in witness set
- **Native script is unsuccessful** - A native script evaluation fails. Evaluation follows the ledger's `evalTimelock`: `ScriptPubkey` holds when its key hash has a vkey witness; `ScriptAll` / `ScriptAny` / `ScriptNOfK` combine their sub-scripts (`n <= 0` always holds); `TimelockStart s` (`invalid_before`) holds iff the transaction has a `validity_interval_start` (body key 8) and `s <= validity_interval_start`; `TimelockExpiry s` (`invalid_hereafter`) holds iff the transaction has a `ttl` (body key 3) and `ttl <= s`. An absent bound never satisfies a timelock. The context `slot` plays no part here; it is judged only by *Outside validity interval*
- **Missing redeemer** - Required redeemer for Plutus script is not provided
- **Missing datum** - Required datum for Plutus script is not provided
- **Extraneous datum witnesses** - Unnecessary datums are provided in witness set
- **Script data hash mismatch** - The script data hash doesn't match the calculated hash

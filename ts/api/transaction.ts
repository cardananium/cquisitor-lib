// Transactions: what a validation needs, the validation itself, script
// execution, and the witness / hash helpers.

import type { LibCallOptions } from "../backend.js";
import type {
  AddWitnessesReport,
  CheckSignaturesResult,
  CostModels,
  ExecuteTxScriptsResult,
  ExUnits,
  ExUnitsText,
  ExtractedHashes,
  NecessaryInputData,
  NetworkType,
  RawRedeemerResult,
  RedeemerResult,
  UTxO,
  ValidationInputContext,
  ValidationResult,
} from "@cardananium/cquisitor-lib/wasm";
import { integerFromText, stringifyJsonExact } from "../util/json.js";
import { callLib } from "./call.js";

/**
 * The chain data a validation of `txHex` needs: UTxOs, accounts, pools, DReps,
 * governance actions and committee members to fetch before `validateTransaction`.
 */
export function necessaryData(txHex: string, network: NetworkType, options?: LibCallOptions): Promise<NecessaryInputData> {
  return callLib("get_necessary_data_list_js", [txHex, network], options);
}

/**
 * Full phase-1 and phase-2 validation of `txHex` against `context` (built by
 * hand or by `fetchValidationData` + `buildValidationContext`). u64 fields of
 * the context may be `number` or `bigint`. Phase 2 executes every script and
 * cannot be interrupted from inside: bound it with `options.timeoutMs` on a
 * worker backend. Rejects when a referenced UTxO is missing from `utxoSet`.
 */
export function validateTransaction(
  txHex: string,
  context: ValidationInputContext,
  options?: LibCallOptions,
): Promise<ValidationResult> {
  return callLib("validate_transaction_js", [txHex, stringifyJsonExact(context)], options);
}

/**
 * Execute the transaction's Plutus scripts against `utxos` with `costModels`:
 * per redeemer, its tag and index, the budget the transaction declared
 * (`original_ex_units`) and either the budget the script used
 * (`calculated_ex_units`) or the `error` it failed with. Integers are
 * `number`, or `bigint` past 2^53 (the raw export writes them as strings).
 */
export async function executeTxScripts(
  txHex: string,
  utxos: UTxO[],
  costModels: CostModels,
  options?: LibCallOptions,
): Promise<ExecuteTxScriptsResult> {
  const raw = await callLib("execute_tx_scripts", [txHex, utxos, costModels], options);
  return raw.map(readRedeemerResult);
}

/** A decimal string from the raw export as `number` (or `bigint` past 2^53); a value already numeric passes through. */
function integerOf(value: string | number | bigint): number | bigint {
  if (typeof value !== "string") return value;
  if (!/^-?\d+$/.test(value)) throw new Error(`execute_tx_scripts wrote ${JSON.stringify(value)} where an integer belongs`);
  return integerFromText(value) as number | bigint;
}

function exUnitsOf(units: ExUnitsText | ExUnits): ExUnits {
  return { mem: integerOf(units.mem), steps: integerOf(units.steps) };
}

function readRedeemerResult(raw: RawRedeemerResult): RedeemerResult {
  const common = {
    original_ex_units: exUnitsOf(raw.original_ex_units),
    redeemer_index: integerOf(raw.redeemer_index),
    redeemer_tag: raw.redeemer_tag,
  };
  if ("error" in raw) return { ...common, error: raw.error };
  return { ...common, calculated_ex_units: exUnitsOf(raw.calculated_ex_units) };
}

/** Script and datum hashes of a transaction, indexed the way the witness set and outputs are. */
export function extractHashes(txHex: string, options?: LibCallOptions): Promise<ExtractedHashes> {
  return callLib("extract_hashes_from_transaction_js", [txHex], options);
}

/** The `txHash#index` references a transaction spends, collateralises and references. */
export function utxoList(txHex: string, options?: LibCallOptions): Promise<string[]> {
  return callLib("get_utxo_list_from_tx", [txHex], options);
}

/** Hex of the reference script carried by output `outputIndex` (one wrapper layer removed). */
export function refScriptBytes(txHex: string, outputIndex: number, options?: LibCallOptions): Promise<string> {
  return callLib("get_ref_script_bytes", [txHex, outputIndex], options);
}

/**
 * Add witnesses to a built transaction, each auto-detected: a Vkeywitness, a
 * BootstrapWitness, a whole witness set (a CIP-30 `signTx` result) or a whole
 * transaction, as hex, base64 or a cardano-cli JSON envelope. Duplicates are
 * ignored; the body bytes and transaction id are preserved. Answers the new hex.
 */
export function addWitnesses(txHex: string, witnesses: string[], options?: LibCallOptions): Promise<string> {
  return callLib("add_witnesses_to_tx", [txHex, witnesses], options);
}

/** Like `addWitnesses`, verifying each vkey witness against the body and reporting what was added, skipped or invalid. */
export function addWitnessesWithReport(
  txHex: string,
  witnesses: string[],
  options?: LibCallOptions,
): Promise<AddWitnessesReport> {
  return callLib("add_witnesses_to_tx_with_report", [txHex, witnesses], options);
}

/** Strict: add vkey witnesses, each the CBOR hex of one `[vkey, signature]`. */
export function addVkeyWitnesses(txHex: string, vkeyWitnessesHex: string[], options?: LibCallOptions): Promise<string> {
  return callLib("add_vkey_witnesses_to_tx", [txHex, vkeyWitnessesHex], options);
}

/** Strict: merge a whole TransactionWitnessSet (CBOR hex) into the transaction. */
export function addWitnessSet(txHex: string, witnessSetHex: string, options?: LibCallOptions): Promise<string> {
  return callLib("add_witness_set_to_tx", [txHex, witnessSetHex], options);
}

/**
 * vkey and Catalyst witness signature check of a transaction or block. The
 * `invalid*Witnesses` lists are omitted when empty (always, for a valid
 * transaction); a block answers its first failing transaction's result.
 */
export function checkSignatures(hex: string, options?: LibCallOptions): Promise<CheckSignaturesResult> {
  return callLib("check_block_or_tx_signatures", [hex], options);
}

// Typed decoders: the ledger types the serialization library knows how to read.

import type { LibCallOptions } from "../backend.js";
import type { DecodingParams, PossibleTypesReport } from "@cardananium/cquisitor-lib/wasm";
import type { DecodedTransaction } from "../types/transaction.js";
import { callLib } from "./call.js";

/**
 * Decode `input` (hex, bech32 or base58) as the named ledger type through the
 * serialization library's own decoder for it. Rejects with the reason when it
 * does not decode. Integers come back as `number`, or `bigint` past 2^53.
 * A `"Transaction"` answers `{ transaction_hash, transaction }`
 * (`DecodedTransaction`); every other type answers its own JSON.
 *
 *     const { transaction_hash, transaction } = await decode(hex, "Transaction");
 *     transaction.body.fee;
 *     const datum = await decode(hex, "PlutusData", { plutus_data_schema: "DetailedSchema" });
 */
export function decode(
  input: string,
  typeName: "Transaction",
  params?: DecodingParams,
  options?: LibCallOptions,
): Promise<DecodedTransaction>;
export function decode<T = unknown>(
  input: string,
  typeName: string,
  params?: DecodingParams,
  options?: LibCallOptions,
): Promise<T>;
export function decode<T = unknown>(
  input: string,
  typeName: string,
  params: DecodingParams = {},
  options?: LibCallOptions,
): Promise<T> {
  return callLib<"decode_specific_type", T>("decode_specific_type", [input, typeName, params], options);
}

/**
 * Sorted names of the ledger types `input` decodes as; empty when none does.
 * A type the input would make the serialization library abort on (malformed
 * CBOR, an empty embedded address, a simple value in a witness list) is left
 * out rather than tried, and so is a type whose reading of the input nests
 * past 64 levels outside the native scripts it holds (native scripts nest up
 * to 32768). `possibleTypesReport` tells a type not tried from one the input
 * does not decode as.
 */
export function possibleTypes(input: string, options?: LibCallOptions): Promise<string[]> {
  return callLib("get_possible_types_for_input", [input], options);
}

/**
 * `possibleTypes` with the types not tried and why: `{ types }`, or, when
 * reading the input as some types nests past what the typed decoders follow,
 * `{ types, unexamined: { kind: "nesting_too_deep", limit, depth?, message,
 * types } }` — `unexamined.types` lists the types not tried, an
 * implementation limit, not a finding that the input is not of those types.
 * A native script thousands of levels deep answers `NativeScript` in `types`
 * and the types that would read it as something else (Plutus data, …) in
 * `unexamined.types`.
 *
 *     const { types, unexamined } = await possibleTypesReport(hex);
 *     if (unexamined) show(`not tried (${unexamined.types.length} types): ${unexamined.message}`);
 */
export function possibleTypesReport(input: string, options?: LibCallOptions): Promise<PossibleTypesReport> {
  return callLib("get_possible_types_report", [input], options);
}

/** Every type name `decode` accepts. */
export function decodableTypes(options?: LibCallOptions): Promise<string[]> {
  return callLib("get_decodable_types", [], options);
}

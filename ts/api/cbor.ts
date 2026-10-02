// CBOR and CDDL: the positional decoder, schema validation, and the CDDL editor
// primitives. Every result is the library's structured answer, parsed once.

import type { LibCallOptions } from "../backend.js";
import type {
  CborCddlMapResult,
  CborDecodeAgainstCddlResult,
  CborDecodeResult,
  CborValidationResult,
  CddlOutlineEntry,
  CddlReferencesResult,
  CddlSymbolAtResult,
  CddlValidationResult,
} from "@cardananium/cquisitor-lib/wasm";
import { callLib } from "./call.js";

/**
 * Positional CBOR tree of `hex`: every item with its byte offsets and encoding
 * oddities, or the structured error (with the partial tree read so far) when
 * the bytes do not decode. Never rejects on malformed CBOR; it rejects only on
 * a refusal (input too large, backend unavailable).
 */
export function cborToJson(hex: string, options?: LibCallOptions): Promise<CborDecodeResult> {
  return callLib("cbor_to_json", [hex], options);
}

/** Whether a CDDL text parses and every reference resolves. */
export function validateCddl(cddl: string, options?: LibCallOptions): Promise<CddlValidationResult> {
  return callLib("validate_cddl", [cddl], options);
}

/**
 * Validate CBOR `hex` against `rule` of `cddl`: `{valid: true}` or the
 * mismatch, with paths and byte spans into both texts.
 */
export function validateCborAgainstCddl(
  hex: string,
  cddl: string,
  rule: string,
  options?: LibCallOptions,
): Promise<CborValidationResult> {
  return callLib("validate_cbor_against_cddl", [hex, cddl, rule], options);
}

/** Alias of `validateCborAgainstCddl`. */
export const cborValidate = validateCborAgainstCddl;

/** Decode CBOR `hex` into the JSON shape `rule` of `cddl` gives it (named fields, unwrapped tags). */
export function decodeCborAgainstCddl(
  hex: string,
  cddl: string,
  rule: string,
  options?: LibCallOptions,
): Promise<CborDecodeAgainstCddlResult> {
  return callLib("decode_cbor_against_cddl", [hex, cddl, rule], options);
}

/** Map every CBOR item of `hex` to the CDDL spans of `cddl` that matched it under `rule`. */
export function mapCborToCddl(
  hex: string,
  cddl: string,
  rule: string,
  options?: LibCallOptions,
): Promise<CborCddlMapResult> {
  return callLib("map_cbor_to_cddl", [hex, cddl, rule], options);
}

/** One entry per top-level rule of `cddl`, with spans. Rejects when the text does not parse. */
export function cddlOutline(cddl: string, options?: LibCallOptions): Promise<CddlOutlineEntry[]> {
  return callLib("cddl_outline", [cddl], options);
}

/** Definition span and every use of rule `name` in `cddl`. Rejects when the text does not parse. */
export function cddlReferences(cddl: string, name: string, options?: LibCallOptions): Promise<CddlReferencesResult> {
  return callLib("cddl_references", [cddl, name], options);
}

/** The identifier under UTF-8 byte offset `offset` of `cddl`. */
export function cddlSymbolAt(cddl: string, offset: number, options?: LibCallOptions): Promise<CddlSymbolAtResult> {
  return callLib("cddl_symbol_at", [cddl, offset], options);
}

/** `cddl` pretty-printed. Rejects when the text does not parse. */
export function cddlFormat(cddl: string, options?: LibCallOptions): Promise<string> {
  return callLib("cddl_format", [cddl], options);
}

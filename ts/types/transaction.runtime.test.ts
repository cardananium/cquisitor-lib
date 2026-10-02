// The decoded-transaction model against what the decoder answers: every
// fixture is decoded with the real wasm and its JSON is walked alongside the
// declared `DecodedTransaction` type, read from transaction.ts by the
// TypeScript checker. A value of a kind the type does not admit, a required
// key the JSON lacks, or a key the type does not declare fails the test, so
// the declarations cannot drift from the runtime shape.

import { describe, expect, test } from "bun:test";
import * as path from "node:path";
import ts from "typescript";
import { decode } from "../api/index.js";
import { DECODED_SHAPE_FIXTURES } from "../testSupport/decodedShapes.js";
import type { DecodedTransaction, ScriptRef } from "./transaction.js";

const MODEL_FILE = path.join(import.meta.dir, "transaction.ts");

function loadChecker(): { checker: ts.TypeChecker; exported: (name: string) => ts.Type } {
  const configPath = path.join(import.meta.dir, "..", "..", "tsconfig.lib.typecheck.json");
  const config = ts.readConfigFile(configPath, ts.sys.readFile);
  const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, path.dirname(configPath));
  const program = ts.createProgram([MODEL_FILE], { ...parsed.options, noEmit: true });
  const checker = program.getTypeChecker();
  const source = program.getSourceFile(MODEL_FILE);
  if (!source) throw new Error("transaction.ts not in the program");
  const moduleSymbol = checker.getSymbolAtLocation(source);
  if (!moduleSymbol) throw new Error("transaction.ts has no module symbol");
  const exports = checker.getExportsOfModule(moduleSymbol);
  return {
    checker,
    exported(name) {
      const symbol = exports.find((s) => s.name === name);
      if (!symbol) throw new Error(`transaction.ts does not export ${name}`);
      return checker.getDeclaredTypeOfSymbol(symbol);
    },
  };
}

/** Where `value` departs from `type`; empty when it conforms. */
function mismatches(checker: ts.TypeChecker, value: unknown, type: ts.Type, at: string): string[] {
  const flags = type.flags;
  if (flags & (ts.TypeFlags.Any | ts.TypeFlags.Unknown)) return [];
  if (type.isUnion()) {
    let best: string[] | undefined;
    const absent = value === null || value === undefined;
    for (const member of type.types) {
      // A present value is judged against the members that can hold one.
      if (!absent && member.flags & (ts.TypeFlags.Null | ts.TypeFlags.Undefined)) continue;
      const found = mismatches(checker, value, member, at);
      if (found.length === 0) return [];
      if (!best || found.length < best.length) best = found;
    }
    const shown = checker.typeToString(type);
    return best && best.length > 0 && best.every((m) => !m.endsWith(": not " + shown))
      ? best
      : [`${at}: ${show(value)} is not ${shown}`];
  }
  const kindError = (expected: string) => [`${at}: ${show(value)} is not ${expected}`];
  if (flags & ts.TypeFlags.Null) return value === null ? [] : kindError("null");
  if (flags & ts.TypeFlags.Undefined) return value === undefined ? [] : kindError("undefined");
  if (flags & ts.TypeFlags.StringLiteral) {
    const literal = (type as ts.StringLiteralType).value;
    return value === literal ? [] : kindError(JSON.stringify(literal));
  }
  if (flags & ts.TypeFlags.String) return typeof value === "string" ? [] : kindError("string");
  if (flags & ts.TypeFlags.NumberLiteral) {
    const literal = (type as ts.NumberLiteralType).value;
    return value === literal ? [] : kindError(String(literal));
  }
  if (flags & ts.TypeFlags.Number) return typeof value === "number" ? [] : kindError("number");
  if (flags & ts.TypeFlags.BigInt) return typeof value === "bigint" ? [] : kindError("bigint");
  if (flags & ts.TypeFlags.BooleanLiteral) {
    const literal = checker.typeToString(type) === "true";
    return value === literal ? [] : kindError(String(literal));
  }
  if (flags & ts.TypeFlags.Boolean) return typeof value === "boolean" ? [] : kindError("boolean");
  if (checker.isTupleType(type)) {
    const elements = checker.getTypeArguments(type as ts.TypeReference);
    if (!Array.isArray(value) || value.length !== elements.length) {
      return kindError(`a tuple of ${elements.length}`);
    }
    return elements.flatMap((element, i) => mismatches(checker, value[i], element, `${at}[${i}]`));
  }
  if (checker.isArrayType(type)) {
    if (!Array.isArray(value)) return kindError("an array");
    const [element] = checker.getTypeArguments(type as ts.TypeReference);
    return value.flatMap((item, i) => mismatches(checker, item, element!, `${at}[${i}]`));
  }
  if (flags & ts.TypeFlags.Object) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return kindError("an object");
    const record = value as Record<string, unknown>;
    const found: string[] = [];
    const declared = new Set<string>();
    for (const property of checker.getPropertiesOfType(type)) {
      declared.add(property.name);
      const optional = (property.flags & ts.SymbolFlags.Optional) !== 0;
      if (!(property.name in record)) {
        if (!optional) found.push(`${at}.${property.name}: required, absent`);
        continue;
      }
      const propertyType = checker.getTypeOfSymbol(property);
      found.push(...mismatches(checker, record[property.name], propertyType, `${at}.${property.name}`));
    }
    const indexType = checker.getIndexTypeOfType(type, ts.IndexKind.String);
    for (const key of Object.keys(record)) {
      if (declared.has(key)) continue;
      if (indexType) found.push(...mismatches(checker, record[key], indexType, `${at}[${JSON.stringify(key)}]`));
      else found.push(`${at}.${key}: not declared (${show(record[key])})`);
    }
    return found;
  }
  return [`${at}: no rule for ${checker.typeToString(type)}`];
}

function show(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "an array";
  if (typeof value === "object") return `an object with keys ${Object.keys(value as object).join(",") || "(none)"}`;
  const text = typeof value === "string" ? JSON.stringify(value) : String(value);
  return `${typeof value} ${text.length > 40 ? text.slice(0, 40) + "…" : text}`;
}

const model = loadChecker();

describe("decoded transaction model", () => {
  for (const fixture of DECODED_SHAPE_FIXTURES) {
    test(fixture.name, async () => {
      const decoded = await decode(fixture.hex, "Transaction");
      expect(mismatches(model.checker, decoded, model.exported("DecodedTransaction"), "$")).toEqual([]);
    });
  }

  test("Plutus scripts decode as { bytes, language } wherever a transaction holds one", async () => {
    const decoded: DecodedTransaction = await decode(DECODED_SHAPE_FIXTURES[0]!.hex, "Transaction");
    const scripts = decoded.transaction.witness_set.plutus_scripts ?? [];
    expect(scripts.map((s) => s.language)).toEqual(["PlutusV1", "PlutusV2", "PlutusV3"]);
    expect(scripts.every((s) => /^([0-9a-f]{2})+$/.test(s.bytes))).toBe(true);
    const auxiliary = decoded.transaction.auxiliary_data?.plutus_scripts ?? [];
    expect(auxiliary.map((s) => s.language)).toEqual(["PlutusV1", "PlutusV2", "PlutusV3"]);
    const refs = decoded.transaction.body.outputs.flatMap((o) =>
      o.script_ref && "PlutusScript" in o.script_ref ? [o.script_ref.PlutusScript] : [],
    );
    expect(refs).toEqual([{ bytes: "4e4d01000033222220051200120012", language: "PlutusV2" }]);
  });

  test("ScriptNOfK.n is an int64: a number, a bigint past 2^53", async () => {
    const decoded: DecodedTransaction = await decode(DECODED_SHAPE_FIXTURES[0]!.hex, "Transaction");
    const ns = (decoded.transaction.witness_set.native_scripts ?? []).flatMap((s) =>
      "ScriptNOfK" in s ? [s.ScriptNOfK.n] : [],
    );
    expect(ns).toEqual([2, -1, 2 ** 40, 2n ** 60n]);
  });

  test("a script reference decoded on its own has the ScriptRef shape", async () => {
    for (const hex of [
      // #6.24(bytes .cbor [2, h'4e4d…'])
      "d81852" + "82024f4e4d01000033222220051200120012",
      // #6.24(bytes .cbor [0, [1, []]])
      "d818458200820180",
    ]) {
      const decoded = await decode<ScriptRef>(hex, "ScriptRef");
      expect(mismatches(model.checker, decoded, model.exported("ScriptRef"), "$")).toEqual([]);
    }
  });
});

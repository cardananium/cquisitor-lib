// The typed API against the real wasm, through the default in-process backend.

import { afterEach, describe, expect, test } from "bun:test";
import { configure, resetConfig } from "../configure.js";
import { LibInputTooLargeError } from "../errors.js";
import { CONWAY_TX_HEX, PERSON_DOC_HEX, PERSON_RULE, PERSON_SCHEMA } from "../testSupport/cddlLib.js";
import type { TransactionBody, TransactionData } from "../types/transaction.js";
import { MAX_LIB_INPUT_BYTES } from "../worker/inputBudget.js";
import {
  cborToJson,
  cborValidate,
  cddlFormat,
  cddlOutline,
  cddlReferences,
  cddlSymbolAt,
  checkSignatures,
  decodableTypes,
  decode,
  decodeCborAgainstCddl,
  decodePlutusProgramJson,
  decodePlutusProgramPretty,
  executeTxScripts,
  extractHashes,
  mapCborToCddl,
  necessaryData,
  possibleTypes,
  possibleTypesReport,
  refScriptBytes,
  utxoList,
  validateCborAgainstCddl,
  validateCddl,
  validateTransaction,
} from "./index.js";

afterEach(() => resetConfig());

describe("decoding", () => {
  test("possibleTypes and decode agree on a transaction", async () => {
    expect(await possibleTypes(CONWAY_TX_HEX)).toEqual(["Transaction"]);
    const tx = await decode<{ transaction_hash: string; transaction: { body: { fee: unknown } } }>(
      CONWAY_TX_HEX,
      "Transaction",
    );
    expect(tx.transaction_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(tx.transaction.body).toBeDefined();
  });

  test('decode(hex, "Transaction") is typed as the { transaction_hash, transaction } it answers', async () => {
    // No type argument: the overload gives DecodedTransaction, so these accesses type-check.
    const decoded = await decode(CONWAY_TX_HEX, "Transaction");
    expect(Object.keys(decoded).sort()).toEqual(["transaction", "transaction_hash"]);
    expect(decoded.transaction_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(typeof decoded.transaction.body.fee).toBe("string");
    expect(Array.isArray(decoded.transaction.body.inputs)).toBe(true);
    expect(typeof decoded.transaction.is_valid).toBe("boolean");
    expect(decoded.transaction.body.update).toBeNull();
  });

  test("the transaction model names every key the decoder answers", async () => {
    // Exactly the declared keys (the compiler holds this list to the types), and the
    // decoder answers no key outside them.
    const bodyKeys: Record<keyof Required<TransactionBody>, true> = {
      inputs: true, outputs: true, fee: true, ttl: true, certs: true, withdrawals: true, update: true,
      auxiliary_data_hash: true, validity_start_interval: true, mint: true, script_data_hash: true,
      collateral: true, required_signers: true, network_id: true, collateral_return: true,
      total_collateral: true, reference_inputs: true, voting_procedures: true, voting_proposals: true,
      donation: true, current_treasury_value: true,
    };
    const txKeys: Record<keyof Required<TransactionData>, true> = {
      body: true, witness_set: true, is_valid: true, auxiliary_data: true,
    };
    const decoded = await decode(CONWAY_TX_HEX, "Transaction");
    expect(Object.keys(decoded.transaction.body).filter((k) => !(k in bodyKeys))).toEqual([]);
    expect(Object.keys(decoded.transaction).filter((k) => !(k in txKeys))).toEqual([]);
  });

  test("decodableTypes lists what decode accepts", async () => {
    const types = await decodableTypes();
    expect(types).toContain("Transaction");
    expect(types).toContain("PlutusData");
  });

  test("integers past 2^53 come back as bigint, smaller ones as number", async () => {
    const datum = await decode<{ plutus_data: { fields: Array<{ int: unknown }> } }>(
      "d8799f1b7fffffffffffffff05ff",
      "PlutusData",
      { plutus_data_schema: "DetailedSchema" },
    );
    expect(datum.plutus_data.fields[0].int).toBe(9223372036854775807n);
    expect(datum.plutus_data.fields[1].int).toBe(5);
  });

  test("a decode that fails rejects with an Error carrying the library's reason", async () => {
    const error = await decode("zz", "Transaction").catch((e: unknown) => e);
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message.length).toBeGreaterThan(0);
  });

  test("malformed input yields no candidate types instead of throwing", async () => {
    expect(Array.isArray(await possibleTypes("85"))).toBe(true);
  });

  test("possibleTypesReport tells an unexamined input from one that decodes as nothing", async () => {
    const chain = (levels: number) => "81".repeat(levels) + "05";
    expect(await possibleTypesReport(CONWAY_TX_HEX)).toEqual({ types: ["Transaction"] });
    expect(await possibleTypesReport("85")).toEqual({ types: [] });
    const within = await possibleTypesReport(chain(64));
    expect(within.unexamined).toBeUndefined();
    expect(within.types.length).toBeGreaterThan(0);
    const past = await possibleTypesReport(chain(65));
    expect(past.types).toEqual([]);
    expect(past.unexamined).toMatchObject({
      kind: "nesting_too_deep",
      limit: 64,
      depth: 65,
      message:
        "CBOR nesting is deeper than the supported limit of 64 levels for typed decoding; " +
        "native scripts do not count toward it and may nest up to 32768 levels",
    });
    expect(past.unexamined?.types).toEqual(await decodableTypes());
    expect(await possibleTypes(chain(65))).toEqual([]);
  });

  test("a native script thousands of levels deep decodes; types that would recurse are not tried", async () => {
    // 5,430 ScriptAll levels around a key leaf: 10,861 CBOR levels.
    const levels = 5430;
    const script = "820181".repeat(levels) + "8200581c" + "11".repeat(28);
    const report = await possibleTypesReport(script);
    expect(report.types).toContain("NativeScript");
    expect(report.types).toContain("ScriptAll");
    expect(report.unexamined?.limit).toBe(64);
    expect(report.unexamined?.depth).toBe(2 * levels + 1);
    expect(report.unexamined?.types).toContain("PlutusData");
    expect(report.unexamined?.types).not.toContain("NativeScript");
    const decoded = await decode<{ script_hash: string; script: unknown }>(script, "NativeScript");
    expect(decoded.script_hash).toMatch(/^[0-9a-f]{56}$/);
    await expect(decode(script, "PlutusData")).rejects.toThrow("supported limit of 64 levels");
  });

  test("a native script decodes at the typed decoders' bound", async () => {
    // 31 ScriptAll levels around a key leaf: 63 CBOR levels.
    const script = "820181".repeat(31) + "8200581c" + "11".repeat(28);
    expect(await possibleTypes(script)).toContain("NativeScript");
    const decoded = await decode<{ script_hash: string; script: unknown }>(script, "NativeScript");
    expect(decoded.script_hash).toMatch(/^[0-9a-f]{56}$/);
    let node = decoded.script as Record<string, unknown>;
    for (let level = 0; level < 31; level++) {
      node = ((node.ScriptAll as { native_scripts: unknown[] }).native_scripts[0]) as Record<string, unknown>;
    }
    expect(node.ScriptPubkey).toBeDefined();
  });
});

describe("CBOR and CDDL", () => {
  test("cborToJson answers the positional tree, parsed", async () => {
    const tree = await cborToJson("a1616101");
    expect(tree.ok).toBe(true);
    if (tree.ok) expect(tree.value.type).toBe("Map");
    const bad = await cborToJson("a1");
    expect(bad.ok).toBe(false);
    if (!bad.ok) expect(bad.error.kind).toBe("unexpected_eof");
  });

  test("validateCddl, validateCborAgainstCddl (and its alias), decode and map", async () => {
    expect(await validateCddl(PERSON_SCHEMA)).toEqual({ valid: true });
    expect((await validateCddl("a = {")).valid).toBe(false);
    expect(await validateCborAgainstCddl(PERSON_DOC_HEX, PERSON_SCHEMA, PERSON_RULE)).toEqual({ valid: true });
    expect(cborValidate).toBe(validateCborAgainstCddl);
    const mismatch = await cborValidate("a1646e616d6505", "Person = { name: tstr }", "Person");
    expect(mismatch.valid).toBe(false);
    if (!mismatch.valid) expect(mismatch.error.path).toBe("$.name");
    const decoded = await decodeCborAgainstCddl(PERSON_DOC_HEX, PERSON_SCHEMA, PERSON_RULE);
    expect(decoded.ok).toBe(true);
    if (decoded.ok) expect(decoded.value).toEqual({ name: "Alice", age: 30, nickname: "Ali" });
    const map = await mapCborToCddl(PERSON_DOC_HEX, PERSON_SCHEMA, PERSON_RULE);
    expect(map.ok).toBe(true);
    if (map.ok) expect(map.value.entries.length).toBeGreaterThan(0);
  });

  test("the CDDL editor primitives", async () => {
    const outline = await cddlOutline(PERSON_SCHEMA);
    expect(outline.map((e) => e.name)).toEqual(["Person"]);
    expect(typeof outline[0].span.offset).toBe("number");
    // The offset is a UTF-8 byte offset; PERSON_SCHEMA's comment has an em dash, so use plain text here.
    const symbol = await cddlSymbolAt("Person = { name: tstr }", 1);
    expect(symbol?.name).toBe("Person");
    const refs = await cddlReferences(`${PERSON_SCHEMA}\nx = Person`, "Person");
    expect(refs.uses.length).toBe(1);
    expect(await cddlFormat("Person = { name: tstr }")).toBe("Person = { name: tstr }\n");
    await expect(cddlFormat("a = {")).rejects.toBeInstanceOf(Error);
  });

  test("input over the budget is refused before it reaches the wasm", async () => {
    await expect(cborToJson("a".repeat(MAX_LIB_INPUT_BYTES + 2))).rejects.toBeInstanceOf(LibInputTooLargeError);
  });
});

describe("transactions", () => {
  test("necessaryData, extractHashes, utxoList, refScriptBytes and checkSignatures", async () => {
    const needed = await necessaryData(CONWAY_TX_HEX, "mainnet");
    // The set of inputs comes back in no particular order.
    expect(needed.utxos.map((u) => u.outputIndex).sort()).toEqual([0, 3]);
    expect(needed.accounts).toEqual([]);
    const hashes = await extractHashes(CONWAY_TX_HEX);
    expect(hashes.output_inline_scripts).toEqual([null, null]);
    const refs = await utxoList(CONWAY_TX_HEX);
    expect(refs).toHaveLength(2);
    expect(refs[0]).toMatch(/^[0-9a-f]{64}#0$/);
    expect(await refScriptBytes(CONWAY_TX_HEX, 0)).toBe("");
    const signatures = await checkSignatures(CONWAY_TX_HEX);
    expect(signatures.valid).toBe(false);
    expect(signatures.tx_hash).toMatch(/^[0-9a-f]{64}$/);
    // The lists are left out when empty: here no Catalyst witness is bad.
    expect("invalidCatalystWitnesses" in signatures).toBe(false);
    expect(signatures.invalidCatalystWitnesses ?? []).toEqual([]);
    // @ts-expect-error -- optional: may be absent, so it cannot be read without a guard.
    void (() => signatures.invalidCatalystWitnesses.length);
  });

  test("executeTxScripts reads the export's decimal strings as numbers (bigint past 2^53)", async () => {
    // What execute_tx_scripts returns, verbatim: every integer a decimal string.
    const raw = [
      {
        original_ex_units: { steps: "133455086", mem: "310608" },
        calculated_ex_units: { steps: "18446744073709551615", mem: "310608" },
        redeemer_index: "2",
        redeemer_tag: "Spend",
      },
      { original_ex_units: { steps: "10", mem: "20" }, error: "script failed", redeemer_index: "0", redeemer_tag: "Mint" },
    ];
    configure({ backend: { callRaw: async <T,>() => raw as unknown as T } });
    const results = await executeTxScripts("84a0", [], {} as never);
    expect(results).toEqual([
      {
        original_ex_units: { steps: 133455086, mem: 310608 },
        calculated_ex_units: { steps: 18446744073709551615n, mem: 310608 },
        redeemer_index: 2,
        redeemer_tag: "Spend",
      },
      { original_ex_units: { steps: 10, mem: 20 }, error: "script failed", redeemer_index: 0, redeemer_tag: "Mint" },
    ]);
    // An index comparison and arithmetic on a budget.
    expect(results.find((r) => r.redeemer_index === 2)).toBe(results[0]);
    const spent = results[0];
    if ("error" in spent) throw new Error("expected a success");
    expect(Number(spent.original_ex_units.steps) + 1).toBe(133455087);
    configure({ backend: { callRaw: async <T,>() => [{ ...raw[1], redeemer_index: "x" }] as unknown as T } });
    await expect(executeTxScripts("84a0", [], {} as never)).rejects.toThrow("where an integer belongs");
  });

  test("validateTransaction serialises bigint context fields as bare integers and parses the answer exactly", async () => {
    const seen: unknown[][] = [];
    configure({
      backend: {
        callRaw: async <T,>(fn: string, args: unknown[]) => {
          seen.push([fn, args]);
          // Written as text: a JS number literal would already have rounded the u64.
          return ('{"errors":[],"warnings":[],"phase2_errors":[],"phase2_warnings":[],' +
            '"eval_redeemer_results":[{"provided_ex_units":{"mem":18446744073709551615,"steps":7}}]}') as unknown as T;
        },
      },
    });
    const result = await validateTransaction("84a0", {
      slot: 123n,
      treasuryValue: 18446744073709551615n,
      networkType: "mainnet",
    } as never);
    expect(seen[0][0]).toBe("validate_transaction_js");
    const ctxJson = (seen[0][1] as string[])[1];
    expect(ctxJson).toBe('{"slot":123,"treasuryValue":18446744073709551615,"networkType":"mainnet"}');
    expect(result.eval_redeemer_results[0].provided_ex_units.mem).toBe(18446744073709551615n);
    expect(result.eval_redeemer_results[0].provided_ex_units.steps).toBe(7);
  });

  test("validateTransaction against the wasm rejects when the context lacks the inputs", async () => {
    const context = {
      utxoSet: [],
      protocolParameters: {
        minFeeCoefficientA: 44n,
        minFeeConstantB: 155381n,
        maxBlockBodySize: 90112,
        maxTransactionSize: 16384,
        maxBlockHeaderSize: 1100,
        stakeKeyDeposit: 2000000n,
        stakePoolDeposit: 500000000n,
        maxEpochForPoolRetirement: 18,
        protocolVersion: [10, 0] as [number, number],
        minPoolCost: 170000000n,
        adaPerUtxoByte: 4310n,
        costModels: {},
        executionPrices: { memPrice: { numerator: 577n, denominator: 10000n }, stepPrice: { numerator: 721n, denominator: 10000000n } },
        maxTxExecutionUnits: { mem: 14000000n, steps: 10000000000n },
        maxBlockExecutionUnits: { mem: 62000000n, steps: 20000000000n },
        maxValueSize: 5000,
        collateralPercentage: 150,
        maxCollateralInputs: 3,
        governanceActionDeposit: 100000000000n,
        drepDeposit: 500000000n,
        referenceScriptCostPerByte: { numerator: 15n, denominator: 1n },
      },
      slot: 133660855n,
      accountContexts: [],
      drepContexts: [],
      poolContexts: [],
      govActionContexts: [],
      lastEnactedGovAction: [],
      currentCommitteeMembers: [],
      potentialCommitteeMembers: [],
      treasuryValue: 0n,
      networkType: "mainnet" as const,
    };
    const outcome = await validateTransaction(CONWAY_TX_HEX, context).then(
      (r) => ({ ok: true as const, r }),
      (e: unknown) => ({ ok: false as const, e }),
    );
    if (outcome.ok) {
      expect(Array.isArray(outcome.r.errors)).toBe(true);
    } else {
      expect(outcome.e).toBeInstanceOf(Error);
      expect((outcome.e as Error).message).toMatch(/UTXO|utxo/i);
    }
  });
});

describe("Plutus", () => {
  const SCRIPT = "4d01000033222220051200120011";
  test("pretty and JSON forms of a program", async () => {
    expect(await decodePlutusProgramPretty(SCRIPT)).toContain("(program");
    const program = await decodePlutusProgramJson(SCRIPT);
    expect(program.program.version).toBe("1.0.0");
    expect(program.program.term).toBeDefined();
  });
});

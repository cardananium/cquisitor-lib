import { describe, expect, test } from "bun:test";
import { answersInJsonText, isWasmFunction, WASM_FUNCTIONS } from "./functions.js";
import { loadWasm } from "./load.js";

describe("the wasm function allowlist", () => {
  test("every listed name is a function of the real module", async () => {
    const wasm = (await loadWasm()) as unknown as Record<string, unknown>;
    for (const fn of WASM_FUNCTIONS) {
      expect(typeof wasm[fn]).toBe("function");
    }
  });

  test("constructors and CSL classes are not callable", () => {
    expect(isWasmFunction("constructor")).toBe(false);
    expect(isWasmFunction("Address")).toBe(false);
    expect(isWasmFunction("min_fee")).toBe(false);
    expect(isWasmFunction("cbor_to_json")).toBe(true);
  });

  test("the text-answering functions really answer text, the others do not", async () => {
    const wasm = (await loadWasm()) as unknown as Record<string, (...a: unknown[]) => unknown>;
    expect(typeof wasm.cbor_to_json("05")).toBe("string");
    expect(answersInJsonText("cbor_to_json")).toBe(true);
    expect(typeof wasm.get_necessary_data_list_js).toBe("function");
    expect(answersInJsonText("get_necessary_data_list_js")).toBe(true);
    expect(Array.isArray(wasm.get_possible_types_for_input("05"))).toBe(true);
    expect(answersInJsonText("get_possible_types_for_input")).toBe(false);
    expect(typeof wasm.validate_cddl("a = int")).toBe("object");
    expect(answersInJsonText("validate_cddl")).toBe(false);
  });
});

import { describe, expect, test } from "bun:test";
import { createInProcessBackend } from "./backend.js";
import { LibAbortedError, LibInputTooLargeError, LibUnavailableError } from "./errors.js";
import type { WasmModule } from "./wasm/functions.js";
import { MAX_LIB_INPUT_BYTES } from "./worker/inputBudget.js";

const stub = (exports: Record<string, unknown>) => async () => exports as unknown as WasmModule;

describe("the in-process backend", () => {
  test("hands the raw return value back, JSON text included", async () => {
    const backend = createInProcessBackend({
      load: stub({
        cbor_to_json: (hex: string) => `{"ok":true,"hex":"${hex}"}`,
        cddl_outline: () => [{ name: "a", span: { "$serde_json::private::Number": "3" } }],
      }),
    });
    expect(await backend.callRaw<string>("cbor_to_json", ["05"])).toBe('{"ok":true,"hex":"05"}');
    // Serde boxes are not touched here: the typed wrappers normalise once.
    expect(await backend.callRaw<unknown[]>("cddl_outline", ["a = int"])).toEqual([
      { name: "a", span: { "$serde_json::private::Number": "3" } },
    ]);
  });

  test("refuses names off the allowlist without loading the module", async () => {
    let loaded = false;
    const backend = createInProcessBackend({
      load: async () => {
        loaded = true;
        return {} as WasmModule;
      },
    });
    await expect(backend.callRaw("constructor" as never, [])).rejects.toThrow("not a callable library function");
    expect(loaded).toBe(false);
  });

  test("applies the input budget before touching the module", async () => {
    let loaded = false;
    const backend = createInProcessBackend({
      load: async () => {
        loaded = true;
        return {} as WasmModule;
      },
    });
    await expect(backend.callRaw("cbor_to_json", ["a".repeat(MAX_LIB_INPUT_BYTES + 1)])).rejects.toBeInstanceOf(
      LibInputTooLargeError,
    );
    expect(loaded).toBe(false);
  });

  test("an aborted signal rejects before the call", async () => {
    const backend = createInProcessBackend({ load: stub({ cbor_to_json: () => "[]" }) });
    const controller = new AbortController();
    controller.abort();
    await expect(backend.callRaw("cbor_to_json", ["05"], { signal: controller.signal })).rejects.toBeInstanceOf(
      LibAbortedError,
    );
  });

  test("a thrown string becomes an Error carrying the message", async () => {
    const backend = createInProcessBackend({
      load: stub({
        decode_specific_type: () => {
          throw "Invalid hex";
        },
      }),
    });
    const error = await backend.callRaw("decode_specific_type", ["zz", "Transaction", {}]).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toBe("Invalid hex");
    expect(backend.poisoned).toBe(false);
  });

  test("a stack overflow poisons the instance and later calls are refused", async () => {
    const backend = createInProcessBackend({
      load: stub({
        cbor_to_json: () => {
          throw new RangeError("Maximum call stack size exceeded");
        },
        validate_cddl: () => ({ valid: true }),
      }),
    });
    await expect(backend.callRaw("cbor_to_json", ["05"])).rejects.toBeInstanceOf(RangeError);
    expect(backend.poisoned).toBe(true);
    await expect(backend.callRaw("validate_cddl", ["a = int"])).rejects.toBeInstanceOf(LibUnavailableError);
    const refused = (await backend.callRaw("validate_cddl", ["a = int"]).catch((e: unknown) => e)) as Error;
    // Readable where an end user sees it (a worker backend's fallback): the operation, not the export,
    // and advice that holds whether or not workers exist.
    expect(refused.message).toContain("after an earlier fatal error (RangeError: Maximum call stack size exceeded)");
    expect(refused.message).toContain("cannot start checking the CDDL schema");
    expect(refused.message).toContain("Reload the page, or restart the process");
    expect(refused.message).not.toMatch(/validate_cddl|worker backend|poisoned/);
  });

  test("a module export that is not a function is reported", async () => {
    const backend = createInProcessBackend({ load: stub({ cbor_to_json: 5 }) });
    await expect(backend.callRaw("cbor_to_json", ["05"])).rejects.toThrow("does not export cbor_to_json");
  });

  test("warm loads the module once", async () => {
    let loads = 0;
    const backend = createInProcessBackend({
      load: async () => {
        loads++;
        return { validate_cddl: () => ({ valid: true }) } as unknown as WasmModule;
      },
    });
    await backend.warm();
    await backend.callRaw("validate_cddl", ["a = int"]);
    // `load` is the caller's; the backend does not cache on its own (loadWasm does).
    expect(loads).toBe(2);
  });
});

describe("the default backend against the real wasm", () => {
  test("loads the wasm lazily and runs a call", async () => {
    const backend = createInProcessBackend();
    expect(await backend.callRaw<string[]>("get_possible_types_for_input", ["05"])).toContain("Int");
    expect(typeof (await backend.callRaw("cbor_to_json", ["05"]))).toBe("string");
  });
});

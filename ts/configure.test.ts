import { afterEach, describe, expect, test } from "bun:test";
import type { LibBackend } from "./backend.js";
import {
  configure,
  getBackend,
  getCompressor,
  getLogger,
  isBackendConfigured,
  isCompressorConfigured,
  resetConfig,
} from "./configure.js";
import { necessaryData } from "./api/transaction.js";

afterEach(() => resetConfig());

describe("configure", () => {
  test("without configuration the backend is the in-process default and the compressor is missing", () => {
    expect(isBackendConfigured()).toBe(false);
    expect(isCompressorConfigured()).toBe(false);
    const backend = getBackend();
    expect(typeof backend.callRaw).toBe("function");
    expect(getBackend()).toBe(backend);
    expect(() => getCompressor()).toThrow("configure({ compressor }) must be called first");
  });

  test("registrations merge instead of replacing each other", () => {
    const backend: LibBackend = { callRaw: async <T,>() => null as T };
    const compressor = { compress: async (b: Uint8Array) => b, decompress: async (b: Uint8Array) => b };
    configure({ backend });
    configure({ compressor });
    expect(getBackend()).toBe(backend);
    expect(isBackendConfigured()).toBe(true);
    expect(getCompressor()).toBe(compressor);
  });

  test("the default logger writes to stderr, never stdout", () => {
    const seen: unknown[][] = [];
    const original = console.error;
    console.error = (...args: unknown[]) => {
      seen.push(args);
    };
    try {
      getLogger().warn("plain");
      getLogger().warn("with error", new Error("boom"));
    } finally {
      console.error = original;
    }
    expect(seen).toHaveLength(2);
    expect(seen[0]).toEqual(["plain"]);
    expect(seen[1][0]).toBe("with error");
  });

  test("a typed wrapper resolves the backend lazily, at call time, and reads the raw answer once", async () => {
    const calls: unknown[] = [];
    configure({
      backend: {
        callRaw: async <T,>(fn: string, args: unknown[]) => {
          calls.push([fn, args]);
          return '{"utxos":[],"accounts":[],"big":18446744073709551615}' as unknown as T;
        },
      },
    });
    const data = await necessaryData("84a0", "preprod");
    expect(calls).toEqual([["get_necessary_data_list_js", ["84a0", "preprod"]]]);
    expect(data).toEqual({ utxos: [], accounts: [], big: 18446744073709551615n } as unknown as typeof data);
  });
});

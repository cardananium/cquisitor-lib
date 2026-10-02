// Reading the wasm exports out of whatever `import()` produced for them. Kept
// apart from the loader (`load.ts`) so a module that only unwraps a namespace
// someone else loaded — `serveWasm` in a worker that instantiates the wasm by
// hand — does not pull the loader's `import("@cardananium/cquisitor-lib/wasm")`,
// and with it the bundler glue, into a bundle that cannot take it.

import type { WasmModule } from "./functions.js";

/**
 * Whatever `import()` produced for the wasm entry, before it is unwrapped: the
 * ESM namespace in browsers, a CommonJS interop namespace (`default` carrying
 * `module.exports`) in Node.
 */
export type WasmNamespace = Record<string, unknown> & { default?: unknown };

const PROBE_FUNCTION = "cbor_to_json";

/**
 * The wasm exports out of an `import()` namespace. Node's ESM-from-CommonJS
 * interop exposes `module.exports` as `default` and only the statically visible
 * names on the namespace itself, so prefer `default` when it carries the module.
 */
export function unwrapWasmNamespace(ns: unknown): WasmModule {
  const record = (ns ?? {}) as WasmNamespace;
  const dflt = record.default as Record<string, unknown> | undefined;
  if (dflt && typeof dflt === "object" && typeof dflt[PROBE_FUNCTION] === "function") {
    return dflt as unknown as WasmModule;
  }
  if (typeof record[PROBE_FUNCTION] === "function") return record as unknown as WasmModule;
  throw new Error(
    "@cardananium/cquisitor-lib/wasm did not load as the cquisitor wasm module " +
      `(no ${PROBE_FUNCTION} export). In a bundler, make sure it can import .wasm files.`,
  );
}

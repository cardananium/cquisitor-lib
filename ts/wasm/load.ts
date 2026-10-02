// Lazy loader for the wasm module. The only place the library imports its own
// `./wasm` subpath as a value, and it does so dynamically: a host that routes
// every call through a worker never pays for the 7 MB module on its main thread.

import type { WasmModule } from "./functions.js";
import { unwrapWasmNamespace } from "./namespace.js";

export { unwrapWasmNamespace, type WasmNamespace } from "./namespace.js";

let modulePromise: Promise<WasmModule> | null = null;

/**
 * The wasm module, loaded on first use and cached. Rejections are not cached, so
 * a transient failure can be retried by calling again.
 */
export function loadWasm(): Promise<WasmModule> {
  if (!modulePromise) {
    modulePromise = import("@cardananium/cquisitor-lib/wasm")
      .then(unwrapWasmNamespace)
      .catch((error: unknown) => {
        modulePromise = null;
        throw error;
      });
  }
  return modulePromise;
}

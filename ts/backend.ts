// Where the wasm runs. Every typed wrapper goes through `getBackend().callRaw`;
// the default backend loads the wasm into the calling thread on first use, and
// a host that wants isolation (a trap or a runaway script must not take the
// page or server down) configures a worker-backed one instead.

import { asError, isFatalToInstance, LibAbortedError, LibUnavailableError } from "./errors.js";
import { describeWasmFunction, isWasmFunction, type WasmFunctionName, type WasmModule } from "./wasm/functions.js";
import { loadWasm } from "./wasm/load.js";
import { guardInputBudget } from "./worker/inputBudget.js";

/** Options every library call accepts. */
export interface LibCallOptions {
  /**
   * Aborts a call that has not been dispatched yet (rejects with
   * `LibAbortedError`). Once the wasm is running the call is bounded only by
   * `timeoutMs`: wasm cannot be interrupted, and the worker backend keeps its
   * worker (and the wasm it loaded) rather than killing it on every abort, so
   * a signal that fires mid-flight lets the call run to its result or its
   * timeout.
   */
  signal?: AbortSignal;
  /**
   * Deadline for the call in milliseconds, measured from when it is made
   * (time queued behind other calls counts; time a fresh worker spends
   * loading the wasm does not). A worker backend drops a call still queued at
   * its deadline and kills the worker of a running one, rejecting with
   * `LibTimeoutError`; `Infinity`, `0` or a negative value means no deadline.
   * The in-process backend cannot interrupt a running call and ignores it.
   */
  timeoutMs?: number;
}

/**
 * Runs one wasm function by name and resolves to EXACTLY what the function
 * returned: JSON text for the text-answering functions (`answersInJsonText`),
 * the JS value for the others, serde number boxes and all. The typed wrappers
 * do the parsing and normalising, once, on top of this.
 *
 * Implementations must refuse names that are not `WasmFunctionName`s, apply
 * `guardInputBudget`, and reject with a plain `Error` carrying the library's
 * message when the function throws.
 */
export interface LibBackend {
  callRaw<T = unknown>(fn: WasmFunctionName, args: unknown[], options?: LibCallOptions): Promise<T>;
}

export interface InProcessBackendOptions {
  /**
   * How to obtain the wasm module. Defaults to a lazy import of
   * `@cardananium/cquisitor-lib/wasm`; tests pass a stub.
   */
  load?: () => Promise<WasmModule>;
}

/** The default backend: the wasm module in this thread, loaded on first call. */
export interface InProcessBackend extends LibBackend {
  /** Load the wasm ahead of the first call. */
  warm(): Promise<void>;
  /**
   * True once a call trapped or overflowed the stack in this instance. The
   * instance is then unusable and every further call rejects with
   * `LibUnavailableError` (a message fit for end users: it names the
   * operation, not the export); only a fresh page or process recovers. A
   * worker backend avoids this by replacing its worker after a trap.
   */
  readonly poisoned: boolean;
}

/**
 * A backend that runs the wasm in the calling thread. There is no watchdog: a
 * call that never returns blocks the thread, and a trap poisons the instance
 * for good. Fine for scripts, tests and servers that trust their input; use
 * `createWorkerBackend` where isolation matters.
 */
export function createInProcessBackend(options: InProcessBackendOptions = {}): InProcessBackend {
  const load = options.load ?? loadWasm;
  let poisoned = false;
  let poisonedBy: Error | null = null;

  const backend: InProcessBackend = {
    get poisoned() {
      return poisoned;
    },
    async warm(): Promise<void> {
      await load();
    },
    async callRaw<T>(fn: WasmFunctionName, args: unknown[], callOptions?: LibCallOptions): Promise<T> {
      if (!isWasmFunction(fn)) throw new Error(`${String(fn)} is not a callable library function`);
      if (poisoned) {
        // Shown to end users too (a worker backend's fallback is this backend): no export
        // names, and advice that holds whether or not workers exist.
        throw new LibUnavailableError(
          "The library stopped working in this page or process after an earlier fatal error " +
            `(${poisonedBy?.name ?? "Error"}: ${poisonedBy?.message ?? "unknown"}), so it cannot start ` +
            `${describeWasmFunction(fn)}. Reload the page, or restart the process, to get a working one.`,
        );
      }
      guardInputBudget(fn, args);
      if (callOptions?.signal?.aborted) throw new LibAbortedError();
      const wasm = await load();
      const impl = (wasm as unknown as Record<string, unknown>)[fn];
      if (typeof impl !== "function") throw new Error(`The library does not export ${fn}`);
      if (callOptions?.signal?.aborted) throw new LibAbortedError();
      try {
        return (impl as (...a: unknown[]) => unknown)(...args) as T;
      } catch (thrown) {
        const error = asError(thrown);
        if (isFatalToInstance(thrown)) {
          poisoned = true;
          poisonedBy = error;
        }
        throw error;
      }
    },
  };
  return backend;
}

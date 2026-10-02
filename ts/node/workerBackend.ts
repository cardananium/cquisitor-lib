// `createWorkerBackend` over `node:worker_threads`, with the worker entry the
// package ships. Node / Bun only.

import { Worker, type ResourceLimits } from "node:worker_threads";
import { createWorkerBackend, type WorkerBackend, type WorkerBackendTransport } from "../worker/workerBackend.js";

/** The worker entry (`lib/node/wasmWorker.js`), for hosts that spawn the worker themselves. */
export const NODE_WASM_WORKER_ENTRY: URL = new URL("./wasmWorker.js", import.meta.url);

export interface NodeWorkerBackendOptions extends Omit<WorkerBackendTransport, "spawn"> {
  /** Worker entry override; defaults to `NODE_WASM_WORKER_ENTRY`. */
  entry?: URL | string;
  /** Passed to `new Worker(entry, { resourceLimits })`, e.g. `{ maxOldGenerationSizeMb: 1024 }`. */
  resourceLimits?: ResourceLimits;
  /**
   * Passed to `new Worker(entry, { execArgv })`. Defaults to `[]` rather than
   * Node's inherit-from-parent: flags such as `--input-type` or `--eval` are
   * illegal in a worker and would make every spawn fail.
   */
  execArgv?: string[];
  /** Passed to `new Worker(entry, { env })`. */
  env?: NodeJS.ProcessEnv;
}

/**
 * A backend that runs the wasm in a `worker_threads` worker: the server thread
 * never blocks, a trap or a runaway script costs one worker, which is replaced.
 * The worker holds the process open only while a call (or `warm()`) waits on
 * it, so a script exits once its last answer is in; a server calls `dispose()`
 * on shutdown to stop the worker at once.
 *
 *     configure({ backend: createNodeWorkerBackend({ timeoutMs: 30_000 }) });
 */
export function createNodeWorkerBackend(options: NodeWorkerBackendOptions = {}): WorkerBackend {
  const { entry, resourceLimits, execArgv, env, ...transport } = options;
  return createWorkerBackend({
    ...transport,
    spawn: () => new Worker(entry ?? NODE_WASM_WORKER_ENTRY, { resourceLimits, execArgv: execArgv ?? [], env }),
  });
}

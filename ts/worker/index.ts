// Running the wasm behind a worker: the wire protocol (`LibRequest` /
// `LibResponse`), the worker side (`serveWasm`), the host side
// (`createWorkerBackend`), the port adapters and the input-size budgets every
// backend applies. A browser worker file is one line:
//
//     serveWasm(import("@cardananium/cquisitor-lib/wasm"), self);
//
// and the page configures the library once (the fallback is optional: where
// calls go when no worker can be started):
//
//     configure({ backend: createWorkerBackend({
//       spawn: () => new Worker(new URL("./lib.worker.js", import.meta.url), { type: "module" }),
//       fallback: () => createInProcessBackend(),
//     }) });

// The protocol, the two ends and the budgets. The worker-side building
// blocks behind `serveWasm` (`answer`, `reply`, `errorPayload`), the message
// texts of the backend and the port adapters stay on their modules
// (`/worker/serve`, `/worker/workerBackend`, `/worker/ports`) for hosts that
// build their own worker loop.
export * from "./protocol.js";
export type { MessagePortLike, WorkerHandle, WebPortSource, NodePortSource, PortSource, WorkerSource } from "./ports.js";
export { serveWasm } from "./serve.js";
export type { LibModule, WasmSource, WasmServer } from "./serve.js";
export {
  createWorkerBackend,
  DEFAULT_CALL_TIMEOUT_MS,
  DEFAULT_LOAD_TIMEOUT_MS,
  DEFAULT_MAX_CONSECUTIVE_FAILURES,
  DEFAULT_RETRY_AFTER_MS,
  MIN_TURN_MS,
  COLD_TURN_MS,
  COLD_TURN_FLOOR_MS,
} from "./workerBackend.js";
export type { WorkerBackend, WorkerBackendEvent, WorkerBackendStats, WorkerBackendTransport } from "./workerBackend.js";
export * from "./inputBudget.js";

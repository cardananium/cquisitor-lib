// Entry of the `worker_threads` worker `createNodeWorkerBackend` spawns: load
// the wasm in this thread and serve it to the parent.

import { parentPort } from "node:worker_threads";
import { loadWasm } from "../wasm/load.js";
import { serveWasm } from "../worker/serve.js";

if (!parentPort) {
  throw new Error("@cardananium/cquisitor-lib/node wasmWorker must run inside a worker_threads Worker");
}

serveWasm(loadWasm, parentPort);

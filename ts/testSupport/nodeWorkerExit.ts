// Run as its own process by ts/node/workerBackend.test.ts: a script that uses
// the worker_threads backend, gets its answer and never calls dispose(). It
// must exit on its own.
import { createNodeWorkerBackend } from "../node/workerBackend.js";

const backend = createNodeWorkerBackend({ entry: new URL("../node/wasmWorker.ts", import.meta.url) });
const types = await backend.callRaw<string[]>("get_possible_types_for_input", ["05"]);
console.log(JSON.stringify({ int: types.includes("Int"), spawns: backend.stats().spawns }));

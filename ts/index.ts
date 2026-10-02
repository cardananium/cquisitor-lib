// @cardananium/cquisitor-lib — Cardano transaction validation, ledger-type and
// CBOR decoding, CDDL validation and UPLC decoding of Plutus scripts, as one
// typed library.
//
// The wasm is an implementation detail: every function below is async and runs
// through the configured backend — in this thread by default (the wasm loads on
// first use), or in a worker once a host calls `configure({ backend })`.
//
//     import { possibleTypes, decode, cborToJson, validateTransaction } from "@cardananium/cquisitor-lib";
//     const kinds = await possibleTypes(hex);              // ["Transaction", ...]
//     const { transaction } = await decode(hex, "Transaction");
//     const tree = await cborToJson(hex);                  // positional CBOR tree
//
// Integers in every answer are `number` when they fit 2^53 and `bigint` above
// (declared `number | bigint` where the Rust side has a u64).
//
// Node-only helpers (`nodeBrotliCompressor`, `createNodeWorkerBackend`) live
// under `@cardananium/cquisitor-lib/node`; the raw wasm exports under
// `@cardananium/cquisitor-lib/wasm`. Every group is also its own subpath
// (`/chain`, `/share`, `/cddl`, `/worker`, `/util`, `/handoff`, `/types`) and
// every module under it (`/chain/koiosClient`, ...).

// ---- the typed API over the wasm ----
export * from "./api/index.js";

// ---- configuration and backends ----
export { configure, resetConfig, getBackend, getCompressor, getLogger, isBackendConfigured, isCompressorConfigured } from "./configure.js";
export type { LibConfig, Compressor, LibLogger } from "./configure.js";
export { createInProcessBackend } from "./backend.js";
export type { LibBackend, LibCallOptions, InProcessBackend, InProcessBackendOptions } from "./backend.js";
export * from "./errors.js";

// ---- running the wasm in a worker (protocol, serveWasm, createWorkerBackend, budgets) ----
export * from "./worker/index.js";
export { loadWasm } from "./wasm/load.js";

// ---- every type the wasm declares (results, contexts, CBOR/CDDL shapes) ----
export type * from "@cardananium/cquisitor-lib/wasm";

// ---- chain data (Koios / Blockfrost) and the online validation pipeline ----
export * from "./chain/index.js";

// ---- share-link codec, CBOR/CDDL diagnostics readers, de-uplc hand-off, helpers, tx model ----
export * from "./share/index.js";
export * from "./cddl/index.js";
export * from "./handoff/deUplcLink.js";
export * from "./util/index.js";
export type * from "./types/transaction.js";

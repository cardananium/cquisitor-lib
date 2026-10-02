// Node / Bun only additions: a brotli `Compressor` over node:zlib and a
// `worker_threads` backend. Import as `@cardananium/cquisitor-lib/node`.
// Nothing here is re-exported from the package root, so browser bundles that
// import the root never see a `node:` import.

export { nodeBrotliCompress, nodeBrotliDecompress, nodeBrotliCompressor } from "./compressor.js";
export { createNodeWorkerBackend, NODE_WASM_WORKER_ENTRY, type NodeWorkerBackendOptions } from "./workerBackend.js";

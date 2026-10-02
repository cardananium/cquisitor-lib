// Library-wide configuration. Nothing here is required: without `configure`
// the wasm runs in the calling thread (loaded on first use) and warnings go
// to `console.error`. A host registers a worker backend, a brotli compressor
// for share links, or a logger once, and the modules that need them read the
// current value lazily, at call time.

import { createInProcessBackend, type InProcessBackend, type LibBackend } from "./backend.js";

/** Byte compressor used by the share-link codec (`e=b` payloads are brotli). */
export interface Compressor {
  compress(bytes: Uint8Array): Promise<Uint8Array>;
  /**
   * Decompress `bytes`. Must reject once the output would exceed `maxBytes`:
   * compression ratio is unbounded, so the input size bounds nothing.
   */
  decompress(bytes: Uint8Array, maxBytes: number): Promise<Uint8Array>;
}

/** Where non-fatal diagnostics go. Defaults to `console.error` so stdout stays clean. */
export interface LibLogger {
  warn(msg: string, err?: unknown): void;
}

export interface LibConfig {
  /** Where the wasm runs. Default: in this thread (`createInProcessBackend`). */
  backend?: LibBackend;
  /** Brotli for `e=b` share links. No default: browsers bring brotli-wasm, Node uses `nodeBrotliCompressor` from `./node`. */
  compressor?: Compressor;
  logger?: LibLogger;
}

const defaultLogger: LibLogger = {
  warn(msg: string, err?: unknown): void {
    if (err === undefined) console.error(msg);
    else console.error(msg, err);
  },
};

interface State {
  backend: LibBackend | null;
  defaultBackend: InProcessBackend | null;
  compressor: Compressor | null;
  logger: LibLogger;
}

const state: State = {
  backend: null,
  defaultBackend: null,
  compressor: null,
  logger: defaultLogger,
};

/**
 * Register services. Merges: a field left out keeps its current value, so
 * different entry points may each register the one service they provide.
 */
export function configure(config: LibConfig): void {
  if (config.backend !== undefined) state.backend = config.backend;
  if (config.compressor !== undefined) state.compressor = config.compressor;
  if (config.logger !== undefined) state.logger = config.logger;
}

/**
 * Back to the defaults: in-process backend, no compressor, console logger
 * (tests). The default backend itself is kept: it wraps the one wasm instance
 * this thread has, poisoned or not.
 */
export function resetConfig(): void {
  state.backend = null;
  state.compressor = null;
  state.logger = defaultLogger;
}

/** True when a host registered a backend (otherwise calls run in this thread). */
export function isBackendConfigured(): boolean {
  return state.backend !== null;
}

export function isCompressorConfigured(): boolean {
  return state.compressor !== null;
}

/** The configured backend, or the in-process default (created on first use, wasm loaded on first call). */
export function getBackend(): LibBackend {
  if (state.backend) return state.backend;
  if (!state.defaultBackend) state.defaultBackend = createInProcessBackend();
  return state.defaultBackend;
}

export function getCompressor(): Compressor {
  if (!state.compressor) {
    throw new Error("configure({ compressor }) must be called first: no compressor is registered");
  }
  return state.compressor;
}

export function getLogger(): LibLogger {
  return state.logger;
}

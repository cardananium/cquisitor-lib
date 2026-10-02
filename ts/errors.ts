// Failures that are not library answers: the call was refused, abandoned or
// never ran. A library answer that is an exception (bad hex, a schema that does
// not parse, ...) is rethrown as a plain `Error` carrying the library's message.

/** Input refused before it reached the library, on size (see `inputBudgetFor`). */
export class LibInputTooLargeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LibInputTooLargeError";
  }
}

/** A call that reached its deadline: dropped while still queued, or abandoned running (the worker holding it was killed). */
export class LibTimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LibTimeoutError";
  }
}

/** The wasm could not be reached: the worker died or never started, or an in-process instance is poisoned. */
export class LibUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LibUnavailableError";
  }
}

/** The library answered, but its answer could not cross the worker boundary (structured clone failed). */
export class LibResultNotTransferableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LibResultNotTransferableError";
  }
}

/** The caller dropped the call before it was dispatched. */
export class LibAbortedError extends Error {
  constructor(message = "The library call was aborted before it ran.") {
    super(message);
    this.name = "LibAbortedError";
  }
}

export function isLibAbortedError(error: unknown): boolean {
  return error instanceof LibAbortedError;
}

/**
 * True when the throw is a size/timeout/unavailable/clone refusal, not a
 * library answer. A `LibAbortedError` (the caller withdrew the call) is not a
 * refusal: test it with `isLibAbortedError`.
 */
export function isLibRefusal(error: unknown): boolean {
  return (
    error instanceof LibInputTooLargeError ||
    error instanceof LibTimeoutError ||
    error instanceof LibUnavailableError ||
    error instanceof LibResultNotTransferableError
  );
}

/** The sentence a panel shows for a failure. */
export function libErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

/** The one corner of the `WebAssembly` global this module needs (typed locally: the library compiles without lib.dom). */
interface WebAssemblyGlobal {
  RuntimeError?: abstract new (...args: never[]) => Error;
}

/** Wasm trap (`unreachable`, a Rust panic): the instance is poisoned and must not be reused. */
export function isWasmTrap(error: unknown): boolean {
  const wasm = (globalThis as { WebAssembly?: WebAssemblyGlobal }).WebAssembly;
  if (wasm && typeof wasm.RuntimeError === "function" && error instanceof wasm.RuntimeError) return true;
  return error instanceof Error && error.name === "RuntimeError";
}

/** Stack overflow inside wasm leaves the instance's stack pointer unrestored, so later calls trap. */
export function isStackOverflow(error: unknown): boolean {
  return error instanceof RangeError;
}

/** True when the wasm instance that threw `error` can no longer be trusted. */
export function isFatalToInstance(error: unknown): boolean {
  return isWasmTrap(error) || isStackOverflow(error);
}

/**
 * The library throws strings as well as `Error`s (wasm-bindgen passes a Rust
 * `Err(String)` through as a JS string). Present every library exception as an
 * `Error` so callers can rely on `.message`.
 */
export function asError(thrown: unknown): Error {
  if (thrown instanceof Error) return thrown;
  return new Error(typeof thrown === "string" ? thrown : String(thrown));
}

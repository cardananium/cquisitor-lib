// Wire format between a host and the worker that owns the wasm. No imports from
// either side; every message is a plain, structured-cloneable object.

import type { WasmFunctionName } from "../wasm/functions.js";

export {
  WASM_FUNCTIONS,
  isWasmFunction,
  answersInJsonText,
  describeWasmFunction,
  type WasmFunctionName,
  type WasmFunctionArgs,
  type WasmFunctionResult,
  type ParsedResult,
  type WasmModule,
} from "../wasm/functions.js";

export interface LibRequest {
  id: number;
  /** Worker generation. Replies from a worker that has been replaced are dropped. */
  gen: number;
  fn: WasmFunctionName;
  args: unknown[];
}

export function isLibRequest(value: unknown): value is LibRequest {
  if (typeof value !== "object" || value === null) return false;
  const m = value as Partial<LibRequest>;
  return typeof m.id === "number" && typeof m.gen === "number" && typeof m.fn === "string" && Array.isArray(m.args);
}

/** Extra error kind: clone failed after the library answered. Reported so the host does not blame the input. */
export type LibErrorKind = "result_not_transferable";

export interface LibErrorPayload {
  name: string;
  message: string;
  /** True for a wasm trap or stack overflow: that instance is poisoned and the worker must be discarded. */
  fatal: boolean;
  kind?: LibErrorKind;
}

/**
 * Posted once when the wasm load settles. Call budgets must not run before this.
 * With `error`, the module did not load and the worker cannot serve anything.
 */
export interface LibLoadedMessage {
  type: "loaded";
  error?: LibErrorPayload;
}

export function isLibLoadedMessage(value: unknown): value is LibLoadedMessage {
  return typeof value === "object" && value !== null && (value as { type?: unknown }).type === "loaded";
}

/**
 * One answer. `value` is exactly what the wasm function returned (JSON text for
 * the text-answering functions), so a backend built on this protocol satisfies
 * the `LibBackend.callRaw` contract by forwarding it.
 */
export type LibResponse =
  | { id: number; gen: number; ok: true; value: unknown }
  | { id: number; gen: number; ok: false; error: LibErrorPayload };

export function isLibResponse(value: unknown): value is LibResponse {
  if (typeof value !== "object" || value === null) return false;
  const m = value as Partial<LibResponse>;
  return typeof m.id === "number" && typeof m.gen === "number" && typeof m.ok === "boolean";
}

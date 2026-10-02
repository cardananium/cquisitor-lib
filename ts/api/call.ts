// The one path from a typed wrapper to the wasm: `getBackend().callRaw`, then
// the answer read once — JSON text parsed exactly (`parseJsonExact`), JS values
// with serde number boxes unboxed (`convertSerdeNumbers`). Integers that fit a
// double come back as `number`, larger ones as `bigint`; a caller never sees a
// serde box or a rounded lovelace amount.

import type { LibCallOptions } from "../backend.js";
import { getBackend } from "../configure.js";
import { parseJsonExact } from "../util/json.js";
import { convertSerdeNumbers } from "../util/serdeNumbers.js";
import { answersInJsonText, type ParsedResult, type WasmFunctionArgs, type WasmFunctionName } from "../wasm/functions.js";

/** Parse or normalise a raw backend answer the way the typed wrappers do. */
export function readAnswer<T>(fn: WasmFunctionName, raw: unknown): T {
  if (answersInJsonText(fn)) {
    if (typeof raw !== "string") {
      throw new Error(`The library answered ${fn} with something other than JSON text`);
    }
    return parseJsonExact<T>(raw);
  }
  return convertSerdeNumbers(raw) as T;
}

/**
 * Run `fn` through the configured backend with its declared argument types and
 * get the normalised answer, typed from the declaration (`ParsedResult<F>`: a
 * `JsonText<X>` answer comes back as `X`). Every typed wrapper is one line on
 * top of this; pass `T` only to narrow further (`callLib<"decode_specific_type", MyType>`).
 */
export async function callLib<F extends WasmFunctionName, T = ParsedResult<F>>(
  fn: F,
  args: WasmFunctionArgs<F>,
  options?: LibCallOptions,
): Promise<T> {
  const raw = await getBackend().callRaw<unknown>(fn, args as unknown[], options);
  return readAnswer<T>(fn, raw);
}

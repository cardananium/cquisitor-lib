// Size ceiling for a single library call.
// Decoder allocation is unbounded and a wasm trap is permanent for that instance.
// Timeouts cannot cover it: the allocation is one synchronous call.

import { LibInputTooLargeError } from "../errors.js";
import type { WasmFunctionName } from "../wasm/functions.js";

/**
 * Largest input any single library call will accept, in bytes, counted over
 * all of its arguments together (see `argumentByteLength`): the UTF-8 length
 * of every string, nested ones in arrays and objects included, plus about the
 * JSON size of the arrays and objects that hold them.
 */
export const MAX_LIB_INPUT_BYTES = 2 * 1024 * 1024;

/** Max decompressed share-link payload. Higher than the call budget: validator links also carry chain context. */
export const MAX_SHARE_PAYLOAD_BYTES = 8 * 1024 * 1024;

/**
 * UTF-8 length of `text` without allocating an encoded copy.
 * Stops once `text.length` already exceeds `limit` (UTF-8 is never shorter than UTF-16).
 */
export function utf8ByteLength(text: string, limit = Number.POSITIVE_INFINITY): number {
  if (text.length > limit) return text.length;
  let bytes = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c < 0x80) bytes += 1;
    else if (c < 0x800) bytes += 2;
    else if (c >= 0xd800 && c <= 0xdbff) {
      // Surrogate pair: one 4-byte code point; skip the low half.
      bytes += 4;
      i++;
    } else bytes += 3;
  }
  return bytes;
}

/**
 * Size of a call's arguments, in bytes, as the wasm will see them: a string
 * counts its UTF-8 length, a byte array its length, a number, bigint or boolean
 * the length of its text, and an array, plain object, `Map` or `Set` everything
 * inside it (keys included) plus one byte per entry, which is about the size of
 * its JSON. Nested strings count as much as top-level ones, so a witness list or
 * a UTxO array cannot carry past the budget what one string argument could not.
 * Iterative (no stack per level) and cycle-safe. Exact up to `limit`; once the
 * total passes it, strings are counted by their length alone (a lower bound of
 * their UTF-8 size, with no scan of their text), so the answer is then a lower
 * bound.
 */
export function argumentByteLength(args: readonly unknown[], limit?: number): number {
  const cap = limit ?? Number.POSITIVE_INFINITY;
  let total = 0;
  const pending: unknown[] = [...args];
  const seen = new Set<object>();
  while (pending.length > 0) {
    const value = pending.pop();
    switch (typeof value) {
      case "string":
        total += utf8ByteLength(value, cap - total);
        break;
      case "number":
      case "bigint":
      case "boolean":
        total += String(value).length;
        break;
      case "object": {
        if (value === null) {
          total += 4;
          break;
        }
        if (seen.has(value)) break;
        seen.add(value);
        if (value instanceof ArrayBuffer) total += value.byteLength;
        else if (ArrayBuffer.isView(value)) total += value.byteLength;
        else if (Array.isArray(value)) {
          total += value.length + 1;
          for (const item of value) pending.push(item);
        } else if (value instanceof Map) {
          total += value.size + 1;
          for (const [k, v] of value) pending.push(k, v);
        } else if (value instanceof Set) {
          total += value.size + 1;
          for (const item of value) pending.push(item);
        } else {
          const record = value as Record<string, unknown>;
          const keys = Object.keys(record);
          total += keys.length + 1;
          for (const key of keys) {
            total += utf8ByteLength(key, cap - total);
            pending.push(record[key]);
          }
        }
        break;
      }
      default:
        // undefined, functions, symbols: nothing the wasm reads.
        break;
    }
  }
  return total;
}

/** Human-readable byte count, rounded to the nearest unit shown (`round: "down"` never overstates). */
export function formatByteSize(bytes: number, round: "nearest" | "down" = "nearest"): string {
  const fit = (value: number, decimals: number) => {
    const scale = 10 ** decimals;
    // The epsilon keeps a value that is exactly on a step (2.0) from flooring below it through float error.
    const rounded = (round === "down" ? Math.floor(value * scale + 1e-9) : Math.round(value * scale)) / scale;
    return rounded.toFixed(decimals);
  };
  if (bytes < 1024) return `${fit(bytes, 0)} B`;
  const kb = bytes / 1024;
  if (kb < 1024) return `${fit(kb, kb < 10 ? 1 : 0)} KB`;
  const mb = kb / 1024;
  return `${fit(mb, mb < 10 ? 1 : 0)} MB`;
}

export interface OverBudgetOptions {
  /**
   * `bytes` is a lower bound, not the size (`argumentByteLength` stops reading
   * text once the total is over the limit): the message says "at least".
   */
  atLeast?: boolean;
}

/**
 * `null` if `bytes` fits, otherwise a message that names the limit and the
 * size, when the size reads differently from the limit once rounded ("at
 * least ..." for a lower bound, see `OverBudgetOptions`).
 */
export function overBudgetMessage(
  bytes: number,
  limit: number,
  subject = "This input",
  options: OverBudgetOptions = {},
): string | null {
  if (bytes <= limit) return null;
  const limitText = formatByteSize(limit);
  const sizeText = formatByteSize(bytes, options.atLeast ? "down" : "nearest");
  const size = sizeText === limitText ? "" : `${options.atLeast ? "at least " : ""}${sizeText}, `;
  return (
    `${subject} is ${size}over the ${limitText} limit. ` +
    `A document that size can exhaust the decoder's memory before it produces ` +
    `anything, so it is refused rather than attempted.`
  );
}

/**
 * Per-function input-size ceilings. `validate_transaction_js` and
 * `execute_tx_scripts` include fetched chain context (UTxOs with their inline
 * datums and reference scripts, cost models), not just the tx bytes.
 */
const INPUT_BUDGETS: Partial<Record<WasmFunctionName, number>> = {
  validate_transaction_js: 16 * 1024 * 1024,
  execute_tx_scripts: 16 * 1024 * 1024,
};

/** The ceiling that applies to one call. */
export function inputBudgetFor(fn: WasmFunctionName): number {
  return INPUT_BUDGETS[fn] ?? MAX_LIB_INPUT_BYTES;
}

/** Refuse oversized input (every argument, nested ones included) before it is copied into wasm. Shared by every backend. */
export function guardInputBudget(fn: WasmFunctionName, args: readonly unknown[]): void {
  const limit = inputBudgetFor(fn);
  const bytes = argumentByteLength(args, limit);
  const message = overBudgetMessage(bytes, limit, "This input", { atLeast: true });
  if (message) throw new LibInputTooLargeError(message);
}

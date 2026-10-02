// JSON with integers that do not fit a double.
//
// The library writes u64 / i128 values (lovelace, ex-units, slots, deposits) as
// bare JSON integers, and serde_json boxes the ones it cannot place in a number
// as `{"$serde_json::private::Number": "123"}`. `JSON.parse` rounds anything past
// 2^53 silently. `parseJsonExact` keeps every integer exact: a literal that fits
// stays a `number`, a larger one becomes a `bigint` (or, on request, a decimal
// string), and the serde boxes are unboxed the same way, so a caller never sees
// them.
//
// Node >= 21 (V8 >= 11.4) hands a JSON.parse reviver the literal's source text;
// there the reviver does the work. Elsewhere (Node 20), and for a document
// nested deeper than the reviver's recursion can go, the text is rewritten once,
// iteratively, so that unsafe integer literals become string literals before
// JSON.parse sees them. Both paths give the same answer for every input.

import { configure as configureStringify } from "safe-stable-stringify";

const SERDE_NUMBER_KEY = "$serde_json::private::Number";

type Reviver = (this: unknown, key: string, value: unknown, context?: { source?: string }) => unknown;

/** True when JSON.parse hands the reviver a `context.source` (Node >= 21, V8 >= 11.4). */
export const REVIVER_HAS_SOURCE: boolean = (() => {
  let seen = false;
  try {
    (JSON.parse as unknown as (t: string, r: Reviver) => unknown)("1", function (_k, v, context) {
      seen = typeof context?.source === "string";
      return v;
    });
  } catch {
    seen = false;
  }
  return seen;
})();

const INTEGER_LITERAL = /^-?\d+$/;

/** How `parseJsonExact` represents an integer that does not fit a JS number exactly. */
export type BigIntegerForm = "bigint" | "string";

export interface ParseJsonExactOptions {
  /** `"bigint"` (default) or `"string"` (its decimal text, for wire formats without BigInt). */
  bigIntegers?: BigIntegerForm;
}

/** Decimal integer text -> number when exactly representable, else bigint or the normalised text. */
export function integerFromText(text: string, form: BigIntegerForm = "bigint"): number | bigint | string {
  const asNumber = Number(text);
  if (Number.isSafeInteger(asNumber)) return asNumber;
  const normalised = normalizeDecimal(text);
  return form === "bigint" ? BigInt(normalised) : normalised;
}

function normalizeDecimal(text: string): string {
  // "-0", "+5", "007" are not produced by serde, but be tolerant.
  let t = text.trim();
  let negative = false;
  if (t.startsWith("-")) {
    negative = true;
    t = t.slice(1);
  } else if (t.startsWith("+")) {
    t = t.slice(1);
  }
  t = t.replace(/^0+(?=\d)/, "");
  if (t === "0" || t === "") return "0";
  return negative ? `-${t}` : t;
}

/** The value a serde number box stands for, or `undefined` when `value` is not one. */
function unboxSerde(
  value: Record<string, unknown>,
  form: BigIntegerForm,
  quoted = false,
): number | bigint | string | undefined {
  if (!(SERDE_NUMBER_KEY in value)) return undefined;
  let raw = value[SERDE_NUMBER_KEY];
  // On the quoting path a bare big literal inside the box arrives quoted.
  if (quoted && typeof raw === "string") raw = unquote(raw, form);
  if (typeof raw === "string") return INTEGER_LITERAL.test(raw) ? integerFromText(raw, form) : Number(raw);
  if (typeof raw === "number") return raw;
  if (typeof raw === "bigint") return bigintTo(raw, form);
  return undefined;
}

function bigintTo(value: bigint, form: BigIntegerForm): number | bigint | string {
  if (value >= BigInt(Number.MIN_SAFE_INTEGER) && value <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(value);
  return form === "bigint" ? value : value.toString();
}

/**
 * Rewrites every integer literal outside the safe range into a JSON string
 * literal, walking the text once and skipping string contents. Used when the
 * reviver has no `context.source`, and as the fallback when it overflows.
 *
 * With a `mark`, each quoted integer is written as `"<mark><digits>"`, and
 * every string VALUE of the document that itself begins with `mark` (written
 * raw or as `\u` escapes) gets a second `mark` in front, so after `JSON.parse`
 * one leading `mark` means "quoted integer" and two mean "the document's own
 * string, less one mark". Object keys are never rewritten.
 */
export function quoteUnsafeIntegers(text: string, mark = ""): string {
  let out = "";
  let i = 0;
  const n = text.length;
  let lastFlush = 0;
  while (i < n) {
    const ch = text.charCodeAt(i);
    if (ch === 0x22 /* " */) {
      const open = i;
      i++;
      while (i < n) {
        const c = text.charCodeAt(i);
        if (c === 0x5c /* \ */) {
          i += 2;
          continue;
        }
        if (c === 0x22) break;
        i++;
      }
      i++;
      if (mark !== "" && literalStartsWith(text, open + 1, mark) && !followedByColon(text, i)) {
        out += text.slice(lastFlush, open + 1) + mark;
        lastFlush = open + 1;
      }
      continue;
    }
    if (ch === 0x2d /* - */ || (ch >= 0x30 && ch <= 0x39)) {
      const start = i;
      if (ch === 0x2d) i++;
      while (i < n) {
        const c = text.charCodeAt(i);
        if (c >= 0x30 && c <= 0x39) i++;
        else break;
      }
      // fraction / exponent -> a float, leave it alone
      let isFloat = false;
      if (i < n) {
        const c = text.charCodeAt(i);
        if (c === 0x2e /* . */ || c === 0x65 /* e */ || c === 0x45 /* E */) {
          isFloat = true;
          i++;
          while (i < n) {
            const d = text.charCodeAt(i);
            if ((d >= 0x30 && d <= 0x39) || d === 0x2b || d === 0x2d || d === 0x2e || d === 0x65 || d === 0x45) i++;
            else break;
          }
        }
      }
      if (!isFloat) {
        const literal = text.slice(start, i);
        if (literal !== "-" && !Number.isSafeInteger(Number(literal))) {
          out += text.slice(lastFlush, start) + '"' + mark + normalizeDecimal(literal) + '"';
          lastFlush = i;
        }
      }
      continue;
    }
    i++;
  }
  return lastFlush === 0 ? text : out + text.slice(lastFlush);
}

/**
 * The UTF-16 code unit a JSON string literal holds at `i` (escapes decoded)
 * and the index after it; `null` at the closing quote or the end of the text.
 */
function literalUnitAt(text: string, i: number): [unit: number, next: number] | null {
  if (i >= text.length) return null;
  const c = text.charCodeAt(i);
  if (c === 0x22 /* " */) return null;
  if (c !== 0x5c /* \ */) return [c, i + 1];
  const escape = text.charCodeAt(i + 1);
  switch (escape) {
    case 0x75 /* u */: {
      const hex = text.slice(i + 2, i + 6);
      return [/^[0-9a-fA-F]{4}$/.test(hex) ? parseInt(hex, 16) : -1, i + 6];
    }
    case 0x62 /* b */:
      return [0x08, i + 2];
    case 0x66 /* f */:
      return [0x0c, i + 2];
    case 0x6e /* n */:
      return [0x0a, i + 2];
    case 0x72 /* r */:
      return [0x0d, i + 2];
    case 0x74 /* t */:
      return [0x09, i + 2];
    default:
      // \" \\ \/ stand for themselves (anything else is invalid JSON; JSON.parse rejects it).
      return [escape, i + 2];
  }
}

/** Whether the string literal whose content starts at `start` begins with `prefix`, escapes decoded. */
function literalStartsWith(text: string, start: number, prefix: string): boolean {
  let i = start;
  for (let k = 0; k < prefix.length; k++) {
    const unit = literalUnitAt(text, i);
    if (unit === null || unit[0] !== prefix.charCodeAt(k)) return false;
    i = unit[1];
  }
  return true;
}

/** Whether the next non-whitespace character at or after `i` is `:` (the literal before it is an object key). */
function followedByColon(text: string, i: number): boolean {
  while (i < text.length) {
    const c = text.charCodeAt(i);
    if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
    else return c === 0x3a /* : */;
  }
  return false;
}

/**
 * Marks a string literal `quoteUnsafeIntegers` made out of an integer, so the
 * walk that follows can tell it from a string the document itself contained.
 * A document string that begins with it is escaped by doubling (see
 * `quoteUnsafeIntegers`), so any input round-trips, this code point included.
 */
const QUOTED_MARK = "\u{10FFFD}";

/**
 * `JSON.parse` that keeps every integer exact. Literals outside ±2^53 become
 * `bigint` (or decimal strings with `{ bigIntegers: "string" }`); serde number
 * boxes are unboxed the same way. Iterative on the fallback path, so document
 * depth costs no stack.
 */
export function parseJsonExact<T = unknown>(text: string, options: ParseJsonExactOptions = {}): T {
  const form = options.bigIntegers ?? "bigint";
  if (REVIVER_HAS_SOURCE) {
    try {
      return finishParse(parseWithReviver(text, form), form, false) as T;
    } catch (error) {
      // V8 walks the reviver recursively: a document nested a few thousand levels
      // deep overflows the stack although plain JSON.parse (iterative) handles it.
      if (!(error instanceof RangeError)) throw error;
    }
  }
  return parseQuoted(text, form) as T;
}

/**
 * `parseJsonExact` without the reviver: the path it takes on engines whose
 * `JSON.parse` reviver sees no source text (Node 20) and for documents nested
 * past the reviver's recursion. Same answer as `parseJsonExact` for every
 * input; exported so that path can be exercised on any engine.
 */
export function parseJsonExactWithoutReviver<T = unknown>(text: string, options: ParseJsonExactOptions = {}): T {
  return parseQuoted(text, options.bigIntegers ?? "bigint") as T;
}

function parseQuoted(text: string, form: BigIntegerForm): unknown {
  return finishParse(JSON.parse(quoteUnsafeIntegers(text, QUOTED_MARK)), form, true);
}

function parseWithReviver(text: string, form: BigIntegerForm): unknown {
  return (JSON.parse as unknown as (t: string, r: Reviver) => unknown)(text, function (_key, value, context) {
    // Not `Number.isInteger`: a literal past ~1.8e308 parses to Infinity, which is
    // no integer, yet its source is one and must stay exact.
    if (typeof value === "number" && !Number.isSafeInteger(value)) {
      const source = context?.source;
      if (source !== undefined && INTEGER_LITERAL.test(source)) return integerFromText(source, form);
    }
    return value;
  });
}

/**
 * Undo `quoteUnsafeIntegers`: one leading mark is a quoted integer, two are a
 * string of the document's own that began with the mark. Other strings pass through.
 */
function unquote(value: string, form: BigIntegerForm): unknown {
  if (!value.startsWith(QUOTED_MARK)) return value;
  const rest = value.slice(QUOTED_MARK.length);
  if (rest.startsWith(QUOTED_MARK)) return rest;
  return integerFromText(rest, form);
}

/** Unbox serde boxes (and undo integer quoting) in place; iterative. */
function finishParse(root: unknown, form: BigIntegerForm, quoted: boolean): unknown {
  if (root === null || typeof root !== "object") {
    return quoted && typeof root === "string" ? unquote(root, form) : root;
  }
  if (!Array.isArray(root)) {
    const boxed = unboxSerde(root as Record<string, unknown>, form, quoted);
    if (boxed !== undefined) return boxed;
  }
  const stack: Array<Record<string, unknown> | unknown[]> = [root as Record<string, unknown> | unknown[]];
  while (stack.length > 0) {
    const node = stack.pop()!;
    const keys: Array<string | number> = Array.isArray(node) ? node.map((_, i) => i) : Object.keys(node);
    for (const key of keys) {
      const child = (node as Record<string | number, unknown>)[key];
      if (child !== null && typeof child === "object") {
        const boxed = Array.isArray(child) ? undefined : unboxSerde(child as Record<string, unknown>, form, quoted);
        if (boxed !== undefined) setOwn(node, key, boxed);
        else stack.push(child as Record<string, unknown> | unknown[]);
      } else if (quoted && typeof child === "string") {
        const restored = unquote(child, form);
        if (restored !== child) setOwn(node, key, restored);
      }
    }
  }
  return root;
}

/** Assign `key` as an own property; `__proto__` must not go through the prototype setter. */
function setOwn(target: Record<string, unknown> | unknown[], key: string | number, value: unknown): void {
  if (Array.isArray(target)) {
    target[key as number] = value;
  } else if (key === "__proto__") {
    Object.defineProperty(target, key, { value, writable: true, enumerable: true, configurable: true });
  } else {
    (target as Record<string, unknown>)[key as string] = value;
  }
}

const stringifyWithBigints = configureStringify({ bigint: true, deterministic: false });

/**
 * JSON text for a value that may contain `bigint`, written as bare integer
 * literals (what serde expects for u64 fields). Key order is preserved;
 * everything else follows `JSON.stringify` (undefined members are dropped, a
 * circular reference becomes `"[Circular]"`).
 */
export function stringifyJsonExact(value: unknown): string {
  return stringifyWithBigints(value) ?? "null";
}

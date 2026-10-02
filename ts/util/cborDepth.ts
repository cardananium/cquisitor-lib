import { hexToBytes } from "./hex.js";

/**
 * Nesting depth from CBOR headers (root = 0; arrays, maps, and tags add a level; string chunks do not).
 * Stops once depth exceeds `ceiling`, or at the first unreadable header.
 */
export function cborNestingDepth(bytes: Uint8Array, ceiling: number): number {
  return scanDepth(bytes, ceiling, null);
}

/** A byte string directly under tag 24, met by the scan: the bytes it carries and the level it sits at. */
interface EmbeddedPayload {
  level: number;
  bytes: Uint8Array;
}

/** Embedding levels {@link cborNestingDepthThroughEmbedded} follows, as the library does. */
const MAX_FOLLOWED_EMBEDDINGS = 2;

/**
 * {@link cborNestingDepth}, reading every byte string under tag 24 (`#6.24(bstr)`: an output's inline datum
 * `[1, #6.24(bytes)]`, a script reference `#6.24(bytes)`) as the item it carries, in place: the payload's root
 * sits at the byte string's level and its items below it; an indefinite-length byte string there counts as its
 * spliced chunks, and a payload is measured as far as its bytes are well-formed. This is the depth the typed
 * decoders recurse to, since they parse those payloads while reading the document. Stops once past `ceiling`.
 */
export function cborNestingDepthThroughEmbedded(bytes: Uint8Array, ceiling: number): number {
  let deepest = 0;
  const pending: { bytes: Uint8Array; base: number; embedding: number }[] = [{ bytes, base: 0, embedding: 0 }];
  while (pending.length > 0) {
    const { bytes: document, base, embedding } = pending.pop()!;
    const found: EmbeddedPayload[] = [];
    const depth = scanDepth(document, Math.max(0, ceiling - base), embedding < MAX_FOLLOWED_EMBEDDINGS ? found : null);
    deepest = Math.max(deepest, base + depth);
    if (deepest > ceiling) break;
    for (const payload of found) pending.push({ bytes: payload.bytes, base: base + payload.level, embedding: embedding + 1 });
  }
  return deepest;
}

/** The header scan behind both depths; with `embedded`, byte strings directly under tag 24 are recorded there. */
function scanDepth(bytes: Uint8Array, ceiling: number, embedded: EmbeddedPayload[] | null): number {
  interface Frame {
    /** Remaining items, or `null` for an indefinite container closed by break. */
    remaining: number | null;
    /** Whether items sit one level below this container. */
    nests: boolean;
    /** Tag 24: the byte string it wraps carries an embedded item. */
    embeds: boolean;
    /** An indefinite byte string under tag 24: its level and the chunks read so far. */
    splice: { level: number; chunks: Uint8Array[] } | null;
  }
  const stack: Frame[] = [];
  let depth = 0;
  let deepest = 0;
  let i = 0;
  const n = bytes.length;

  const readArgument = (additional: number, at: number): { value: number | null; width: number } | null => {
    if (additional < 24) return { value: additional, width: 0 };
    if (additional === 31) return { value: null, width: 0 };
    const width = additional === 24 ? 1 : additional === 25 ? 2 : additional === 26 ? 4 : additional === 27 ? 8 : -1;
    if (width < 0 || at + width > n) return null;
    let value = 0;
    for (let k = 0; k < width; k++) value = value * 256 + bytes[at + k];
    return { value, width };
  };

  for (;;) {
    while (stack.length > 0 && stack[stack.length - 1].remaining === 0) {
      if (stack.pop()!.nests) depth--;
    }
    if (i >= n) break;

    const initial = bytes[i];
    if (initial === 0xff) {
      i++;
      const top = stack[stack.length - 1];
      if (top && top.remaining === null) {
        const closed = stack.pop()!;
        if (closed.nests) depth--;
        if (closed.splice && embedded) {
          const length = closed.splice.chunks.reduce((sum, chunk) => sum + chunk.length, 0);
          const spliced = new Uint8Array(length);
          let at = 0;
          for (const chunk of closed.splice.chunks) {
            spliced.set(chunk, at);
            at += chunk.length;
          }
          embedded.push({ level: closed.splice.level, bytes: spliced });
        }
        continue;
      }
      break;
    }

    if (depth > deepest) {
      deepest = depth;
      if (deepest > ceiling) return deepest;
    }
    const top = stack[stack.length - 1];
    const chunk = top !== undefined && !top.nests;
    const underTag24 = top !== undefined && top.embeds;
    if (top && top.remaining !== null) top.remaining--;

    const major = initial >> 5;
    const argument = readArgument(initial & 0x1f, i + 1);
    if (argument === null) break;
    i += 1 + argument.width;
    const { value } = argument;
    const embeds = embedded !== null && underTag24 && major === 2;
    const level = depth;
    const open = (remaining: number | null, nests: boolean, tag24 = false, splice: Frame["splice"] = null) => {
      stack.push({ remaining, nests, embeds: tag24, splice });
      if (nests) depth++;
    };

    switch (major) {
      // Definite strings skip payload; indefinite strings chunk in place (do not nest).
      case 2:
      case 3:
        if (value === null) open(null, false, false, embeds ? { level, chunks: [] } : null);
        else if (i + value <= n) {
          if (embeds) embedded!.push({ level, bytes: bytes.subarray(i, i + value) });
          else if (chunk && major === 2 && top?.splice) top.splice.chunks.push(bytes.subarray(i, i + value));
          i += value;
        } else return deepest;
        break;
      case 4:
        if (value === null) open(null, true);
        else if (value > 0) open(value, true);
        break;
      // n pairs → 2n items, all one level down.
      case 5:
        if (value === null) open(null, true);
        else if (value > 0) open(value * 2, true);
        break;
      // Tag wraps exactly one item.
      case 6:
        open(1, true, value === 24);
        break;
      // Integers, simples, floats: complete in the header.
      default:
        break;
    }
  }
  return deepest;
}

export { hexToBytes };

/**
 * Max nesting typed decoders accept outside native scripts, counted through tag-24 payloads
 * ({@link cborNestingDepthThroughEmbedded}); past this the typed decoder refuses the input and
 * get_possible_types_for_input does not try the type (get_possible_types_report lists it and says why).
 * Levels inside the native scripts a type holds where the ledger puts them (a native script itself, a
 * witness set's key 1, auxiliary data's scripts, an output's script reference) do not count: those nest up
 * to {@link NATIVE_SCRIPT_DEPTH_LIMIT}. Sized for a WebKit Web Worker's stack.
 */
export const TYPED_DECODING_DEPTH_LIMIT = 64;

/**
 * Max nesting outside native scripts the transaction entry points hand the serialization library
 * (validate, necessary data, hashes, signatures, witness insertion), counted like
 * {@link TYPED_DECODING_DEPTH_LIMIT}.
 */
export const CSL_DECODING_DEPTH_LIMIT = 128;

/**
 * Max nesting outside native scripts of what only pallas and the Plutus evaluator read (script execution,
 * UTxO list, reference script bytes, a validation context's inline datum), counted like
 * {@link TYPED_DECODING_DEPTH_LIMIT}.
 */
export const EVALUATOR_DECODING_DEPTH_LIMIT = 128;

/**
 * Deepest CBOR nesting the document walkers follow (cbor_to_json, validate/decode/map against CDDL);
 * past it they answer `nesting_too_deep`.
 */
export const CBOR_WALKER_DEPTH_LIMIT = 32768;

/**
 * Deepest CBOR nesting of an input holding native scripts, the scripts' own levels included (through tag-24
 * payloads): native scripts are exempt from {@link TYPED_DECODING_DEPTH_LIMIT},
 * {@link CSL_DECODING_DEPTH_LIMIT} and {@link EVALUATOR_DECODING_DEPTH_LIMIT} and bounded only by the walkers'
 * bound. A `ScriptAll` level is two CBOR levels, so about 16,380 script levels fit.
 */
export const NATIVE_SCRIPT_DEPTH_LIMIT = CBOR_WALKER_DEPTH_LIMIT;

/**
 * True if `hex` nests deeper than {@link TYPED_DECODING_DEPTH_LIMIT}, tag-24 payloads included, counting every
 * level. Conservative: the library itself does not count native-script levels, so an input this answers
 * `true` for may still decode as a type holding native scripts (ask get_possible_types_report).
 */
export function nestsPastTypedDecoding(hex: string): boolean {
  return cborNestingDepthThroughEmbedded(hexToBytes(hex), TYPED_DECODING_DEPTH_LIMIT) > TYPED_DECODING_DEPTH_LIMIT;
}

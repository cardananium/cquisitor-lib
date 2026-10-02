// The path grammar cquisitor-lib uses to name a place in a decoded CBOR document
// (`path` on validation errors, `decoded_path` on CBOR/CDDL mappings, the
// labelled-decode tree): `$` is the root, `.name` a map entry whose key is an
// identifier (ASCII `[A-Za-z_][A-Za-z0-9_-]*`), `["key"]` any other string key
// (numeric map keys included) with `\` written `\\` and `"` written `\"` and
// nothing else escaped, and `[0]` an array index. The validator also names a
// map entry whose key is not text: an integer key `[2]` / `[-1]` and a float key
// `[1.5]` in brackets, a byte string, boolean or null key by its CDDL literal
// after a dot, `.h'0102'`, `.true`, `.null`, and a composite key in CBOR
// diagnostic notation in brackets, `[[2, h'0102']]`, `[{1: 2}]`, `[24(0)]`,
// `[simple(32)]`. The validator does not write out a key whose rendering would
// pass 256 bytes: it names the entry by its position in the map, `[n]` as for
// an array index, when the map holds no integer key `n`, and by `[...]`, which
// names no entry, when it does. Where the library can tell which entry that
// is (always for `[n]`; for `[...]`, when the map has no composite key and
// only that entry's key is a text or byte string rendering past 256 bytes)
// and the key is a text or byte string whose rendering fits 1024 bytes, the
// path writes the key out instead (`.key`, `["key"]`, `.h'…'`). Every other
// such entry keeps `[n]` / `[...]`; its byte spans are the entry's when the
// library can tell which entry it is, the map's when it cannot.
//
// Segments are compared as plain strings, so a bracket segment and a quoted
// key with the same text are one segment: `[1]` and `["1"]` (on purpose: the
// decoded tree spells a numeric key `["1"]`), and also `[...]` and `["..."]`,
// `[[1, 2]]` and `["[1, 2]"]`. The path alone therefore does not tell those
// entries apart; the byte spans an error carries do.

/** The path of the document root. */
export const CBOR_PATH_ROOT = "$";

const IDENT_RE = /^[a-zA-Z_][\w-]*$/;

function isIdent(s: string): boolean {
  return IDENT_RE.test(s);
}

function escString(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

/**
 * Path of a child: an array index is `[i]`, an identifier-safe key `.key`, any
 * other string key `["key"]` with quotes and backslashes escaped.
 */
export function joinCborPath(parentPath: string, key: string | number): string {
  if (typeof key === "number") return `${parentPath}[${key}]`;
  if (isIdent(key)) return `${parentPath}.${key}`;
  return `${parentPath}["${escString(key)}"]`;
}

/** Index just past the closing quote of a `"…"` literal opened at `open`, escapes honoured. */
function quotedEnd(path: string, open: number): number {
  let i = open + 1;
  while (i < path.length) {
    const c = path[i];
    if (c === "\\") i += 2;
    else if (c === '"') return i + 1;
    else i += 1;
  }
  return path.length;
}

/**
 * Index just past the `]` closing the bracket opened at `open`. Brackets, braces
 * and parentheses nest, and `"…"` / `h'…'` literals inside are skipped whole, so
 * a composite key written in diagnostic notation is one segment.
 */
function bracketEnd(path: string, open: number): number {
  let depth = 0;
  let i = open;
  while (i < path.length) {
    const c = path[i];
    if (c === '"') {
      i = quotedEnd(path, i);
      continue;
    }
    if (c === "'") {
      const close = path.indexOf("'", i + 1);
      i = close === -1 ? path.length : close + 1;
      continue;
    }
    if (c === "[" || c === "{" || c === "(") depth += 1;
    else if (c === "]" || c === "}" || c === ")") {
      depth -= 1;
      if (depth === 0) return i + 1;
    }
    i += 1;
  }
  return path.length;
}

/**
 * The segments of a path, root excluded, as strings: `$.body[0]["a b"]` →
 * `["body", "0", "a b"]`, `$[[2, h'0102']].a` → `["[2, h'0102']", "a"]`. Escapes
 * inside a quoted segment are kept, not unescaped.
 */
export function splitCborPath(path: string): string[] {
  const out: string[] = [];
  let i = 0;
  while (i < path.length) {
    const c = path[i];
    if (c === ".") {
      let j = i + 1;
      while (j < path.length && path[j] !== "." && path[j] !== "[" && path[j] !== "]") j += 1;
      if (j > i + 1) out.push(path.slice(i + 1, j));
      i = j;
    } else if (c === "[") {
      if (path[i + 1] === '"') {
        const end = quotedEnd(path, i + 1);
        const closed = end > i + 2 && path[end - 1] === '"';
        out.push(path.slice(i + 2, closed ? end - 1 : end));
        i = path[end] === "]" ? end + 1 : end;
      } else {
        const end = bracketEnd(path, i);
        const inner = path.slice(i + 1, path[end - 1] === "]" ? end - 1 : end);
        if (inner.length > 0) out.push(inner);
        i = end;
      }
    } else {
      i += 1;
    }
  }
  return out;
}

/** The segment `splitCborPath` yields for `joinCborPath(parent, key)`. */
export function cborPathSegment(key: string | number): string {
  if (typeof key === "number") return String(key);
  return isIdent(key) ? key : escString(key);
}

/** Whether two paths name the same place, whichever spelling each uses. */
export function cborPathsEqual(a: string, b: string): boolean {
  if (a === b) return true;
  const sa = splitCborPath(a);
  const sb = splitCborPath(b);
  if (sa.length !== sb.length) return false;
  for (let i = 0; i < sa.length; i++) if (sa[i] !== sb[i]) return false;
  return true;
}

/** Whether `ancestor` strictly contains `descendant`. */
export function isCborPathAncestor(ancestor: string, descendant: string): boolean {
  const sa = splitCborPath(ancestor);
  const sd = splitCborPath(descendant);
  if (sa.length >= sd.length) return false;
  for (let i = 0; i < sa.length; i++) if (sa[i] !== sd[i]) return false;
  return true;
}

/** Number of segments below the root. */
export function cborPathDepth(path: string): number {
  return splitCborPath(path).length;
}

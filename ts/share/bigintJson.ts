// The share-link container's JSON: `bigint` travels as a `{"$bi": "<digits>"}`
// box so a link decodes to the same values on any host. This is the codec of
// share links (and of caches that store their payloads) only; JSON text from
// the library itself is read with `parseJsonExact` / written with
// `stringifyJsonExact` (`../util/json.ts`), where large integers are bare digits.

const BIGINT_TAG = "$bi";

/** JSON for a share-link container: `bigint` as a `{"$bi": "<digits>"}` box. */
export function stringifyShareJson(value: unknown): string {
  return JSON.stringify(value, (_key, val) => {
    if (typeof val === "bigint") {
      return { [BIGINT_TAG]: val.toString() };
    }
    return val;
  });
}

/** Inverse of `stringifyShareJson`: `{"$bi": "<digits>"}` boxes come back as `bigint`. */
export function parseShareJson(text: string): unknown {
  return JSON.parse(text, (_key, val) => {
    if (val && typeof val === "object" && !Array.isArray(val)) {
      const keys = Object.keys(val as Record<string, unknown>);
      if (keys.length === 1 && keys[0] === BIGINT_TAG) {
        const s = (val as Record<string, unknown>)[BIGINT_TAG];
        if (typeof s === "string") {
          try {
            return BigInt(s);
          } catch {
            return val;
          }
        }
      }
    }
    return val;
  });
}

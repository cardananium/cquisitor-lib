import { describe, expect, test } from "bun:test";
import {
  integerFromText,
  parseJsonExact,
  parseJsonExactWithoutReviver,
  quoteUnsafeIntegers,
  REVIVER_HAS_SOURCE,
  stringifyJsonExact,
  type ParseJsonExactOptions,
} from "./json.js";

describe("parseJsonExact", () => {
  test("integers that fit a double stay numbers, larger ones become bigint", () => {
    const parsed = parseJsonExact<{ a: number; b: bigint; c: bigint; d: number; e: number }>(
      '{"a":5,"b":18446744073709551615,"c":-9007199254740993,"d":9007199254740991,"e":1.5}',
    );
    expect(parsed.a).toBe(5);
    expect(parsed.b).toBe(18446744073709551615n);
    expect(parsed.c).toBe(-9007199254740993n);
    expect(parsed.d).toBe(9007199254740991);
    expect(parsed.e).toBe(1.5);
  });

  test("serde number boxes are unboxed the same way", () => {
    const parsed = parseJsonExact<{ x: unknown; y: unknown; z: unknown }>(
      '{"x":{"$serde_json::private::Number":"12"},"y":{"$serde_json::private::Number":"18446744073709551615"},"z":{"$serde_json::private::Number":"2.5"}}',
    );
    expect(parsed).toEqual({ x: 12, y: 18446744073709551615n, z: 2.5 });
  });

  test("a document that is itself a box or a big literal", () => {
    expect(parseJsonExact<bigint>('{"$serde_json::private::Number":"340282366920938463463374607431768211455"}')).toBe(
      340282366920938463463374607431768211455n,
    );
    expect(parseJsonExact<bigint>("18446744073709551615")).toBe(18446744073709551615n);
    expect(parseJsonExact<number>("7")).toBe(7);
  });

  test("strings that look like numbers are left alone, in and out of arrays", () => {
    expect(parseJsonExact<unknown[]>('["18446744073709551615", {"k": "99999999999999999999"}]')).toEqual([
      "18446744073709551615",
      { k: "99999999999999999999" },
    ]);
  });

  test("bigIntegers: 'string' gives decimal text instead", () => {
    expect(parseJsonExact<object>('{"b":18446744073709551615,"s":7}', { bigIntegers: "string" })).toEqual({
      b: "18446744073709551615",
      s: 7,
    });
    expect(
      parseJsonExact<string>('{"$serde_json::private::Number":"18446744073709551616"}', { bigIntegers: "string" }),
    ).toBe("18446744073709551616");
  });

  test("a document nested deeper than the reviver's stack still parses exactly", () => {
    const depth = 20_000;
    const text = "[".repeat(depth) + "18446744073709551615" + "]".repeat(depth);
    let node: unknown = parseJsonExact(text);
    for (let i = 0; i < depth; i++) node = (node as unknown[])[0];
    expect(node).toBe(18446744073709551615n);
  });

  test("__proto__ keys stay own properties", () => {
    const parsed = parseJsonExact<Record<string, unknown>>('{"__proto__":{"$serde_json::private::Number":"1"}}');
    expect(Object.getOwnPropertyDescriptor(parsed, "__proto__")?.value).toBe(1);
    expect(Object.getPrototypeOf(parsed)).toBe(Object.prototype);
  });

  test("invalid JSON is rejected with a SyntaxError", () => {
    expect(() => parseJsonExact("{")).toThrow(SyntaxError);
  });

  test("the environment is reported", () => {
    expect(typeof REVIVER_HAS_SOURCE).toBe("boolean");
  });
});

// The code point the quoting path marks its quoted integers with.
const MARK = "\u{10FFFD}";

describe("both parse paths give the same answer", () => {
  // `parseJsonExact` takes the reviver path where the engine hands the reviver
  // its source text (bun, Node >= 21) and the quoting path elsewhere (Node 20)
  // or when the reviver runs out of stack; `parseJsonExactWithoutReviver`
  // forces the quoting path on any engine.
  const paths: Array<[string, (text: string, options?: ParseJsonExactOptions) => unknown]> = [
    ["parseJsonExact", parseJsonExact],
    ["parseJsonExactWithoutReviver", parseJsonExactWithoutReviver],
  ];

  const documents: Array<[string, unknown]> = [
    ["a digit string after the mark", [JSON.parse(JSON.stringify(MARK + "123"))]],
    ["letters after the mark", [MARK + "abc"]],
    ["the mark alone", [MARK]],
    ["the mark twice", [MARK + MARK + "1"]],
    ["the mark as the whole document", MARK + "5"],
    ["the mark in a key and in a value", { [MARK + "k"]: MARK + MARK + "1", n: 18446744073709551615n }],
  ];

  for (const [name, fn] of paths) {
    test(`${name}: a text that begins with the mark stays that text`, () => {
      for (const [, value] of documents) {
        const text = JSON.stringify(value, (_k, v) => (typeof v === "bigint" ? `__BIG__${v}` : v)).replace(
          /"__BIG__(-?\d+)"/g,
          "$1",
        );
        expect(fn(text)).toEqual(value);
      }
      // Escaped as \u surrogates rather than written raw.
      expect(fn('["\\udbff\\udffd123", "\\uDBFF\\uDFFDabc"]')).toEqual([MARK + "123", MARK + "abc"]);
      // A big integer and a marked string side by side.
      expect(fn(`[18446744073709551615, "${MARK}18446744073709551615"]`)).toEqual([
        18446744073709551615n,
        MARK + "18446744073709551615",
      ]);
    });

    test(`${name}: an integer literal too large for a double is still exact`, () => {
      const huge = "1" + "0".repeat(400);
      expect(fn(huge)).toBe(10n ** 400n);
      expect(fn(`[-${huge}, 1e400]`)).toEqual([-(10n ** 400n), Infinity]);
      expect(fn(huge, { bigIntegers: "string" })).toBe(huge);
    });

    test(`${name}: a bare big literal inside a serde box is unboxed exactly`, () => {
      expect(fn('{"x":{"$serde_json::private::Number":18446744073709551615}}')).toEqual({ x: 18446744073709551615n });
    });
  }

  test("a marked string nested past the reviver's stack stays text", () => {
    const depth = 20_000;
    const text = "[".repeat(depth) + JSON.stringify(MARK + "5") + "]".repeat(depth);
    for (const [, fn] of paths) {
      let node: unknown = fn(text);
      for (let i = 0; i < depth; i++) node = (node as unknown[])[0];
      expect(node).toBe(MARK + "5");
    }
  });
});

describe("quoteUnsafeIntegers", () => {
  test("with a mark, doubles it on document string values that begin with it, never on keys", () => {
    const text = `{"${MARK}k":"${MARK}v","s":"x${MARK}","n":18446744073709551615}`;
    expect(quoteUnsafeIntegers(text, MARK)).toBe(
      `{"${MARK}k":"${MARK}${MARK}v","s":"x${MARK}","n":"${MARK}18446744073709551615"}`,
    );
    // A key followed by whitespace before its colon is still a key.
    expect(quoteUnsafeIntegers(`{"${MARK}k" \n : 1}`, MARK)).toBe(`{"${MARK}k" \n : 1}`);
  });

  test("rewrites only unsafe integer literals, skipping strings and floats", () => {
    expect(quoteUnsafeIntegers('{"a":1,"b":18446744073709551615,"c":"18446744073709551615","d":1e300,"e":-9007199254740993}')).toBe(
      '{"a":1,"b":"18446744073709551615","c":"18446744073709551615","d":1e300,"e":"-9007199254740993"}',
    );
  });

  test("escaped quotes inside strings do not end the string", () => {
    const text = '{"s":"a\\"b 99999999999999999999","n":99999999999999999999}';
    expect(quoteUnsafeIntegers(text)).toBe('{"s":"a\\"b 99999999999999999999","n":"99999999999999999999"}');
  });

  test("returns the same text when nothing needs quoting", () => {
    const text = '{"a":[1,2,3],"b":"x"}';
    expect(quoteUnsafeIntegers(text)).toBe(text);
  });
});

describe("integerFromText / stringifyJsonExact", () => {
  test("integerFromText normalises leading zeros and signs", () => {
    expect(integerFromText("007")).toBe(7);
    expect(integerFromText("-0")).toBe(-0);
    expect(integerFromText("00018446744073709551615")).toBe(18446744073709551615n);
    expect(integerFromText("18446744073709551615", "string")).toBe("18446744073709551615");
  });

  test("stringifyJsonExact writes bigint as bare literals and round-trips", () => {
    const value = { slot: 123n, fee: 18446744073709551615n, list: [1n, 2], name: "x", nested: { n: null } };
    const text = stringifyJsonExact(value);
    expect(text).toBe('{"slot":123,"fee":18446744073709551615,"list":[1,2],"name":"x","nested":{"n":null}}');
    expect(parseJsonExact<object>(text)).toEqual({ slot: 123, fee: 18446744073709551615n, list: [1, 2], name: "x", nested: { n: null } });
  });
});

import { describe, expect, test } from "bun:test";
import {
  CBOR_PATH_ROOT,
  cborPathDepth,
  cborPathSegment,
  cborPathsEqual,
  isCborPathAncestor,
  joinCborPath,
  splitCborPath,
} from "./cborPath.js";

describe("joinCborPath", () => {
  test("an array index is a bracketed integer", () => {
    expect(joinCborPath(CBOR_PATH_ROOT, 0)).toBe("$[0]");
    expect(joinCborPath("$.body", 12)).toBe("$.body[12]");
  });

  test("an identifier-safe key uses dot notation", () => {
    expect(joinCborPath("$", "body")).toBe("$.body");
    expect(joinCborPath("$.body", "tx_inputs")).toBe("$.body.tx_inputs");
    expect(joinCborPath("$", "_underscore")).toBe("$._underscore");
    expect(joinCborPath("$", "with-dash")).toBe("$.with-dash");
  });

  test("any other key is bracketed and quoted, numeric map keys included", () => {
    expect(joinCborPath("$", "with space")).toBe('$["with space"]');
    expect(joinCborPath("$", "0")).toBe('$["0"]');
    expect(joinCborPath("$", "@entries")).toBe('$["@entries"]');
  });

  test("escapes embedded quotes and backslashes", () => {
    expect(joinCborPath("$", 'a"b')).toBe('$["a\\"b"]');
    expect(joinCborPath("$", "a\\b")).toBe('$["a\\\\b"]');
  });
});

describe("splitCborPath", () => {
  test("splits the mix of dots, brackets and quoted strings", () => {
    expect(splitCborPath("$.body[0].tx_inputs[12]")).toEqual(["body", "0", "tx_inputs", "12"]);
    expect(splitCborPath('$["@entries"][2]["complex key"]')).toEqual(["@entries", "2", "complex key"]);
  });

  test("the bare root has no segments", () => {
    expect(splitCborPath("$")).toEqual([]);
    expect(cborPathDepth("$")).toBe(0);
    expect(cborPathDepth("$.a[0].b")).toBe(3);
  });

  test("repeated calls give the same answer", () => {
    const p = "$.a[0].b";
    expect(splitCborPath(p)).toEqual(["a", "0", "b"]);
    expect(splitCborPath(p)).toEqual(["a", "0", "b"]);
  });

  test("keeps the escapes of a quoted segment", () => {
    expect(splitCborPath('$["a\\"b"]')).toEqual(['a\\"b']);
  });

  test("round-trips through joinCborPath one segment at a time", () => {
    const keys: Array<string | number> = ["body", 0, "with space", "0", 'q"q'];
    let path: string = CBOR_PATH_ROOT;
    for (const k of keys) path = joinCborPath(path, k);
    expect(splitCborPath(path)).toEqual(keys.map(cborPathSegment));
  });
});

describe("cborPathsEqual / isCborPathAncestor", () => {
  test("identical strings and equivalent spellings are equal", () => {
    expect(cborPathsEqual("$.a[0]", "$.a[0]")).toBe(true);
    expect(cborPathsEqual("$.a", '$["a"]')).toBe(true);
    expect(cborPathsEqual("$.a", "$.b")).toBe(false);
    expect(cborPathsEqual("$.a", "$.a[0]")).toBe(false);
  });

  test("an ancestor strictly contains its descendant", () => {
    expect(isCborPathAncestor("$", "$.a")).toBe(true);
    expect(isCborPathAncestor("$.a", "$.a[0].b")).toBe(true);
    expect(isCborPathAncestor("$.a", "$.a")).toBe(false);
    expect(isCborPathAncestor("$.a[0]", "$.a")).toBe(false);
    expect(isCborPathAncestor("$.a", "$.ab")).toBe(false);
  });
});

describe("splitCborPath on the validator's bracket forms", () => {
  test("integer map keys, negative ones included, are one segment", () => {
    expect(splitCborPath("$[2]")).toEqual(["2"]);
    expect(splitCborPath("$[-1].a")).toEqual(["-1", "a"]);
  });

  test("a composite key in diagnostic notation is one segment", () => {
    expect(splitCborPath("$[[2, h'0102']]")).toEqual(["[2, h'0102']"]);
    expect(splitCborPath("$[[2, h'0102']].a[0]")).toEqual(["[2, h'0102']", "a", "0"]);
    expect(splitCborPath("$[{1: 2}]")).toEqual(["{1: 2}"]);
    expect(splitCborPath("$[24(0)]")).toEqual(["24(0)"]);
    expect(splitCborPath("$[simple(32)]")).toEqual(["simple(32)"]);
    expect(splitCborPath('$[["a]b", 1]]')).toEqual(['["a]b", 1]']);
    expect(cborPathDepth("$[[2, h'0102']].a")).toBe(2);
  });

  test("composite-key paths compare by segment", () => {
    expect(cborPathsEqual("$[[2, h'0102']]", "$")).toBe(false);
    expect(cborPathsEqual("$[[2, h'0102']]", "$[[2, h'0102']]")).toBe(true);
    expect(isCborPathAncestor("$[[2, h'0102']]", "$[[2, h'0102']].a")).toBe(true);
    expect(isCborPathAncestor("$[{1: 2}]", "$[{1: 3}].a")).toBe(false);
  });

  test("the other key notations keep their dot form", () => {
    expect(splitCborPath("$.h'0102'")).toEqual(["h'0102'"]);
    expect(splitCborPath("$.true.x")).toEqual(["true", "x"]);
  });
});

describe("text keys that are not identifiers, as the validator writes them", () => {
  // The validator writes such a key as `["…"]` with `\` and `"` escaped (and
  // nothing else), exactly like joinCborPath, so its paths split into the same
  // segments the tree builds from the decoded keys.
  const awkward = ["a.b", "[1]", "v1.0", 'a"b', "a\\b", "a/b", "a\nb", "a]b", "", "ключ", "1", "x y", "a'b"];

  test("each is one segment, equal to the one joinCborPath's path gives", () => {
    for (const key of awkward) {
      const path = joinCborPath("$.metadata", key);
      expect(path).toStartWith('$.metadata["');
      expect(splitCborPath(path)).toEqual(["metadata", cborPathSegment(key)]);
      expect(splitCborPath(`${path}[0].x`)).toEqual(["metadata", cborPathSegment(key), "0", "x"]);
      expect(cborPathDepth(path)).toBe(2);
    }
  });

  test("a dotted or bracketed key names its own entry, not a path through others", () => {
    expect(splitCborPath('$["a.b"]')).toEqual(["a.b"]);
    expect(cborPathsEqual('$["a.b"]', "$.a.b")).toBe(false);
    expect(isCborPathAncestor("$.a", '$["a.b"]')).toBe(false);
    expect(splitCborPath('$["[1]"]')).toEqual(["[1]"]);
    expect(cborPathsEqual('$["[1]"]', "$[1]")).toBe(false);
    expect(splitCborPath('$["v1.0"].name')).toEqual(["v1.0", "name"]);
  });

  test("escaped quotes and backslashes do not end the key", () => {
    expect(splitCborPath('$["a\\"]b"].c')).toEqual(['a\\"]b', "c"]);
    expect(splitCborPath('$["a\\\\"].c')).toEqual(["a\\\\", "c"]);
    expect(cborPathsEqual('$["a\\"b"]', joinCborPath("$", 'a"b'))).toBe(true);
  });
});

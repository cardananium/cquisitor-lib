import { describe, expect, test } from "bun:test";
import { cbor_to_json, type CborDecodeResult, type CborValue } from "@cardananium/cquisitor-lib/wasm";
import { parseJsonExact } from "./json.js";
import {
  cborNestingDepth,
  cborNestingDepthThroughEmbedded,
  hexToBytes,
  nestsPastTypedDecoding,
  TYPED_DECODING_DEPTH_LIMIT,
} from "./cborDepth.js";
import { get_possible_types_for_input } from "@cardananium/cquisitor-lib/wasm";

/** Tree depth matching the scanner: arrays, maps, and tags add a level. */
function treeDepth(root: CborValue): number {
  let deepest = 0;
  const stack: { node: CborValue; level: number }[] = [{ node: root, level: 0 }];
  while (stack.length > 0) {
    const { node, level } = stack.pop()!;
    if (level > deepest) deepest = level;
    const n = node as { type: string; values?: unknown[]; value?: CborValue | null };
    if (n.type === "Array") for (const item of n.values ?? []) stack.push({ node: item as CborValue, level: level + 1 });
    if (n.type === "Map") {
      // Indefinite maps list the closing break as a bare node.
      for (const entry of n.values ?? []) {
        if ("type" in (entry as object)) continue;
        const pair = entry as { key: CborValue; value: CborValue };
        stack.push({ node: pair.key, level: level + 1 });
        stack.push({ node: pair.value, level: level + 1 });
      }
    }
    if (n.type === "Tag" && n.value) stack.push({ node: n.value, level: level + 1 });
  }
  return deepest;
}

const depth = (hex: string, ceiling = Number.MAX_SAFE_INTEGER) => cborNestingDepth(hexToBytes(hex), ceiling);

describe("cborNestingDepth", () => {
  test("a scalar sits at the root level", () => {
    expect(depth("05")).toBe(0);
    expect(depth("f6")).toBe(0);
    expect(depth("43010203")).toBe(0);
    expect(depth("80")).toBe(0);
  });

  test("every array, map and tag adds a level, and a map's keys sit with its values", () => {
    expect(depth("8105")).toBe(1);
    expect(depth("a1008105")).toBe(2);
    expect(depth("a1810500")).toBe(2);
    expect(depth("c105")).toBe(1);
    expect(depth("d9010281818105")).toBe(4);
    expect(depth("8205" + "8105")).toBe(2);
  });

  test("indefinite-length containers nest, and the chunks of an indefinite-length string do not", () => {
    expect(depth("9f8105ff")).toBe(2);
    expect(depth("bf008105ff")).toBe(2);
    expect(depth("7f616161ff")).toBe(0);
    expect(depth("817f6161ff")).toBe(1);
    expect(depth("5f4101ff")).toBe(0);
  });

  test("the scan stops as soon as the depth passes the ceiling", () => {
    const chain = "81".repeat(1000) + "05";
    expect(depth(chain)).toBe(1000);
    expect(depth(chain, 256)).toBe(257);
    expect(depth(chain, 1000)).toBe(1000);
  });

  test("a header the scan cannot read ends it, reporting the well-formed prefix", () => {
    // Reserved AI, truncated argument, payload past end.
    expect(depth("81811c")).toBe(2);
    expect(depth("8118")).toBe(1);
    expect(depth("81590100")).toBe(1);
    expect(depth("814301")).toBe(1);
  });

  test("agrees with the library's decoder", () => {
    const documents = [
      // {"name": "Alice", "age": "20"}
      "a2646e616d6565416c69636563616765623230",
      // Plutus constructor: tag 121, indefinite array, tag, map, bytes, indefinite text.
      "d8799fd87a9f0102ffa1008201027f6161ff4401020304ff",
      // 300 arrays around a map whose value is a tagged array.
      "81".repeat(300) + "a100c1" + "8105",
      // Indefinite map of an indefinite array of tags.
      "bf009fc1c1c105ffff",
    ];
    for (const hex of documents) {
      const decoded = parseJsonExact<CborDecodeResult>(cbor_to_json(hex));
      if (!decoded.ok) throw new Error(`${hex} did not decode: ${decoded.error.message}`);
      expect(depth(hex)).toBe(treeDepth(decoded.value));
    }
  });

  test("hexToBytes reads the bytes a hex string spells", () => {
    expect(Array.from(hexToBytes("00ff10"))).toEqual([0, 255, 16]);
    expect(Array.from(hexToBytes("A1"))).toEqual([161]);
  });
});

describe("nestsPastTypedDecoding", () => {
  test("is the line at which the library stops trying types", () => {
    const chain = (depth: number) => "81".repeat(depth) + "05";
    const at = chain(TYPED_DECODING_DEPTH_LIMIT);
    const past = chain(TYPED_DECODING_DEPTH_LIMIT + 1);
    expect(nestsPastTypedDecoding(at)).toBe(false);
    expect(nestsPastTypedDecoding(past)).toBe(true);
    // Library still types a document at the bound and refuses one level past it.
    expect(get_possible_types_for_input(at).length).toBeGreaterThan(0);
    expect(get_possible_types_for_input(past)).toEqual([]);
  });
});

/** `n` Plutus constructors, each holding the next: `121([121([… 0])])`, 2n levels. */
const nestedConstr = (n: number) => "d87981".repeat(n) + "00";

/** A byte string header and payload for `hex`. */
function byteString(hex: string): string {
  const length = hex.length / 2;
  if (length < 24) return (0x40 + length).toString(16).padStart(2, "0") + hex;
  if (length < 256) return "58" + length.toString(16).padStart(2, "0") + hex;
  return "59" + length.toString(16).padStart(4, "0") + hex;
}

/** `[{0: [input], 1: [{0: address, 1: 2000000, 2: [1, #6.24(datum)]}], 2: 0}, {}, true, null]`. */
function transactionWithInlineDatum(datumHex: string): string {
  const input = "825820" + "11".repeat(32) + "00";
  const output = "a300581d61" + "ab".repeat(28) + "011a001e8480" + "028201d818" + byteString(datumHex);
  return "84a30081" + input + "0181" + output + "0200a0f5f6";
}

describe("cborNestingDepthThroughEmbedded", () => {
  test("a tag-24 payload counts from the level of its byte string", () => {
    // [24(<<[[5]]>>)]: the byte string sits at level 2, its item's arrays at 3 and 4.
    expect(depth("81d818" + byteString("818105"))).toBe(2);
    expect(cborNestingDepthThroughEmbedded(hexToBytes("81d818" + byteString("818105")), 1000)).toBe(4);
    // An indefinite byte string there counts as its spliced chunks.
    expect(cborNestingDepthThroughEmbedded(hexToBytes("81d8185f4181428105ff"), 1000)).toBe(4);
    // Any other tag keeps its byte string opaque.
    expect(cborNestingDepthThroughEmbedded(hexToBytes("81d819" + byteString("818105")), 1000)).toBe(2);
  });
});

describe("nestsPastTypedDecoding", () => {
  // The typed decoders parse an output's inline datum while reading the
  // transaction, so a small transaction whose datum nests deep is refused
  // although the transaction itself is a few levels deep.
  test("counts an inline datum on top of the level it is embedded at, as the library does", () => {
    const deep = transactionWithInlineDatum(nestedConstr(1100));
    expect(depth(deep)).toBeLessThan(10);
    expect(nestsPastTypedDecoding(deep)).toBe(true);
    expect(get_possible_types_for_input(deep)).toEqual([]);

    const shallow = transactionWithInlineDatum(nestedConstr(25));
    expect(nestsPastTypedDecoding(shallow)).toBe(false);
    expect(get_possible_types_for_input(shallow)).toContain("Transaction");
  });

  test("draws the line where the library does", () => {
    const answers: [number, boolean, boolean][] = [];
    for (let constructors = 24; constructors <= 34; constructors++) {
      const hex = transactionWithInlineDatum(nestedConstr(constructors));
      answers.push([constructors, nestsPastTypedDecoding(hex), get_possible_types_for_input(hex).length === 0]);
    }
    for (const [constructors, past, refused] of answers) expect([constructors, past]).toEqual([constructors, refused]);
    // Both sides of the line are in the range.
    expect(answers.some(([, past]) => past)).toBe(true);
    expect(answers.some(([, past]) => !past)).toBe(true);
  });
});

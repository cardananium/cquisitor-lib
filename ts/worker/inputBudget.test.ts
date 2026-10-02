import { describe, expect, test } from "bun:test";
import { LibInputTooLargeError } from "../errors.js";
import {
  MAX_LIB_INPUT_BYTES,
  argumentByteLength,
  formatByteSize,
  guardInputBudget,
  overBudgetMessage,
  utf8ByteLength,
} from "./inputBudget.js";

describe("utf8ByteLength", () => {
  test("counts what an encoder would produce", () => {
    for (const text of ["", "abc", "кириллица", "🦀", "a🦀b", "é", "\u{10FFFF}"]) {
      expect(utf8ByteLength(text)).toBe(new TextEncoder().encode(text).length);
    }
  });

  test("stops counting once the text cannot possibly fit", () => {
    // UTF-8 is never shorter than UTF-16, so over-limit code-unit length can stop early.
    const huge = "a".repeat(1000);
    expect(utf8ByteLength(huge, 10)).toBeGreaterThan(10);
  });

  test("a lone surrogate is still counted, not skipped", () => {
    // Lone surrogates still count (must not hang or skip).
    expect(utf8ByteLength("\ud800")).toBe(4);
  });
});

describe("argumentByteLength", () => {
  test("top-level strings count their UTF-8 bytes exactly; scalars their text", () => {
    expect(argumentByteLength(["abc", "de"])).toBe(5);
    expect(argumentByteLength(["abc", 7, undefined, "de"])).toBe(6);
    expect(argumentByteLength([])).toBe(0);
  });

  test("strings inside arrays and objects count as much as top-level ones", () => {
    const witness = "a".repeat(1000);
    // An array of strings: the strings plus a separator each.
    expect(argumentByteLength([[witness, witness]])).toBeGreaterThanOrEqual(2000);
    // Objects: keys, values and nesting, at about their JSON size.
    const utxos = [{ input: { txHash: witness, outputIndex: 0 }, output: { address: witness, amount: [{ unit: "lovelace", quantity: 5n }] } }];
    const size = argumentByteLength([utxos]);
    expect(size).toBeGreaterThanOrEqual(2000);
    expect(size).toBeLessThanOrEqual(JSON.stringify(utxos, (_k, v) => (typeof v === "bigint" ? Number(v) : v)).length);
    expect(argumentByteLength([new Uint8Array(300)])).toBe(300);
    expect(argumentByteLength([new Map([["k", witness]])])).toBeGreaterThanOrEqual(1000);
  });

  test("a cycle is counted once, not followed forever", () => {
    const node: Record<string, unknown> = { s: "abc" };
    node.self = node;
    expect(argumentByteLength([node])).toBeLessThan(20);
  });

  test("deep nesting costs no stack", () => {
    let deep: unknown = "x";
    for (let i = 0; i < 100_000; i++) deep = [deep];
    expect(argumentByteLength([deep])).toBeGreaterThan(100_000);
  });

  test("past the limit, strings count by their length: still all of them, and never more than their UTF-8", () => {
    expect(argumentByteLength(["a".repeat(100), "b".repeat(100)], 50)).toBe(200);
    expect(argumentByteLength([["a".repeat(100), "b".repeat(100)]], 50)).toBe(203);
    // "é" is two UTF-8 bytes: past the limit it counts one, so the total is a lower bound.
    const mixed = argumentByteLength(["a".repeat(100), "é".repeat(100)], 50);
    expect(mixed).toBeGreaterThanOrEqual(200);
    expect(mixed).toBeLessThanOrEqual(300);
  });
});

describe("guardInputBudget", () => {
  test("a list argument cannot carry past the budget what one string could not", () => {
    const tx = "84a4";
    const oneMb = "a".repeat(1024 * 1024);
    // One 12 MB witness, and forty 1 MB witnesses: both over the 2 MB budget.
    expect(() => guardInputBudget("add_witnesses_to_tx", [tx, ["a".repeat(12 * 1024 * 1024)]])).toThrow(LibInputTooLargeError);
    // The whole list is counted, not just the part that crossed the limit.
    expect(() => guardInputBudget("add_witnesses_to_tx_with_report", [tx, Array(40).fill(oneMb)])).toThrow(
      /This input is at least 40 MB, over the 2\.0 MB limit\./,
    );
    // Objects are counted too.
    expect(() => guardInputBudget("execute_tx_scripts", [tx, [{ datum: "a".repeat(17 * 1024 * 1024) }], {}])).toThrow(LibInputTooLargeError);
    // Within budget: allowed.
    expect(() => guardInputBudget("add_witnesses_to_tx", [tx, [oneMb.slice(0, 1000)]])).not.toThrow();
    expect(() => guardInputBudget("cbor_to_json", ["a".repeat(MAX_LIB_INPUT_BYTES)])).not.toThrow();
  });
});

describe("formatByteSize", () => {
  test("reads in the units the reader thinks in", () => {
    expect(formatByteSize(512)).toBe("512 B");
    expect(formatByteSize(2048)).toBe("2.0 KB");
    expect(formatByteSize(64 * 1024)).toBe("64 KB");
    expect(formatByteSize(2 * 1024 * 1024)).toBe("2.0 MB");
    expect(formatByteSize(13 * 1024 * 1024)).toBe("13 MB");
  });

  test("rounds down on request, so a lower bound is never overstated", () => {
    expect(formatByteSize(2.99 * 1024 * 1024)).toBe("3.0 MB");
    expect(formatByteSize(2.99 * 1024 * 1024, "down")).toBe("2.9 MB");
    expect(formatByteSize(2 * 1024 * 1024, "down")).toBe("2.0 MB");
    expect(formatByteSize(16.7 * 1024 * 1024, "down")).toBe("16 MB");
  });
});

describe("overBudgetMessage", () => {
  test("nothing to say while the input fits", () => {
    expect(overBudgetMessage(0, MAX_LIB_INPUT_BYTES)).toBeNull();
    expect(overBudgetMessage(MAX_LIB_INPUT_BYTES, MAX_LIB_INPUT_BYTES)).toBeNull();
  });

  test("names both numbers, because a limit alone leaves the reader guessing", () => {
    const message = overBudgetMessage(13 * 1024 * 1024, MAX_LIB_INPUT_BYTES);
    expect(message).toContain("13 MB");
    expect(message).toContain("2.0 MB");
  });

  test("never prints a size that reads the same as the limit", () => {
    // 16.2 MB rounds to the 16 MB of the limit: the size is left out rather than read "16 MB, over the 16 MB limit".
    const message = overBudgetMessage(17_000_002, 16 * 1024 * 1024)!;
    expect(message).toStartWith("This input is over the 16 MB limit.");
    expect(overBudgetMessage(17_000_002, 16 * 1024 * 1024, "This input", { atLeast: true })).toStartWith(
      "This input is over the 16 MB limit.",
    );
  });

  test("a lower bound reads as one", () => {
    const message = overBudgetMessage(40 * 1024 * 1024 + 12, MAX_LIB_INPUT_BYTES, "This input", { atLeast: true });
    expect(message).toStartWith("This input is at least 40 MB, over the 2.0 MB limit.");
    expect(overBudgetMessage(2.99 * 1024 * 1024, MAX_LIB_INPUT_BYTES, "This input", { atLeast: true })).toContain("at least 2.9 MB");
  });

  test("the subject can name what was refused", () => {
    expect(overBudgetMessage(9e9, 1, "The shared document")).toContain("The shared document");
  });
});

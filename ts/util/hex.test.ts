import { describe, expect, test } from "bun:test";
import { bytesToHex, hexToBytes } from "./hex.js";

describe("hexToBytes / bytesToHex", () => {
  test("round-trips and accepts an optional 0x prefix and upper case", () => {
    expect(Array.from(hexToBytes("00ff10"))).toEqual([0, 255, 16]);
    expect(Array.from(hexToBytes("0x00FF10"))).toEqual([0, 255, 16]);
    expect(bytesToHex(new Uint8Array([0, 255, 16]))).toBe("00ff10");
    expect(hexToBytes("").length).toBe(0);
  });

  test("rejects odd length and non-hex characters", () => {
    expect(() => hexToBytes("abc")).toThrow("odd length");
    expect(() => hexToBytes("zz")).toThrow("non-hex");
  });
});

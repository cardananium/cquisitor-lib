// Hex <-> bytes, the one pair every module uses.

const HEX_DIGITS = /^[0-9a-fA-F]*$/;

/**
 * The bytes of a hex string. An optional `0x` prefix is accepted; the rest must
 * be an even number of hex digits, otherwise an `Error` naming the problem is
 * thrown.
 */
export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error("Invalid hex string: odd length");
  if (!HEX_DIGITS.test(clean)) throw new Error("Invalid hex string: non-hex character");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Lowercase hex of `bytes`. */
export function bytesToHex(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, "0");
  return s;
}

// Brotli Compressor backed by node:zlib. Node/Bun only: exported through the
// `./node` subpath so browser bundles never see the node: import.

import { brotliCompress, brotliDecompress, constants } from "node:zlib";
import { promisify } from "node:util";
import type { Compressor } from "../configure.js";
import { formatByteSize, MAX_SHARE_PAYLOAD_BYTES } from "../worker/inputBudget.js";

const compressAsync = promisify(brotliCompress);
const decompressAsync = promisify(brotliDecompress);

/** A byte view over a Uint8Array without copying it. */
function asUint8Array(buf: Buffer): Uint8Array {
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

function isOutputTooLarge(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  const code = (error as { code?: unknown }).code;
  return code === "ERR_BUFFER_TOO_LARGE" || error instanceof RangeError;
}

/** Brotli at quality 11, matching the browser (brotli-wasm) encoder the app uses. */
export async function nodeBrotliCompress(input: Uint8Array): Promise<Uint8Array> {
  const out = await compressAsync(input, {
    params: {
      [constants.BROTLI_PARAM_QUALITY]: 11,
      [constants.BROTLI_PARAM_SIZE_HINT]: input.byteLength,
    },
  });
  return asUint8Array(out);
}

/**
 * Decompress `input`, refusing output above `maxOutputBytes`. Brotli's ratio is
 * unbounded, so the compressed size bounds nothing; zlib enforces the cap while
 * inflating and never allocates past it.
 */
export async function nodeBrotliDecompress(
  input: Uint8Array,
  maxOutputBytes: number = MAX_SHARE_PAYLOAD_BYTES,
): Promise<Uint8Array> {
  try {
    const out = await decompressAsync(input, { maxOutputLength: maxOutputBytes });
    return asUint8Array(out);
  } catch (error) {
    if (isOutputTooLarge(error)) {
      throw new Error(
        `This link expands to more than ${formatByteSize(maxOutputBytes)}, ` +
          `which is more than a shared document is expected to hold.`,
      );
    }
    if (error instanceof Error && /unexpected end|truncat|Z_BUF_ERROR/i.test(error.message)) {
      throw new Error("This link's payload is incomplete.");
    }
    throw error;
  }
}

/** Ready-made Compressor for `configure({ compressor: nodeBrotliCompressor })`. */
export const nodeBrotliCompressor: Compressor = {
  compress: nodeBrotliCompress,
  decompress: nodeBrotliDecompress,
};

// The worker entry points must not reach the wasm loader: a worker that
// instantiates the wasm by hand (README, "Without a plugin") imports
// `serveWasm` from `/worker`, and a bundler that follows the loader's
// `import("@cardananium/cquisitor-lib/wasm")` pulls in the bundler glue, whose
// `import * as wasm from "./cquisitor_lib_bg.wasm"` fails to build where the
// .wasm is an asset URL (webpack's `asset/resource`).

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const TS_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** Every module `entry` reaches through value imports (type-only imports are erased). */
function valueImportClosure(entry: string): Set<string> {
  const seen = new Set<string>();
  const pending = [resolve(TS_ROOT, entry)];
  while (pending.length > 0) {
    const file = pending.pop()!;
    if (seen.has(file)) continue;
    seen.add(file);
    const source = readFileSync(file, "utf8");
    const re = /^\s*(import|export)\s+(?!type\b)([^;]*?)\s*from\s+"(\.[^"]+)"/gm;
    for (const m of source.matchAll(re)) {
      // `export type { … } from` / `import type` are erased; `export { type X }` alone is too.
      if (/^\{\s*(type\s+[\w$]+\s*,?\s*)+\}$/.test(m[2].trim())) continue;
      pending.push(join(dirname(file), m[3].replace(/\.js$/, ".ts")));
    }
  }
  return seen;
}

describe("module graph", () => {
  test("the /worker barrel and serveWasm do not import the wasm loader", () => {
    for (const entry of ["worker/index.ts", "worker/serve.ts"]) {
      const reached = [...valueImportClosure(entry)].map((f) => relative(TS_ROOT, f));
      expect(reached).toContain("wasm/namespace.ts");
      expect(reached).not.toContain("wasm/load.ts");
    }
  });

  test("the check does see the loader where it is imported", () => {
    const reached = [...valueImportClosure("backend.ts")].map((f) => relative(TS_ROOT, f));
    expect(reached).toContain("wasm/load.ts");
  });
});

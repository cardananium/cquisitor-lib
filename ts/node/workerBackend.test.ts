// The worker_threads backend end to end, against the real wasm. Under bun the
// worker entry is the TypeScript source; the packaged build ships the .js.

import { afterAll, describe, expect, test } from "bun:test";
import { configure, resetConfig } from "../configure.js";
import { cborToJson, possibleTypes, validateCddl } from "../api/index.js";
import { LibTimeoutError } from "../errors.js";
import { createNodeWorkerBackend, NODE_WASM_WORKER_ENTRY } from "./workerBackend.js";

const ENTRY = new URL("./wasmWorker.ts", import.meta.url);

describe("createNodeWorkerBackend", () => {
  const backend = createNodeWorkerBackend({ entry: ENTRY, timeoutMs: 60_000, loadTimeoutMs: 60_000 });

  afterAll(async () => {
    resetConfig();
    await backend.dispose();
  });

  test("the packaged entry is the compiled worker next to this module", () => {
    expect(NODE_WASM_WORKER_ENTRY.pathname.endsWith("/node/wasmWorker.js")).toBe(true);
  });

  test("loads the wasm in a worker thread and answers raw", async () => {
    await backend.warm();
    expect(backend.stats().ready).toBe(true);
    const raw = await backend.callRaw<string>("cbor_to_json", ["05"]);
    expect(typeof raw).toBe("string");
    expect(JSON.parse(raw).ok).toBe(true);
    const types = await backend.callRaw<string[]>("get_possible_types_for_input", ["05"]);
    expect(types).toContain("Int");
  });

  test("the typed API runs through it once configured", async () => {
    configure({ backend });
    expect(await possibleTypes("05")).toContain("Int");
    const tree = await cborToJson("a1616101");
    expect(tree.ok).toBe(true);
    expect(await validateCddl("a = int")).toEqual({ valid: true });
    const error = await validateCddl("a = {").then((r) => r, (e: unknown) => e);
    expect((error as { valid: boolean }).valid).toBe(false);
  });

  test("a library exception crosses the thread as an Error with its message", async () => {
    configure({ backend });
    const error = await backend.callRaw("decode_specific_type", ["zz", "Transaction", {}]).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toContain("hex");
    expect(backend.stats().spawns).toBe(1);
  });

  test("a script that is done exits without dispose(): an idle worker does not hold the process", async () => {
    const script = new URL("../testSupport/nodeWorkerExit.ts", import.meta.url).pathname;
    const child = Bun.spawn([process.execPath, script], { stdout: "pipe", stderr: "pipe" });
    const exited = await Promise.race([
      child.exited.then((code) => ({ code })),
      new Promise<null>((resolve) => setTimeout(() => resolve(null), 20_000)),
    ]);
    if (exited === null) child.kill();
    expect(exited).toEqual({ code: 0 });
    expect(JSON.parse(await new Response(child.stdout).text())).toEqual({ int: true, spawns: 1 });
  }, 30_000);

  test("calls made together with one that runs out of time are dropped with it, not each started on a fresh worker", async () => {
    const events: string[] = [];
    const local = createNodeWorkerBackend({
      entry: ENTRY,
      timeoutMs: 200,
      loadTimeoutMs: 60_000,
      onEvent: (e) => events.push(e.type),
    });
    try {
      await local.warm();
      // Takes seconds to walk: far past the deadline.
      const slow = "9f" + "00".repeat(900_000) + "ff";
      const outcome = (p: Promise<unknown>) => p.then(() => "ok", (e: unknown) => e);
      const [head, ...behind] = await Promise.all([
        outcome(local.callRaw("cbor_to_json", [slow])),
        outcome(local.callRaw("get_possible_types_for_input", ["05"])),
        outcome(local.callRaw("cbor_to_json", ["05"])),
        outcome(local.callRaw("cbor_to_json", ["06"])),
      ]);
      expect(head).toBeInstanceOf(LibTimeoutError);
      for (const error of behind) {
        expect(error).toBeInstanceOf(LibTimeoutError);
        expect((error as Error).message).toContain("never ran");
      }
      expect(events.filter((e) => e === "timeout")).toHaveLength(1);
      expect(local.stats().spawns).toBe(1);
      // A call made now has its whole deadline, on one fresh worker.
      expect(await local.callRaw<string[]>("get_possible_types_for_input", ["05"])).toContain("Int");
      expect(local.stats().spawns).toBe(2);
    } finally {
      await local.dispose();
    }
  }, 30_000);

  test("calls with a few ms left when the one ahead runs out are dropped, not each started (and killed) on a fresh worker", async () => {
    // Deadlines 8, 16 and 24 ms after the head's, as for calls made that far apart: that is all they
    // have left when it runs out, while a first run of a function on the replacement worker alone
    // takes some 10–25 ms (its code is compiled then). Each needs a tenth of its deadline (~61 ms).
    const events: string[] = [];
    const local = createNodeWorkerBackend({
      entry: ENTRY,
      timeoutMs: 600,
      loadTimeoutMs: 60_000,
      onEvent: (e) => events.push(e.type),
    });
    try {
      await local.warm();
      const slow = "9f" + "00".repeat(900_000) + "ff";
      const outcome = (p: Promise<unknown>) => p.then(() => "ok", (e: unknown) => e);
      const [head, ...behind] = await Promise.all([
        outcome(local.callRaw("cbor_to_json", [slow])),
        outcome(local.callRaw("get_possible_types_for_input", ["05"], { timeoutMs: 608 })),
        outcome(local.callRaw("decode_specific_type", ["05", "BigNum", {}], { timeoutMs: 616 })),
        outcome(local.callRaw("cbor_to_json", ["05"], { timeoutMs: 624 })),
      ]);
      expect(head).toBeInstanceOf(LibTimeoutError);
      for (const error of behind) {
        expect(error).toBeInstanceOf(LibTimeoutError);
        expect((error as Error).message).toContain("never ran");
      }
      expect(events.filter((e) => e === "timeout")).toHaveLength(1);
      expect(local.stats().spawns).toBe(1);
    } finally {
      await local.dispose();
    }
  }, 30_000);

  test("with a short deadline, calls with under 25 ms left when the one ahead runs out are dropped, not started (and killed) on the replacement", async () => {
    // A 100 ms deadline: a tenth of it (10 ms) is less than a first run takes, so the floor decides.
    // The calls behind have some 15 and 22 ms left when the head runs out; the last has 200 ms.
    const events: string[] = [];
    const local = createNodeWorkerBackend({
      entry: ENTRY,
      timeoutMs: 100,
      loadTimeoutMs: 60_000,
      onEvent: (e) => events.push(e.type),
    });
    try {
      await local.warm();
      const slow = "9f" + "00".repeat(900_000) + "ff";
      const outcome = (p: Promise<unknown>) => p.then((v) => v, (e: unknown) => e);
      const [head, first, second, roomy] = await Promise.all([
        outcome(local.callRaw("cbor_to_json", [slow])),
        outcome(local.callRaw("get_possible_types_for_input", ["05"], { timeoutMs: 115 })),
        outcome(local.callRaw("decode_specific_type", ["05", "BigNum", {}], { timeoutMs: 122 })),
        outcome(local.callRaw<string[]>("get_possible_types_for_input", ["05"], { timeoutMs: 300 })),
      ]);
      expect(head).toBeInstanceOf(LibTimeoutError);
      for (const error of [first, second]) {
        expect(error).toBeInstanceOf(LibTimeoutError);
        expect((error as Error).message).toContain("too little to start, so this call never ran");
      }
      expect(roomy).toContain("Int");
      expect(events.filter((e) => e === "timeout")).toHaveLength(1);
      expect(local.stats().spawns).toBe(2);
    } finally {
      await local.dispose();
    }
  }, 30_000);

  test("a call over its budget is abandoned and the worker replaced", async () => {
    // Nothing legitimately takes 1 ms after the load; the budget is what is tested.
    await backend.warm();
    const error = await backend
      .callRaw("validate_cbor_against_cddl", ["a1616101", "a = { * tstr => int }", "a"], { timeoutMs: 1 })
      .catch((e: unknown) => e);
    // Either the answer beat the 1 ms clock or the call was abandoned; both are legal, but
    // an abandonment must have replaced the worker and the backend must still work.
    if (error instanceof LibTimeoutError) {
      expect(await backend.callRaw<string[]>("get_possible_types_for_input", ["05"])).toContain("Int");
      expect(backend.stats().spawns).toBe(2);
    }
  });
});

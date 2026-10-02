import { describe, expect, test } from "bun:test";
import { createInProcessBackend, type LibBackend } from "../backend.js";
import type { WasmModule } from "../wasm/functions.js";
import { LibAbortedError, LibTimeoutError, LibUnavailableError, isLibRefusal } from "../errors.js";
import type { WorkerHandle } from "./ports.js";
import type { LibRequest, LibResponse } from "./protocol.js";
import { serveWasm } from "./serve.js";
import {
  abandonedMessage,
  createWorkerBackend,
  neverRanMessage,
  type WorkerBackendEvent,
} from "./workerBackend.js";

const tick = (ms = 5) => new Promise((r) => setTimeout(r, ms));

/**
 * A worker that lives in this thread: requests go to `onRequest`, which may
 * answer (through `post`), stay silent (a hang) or throw (a crash).
 */
type FakeMessage = LibResponse | { type: "loaded"; error?: unknown };

type FakeWorker = WorkerHandle & {
  terminated: boolean;
  posted: LibRequest[];
  /** Deliver a message to the host as this worker. */
  post: (m: FakeMessage) => void;
  /** Raise a worker error (a crash). */
  crash: (error: unknown) => void;
  /** ref()/unref() calls, in order. */
  refs: Array<"ref" | "unref">;
};

function fakeWorker(
  onRequest: (request: LibRequest, post: (m: FakeMessage) => void) => void,
  options: {
    announceLoaded?: boolean;
    /** Unsubscribing does not stop delivery, as when a message was already queued. */
    leaky?: boolean;
    /** postMessage throws what this returns (if anything) instead of delivering. */
    postThrows?: (message: LibRequest) => unknown;
  } = {},
): FakeWorker {
  const listeners = new Set<(data: unknown) => void>();
  const errorListeners = new Set<(error: unknown) => void>();
  const post = (m: unknown) => queueMicrotask(() => [...listeners].forEach((l) => l(m)));
  const handle: FakeWorker = {
    terminated: false,
    posted: [] as LibRequest[],
    refs: [],
    post,
    crash: (error: unknown) => [...errorListeners].forEach((l) => l(error)),
    postMessage(message: unknown) {
      const thrown = options.postThrows?.(message as LibRequest);
      if (thrown !== undefined) throw thrown;
      handle.posted.push(message as LibRequest);
      queueMicrotask(() => {
        try {
          onRequest(message as LibRequest, post);
        } catch (error) {
          errorListeners.forEach((l) => l(error));
        }
      });
    },
    subscribe(onMessage: (data: unknown) => void) {
      listeners.add(onMessage);
      return () => {
        if (!options.leaky) listeners.delete(onMessage);
      };
    },
    onError(handler: (error: unknown) => void) {
      errorListeners.add(handler);
      return () => errorListeners.delete(handler);
    },
    terminate() {
      handle.terminated = true;
    },
    ref() {
      handle.refs.push("ref");
    },
    unref() {
      handle.refs.push("unref");
    },
  };
  if (options.announceLoaded !== false) post({ type: "loaded" });
  return handle;
}

/** A worker that never answers on its own: the test answers through `post`. */
const silentWorker = (options: Parameters<typeof fakeWorker>[1] = {}) => fakeWorker(() => {}, options);

/** Spawns fresh workers from `make` and keeps them for inspection. */
function spawner(make: () => FakeWorker = echoWorker) {
  const workers: FakeWorker[] = [];
  return {
    workers,
    latest: () => workers[workers.length - 1],
    spawn: () => {
      const w = make();
      workers.push(w);
      return w;
    },
  };
}

/** A stand-in for the in-process backend: records what it was asked, answers "in process". */
function inProcess() {
  const calls: string[] = [];
  let warmed = 0;
  let disposed = 0;
  const backend: LibBackend & { warm(): Promise<void>; dispose(): void } = {
    async callRaw<T>(fn: string): Promise<T> {
      calls.push(fn);
      return "in process" as T;
    },
    async warm() {
      warmed++;
    },
    dispose() {
      disposed++;
    },
  };
  return {
    calls,
    backend,
    warmed: () => warmed,
    disposed: () => disposed,
  };
}

const errorOf = (p: Promise<unknown>) => p.then(() => null, (e: unknown) => e);

/**
 * A worker that loads the way a real one does: `loaded` arrives `loadMs`
 * after the spawn (at once for the first worker when `firstLoaded`), and
 * requests are answered only after that, 1 ms apart. `get_possible_types_for_input`
 * hangs.
 */
function loadingWorker(loadMs: number): FakeWorker {
  let loaded = false;
  const waiting: Array<() => void> = [];
  const w = fakeWorker(
    (req, post) => {
      if (req.fn === "get_possible_types_for_input") return;
      const answer = () => setTimeout(() => post({ id: req.id, gen: req.gen, ok: true, value: `ran ${String(req.args[0])}` }), 1);
      if (loaded) answer();
      else waiting.push(answer);
    },
    { announceLoaded: false },
  );
  setTimeout(() => {
    loaded = true;
    w.post({ type: "loaded" });
    waiting.splice(0).forEach((answer) => answer());
  }, loadMs);
  return w;
}

/**
 * A worker that pays for a function's first run the way a real one does (the
 * function's code is compiled then): `loaded` arrives `loadMs` after the spawn,
 * and a request is answered `firstRunMs` later the first time this worker runs
 * its function, 1 ms later after that. `get_possible_types_for_input` hangs.
 */
function coldWorker(loadMs: number, firstRunMs: number): FakeWorker {
  let loaded = false;
  const ran = new Set<string>();
  const waiting: Array<() => void> = [];
  const w = fakeWorker(
    (req, post) => {
      if (req.fn === "get_possible_types_for_input") return;
      const run = () => {
        const ms = ran.has(req.fn) ? 1 : firstRunMs;
        ran.add(req.fn);
        setTimeout(() => post({ id: req.id, gen: req.gen, ok: true, value: `ran ${String(req.args[0])}` }), ms);
      };
      if (loaded) run();
      else waiting.push(run);
    },
    { announceLoaded: false },
  );
  setTimeout(() => {
    loaded = true;
    w.post({ type: "loaded" });
    waiting.splice(0).forEach((run) => run());
  }, loadMs);
  return w;
}

function echoWorker(): FakeWorker {
  return fakeWorker((req, post) => {
    if (req.fn === "cbor_to_json") post({ id: req.id, gen: req.gen, ok: true, value: `["${String(req.args[0])}"]` });
    else if (req.fn === "validate_cddl") post({ id: req.id, gen: req.gen, ok: true, value: { valid: true } });
    else if (req.fn === "cddl_format") post({ id: req.id, gen: req.gen, ok: false, error: { name: "Error", message: "parse error", fatal: false } });
    else if (req.fn === "decode_specific_type") post({ id: req.id, gen: req.gen, ok: false, error: { name: "RuntimeError", message: "unreachable", fatal: true } });
    // get_possible_types_for_input: never answers (a hang)
  });
}

describe("createWorkerBackend", () => {
  test("forwards raw answers and library errors, one call at a time", async () => {
    const workers: ReturnType<typeof echoWorker>[] = [];
    const backend = createWorkerBackend({
      spawn: () => {
        const w = echoWorker();
        workers.push(w);
        return w;
      },
    });
    const [a, b] = await Promise.all([
      backend.callRaw<string>("cbor_to_json", ["05"]),
      backend.callRaw<object>("validate_cddl", ["a = int"]),
    ]);
    expect(a).toBe('["05"]');
    expect(b).toEqual({ valid: true });
    expect(workers).toHaveLength(1);
    // Serial: the second request was posted after the first was answered.
    expect(workers[0].posted.map((r) => r.fn)).toEqual(["cbor_to_json", "validate_cddl"]);
    const error = await backend.callRaw("cddl_format", ["a = {"]).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toBe("parse error");
    expect(workers).toHaveLength(1);
    expect(backend.stats()).toMatchObject({ spawns: 1, ready: true, queued: 0, inFlight: false });
    await backend.dispose();
    expect(workers[0].terminated).toBe(true);
  });

  test("a fatal answer discards the worker; the next call gets a fresh one", async () => {
    const events: WorkerBackendEvent["type"][] = [];
    const workers: ReturnType<typeof echoWorker>[] = [];
    const backend = createWorkerBackend({
      spawn: () => {
        const w = echoWorker();
        workers.push(w);
        return w;
      },
      onEvent: (e) => events.push(e.type),
    });
    await expect(backend.callRaw("decode_specific_type", ["05", "X", {}])).rejects.toThrow("unreachable");
    expect(workers[0].terminated).toBe(true);
    expect(await backend.callRaw<string>("cbor_to_json", ["06"])).toBe('["06"]');
    expect(workers).toHaveLength(2);
    expect(events).toEqual(["spawned", "loaded", "fatal", "terminated", "spawned", "loaded"]);
    await backend.dispose();
  });

  test("a call past its budget kills the worker and rejects with LibTimeoutError; queued calls run on the replacement", async () => {
    const workers: ReturnType<typeof echoWorker>[] = [];
    const backend = createWorkerBackend({
      spawn: () => {
        const w = echoWorker();
        workers.push(w);
        return w;
      },
      timeoutMs: 30,
    });
    const hung = errorOf(backend.callRaw("get_possible_types_for_input", ["05"]));
    const next = backend.callRaw<string>("cbor_to_json", ["07"], { timeoutMs: 1000 });
    const error = await hung;
    expect(error).toBeInstanceOf(LibTimeoutError);
    // It started at once: nothing about waiting, the input is what took the time.
    expect((error as Error).message).not.toContain("waiting");
    expect((error as Error).message).toContain("The input is too large or too complex");
    expect(workers[0].terminated).toBe(true);
    expect(await next).toBe('["07"]');
    expect(workers).toHaveLength(2);
    await backend.dispose();
  });

  test("a queued call that expires never runs", async () => {
    const backend = createWorkerBackend({ spawn: echoWorker, timeoutMs: 200 });
    const hung = backend.callRaw("get_possible_types_for_input", ["05"]);
    const queued = backend.callRaw("cbor_to_json", ["07"], { timeoutMs: 20 });
    const error = await queued.catch((e: unknown) => e);
    expect(error).toBeInstanceOf(LibTimeoutError);
    expect((error as Error).message).toContain("never ran");
    await backend.dispose();
    await expect(hung).rejects.toBeInstanceOf(LibUnavailableError);
  });

  test("an abort signal drops a queued call; an aborted signal rejects up front", async () => {
    const backend = createWorkerBackend({ spawn: echoWorker, timeoutMs: 500 });
    const hung = backend.callRaw("get_possible_types_for_input", ["05"]);
    const controller = new AbortController();
    const queued = backend.callRaw("cbor_to_json", ["07"], { signal: controller.signal });
    controller.abort();
    await expect(queued).rejects.toBeInstanceOf(LibAbortedError);
    await expect(backend.callRaw("cbor_to_json", ["07"], { signal: controller.signal })).rejects.toBeInstanceOf(LibAbortedError);
    await backend.dispose();
    await expect(hung).rejects.toBeInstanceOf(LibUnavailableError);
  });

  test("call budgets do not run while the module loads; they start at the loaded message", async () => {
    let post: ((m: unknown) => void) | null = null;
    const requests: LibRequest[] = [];
    const backend = createWorkerBackend({
      spawn: () =>
        fakeWorker(
          (req, p) => {
            post = p as (m: unknown) => void;
            requests.push(req);
          },
          { announceLoaded: false },
        ),
      timeoutMs: 40,
      loadTimeoutMs: 1000,
    });
    let settled = false;
    const call = backend.callRaw<string>("cbor_to_json", ["05"]).finally(() => {
      settled = true;
    });
    // Twice the call budget, but the module is still loading: no timeout.
    await tick(80);
    expect(settled).toBe(false);
    expect(backend.stats().ready).toBe(false);
    expect(requests).toHaveLength(1);
    // Module loaded: the budget starts now, and the answer arrives within it.
    post!({ type: "loaded" });
    await tick(5);
    expect(backend.stats().ready).toBe(true);
    post!({ id: requests[0].id, gen: requests[0].gen, ok: true, value: "[]" });
    expect(await call).toBe("[]");
    await backend.dispose();
  });

  test("a module that fails to load is retried, then refused after the failure limit", async () => {
    let spawns = 0;
    const backend = createWorkerBackend({
      spawn: () => {
        spawns++;
        // Reports that the wasm did not load (a failed fetch, say).
        const w = fakeWorker(() => {}, { announceLoaded: false });
        w.post({ type: "loaded", error: { name: "Error", message: "fetch failed", fatal: true } });
        return w;
      },
      maxConsecutiveFailures: 2,
      retryAfterMs: 10_000,
    });
    const error = await backend.callRaw("cbor_to_json", ["05"]).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(LibUnavailableError);
    expect((error as Error).message).toContain("2 consecutive failures");
    expect((error as Error).message).toContain("fetch failed");
    expect(spawns).toBe(2);
    // Cooling down: refused without spawning.
    await expect(backend.callRaw("cbor_to_json", ["05"])).rejects.toBeInstanceOf(LibUnavailableError);
    expect(spawns).toBe(2);
    await backend.dispose();
  });

  test("a load that runs out of time is not retried at once: no second download", async () => {
    let spawns = 0;
    const backend = createWorkerBackend({
      spawn: () => {
        spawns++;
        // Never announces `loaded`, never answers: the load times out.
        return silentWorker({ announceLoaded: false });
      },
      loadTimeoutMs: 15,
      retryAfterMs: 10_000,
    });
    const error = await errorOf(backend.callRaw("cbor_to_json", ["05"]));
    expect(error).toBeInstanceOf(LibUnavailableError);
    expect((error as Error).message).toContain("did not finish loading the wasm within 15 ms");
    expect((error as Error).message).toMatch(/calls are refused for another \d+ s/);
    expect(spawns).toBe(1);
    await expect(backend.callRaw("cbor_to_json", ["05"])).rejects.toBeInstanceOf(LibUnavailableError);
    expect(spawns).toBe(1);
    await backend.dispose();
  });

  test("a spawn that throws counts as a failure", async () => {
    const backend = createWorkerBackend({
      spawn: () => {
        throw new Error("no Worker here");
      },
      maxConsecutiveFailures: 1,
    });
    const error = await backend.callRaw("cbor_to_json", ["05"]).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(LibUnavailableError);
    expect((error as Error).message).toContain("no Worker here");
    await expect(backend.warm()).rejects.toBeInstanceOf(LibUnavailableError);
  });

  test("a refusal says calls are refused only while they are", async () => {
    let spawns = 0;
    const backend = createWorkerBackend({
      spawn: () => {
        spawns++;
        throw new Error("no Worker here");
      },
      maxConsecutiveFailures: 3,
      retryAfterMs: 30_000,
    });
    const first = (await errorOf(backend.callRaw("cbor_to_json", ["05"]))) as Error;
    expect(first.message).toContain("(1 consecutive failure)");
    expect(first.message).toContain("the next call will try again");
    expect(first.message).not.toContain("refused");
    const second = (await errorOf(backend.callRaw("cbor_to_json", ["05"]))) as Error;
    expect(second.message).toContain("(2 consecutive failures)");
    expect(second.message).not.toContain("refused");
    const third = (await errorOf(backend.callRaw("cbor_to_json", ["05"]))) as Error;
    expect(third.message).toContain("(3 consecutive failures)");
    expect(third.message).toContain("calls are refused for another 30 s");
    expect(spawns).toBe(3);
    // Refused without trying: the claim holds.
    await errorOf(backend.callRaw("cbor_to_json", ["05"]));
    expect(spawns).toBe(3);
  });

  test("warm resolves once the module is loaded", async () => {
    const backend = createWorkerBackend({ spawn: echoWorker });
    await backend.warm();
    expect(backend.stats()).toMatchObject({ spawns: 1, ready: true });
    await backend.dispose();
    await expect(backend.callRaw("cbor_to_json", ["05"])).rejects.toBeInstanceOf(LibUnavailableError);
  });

  test("names off the allowlist and oversized input are refused before any worker exists", async () => {
    let spawned = false;
    const backend = createWorkerBackend({
      spawn: () => {
        spawned = true;
        return echoWorker();
      },
    });
    await expect(backend.callRaw("constructor" as never, [])).rejects.toThrow("not a callable library function");
    await expect(backend.callRaw("cbor_to_json", ["a".repeat(3 * 1024 * 1024)])).rejects.toThrow(/over the/);
    expect(spawned).toBe(false);
  });
});

describe("one deadline per call, queue wait included", () => {
  test("a call that finally gets its turn runs on what is left of its deadline, not a fresh one", async () => {
    const workers = spawner(() => silentWorker());
    const backend = createWorkerBackend({ spawn: workers.spawn, timeoutMs: 300 });
    const head = backend.callRaw<string>("cddl_outline", ["a = int"], { timeoutMs: 5_000 });
    const madeAt = Date.now();
    const behind = errorOf(backend.callRaw("cbor_to_json", ["01"]));
    await tick(200);
    // The head answers at ~200 ms; `behind` runs from then on and never answers.
    const w = workers.latest();
    w.post({ id: w.posted[0].id, gen: w.posted[0].gen, ok: true, value: "[]" });
    expect(await head).toBe("[]");
    const error = await behind;
    const elapsed = Date.now() - madeAt;
    expect(error).toBeInstanceOf(LibTimeoutError);
    expect((error as Error).message).toContain("did not finish decoding the CBOR");
    // Its deadline counts from when it was made (~300 ms), not from its turn (~500 ms).
    expect(elapsed).toBeLessThan(450);
    expect(elapsed).toBeGreaterThanOrEqual(290);
    await backend.dispose();
  });

  test("the deadline pauses while a replacement worker loads the wasm, and resumes with what was left", async () => {
    const workers = spawner(() => (workers.workers.length === 0 ? silentWorker() : silentWorker({ announceLoaded: false })));
    const backend = createWorkerBackend({ spawn: workers.spawn, timeoutMs: 400, loadTimeoutMs: 5_000 });
    const head = errorOf(backend.callRaw("cddl_outline", ["a = int"], { timeoutMs: 5_000 }));
    const behind = errorOf(backend.callRaw("cbor_to_json", ["01"]));
    await tick(200);
    // The head's worker dies; `behind` goes to a replacement that is still loading.
    workers.workers[0].crash(new Error("gone"));
    expect(await head).toBeInstanceOf(LibUnavailableError);
    await tick(500);
    // Longer than its whole deadline, but the load is not charged to it.
    expect(backend.stats()).toMatchObject({ inFlight: true, ready: false });
    const loadedAt = Date.now();
    workers.latest().post({ type: "loaded" });
    const error = await behind;
    expect(error).toBeInstanceOf(LibTimeoutError);
    // About the 200 ms that were left, not a fresh 400 ms.
    const ranFor = Date.now() - loadedAt;
    expect(ranFor).toBeGreaterThanOrEqual(150);
    expect(ranFor).toBeLessThan(330);
    await backend.dispose();
  });

  test("calls made together with one that times out are out of time too: dropped, not started on a fresh worker", async () => {
    const workers = spawner(() => loadingWorker(workers.workers.length === 0 ? 0 : 15));
    const events: string[] = [];
    const backend = createWorkerBackend({ spawn: workers.spawn, timeoutMs: 60, onEvent: (e) => events.push(e.type) });
    await backend.warm();
    const madeAt = Date.now();
    const head = errorOf(backend.callRaw("get_possible_types_for_input", ["05"]));
    const behind = ["01", "02", "03"].map((hex) => errorOf(backend.callRaw("cbor_to_json", [hex])));
    const headError = await head;
    expect(headError).toBeInstanceOf(LibTimeoutError);
    expect((headError as Error).message).toContain("abandoned");
    for (const error of await Promise.all(behind)) {
      expect(error).toBeInstanceOf(LibTimeoutError);
      expect((error as Error).message).toContain("never ran");
    }
    // Within the deadline plus timer slack; no load was waited for.
    expect(Date.now() - madeAt).toBeLessThan(100);
    // Only the head ever ran; no worker was started (and killed) for the calls behind it.
    expect(workers.workers.flatMap((w) => w.posted.map((r) => r.fn))).toEqual(["get_possible_types_for_input"]);
    expect(events.filter((e) => e === "timeout")).toHaveLength(1);
    expect(backend.stats()).toMatchObject({ spawns: 1, queued: 0, inFlight: false });
    // The next call gets a fresh worker and its full deadline.
    expect(await backend.callRaw<string>("cbor_to_json", ["04"])).toBe("ran 04");
    expect(backend.stats().spawns).toBe(2);
    await backend.dispose();
  });

  test("a call out of time behind one that gets a replacement worker is told at once, not after the load", async () => {
    const workers = spawner(() => loadingWorker(workers.workers.length === 0 ? 0 : 200));
    const backend = createWorkerBackend({ spawn: workers.spawn, timeoutMs: 60, loadTimeoutMs: 5_000 });
    await backend.warm();
    const madeAt = Date.now();
    const head = errorOf(backend.callRaw("get_possible_types_for_input", ["05"]));
    const patient = backend.callRaw<string>("cbor_to_json", ["01"], { timeoutMs: 5_000 });
    const late = errorOf(backend.callRaw("cbor_to_json", ["02"]));
    expect(await head).toBeInstanceOf(LibTimeoutError);
    const error = await late;
    expect(error).toBeInstanceOf(LibTimeoutError);
    expect((error as Error).message).toContain("never ran");
    // Answered while the replacement was still loading.
    expect(Date.now() - madeAt).toBeLessThan(150);
    expect(backend.stats().ready).toBe(false);
    expect(await patient).toBe("ran 01");
    expect(workers.workers[1].posted.map((r) => r.args[0])).toEqual(["01"]);
    await backend.dispose();
  });

  test("a call whose deadline has passed never runs, even when its own timer has not fired yet", async () => {
    // The head answers late, in the same instant the queued call's deadline passes: it must not be started.
    const workers = spawner(() => silentWorker());
    const backend = createWorkerBackend({ spawn: workers.spawn, timeoutMs: 5_000 });
    await backend.warm();
    const head = backend.callRaw<string>("cddl_outline", ["a = int"]);
    const behind = errorOf(backend.callRaw("cbor_to_json", ["01"], { timeoutMs: 40 }));
    const w = workers.latest();
    // Block the thread past the queued call's deadline, then answer the head before any timer can fire.
    const until = Date.now() + 50;
    while (Date.now() < until) {
      // busy
    }
    w.post({ id: w.posted[0].id, gen: w.posted[0].gen, ok: true, value: "[]" });
    expect(await head).toBe("[]");
    const error = await behind;
    expect(error).toBeInstanceOf(LibTimeoutError);
    expect((error as Error).message).toContain("never ran");
    expect(w.posted.map((r) => r.fn)).toEqual(["cddl_outline"]);
    await backend.dispose();
  });

  test("calls queued behind the one a replacement worker loads for keep their deadlines paused too", async () => {
    const workers = spawner(() => (workers.workers.length === 0 ? silentWorker() : silentWorker({ announceLoaded: false })));
    const backend = createWorkerBackend({ spawn: workers.spawn, timeoutMs: 400, loadTimeoutMs: 5_000 });
    const head = errorOf(backend.callRaw("cddl_outline", ["a = int"], { timeoutMs: 5_000 }));
    const second = backend.callRaw<string>("cbor_to_json", ["01"]);
    const third = backend.callRaw<string>("cbor_to_json", ["02"]);
    await tick(200);
    workers.workers[0].crash(new Error("gone"));
    expect(await head).toBeInstanceOf(LibUnavailableError);
    // Longer than what is left of either deadline, but the load is charged to neither.
    await tick(400);
    expect(backend.stats()).toMatchObject({ inFlight: true, queued: 1, ready: false });
    const w = workers.latest();
    w.post({ type: "loaded" });
    await tick();
    w.post({ id: w.posted[0].id, gen: w.posted[0].gen, ok: true, value: "one" });
    expect(await second).toBe("one");
    await tick();
    w.post({ id: w.posted[1].id, gen: w.posted[1].gen, ok: true, value: "two" });
    expect(await third).toBe("two");
    await backend.dispose();
  });

  test("calls made a few ms after one that times out are dropped, not each started (and killed) on a fresh worker", async () => {
    // A fresh worker's first run of a function takes 60 ms here; the replacement loads in 15 ms.
    const workers = spawner(() => coldWorker(workers.workers.length === 0 ? 0 : 15, 60));
    const events: string[] = [];
    const backend = createWorkerBackend({ spawn: workers.spawn, timeoutMs: 600, onEvent: (e) => events.push(e.type) });
    await backend.warm();
    // The first worker has run cbor_to_json; that does not make it quick on the replacement.
    expect(await backend.callRaw<string>("cbor_to_json", ["ff"])).toBe("ran ff");
    const head = errorOf(backend.callRaw("get_possible_types_for_input", ["05"]));
    // Deadlines 6, 12 and 18 ms after the head's, as for calls a render loop makes 6 ms apart
    // (given as longer deadlines so that timer jitter cannot move them): when the head runs out,
    // each has at most that much left, less than a first run on the replacement takes.
    const behind = (["validate_cddl", "cddl_outline", "cbor_to_json"] as const).map((fn, i) =>
      errorOf(backend.callRaw(fn, ["00"], { timeoutMs: 600 + 6 * (i + 1) })),
    );
    // A deadline 150 ms after the head's: room for a first run, so it is started on the replacement and finishes.
    const roomy = backend.callRaw<string>("cbor_to_json", ["01"], { timeoutMs: 750 });
    expect(await head).toBeInstanceOf(LibTimeoutError);
    for (const error of await Promise.all(behind)) {
      expect(error).toBeInstanceOf(LibTimeoutError);
      expect((error as Error).message).toContain("never ran");
    }
    expect(await roomy).toBe("ran 01");
    expect(events.filter((e) => e === "timeout")).toHaveLength(1);
    expect(backend.stats().spawns).toBe(2);
    expect(workers.workers.map((w) => w.posted.map((r) => r.fn))).toEqual([
      ["cbor_to_json", "get_possible_types_for_input"],
      ["cbor_to_json"],
    ]);
    await backend.dispose();
  });

  test("on a replacement still loading, a call that will be out of time at its turn is told at once; one whose function runs ahead of it is kept", async () => {
    const workers = spawner(() => loadingWorker(workers.workers.length === 0 ? 0 : 200));
    const backend = createWorkerBackend({ spawn: workers.spawn, timeoutMs: 1_000, loadTimeoutMs: 5_000 });
    await backend.warm();
    const head = errorOf(backend.callRaw("get_possible_types_for_input", ["05"]));
    const patient = backend.callRaw<string>("cbor_to_json", ["01"], { timeoutMs: 5_000 });
    const ahead = backend.callRaw<string>("validate_cddl", ["02"], { timeoutMs: 5_000 });
    // Both have at most 60 ms left when the head runs out: less than a first run needs (100 ms),
    // plenty for a function the replacement will have run by their turn.
    const sameFn = backend.callRaw<string>("validate_cddl", ["03"], { timeoutMs: 1_060 });
    const late = errorOf(backend.callRaw("cddl_outline", ["04"], { timeoutMs: 1_060 }));
    expect(await head).toBeInstanceOf(LibTimeoutError);
    const headAt = Date.now();
    const error = await late;
    expect(error).toBeInstanceOf(LibTimeoutError);
    expect((error as Error).message).toContain("too little to start");
    // Told while the replacement was still loading.
    expect(Date.now() - headAt).toBeLessThan(150);
    expect(backend.stats().ready).toBe(false);
    expect(await patient).toBe("ran 01");
    expect(await ahead).toBe("ran 02");
    expect(await sameFn).toBe("ran 03");
    expect(workers.workers[1].posted.map((r) => r.fn)).toEqual(["cbor_to_json", "validate_cddl", "validate_cddl"]);
    await backend.dispose();
  });

  test("a function the worker has run needs only MIN_TURN_MS to start; one it has not needs room for a first run", async () => {
    const workers = spawner(echoWorker);
    const backend = createWorkerBackend({ spawn: workers.spawn, timeoutMs: 1_000 });
    expect(await backend.callRaw<string>("cbor_to_json", ["00"])).toBe('["00"]');
    // cddl_outline is never answered by the echo worker: the test answers it.
    const head = backend.callRaw<string>("cddl_outline", ["a = int"], { timeoutMs: 5_000 });
    const madeAt = Date.now();
    const again = backend.callRaw<string>("cbor_to_json", ["01"]);
    const first = errorOf(backend.callRaw("validate_cddl", ["a = int"]));
    // The head answers with about 70 ms of the others' deadlines left: plenty for a function this
    // worker has already run, too little for one it has not (a tenth of the deadline, 100 ms).
    await tick(930 - (Date.now() - madeAt));
    const w = workers.latest();
    const request = w.posted.find((r) => r.fn === "cddl_outline")!;
    w.post({ id: request.id, gen: request.gen, ok: true, value: "[]" });
    expect(await head).toBe("[]");
    expect(await again).toBe('["01"]');
    const error = await first;
    expect(error).toBeInstanceOf(LibTimeoutError);
    expect((error as Error).message).toContain("never ran");
    expect((error as Error).message).toContain("too little to start");
    expect(w.posted.map((r) => r.fn)).toEqual(["cbor_to_json", "cddl_outline", "cbor_to_json"]);
    expect(backend.stats().spawns).toBe(1);
    await backend.dispose();
  });

  describe("the margin a queued call needs left to be started, to the millisecond", () => {
    // `Date.now` is frozen and moved on by hand, so what each call has left at its turn is exact;
    // nothing awaits between making the calls and their turn, so no real timer fires meanwhile.
    async function withFrozenClock(body: (advance: (ms: number) => void) => Promise<void>): Promise<void> {
      const realNow = Date.now;
      let now = realNow();
      Date.now = () => now;
      try {
        await body((ms) => {
          now += ms;
        });
      } finally {
        Date.now = realNow;
      }
    }

    /**
     * Two cbor_to_json calls with deadline `deadlineMs` queue behind a head the worker never
     * answers; when the head ends they have `marginMs - 1` and `marginMs` left. `warm`: the worker
     * has run cbor_to_json and the test answers the head; otherwise the head's worker dies and their
     * turn comes on a replacement. The first must be dropped, the second started.
     */
    async function turnWith(deadlineMs: number, warm: boolean, marginMs: number, left: string, allowed: string) {
      await withFrozenClock(async (advance) => {
        const workers = spawner(echoWorker);
        const backend = createWorkerBackend({ spawn: workers.spawn, timeoutMs: deadlineMs });
        if (warm) expect(await backend.callRaw<string>("cbor_to_json", ["00"])).toBe('["00"]');
        else await backend.warm();
        // cddl_outline is never answered by the echo worker.
        const head = errorOf(backend.callRaw("cddl_outline", ["a = int"], { timeoutMs: 60_000 }));
        const short = errorOf(backend.callRaw("cbor_to_json", ["01"]));
        advance(1);
        const enough = backend.callRaw<string>("cbor_to_json", ["02"]);
        advance(deadlineMs - marginMs);
        const w = workers.latest();
        if (warm) {
          const request = w.posted.find((r) => r.fn === "cddl_outline")!;
          w.post({ id: request.id, gen: request.gen, ok: true, value: "[]" });
          expect(await head).toBeNull();
        } else {
          w.crash(new Error("gone"));
          expect(await head).toBeInstanceOf(LibUnavailableError);
        }
        const error = await short;
        expect(error).toBeInstanceOf(LibTimeoutError);
        expect((error as Error).message).toContain(
          `only ${left} of the ${allowed} allowed was left, too little to start, so this call never ran`,
        );
        expect(await enough).toBe('["02"]');
        const ran = workers.latest().posted.map((r) => r.args[0]);
        expect(ran.filter((a) => a !== "a = int")).toEqual(warm ? ["00", "02"] : ["02"]);
        expect(backend.stats().spawns).toBe(warm ? 1 : 2);
        await backend.dispose();
      });
    }

    test("on a worker that has run the function: MIN_TURN_MS (5 ms), whatever the deadline", async () => {
      await turnWith(10_000, true, 5, "4 ms", "10 s");
    });

    test("on a fresh worker with the app's 10 s deadline: COLD_TURN_MS (100 ms), not a tenth of the deadline", async () => {
      await turnWith(10_000, false, 100, "99 ms", "10 s");
    });

    test("on a fresh worker with a 300 ms deadline: a tenth of it", async () => {
      await turnWith(300, false, 30, "29 ms", "300 ms");
    });

    test("on a fresh worker with a 200 ms deadline: COLD_TURN_FLOOR_MS (25 ms, a first run of the lighter functions), not a tenth", async () => {
      await turnWith(200, false, 25, "24 ms", "200 ms");
    });

    test("on a fresh worker with a deadline under the floor: all of it, i.e. no wait at all", async () => {
      await turnWith(20, false, 20, "19 ms", "20 ms");
    });

    test("behind the call a replacement is spawned for, a call of the same function needs only MIN_TURN_MS: it will have run there by its turn", async () => {
      await withFrozenClock(async (advance) => {
        const workers = spawner(echoWorker);
        const backend = createWorkerBackend({ spawn: workers.spawn, timeoutMs: 10_000 });
        await backend.warm();
        const head = errorOf(backend.callRaw("cddl_outline", ["a = int"]));
        // The replacement is spawned for `first`; validate_cddl runs there before `sameFn`'s turn.
        const first = backend.callRaw("validate_cddl", ["a = int"]);
        const sameFn = backend.callRaw("validate_cddl", ["b = int"], { timeoutMs: 1_000 });
        const otherFn = errorOf(backend.callRaw("cbor_to_json", ["01"], { timeoutMs: 1_000 }));
        // 50 ms left for both: too little for a first run (100 ms), plenty for a function run just before.
        advance(950);
        workers.latest().crash(new Error("gone"));
        // Sorted at the spawn, before the replacement has loaded: `otherFn` is dropped, `sameFn` kept.
        expect(backend.stats()).toMatchObject({ spawns: 2, ready: false, queued: 1, inFlight: true });
        expect(await head).toBeInstanceOf(LibUnavailableError);
        const error = await otherFn;
        expect(error).toBeInstanceOf(LibTimeoutError);
        expect((error as Error).message).toContain("only 50 ms of the 1 s allowed was left");
        expect(await first).toEqual({ valid: true });
        expect(await sameFn).toEqual({ valid: true });
        expect(workers.latest().posted.map((r) => r.args[0])).toEqual(["a = int", "b = int"]);
        await backend.dispose();
      });
    });
  });

  test("a call that did not wait reads as not having waited, whether its worker was ready or still loading", async () => {
    // Every read of the clock moves it on 20 ms, so a read between starting a call's clock and noting
    // how long it had waited would show up as waiting (a tenth of the 100 ms deadline is enough to be told).
    const realNow = Date.now;
    let now = realNow();
    Date.now = () => (now += 20);
    try {
      const ready = createWorkerBackend({ spawn: () => silentWorker(), timeoutMs: 100 });
      await ready.warm();
      const atOnce = await errorOf(ready.callRaw("cbor_to_json", ["01"]));
      expect(atOnce).toBeInstanceOf(LibTimeoutError);
      expect((atOnce as Error).message).not.toContain("waiting");
      await ready.dispose();

      const workers = spawner(() => silentWorker({ announceLoaded: false }));
      const loading = createWorkerBackend({ spawn: workers.spawn, timeoutMs: 100 });
      const afterLoad = errorOf(loading.callRaw("cbor_to_json", ["01"]));
      await tick();
      workers.latest().post({ type: "loaded" });
      const error = await afterLoad;
      expect(error).toBeInstanceOf(LibTimeoutError);
      expect((error as Error).message).not.toContain("waiting");
      await loading.dispose();
    } finally {
      Date.now = realNow;
    }
  });

  test("the message names the operation, not the export, and does not blame the input for the queue", () => {
    const plain = abandonedMessage("cbor_to_json", 10_000);
    expect(plain).toContain("did not finish decoding the CBOR within 10 s");
    expect(plain).toContain("too large or too complex");
    expect(plain).not.toContain("cbor_to_json");
    expect(plain).not.toContain("waiting");
    const mostlyQueued = abandonedMessage("map_cbor_to_cddl", 10_000, 9_000);
    expect(mostlyQueued).toContain("mapping the CBOR onto the CDDL schema");
    expect(mostlyQueued).toContain("It had spent 9 s of that waiting for earlier calls to finish.");
    expect(mostlyQueued).toContain("or the calls ahead of it took most of its time");
    const brieflyQueued = abandonedMessage("validate_transaction_js", 60_000, 2_000);
    expect(brieflyQueued).toContain("It had spent 2 s of that waiting");
    expect(brieflyQueued).toContain("The input is too large or too complex");
    // A short deadline: the wait is judged against it, not against a fixed second.
    const mostOfASecond = abandonedMessage("cbor_to_json", 1_000, 912);
    expect(mostOfASecond).toContain("It had spent 912 ms of that waiting");
    expect(mostOfASecond).toContain("or the calls ahead of it took most of its time");
    expect(mostOfASecond).not.toContain("The input is too large");
    const aFifth = abandonedMessage("cbor_to_json", 300, 60);
    expect(aFifth).toContain("It had spent 60 ms of that waiting");
    expect(aFifth).toContain("The input is too large or too complex");
    expect(abandonedMessage("cbor_to_json", 10_000, 500)).not.toContain("waiting");
    const never = neverRanMessage("validate_cbor_against_cddl", 10_000);
    expect(never).toContain("validating the CBOR against the CDDL schema");
    expect(never).toContain("never ran");
    expect(never).not.toMatch(/too large|too complex|validate_cbor_against_cddl/);
    expect(never).toContain("still busy with earlier work 10 s after it was asked");
    // Dropped with a little of its deadline left: says how little, not that all of it went.
    const tooLittle = neverRanMessage("cbor_to_json", 10_000, 80);
    expect(tooLittle).toContain("decoding the CBOR");
    expect(tooLittle).toContain("only 80 ms of the 10 s allowed was left, too little to start");
    expect(tooLittle).toContain("never ran");
    expect(tooLittle).not.toMatch(/too large|too complex|cbor_to_json|10 s after/);
    expect(neverRanMessage("cbor_to_json", 10_000, 0.3)).toBe(neverRanMessage("cbor_to_json", 10_000));
  });
});

describe("limits", () => {
  /** A worker that answers every call after `ms`. */
  const slowWorker = (ms: number) =>
    fakeWorker((req, post) => {
      setTimeout(() => post({ id: req.id, gen: req.gen, ok: true, value: "late" }), ms);
    });

  test("Infinity, 0, a negative number or a huge value mean no deadline (or the longest a timer holds), not 1 ms", async () => {
    for (const timeoutMs of [Infinity, 0, -1, 2 ** 31, Number.MAX_SAFE_INTEGER]) {
      const backend = createWorkerBackend({ spawn: () => slowWorker(30), timeoutMs });
      expect(await backend.callRaw<string>("cbor_to_json", ["01"])).toBe("late");
      // The per-call option follows the same rules.
      expect(await backend.callRaw<string>("cbor_to_json", ["01"], { timeoutMs })).toBe("late");
      expect(backend.stats().spawns).toBe(1);
      await backend.dispose();
    }
  });

  test("NaN is refused where it is given", async () => {
    expect(() => createWorkerBackend({ spawn: echoWorker, timeoutMs: NaN })).toThrow(TypeError);
    expect(() => createWorkerBackend({ spawn: echoWorker, loadTimeoutMs: NaN })).toThrow(TypeError);
    expect(() => createWorkerBackend({ spawn: echoWorker, maxConsecutiveFailures: 0 })).toThrow(TypeError);
    const backend = createWorkerBackend({ spawn: echoWorker, timeoutFor: (fn) => (fn === "cddl_format" ? NaN : undefined) });
    await expect(backend.callRaw("cbor_to_json", ["01"], { timeoutMs: NaN })).rejects.toBeInstanceOf(TypeError);
    await expect(backend.callRaw("cddl_format", ["a = int"])).rejects.toBeInstanceOf(TypeError);
    expect(await backend.callRaw<string>("cbor_to_json", ["01"])).toBe('["01"]');
    await backend.dispose();
  });

  test("an unbounded load waits for the module instead of failing at once", async () => {
    const events: string[] = [];
    const backend = createWorkerBackend({
      spawn: echoWorker,
      loadTimeoutMs: Infinity,
      onEvent: (e) => events.push(e.type),
    });
    expect(await backend.callRaw<string>("cbor_to_json", ["01"])).toBe('["01"]');
    expect(events).not.toContain("load_failed");
    await backend.dispose();
  });
});

describe("a worker that will not take the message", () => {
  test("arguments that do not clone refuse that call only: the worker is kept and nothing counts as a failure", async () => {
    const cloneError = Object.assign(new Error("() => 1 could not be cloned."), { name: "DataCloneError" });
    const workers = spawner(() =>
      fakeWorker(
        (req, post) => post({ id: req.id, gen: req.gen, ok: true, value: "ok" }),
        { postThrows: (m) => (typeof m.args[0] === "function" ? cloneError : undefined) },
      ),
    );
    const backend = createWorkerBackend({ spawn: workers.spawn, maxConsecutiveFailures: 3 });
    for (let i = 0; i < 4; i++) {
      const error = await errorOf(backend.callRaw("cbor_to_json", [() => 1]));
      expect(error).toBeInstanceOf(TypeError);
      expect((error as Error).message).toContain("cannot be sent to the library worker");
      expect(isLibRefusal(error)).toBe(false);
    }
    expect(workers.workers).toHaveLength(1);
    expect(workers.workers[0].terminated).toBe(false);
    expect(backend.stats().consecutiveFailures).toBe(0);
    expect(await backend.callRaw<string>("cbor_to_json", ["01"])).toBe("ok");
    await backend.dispose();
  });

  test("a real structured-clone failure is recognised as one", async () => {
    const channel = new MessageChannel();
    const server = serveWasm(() => ({ cbor_to_json: (hex: string) => `"${hex}"` }) as never, channel.port2);
    const port = channel.port1 as unknown as MessagePort & { terminate?: () => void };
    let terminated = false;
    port.terminate = () => {
      terminated = true;
    };
    const backend = createWorkerBackend({ spawn: () => port as never });
    await expect(backend.callRaw("cbor_to_json", [{ f: () => 1 }])).rejects.toBeInstanceOf(TypeError);
    expect(terminated).toBe(false);
    expect(await backend.callRaw<string>("cbor_to_json", ["05"])).toBe('"05"');
    await backend.dispose();
    server.stop();
    channel.port1.close();
    channel.port2.close();
  });

  test("any other refusal is the worker failing: reported as unavailable, the worker replaced, and counted", async () => {
    const workers = spawner(() => fakeWorker(() => {}, { postThrows: () => new Error("worker is gone") }));
    const backend = createWorkerBackend({ spawn: workers.spawn, maxConsecutiveFailures: 3, retryAfterMs: 10_000 });
    const results: unknown[] = [];
    for (let i = 0; i < 4; i++) results.push(await errorOf(backend.callRaw("cbor_to_json", ["01"])));
    expect(results.every((r) => r instanceof LibUnavailableError)).toBe(true);
    expect((results[0] as Error).message).toContain("could not be handed the call (decoding the CBOR): worker is gone");
    expect(workers.workers.every((w) => w.terminated)).toBe(true);
    // Three failures, then the cooldown: no fourth worker.
    expect(workers.workers).toHaveLength(3);
    expect((results[3] as Error).message).toContain("calls are refused");
  });
});

describe("replies and crashes", () => {
  test("a reply from a discarded worker is ignored, even one that still gets through", async () => {
    // Leaky: unsubscribing does not stop delivery, so only the generation check stands in the way.
    const workers = spawner(() =>
      fakeWorker(
        (req, post) => {
          if (req.fn === "decode_specific_type") post({ id: req.id, gen: req.gen, ok: false, error: { name: "RuntimeError", message: "unreachable", fatal: true } });
        },
        { leaky: true },
      ),
    );
    const backend = createWorkerBackend({ spawn: workers.spawn });
    await expect(backend.callRaw("decode_specific_type", ["05", "X", {}])).rejects.toThrow("unreachable");
    const dead = workers.workers[0];
    expect(dead.terminated).toBe(true);
    const next = backend.callRaw<string>("cbor_to_json", ["01"]);
    await tick();
    const fresh = workers.workers[1];
    const request = fresh.posted[0];
    // The dead worker answers the live call's id, with its own generation and with the live one.
    dead.post({ id: request.id, gen: 0, ok: true, value: "stale" });
    dead.post({ id: request.id, gen: request.gen, ok: true, value: "stale" });
    await tick();
    fresh.post({ id: request.id, gen: request.gen, ok: true, value: "fresh" });
    expect(await next).toBe("fresh");
    await backend.dispose();
  });

  test("a reply that carries an old generation is dropped when the same port serves the next generation", async () => {
    const port = silentWorker();
    const backend = createWorkerBackend({ spawn: () => port, timeoutMs: 20 });
    // The first call hangs past its deadline: gen 0 is discarded, the same port comes back as gen 1.
    await expect(backend.callRaw("get_possible_types_for_input", ["05"])).rejects.toBeInstanceOf(LibTimeoutError);
    const next = backend.callRaw<string>("cbor_to_json", ["01"], { timeoutMs: 1_000 });
    await tick();
    const request = port.posted[port.posted.length - 1];
    expect(request.gen).toBe(1);
    port.post({ id: request.id, gen: 0, ok: true, value: "stale" });
    await tick();
    port.post({ id: request.id, gen: 1, ok: true, value: "fresh" });
    expect(await next).toBe("fresh");
    await backend.dispose();
  });

  test("a worker that dies mid-call: that call is reported, the next gets a new worker", async () => {
    const workers = spawner(() => silentWorker());
    const backend = createWorkerBackend({ spawn: workers.spawn });
    const call = errorOf(backend.callRaw("cbor_to_json", ["01"]));
    await tick();
    workers.workers[0].crash(new Error("worker crashed"));
    const error = await call;
    expect(error).toBeInstanceOf(LibUnavailableError);
    expect((error as Error).message).toBe("The library worker stopped while decoding the CBOR: worker crashed");
    const next = backend.callRaw<string>("cbor_to_json", ["02"]);
    await tick();
    expect(workers.workers).toHaveLength(2);
    const request = workers.workers[1].posted[0];
    workers.workers[1].post({ id: request.id, gen: request.gen, ok: true, value: "fresh" });
    expect(await next).toBe("fresh");
    await backend.dispose();
  });

  test("an answer counts as the module being loaded, announcement or not", async () => {
    const workers = spawner(() => silentWorker({ announceLoaded: false }));
    const backend = createWorkerBackend({ spawn: workers.spawn, timeoutMs: 40, loadTimeoutMs: 10_000 });
    const first = backend.callRaw<string>("cddl_outline", ["a = int"]);
    await tick();
    const request = workers.workers[0].posted[0];
    workers.workers[0].post({ id: request.id, gen: request.gen, ok: true, value: "[]" });
    expect(await first).toBe("[]");
    expect(backend.stats().ready).toBe(true);
    // The next call is held to its own deadline, not paused as if the module were still loading.
    const stuck = await errorOf(backend.callRaw("cbor_to_json", ["01"]));
    expect(stuck).toBeInstanceOf(LibTimeoutError);
    expect(workers.workers[0].terminated).toBe(true);
    await backend.dispose();
  });
});

describe("the fallback, for when no worker can be had", () => {
  test("a spawn that throws sends calls to the fallback, which is built once", async () => {
    const fallback = inProcess();
    let built = 0;
    let spawns = 0;
    const events: string[] = [];
    const backend = createWorkerBackend({
      spawn: () => {
        spawns++;
        throw new Error("404");
      },
      fallback: () => {
        built++;
        return fallback.backend;
      },
      onEvent: (e) => events.push(e.type),
    });
    for (let i = 0; i < 5; i++) expect(await backend.callRaw<string>("cbor_to_json", ["01"])).toBe("in process");
    expect(fallback.calls).toHaveLength(5);
    expect(built).toBe(1);
    // Three tries, then the cooldown: no worker is started for the rest.
    expect(spawns).toBe(3);
    expect(backend.stats().fallbackCalls).toBe(5);
    expect(events.filter((e) => e === "fallback")).toHaveLength(5);
    await backend.dispose();
    expect(fallback.disposed()).toBe(1);
  });

  test("a module that never arrives costs the backend its worker, not the call, and is not downloaded again", async () => {
    const fallback = inProcess();
    const workers = spawner(() => silentWorker({ announceLoaded: false }));
    const backend = createWorkerBackend({
      spawn: workers.spawn,
      loadTimeoutMs: 20,
      timeoutMs: 10_000,
      fallback: () => fallback.backend,
    });
    expect(await backend.callRaw<string>("cbor_to_json", ["01"])).toBe("in process");
    expect(workers.workers[0].terminated).toBe(true);
    expect(await backend.callRaw<string>("cbor_to_json", ["02"])).toBe("in process");
    expect(workers.workers).toHaveLength(1);
    expect(fallback.calls).toHaveLength(2);
    await backend.dispose();
  });

  test("workers that keep failing to load are tried up to the limit, then the fallback serves", async () => {
    const fallback = inProcess();
    const workers = spawner(() => {
      const w = silentWorker({ announceLoaded: false });
      w.post({ type: "loaded", error: { name: "Error", message: "fetch failed", fatal: true } });
      return w;
    });
    const backend = createWorkerBackend({ spawn: workers.spawn, fallback: () => fallback.backend });
    expect(await backend.callRaw<string>("cbor_to_json", ["01"])).toBe("in process");
    expect(workers.workers).toHaveLength(3);
    await backend.dispose();
  });

  test("a worker is tried again once the cooldown is over", async () => {
    const fallback = inProcess();
    const workers = spawner(() => (workers.workers.length === 0 ? silentWorker({ announceLoaded: false }) : silentWorker()));
    const backend = createWorkerBackend({
      spawn: workers.spawn,
      loadTimeoutMs: 20,
      retryAfterMs: 30,
      fallback: () => fallback.backend,
    });
    expect(await backend.callRaw<string>("cbor_to_json", ["01"])).toBe("in process");
    await tick(60);
    const call = backend.callRaw<string>("cbor_to_json", ["02"]);
    await tick();
    expect(workers.workers).toHaveLength(2);
    const request = workers.workers[1].posted[0];
    workers.workers[1].post({ id: request.id, gen: request.gen, ok: true, value: "from a worker" });
    expect(await call).toBe("from a worker");
    await backend.dispose();
  });

  test("a call killed for its deadline, or by a trap, never sends the next one to the fallback", async () => {
    const fallback = inProcess();
    const workers = spawner();
    const backend = createWorkerBackend({ spawn: workers.spawn, timeoutMs: 10, fallback: () => fallback.backend });
    for (let i = 0; i < 4; i++) {
      expect(await errorOf(backend.callRaw("get_possible_types_for_input", ["01"]))).toBeInstanceOf(LibTimeoutError);
      await expect(backend.callRaw("decode_specific_type", ["05", "X", {}])).rejects.toThrow("unreachable");
    }
    expect(fallback.calls).toHaveLength(0);
    expect(workers.workers).toHaveLength(8);
    await backend.dispose();
  });

  test("workers that crash mid-call are not replaced by the fallback", async () => {
    const fallback = inProcess();
    const workers = spawner(() => silentWorker());
    // A worker that loaded and then crashed: with a limit of one failure, the backend cools down at once.
    const backend = createWorkerBackend({
      spawn: workers.spawn,
      maxConsecutiveFailures: 1,
      retryAfterMs: 10_000,
      fallback: () => fallback.backend,
    });
    const call = errorOf(backend.callRaw("cbor_to_json", ["01"]));
    await tick();
    workers.latest().crash(new Error("killed"));
    expect(await call).toBeInstanceOf(LibUnavailableError);
    const refused = await errorOf(backend.callRaw("cbor_to_json", ["01"]));
    expect(refused).toBeInstanceOf(LibUnavailableError);
    expect((refused as Error).message).toContain("keeps stopping");
    expect(fallback.calls).toHaveLength(0);
    await backend.dispose();
  });

  test("a fallback factory that fails is reported, and asked again next time", async () => {
    let attempts = 0;
    const fallback = inProcess();
    const backend = createWorkerBackend({
      spawn: () => {
        throw new Error("404");
      },
      fallback: () => {
        attempts++;
        if (attempts === 1) throw new Error("no wasm either");
        return fallback.backend;
      },
    });
    await expect(backend.callRaw("cbor_to_json", ["01"])).rejects.toThrow("no wasm either");
    expect(await backend.callRaw<string>("cbor_to_json", ["01"])).toBe("in process");
    expect(attempts).toBe(2);
  });

  test("after a trap in the fallback, later calls are refused in words an end user can act on", async () => {
    const backend = createWorkerBackend({
      spawn: () => {
        throw new Error("no Worker here");
      },
      fallback: () =>
        createInProcessBackend({
          load: async () =>
            ({
              cbor_to_json: () => {
                throw new WebAssembly.RuntimeError("unreachable");
              },
            }) as unknown as WasmModule,
        }),
    });
    await expect(backend.callRaw("cbor_to_json", ["05"])).rejects.toThrow("unreachable");
    const refused = await errorOf(backend.callRaw("cbor_to_json", ["05"]));
    expect(refused).toBeInstanceOf(LibUnavailableError);
    expect((refused as Error).message).toContain("cannot start decoding the CBOR");
    expect((refused as Error).message).toContain("Reload the page, or restart the process");
    expect((refused as Error).message).not.toMatch(/cbor_to_json|worker backend/);
    await backend.dispose();
  });

  test("warm() prepares the fallback when no worker can be had", async () => {
    const fallback = inProcess();
    const backend = createWorkerBackend({
      spawn: () => {
        throw new Error("404");
      },
      fallback: () => fallback.backend,
    });
    await backend.warm();
    expect(fallback.warmed()).toBe(1);
  });
});

describe("warm()", () => {
  test("after a load error with nothing queued, the worker is tried again rather than left pending", async () => {
    const workers = spawner(() => {
      const w = silentWorker({ announceLoaded: false });
      if (workers.workers.length === 0) {
        w.post({ type: "loaded", error: { name: "Error", message: "fetch failed", fatal: true } });
      } else {
        w.post({ type: "loaded" });
      }
      return w;
    });
    const backend = createWorkerBackend({ spawn: workers.spawn });
    await backend.warm();
    expect(workers.workers).toHaveLength(2);
    expect(backend.stats().ready).toBe(true);
    await backend.dispose();
  });

  test("after a load timeout without a fallback, it rejects instead of hanging", async () => {
    const backend = createWorkerBackend({ spawn: () => silentWorker({ announceLoaded: false }), loadTimeoutMs: 15 });
    const error = await errorOf(backend.warm());
    expect(error).toBeInstanceOf(LibUnavailableError);
    expect((error as Error).message).toContain("did not finish loading the wasm");
    await backend.dispose();
  });
});

describe("keeping a Node process alive", () => {
  test("the worker is ref'd while a call or a warm() waits on it and unref'd when idle", async () => {
    const workers = spawner(() => silentWorker({ announceLoaded: false }));
    const backend = createWorkerBackend({ spawn: workers.spawn });
    const warming = backend.warm();
    const w = workers.workers[0];
    expect(w.refs).toEqual(["ref"]);
    w.post({ type: "loaded" });
    await warming;
    expect(w.refs).toEqual(["ref", "unref"]);
    const call = backend.callRaw<string>("cbor_to_json", ["01"]);
    expect(w.refs).toEqual(["ref", "unref", "ref"]);
    await tick();
    w.post({ id: w.posted[0].id, gen: w.posted[0].gen, ok: true, value: "done" });
    expect(await call).toBe("done");
    expect(w.refs).toEqual(["ref", "unref", "ref", "unref"]);
    await backend.dispose();
  });
});

describe("createWorkerBackend over a MessageChannel served by serveWasm", () => {
  test("round-trips through the real protocol", async () => {
    const channel = new MessageChannel();
    const server = serveWasm(
      () => ({ cbor_to_json: (hex: string) => `{"hex":"${hex}"}`, validate_cddl: () => ({ valid: true }) }) as never,
      channel.port2,
    );
    const port = channel.port1 as unknown as MessagePort & { terminate?: () => void };
    port.terminate = () => port.close();
    const backend = createWorkerBackend({ spawn: () => port as never });
    expect(await backend.callRaw<string>("cbor_to_json", ["05"])).toBe('{"hex":"05"}');
    expect(await backend.callRaw<object>("validate_cddl", ["a = int"])).toEqual({ valid: true });
    await backend.dispose();
    server.stop();
    channel.port2.close();
  });
});

// A `LibBackend` over a worker that runs `serveWasm`: serial queue, generation
// counter, load handshake, one hard deadline per call, a respawn after anything
// that leaves the wasm instance untrustworthy, and an optional fallback for when
// no worker can be had at all. The host only says how to spawn.

import type { LibBackend, LibCallOptions } from "../backend.js";
import {
  LibAbortedError,
  LibResultNotTransferableError,
  LibTimeoutError,
  LibUnavailableError,
} from "../errors.js";
import { describeWasmFunction, isWasmFunction, type WasmFunctionName } from "../wasm/functions.js";
import { guardInputBudget } from "./inputBudget.js";
import { toWorkerHandle, type WorkerHandle, type WorkerSource } from "./ports.js";
import { isLibLoadedMessage, isLibResponse, type LibRequest } from "./protocol.js";

/** Default deadline for one call, in milliseconds. */
export const DEFAULT_CALL_TIMEOUT_MS = 120_000;
/** Default time a fresh worker may take to report its module loaded. */
export const DEFAULT_LOAD_TIMEOUT_MS = 60_000;
/** Consecutive worker failures before calls are refused (or sent to the fallback) for `retryAfterMs`. */
export const DEFAULT_MAX_CONSECUTIVE_FAILURES = 3;
/** How long calls are refused (or sent to the fallback) after `maxConsecutiveFailures`, or after a load timeout. */
export const DEFAULT_RETRY_AFTER_MS = 30_000;

/** The longest delay a timer holds (2^31 - 1 ms, about 24.8 days); longer limits are clamped to it. */
const MAX_TIMER_MS = 2 ** 31 - 1;

/**
 * What a queued call needs left of its deadline, when its turn comes, to be
 * started on a worker that has already run its function; with less it is
 * dropped as never run. Timers are not precise to the millisecond (a browser
 * clamps them to 4 ms), so calls made together share a deadline only to within
 * a few ms: without this margin they would be started with nothing left, and
 * each would cost the worker it was killed on.
 */
export const MIN_TURN_MS = 5;

/**
 * The most a queued call needs left of its deadline to be started on a worker
 * that has not run its function yet — a replacement, or one still to be
 * spawned. A function's first run in a worker also compiles its code: on a
 * fast machine (Node, Chromium, WebKit) up to some 25 ms for `possibleTypes`,
 * `decode`, `cborToJson` and `necessaryData`, 35–55 ms for
 * `validateTransaction` and the CDDL functions (parsing a Conway-sized schema
 * included). Without a margin, calls made a few ms after one that times out
 * would each be started on the replacement with less left than that and be
 * killed with it. The margin is a tenth of the call's deadline, at least
 * `COLD_TURN_FLOOR_MS` and at most this, and never more than the deadline
 * itself: 100 ms from a deadline of 1 s up (the app's 10 s included), 30 ms
 * with 300 ms, 25 ms with 100 ms, the whole deadline under 25 ms. So it covers
 * a first run of the lighter functions at any deadline, of the heavier ones
 * from a deadline of about 600 ms; under that, one of those can still be
 * started on a replacement with too little left and be killed with it.
 */
export const COLD_TURN_MS = 100;

/**
 * The least margin a call needs left to be started on a worker that has not
 * run its function (see `COLD_TURN_MS`), however short its deadline: a first
 * run of the lighter functions. A deadline shorter than this must be all
 * there, i.e. the call must not have waited at all.
 */
export const COLD_TURN_FLOOR_MS = 25;

/** What a call with deadline `budgetMs` needs left to be started, on a worker that has (`warm`) or has not run its function. */
function minTurnMs(budgetMs: number, warm: boolean): number {
  const wanted = warm ? MIN_TURN_MS : Math.max(COLD_TURN_FLOOR_MS, Math.min(COLD_TURN_MS, budgetMs / 10));
  // A deadline shorter than that: the call needs all of it, i.e. must not have waited at all.
  return Math.min(wanted, budgetMs);
}

export type WorkerBackendEvent =
  | { type: "spawned" }
  | { type: "loaded"; ms: number }
  | { type: "load_failed"; error: Error }
  | { type: "worker_error"; error: Error }
  | { type: "timeout"; fn: WasmFunctionName; budgetMs: number }
  | { type: "fatal"; fn: WasmFunctionName; error: Error }
  | { type: "fallback"; fn: WasmFunctionName }
  | { type: "terminated" };

export interface WorkerBackendTransport {
  /**
   * A fresh worker running `serveWasm` — a Web `Worker`, a `worker_threads`
   * `Worker`, or a `WorkerHandle`. Called lazily on the first call, and again
   * after a fatal error, a timeout or a crash discarded the previous one.
   */
  spawn(): WorkerSource;
  /**
   * Deadline for one call unless `LibCallOptions.timeoutMs` says otherwise.
   * Measured from when the call was made, so time spent queued behind other
   * calls counts; time a fresh worker spends loading the wasm does not (that is
   * bounded by `loadTimeoutMs`). A call still queued at its deadline, or whose
   * turn comes with too little of it left to be worth starting (`MIN_TURN_MS`
   * on a worker that has run its function; on one that has not, a tenth of the
   * deadline between `COLD_TURN_FLOOR_MS` and `COLD_TURN_MS`), is dropped and
   * never runs; a running one has its worker killed. That margin holds on a
   * healthy worker too: a call whose function it has not run yet is refused
   * with less than the margin left even when it would have finished in time
   * (with a 10 s deadline, one queued behind a call that ran for over 9.9 s).
   * `Infinity`, `0` or a negative number means no deadline; values over
   * 2^31 - 1 ms are clamped; `NaN` is refused with a `TypeError`. Default
   * `DEFAULT_CALL_TIMEOUT_MS`.
   */
  timeoutMs?: number;
  /** Per-function override of the default deadline (e.g. more for `validate_transaction_js`); same rules as `timeoutMs`. */
  timeoutFor?: (fn: WasmFunctionName) => number | undefined;
  /**
   * How long a fresh worker may take to load the wasm; call deadlines are
   * paused meanwhile. A load that runs out of time is not retried at once:
   * the backend goes straight into its `retryAfterMs` cooldown (serving calls
   * from `fallback`, when there is one) rather than download the wasm again.
   * Same rules as `timeoutMs`. Default `DEFAULT_LOAD_TIMEOUT_MS`.
   */
  loadTimeoutMs?: number;
  /** Worker failures in a row (spawn throws, load errors, crashes) before the `retryAfterMs` cooldown. Default 3. */
  maxConsecutiveFailures?: number;
  /** Length of the cooldown, during which no worker is spawned. Default `DEFAULT_RETRY_AFTER_MS`. */
  retryAfterMs?: number;
  /**
   * Where calls go when no worker can be had: `spawn` threw, or workers keep
   * failing to load (an error, or no `loaded` within `loadTimeoutMs`) and the
   * backend is cooling down. Typically `() => createInProcessBackend()`.
   * Built once, lazily, by the first call that needs it (a factory that
   * rejects is asked again next time). Calls it serves run without the
   * worker's deadline (wasm in the calling thread cannot be interrupted), and
   * after the cooldown the next call tries a worker again. Never used for a
   * call whose worker was killed for its deadline or by a trap — those get a
   * fresh worker — nor after workers crash mid-call. Without it, such calls
   * reject with `LibUnavailableError`.
   */
  fallback?: () => LibBackend | Promise<LibBackend>;
  /** Observability: spawns, loads, timeouts, fatal errors, fallbacks, terminations. */
  onEvent?: (event: WorkerBackendEvent) => void;
}

export interface WorkerBackendStats {
  /** Workers spawned so far. */
  spawns: number;
  /** True while a worker exists and has reported its module loaded. */
  ready: boolean;
  queued: number;
  inFlight: boolean;
  consecutiveFailures: number;
  /** Calls handed to `fallback` so far. */
  fallbackCalls: number;
}

export interface WorkerBackend extends LibBackend {
  /**
   * Spawn the worker and load the wasm ahead of the first call. When no worker
   * can be had and a `fallback` is configured, prepares the fallback instead.
   */
  warm(): Promise<void>;
  /**
   * Stop: reject outstanding calls, terminate the worker (and dispose a
   * fallback that has a `dispose`). Further calls are refused. A Node worker
   * does not keep the process alive while idle, so a script that is done exits
   * without this; a long-running host calls it on shutdown.
   */
  dispose(): Promise<void>;
  stats(): WorkerBackendStats;
}

interface PendingCall {
  id: number;
  fn: WasmFunctionName;
  args: unknown[];
  options?: LibCallOptions;
  /** The whole deadline, `Infinity` for none. */
  budgetMs: number;
  /** What is left of it while its clock is stopped (a worker is loading the wasm). */
  remainingMs: number;
  /** When the clock runs out, while it runs. */
  deadline: number | null;
  timer: ReturnType<typeof setTimeout> | null;
  /** How much of the deadline had gone when the call started running. */
  waitedMs: number;
  resolve: (value: unknown) => void;
  reject: (error: unknown) => void;
  signal?: AbortSignal;
  detach?: () => void;
  settled: boolean;
}

/** What the latest worker failure was: only "start" failures send calls to the fallback. */
type FailureKind = "start" | "crash";

function formatDuration(ms: number): string {
  if (!Number.isFinite(ms)) return "ever";
  return ms >= 1000 ? `${Math.round(ms / 1000)} s` : `${Math.round(ms)} ms`;
}

/** Queue wait of at least this, or of a tenth of the deadline if that is less, is worth a sentence in a timeout message. */
const WAIT_WORTH_SAYING_MS = 1_000;

/**
 * Message for a call that ran past its deadline. `waitedMs` is how much of the
 * deadline went on waiting for earlier calls before it started: it is
 * mentioned once it is a second or a tenth of the deadline, and when it was
 * half of it or more the input is not blamed.
 */
export function abandonedMessage(fn: string, budgetMs: number, waitedMs = 0): string {
  const head =
    `The library did not finish ${describeWasmFunction(fn)} within ${formatDuration(budgetMs)}, so the call was ` +
    `abandoned and the worker running it was replaced.`;
  if (waitedMs < Math.min(WAIT_WORTH_SAYING_MS, budgetMs / 10)) {
    return `${head} The input is too large or too complex for this operation to finish in time.`;
  }
  const waited = ` It had spent ${formatDuration(waitedMs)} of that waiting for earlier calls to finish.`;
  return waitedMs * 2 >= budgetMs
    ? `${head}${waited} The input may be too large or too complex for this operation, or the calls ahead of it took most of its time.`
    : `${head}${waited} The input is too large or too complex for this operation to finish in time.`;
}

/**
 * Message for a call dropped while still queued: at its deadline, or when its
 * turn came with only `leftMs` of it left, too little to start it. Does not
 * blame the input.
 */
export function neverRanMessage(fn: string, budgetMs: number, leftMs = 0): string {
  if (Math.round(leftMs) >= 1) {
    return (
      `The library was still busy with earlier work when it came to ${describeWasmFunction(fn)}: only ` +
      `${formatDuration(leftMs)} of the ${formatDuration(budgetMs)} allowed was left, too little to start, ` +
      `so this call never ran.`
    );
  }
  return (
    `The library was still busy with earlier work ${formatDuration(budgetMs)} after it was asked to start ` +
    `${describeWasmFunction(fn)}, so this call never ran.`
  );
}

/**
 * A limit in milliseconds as the backend applies it: `undefined` stays
 * `undefined` (use the next default), `Infinity`, `0` or less means none
 * (`Infinity`), anything above what a timer holds is clamped, and `NaN` or a
 * non-number is a caller error.
 */
function normalizeLimit(value: number | undefined, name: string): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "number" || Number.isNaN(value)) {
    throw new TypeError(`${name} must be a number of milliseconds, got ${String(value)}`);
  }
  if (!Number.isFinite(value) || value <= 0) return Number.POSITIVE_INFINITY;
  return Math.min(value, MAX_TIMER_MS);
}

/** A `postMessage` that failed on its argument (structured clone), not on the worker. */
function isCloneError(error: unknown): boolean {
  return typeof error === "object" && error !== null && (error as { name?: unknown }).name === "DataCloneError";
}

/** `ref()` / `unref()` on a Node timer; a no-op on a browser's numeric timer id. */
function setTimerRef(timer: ReturnType<typeof setTimeout> | null, ref: boolean): void {
  const t = timer as unknown as { ref?: () => void; unref?: () => void } | null;
  if (t === null || typeof t !== "object") return;
  if (ref) t.ref?.();
  else t.unref?.();
}

export function createWorkerBackend(transport: WorkerBackendTransport): WorkerBackend {
  const defaultTimeout = normalizeLimit(transport.timeoutMs, "timeoutMs") ?? DEFAULT_CALL_TIMEOUT_MS;
  const loadTimeoutMs = normalizeLimit(transport.loadTimeoutMs, "loadTimeoutMs") ?? DEFAULT_LOAD_TIMEOUT_MS;
  const maxFailures = transport.maxConsecutiveFailures ?? DEFAULT_MAX_CONSECUTIVE_FAILURES;
  if (!Number.isInteger(maxFailures) || maxFailures < 1) {
    throw new TypeError(`maxConsecutiveFailures must be a whole number of at least 1, got ${String(maxFailures)}`);
  }
  const retryAfterMs = transport.retryAfterMs ?? DEFAULT_RETRY_AFTER_MS;
  if (typeof retryAfterMs !== "number" || Number.isNaN(retryAfterMs)) {
    throw new TypeError(`retryAfterMs must be a number of milliseconds, got ${String(retryAfterMs)}`);
  }
  const emit = (event: WorkerBackendEvent) => {
    try {
      transport.onEvent?.(event);
    } catch {
      // An observer must not break the backend.
    }
  };

  let worker: WorkerHandle | null = null;
  let unsubscribe: (() => void) | null = null;
  let gen = 0;
  let nextId = 1;
  let spawns = 0;
  let moduleReady = false;
  let spawnedAt = 0;
  let loadTimer: ReturnType<typeof setTimeout> | null = null;
  let lastLoadError: Error | null = null;
  let inFlight: PendingCall | null = null;
  const queue: PendingCall[] = [];
  /** Functions the current worker has answered a call of: their code is compiled there. */
  const ranHere = new Set<WasmFunctionName>();
  let consecutiveFailures = 0;
  let lastFailureAt = 0;
  let lastFailureKind: FailureKind = "start";
  /** Set by a load timeout: cool down now rather than download the wasm again. */
  let cooldownForced = false;
  let disposed = false;
  /** Whether the current worker is ref'd (keeps a Node process alive); `null` until first synced. */
  let workerRefd: boolean | null = null;
  let fallbackBackend: Promise<LibBackend> | null = null;
  let fallbackCalls = 0;
  const readyWaiters: Array<{ resolve: () => void; reject: (e: unknown) => void }> = [];

  const budgetFor = (fn: WasmFunctionName, options?: LibCallOptions): number =>
    normalizeLimit(options?.timeoutMs, "timeoutMs") ??
    normalizeLimit(transport.timeoutFor?.(fn), `timeoutFor("${fn}")`) ??
    defaultTimeout;

  // ---------- deadlines ----------

  /** Start (or resume) the call's clock with what is left of its deadline. */
  function runClock(call: PendingCall): void {
    if (call.settled || call.timer !== null || call.remainingMs === Number.POSITIVE_INFINITY) return;
    call.deadline = Date.now() + call.remainingMs;
    call.timer = setTimeout(() => expire(call), call.remainingMs);
  }

  /** Stop the call's clock, keeping what is left (a worker is loading the wasm). */
  function pauseClock(call: PendingCall): void {
    if (call.timer === null) return;
    clearTimeout(call.timer);
    call.timer = null;
    call.remainingMs = Math.max(0, (call.deadline ?? Date.now()) - Date.now());
    call.deadline = null;
  }

  function clearClock(call: PendingCall): void {
    if (call.timer !== null) {
      clearTimeout(call.timer);
      call.timer = null;
    }
    call.deadline = null;
  }

  /** What is left of the call's deadline, running clock or stopped. */
  function timeLeft(call: PendingCall): number {
    return call.deadline !== null ? call.deadline - Date.now() : call.remainingMs;
  }

  /**
   * Too little left to be worth starting: under `MIN_TURN_MS` on a worker that
   * has run the call's function (`warm`, by default the current worker), under
   * the cold margin (`COLD_TURN_FLOOR_MS`..`COLD_TURN_MS`) on one that has not.
   */
  function outOfTime(call: PendingCall, warm = ranHere.has(call.fn)): boolean {
    return timeLeft(call) < minTurnMs(call.budgetMs, warm);
  }

  /** The call starts running now: note how much of its deadline went on waiting (before its clock is (re)started, so a call that never waited reads 0). */
  function markStarted(call: PendingCall): void {
    if (call.budgetMs === Number.POSITIVE_INFINITY) return;
    call.waitedMs = Math.max(0, call.budgetMs - timeLeft(call));
  }

  // ---------- settling ----------

  function settle(call: PendingCall, error: unknown, value?: unknown): void {
    if (call.settled) return;
    call.settled = true;
    clearClock(call);
    call.detach?.();
    if (error === null) call.resolve(value);
    else call.reject(error);
  }

  function loadingModule(): boolean {
    return worker !== null && !moduleReady;
  }

  /**
   * A Node worker keeps the process alive only while something waits on it: a
   * call in flight or queued, or a `warm()`. Idle, it is unref'd (and so is a
   * pending load timer), so a script that is done exits without `dispose()`.
   */
  function syncRef(): void {
    const busy = inFlight !== null || queue.length > 0 || readyWaiters.length > 0;
    setTimerRef(loadTimer, busy);
    if (!worker || workerRefd === busy) return;
    workerRefd = busy;
    try {
      if (busy) worker.ref?.();
      else worker.unref?.();
    } catch {
      // A worker that cannot be (un)ref'd is left as it is.
    }
  }

  // ---------- worker lifecycle ----------

  function recordFailure(kind: FailureKind): void {
    consecutiveFailures++;
    lastFailureAt = Date.now();
    lastFailureKind = kind;
  }

  function coolingDown(): boolean {
    if (consecutiveFailures < maxFailures && !cooldownForced) return false;
    if (Date.now() - lastFailureAt < retryAfterMs) return true;
    consecutiveFailures = 0;
    cooldownForced = false;
    return false;
  }

  /** Whether a call with no worker to run on may go to the fallback. */
  function fallbackApplies(): boolean {
    return transport.fallback !== undefined && lastFailureKind === "start";
  }

  /** The current worker, or a fresh one (`first`: the function of the call it is spawned for). */
  function ensureWorker(first?: WasmFunctionName): WorkerHandle | null {
    if (worker) return worker;
    if (coolingDown()) return null;
    let handle: WorkerHandle;
    try {
      handle = toWorkerHandle(transport.spawn());
    } catch (error) {
      recordFailure("start");
      lastLoadError = error instanceof Error ? error : new Error(String(error));
      emit({ type: "load_failed", error: lastLoadError });
      return null;
    }
    const thisGen = gen;
    spawns++;
    spawnedAt = Date.now();
    const offMessage = handle.subscribe((data) => receive(thisGen, data));
    const offError = handle.onError((error) => workerFailed(thisGen, error));
    unsubscribe = () => {
      offMessage();
      offError();
    };
    worker = handle;
    workerRefd = null;
    moduleReady = false;
    // Pause the queued calls' deadlines until the module loads; only the load
    // timer runs. A call already out of time would only be dropped after the
    // load: drop it now.
    for (const call of queue) pauseClock(call);
    dropOutOfTime(first);
    if (loadTimeoutMs !== Number.POSITIVE_INFINITY) {
      loadTimer = setTimeout(() => loadTimedOut(thisGen), loadTimeoutMs);
    }
    emit({ type: "spawned" });
    syncRef();
    return handle;
  }

  /** Forget the current worker and terminate it. Resolves when a Node worker has exited. */
  function discardWorker(): Promise<void> {
    const current = worker;
    worker = null;
    workerRefd = null;
    gen += 1;
    moduleReady = false;
    ranHere.clear();
    if (loadTimer !== null) {
      clearTimeout(loadTimer);
      loadTimer = null;
    }
    unsubscribe?.();
    unsubscribe = null;
    if (!current) return Promise.resolve();
    let terminated: Promise<unknown>;
    try {
      terminated = Promise.resolve(current.terminate());
    } catch {
      // A worker that cannot be terminated is already gone.
      terminated = Promise.resolve();
    }
    emit({ type: "terminated" });
    return terminated.then(
      () => undefined,
      () => undefined,
    );
  }

  function moduleLoaded(thisGen: number): void {
    if (thisGen !== gen || disposed || moduleReady) return;
    moduleReady = true;
    consecutiveFailures = 0;
    cooldownForced = false;
    lastLoadError = null;
    if (loadTimer !== null) {
      clearTimeout(loadTimer);
      loadTimer = null;
    }
    emit({ type: "loaded", ms: Date.now() - spawnedAt });
    // Deadlines resume now: the wait so far was the load, not the call.
    if (inFlight && !inFlight.settled) {
      markStarted(inFlight);
      runClock(inFlight);
    }
    for (const call of queue) runClock(call);
    for (const waiter of readyWaiters.splice(0)) waiter.resolve();
    syncRef();
  }

  /** The module did not load (error or timeout). The in-flight call never ran, so it goes back on the queue. */
  function loadFailed(thisGen: number, error: Error, timedOut = false): void {
    if (thisGen !== gen || disposed) return;
    lastLoadError = error;
    recordFailure("start");
    // A load that ran out of time is not retried at once: the next attempt would
    // download the wasm again at the same speed.
    if (timedOut) cooldownForced = true;
    emit({ type: "load_failed", error });
    const call = inFlight;
    inFlight = null;
    void discardWorker();
    if (call && !call.settled) queue.unshift(call);
    pump();
    // A `warm()` with nothing queued: retry the worker, or settle the waiters.
    if (readyWaiters.length > 0 && !worker && !ensureWorker()) settleWaitersWithoutWorker();
    syncRef();
  }

  function loadTimedOut(thisGen: number): void {
    loadTimer = null;
    loadFailed(
      thisGen,
      new LibUnavailableError(
        `The library worker did not finish loading the wasm within ${formatDuration(loadTimeoutMs)}.`,
      ),
      true,
    );
  }

  /** The worker died. Before its module loaded that is a load failure; after, the running call is reported and nothing is replayed. */
  function workerFailed(thisGen: number, error: unknown): void {
    if (thisGen !== gen || disposed) return;
    const err = error instanceof Error ? error : new Error(String(error));
    emit({ type: "worker_error", error: err });
    if (!moduleReady) {
      loadFailed(thisGen, err);
      return;
    }
    recordFailure("crash");
    void discardWorker();
    const call = inFlight;
    inFlight = null;
    if (call) {
      settle(
        call,
        new LibUnavailableError(`The library worker stopped while ${describeWasmFunction(call.fn)}: ${err.message}`),
      );
    }
    pump();
  }

  function unavailable(): LibUnavailableError {
    const reason = lastLoadError ? ` Last failure: ${lastLoadError.message}` : "";
    const failures = `${consecutiveFailures} consecutive failure${consecutiveFailures === 1 ? "" : "s"}`;
    const what =
      lastFailureKind === "crash"
        ? `The library worker keeps stopping (${failures})`
        : `The library worker could not be started (${failures})`;
    let next: string;
    if (!coolingDown()) {
      next = "the next call will try again";
    } else if (!Number.isFinite(retryAfterMs)) {
      next = "calls are refused from now on";
    } else {
      next = `calls are refused for another ${formatDuration(Math.max(0, retryAfterMs - (Date.now() - lastFailureAt)))}`;
    }
    return new LibUnavailableError(`${what}; ${next}.${reason}`);
  }

  // ---------- fallback ----------

  function getFallback(): Promise<LibBackend> {
    if (!fallbackBackend) {
      const build = transport.fallback!;
      fallbackBackend = Promise.resolve()
        .then(() => build())
        .catch((error: unknown) => {
          fallbackBackend = null;
          throw error;
        });
    }
    return fallbackBackend;
  }

  /** Run `call` on the fallback: no worker, so no deadline either. */
  function runOnFallback(call: PendingCall): void {
    clearClock(call);
    fallbackCalls++;
    emit({ type: "fallback", fn: call.fn });
    getFallback()
      .then((backend) => {
        if (disposed || call.settled) return undefined;
        return backend.callRaw(call.fn, call.args, { signal: call.signal, timeoutMs: call.options?.timeoutMs });
      })
      .then(
        (value) => settle(call, null, value),
        (error: unknown) => settle(call, error),
      );
  }

  /** `warm()` callers when no worker can be had: prepare the fallback, or say why not. */
  function settleWaitersWithoutWorker(): void {
    const waiters = readyWaiters.splice(0);
    if (waiters.length === 0) return;
    if (!fallbackApplies()) {
      const error = unavailable();
      for (const waiter of waiters) waiter.reject(error);
      return;
    }
    getFallback()
      .then((backend) => (backend as { warm?: () => Promise<void> }).warm?.())
      .then(
        () => waiters.forEach((w) => w.resolve()),
        (error: unknown) => waiters.forEach((w) => w.reject(error)),
      );
  }

  // ---------- scheduling ----------

  function pump(): void {
    while (!disposed && !inFlight && queue.length > 0) {
      const next = queue.shift();
      if (!next || next.settled) continue;
      // Its deadline passed while it waited (its own timer may just not have
      // fired yet), or too little of it is left to start it here: it never
      // runs, and costs no worker.
      if (outOfTime(next)) {
        settle(next, new LibTimeoutError(neverRanMessage(next.fn, next.budgetMs, Math.max(0, timeLeft(next)))));
        continue;
      }
      const handle = ensureWorker(next.fn);
      if (!handle) {
        if (fallbackApplies()) runOnFallback(next);
        else settle(next, unavailable());
        continue;
      }
      inFlight = next;
      // A fresh worker may still be loading: the clock resumes at `loaded`.
      if (loadingModule()) {
        pauseClock(next);
      } else {
        markStarted(next);
        runClock(next);
      }
      const request: LibRequest = { id: next.id, gen, fn: next.fn, args: next.args };
      try {
        handle.postMessage(request);
      } catch (error) {
        inFlight = null;
        const detail = error instanceof Error ? error.message : String(error);
        if (isCloneError(error)) {
          // The caller's arguments, not the worker: refuse this call and keep the worker.
          settle(
            next,
            new TypeError(
              `The arguments for ${describeWasmFunction(next.fn)} cannot be sent to the library worker ` +
                `(${detail}); pass plain data: strings, numbers, bigints, arrays and objects.`,
            ),
          );
          continue;
        }
        // The worker would not take the message: it is dead or unusable.
        recordFailure("start");
        lastLoadError = error instanceof Error ? error : new Error(detail);
        void discardWorker();
        settle(
          next,
          new LibUnavailableError(
            `The library worker could not be handed the call (${describeWasmFunction(next.fn)}): ${detail}`,
          ),
        );
      }
    }
    syncRef();
  }

  function receive(thisGen: number, data: unknown): void {
    if (thisGen !== gen || disposed) return;
    if (isLibLoadedMessage(data)) {
      if (data.error) {
        const err = Object.assign(new Error(data.error.message), { name: data.error.name });
        loadFailed(thisGen, err);
      } else {
        moduleLoaded(thisGen);
      }
      return;
    }
    if (!isLibResponse(data) || data.gen !== thisGen) return;
    // An answer means the module is loaded, even if `loaded` was never posted.
    moduleLoaded(thisGen);

    const call = inFlight;
    if (!call || call.id !== data.id) return;
    inFlight = null;
    ranHere.add(call.fn);

    if (data.ok) {
      settle(call, null, data.value);
    } else {
      const error =
        data.error.kind === "result_not_transferable"
          ? new LibResultNotTransferableError(data.error.message)
          : Object.assign(new Error(data.error.message), { name: data.error.name });
      settle(call, error);
      if (data.error.fatal) {
        // A trap poisons the wasm instance; drop this worker. Not a worker failure: the input did it.
        emit({ type: "fatal", fn: call.fn, error });
        void discardWorker();
      }
    }
    pump();
  }

  /** Deadline reached: kill the worker if this call is running; drop it if still queued. */
  function expire(call: PendingCall): void {
    call.timer = null;
    if (call.settled || disposed) return;
    if (inFlight === call) {
      inFlight = null;
      emit({ type: "timeout", fn: call.fn, budgetMs: call.budgetMs });
      // Not a worker failure but the call's own cost: the next call gets a fresh worker, never the fallback.
      void discardWorker();
      settle(call, new LibTimeoutError(abandonedMessage(call.fn, call.budgetMs, call.waitedMs)));
      pump();
      return;
    }
    expireQueued(call);
    syncRef();
  }

  /** Drop a queued call as never run; `leftMs`: what was left of its deadline. */
  function expireQueued(call: PendingCall, leftMs = 0): void {
    const index = queue.indexOf(call);
    if (index >= 0) queue.splice(index, 1);
    settle(call, new LibTimeoutError(neverRanMessage(call.fn, call.budgetMs, leftMs)));
  }

  /**
   * On a fresh worker (`first`: the function of the call it is spawned for),
   * drop every queued call that will be out of time at its turn: its clock is
   * stopped until the load and can only run down after it, and its function
   * can only have run there by then if a call ahead of it runs that function.
   */
  function dropOutOfTime(first?: WasmFunctionName): void {
    const runsAhead = new Set<WasmFunctionName>(ranHere);
    if (first !== undefined) runsAhead.add(first);
    for (const call of [...queue]) {
      if (outOfTime(call, runsAhead.has(call.fn))) expireQueued(call, Math.max(0, timeLeft(call)));
      else runsAhead.add(call.fn);
    }
  }

  function dropQueued(call: PendingCall): void {
    if (call.settled || inFlight === call) return;
    const index = queue.indexOf(call);
    if (index < 0) return;
    queue.splice(index, 1);
    settle(call, new LibAbortedError());
    syncRef();
  }

  // ---------- public surface ----------

  return {
    callRaw<T>(fn: WasmFunctionName, args: unknown[], options?: LibCallOptions): Promise<T> {
      return new Promise<T>((resolve, reject) => {
        if (disposed) {
          reject(new LibUnavailableError("The library worker backend has been disposed."));
          return;
        }
        if (!isWasmFunction(fn)) {
          reject(new Error(`${String(fn)} is not a callable library function`));
          return;
        }
        let budgetMs: number;
        try {
          guardInputBudget(fn, args);
          budgetMs = budgetFor(fn, options);
        } catch (error) {
          reject(error);
          return;
        }
        if (options?.signal?.aborted) {
          reject(new LibAbortedError());
          return;
        }
        const call: PendingCall = {
          id: nextId++,
          fn,
          args,
          options,
          budgetMs,
          remainingMs: budgetMs,
          deadline: null,
          timer: null,
          waitedMs: 0,
          resolve: resolve as (value: unknown) => void,
          reject,
          signal: options?.signal,
          settled: false,
        };
        const signal = options?.signal;
        if (signal) {
          const onAbort = () => dropQueued(call);
          signal.addEventListener("abort", onAbort);
          call.detach = () => signal.removeEventListener("abort", onAbort);
        }
        // One deadline from now, queue wait included; paused while a worker
        // loads the wasm. `pump` starts it for a call it dispatches at once.
        queue.push(call);
        pump();
        if (!loadingModule() && queue.includes(call)) runClock(call);
      });
    },

    warm(): Promise<void> {
      return new Promise<void>((resolve, reject) => {
        if (disposed) {
          reject(new LibUnavailableError("The library worker backend has been disposed."));
          return;
        }
        if (worker && moduleReady) {
          resolve();
          return;
        }
        readyWaiters.push({ resolve, reject });
        if (!ensureWorker()) settleWaitersWithoutWorker();
        syncRef();
      });
    },

    async dispose(): Promise<void> {
      if (disposed) return;
      disposed = true;
      const error = new LibUnavailableError("The library worker backend has been disposed.");
      const outstanding = queue.splice(0);
      if (inFlight) {
        outstanding.unshift(inFlight);
        inFlight = null;
      }
      for (const call of outstanding) settle(call, error);
      for (const waiter of readyWaiters.splice(0)) waiter.reject(error);
      const fallback = fallbackBackend;
      fallbackBackend = null;
      await discardWorker();
      if (fallback) {
        await fallback.then(
          (backend) => (backend as { dispose?: () => unknown }).dispose?.(),
          () => undefined,
        );
      }
    },

    stats(): WorkerBackendStats {
      return {
        spawns,
        ready: worker !== null && moduleReady,
        queued: queue.length,
        inFlight: inFlight !== null,
        consecutiveFailures,
        fallbackCalls,
      };
    },
  };
}

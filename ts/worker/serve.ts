// The worker side: answer `LibRequest`s with the wasm's raw return values.
// `answer`/`reply` are independent of any global so tests can stub the module
// and the port; `serveWasm` wires them to a real one.

import { asError, isFatalToInstance } from "../errors.js";
import type { WasmModule } from "../wasm/functions.js";
import { unwrapWasmNamespace } from "../wasm/namespace.js";
import {
  isLibRequest,
  isWasmFunction,
  type LibErrorPayload,
  type LibLoadedMessage,
  type LibRequest,
  type LibResponse,
} from "./protocol.js";
import { toMessagePort, type PortSource } from "./ports.js";

/** The wasm module as the worker holds it: exports looked up by name. */
export type LibModule = Record<string, unknown>;

export function errorPayload(error: unknown): LibErrorPayload {
  const e = asError(error);
  return { name: e.name, message: e.message, fatal: isFatalToInstance(error) };
}

/**
 * The reply to one request: the library's answer exactly as returned, or why
 * there is none. A load failure is reported fatal: nothing can be served.
 */
export async function answer(request: LibRequest, loadLib: () => Promise<LibModule>): Promise<LibResponse> {
  const { id, gen } = request;
  try {
    if (!isWasmFunction(request.fn)) {
      throw new Error(`${String(request.fn)} is not a callable library function`);
    }
    let lib: LibModule;
    try {
      lib = await loadLib();
    } catch (error) {
      const payload = errorPayload(error);
      return { id, gen, ok: false, error: { ...payload, fatal: true } };
    }
    const impl = lib[request.fn];
    if (typeof impl !== "function") {
      throw new Error(`The library does not export ${request.fn}`);
    }
    const value = (impl as (...a: unknown[]) => unknown)(...request.args);
    return { id, gen, ok: true, value };
  } catch (error) {
    return { id, gen, ok: false, error: errorPayload(error) };
  }
}

/**
 * Post a reply. If structured clone fails, post a `result_not_transferable`
 * error instead of leaving the host to wait for its watchdog.
 */
export function reply(response: LibResponse, post: (message: LibResponse) => void): void {
  try {
    post(response);
  } catch (error) {
    const { id, gen } = response;
    post({
      id,
      gen,
      ok: false,
      error: {
        name: error instanceof Error ? error.name : "Error",
        message:
          "The library answered, but the answer could not be handed to the caller: " +
          (error instanceof Error ? error.message : String(error)),
        fatal: false,
        kind: "result_not_transferable",
      },
    });
  }
}

/**
 * How `serveWasm` gets the module: the module itself, the promise of one
 * (`import("@cardananium/cquisitor-lib/wasm")` — the namespace is unwrapped),
 * or a function producing either (loaded lazily, on the first request).
 */
export type WasmSource = WasmModule | Promise<unknown> | (() => WasmModule | Promise<unknown>);

export interface WasmServer {
  /** Stop answering requests. */
  stop(): void;
}

/**
 * Serve one wasm instance over `port` — a worker's `self`, Node's `parentPort`,
 * or a `MessagePort`. Posts `{type: "loaded"}` when the load settles (with
 * `error` when it failed), then answers each `LibRequest` in turn. One call at
 * a time is the host's job: the worker is single-threaded and the wasm's schema
 * cache is shared.
 *
 * Call it synchronously when the worker starts, handing it the module or the
 * promise of one: after a top-level `await` the host's first request may
 * already have arrived with nothing listening for it, and it is lost.
 *
 *     // browser worker file
 *     serveWasm(import("@cardananium/cquisitor-lib/wasm"), self);
 */
export function serveWasm(wasm: WasmSource, port: PortSource): WasmServer {
  const endpoint = toMessagePort(port);
  let modulePromise: Promise<LibModule> | null = null;
  const loadLib = (): Promise<LibModule> => {
    if (!modulePromise) {
      modulePromise = Promise.resolve()
        .then(() => (typeof wasm === "function" ? (wasm as () => unknown)() : wasm))
        .then((loaded) => unwrapWasmNamespace(loaded) as unknown as LibModule);
    }
    return modulePromise;
  };
  const post = (message: LibResponse | LibLoadedMessage) => endpoint.postMessage(message);

  const unsubscribe = endpoint.subscribe((data) => {
    if (!isLibRequest(data)) return;
    void answer(data, loadLib).then((response) => reply(response, post));
  });

  // Announce as soon as load settles (ok or fail) so the host can start call budgets.
  loadLib().then(
    () => post({ type: "loaded" }),
    (error: unknown) => post({ type: "loaded", error: { ...errorPayload(error), fatal: true } }),
  );

  return { stop: unsubscribe };
}

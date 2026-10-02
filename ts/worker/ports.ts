// The two message-passing APIs the library meets (the Web `Worker` /
// `MessagePort` / worker global scope, and Node's `worker_threads`), reduced to
// one shape by duck typing so neither side needs a platform import.

/** Messages in and out of one endpoint. */
export interface MessagePortLike {
  postMessage(message: unknown): void;
  /** Deliver each incoming message's data. Returns the unsubscribe. */
  subscribe(onMessage: (data: unknown) => void): () => void;
}

/** A worker as its host sees it: a port plus failure and termination. */
export interface WorkerHandle extends MessagePortLike {
  /** Errors thrown at the top level of the worker, clone failures on the way in, and abnormal exits. */
  onError(handler: (error: unknown) => void): () => void;
  terminate(): void | Promise<unknown>;
  /**
   * Node only (`worker_threads`): let the worker keep the process alive
   * (`ref`) or not (`unref`). `createWorkerBackend` refs it while a call or a
   * `warm()` is outstanding and unrefs it when idle, so a script that is done
   * exits without `dispose()`. Web workers have no such notion.
   */
  ref?(): void;
  unref?(): void;
}

/** Web: `Worker`, `MessagePort`, `DedicatedWorkerGlobalScope` (`self`). */
export interface WebPortSource {
  postMessage(message: unknown): void;
  addEventListener(type: string, listener: (event: { data?: unknown }) => void): void;
  removeEventListener(type: string, listener: (event: { data?: unknown }) => void): void;
  /** `MessagePort` needs `start()` when listening via `addEventListener`. */
  start?(): void;
  terminate?(): void;
}

/** Node: `worker_threads.Worker`, `worker_threads.MessagePort`, `parentPort`. */
export interface NodePortSource {
  postMessage(message: unknown): void;
  on(event: string, listener: (value: unknown) => void): unknown;
  off(event: string, listener: (value: unknown) => void): unknown;
  terminate?(): Promise<unknown> | void;
  ref?(): unknown;
  unref?(): unknown;
}

export type PortSource = MessagePortLike | WebPortSource | NodePortSource;
export type WorkerSource = WorkerHandle | (WebPortSource & { terminate(): void }) | (NodePortSource & { terminate(): Promise<unknown> | void });

function isAdapted(source: object): source is MessagePortLike {
  return typeof (source as MessagePortLike).subscribe === "function";
}

function isWeb(source: object): source is WebPortSource {
  return typeof (source as WebPortSource).addEventListener === "function";
}

function isNode(source: object): source is NodePortSource {
  return typeof (source as NodePortSource).on === "function";
}

/** One shape over a Web or Node message endpoint. Already-adapted ports pass through. */
export function toMessagePort(source: PortSource): MessagePortLike {
  if (isAdapted(source)) return source;
  if (isWeb(source)) {
    return {
      postMessage: (m) => source.postMessage(m),
      subscribe(onMessage) {
        const listener = (event: { data?: unknown }) => onMessage(event.data);
        source.addEventListener("message", listener);
        source.start?.();
        return () => source.removeEventListener("message", listener);
      },
    };
  }
  if (isNode(source)) {
    return {
      postMessage: (m) => source.postMessage(m),
      subscribe(onMessage) {
        source.on("message", onMessage);
        return () => source.off("message", onMessage);
      },
    };
  }
  throw new TypeError("Not a message port: expected postMessage plus addEventListener (Web) or on/off (Node)");
}

/** One shape over a Web `Worker` or a `worker_threads.Worker`. Already-adapted handles pass through. */
export function toWorkerHandle(source: WorkerSource): WorkerHandle {
  if (isAdapted(source) && typeof (source as WorkerHandle).onError === "function") return source as WorkerHandle;
  const port = toMessagePort(source);
  if (isWeb(source)) {
    return {
      ...port,
      onError(handler) {
        const onError = (event: unknown) => handler(errorOfEvent(event));
        source.addEventListener("error", onError);
        source.addEventListener("messageerror", onError);
        return () => {
          source.removeEventListener("error", onError);
          source.removeEventListener("messageerror", onError);
        };
      },
      terminate: () => source.terminate?.(),
    };
  }
  const node = source as NodePortSource;
  return {
    ...port,
    onError(handler) {
      const onError = (value: unknown) => handler(value instanceof Error ? value : new Error(String(value)));
      const onExit = (code: unknown) => {
        if (code !== 0) handler(new Error(`The library worker exited with code ${String(code)}`));
      };
      node.on("error", onError);
      node.on("messageerror", onError);
      node.on("exit", onExit);
      return () => {
        node.off("error", onError);
        node.off("messageerror", onError);
        node.off("exit", onExit);
      };
    },
    terminate: () => node.terminate?.(),
    ref: () => {
      node.ref?.();
    },
    unref: () => {
      node.unref?.();
    },
  };
}

function errorOfEvent(event: unknown): Error {
  if (event instanceof Error) return event;
  const e = event as { message?: unknown; error?: unknown; type?: unknown } | null;
  if (e && e.error instanceof Error) return e.error;
  if (e && typeof e.message === "string" && e.message) return new Error(e.message);
  return new Error(`The library worker raised ${String(e?.type ?? "an error")}`);
}

import { describe, expect, test } from "bun:test";
import type { LibRequest, LibResponse } from "./protocol.js";
import { toMessagePort, type PortSource } from "./ports.js";
import { answer, reply, serveWasm, type LibModule } from "./serve.js";

const listen = (port: unknown, onMessage: (data: unknown) => void) => toMessagePort(port as PortSource).subscribe(onMessage);

const request = (fn: LibRequest["fn"], ...args: unknown[]): LibRequest => ({ id: 7, gen: 0, fn, args });
const libOf = (exports: LibModule) => () => Promise.resolve(exports);

describe("answering a request", () => {
  test("the wasm's return value is posted as it is: text stays text, boxes stay boxed", async () => {
    const lib = libOf({
      cbor_to_json: () => '{"ok":true,"value":5}',
      cddl_outline: () => [{ name: "a", span: { "$serde_json::private::Number": "3" } }],
    });
    expect(await answer(request("cbor_to_json", "05"), lib)).toEqual({
      id: 7,
      gen: 0,
      ok: true,
      value: '{"ok":true,"value":5}',
    });
    expect(await answer(request("cddl_outline", "a = int"), lib)).toEqual({
      id: 7,
      gen: 0,
      ok: true,
      value: [{ name: "a", span: { "$serde_json::private::Number": "3" } }],
    });
  });

  test("a stack overflow inside the call is fatal to the instance", async () => {
    const lib = libOf({
      cbor_to_json: () => {
        throw new RangeError("Maximum call stack size exceeded");
      },
    });
    const response = await answer(request("cbor_to_json", "05"), lib);
    expect(response.ok).toBe(false);
    if (!response.ok) {
      expect(response.error.name).toBe("RangeError");
      expect(response.error.fatal).toBe(true);
    }
  });

  test("a throw that is neither a trap nor an overflow keeps the instance, and a thrown string keeps its text", async () => {
    const lib = libOf({
      cddl_format: () => {
        throw "parse error";
      },
    });
    const response = await answer(request("cddl_format", "a = {"), lib);
    expect(response.ok).toBe(false);
    if (!response.ok) {
      expect(response.error.fatal).toBe(false);
      expect(response.error.message).toBe("parse error");
    }
  });

  test("a module that failed to load answers fatal", async () => {
    const response = await answer(request("cbor_to_json", "05"), () => Promise.reject(new Error("no wasm")));
    expect(response.ok).toBe(false);
    if (!response.ok) {
      expect(response.error.fatal).toBe(true);
      expect(response.error.message).toBe("no wasm");
    }
  });

  test("a name off the allowlist never reaches the module", async () => {
    let loaded = false;
    const lib = () => {
      loaded = true;
      return Promise.resolve({});
    };
    const response = await answer(request("constructor" as LibRequest["fn"]), lib);
    expect(response.ok).toBe(false);
    expect(loaded).toBe(false);
  });
});

describe("posting a reply", () => {
  test("an answer the clone refuses is replaced by a refusal that names the kind", () => {
    const posted: LibResponse[] = [];
    let attempts = 0;
    const post = (message: LibResponse) => {
      attempts++;
      if (attempts === 1) throw new DOMException("too deep", "DataCloneError");
      posted.push(message);
    };
    reply({ id: 7, gen: 0, ok: true, value: { deep: true } }, post);
    expect(posted.length).toBe(1);
    const only = posted[0];
    expect(only.ok).toBe(false);
    if (!only.ok) {
      expect(only.error.kind).toBe("result_not_transferable");
      expect(only.error.fatal).toBe(false);
      expect(only.error.message).toContain("too deep");
    }
    expect(only.id).toBe(7);
  });

  test("an answer that posts is posted once, as it is", () => {
    const posted: LibResponse[] = [];
    const response: LibResponse = { id: 7, gen: 0, ok: true, value: "[]" };
    reply(response, (m) => posted.push(m));
    expect(posted).toEqual([response]);
  });
});

describe("serveWasm over a MessageChannel", () => {
  test("announces the load, answers requests, ignores noise", async () => {
    const channel = new MessageChannel();
    const received: unknown[] = [];
    const waitFor = (count: number) =>
      new Promise<void>((resolve) => {
        const check = () => {
          if (received.length >= count) resolve();
          else setTimeout(check, 5);
        };
        check();
      });
    listen(channel.port1, (data) => received.push(data));
    const server = serveWasm(() => ({ cbor_to_json: (hex: string) => `["${hex}"]` }) as never, channel.port2);
    await waitFor(1);
    expect(received[0]).toEqual({ type: "loaded" });
    channel.port1.postMessage("noise");
    channel.port1.postMessage({ id: 1, gen: 0, fn: "cbor_to_json", args: ["05"] });
    await waitFor(2);
    expect(received[1]).toEqual({ id: 1, gen: 0, ok: true, value: '["05"]' });
    server.stop();
    channel.port1.close();
    channel.port2.close();
  });

  test("a load failure is announced and every request answers fatal", async () => {
    const channel = new MessageChannel();
    const received: unknown[] = [];
    listen(channel.port1, (data) => received.push(data));
    const server = serveWasm(() => Promise.reject(new Error("no wasm here")), channel.port2);
    channel.port1.postMessage({ id: 1, gen: 0, fn: "cbor_to_json", args: ["05"] });
    await new Promise((r) => setTimeout(r, 30));
    const loaded = received.find((m) => (m as { type?: string }).type === "loaded") as { error?: { message: string } };
    expect(loaded.error?.message).toBe("no wasm here");
    const response = received.find((m) => (m as { id?: number }).id === 1) as LibResponse;
    expect(response.ok).toBe(false);
    if (!response.ok) expect(response.error.fatal).toBe(true);
    server.stop();
    channel.port1.close();
    channel.port2.close();
  });
});

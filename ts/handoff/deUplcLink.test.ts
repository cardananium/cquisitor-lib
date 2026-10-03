import { describe, expect, test } from "bun:test";
import type { EvalRedeemerResult } from "@cardananium/cquisitor-lib/wasm";
import type { Redeemer } from "../types/transaction.js";
import {
  fieldsFromEval,
  buildAllDeUplcLinks,
  fieldsToPlainUrl,
  fieldsToCompressedUrl,
  fieldsFromDecompile,
  fieldsFromEvalDecompile,
  fieldsToDecompilePlainUrl,
  fieldsToDecompileCompressedUrl,
  fieldsToDecompileUrl,
  decompilePurpose,
  plutusVersionFromScriptType,
  fieldsToUrl,
  readDeUplcAnnotations,
  type DeUplcFields,
  type DecompileFields,
} from "./deUplcLink.js";
import type { Annotation, DeUplcTarget } from "../share/annotations.js";
import { fromBase64Url } from "../share/base64url.js";

// ── minimal typed mocks ──────────────────────────────────────────────────────────────────────────

function redeemer(tag: string, index: number): Redeemer {
  return { tag, index: String(index), data: "00", ex_units: { mem: "0", steps: "0" } };
}

function evalResult(opts: {
  tag: string;
  index: number;
  version?: string | null;
  script?: string | null;
  context?: string | null;
  redeemer?: string | null;
  datum?: string | null;
  provided?: { mem: bigint; steps: bigint };
}): EvalRedeemerResult {
  return {
    tag: opts.tag,
    index: BigInt(opts.index),
    script_bytes: opts.script ?? null,
    plutus_version: opts.version ?? null,
    script_context_bytes: opts.context ?? null,
    redeemer_bytes: opts.redeemer ?? null,
    datum_bytes: opts.datum ?? null,
    script_context: null,
    success: true,
    error: null,
    logs: [],
    calculated_ex_units: { mem: BigInt(0), steps: BigInt(0) },
    provided_ex_units: opts.provided ?? { mem: BigInt(0), steps: BigInt(0) },
  } as unknown as EvalRedeemerResult;
}

function parseHashParams(url: string): URLSearchParams {
  return new URLSearchParams(url.slice(url.indexOf("#") + 1));
}

async function gunzipBase64Url(d: string): Promise<string> {
  const ds = new DecompressionStream("gzip");
  const w = ds.writable.getWriter();
  void w.write(fromBase64Url(d));
  void w.close();
  return new Response(ds.readable).text();
}

// ── fieldsFromEval — param mapping per version ────────────────────────────────────────────────────

describe("fieldsFromEval — apply-order per version", () => {
  test("V3 spend → context ONLY (redeemer/datum embedded in the V3 context, never sent)", () => {
    const link = fieldsFromEval(
      evalResult({
        tag: "Spend",
        index: 0,
        version: "V3",
        script: "5350563348",
        context: "d87980ctx3",
        redeemer: "d8799f00ff", // present on the result but must be dropped for V3
        datum: "d8799fdatumff",
      }),
    );
    expect(link.ok).toBe(true);
    if (!link.ok) return;
    expect(link.fidelity).toBe("full");
    expect(link.fields).toEqual({
      script: "5350563348",
      v: "v3",
      context: "d87980ctx3",
      exUnits: [0, 0],
      purpose: "Spending #0",
    });
  });

  test("V3 spend WITHOUT datum → still context only (datum optional for V3 spend)", () => {
    const link = fieldsFromEval(
      evalResult({ tag: "Spend", index: 0, version: "V3", script: "aa", context: "ctx", datum: null }),
    );
    expect(link.ok && link.fields).toEqual({
      script: "aa",
      v: "v3",
      context: "ctx",
      exUnits: [0, 0],
      purpose: "Spending #0",
    });
  });

  test("V2 spend → datum + redeemer + context", () => {
    const link = fieldsFromEval(
      evalResult({
        tag: "Spend",
        index: 0,
        version: "V2",
        script: "5350563248",
        context: "ctxv2",
        redeemer: "d8799f01ff",
        datum: "d8799fdatumff",
      }),
    );
    expect(link.ok).toBe(true);
    if (!link.ok) return;
    expect(link.fields).toEqual({
      script: "5350563248",
      v: "v2",
      context: "ctxv2",
      redeemer: "d8799f01ff",
      datum: "d8799fdatumff",
      exUnits: [0, 0],
      purpose: "Spending #0",
    });
  });

  test("V2 mint → redeemer + context, NO datum", () => {
    const link = fieldsFromEval(
      evalResult({ tag: "Mint", index: 0, version: "V2", script: "minthex", context: "mintctx", redeemer: "d8799f00ff", datum: "shouldBeIgnored" }),
    );
    expect(link.ok).toBe(true);
    if (!link.ok) return;
    expect(link.fields).toEqual({
      script: "minthex",
      v: "v2",
      context: "mintctx",
      redeemer: "d8799f00ff",
      exUnits: [0, 0],
      purpose: "Minting #0",
    });
    expect(link.fields.datum).toBeUndefined();
  });

  test("V1 spend without a datum → redeemer + context, no datum", () => {
    const link = fieldsFromEval(
      evalResult({ tag: "Spend", index: 0, version: "V1", script: "v1hex", context: "c", redeemer: "r", datum: null }),
    );
    expect(link.ok && link.fields).toEqual({
      script: "v1hex",
      v: "v1",
      context: "c",
      redeemer: "r",
      exUnits: [0, 0],
      purpose: "Spending #0",
    });
  });
});

describe("fieldsFromEval — exUnits & purpose", () => {
  test("exUnits carries the DECLARED budget as [cpu(steps), mem] — cpu first", () => {
    const link = fieldsFromEval(
      evalResult({
        tag: "Spend",
        index: 0,
        version: "V2",
        script: "aa",
        context: "c",
        redeemer: "r",
        provided: { mem: BigInt(25305), steps: BigInt(8177555) },
      }),
    );
    expect(link.ok && link.fields.exUnits).toEqual([8177555, 25305]);
  });

  test("out-of-range / negative declared units are dropped, not sent as junk", () => {
    const huge = fieldsFromEval(
      evalResult({
        tag: "Spend", index: 0, version: "V2", script: "aa", context: "c", redeemer: "r",
        provided: { mem: BigInt(1), steps: BigInt("18446744073709551615") },
      }),
    );
    expect(huge.ok && huge.fields.exUnits).toBeUndefined();
    const negative = fieldsFromEval(
      evalResult({
        tag: "Spend", index: 0, version: "V2", script: "aa", context: "c", redeemer: "r",
        provided: { mem: BigInt(-1), steps: BigInt(5) },
      }),
    );
    expect(negative.ok && negative.fields.exUnits).toBeUndefined();
  });

  test("purpose maps every RedeemerTag to its display label + index", () => {
    const cases: Array<[string, string]> = [
      ["Spend", "Spending #2"],
      ["Mint", "Minting #2"],
      ["Cert", "Certifying #2"],
      ["Reward", "Rewarding #2"],
      ["Vote", "Voting #2"],
      ["Propose", "Proposing #2"],
    ];
    for (const [tag, expected] of cases) {
      const link = fieldsFromEval(
        evalResult({ tag, index: 2, version: "V3", script: "aa", context: "c" }),
      );
      expect(link.ok && link.fields.purpose).toBe(expected);
    }
  });
});

describe("fieldsFromEval — degraded & failure paths", () => {
  test("null context (eval couldn't build one) → program-only, no context", () => {
    const link = fieldsFromEval(evalResult({ tag: "Spend", index: 0, version: "V3", script: "scripthex", context: null }));
    expect(link.ok).toBe(true);
    if (!link.ok) return;
    expect(link.fidelity).toBe("program-only");
    expect(link.fields).toEqual({
      script: "scripthex",
      v: "v3",
      exUnits: [0, 0],
      purpose: "Spending #0",
    });
  });

  test("missing script bytecode → ok:false", () => {
    const link = fieldsFromEval(evalResult({ tag: "Spend", index: 0, version: "V2", script: null, context: "c" }));
    expect(link.ok).toBe(false);
  });

  test("unknown/absent version → ok:false", () => {
    const link = fieldsFromEval(evalResult({ tag: "Spend", index: 0, version: null, script: "aa", context: "c" }));
    expect(link.ok).toBe(false);
  });
});

describe("URL encoders", () => {
  const fields: DeUplcFields = { script: "abcd", v: "v3", context: "ef01" };

  test("fieldsToPlainUrl uses the hash form with the right params", () => {
    const url = fieldsToPlainUrl(fields, "https://x.test");
    expect(url.startsWith("https://x.test/#")).toBe(true);
    const p = parseHashParams(url);
    expect(p.get("script")).toBe("abcd");
    expect(p.get("v")).toBe("v3");
    expect(p.get("context")).toBe("ef01");
    expect(p.get("redeemer")).toBeNull();
    // No exUnits/purpose on the fields → params absent (no invented budget).
    expect(p.get("exUnits")).toBeNull();
    expect(p.get("purpose")).toBeNull();
  });

  test("fieldsToPlainUrl encodes exUnits as 'cpu,mem' and passes purpose through", () => {
    const url = fieldsToPlainUrl(
      { ...fields, exUnits: [8177555, 25305], purpose: "Spending #0" },
      "https://x.test",
    );
    const p = parseHashParams(url);
    expect(p.get("exUnits")).toBe("8177555,25305");
    expect(p.get("purpose")).toBe("Spending #0");
  });

  test("fieldsToCompressedUrl round-trips to the same fields (gzip)", async () => {
    const big: DeUplcFields = {
      script: "ab".repeat(4000),
      v: "v2",
      context: "cd".repeat(1000),
      redeemer: "d8799f00ff",
      exUnits: [8177555, 25305],
      purpose: "Spending #0",
    };
    const url = await fieldsToCompressedUrl(big, "https://x.test");
    expect(url.startsWith("https://x.test/#d=")).toBe(true);
    const d = parseHashParams(url).get("d")!;
    expect(JSON.parse(await gunzipBase64Url(d))).toEqual(big);
    expect(url.length).toBeLessThan(fieldsToPlainUrl(big, "https://x.test").length);
  });
});

describe("buildAllDeUplcLinks — byEval / byRedeemer mapping", () => {
  test("byEval keyed by tag:index; byRedeemer maps redeemer array index → its eval link", async () => {
    const evals = [
      evalResult({ tag: "Spend", index: 0, version: "V3", script: "s0", context: "c0" }),
      evalResult({ tag: "Mint", index: 0, version: "V2", script: "s1", context: "c1", redeemer: "r1" }),
    ];
    const redeemers = [redeemer("Spend", 0), redeemer("Mint", 0)];
    const maps = await buildAllDeUplcLinks(evals, redeemers, "https://x.test");

    expect(maps.byEval.get("Spend:0")?.ok).toBe(true);
    expect(maps.byEval.get("Mint:0")?.ok).toBe(true);
    const r0 = maps.byRedeemer.get(0);
    const r1 = maps.byRedeemer.get(1);
    expect(r0?.ok && r1?.ok).toBe(true);
    expect(r0?.ok && r0.url).not.toBe(r1?.ok && r1.url); // distinct scripts/contexts → distinct links
  });

  test("decoded-tx 'VotingProposal' tag matches eval 'Propose' (canonicalized)", async () => {
    const evals = [evalResult({ tag: "Propose", index: 0, version: "V3", script: "p", context: "pc" })];
    const maps = await buildAllDeUplcLinks(evals, [redeemer("VotingProposal", 0)], "https://x.test");
    expect(maps.byRedeemer.get(0)?.ok).toBe(true);
    expect(maps.byRedeemer.get(0)).toBe(maps.byEval.get("Propose:0"));
  });
});

describe("decompiler deep-link — not the debugger", () => {
  test("hex only is enough; v/purpose omitted when unknown (Auto)", () => {
    const fields = fieldsFromDecompile({ hex: "46010000200101" });
    expect(fields).toEqual({ script: "46010000200101" });
    const url = fieldsToDecompilePlainUrl(fields!, "https://x.test");
    const p = parseHashParams(url);
    expect(p.get("decompile")).toBe("46010000200101");
    expect(p.get("script")).toBeNull();
    expect(p.get("view")).toBeNull();
    expect(p.get("v")).toBeNull();
    expect(p.get("purpose")).toBeNull();
  });

  test("V2 spend → v=v2&purpose=spend, never Spending / Spending #0", () => {
    const fields = fieldsFromEvalDecompile(
      evalResult({ tag: "Spend", index: 0, version: "V2", script: "5904ac01" }),
    );
    expect(fields).toEqual({ script: "5904ac01", v: "v2", purpose: "spend" });
    const p = parseHashParams(fieldsToDecompilePlainUrl(fields!, "https://x.test"));
    expect(p.get("decompile")).toBe("5904ac01");
    expect(p.get("v")).toBe("v2");
    expect(p.get("purpose")).toBe("spend");
    expect(p.get("script")).toBeNull();
  });

  test("purpose tokens: Cert→certificate, Reward→withdraw; publish/Spending dropped", () => {
    expect(decompilePurpose("Cert")).toBe("certificate");
    expect(decompilePurpose("Reward")).toBe("withdraw");
    expect(decompilePurpose("Vote")).toBe("vote");
    expect(decompilePurpose("Propose")).toBe("propose");
    expect(decompilePurpose("Mint")).toBe("mint");
    expect(decompilePurpose("publish")).toBeUndefined();
    expect(decompilePurpose("Publish")).toBeUndefined();
    expect(decompilePurpose("Spending")).toBeUndefined();
    expect(decompilePurpose("Spending #0")).toBeUndefined();
    expect(decompilePurpose("Certifying")).toBeUndefined();
  });

  test("non-hex / UPLC text is rejected", () => {
    expect(fieldsFromDecompile({ hex: "(program 1.0.0 (con integer 1))" })).toBeNull();
    expect(fieldsFromDecompile({ hex: "not-hex" })).toBeNull();
    expect(fieldsFromDecompile({ hex: "" })).toBeNull();
  });

  test("plutusVersionFromScriptType reads Koios / extractedHashes shapes", () => {
    expect(plutusVersionFromScriptType({ Plutus: "V2" })).toBe("V2");
    expect(plutusVersionFromScriptType("plutusV3")).toBe("plutusV3");
    expect(plutusVersionFromScriptType("Native")).toBeUndefined();
    expect(plutusVersionFromScriptType("timelock")).toBeUndefined();
    expect(fieldsFromDecompile({ hex: "aa", version: plutusVersionFromScriptType({ Plutus: "V1" }) })).toEqual({
      script: "aa",
      v: "v1",
    });
  });

  test("strips 0x and whitespace; PlutusV2 / unknown v", () => {
    expect(fieldsFromDecompile({ hex: "0x4601", version: "PlutusV2" })).toEqual({ script: "4601", v: "v2" });
    expect(fieldsFromDecompile({ hex: "46 01", version: "V3" })).toEqual({ script: "4601", v: "v3" });
    expect(fieldsFromDecompile({ hex: "4601", version: "not-a-version" })).toEqual({ script: "4601" });
  });

  test("hex > 2000 uses #d= with view=decompiler and no debugger fields", async () => {
    const script = "ab".repeat(1001); // 2002 chars
    const url = await fieldsToDecompileUrl(
      { script, v: "v3", purpose: "certificate" },
      "https://x.test",
    );
    expect(url.startsWith("https://x.test/#d=")).toBe(true);
    expect(url.includes("decompile=")).toBe(false);
    const d = parseHashParams(url).get("d")!;
    expect(JSON.parse(await gunzipBase64Url(d))).toEqual({
      view: "decompiler",
      script,
      v: "v3",
      purpose: "certificate",
    });
  });

  test("compressed payload never carries debugger keys", async () => {
    const url = await fieldsToDecompileCompressedUrl(
      { script: "aa", v: "v2", purpose: "mint" },
      "https://x.test",
    );
    const payload = JSON.parse(await gunzipBase64Url(parseHashParams(url).get("d")!)) as Record<string, unknown>;
    expect(payload).toEqual({ view: "decompiler", script: "aa", v: "v2", purpose: "mint" });
    expect(payload).not.toHaveProperty("tx");
    expect(payload).not.toHaveProperty("context");
    expect(payload).not.toHaveProperty("redeemer");
    expect(payload).not.toHaveProperty("datum");
    expect(payload).not.toHaveProperty("exUnits");
  });
});

// ── annotations ──────────────────────────────────────────────────────────────────────────────────

async function payloadOf(url: string): Promise<Record<string, unknown>> {
  const d = parseHashParams(url).get("d");
  expect(d).toBeTruthy();
  return JSON.parse(await gunzipBase64Url(d!));
}

describe("de-uplc links with annotations", () => {
  const ANN: Annotation<DeUplcTarget>[] = [
    { target: { kind: "term", term_id: 12 }, label: "Fails here", hint: "error term", severity: "error" },
    { target: { kind: "uplc_line", line: 3 } },
  ];
  const PSEUDO: Annotation<DeUplcTarget>[] = [
    { target: { kind: "pseudo_line", line: 10, end_line: 14 }, hint: "datum check" },
    { target: { kind: "pseudo_line", line: 20 } },
  ];
  const small: DeUplcFields = { script: "4e4d01000033222220051200120011", v: "v3", context: "d87980" };

  test("a small debugger link stays plain without annotations", async () => {
    expect(await fieldsToUrl(small)).toBe(fieldsToPlainUrl(small));
  });

  test("annotations switch a small debugger link to #d= and travel as ann / ann_focus", async () => {
    const url = await fieldsToUrl({ ...small, annotations: ANN, annotationFocus: 1 });
    expect(url).toContain("/#d=");
    const json = await payloadOf(url);
    expect(json).toEqual({ ...small, ann: ANN, ann_focus: 1 });
    expect(readDeUplcAnnotations(json)).toEqual({ annotations: ANN, annotationFocus: 1 });
  });

  test("the compressed debugger payload never holds the field names, and focus 0 is omitted", async () => {
    const json = await payloadOf(await fieldsToCompressedUrl({ ...small, annotations: ANN, annotationFocus: 0 }));
    expect(json).toEqual({ ...small, ann: ANN });
    expect("annotations" in json).toBe(false);
    expect("annotationFocus" in json).toBe(false);
  });

  test("invalid annotations alone keep a small link plain", async () => {
    const junk = [{ target: { kind: "tx_path", path: "x" } }] as unknown as Annotation<DeUplcTarget>[];
    const fields = { ...small, annotations: junk };
    expect(await fieldsToUrl(fields)).toBe(fieldsToPlainUrl(small));
    expect(fieldsToPlainUrl(fields)).not.toContain("ann");
  });

  test("annotations switch a small decompiler link to #d=", async () => {
    const fields: DecompileFields = { script: "4e4d01", v: "v3", purpose: "spend", annotations: PSEUDO, annotationFocus: 1 };
    const url = await fieldsToDecompileUrl(fields);
    expect(url).toContain("/#d=");
    const json = await payloadOf(url);
    expect(json).toEqual({ view: "decompiler", script: "4e4d01", v: "v3", purpose: "spend", ann: PSEUDO, ann_focus: 1 });
  });

  test("decompiler options switch to #d= and are carried as is", async () => {
    const options = { preset: "readable", inlineLets: false, depth: 3 };
    const url = await fieldsToDecompileUrl({ script: "4e4d01", options, annotations: PSEUDO });
    const json = await payloadOf(url);
    expect(json.options).toEqual(options);
    expect(readDeUplcAnnotations(json)).toEqual({ annotations: PSEUDO, annotationFocus: 0, options });
  });

  test("an empty options object needs no payload", async () => {
    const url = await fieldsToDecompileUrl({ script: "4e4d01", options: {} });
    expect(url).toBe(fieldsToDecompilePlainUrl({ script: "4e4d01" }));
  });

  test("the plain decompiler URL cannot carry options or annotations", () => {
    const url = fieldsToDecompilePlainUrl({ script: "4e4d01", options: { a: 1 }, annotations: PSEUDO });
    expect(url).toBe(fieldsToDecompilePlainUrl({ script: "4e4d01" }));
  });
});

describe("readDeUplcAnnotations", () => {
  test("a payload without annotations has none", () => {
    expect(readDeUplcAnnotations({ script: "00", v: "v3" })).toEqual({ annotations: [], annotationFocus: 0 });
    expect(readDeUplcAnnotations(null)).toEqual({ annotations: [], annotationFocus: 0 });
    expect(readDeUplcAnnotations("ann")).toEqual({ annotations: [], annotationFocus: 0 });
  });

  test("drops unknown kinds and malformed entries, clamps focus, ignores non-object options", () => {
    const out = readDeUplcAnnotations({
      ann: [
        { target: { kind: "term", term_id: 1 } },
        { target: { kind: "cbor_span", offset: 0, length: 1 } },
        { target: { kind: "pseudo_line", line: 5, end_line: 2 } },
        { target: { kind: "uplc_line", line: 9 }, severity: "warning", label: "x".repeat(200) },
      ],
      ann_focus: 50,
      options: ["not", "an", "object"],
    });
    expect(out.annotations.length).toBe(2);
    expect(out.annotations[1]).toEqual({
      target: { kind: "uplc_line", line: 9 },
      severity: "warning",
      label: "x".repeat(80),
    });
    expect(out.annotationFocus).toBe(1);
    expect(out.options).toBeUndefined();
  });
});

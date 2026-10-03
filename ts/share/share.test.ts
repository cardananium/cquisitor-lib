// Share-link codec round trips, run with the node:zlib brotli Compressor. The
// app runs the same suite against its brotli-wasm Compressor; both are brotli,
// so links made by either side parse on the other.

import { beforeAll, describe, expect, test } from "bun:test";
import type { NetworkType } from "@cardananium/cquisitor-lib/wasm";
import type { FetchedValidationData } from "../chain/transactionValidation.js";
import { configure, resetConfig, getCompressor } from "../configure.js";
import { nodeBrotliCompressor } from "../node/compressor.js";
import { MAX_SHARE_PAYLOAD_BYTES } from "../worker/inputBudget.js";
import {
  encodeCardanoCborLink,
  encodeCddlLink,
  encodeGeneralCborLink,
  encodeValidatorLink,
  type BuildLinkOpts,
} from "./encoder.js";
import {
  parseCardanoCborShare,
  parseCddlShare,
  parseGeneralCborShare,
  parseHash,
  parseValidatorShare,
} from "./parser.js";
import { CTX_SCHEMA_VERSION, URL_FORMAT_VERSION } from "./version.js";
import { bytesToText, fromBase64Url, hexToBytes, textToBytes, toBase64Url } from "./base64url.js";
import { MAX_ANNOTATIONS, type Annotation, type CquisitorTarget } from "./annotations.js";

const OPTS: BuildLinkOpts = { origin: "https://example.test", basePath: "/cquisitor" };

/** Stands in for a ~25 KB era schema: many distinct rules, so it is real work for the compressor. */
const BIG_CDDL: string = Array.from({ length: 700 }, (_, i) =>
  `rule_${i} = { ? field_${i}_a: uint, field_${i}_b: tstr, field_${i}_c: [* bstr] }`,
).join("\n");

beforeAll(() => {
  configure({ compressor: nodeBrotliCompressor });
});

/** What every parser returns for a link without annotations. */
const NO_ANNOTATIONS = { annotations: [], annotationFocus: 0 };

const SAMPLE_CBOR = "a3646e616d6565416c69636563616765181e686e69636b6e616d6563416c69";
const SAMPLE_CDDL = `; CDDL schema — edit me.
Person = {
  name: tstr,
  age: uint,
  ? nickname: tstr,
}
`;

/** The query part of a link, read back the way the app reads a location. */
function paramsOf(url: string): URLSearchParams {
  const parsed = parseHash(url.slice(url.indexOf("#")));
  return parsed.params;
}

function tabOf(url: string): string | null {
  return parseHash(url.slice(url.indexOf("#"))).tab;
}

/** Encoder container: BE u32 CBOR length, CBOR bytes, JSON rest. Built here for malformed cases. */
function packContainer(cborHex: string, rest: unknown): Uint8Array {
  const cborBytes = cborHex ? hexToBytes(cborHex) : new Uint8Array(0);
  const jsonBytes = textToBytes(JSON.stringify(rest));
  const out = new Uint8Array(4 + cborBytes.length + jsonBytes.length);
  new DataView(out.buffer).setUint32(0, cborBytes.length, false);
  out.set(cborBytes, 4);
  out.set(jsonBytes, 4 + cborBytes.length);
  return out;
}

/** An uncompressed (`e=j`) rich link carrying exactly `container`. */
function richParams(container: Uint8Array, version = URL_FORMAT_VERSION): URLSearchParams {
  return new URLSearchParams({
    v: String(version),
    e: "j",
    d: toBase64Url(container),
  });
}

// ---------------------------------------------------------------------------
// parseHash
// ---------------------------------------------------------------------------

describe("parseHash", () => {
  test("an empty hash opens the default tab", () => {
    const parsed = parseHash("");
    expect(parsed.tab).toBe("transaction-validator");
    expect([...parsed.params]).toEqual([]);
    expect(parsed.invalidHash).toBeNull();
  });

  test("splits tab from query", () => {
    const parsed = parseHash("#cardano-cbor?cbor=00&net=preview");
    expect(parsed.tab).toBe("cardano-cbor");
    expect(parsed.params.get("cbor")).toBe("00");
    expect(parsed.params.get("net")).toBe("preview");
  });

  test("accepts the cddl-validator tab", () => {
    expect(parseHash("#cddl-validator").tab).toBe("cddl-validator");
    expect(parseHash("#cddl-validator?rule=Person").params.get("rule")).toBe("Person");
  });

  test("reports an unknown tab rather than guessing one", () => {
    const parsed = parseHash("#not-a-tab?cbor=00");
    expect(parsed.tab).toBeNull();
    expect(parsed.invalidHash).toBe("not-a-tab");
    expect([...parsed.params]).toEqual([]);
  });
});

describe("compressor injection", () => {
  test("encoding a compressed link without a registered compressor fails clearly", async () => {
    resetConfig();
    try {
      expect(() => getCompressor()).toThrow(/configure\(\{ compressor \}\)/);
      await expect(
        encodeGeneralCborLink(OPTS, { cbor: SAMPLE_CBOR }, { kind: "compressed" }),
      ).rejects.toThrow(/configure\(/);
      // Uncompressed and minimal links need no compressor at all.
      const url = await encodeGeneralCborLink(OPTS, { cbor: SAMPLE_CBOR }, { kind: "readable" });
      expect(await parseGeneralCborShare(paramsOf(url))).toEqual({ ...NO_ANNOTATIONS, cbor: SAMPLE_CBOR });
    } finally {
      configure({ compressor: nodeBrotliCompressor });
    }
  });

  test("a payload that inflates past the cap is refused, not allocated", async () => {
    const huge = new Uint8Array(MAX_SHARE_PAYLOAD_BYTES + 1024);
    const compressed = await nodeBrotliCompressor.compress(huge);
    expect(compressed.length).toBeLessThan(4096);
    await expect(nodeBrotliCompressor.decompress(compressed, MAX_SHARE_PAYLOAD_BYTES)).rejects.toThrow(
      /expands to more than/,
    );
    const params = new URLSearchParams({ v: String(URL_FORMAT_VERSION), e: "b", d: toBase64Url(compressed) });
    const parsed = await parseGeneralCborShare(params);
    expect(parsed.parseError).toMatch(/expands to more than/);
  });
});

// ---------------------------------------------------------------------------
// CDDL validator round trips
// ---------------------------------------------------------------------------

describe("encodeCddlLink / parseCddlShare", () => {
  const input = { cddl: SAMPLE_CDDL, cbor: SAMPLE_CBOR, rule: "Person" };

  test("compressed round trip", async () => {
    const url = await encodeCddlLink(OPTS, input, { kind: "compressed" });
    expect(tabOf(url)).toBe("cddl-validator");
    const params = paramsOf(url);
    expect(params.get("v")).toBe(String(URL_FORMAT_VERSION));
    expect(params.get("e")).toBe("b");
    // Schema must not appear in the URL if compression worked.
    expect(url).not.toContain("nickname");

    const parsed = await parseCddlShare(params);
    expect(parsed).toEqual({ ...NO_ANNOTATIONS, cddl: SAMPLE_CDDL, cbor: SAMPLE_CBOR, rule: "Person" });
  });

  test("uncompressed round trip", async () => {
    const url = await encodeCddlLink(OPTS, input, { kind: "readable" });
    expect(paramsOf(url).get("e")).toBe("j");
    const parsed = await parseCddlShare(paramsOf(url));
    expect(parsed).toEqual({ ...NO_ANNOTATIONS, cddl: SAMPLE_CDDL, cbor: SAMPLE_CBOR, rule: "Person" });
  });

  test("minimal round trip uses plain params only", async () => {
    const url = await encodeCddlLink(OPTS, input, { kind: "minimal" });
    const params = paramsOf(url);
    expect(params.get("v")).toBeNull();
    expect(params.get("d")).toBeNull();
    expect(params.get("cddl")).toBe(SAMPLE_CDDL);
    expect(params.get("rule")).toBe("Person");
    expect(params.get("cbor")).toBe(SAMPLE_CBOR);

    const parsed = await parseCddlShare(params);
    expect(parsed).toEqual({ ...NO_ANNOTATIONS, cddl: SAMPLE_CDDL, cbor: SAMPLE_CBOR, rule: "Person" });
  });

  test("an empty schema and empty CBOR survive as empty", async () => {
    const url = await encodeCddlLink(
      OPTS,
      { cddl: "", cbor: "", rule: "" },
      { kind: "compressed" },
    );
    const parsed = await parseCddlShare(paramsOf(url));
    expect(parsed.cddl).toBeUndefined();
    expect(parsed.cbor).toBeUndefined();
    expect(parsed.rule).toBeUndefined();
    expect(parsed.parseError).toBeUndefined();
  });

  test("an unedited preset travels as its id, not as the schema text", async () => {
    const url = await encodeCddlLink(
      OPTS,
      { cddl: BIG_CDDL, cbor: SAMPLE_CBOR, rule: "transaction", preset: "conway" },
      { kind: "compressed" },
    );
    expect(url.length).toBeLessThan(512);

    const parsed = await parseCddlShare(paramsOf(url));
    expect(parsed.preset).toBe("conway");
    expect(parsed.cddl).toBeUndefined();
    expect(parsed.rule).toBe("transaction");
    expect(parsed.cbor).toBe(SAMPLE_CBOR);
  });

  test("a preset is a plain param in minimal mode", async () => {
    const url = await encodeCddlLink(
      OPTS,
      { cddl: BIG_CDDL, cbor: SAMPLE_CBOR, rule: "transaction", preset: "conway" },
      { kind: "minimal" },
    );
    const params = paramsOf(url);
    expect(params.get("preset")).toBe("conway");
    expect(params.get("cddl")).toBeNull();
    expect(await parseCddlShare(params)).toEqual({
      ...NO_ANNOTATIONS,
      preset: "conway",
      rule: "transaction",
      cbor: SAMPLE_CBOR,
    });
  });

  test("a full era schema still yields a usable URL", async () => {
    expect(BIG_CDDL.length).toBeGreaterThan(24_000);
    const input24k = { cddl: BIG_CDDL, cbor: SAMPLE_CBOR, rule: "transaction" };

    const compressed = await encodeCddlLink(OPTS, input24k, { kind: "compressed" });
    const readable = await encodeCddlLink(OPTS, input24k, { kind: "readable" });

    // Under typical URL limits; compression must beat uncompressed by a lot.
    expect(compressed.length).toBeLessThan(12_000);
    expect(compressed.length).toBeLessThan(readable.length / 3);

    const parsed = await parseCddlShare(paramsOf(compressed));
    expect(parsed.cddl).toBe(BIG_CDDL);
    expect(parsed.rule).toBe("transaction");
    expect(parsed.cbor).toBe(SAMPLE_CBOR);
  });

  test("plain params win over the same field inside the payload", async () => {
    const url = await encodeCddlLink(OPTS, input, { kind: "compressed" });
    const params = paramsOf(url);
    params.set("rule", "Other");
    params.set("cbor", "00");
    const parsed = await parseCddlShare(params);
    expect(parsed.rule).toBe("Other");
    expect(parsed.cbor).toBe("00");
    expect(parsed.cddl).toBe(SAMPLE_CDDL);
  });
});

// ---------------------------------------------------------------------------
// Parser failure modes
// ---------------------------------------------------------------------------

describe("rich payload failure modes", () => {
  test("a truncated payload is reported, and the plain params still land", async () => {
    const url = await encodeCddlLink(
      OPTS,
      { cddl: SAMPLE_CDDL, cbor: SAMPLE_CBOR, rule: "Person" },
      { kind: "compressed" },
    );
    const params = paramsOf(url);
    params.set("d", params.get("d")!.slice(0, 40));
    params.set("rule", "Person");

    const parsed = await parseCddlShare(params);
    expect(parsed.parseError).toBeTruthy();
    expect(parsed.cddl).toBeUndefined();
    expect(parsed.rule).toBe("Person");
  });

  test("a container with no length header is rejected", async () => {
    const parsed = await parseCddlShare(richParams(new Uint8Array([1, 2, 3])));
    expect(parsed.parseError).toBe("Rich payload too short");
  });

  test("a CBOR length longer than the container is rejected", async () => {
    const container = packContainer(SAMPLE_CBOR, { rule: "Person" });
    new DataView(container.buffer).setUint32(0, 0xffff, false);
    const parsed = await parseCddlShare(richParams(container));
    expect(parsed.parseError).toBe("Rich payload cbor length overflow");
  });

  test("an unknown encoding is rejected rather than guessed at", async () => {
    const params = richParams(packContainer("", {}));
    params.set("e", "x");
    const parsed = await parseCddlShare(params);
    expect(parsed.parseError).toBe("Unsupported encoding: x");
  });

  test("a future format version is flagged, not decoded", async () => {
    const params = richParams(packContainer(SAMPLE_CBOR, { rule: "Person" }), URL_FORMAT_VERSION + 1);
    params.set("cbor", "00");

    const parsed = await parseCddlShare(params);
    expect(parsed.futureVersion).toBe(true);
    expect(parsed.parseError).toBeUndefined();
    expect(parsed.rule).toBeUndefined();
    // Plain params of any version still apply.
    expect(parsed.cbor).toBe("00");
  });

  test("a future format version is flagged on every tab", async () => {
    const container = packContainer(SAMPLE_CBOR, {});
    const params = richParams(container, URL_FORMAT_VERSION + 1);
    expect((await parseValidatorShare(params)).futureVersion).toBe(true);
    expect((await parseCardanoCborShare(params)).futureVersion).toBe(true);
    expect((await parseGeneralCborShare(params)).futureVersion).toBe(true);
  });

  test("a payload for another tab is not read as this one's", async () => {
    const url = await encodeCddlLink(
      OPTS,
      { cddl: SAMPLE_CDDL, cbor: SAMPLE_CBOR, rule: "Person" },
      { kind: "compressed" },
    );
    // Wrong parser: CBOR comes through; CDDL fields do not.
    const parsed = await parseGeneralCborShare(paramsOf(url));
    expect(parsed.cbor).toBe(SAMPLE_CBOR);
    expect(parsed.parseError).toBeUndefined();
    expect(tabOf(url)).toBe("cddl-validator");
  });
});

// ---------------------------------------------------------------------------
// Validation context versioning
// ---------------------------------------------------------------------------

describe("validator share context", () => {
  const ctx = { utxos: [], protocolParams: null } as unknown as FetchedValidationData;

  test("a context of the current schema version round trips", async () => {
    const url = await encodeValidatorLink(
      OPTS,
      { cbor: SAMPLE_CBOR, net: "preprod" as NetworkType, ctx, capturedAt: 1700000000 },
      { kind: "compressed" },
      true,
    );
    const parsed = await parseValidatorShare(paramsOf(url));
    expect(parsed.cbor).toBe(SAMPLE_CBOR);
    expect(parsed.net).toBe("preprod");
    expect(parsed.capturedAt).toBe(1700000000);
    expect(parsed.ctx).toEqual(ctx);
    expect(parsed.ctxIncompatible).toBeUndefined();
  });

  test("a context from another schema version is dropped, not misread", async () => {
    const container = packContainer(SAMPLE_CBOR, {
      ctx_v: CTX_SCHEMA_VERSION + 1,
      net: "mainnet",
      ctx,
    });
    const parsed = await parseValidatorShare(richParams(container));
    expect(parsed.ctxIncompatible).toBe(true);
    expect(parsed.ctx).toBeUndefined();
    // Tx and network survive so a fresh context can be fetched.
    expect(parsed.cbor).toBe(SAMPLE_CBOR);
    expect(parsed.net).toBe("mainnet");
  });

  test("without a context the link stays minimal", async () => {
    const url = await encodeValidatorLink(
      OPTS,
      { cbor: SAMPLE_CBOR, net: "mainnet" as NetworkType },
      { kind: "compressed" },
      true,
    );
    const params = paramsOf(url);
    expect(params.get("d")).toBeNull();
    expect(params.get("cbor")).toBe(SAMPLE_CBOR);

    const parsed = await parseValidatorShare(params);
    expect(parsed).toEqual({ ...NO_ANNOTATIONS, cbor: SAMPLE_CBOR, net: "mainnet" });
  });

  test("declining to include the context downgrades the link", async () => {
    const url = await encodeValidatorLink(
      OPTS,
      { cbor: SAMPLE_CBOR, net: "mainnet" as NetworkType, ctx },
      { kind: "compressed" },
      false,
    );
    expect(paramsOf(url).get("d")).toBeNull();
    expect((await parseValidatorShare(paramsOf(url))).ctx).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// cardano-cbor / general-cbor: shared container round trips
// ---------------------------------------------------------------------------

describe("cardano-cbor and general-cbor round trips", () => {
  test("cardano-cbor compressed round trip", async () => {
    const url = await encodeCardanoCborLink(
      OPTS,
      {
        cbor: SAMPLE_CBOR,
        net: "preview" as NetworkType,
        type: "Transaction",
        psv: 3,
        pds: "DetailedSchema",
      },
      { kind: "compressed" },
    );
    expect(tabOf(url)).toBe("cardano-cbor");
    expect(await parseCardanoCborShare(paramsOf(url))).toEqual({
      ...NO_ANNOTATIONS,
      cbor: SAMPLE_CBOR,
      net: "preview",
      type: "Transaction",
      psv: 3,
      pds: "DetailedSchema",
    });
  });

  test("cardano-cbor minimal abbreviates the plutus data schema", async () => {
    const url = await encodeCardanoCborLink(
      OPTS,
      { cbor: SAMPLE_CBOR, net: "mainnet" as NetworkType, pds: "BasicConversions" },
      { kind: "minimal" },
    );
    expect(paramsOf(url).get("pds")).toBe("b");
    expect((await parseCardanoCborShare(paramsOf(url))).pds).toBe("BasicConversions");
  });

  test("an out-of-range plutus script version is ignored", async () => {
    const params = new URLSearchParams({ cbor: SAMPLE_CBOR, psv: "9" });
    expect((await parseCardanoCborShare(params)).psv).toBeUndefined();
  });

  test("an unknown network is ignored rather than trusted", async () => {
    const params = new URLSearchParams({ cbor: SAMPLE_CBOR, net: "sanchonet" });
    expect((await parseCardanoCborShare(params)).net).toBeUndefined();
  });

  test("general-cbor compressed round trip", async () => {
    const url = await encodeGeneralCborLink(OPTS, { cbor: SAMPLE_CBOR }, { kind: "compressed" });
    expect(tabOf(url)).toBe("general-cbor");
    expect(paramsOf(url).get("e")).toBe("b");
    expect(await parseGeneralCborShare(paramsOf(url))).toEqual({ ...NO_ANNOTATIONS, cbor: SAMPLE_CBOR });
  });
});

// ---------------------------------------------------------------------------
// Annotations
// ---------------------------------------------------------------------------

const ANN: Annotation<CquisitorTarget>[] = [
  { target: { kind: "tx_path", path: "transaction.body.fee" }, label: "Fee", hint: "Too small", severity: "error" },
  { target: { kind: "diagnostic", name: "FeeTooSmall", occurrence: 0 } },
  { target: { kind: "redeemer", tag: "Spend", index: 0 }, severity: "warning" },
  { target: { kind: "cbor_span", offset: 2, length: 4 } },
  { target: { kind: "cbor_path", path: "$.name" }, hint: "line one\nline two" },
  { target: { kind: "cddl_range", start: 0, end: 6 } },
  { target: { kind: "cddl_rule", name: "Person" }, severity: "info" },
];

/** The JSON rest of an uncompressed (`e=j`) link. */
function readableRest(url: string): Record<string, unknown> {
  const container = fromBase64Url(paramsOf(url).get("d")!);
  const cborLen = new DataView(container.buffer, container.byteOffset).getUint32(0, false);
  return JSON.parse(bytesToText(container.subarray(4 + cborLen)));
}

/** A parse result without its annotation fields: what a parser that predates them returns. */
function withoutAnnotations<T extends { annotations: unknown; annotationFocus: unknown }>(parsed: T) {
  const { annotations: _a, annotationFocus: _f, ...rest } = parsed;
  return rest;
}

type Encoder = (mode: ShareLinkModeKind, ann?: Annotation<CquisitorTarget>[], focus?: number) => Promise<string>;
type ShareLinkModeKind = "minimal" | "readable" | "compressed";
type Parser = (params: URLSearchParams) => Promise<{ annotations: Annotation<CquisitorTarget>[]; annotationFocus: number }>;

const ctx = { utxos: [], protocolParams: null } as unknown as FetchedValidationData;

const TABS: { name: string; encode: Encoder; parse: Parser }[] = [
  {
    name: "transaction-validator",
    encode: (kind, annotations, annotationFocus) =>
      encodeValidatorLink(
        OPTS,
        { cbor: SAMPLE_CBOR, net: "preprod" as NetworkType, annotations, annotationFocus },
        { kind },
        true,
      ),
    parse: parseValidatorShare,
  },
  {
    name: "cardano-cbor",
    encode: (kind, annotations, annotationFocus) =>
      encodeCardanoCborLink(
        OPTS,
        { cbor: SAMPLE_CBOR, net: "preview" as NetworkType, type: "Transaction", psv: 2, pds: "BasicConversions", annotations, annotationFocus },
        { kind },
      ),
    parse: parseCardanoCborShare,
  },
  {
    name: "general-cbor",
    encode: (kind, annotations, annotationFocus) =>
      encodeGeneralCborLink(OPTS, { cbor: SAMPLE_CBOR, annotations, annotationFocus }, { kind }),
    parse: parseGeneralCborShare,
  },
  {
    name: "cddl-validator",
    encode: (kind, annotations, annotationFocus) =>
      encodeCddlLink(OPTS, { cddl: SAMPLE_CDDL, cbor: SAMPLE_CBOR, rule: "Person", annotations, annotationFocus }, { kind }),
    parse: parseCddlShare,
  },
];

for (const tab of TABS) {
  describe(`${tab.name} annotations`, () => {
    for (const kind of ["readable", "compressed"] as const) {
      test(`${kind} round trip`, async () => {
        const url = await tab.encode(kind, ANN, 3);
        expect(paramsOf(url).get("e")).toBe(kind === "compressed" ? "b" : "j");
        const parsed = await tab.parse(paramsOf(url));
        expect(parsed.annotations).toEqual(ANN);
        expect(parsed.annotationFocus).toBe(3);
        expect(parsed).not.toHaveProperty("parseError");
      });
    }

    test("readable links write ann / ann_focus into the JSON rest", async () => {
      const rest = readableRest(await tab.encode("readable", ANN, 2));
      expect(rest.ann).toEqual(ANN);
      expect(rest.ann_focus).toBe(2);
      const noFocus = readableRest(await tab.encode("readable", ANN));
      expect(noFocus.ann).toEqual(ANN);
      expect("ann_focus" in noFocus).toBe(false);
    });

    test("a minimal request with annotations becomes compressed when a compressor is configured", async () => {
      const url = await tab.encode("minimal", ANN);
      const params = paramsOf(url);
      expect(params.get("v")).toBe(String(URL_FORMAT_VERSION));
      expect(params.get("e")).toBe("b");
      expect((await tab.parse(params)).annotations).toEqual(ANN);
    });

    test("a minimal request with annotations becomes readable without a compressor", async () => {
      resetConfig();
      try {
        const url = await tab.encode("minimal", ANN, 1);
        expect(paramsOf(url).get("e")).toBe("j");
        const parsed = await tab.parse(paramsOf(url));
        expect(parsed.annotations).toEqual(ANN);
        expect(parsed.annotationFocus).toBe(1);
      } finally {
        configure({ compressor: nodeBrotliCompressor });
      }
    });

    test("annotations that are all invalid leave a minimal link minimal", async () => {
      const junk = [{ target: { kind: "nope" } }] as unknown as Annotation<CquisitorTarget>[];
      const url = await tab.encode("minimal", junk);
      expect(paramsOf(url).get("d")).toBeNull();
      expect(await tab.parse(paramsOf(url))).toMatchObject(NO_ANNOTATIONS);
    });

    test("invalid entries are dropped before encoding, focus follows its entry", async () => {
      const mixed = [
        ANN[0],
        { target: { kind: "nope" } },
        ANN[1],
      ] as unknown as Annotation<CquisitorTarget>[];
      const parsed = await tab.parse(paramsOf(await tab.encode("readable", mixed, 2)));
      expect(parsed.annotations).toEqual([ANN[0], ANN[1]]);
      expect(parsed.annotationFocus).toBe(1);
    });

    test("annotations do not change the other parsed fields", async () => {
      for (const kind of ["readable", "compressed"] as const) {
        const plain = await tab.parse(paramsOf(await tab.encode(kind)));
        const annotated = await tab.parse(paramsOf(await tab.encode(kind, ANN, 1)));
        expect(withoutAnnotations(annotated)).toEqual(withoutAnnotations(plain));
      }
    });
  });
}

describe("annotations read from hand-made payloads", () => {
  test("unknown kinds and malformed entries are skipped, the link still opens", async () => {
    const container = packContainer(SAMPLE_CBOR, {
      rule: "Person",
      ann: [
        { target: { kind: "from_the_future", x: 1 }, label: "later" },
        "garbage",
        { target: { kind: "cddl_rule", name: "Person" }, label: "Person" },
        { target: { kind: "cbor_span", offset: "0", length: 1 } },
      ],
      ann_focus: 2,
    });
    const parsed = await parseCddlShare(richParams(container));
    expect(parsed.parseError).toBeUndefined();
    expect(parsed.rule).toBe("Person");
    expect(parsed.cbor).toBe(SAMPLE_CBOR);
    expect(parsed.annotations).toEqual([{ target: { kind: "cddl_rule", name: "Person" }, label: "Person" }]);
    expect(parsed.annotationFocus).toBe(0);
  });

  test("a non-array ann is ignored", async () => {
    const parsed = await parseGeneralCborShare(richParams(packContainer(SAMPLE_CBOR, { ann: { kind: "tx_path" } })));
    expect(parsed).toEqual({ ...NO_ANNOTATIONS, cbor: SAMPLE_CBOR });
  });

  test("focus past the end clamps to the last annotation", async () => {
    const container = packContainer(SAMPLE_CBOR, {
      ann: [{ target: { kind: "cbor_path", path: "$" } }, { target: { kind: "cbor_path", path: "$[0]" } }],
      ann_focus: 40,
    });
    expect((await parseGeneralCborShare(richParams(container))).annotationFocus).toBe(1);
  });

  test("at most MAX_ANNOTATIONS are read", async () => {
    const ann = Array.from({ length: MAX_ANNOTATIONS + 5 }, (_, i) => ({
      target: { kind: "cbor_span", offset: i, length: 1 },
    }));
    const url = await encodeGeneralCborLink(
      OPTS,
      { cbor: SAMPLE_CBOR, annotations: ann as Annotation<CquisitorTarget>[] },
      { kind: "compressed" },
    );
    expect((await parseGeneralCborShare(paramsOf(url))).annotations.length).toBe(MAX_ANNOTATIONS);
  });

  test("a future format version yields no annotations", async () => {
    const container = packContainer(SAMPLE_CBOR, { ann: [{ target: { kind: "cddl_rule", name: "a" } }] });
    const parsed = await parseCddlShare(richParams(container, URL_FORMAT_VERSION + 1));
    expect(parsed.futureVersion).toBe(true);
    expect(parsed.annotations).toEqual([]);
  });
});

describe("validator links with annotations", () => {
  test("annotations alone make the link rich; the context travels only with includeCtx", async () => {
    const withCtx = { cbor: SAMPLE_CBOR, net: "mainnet" as NetworkType, ctx, capturedAt: 1700000000, annotations: ANN };
    const excluded = await encodeValidatorLink(OPTS, withCtx, { kind: "readable" }, false);
    const rest = readableRest(excluded);
    expect(rest.ctx).toBeUndefined();
    expect(rest.capturedAt).toBeUndefined();
    expect(rest.ann).toEqual(ANN);
    const parsedExcluded = await parseValidatorShare(paramsOf(excluded));
    expect(parsedExcluded.ctx).toBeUndefined();
    expect(parsedExcluded.annotations).toEqual(ANN);

    const included = await parseValidatorShare(
      paramsOf(await encodeValidatorLink(OPTS, withCtx, { kind: "compressed" }, true)),
    );
    expect(included.ctx).toEqual(ctx);
    expect(included.capturedAt).toBe(1700000000);
    expect(included.annotations).toEqual(ANN);
  });

  test("a minimal request keeps the context out even with includeCtx", async () => {
    const url = await encodeValidatorLink(
      OPTS,
      { cbor: SAMPLE_CBOR, net: "mainnet" as NetworkType, ctx, annotations: ANN },
      { kind: "minimal" },
      true,
    );
    const params = paramsOf(url);
    expect(params.get("e")).toBe("b");
    expect(params.get("cbor")).toBe(SAMPLE_CBOR);
    const parsed = await parseValidatorShare(params);
    expect(parsed.ctx).toBeUndefined();
    expect(parsed.annotations).toEqual(ANN);
  });

  test("the plain cbor / net params stay next to the payload", async () => {
    const url = await encodeValidatorLink(
      OPTS,
      { cbor: SAMPLE_CBOR, net: "preview" as NetworkType, annotations: ANN },
      { kind: "readable" },
      false,
    );
    const params = paramsOf(url);
    expect(params.get("cbor")).toBe(SAMPLE_CBOR);
    expect(params.get("net")).toBe("preview");
    expect(readableRest(url).ctx_v).toBe(CTX_SCHEMA_VERSION);
  });
});

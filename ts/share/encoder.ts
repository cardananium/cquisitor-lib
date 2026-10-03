import type { PlutusDataSchema } from "@cardananium/cquisitor-lib/wasm";
import { getCompressor, isCompressorConfigured } from "../configure.js";
import { URL_FORMAT_VERSION, CTX_SCHEMA_VERSION } from "./version.js";
import { toBase64Url, textToBytes, hexToBytes } from "./base64url.js";
import { stringifyShareJson } from "./bigintJson.js";
import { annotationPayload, isCquisitorTarget } from "./annotations.js";
import type {
  ShareLinkMode,
  ValidatorShareInput,
  CardanoCborShareInput,
  GeneralCborShareInput,
  CddlShareInput,
  ShareAnnotationsInput,
} from "./types.js";

/**
 * Where a link points: `${origin}${basePath}/#tab?...`. The app derives this
 * from `window.location`; a server passes the deployed origin explicitly.
 */
export interface BuildLinkOpts {
  origin: string;
  basePath: string;
}

function appendParam(
  parts: string[],
  key: string,
  value: string | number | null | undefined
) {
  if (value === null || value === undefined || value === "") return;
  parts.push(`${key}=${encodeURIComponent(String(value))}`);
}

function packContainer(cborHex: string, rest: unknown): Uint8Array {
  const cborBytes = cborHex ? hexToBytes(cborHex) : new Uint8Array(0);
  const jsonBytes = textToBytes(stringifyShareJson(rest));
  const out = new Uint8Array(4 + cborBytes.length + jsonBytes.length);
  const view = new DataView(out.buffer);
  view.setUint32(0, cborBytes.length, false);
  out.set(cborBytes, 4);
  out.set(jsonBytes, 4 + cborBytes.length);
  return out;
}

async function encodeRichData(
  cborHex: string,
  rest: unknown,
  encoding: "j" | "b"
): Promise<string> {
  const container = packContainer(cborHex, rest);
  if (encoding === "j") return toBase64Url(container);
  // `e=b` payloads are brotli; the host registers the implementation (configure({ compressor })).
  const compressed = await getCompressor().compress(container);
  return toBase64Url(compressed);
}

function annotationFields(input: ShareAnnotationsInput) {
  return annotationPayload(input.annotations, input.annotationFocus, isCquisitorTarget);
}

/**
 * The rich encoding for `mode`, or null for a minimal link. Annotations need the rich
 * payload, so with annotations a minimal request is upgraded: `b` when a compressor is
 * configured, `j` otherwise.
 */
function richEncoding(mode: ShareLinkMode, hasAnnotations: boolean): "j" | "b" | null {
  if (mode.kind === "compressed") return "b";
  if (mode.kind === "readable") return "j";
  if (!hasAnnotations) return null;
  return isCompressorConfigured() ? "b" : "j";
}

async function pushRichParams(
  parts: string[],
  cborHex: string,
  rest: unknown,
  encoding: "j" | "b"
): Promise<void> {
  const data = await encodeRichData(cborHex, rest, encoding);
  parts.push(`v=${URL_FORMAT_VERSION}`);
  parts.push(`e=${encoding}`);
  parts.push(`d=${data}`);
}

function pdsShort(pds: PlutusDataSchema | null | undefined): string | undefined {
  if (pds === "BasicConversions") return "b";
  if (pds === "DetailedSchema") return "d";
  return undefined;
}

function buildUrl(opts: BuildLinkOpts, tab: string, params: string[]): string {
  const query = params.length > 0 ? `?${params.join("&")}` : "";
  return `${opts.origin}${opts.basePath}/#${tab}${query}`;
}

/**
 * Encode transaction validator state. The link is rich when the validation context is
 * included (`includeCtx`, a context present, mode not minimal) or annotations are
 * present; otherwise it is minimal. The context travels only in the first case.
 */
export async function encodeValidatorLink(
  opts: BuildLinkOpts,
  input: ValidatorShareInput,
  mode: ShareLinkMode,
  includeCtx: boolean
): Promise<string> {
  const parts: string[] = [];
  const hasCtx = includeCtx && !!input.ctx && mode.kind !== "minimal";
  const ann = annotationFields(input);
  const hasAnnotations = ann.ann !== undefined;
  const encoding = hasCtx || hasAnnotations ? richEncoding(mode, hasAnnotations) : null;

  if (encoding) {
    const rest = {
      ctx_v: CTX_SCHEMA_VERSION,
      net: input.net,
      capturedAt: hasCtx ? input.capturedAt : undefined,
      ctx: hasCtx ? input.ctx : undefined,
      ...ann,
    };
    await pushRichParams(parts, input.cbor, rest, encoding);
  }
  appendParam(parts, "cbor", input.cbor);
  appendParam(parts, "net", input.net);

  return buildUrl(opts, "transaction-validator", parts);
}

export async function encodeCardanoCborLink(
  opts: BuildLinkOpts,
  input: CardanoCborShareInput,
  mode: ShareLinkMode
): Promise<string> {
  const parts: string[] = [];
  const ann = annotationFields(input);
  const encoding = richEncoding(mode, ann.ann !== undefined);

  if (encoding) {
    const rest = {
      net: input.net,
      type: input.type ?? undefined,
      psv: input.psv ?? undefined,
      pds: input.pds ?? undefined,
      ...ann,
    };
    await pushRichParams(parts, input.cbor, rest, encoding);
  } else {
    appendParam(parts, "cbor", input.cbor);
    appendParam(parts, "net", input.net);
    appendParam(parts, "type", input.type ?? undefined);
    appendParam(parts, "psv", input.psv ?? undefined);
    appendParam(parts, "pds", pdsShort(input.pds));
  }

  return buildUrl(opts, "cardano-cbor", parts);
}

export async function encodeGeneralCborLink(
  opts: BuildLinkOpts,
  input: GeneralCborShareInput,
  mode: ShareLinkMode
): Promise<string> {
  const parts: string[] = [];
  const ann = annotationFields(input);
  const encoding = richEncoding(mode, ann.ann !== undefined);

  if (encoding) {
    await pushRichParams(parts, input.cbor, { ...ann }, encoding);
  } else {
    appendParam(parts, "cbor", input.cbor);
  }

  return buildUrl(opts, "general-cbor", parts);
}

/**
 * Encode CDDL validator state. Compressed is the practical mode; minimal still works for a
 * preset name (and is upgraded to a rich link when annotations are present).
 */
export async function encodeCddlLink(
  opts: BuildLinkOpts,
  input: CddlShareInput,
  mode: ShareLinkMode
): Promise<string> {
  const parts: string[] = [];
  const preset = input.preset || undefined;
  const ann = annotationFields(input);
  const encoding = richEncoding(mode, ann.ann !== undefined);

  if (!encoding) {
    // Minimal: preset id, or the full schema text if there is no preset.
    if (preset) appendParam(parts, "preset", preset);
    else appendParam(parts, "cddl", input.cddl);
    appendParam(parts, "rule", input.rule);
    appendParam(parts, "cbor", input.cbor);
  } else {
    const rest = {
      preset,
      cddl: preset ? undefined : input.cddl || undefined,
      rule: input.rule || undefined,
      ...ann,
    };
    await pushRichParams(parts, input.cbor, rest, encoding);
  }

  return buildUrl(opts, "cddl-validator", parts);
}

// Share-link codec: `#tab?v=1&e=j|b&d=<base64url(container)>` plus plain params.
// Container = BE u32 CBOR length + CBOR bytes + JSON rest (bigint as {"$bi":"…"}).
// Compression (`e=b`, brotli) is host-provided: see configure({ compressor }).

export { URL_FORMAT_VERSION, CTX_SCHEMA_VERSION } from "./version.js";
export {
  encodeValidatorLink,
  encodeCardanoCborLink,
  encodeGeneralCborLink,
  encodeCddlLink,
} from "./encoder.js";
export type { BuildLinkOpts } from "./encoder.js";
export {
  parseHash,
  parseValidatorShare,
  parseCardanoCborShare,
  parseGeneralCborShare,
  parseCddlShare,
} from "./parser.js";
export type { ParsedHash } from "./parser.js";
export type {
  TabId,
  ShareLinkMode,
  ValidatorShareInput,
  CardanoCborShareInput,
  GeneralCborShareInput,
  CddlShareInput,
  ValidatorRichPayloadV1,
  ParsedValidatorShare,
  ParsedCardanoCborShare,
  ParsedGeneralCborShare,
  ParsedCddlShare,
} from "./types.js";
export { toBase64Url, fromBase64Url, textToBytes, bytesToText, hexToBytes, bytesToHex } from "./base64url.js";
export { stringifyShareJson, parseShareJson } from "./bigintJson.js";

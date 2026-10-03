import type { NetworkType, PlutusDataSchema } from "@cardananium/cquisitor-lib/wasm";
import type { FetchedValidationData } from "../chain/transactionValidation.js";
import type { Annotation, CquisitorTarget } from "./annotations.js";

export type TabId = "transaction-validator" | "cardano-cbor" | "general-cbor" | "cddl-validator";

/**
 * Annotations a share link carries (any tab). Non-empty annotations always produce a rich
 * link (`v=1&e=j|b&d=…`, written as `ann` / `ann_focus` in the payload's JSON): a
 * `minimal` mode request becomes `compressed` (`e=b`) when a compressor is configured and
 * `readable` (`e=j`) otherwise. Invalid entries are dropped before encoding.
 */
export interface ShareAnnotationsInput {
  annotations?: Annotation<CquisitorTarget>[];
  /** Index of the annotation to focus first; 0 when absent. */
  annotationFocus?: number;
}

/** Annotations read from a share link: validated, at most MAX_ANNOTATIONS, empty when absent. */
export interface ParsedShareAnnotations {
  annotations: Annotation<CquisitorTarget>[];
  /** Index into `annotations`, clamped to the list; 0 when absent or empty. */
  annotationFocus: number;
}

export type ShareLinkMode =
  | { kind: "minimal" }
  | { kind: "readable" }
  | { kind: "compressed" };

export interface ValidatorShareInput extends ShareAnnotationsInput {
  cbor: string;
  net: NetworkType;
  ctx?: FetchedValidationData;
  capturedAt?: number;
}

export interface CardanoCborShareInput extends ShareAnnotationsInput {
  cbor: string;
  net: NetworkType;
  type?: string | null;
  psv?: number | null;
  pds?: PlutusDataSchema | null;
}

export interface GeneralCborShareInput extends ShareAnnotationsInput {
  cbor: string;
}

export interface CddlShareInput extends ShareAnnotationsInput {
  /** The schema text. Ignored when `preset` names one. */
  cddl: string;
  /** Whole-byte hex — the container stores CBOR as bytes. */
  cbor: string;
  rule: string;
  /** Era id when the editor holds that preset verbatim; names the era instead of ~25 KB of text. */
  preset?: string | null;
}

export interface ValidatorRichPayloadV1 {
  ctx_v: number;
  cbor: string;
  net: NetworkType;
  capturedAt?: number;
  ctx?: FetchedValidationData;
  ann?: Annotation<CquisitorTarget>[];
  ann_focus?: number;
}

export interface ParsedValidatorShare extends ParsedShareAnnotations {
  cbor?: string;
  net?: NetworkType;
  ctx?: FetchedValidationData;
  capturedAt?: number;
  ctxIncompatible?: boolean;
  futureVersion?: boolean;
  parseError?: string;
}

export interface ParsedCardanoCborShare extends ParsedShareAnnotations {
  cbor?: string;
  net?: NetworkType;
  type?: string;
  psv?: number;
  pds?: PlutusDataSchema;
  futureVersion?: boolean;
  parseError?: string;
}

export interface ParsedGeneralCborShare extends ParsedShareAnnotations {
  cbor?: string;
  futureVersion?: boolean;
  parseError?: string;
}

export interface ParsedCddlShare extends ParsedShareAnnotations {
  cddl?: string;
  cbor?: string;
  rule?: string;
  /** Era id; still needs resolving to schema text. */
  preset?: string;
  futureVersion?: boolean;
  parseError?: string;
}

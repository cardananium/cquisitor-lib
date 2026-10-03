// UI annotations carried by deep links into cquisitor and de-uplc-web: targets to
// highlight persistently, each with an optional hint. Links carry them as
// `ann: Annotation[]` plus an optional `ann_focus` index. Unknown target kinds
// and malformed entries are dropped on read, never fatal.

export type AnnotationSeverity = "error" | "warning" | "info";

export interface Annotation<T> {
  target: T;
  /** Short title shown in the hint card and the navigator (at most MAX_ANNOTATION_LABEL chars). */
  label?: string;
  /** Hint text: plain text, newlines allowed (at most MAX_ANNOTATION_HINT chars). */
  hint?: string;
  /** Rendered as "info" when absent. */
  severity?: AnnotationSeverity;
}

/** A link carries at most this many annotations; entries past it are ignored. */
export const MAX_ANNOTATIONS = 64;
export const MAX_ANNOTATION_LABEL = 80;
export const MAX_ANNOTATION_HINT = 2000;

/** Targets inside the cquisitor app. Indices and offsets are non-negative integers. */
export type CquisitorTarget =
  /** Dotted validator location as in `ValidationPhase1Error.locations`, e.g. `transaction.body.outputs.0`. */
  | { kind: "tx_path"; path: string }
  /**
   * An entry of the diagnostics list (phase-1 errors, phase-2 errors, phase-1 warnings,
   * phase-2 warnings, in that order), by position or by name. `occurrence` (0-based)
   * picks among entries sharing the name.
   */
  | { kind: "diagnostic"; index: number }
  | { kind: "diagnostic"; name: string; occurrence?: number }
  /** A row of the Plutus results, e.g. `Spend[0]` is `{ tag: "Spend", index: 0 }`. */
  | { kind: "redeemer"; tag: string; index: number }
  /** Byte range of the hex input (general-cbor, cddl-validator); `length` is at least 1. */
  | { kind: "cbor_span"; offset: number; length: number }
  /** A CBOR path in the lib's path grammar (`$`, `.ident`, `[n]`, `["str"]`, ...). */
  | { kind: "cbor_path"; path: string }
  /** `[start, end)` character range of the CDDL schema text; `end > start`. */
  | { kind: "cddl_range"; start: number; end: number }
  /** The definition of a CDDL rule. */
  | { kind: "cddl_rule"; name: string };

/** Targets inside de-uplc-web. Lines are 1-based. */
export type DeUplcTarget =
  /** Normalised term id: `uniq_id - base`, base = smallest term uniq id of the loaded program. */
  | { kind: "term"; term_id: number }
  /** Line of the canonical one-term-per-line UPLC listing. */
  | { kind: "uplc_line"; line: number }
  /** Line range of the decompiled output (made with the link's decompiler options); `end_line >= line`. */
  | { kind: "pseudo_line"; line: number; end_line?: number };

export type AnnotationTargetGuard<T> = (value: unknown) => value is T;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isIndex(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isLine(value: unknown): value is number {
  return isIndex(value) && value >= 1;
}

function isText(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

/**
 * True for a well-formed cquisitor target. Every field the kind defines must have its
 * type when present; a `diagnostic` carries `index` or `name`, and `index` wins when
 * both are present. Fields the kind does not define are ignored.
 */
export function isCquisitorTarget(value: unknown): value is CquisitorTarget {
  if (!isRecord(value)) return false;
  switch (value.kind) {
    case "tx_path":
    case "cbor_path":
      return isText(value.path);
    case "diagnostic":
      if (value.index !== undefined) return isIndex(value.index);
      return isText(value.name) && (value.occurrence === undefined || isIndex(value.occurrence));
    case "redeemer":
      return isText(value.tag) && isIndex(value.index);
    case "cbor_span":
      return isIndex(value.offset) && isIndex(value.length) && value.length >= 1;
    case "cddl_range":
      return isIndex(value.start) && isIndex(value.end) && value.end > value.start;
    case "cddl_rule":
      return isText(value.name);
    default:
      return false;
  }
}

/** True for a well-formed de-uplc-web target. Fields the kind does not define are ignored. */
export function isDeUplcTarget(value: unknown): value is DeUplcTarget {
  if (!isRecord(value)) return false;
  switch (value.kind) {
    case "term":
      return isIndex(value.term_id);
    case "uplc_line":
      return isLine(value.line);
    case "pseudo_line":
      return (
        isLine(value.line) &&
        (value.end_line === undefined || (isLine(value.end_line) && value.end_line >= value.line))
      );
    default:
      return false;
  }
}

/** The kind's own fields only, so a link never carries (or passes on) anything else. */
function canonicalTarget(target: Record<string, unknown>): Record<string, unknown> {
  switch (target.kind) {
    case "tx_path":
    case "cbor_path":
      return { kind: target.kind, path: target.path };
    case "diagnostic":
      if (target.index !== undefined) return { kind: "diagnostic", index: target.index };
      return target.occurrence === undefined
        ? { kind: "diagnostic", name: target.name }
        : { kind: "diagnostic", name: target.name, occurrence: target.occurrence };
    case "redeemer":
      return { kind: "redeemer", tag: target.tag, index: target.index };
    case "cbor_span":
      return { kind: "cbor_span", offset: target.offset, length: target.length };
    case "cddl_range":
      return { kind: "cddl_range", start: target.start, end: target.end };
    case "cddl_rule":
      return { kind: "cddl_rule", name: target.name };
    case "term":
      return { kind: "term", term_id: target.term_id };
    case "uplc_line":
      return { kind: "uplc_line", line: target.line };
    case "pseudo_line":
      return target.end_line === undefined
        ? { kind: "pseudo_line", line: target.line }
        : { kind: "pseudo_line", line: target.line, end_line: target.end_line };
    default:
      return { ...target };
  }
}

/** At most `max` UTF-16 code units, never splitting a surrogate pair. */
function truncate(text: string, max: number): string {
  if (text.length <= max) return text;
  let end = max;
  const last = text.charCodeAt(end - 1);
  if (last >= 0xd800 && last <= 0xdbff) end -= 1;
  return text.slice(0, end);
}

const SEVERITIES: ReadonlySet<string> = new Set<AnnotationSeverity>(["error", "warning", "info"]);

function normalizeOne<T>(raw: unknown, isTarget: AnnotationTargetGuard<T>): Annotation<T> | null {
  if (!isRecord(raw)) return null;
  if (!isTarget(raw.target)) return null;
  if (raw.label !== undefined && typeof raw.label !== "string") return null;
  if (raw.hint !== undefined && typeof raw.hint !== "string") return null;
  if (raw.severity !== undefined && !(typeof raw.severity === "string" && SEVERITIES.has(raw.severity))) {
    return null;
  }
  const out: Annotation<T> = { target: canonicalTarget(raw.target as Record<string, unknown>) as T };
  if (raw.label) out.label = truncate(raw.label, MAX_ANNOTATION_LABEL);
  if (raw.hint) out.hint = truncate(raw.hint, MAX_ANNOTATION_HINT);
  if (raw.severity !== undefined) out.severity = raw.severity as AnnotationSeverity;
  return out;
}

export interface NormalizedAnnotations<T> {
  annotations: Annotation<T>[];
  /** Index into `annotations`; 0 when there are none. */
  annotationFocus: number;
}

/**
 * Validate an `ann` array together with its `ann_focus`.
 *
 * Only the first MAX_ANNOTATIONS entries are read. An entry is dropped when it is not
 * an object, its target fails `isTarget` (unknown kind or malformed fields), `label` /
 * `hint` is not a string, or `severity` is not one of the three values. Kept entries
 * hold the target's own fields only; `label` / `hint` are truncated to their limits and
 * empty ones are omitted; an absent `severity` stays absent.
 *
 * `rawFocus` indexes the raw array. It is mapped onto the kept entries: a dropped
 * focused entry moves focus to the next kept one (or the last kept one); anything that
 * is not a non-negative integer is 0; past the end it clamps to the last entry.
 */
export function normalizeAnnotationList<T>(
  raw: unknown,
  rawFocus: unknown,
  isTarget: AnnotationTargetGuard<T>,
): NormalizedAnnotations<T> {
  if (!Array.isArray(raw)) return { annotations: [], annotationFocus: 0 };
  const focus = isIndex(rawFocus) ? rawFocus : 0;
  const annotations: Annotation<T>[] = [];
  let annotationFocus = -1;
  const limit = Math.min(raw.length, MAX_ANNOTATIONS);
  for (let i = 0; i < limit; i++) {
    const entry = normalizeOne(raw[i], isTarget);
    if (!entry) continue;
    if (annotationFocus < 0 && i >= focus) annotationFocus = annotations.length;
    annotations.push(entry);
  }
  if (annotations.length === 0) return { annotations, annotationFocus: 0 };
  if (annotationFocus < 0) annotationFocus = annotations.length - 1;
  return { annotations, annotationFocus };
}

/** `normalizeAnnotationList` without a focus: the validated, capped annotations. */
export function normalizeAnnotations<T>(raw: unknown, isTarget: AnnotationTargetGuard<T>): Annotation<T>[] {
  return normalizeAnnotationList(raw, 0, isTarget).annotations;
}

/**
 * The `ann` / `ann_focus` fields a link payload gets, validated as `normalizeAnnotationList`
 * does: none when no annotation survives, `ann_focus` only when it is not 0.
 */
export function annotationPayload<T>(
  annotations: readonly Annotation<T>[] | null | undefined,
  focus: number | null | undefined,
  isTarget: AnnotationTargetGuard<T>,
): { ann?: Annotation<T>[]; ann_focus?: number } {
  const { annotations: ann, annotationFocus } = normalizeAnnotationList(annotations, focus, isTarget);
  if (ann.length === 0) return {};
  return annotationFocus === 0 ? { ann } : { ann, ann_focus: annotationFocus };
}

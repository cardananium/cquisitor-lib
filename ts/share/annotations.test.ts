import { describe, expect, test } from "bun:test";
import {
  MAX_ANNOTATIONS,
  MAX_ANNOTATION_HINT,
  MAX_ANNOTATION_LABEL,
  annotationPayload,
  isCquisitorTarget,
  isDeUplcTarget,
  normalizeAnnotationList,
  normalizeAnnotations,
  type Annotation,
  type CquisitorTarget,
} from "./annotations.js";

describe("isCquisitorTarget", () => {
  test("accepts every kind with its fields", () => {
    const ok: unknown[] = [
      { kind: "tx_path", path: "transaction.body.outputs.0" },
      { kind: "diagnostic", index: 0 },
      { kind: "diagnostic", name: "FeeTooSmall" },
      { kind: "diagnostic", name: "FeeTooSmall", occurrence: 2 },
      { kind: "redeemer", tag: "Spend", index: 0 },
      { kind: "cbor_span", offset: 0, length: 1 },
      { kind: "cbor_path", path: "$[0].ident" },
      { kind: "cddl_range", start: 3, end: 10 },
      { kind: "cddl_rule", name: "transaction" },
    ];
    for (const t of ok) expect(isCquisitorTarget(t)).toBe(true);
  });

  test("rejects unknown kinds, missing or mistyped fields", () => {
    const bad: unknown[] = [
      null,
      "tx_path",
      [],
      { kind: "future_kind", path: "x" },
      { kind: "term", term_id: 1 },
      { kind: "tx_path" },
      { kind: "tx_path", path: "" },
      { kind: "tx_path", path: 7 },
      { kind: "diagnostic" },
      { kind: "diagnostic", index: -1 },
      { kind: "diagnostic", index: 1.5 },
      { kind: "diagnostic", index: "0" },
      { kind: "diagnostic", name: "X", occurrence: -1 },
      { kind: "redeemer", tag: "Spend" },
      { kind: "redeemer", index: 0 },
      { kind: "cbor_span", offset: 0, length: 0 },
      { kind: "cbor_span", offset: -1, length: 2 },
      { kind: "cddl_range", start: 5, end: 5 },
      { kind: "cddl_range", start: 6, end: 5 },
      { kind: "cddl_rule", name: "" },
    ];
    for (const t of bad) expect(isCquisitorTarget(t)).toBe(false);
  });
});

describe("isDeUplcTarget", () => {
  test("accepts every kind with its fields", () => {
    expect(isDeUplcTarget({ kind: "term", term_id: 0 })).toBe(true);
    expect(isDeUplcTarget({ kind: "uplc_line", line: 1 })).toBe(true);
    expect(isDeUplcTarget({ kind: "pseudo_line", line: 4 })).toBe(true);
    expect(isDeUplcTarget({ kind: "pseudo_line", line: 4, end_line: 4 })).toBe(true);
  });

  test("rejects unknown kinds and bad lines", () => {
    expect(isDeUplcTarget({ kind: "tx_path", path: "x" })).toBe(false);
    expect(isDeUplcTarget({ kind: "term", term_id: -1 })).toBe(false);
    expect(isDeUplcTarget({ kind: "uplc_line", line: 0 })).toBe(false);
    expect(isDeUplcTarget({ kind: "pseudo_line", line: 4, end_line: 3 })).toBe(false);
    expect(isDeUplcTarget({ kind: "pseudo_line", line: 4, end_line: "5" })).toBe(false);
  });
});

describe("normalizeAnnotations", () => {
  test("a non-array is no annotations", () => {
    expect(normalizeAnnotations(undefined, isCquisitorTarget)).toEqual([]);
    expect(normalizeAnnotations({ target: { kind: "tx_path", path: "a" } }, isCquisitorTarget)).toEqual([]);
    expect(normalizeAnnotations("[]", isCquisitorTarget)).toEqual([]);
  });

  test("drops malformed entries and unknown kinds, keeps the rest in order", () => {
    const out = normalizeAnnotations(
      [
        { target: { kind: "tx_path", path: "transaction.body.fee" }, label: "Fee", severity: "error" },
        null,
        { label: "no target" },
        { target: { kind: "hologram", id: 1 } },
        { target: { kind: "cddl_rule", name: "x" }, label: 5 },
        { target: { kind: "cddl_rule", name: "x" }, severity: "fatal" },
        { target: { kind: "cddl_rule", name: "x" }, hint: ["a"] },
        { target: { kind: "cddl_rule", name: "transaction" }, hint: "line1\nline2" },
      ],
      isCquisitorTarget,
    );
    expect(out).toEqual([
      { target: { kind: "tx_path", path: "transaction.body.fee" }, label: "Fee", severity: "error" },
      { target: { kind: "cddl_rule", name: "transaction" }, hint: "line1\nline2" },
    ]);
  });

  test("keeps only the kind's fields and the annotation's fields", () => {
    const out = normalizeAnnotations(
      [
        {
          target: { kind: "diagnostic", index: 3, name: "ignored", occurrence: 1, extra: true },
          label: "",
          extra: "dropped",
        },
        { target: { kind: "diagnostic", name: "BadInputs", occurrence: 1, extra: 1 } },
      ],
      isCquisitorTarget,
    );
    expect(out).toEqual([
      { target: { kind: "diagnostic", index: 3 } },
      { target: { kind: "diagnostic", name: "BadInputs", occurrence: 1 } },
    ]);
  });

  test("truncates label and hint to their limits without splitting a surrogate pair", () => {
    const label = "x".repeat(MAX_ANNOTATION_LABEL - 1) + "😀tail";
    const hint = "h".repeat(MAX_ANNOTATION_HINT + 500);
    const [a] = normalizeAnnotations([{ target: { kind: "term", term_id: 1 }, label, hint }], isDeUplcTarget);
    expect(a.label).toBe("x".repeat(MAX_ANNOTATION_LABEL - 1));
    expect(a.hint).toBe("h".repeat(MAX_ANNOTATION_HINT));
    const [b] = normalizeAnnotations(
      [{ target: { kind: "term", term_id: 1 }, label: "y".repeat(MAX_ANNOTATION_LABEL - 2) + "😀z" }],
      isDeUplcTarget,
    );
    expect(b.label).toBe("y".repeat(MAX_ANNOTATION_LABEL - 2) + "😀");
  });

  test("reads at most MAX_ANNOTATIONS entries", () => {
    const raw = Array.from({ length: MAX_ANNOTATIONS + 10 }, (_, i) => ({ target: { kind: "term", term_id: i } }));
    const out = normalizeAnnotations(raw, isDeUplcTarget);
    expect(out.length).toBe(MAX_ANNOTATIONS);
    expect(out[MAX_ANNOTATIONS - 1].target).toEqual({ kind: "term", term_id: MAX_ANNOTATIONS - 1 });
  });

  test("an absent severity stays absent", () => {
    const [a] = normalizeAnnotations([{ target: { kind: "uplc_line", line: 2 } }], isDeUplcTarget);
    expect("severity" in a).toBe(false);
  });
});

describe("normalizeAnnotationList focus", () => {
  const t = (path: string) => ({ target: { kind: "tx_path", path } });

  test("defaults to 0 and clamps", () => {
    const raw = [t("a"), t("b"), t("c")];
    expect(normalizeAnnotationList(raw, undefined, isCquisitorTarget).annotationFocus).toBe(0);
    expect(normalizeAnnotationList(raw, 2, isCquisitorTarget).annotationFocus).toBe(2);
    expect(normalizeAnnotationList(raw, 99, isCquisitorTarget).annotationFocus).toBe(2);
    expect(normalizeAnnotationList(raw, -1, isCquisitorTarget).annotationFocus).toBe(0);
    expect(normalizeAnnotationList(raw, 1.5, isCquisitorTarget).annotationFocus).toBe(0);
    expect(normalizeAnnotationList(raw, "1", isCquisitorTarget).annotationFocus).toBe(0);
    expect(normalizeAnnotationList([], 3, isCquisitorTarget)).toEqual({ annotations: [], annotationFocus: 0 });
  });

  test("follows the focused entry when earlier entries are dropped", () => {
    const raw = [t("a"), { target: { kind: "new_kind" } }, t("c"), t("d")];
    const out = normalizeAnnotationList(raw, 3, isCquisitorTarget);
    expect(out.annotations.map((a) => (a.target as { path: string }).path)).toEqual(["a", "c", "d"]);
    expect(out.annotationFocus).toBe(2);
  });

  test("a dropped focused entry hands focus to the next kept one, else the last", () => {
    const raw = [t("a"), { target: { kind: "new_kind" } }, t("c")];
    expect(normalizeAnnotationList(raw, 1, isCquisitorTarget).annotationFocus).toBe(1);
    const tail = [t("a"), t("b"), { target: { kind: "new_kind" } }];
    expect(normalizeAnnotationList(tail, 2, isCquisitorTarget).annotationFocus).toBe(1);
  });
});

describe("annotationPayload", () => {
  test("nothing for no valid annotations", () => {
    expect(annotationPayload(undefined, 3, isCquisitorTarget)).toEqual({});
    expect(
      annotationPayload([{ target: { kind: "nope" } } as unknown as Annotation<CquisitorTarget>], 0, isCquisitorTarget),
    ).toEqual({});
  });

  test("ann_focus only when not 0", () => {
    const ann: Annotation<CquisitorTarget>[] = [
      { target: { kind: "cddl_rule", name: "a" } },
      { target: { kind: "cddl_rule", name: "b" } },
    ];
    expect(annotationPayload(ann, 0, isCquisitorTarget)).toEqual({ ann });
    expect(annotationPayload(ann, 1, isCquisitorTarget)).toEqual({ ann, ann_focus: 1 });
    expect(annotationPayload(ann, 7, isCquisitorTarget)).toEqual({ ann, ann_focus: 1 });
  });
});

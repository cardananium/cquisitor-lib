// Hand-off to other tools: de-uplc debugger / decompiler links built from eval results,
// with optional UI annotations.

export * from "./deUplcLink.js";
export {
  MAX_ANNOTATIONS,
  MAX_ANNOTATION_LABEL,
  MAX_ANNOTATION_HINT,
  isDeUplcTarget,
  normalizeAnnotations,
  normalizeAnnotationList,
} from "../share/annotations.js";
export type { AnnotationSeverity, Annotation, DeUplcTarget, AnnotationTargetGuard, NormalizedAnnotations } from "../share/annotations.js";

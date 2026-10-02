// CBOR-against-CDDL diagnostics: pure readings of what `validate_cddl`,
// `validate_cbor_against_cddl`, `cddl_outline` and `cbor_to_json` answer.
// Nothing here calls the wasm; every function takes the library's result (or the
// schema text and its outline) and turns it into something a UI or a tool can show:
//
//   cborPath      — the `$.a[0]["k"]` path grammar of validation errors and decoded trees
//   rootKinds     — which CBOR root kinds a rule admits (`ruleRootKinds`) and a
//                   decoded document has (`cborRootKind`), plus a CDDL tokenizer
//   ruleSelection — which rules can be a validation root, and which to try next
//   cddlError     — schema errors and CBOR mismatches as diagnostics with source ranges
//   verdict       — the one-line verdict of a run, and what stopped it short of one

export * from "./cborPath.js";
export * from "./rootKinds.js";
export * from "./ruleSelection.js";
export * from "./cddlError.js";
export * from "./verdict.js";

//! Sole entry point that turns CDDL source into an AST.
//!
//! Entries are keyed on full source text (~37 ms for ledger schemas) and
//! reused across exports. Every path runs [`limits::cddl_nesting_overflow`]
//! before the recursive parser.
//!
//! * *unchecked* — parses (IDE mid-edit, unresolved refs OK).
//! * *checked* — parses and all refs resolve (validation/mappers).
//!
//! Parse-but-unresolved is parsed twice and cached as one entry.

use std::cell::RefCell;
use std::rc::Rc;

use cddl::ast::CDDL;

use crate::cbor::limits;
use crate::js_error::JsError;

/// Distinct documents kept resident (one editor schema + spare slots).
///
/// ~2 MB per ledger schema → ~8 MB at capacity 4.
const CACHE_CAPACITY: usize = 4;

/// Why a document is not usable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum SchemaErrorKind {
    /// Nesting deeper than the parser is run on.
    NestingTooDeep,
    /// Does not parse.
    Parse,
    /// Parses but names an undefined rule.
    Unresolved,
}

impl SchemaErrorKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            SchemaErrorKind::NestingTooDeep => "nesting_too_deep",
            SchemaErrorKind::Parse => "parse_error",
            SchemaErrorKind::Unresolved => "unresolved_references",
        }
    }
}

/// Rejected document: short message plus optional span.
#[derive(Clone, Debug)]
pub(crate) struct SchemaError {
    pub(crate) kind: SchemaErrorKind,
    /// Parser message for `Parse` / `Unresolved`; limit message for `NestingTooDeep`.
    pub(crate) message: String,
    /// `(start, end, line)` when the failure has a position.
    pub(crate) span: Option<cddl::ast::Span>,
}

impl SchemaError {
    /// Error string for throwing exports.
    pub(crate) fn to_js_error(&self) -> JsError {
        JsError::new(&format!("CDDL parse error: {}", self.message))
    }
}

/// Text prefixing the name of a reference the parser could not resolve.
const MISSING_RULE_PREFIX: &str = "missing definition for rule ";

fn classify(e: &cddl::parser::Error) -> SchemaError {
    match e {
        cddl::parser::Error::PARSER { position, msg } => {
            let kind = if msg.short.starts_with(MISSING_RULE_PREFIX) {
                SchemaErrorKind::Unresolved
            } else {
                SchemaErrorKind::Parse
            };
            SchemaError {
                kind,
                message: msg.short.clone(),
                // Empty range means the parser could not place the failure;
                // reporting it as a span would falsely mark the first byte.
                span: (position.range.0 != position.range.1).then_some((
                    position.range.0,
                    position.range.1,
                    position.line,
                )),
            }
        }
        other => SchemaError {
            kind: SchemaErrorKind::Parse,
            message: other.to_string(),
            span: None,
        },
    }
}

// ============================================================
// Owned AST
// ============================================================

/// Parsed document that owns the text its AST borrows.
///
/// Soundness: `ast` is declared before `src` (dropped first); `src` is
/// `Box<str>` so the bytes stay at a fixed address under moves.
struct OwnedDocument {
    ast: CDDL<'static>,
    /// Keeps the allocation alive at a fixed address for `ast`'s borrows.
    #[allow(dead_code)]
    src: Box<str>,
}

impl OwnedDocument {
    fn parse(src: &str, checked: bool) -> Result<OwnedDocument, cddl::parser::Error> {
        #[cfg(test)]
        PARSE_COUNT.with(|n| n.set(n.get() + 1));
        let owned: Box<str> = Box::from(src);
        // SAFETY: `text` points into `owned`'s heap allocation, which is
        // moved into the returned value and dropped only after `ast`.
        // The `'static` lifetime never escapes: `ast()` hands out a
        // reference no longer than the borrow of `self`.
        let text: &'static str = unsafe { &*(&*owned as *const str) };
        let ast = if checked {
            cddl::pest_bridge::cddl_from_pest_str_checked(text)?
        } else {
            cddl::pest_bridge::cddl_from_pest_str(text)?
        };
        Ok(OwnedDocument { ast, src: owned })
    }

    /// Borrow the AST for no longer than this document lives.
    ///
    /// Shortening `'static` to the borrow is a subtype coercion (requires
    /// `CDDL<'a>` covariant in `'a`), not a transmute.
    fn ast(&self) -> &CDDL<'_> {
        &self.ast
    }
}

/// Cached document. `parsed` when the text parses at all; `error` when
/// it fails the *checked* question (so unresolved docs may carry both).
struct Entry {
    parsed: Option<OwnedDocument>,
    error: Option<SchemaError>,
}

impl Entry {
    fn build(src: &str) -> Entry {
        if let Some(overflow) = limits::cddl_nesting_overflow(src) {
            let at = overflow.offset;
            return Entry {
                parsed: None,
                error: Some(SchemaError {
                    kind: SchemaErrorKind::NestingTooDeep,
                    message: overflow.message(),
                    span: Some((at, at + 1, line_of(src, at))),
                }),
            };
        }

        match OwnedDocument::parse(src, true) {
            Ok(doc) => Entry {
                parsed: Some(doc),
                error: None,
            },
            Err(e) => {
                let error = classify(&e);
                // Unresolved refs are reported after a successful parse,
                // so keep an AST for mid-edit callers.
                let parsed = if error.kind == SchemaErrorKind::Unresolved {
                    OwnedDocument::parse(src, false).ok()
                } else {
                    None
                };
                Entry {
                    parsed,
                    error: Some(error),
                }
            }
        }
    }

    /// AST whether or not every reference resolves.
    fn unchecked(&self) -> Result<&CDDL<'_>, &SchemaError> {
        match (&self.parsed, &self.error) {
            (Some(doc), _) => Ok(doc.ast()),
            (None, Some(e)) => Err(e),
            // `build` never produces this: no AST always carries a reason.
            (None, None) => unreachable!("cached document has neither an AST nor an error"),
        }
    }

    /// AST only when the whole document resolves.
    fn checked(&self) -> Result<&CDDL<'_>, &SchemaError> {
        match (&self.error, &self.parsed) {
            (Some(e), _) => Err(e),
            (None, Some(doc)) => Ok(doc.ast()),
            (None, None) => unreachable!("cached document has neither an AST nor an error"),
        }
    }
}

/// 1-based line number containing `offset`.
fn line_of(src: &str, offset: usize) -> usize {
    1 + src.as_bytes()[..offset.min(src.len())]
        .iter()
        .filter(|b| **b == b'\n')
        .count()
}

// ============================================================
// Cache
// ============================================================

thread_local! {
    /// MRU-first. Linear full-text compare beats parsing; full-text keys
    /// avoid hash collisions serving the wrong AST.
    static CACHE: RefCell<Vec<(Box<str>, Rc<Entry>)>> = const { RefCell::new(Vec::new()) };
}

fn lookup(src: &str) -> Rc<Entry> {
    if let Some(hit) = CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        let found = cache.iter().position(|(key, _)| &**key == src)?;
        let entry = cache.remove(found);
        let value = Rc::clone(&entry.1);
        cache.insert(0, entry);
        Some(value)
    }) {
        return hit;
    }

    // Build with no borrow held: parsing must not observe/deadlock the
    // cache, and callers may re-enter from inside `f`.
    let entry = Rc::new(Entry::build(src));

    CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        cache.retain(|(key, _)| &**key != src);
        cache.insert(0, (Box::from(src), Rc::clone(&entry)));
        cache.truncate(CACHE_CAPACITY);
    });

    entry
}

/// Run `f` with the AST whether or not every reference resolves (IDE).
pub(crate) fn with_ast_unchecked<R>(
    src: &str,
    f: impl FnOnce(Result<&CDDL<'_>, &SchemaError>) -> R,
) -> R {
    // Hold the `Rc` for the whole call so a re-entrant eviction cannot
    // free the AST `f` is reading.
    let entry = lookup(src);
    f(entry.unchecked())
}

/// Run `f` with the AST only when the document parses and resolves.
pub(crate) fn with_ast_checked<R>(
    src: &str,
    f: impl FnOnce(Result<&CDDL<'_>, &SchemaError>) -> R,
) -> R {
    let entry = lookup(src);
    f(entry.checked())
}

/// Number of documents currently resident.
#[cfg(test)]
pub(crate) fn cached_document_count() -> usize {
    CACHE.with(|cache| cache.borrow().len())
}

#[cfg(test)]
thread_local! {
    /// Parser invocations on this thread (asserted by cache tests).
    static PARSE_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn parse_count() -> usize {
    PARSE_COUNT.with(|n| n.get())
}

#[cfg(test)]
pub(crate) fn reset_parse_count() {
    PARSE_COUNT.with(|n| n.set(0));
}

#[cfg(test)]
pub(crate) fn clear_cache() {
    CACHE.with(|cache| cache.borrow_mut().clear());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_names(src: &str) -> Vec<String> {
        with_ast_unchecked(src, |r| {
            r.expect("expected a parsed document")
                .rules
                .iter()
                .map(|rule| match rule {
                    cddl::ast::Rule::Type { rule, .. } => rule.name.ident.to_string(),
                    cddl::ast::Rule::Group { rule, .. } => rule.name.ident.to_string(),
                })
                .collect()
        })
    }

    fn body_of(src: &str, name: &str) -> String {
        with_ast_checked(src, |r| {
            let ast = r.expect("expected a resolving document");
            ast.rules
                .iter()
                .find_map(|rule| match rule {
                    cddl::ast::Rule::Type { rule, .. } if rule.name.ident == name => {
                        Some(rule.value.to_string())
                    }
                    _ => None,
                })
                .expect("rule not found")
        })
    }

    #[test]
    fn a_resolving_document_is_served_from_both_questions() {
        clear_cache();
        let src = "thing = {n: uint}";
        assert_eq!(rule_names(src), vec!["thing"]);
        with_ast_checked(src, |r| assert!(r.is_ok()));
        assert_eq!(cached_document_count(), 1);
    }

    #[test]
    fn an_unresolved_document_answers_unchecked_and_fails_checked() {
        clear_cache();
        let src = "a = [alpha, beta]\n";
        assert_eq!(rule_names(src), vec!["a"]);
        with_ast_checked(src, |r| {
            let e = r.expect_err("expected a rejection");
            assert_eq!(e.kind, SchemaErrorKind::Unresolved);
            assert_eq!(e.message, "missing definition for rule alpha");
            assert!(e.span.is_some());
        });
    }

    /// Placed rejections keep their span; unplaced ones return `None`
    /// rather than pointing at the first byte.
    #[test]
    fn only_a_rejection_the_parser_placed_carries_a_span() {
        let placed = cddl::parser::Error::PARSER {
            position: cddl::lexer::Position {
                line: 3,
                column: 5,
                range: (20, 28),
                index: 20,
            },
            msg: cddl::error::ErrorMsg {
                short: "placed".into(),
                extended: None,
            },
        };
        assert_eq!(super::classify(&placed).span, Some((20, 28, 3)));

        let unplaced = cddl::parser::Error::PARSER {
            position: cddl::lexer::Position::default(),
            msg: cddl::error::ErrorMsg {
                short: "unplaced".into(),
                extended: None,
            },
        };
        assert_eq!(super::classify(&unplaced).span, None);
    }

    #[test]
    fn a_syntax_error_fails_both_questions_identically() {
        clear_cache();
        let src = "A = [";
        let first = with_ast_unchecked(src, |r| r.expect_err("expected a rejection").clone());
        let second = with_ast_checked(src, |r| r.expect_err("expected a rejection").clone());
        assert_eq!(first.kind, SchemaErrorKind::Parse);
        assert_eq!(first.message, second.message);
        assert_eq!(first.span, second.span);
    }

    /// Cache hits must report the same position info as the miss that built the entry.
    #[test]
    fn parse_failures_are_cached_and_reported_identically() {
        clear_cache();
        let src = "thing = [\n  a: int\n";
        let first = with_ast_checked(src, |r| r.expect_err("expected a rejection").clone());
        assert_eq!(cached_document_count(), 1);
        let second = with_ast_checked(src, |r| r.expect_err("expected a rejection").clone());
        assert_eq!(first.kind, second.kind);
        assert_eq!(first.message, second.message);
        assert_eq!(first.span, second.span);
        assert!(first.span.is_some(), "expected positional info");
    }

    /// Same rule name, different bodies must never share an AST.
    #[test]
    fn alternating_schemas_never_cross() {
        clear_cache();
        let a = "x = uint\n";
        let b = "x = tstr\n";
        for _ in 0..50 {
            assert_eq!(body_of(a, "x"), "uint");
            assert_eq!(body_of(b, "x"), "tstr");
        }
        assert!(cached_document_count() <= CACHE_CAPACITY);
    }

    #[test]
    fn cache_survives_eviction_and_reuse() {
        clear_cache();
        for round in 0..5 {
            for i in 0..CACHE_CAPACITY * 3 {
                let src = format!("r{} = uint\nx = [r{}]\n", i, i);
                assert_eq!(body_of(&src, "x"), format!("[ r{} ]", i), "round {}", round);
                assert!(
                    cached_document_count() <= CACHE_CAPACITY,
                    "cache grew to {}",
                    cached_document_count()
                );
            }
        }
    }

    /// Bare `[`-nesting is the slow parser shape that pins the bound.
    pub(crate) fn nested_schema(levels: usize) -> String {
        let mut src = String::from("x = ");
        for _ in 0..levels {
            src.push('[');
        }
        src.push_str("uint");
        for _ in 0..levels {
            src.push(']');
        }
        src
    }

    #[test]
    fn a_document_nested_past_the_limit_is_rejected_without_parsing() {
        clear_cache();
        let src = nested_schema(limits::MAX_CDDL_NESTING_DEPTH + 1);
        with_ast_checked(&src, |r| {
            let e = r.expect_err("expected a rejection");
            assert_eq!(e.kind, SchemaErrorKind::NestingTooDeep);
            assert!(e.span.is_some());
        });
        with_ast_unchecked(&src, |r| {
            assert_eq!(
                r.expect_err("expected a rejection").kind,
                SchemaErrorKind::NestingTooDeep
            );
        });
    }

    /// Exactly at the limit must still parse (guard is not "any brackets").
    #[test]
    fn a_document_nested_to_the_limit_still_parses() {
        crate::cbor::test_fixtures::on_large_stack(|| {
            clear_cache();
            let src = nested_schema(limits::MAX_CDDL_NESTING_DEPTH);
            with_ast_checked(&src, |r| assert!(r.is_ok(), "{:?}", r.err()));
        });
    }

    /// Resolving docs parse once; unresolved cost a second parse for the IDE AST.
    #[test]
    fn a_document_is_parsed_once_per_distinct_source() {
        clear_cache();
        reset_parse_count();
        let src = "thing = {n: uint}\nother = [thing]\n";
        for _ in 0..20 {
            with_ast_checked(src, |r| assert!(r.is_ok()));
            with_ast_unchecked(src, |r| assert!(r.is_ok()));
        }
        assert_eq!(parse_count(), 1);

        clear_cache();
        reset_parse_count();
        let src = "thing = [missing_name]\n";
        for _ in 0..20 {
            with_ast_checked(src, |r| assert!(r.is_err()));
            with_ast_unchecked(src, |r| assert!(r.is_ok()));
        }
        assert_eq!(parse_count(), 2);

        clear_cache();
        reset_parse_count();
        let src = "thing = [";
        for _ in 0..20 {
            with_ast_checked(src, |r| assert!(r.is_err()));
        }
        assert_eq!(parse_count(), 1);
    }

    /// Every version of the ledger schema, oldest to newest, resolves and
    /// parses through both cache paths.
    #[test]
    fn every_schema_version_resolves_through_the_cache() {
        clear_cache();
        for (version, src) in crate::cbor::test_fixtures::schema_suite() {
            with_ast_checked(src, |r| {
                assert!(r.is_ok(), "{} did not resolve: {:?}", version, r.err());
            });
            with_ast_unchecked(src, |r| {
                assert!(r.is_ok(), "{} did not parse: {:?}", version, r.err());
            });
        }
    }
}

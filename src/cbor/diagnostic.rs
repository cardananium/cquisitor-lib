//! CBOR diagnostic notation (RFC 8949, Section 8) for the composite map keys
//! the validator writes into its locations.
//!
//! A location component names a map key. A scalar key is written as a
//! CDDL literal; an array, map, tagged or simple-value key has no literal
//! and is written in diagnostic notation: `[2, h'0102']`, `{1: 2}`,
//! `24(h'00')`, `simple(32)`. This module reads such a component back into
//! an [`Item`] and matches it against the positional decode tree, so that
//! an error under a composite key still gets its spans.
//!
//! The notation read here is exactly what the validator writes: integers in
//! decimal, byte strings as `h'…'`, text strings quoted with `\"` and `\\`
//! escapes, floats as CDDL float literals, `true`, `false`, `null`,
//! `simple(n)`, `n(item)`, `[a, b]` and `{k: v}`. Nesting the validator
//! elided (`[...]`, `{...}`, `n(...)`) names no item and matches nothing.

use serde_json::Value;
use std::convert::TryFrom;

/// A data item read from diagnostic notation.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Item {
    Int(i128),
    Bytes(Vec<u8>),
    Text(String),
    Float(f64),
    Bool(bool),
    Null,
    Simple(u8),
    Tag(u64, Box<Item>),
    Array(Vec<Item>),
    Map(Vec<(Item, Item)>),
}

/// Deepest nesting read; the validator elides past its own bound, so this
/// only guards against a component that is not the validator's.
const MAX_DEPTH: usize = 32;

/// The composite item `text` denotes, or `None` when it is not one: only
/// arrays, maps, tagged items and simple values are read here, a scalar
/// key being read by its own literal form.
pub(crate) fn parse_composite(text: &str) -> Option<Item> {
    let mut parser = Parser {
        bytes: text.as_bytes(),
        pos: 0,
    };
    parser.skip_ws();
    let starts_composite = match parser.peek()? {
        b'[' | b'{' => true,
        b's' => text[parser.pos..].starts_with("simple("),
        b'0'..=b'9' => {
            // `n(item)`: a tag.
            let mut i = parser.pos;
            while i < parser.bytes.len() && parser.bytes[i].is_ascii_digit() {
                i += 1;
            }
            parser.bytes.get(i) == Some(&b'(')
        }
        _ => false,
    };
    if !starts_composite {
        return None;
    }
    let item = parser.item(0)?;
    parser.skip_ws();
    (parser.pos == parser.bytes.len()).then_some(item)
}

/// The text a quoted text literal `text` denotes (escapes as in a
/// composite key), or `None` when `text` is not exactly one such literal.
pub(crate) fn parse_text(text: &str) -> Option<String> {
    if !text.starts_with('"') {
        return None;
    }
    let mut parser = Parser {
        bytes: text.as_bytes(),
        pos: 0,
    };
    match parser.item(0)? {
        Item::Text(s) if parser.pos == parser.bytes.len() => Some(s),
        _ => None,
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn eat(&mut self, byte: u8) -> Option<()> {
        self.skip_ws();
        if self.peek()? == byte {
            self.pos += 1;
            Some(())
        } else {
            None
        }
    }

    fn eat_literal(&mut self, literal: &str) -> bool {
        if self.bytes[self.pos..].starts_with(literal.as_bytes()) {
            self.pos += literal.len();
            true
        } else {
            false
        }
    }

    fn item(&mut self, depth: usize) -> Option<Item> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.skip_ws();
        match self.peek()? {
            b'[' => {
                self.pos += 1;
                let mut items = Vec::new();
                self.skip_ws();
                if self.peek()? == b']' {
                    self.pos += 1;
                    return Some(Item::Array(items));
                }
                loop {
                    // Elided nesting names no item.
                    self.skip_ws();
                    if self.eat_literal("...") {
                        return None;
                    }
                    items.push(self.item(depth + 1)?);
                    self.skip_ws();
                    match self.peek()? {
                        b',' => self.pos += 1,
                        b']' => {
                            self.pos += 1;
                            return Some(Item::Array(items));
                        }
                        _ => return None,
                    }
                }
            }
            b'{' => {
                self.pos += 1;
                let mut entries = Vec::new();
                self.skip_ws();
                if self.peek()? == b'}' {
                    self.pos += 1;
                    return Some(Item::Map(entries));
                }
                loop {
                    self.skip_ws();
                    if self.eat_literal("...") {
                        return None;
                    }
                    let key = self.item(depth + 1)?;
                    self.eat(b':')?;
                    let value = self.item(depth + 1)?;
                    entries.push((key, value));
                    self.skip_ws();
                    match self.peek()? {
                        b',' => self.pos += 1,
                        b'}' => {
                            self.pos += 1;
                            return Some(Item::Map(entries));
                        }
                        _ => return None,
                    }
                }
            }
            b'h' if self.bytes[self.pos..].starts_with(b"h'") => {
                self.pos += 2;
                let start = self.pos;
                while self.peek()? != b'\'' {
                    self.pos += 1;
                }
                let hex = std::str::from_utf8(&self.bytes[start..self.pos]).ok()?;
                self.pos += 1;
                Some(Item::Bytes(hex::decode(hex).ok()?))
            }
            b'"' => {
                self.pos += 1;
                let mut out = String::new();
                loop {
                    let rest = std::str::from_utf8(&self.bytes[self.pos..]).ok()?;
                    let c = rest.chars().next()?;
                    self.pos += c.len_utf8();
                    match c {
                        '"' => return Some(Item::Text(out)),
                        '\\' => {
                            let rest = std::str::from_utf8(&self.bytes[self.pos..]).ok()?;
                            let escaped = rest.chars().next()?;
                            self.pos += escaped.len_utf8();
                            match escaped {
                                '"' => out.push('"'),
                                '\\' => out.push('\\'),
                                'n' => out.push('\n'),
                                't' => out.push('\t'),
                                'r' => out.push('\r'),
                                '0' => out.push('\0'),
                                '\'' => out.push('\''),
                                'u' => {
                                    // Rust's `{:?}` writes `\u{XXXX}`.
                                    self.eat(b'{')?;
                                    let start = self.pos;
                                    while self.peek()? != b'}' {
                                        self.pos += 1;
                                    }
                                    let digits =
                                        std::str::from_utf8(&self.bytes[start..self.pos]).ok()?;
                                    self.pos += 1;
                                    out.push(char::from_u32(
                                        u32::from_str_radix(digits, 16).ok()?,
                                    )?);
                                }
                                other => {
                                    out.push('\\');
                                    out.push(other);
                                }
                            }
                        }
                        c => out.push(c),
                    }
                }
            }
            b's' if self.eat_literal("simple(") => {
                let n = self.digits()?;
                self.eat(b')')?;
                Some(Item::Simple(u8::try_from(n).ok()?))
            }
            b't' if self.eat_literal("true") => Some(Item::Bool(true)),
            b'f' if self.eat_literal("false") => Some(Item::Bool(false)),
            b'n' if self.eat_literal("null") => Some(Item::Null),
            b'u' if self.eat_literal("undefined") => Some(Item::Null),
            b'N' if self.eat_literal("NaN") => Some(Item::Float(f64::NAN)),
            b'I' if self.eat_literal("Infinity") => Some(Item::Float(f64::INFINITY)),
            b'-' if self.bytes[self.pos..].starts_with(b"-Infinity") => {
                self.pos += "-Infinity".len();
                Some(Item::Float(f64::NEG_INFINITY))
            }
            b'-' | b'0'..=b'9' => self.number(depth),
            _ => None,
        }
    }

    /// An unsigned decimal.
    fn digits(&mut self) -> Option<u64> {
        self.skip_ws();
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        std::str::from_utf8(&self.bytes[start..self.pos])
            .ok()?
            .parse()
            .ok()
    }

    /// An integer, a float literal, or a tag `n(item)`.
    fn number(&mut self, depth: usize) -> Option<Item> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        let mut is_float = false;
        if matches!(self.peek(), Some(b'.'))
            && matches!(self.bytes.get(self.pos + 1), Some(b'0'..=b'9'))
        {
            is_float = true;
            self.pos += 1;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            is_float = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos]).ok()?;
        if is_float {
            return Some(Item::Float(text.parse().ok()?));
        }
        let n: i128 = text.parse().ok()?;
        if self.peek() == Some(b'(') {
            // A tag: `n(item)`, or elided `n(...)`.
            self.pos += 1;
            self.skip_ws();
            if self.eat_literal("...") {
                return None;
            }
            let inner = self.item(depth + 1)?;
            self.eat(b')')?;
            return Some(Item::Tag(u64::try_from(n).ok()?, Box::new(inner)));
        }
        Some(Item::Int(n))
    }
}

/// Whether the decoded node `node` is the data item `item` denotes.
///
/// Tags on the node count: a tagged key is matched by a tagged item. The
/// undefined value is read as `null`, as the validator's data model reads
/// it.
pub(crate) fn node_matches(node: &Value, item: &Item) -> bool {
    let kind = node.get("type").and_then(Value::as_str).unwrap_or("");
    match item {
        Item::Int(n) => int_node_is(node, *n),
        Item::Bytes(b) => {
            string_payload_is(node, "Bytes", "IndefiniteLengthBytes", &hex::encode(b))
        }
        Item::Text(t) => string_payload_is(node, "String", "IndefiniteLengthString", t),
        Item::Float(f) => {
            matches!(kind, "F16" | "F32" | "F64")
                && node
                    .get("value")
                    .and_then(Value::as_f64)
                    .map(|v| v == *f || (v.is_nan() && f.is_nan()))
                    .unwrap_or(false)
        }
        Item::Bool(b) => kind == "Bool" && node.get("value").and_then(Value::as_bool) == Some(*b),
        Item::Null => matches!(kind, "Null" | "Undefined"),
        Item::Simple(n) => {
            kind == "Simple" && node.get("value").and_then(Value::as_u64) == Some(*n as u64)
        }
        Item::Tag(tag, inner) => {
            kind == "Tag"
                && node
                    .get("tag")
                    .and_then(Value::as_str)
                    .and_then(crate::cbor::tags::tag_number)
                    == Some(*tag)
                && node
                    .get("value")
                    .map(|v| node_matches(v, inner))
                    .unwrap_or(false)
        }
        Item::Array(items) => {
            kind == "Array"
                && node
                    .get("values")
                    .and_then(Value::as_array)
                    .map(|values| {
                        let values = without_break(values);
                        values.len() == items.len()
                            && values.iter().zip(items).all(|(v, i)| node_matches(v, i))
                    })
                    .unwrap_or(false)
        }
        Item::Map(entries) => {
            kind == "Map"
                && node
                    .get("values")
                    .and_then(Value::as_array)
                    .map(|values| {
                        let values = without_break(values);
                        values.len() == entries.len()
                            && values.iter().zip(entries).all(|(entry, (k, v))| {
                                entry
                                    .get("key")
                                    .map(|n| node_matches(n, k))
                                    .unwrap_or(false)
                                    && entry
                                        .get("value")
                                        .map(|n| node_matches(n, v))
                                        .unwrap_or(false)
                            })
                    })
                    .unwrap_or(false)
        }
    }
}

/// The items of an array or map node, without the break an indefinite-length
/// one is decoded with.
fn without_break(values: &[Value]) -> Vec<&Value> {
    values
        .iter()
        .filter(|v| v.get("type").and_then(Value::as_str) != Some("Break"))
        .collect()
}

/// Whether the string node `node` spells `want`: its `value`, or its chunks'
/// values in turn when the string was of indefinite length. Nothing is
/// copied, so a lookup that compares every key of a large map stays cheap.
pub(crate) fn string_payload_is(
    node: &Value,
    definite: &str,
    indefinite: &str,
    want: &str,
) -> bool {
    let Some(kind) = node.get("type").and_then(Value::as_str) else {
        return false;
    };
    if kind == definite {
        return node.get("value").and_then(Value::as_str) == Some(want);
    }
    if kind != indefinite {
        return false;
    }
    let Some(chunks) = node.get("chunks").and_then(Value::as_array) else {
        return false;
    };
    let mut rest = want;
    for chunk in chunks {
        if chunk.get("type").and_then(Value::as_str) == Some("Break") {
            continue;
        }
        let Some(part) = chunk.get("value").and_then(Value::as_str) else {
            return false;
        };
        match rest.strip_prefix(part) {
            Some(after) => rest = after,
            None => return false,
        }
    }
    rest.is_empty()
}

/// Whether the decoded node `node` is the integer `n`.
pub(crate) fn int_node_is(node: &Value, n: i128) -> bool {
    let kind = node.get("type").and_then(Value::as_str).unwrap_or("");
    if !matches!(
        kind,
        "U8" | "U16" | "U32" | "U64" | "I8" | "I16" | "I32" | "I64" | "Int"
    ) {
        return false;
    }
    match node.get("value") {
        Some(Value::Number(num)) => {
            if let Some(v) = num.as_i64() {
                v as i128 == n
            } else if let Some(v) = num.as_u64() {
                v as i128 == n
            } else {
                // Past 64 bits the number is held as its digits.
                num.to_string() == n.to_string()
            }
        }
        _ => false,
    }
}

/// The payload of a string node: its `value`, or its chunks' values spliced
/// together when the string was of indefinite length.
pub(crate) fn string_payload(node: &Value, definite: &str, indefinite: &str) -> Option<String> {
    let kind = node.get("type").and_then(Value::as_str)?;
    if kind == definite {
        return node
            .get("value")
            .and_then(Value::as_str)
            .map(str::to_string);
    }
    if kind == indefinite {
        let mut out = String::new();
        for chunk in node.get("chunks")?.as_array()? {
            if chunk.get("type").and_then(Value::as_str) == Some("Break") {
                continue;
            }
            out.push_str(chunk.get("value")?.as_str()?);
        }
        return Some(out);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_validators_notation() {
        assert_eq!(
            parse_composite(r#"[2, h'0102', "a\"b", 24({true: null}), 1.5, simple(32), -3]"#),
            Some(Item::Array(vec![
                Item::Int(2),
                Item::Bytes(vec![1, 2]),
                Item::Text("a\"b".into()),
                Item::Tag(
                    24,
                    Box::new(Item::Map(vec![(Item::Bool(true), Item::Null)]))
                ),
                Item::Float(1.5),
                Item::Simple(32),
                Item::Int(-3),
            ]))
        );
        assert_eq!(parse_composite("{}"), Some(Item::Map(vec![])));
        assert_eq!(parse_composite("[]"), Some(Item::Array(vec![])));
        assert_eq!(
            parse_composite("1(2)"),
            Some(Item::Tag(1, Box::new(Item::Int(2))))
        );
        assert_eq!(parse_composite("simple(5)"), Some(Item::Simple(5)));
        // Scalars are not composite; elided nesting names nothing.
        assert_eq!(parse_composite("5"), None);
        assert_eq!(parse_composite("\"x\""), None);
        assert_eq!(parse_composite("h'00'"), None);
        assert_eq!(parse_composite("[[...]]"), None);
        assert_eq!(parse_composite("[1, 2"), None);
        assert_eq!(parse_composite("[1] x"), None);
    }

    #[test]
    fn matches_decoded_nodes() {
        let tree =
            crate::cbor::decoder::decode_cbor_to_value(&hex::decode("83024201025f4101ff").unwrap())
                .unwrap()
                .into_inner();
        // Not this: the array has three items.
        assert!(!node_matches(
            &tree,
            &parse_composite("[2, h'0102']").unwrap()
        ));
        assert!(node_matches(
            &tree,
            &parse_composite("[2, h'0102', h'01']").unwrap()
        ));
        let tagged = crate::cbor::decoder::decode_cbor_to_value(&hex::decode("d81802").unwrap())
            .unwrap()
            .into_inner();
        assert!(node_matches(&tagged, &parse_composite("24(2)").unwrap()));
        assert!(!node_matches(&tagged, &parse_composite("25(2)").unwrap()));
    }
}

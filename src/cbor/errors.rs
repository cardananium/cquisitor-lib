//! Structured decode errors for the CBOR decoder.
//!
//! Every error produced by [`super::decoder`] carries a machine-readable
//! `kind`, a byte offset (where available), an optional `byte_span`, a
//! structural `path` (JSON-pointer-ish), and a human message.
//!
//! The decoder threads a mutable path stack through recursive calls and
//! each error site builds a `CborDecodeError` from whatever segments are on
//! that stack — so the returned `path` points at the *deepest* location
//! where the decode failed, e.g. `$.entries[2].value[0].chunks[1]`.

use serde_json::{Map, Value};
use std::fmt::{self, Write as _};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// Input hex string couldn't be decoded (non-hex chars, odd length, …).
    InvalidHex,
    /// CBOR major/minor encoding violates RFC 8949 §3 framing.
    InvalidSyntax,
    /// Input ended mid-item: header needed more bytes, or a content buffer
    /// was truncated.
    UnexpectedEof,
    /// `0xff` appeared outside an indefinite-length container.
    UnexpectedBreak,
    /// Bytes remain on the wire after a complete root item.
    TrailingData,
    /// Text string header advertised bytes that aren't valid UTF-8.
    InvalidUtf8,
    /// Indefinite bytes/text contained a chunk whose major type didn't
    /// match the container (RFC 8949 §3.2.3) or that was itself indefinite.
    InvalidChunk,
    /// A negative integer < i64::MIN that also doesn't fit as i128 in
    /// serde_json::Number.
    IntNotRepresentable,
    /// A non-finite float (NaN / ±Inf) — serde_json can't encode these.
    NonFiniteFloat,
    /// Other underlying IO error from the CBOR parser.
    Io,
}

impl ErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorKind::InvalidHex => "invalid_hex",
            ErrorKind::InvalidSyntax => "invalid_syntax",
            ErrorKind::UnexpectedEof => "unexpected_eof",
            ErrorKind::UnexpectedBreak => "unexpected_break",
            ErrorKind::TrailingData => "trailing_data",
            ErrorKind::InvalidUtf8 => "invalid_utf8",
            ErrorKind::InvalidChunk => "invalid_chunk",
            ErrorKind::IntNotRepresentable => "int_not_representable",
            ErrorKind::NonFiniteFloat => "non_finite_float",
            ErrorKind::Io => "io_error",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Side {
    Key,
    Value,
}

#[derive(Clone, Debug)]
pub enum PathSeg {
    ArrayIdx(usize),
    MapEntry(usize, Side),
    Chunk(usize),
    TagInner,
}

pub fn render_path(segs: &[PathSeg]) -> String {
    let mut s = String::from("$");
    for seg in segs {
        match seg {
            PathSeg::ArrayIdx(i) => {
                write!(s, "[{}]", i).unwrap();
            }
            PathSeg::MapEntry(i, Side::Key) => {
                write!(s, ".entries[{}].key", i).unwrap();
            }
            PathSeg::MapEntry(i, Side::Value) => {
                write!(s, ".entries[{}].value", i).unwrap();
            }
            PathSeg::Chunk(i) => {
                write!(s, ".chunks[{}]", i).unwrap();
            }
            PathSeg::TagInner => s.push_str(".tag"),
        }
    }
    s
}

#[derive(Clone, Debug)]
pub struct CborDecodeError {
    pub kind: ErrorKind,
    pub offset: Option<usize>,
    /// `(offset, length)`. Present when the error pinpoints a specific byte
    /// range rather than a single cursor position.
    pub byte_span: Option<(usize, usize)>,
    pub path: String,
    pub message: String,
    /// Partial tree decoded up to the failure point, if any. Carried
    /// separately from the serialised error object so the top-level caller
    /// can expose it alongside (not inside) the `error` field.
    pub partial: Option<Value>,
}

impl CborDecodeError {
    /// Base constructor — paths are rendered from segments at the error site,
    /// so the returned error is self-contained.
    pub fn new(
        kind: ErrorKind,
        path: &[PathSeg],
        offset: Option<usize>,
        byte_span: Option<(usize, usize)>,
        message: impl Into<String>,
    ) -> Self {
        CborDecodeError {
            kind,
            offset,
            byte_span,
            path: render_path(path),
            message: message.into(),
            partial: None,
        }
    }

    pub fn with_partial(mut self, partial: Value) -> Self {
        self.partial = Some(partial);
        self
    }

    pub fn to_json(&self) -> Value {
        let mut obj = Map::new();
        obj.insert("kind".into(), Value::String(self.kind.as_str().into()));
        obj.insert("message".into(), Value::String(self.message.clone()));
        obj.insert("path".into(), Value::String(self.path.clone()));
        if let Some(offset) = self.offset {
            obj.insert("offset".into(), Value::Number(offset.into()));
        }
        if let Some((offset, length)) = self.byte_span {
            let mut span = Map::new();
            span.insert("offset".into(), Value::Number(offset.into()));
            span.insert("length".into(), Value::Number(length.into()));
            obj.insert("byte_span".into(), Value::Object(span));
        }
        Value::Object(obj)
    }
}

impl fmt::Display for CborDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({}): {}", self.kind.as_str(), self.path, self.message)
    }
}

impl std::error::Error for CborDecodeError {}

// === Convenience constructors used by the decoder ===

pub fn invalid_hex(reason: impl Into<String>) -> CborDecodeError {
    let reason = reason.into();
    let message = format!("invalid CBOR hex: {}", reason);
    CborDecodeError::new(ErrorKind::InvalidHex, &[], None, None, message)
}

pub fn invalid_syntax(path: &[PathSeg], offset: usize) -> CborDecodeError {
    CborDecodeError::new(
        ErrorKind::InvalidSyntax,
        path,
        Some(offset),
        None,
        format!("invalid CBOR syntax at offset {}", offset),
    )
}

pub fn unexpected_eof(path: &[PathSeg], offset: usize) -> CborDecodeError {
    CborDecodeError::new(
        ErrorKind::UnexpectedEof,
        path,
        Some(offset),
        None,
        format!("unexpected end of CBOR input at offset {}", offset),
    )
}

pub fn unexpected_break(path: &[PathSeg], offset: usize) -> CborDecodeError {
    CborDecodeError::new(
        ErrorKind::UnexpectedBreak,
        path,
        Some(offset),
        Some((offset, 1)),
        format!("unexpected CBOR break at offset {}", offset),
    )
}

pub fn trailing_data(offset: usize, bytes_left: usize) -> CborDecodeError {
    CborDecodeError::new(
        ErrorKind::TrailingData,
        &[],
        Some(offset),
        Some((offset, bytes_left)),
        format!(
            "trailing CBOR data at offset {} ({} byte(s) left)",
            offset, bytes_left
        ),
    )
}

pub fn invalid_utf8(path: &[PathSeg], offset: usize, length: usize) -> CborDecodeError {
    CborDecodeError::new(
        ErrorKind::InvalidUtf8,
        path,
        Some(offset),
        Some((offset, length)),
        format!("invalid UTF-8 text string at offset {}", offset),
    )
}

pub fn invalid_chunk(
    path: &[PathSeg],
    offset: usize,
    container: &'static str,
) -> CborDecodeError {
    CborDecodeError::new(
        ErrorKind::InvalidChunk,
        path,
        Some(offset),
        None,
        format!("invalid {} chunk at offset {}", container, offset),
    )
}

pub fn int_not_representable(path: &[PathSeg], offset: usize, value: i128) -> CborDecodeError {
    CborDecodeError::new(
        ErrorKind::IntNotRepresentable,
        path,
        Some(offset),
        None,
        format!(
            "cannot represent CBOR negative integer {} as JSON number",
            value
        ),
    )
}

pub fn non_finite_float(path: &[PathSeg], offset: usize) -> CborDecodeError {
    CborDecodeError::new(
        ErrorKind::NonFiniteFloat,
        path,
        Some(offset),
        None,
        "cannot encode non-finite CBOR float as JSON number",
    )
}

pub fn io(path: &[PathSeg], offset: Option<usize>, reason: impl Into<String>) -> CborDecodeError {
    let reason = reason.into();
    CborDecodeError::new(
        ErrorKind::Io,
        path,
        offset,
        None,
        format!("CBOR read error: {}", reason),
    )
}

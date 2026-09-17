use std::convert::TryFrom;
use std::io::Cursor;
use std::mem;

use ciborium_io::Read as _;
use ciborium_ll::{simple, Decoder, Error as CborError, Header};
use serde_json::{Map, Number, Value};

use crate::cbor::errors::{self as err, CborDecodeError, PathSeg, Side};
use crate::cbor::limits::MAX_CBOR_DECODE_NESTING_DEPTH;
use crate::cbor::tags::tag_name;
use crate::deep_json::DeepJson;

type CborDecoder<'a> = Decoder<Cursor<&'a [u8]>>;
type DecodeResult<T> = Result<T, CborDecodeError>;
type Path = Vec<PathSeg>;

#[derive(Clone, Copy, Debug)]
struct Pos {
    offset: usize,
    length: usize,
}

impl Pos {
    fn new(start: usize, end: usize) -> Pos {
        Pos {
            offset: start,
            length: end.saturating_sub(start),
        }
    }

    fn to_value(self) -> Value {
        let mut obj = Map::new();
        obj.insert("offset".into(), Value::Number(self.offset.into()));
        obj.insert("length".into(), Value::Number(self.length.into()));
        Value::Object(obj)
    }
}

// === Oddity model (RFC 8949 §4.1/§4.2 deterministic-encoding deviations) ===

#[derive(Clone, Copy, Debug)]
enum OddityKind {
    /// Integer not encoded in its shortest argument width. RFC 8949 §4.2.1.
    IntNotShortest,
    /// Float value representable in a narrower IEEE-754 width without loss. RFC 8949 §4.1.
    FloatNotShortest,
    /// Indefinite-length bytes / text / array / map. RFC 8949 §4.2.1.
    IndefiniteLength,
    /// Map keys not in bytewise lexicographic order of their encoded form. RFC 8949 §4.2.1.
    MapKeysNotSorted,
    /// Map contains duplicate encoded keys. RFC 8949 §5.6 / §4.2.1.
    DuplicateMapKeys,
    /// Bignum (tag 2/3) wrapping a value that fits in a native CBOR integer. RFC 8949 §3.4.3.
    BignumForSmallInt,
    /// Bignum byte string has leading zero bytes. RFC 8949 §3.4.3.
    BignumLeadingZeroes,
}

impl OddityKind {
    fn as_str(self) -> &'static str {
        match self {
            OddityKind::IntNotShortest => "IntNotShortest",
            OddityKind::FloatNotShortest => "FloatNotShortest",
            OddityKind::IndefiniteLength => "IndefiniteLength",
            OddityKind::MapKeysNotSorted => "MapKeysNotSorted",
            OddityKind::DuplicateMapKeys => "DuplicateMapKeys",
            OddityKind::BignumForSmallInt => "BignumForSmallInt",
            OddityKind::BignumLeadingZeroes => "BignumLeadingZeroes",
        }
    }
}

#[derive(Clone, Debug)]
struct Oddity {
    kind: OddityKind,
    detail: Option<String>,
}

fn oddity<S: Into<String>>(kind: OddityKind, detail: S) -> Oddity {
    Oddity {
        kind,
        detail: Some(detail.into()),
    }
}

fn attach_oddities(value: Value, oddities: Vec<Oddity>) -> Value {
    if oddities.is_empty() {
        return value;
    }
    let Value::Object(mut obj) = value else {
        return value;
    };
    let arr: Vec<Value> = oddities
        .into_iter()
        .map(|o| {
            let mut m = Map::new();
            m.insert("kind".into(), Value::String(o.kind.as_str().into()));
            if let Some(d) = o.detail {
                m.insert("detail".into(), Value::String(d));
            }
            Value::Object(m)
        })
        .collect();
    obj.insert("oddities".into(), Value::Array(arr));
    Value::Object(obj)
}

/// Shortest-form argument width (in bytes) for an unsigned value on a CBOR header.
/// 0..23: 0 bytes (inlined in initial byte). 24..=255: 1, 256..=65535: 2, etc.
fn shortest_arg_width(v: u64) -> usize {
    if v < 24 {
        0
    } else if v < 1 << 8 {
        1
    } else if v < 1 << 16 {
        2
    } else if v < 1 << 32 {
        4
    } else {
        8
    }
}

/// For a header whose wire length is `header_len` bytes and argument value `v`,
/// return an [`OddityKind::IntNotShortest`] if a narrower encoding exists.
fn int_not_shortest(v: u64, header_len: usize, is_negative: bool) -> Option<Oddity> {
    let shortest_len = 1 + shortest_arg_width(v);
    if header_len <= shortest_len {
        return None;
    }
    let value_repr = if is_negative {
        format!("{}", -(v as i128) - 1)
    } else {
        v.to_string()
    };
    Some(oddity(
        OddityKind::IntNotShortest,
        format!(
            "value {} uses {}-byte header, shortest is {}",
            value_repr, header_len, shortest_len
        ),
    ))
}

/// Shortest width (in bytes, including the initial byte) that losslessly encodes
/// a **finite non-NaN** float. NaN is intentionally not canonicalised here.
fn shortest_float_len(v: f64) -> usize {
    if v.is_nan() || !v.is_finite() {
        return 9;
    }
    if f64_fits_f16_exactly(v) {
        3
    } else if (v as f32) as f64 == v {
        5
    } else {
        9
    }
}

/// True iff `v` is exactly representable in IEEE-754 binary16.
fn f64_fits_f16_exactly(v: f64) -> bool {
    if (v as f32) as f64 != v {
        return false;
    }
    let f = v as f32;
    // f16: sign(1) | exp(5, bias 15) | mant(10)
    let bits = f.to_bits();
    let sign = (bits >> 31) & 0x1;
    let exp = ((bits >> 23) & 0xff) as i32;
    let mant = bits & 0x7fffff;

    if exp == 0 && mant == 0 {
        // Signed zero — representable.
        let _ = sign;
        return true;
    }
    if exp == 0xff {
        // Inf (representable) or NaN (caller filtered NaN out).
        return mant == 0;
    }
    let e = exp - 127;
    if e > 15 {
        return false; // overflow
    }
    if e >= -14 {
        // Normal f16: lower 13 mantissa bits must be zero.
        return mant & 0x1fff == 0;
    }
    // Subnormal f16: scale implicit leading 1 into the mantissa.
    if e < -24 {
        return false; // too small even for subnormal
    }
    let full_mant = (1u32 << 23) | mant;
    let extra_shift = (-14 - e) as u32; // 1..=10
    let total_low_bits = 13 + extra_shift;
    let mask = (1u64 << total_low_bits) - 1;
    (full_mant as u64) & mask == 0
}

fn float_not_shortest(v: f64, header_len: usize) -> Option<Oddity> {
    if v.is_nan() {
        return None; // NaN canonicalisation skipped (decoder rejects NaN anyway).
    }
    let shortest = shortest_float_len(v);
    if header_len <= shortest {
        return None;
    }
    Some(oddity(
        OddityKind::FloatNotShortest,
        format!(
            "value {} uses {}-byte encoding, shortest is {}",
            v, header_len, shortest
        ),
    ))
}

/// Decode CBOR bytes into the positional JSON tree for `cbor_to_json`.
///
/// Success and error `partial` trees are [`DeepJson`] (up to
/// [`MAX_CBOR_DECODE_NESTING_DEPTH`]) so drop costs no stack per level.
pub fn decode_cbor_to_value(bytes: &[u8]) -> DecodeResult<DeepJson> {
    let mut decoder = Decoder::from(Cursor::new(bytes));
    let mut path: Path = Vec::new();
    let value = decode_item(&mut decoder, bytes, &mut path)?;
    let trailing = decoder.offset();
    if trailing != bytes.len() {
        // Valid root becomes `partial` when trailing bytes remain.
        return Err(err::trailing_data(trailing, bytes.len() - trailing).with_partial(value));
    }
    Ok(DeepJson::new(value))
}

/// Mark a container value as only partially decoded. Consumers (JS side)
/// can combine this with `error.path` to find exactly where the decode
/// stopped and what was successfully parsed so far.
fn mark_incomplete(mut obj: Map<String, Value>) -> Value {
    obj.insert("incomplete".into(), Value::Bool(true));
    Value::Object(obj)
}

/// The positional object of an array or map: the span of its header,
/// the span of the whole item, its declared count and its items.
fn container_object(
    type_name: &str,
    start: usize,
    header_end: usize,
    end: usize,
    len: Option<usize>,
    values: Vec<Value>,
) -> Map<String, Value> {
    let mut obj = Map::new();
    obj.insert("type".into(), Value::String(type_name.into()));
    obj.insert(
        "position_info".into(),
        Pos::new(start, header_end).to_value(),
    );
    obj.insert(
        "struct_position_info".into(),
        Pos::new(start, end).to_value(),
    );
    obj.insert(
        "items".into(),
        match len {
            Some(n) => Value::Number(n.into()),
            None => Value::String("Indefinite".into()),
        },
    );
    obj.insert("values".into(), Value::Array(values));
    obj
}

fn partial_array(
    start: usize,
    header_end: usize,
    values_end: usize,
    values: Vec<Value>,
    len: Option<usize>,
) -> Value {
    mark_incomplete(container_object(
        "Array", start, header_end, values_end, len, values,
    ))
}

fn partial_map(
    start: usize,
    header_end: usize,
    values_end: usize,
    entries: Vec<Value>,
    len: Option<usize>,
) -> Value {
    mark_incomplete(container_object(
        "Map", start, header_end, values_end, len, entries,
    ))
}

fn partial_chunks(
    start: usize,
    header_end: usize,
    chunks_end: usize,
    chunks: Vec<Value>,
    kind: ChunkKind,
) -> Value {
    let mut obj = Map::new();
    obj.insert("type".into(), Value::String(kind.type_name().into()));
    obj.insert(
        "position_info".into(),
        Pos::new(start, header_end).to_value(),
    );
    obj.insert(
        "struct_position_info".into(),
        Pos::new(start, chunks_end).to_value(),
    );
    obj.insert("chunks".into(), Value::Array(chunks));
    mark_incomplete(obj)
}

/// The positional object of a tag, without the item it wraps.
fn tag_object(start: usize, header_end: usize, end: usize, tag: u64) -> Map<String, Value> {
    let mut obj = Map::new();
    obj.insert("type".into(), Value::String("Tag".into()));
    obj.insert(
        "position_info".into(),
        Pos::new(start, header_end).to_value(),
    );
    obj.insert(
        "struct_position_info".into(),
        Pos::new(start, end).to_value(),
    );
    obj.insert("tag".into(), Value::String(tag_name(tag)));
    obj
}

fn partial_tag(
    start: usize,
    header_end: usize,
    inner_end: usize,
    tag: u64,
    inner: Option<Value>,
) -> Value {
    let mut obj = tag_object(start, header_end, inner_end, tag);
    if let Some(inner) = inner {
        obj.insert("value".into(), inner);
    }
    mark_incomplete(obj)
}

fn partial_map_entry(key: Option<Value>, value: Option<Value>, failing_side: Side) -> Value {
    let mut entry = Map::new();
    if let Some(k) = key {
        entry.insert("key".into(), k);
    }
    if let Some(v) = value {
        entry.insert("value".into(), v);
    }
    entry.insert(
        "incomplete_at".into(),
        Value::String(match failing_side {
            Side::Key => "key".into(),
            Side::Value => "value".into(),
        }),
    );
    entry.insert("incomplete".into(), Value::Bool(true));
    Value::Object(entry)
}

fn map_entry(key: Value, value: Value) -> Value {
    let mut entry = Map::new();
    entry.insert("key".into(), key);
    entry.insert("value".into(), value);
    Value::Object(entry)
}

/// Open container while its items are decoded (heap stack frame).
///
/// Depth is bounded by [`MAX_CBOR_DECODE_NESTING_DEPTH`]. `path` length
/// matches open-container count (one segment per level).
enum Open {
    Array {
        start: usize,
        header_end: usize,
        len: Option<usize>,
        values: Vec<Value>,
    },
    Map {
        start: usize,
        header_end: usize,
        len: Option<usize>,
        entries: Vec<Value>,
        /// `(start, end)` of every key decoded so far, for the ordering
        /// and duplicate checks run when the map closes.
        key_spans: Vec<(usize, usize)>,
        /// Where the key of the entry being decoded starts.
        key_start: usize,
        /// The key of the entry being decoded and the offset it ends
        /// at, from when it completes until its value does.
        key: Option<(Value, usize)>,
    },
    Tag {
        start: usize,
        header_end: usize,
        tag: u64,
    },
}

/// What one header decoded to.
enum Decoded {
    /// A complete item.
    Item(Value),
    /// A container whose items follow. Its frame is on the stack and
    /// `path` names its first item.
    Opened,
}

fn decode_item(
    decoder: &mut CborDecoder<'_>,
    bytes: &[u8],
    path: &mut Path,
) -> DecodeResult<Value> {
    let mut open: Vec<Open> = Vec::new();
    loop {
        // The item at the level `path` names.
        let start = decoder.offset();
        // Policy depth limit; unwind keeps the partial tree.
        if path.len() > MAX_CBOR_DECODE_NESTING_DEPTH {
            let error = err::nesting_too_deep(path, start, MAX_CBOR_DECODE_NESTING_DEPTH);
            return Err(unwind(error, open, path, decoder.offset()));
        }
        let decoded = pull_header(decoder, path)
            .and_then(|header| decode_header(header, decoder, bytes, start, path, &mut open));
        let mut done = match decoded {
            Ok(Decoded::Item(value)) => value,
            Ok(Decoded::Opened) => continue,
            Err(error) => return Err(unwind(error, open, path, decoder.offset())),
        };

        // Attach to parent; close completed containers outward.
        loop {
            let Some(top) = open.last_mut() else {
                return Ok(done);
            };
            path.pop();
            match top {
                Open::Array { values, .. } => values.push(done),
                Open::Map {
                    entries,
                    key_spans,
                    key_start,
                    key,
                    ..
                } => match key.take() {
                    None => {
                        *key = Some((done, decoder.offset()));
                        path.push(PathSeg::MapEntry(entries.len(), Side::Value));
                        break;
                    }
                    Some((key, key_end)) => {
                        entries.push(map_entry(key, done));
                        key_spans.push((*key_start, key_end));
                    }
                },
                Open::Tag {
                    start,
                    header_end,
                    tag,
                } => {
                    let (start, header_end, tag) = (*start, *header_end, *tag);
                    open.pop();
                    done = tag_value(start, header_end, decoder.offset(), tag, done);
                    continue;
                }
            }
            match advance(top, decoder, bytes, path) {
                Ok(None) => break,
                Ok(Some(value)) => {
                    open.pop();
                    done = value;
                }
                Err(error) => return Err(unwind(error, open, path, decoder.offset())),
            }
        }
    }
}

fn decode_header(
    header: Header,
    decoder: &mut CborDecoder<'_>,
    bytes: &[u8],
    start: usize,
    path: &mut Path,
    open: &mut Vec<Open>,
) -> DecodeResult<Decoded> {
    let header_end = decoder.offset();
    let item = match header {
        Header::Positive(v) => {
            let pos = Pos::new(start, header_end);
            let token = simple_token(
                positive_type_name(start, header_end),
                Value::Number(v.into()),
                pos,
            );
            let odd = int_not_shortest(v, header_end - start, false)
                .into_iter()
                .collect();
            attach_oddities(token, odd)
        }
        Header::Negative(v) => {
            let token = negative_value(v, start, header_end, path)?;
            let odd = int_not_shortest(v, header_end - start, true)
                .into_iter()
                .collect();
            attach_oddities(token, odd)
        }
        Header::Float(f) => {
            let pos = Pos::new(start, header_end);
            let token = simple_token(
                float_type_name(start, header_end),
                number_from_f64(f, start, path)?,
                pos,
            );
            let odd = float_not_shortest(f, header_end - start)
                .into_iter()
                .collect();
            attach_oddities(token, odd)
        }
        Header::Simple(simple::FALSE) => {
            simple_token("Bool", Value::Bool(false), Pos::new(start, header_end))
        }
        Header::Simple(simple::TRUE) => {
            simple_token("Bool", Value::Bool(true), Pos::new(start, header_end))
        }
        Header::Simple(simple::NULL) => {
            simple_token("Null", Value::Null, Pos::new(start, header_end))
        }
        Header::Simple(simple::UNDEFINED) => {
            simple_token("Undefined", Value::Null, Pos::new(start, header_end))
        }
        Header::Simple(v) => simple_token(
            "Simple",
            Value::Number(v.into()),
            Pos::new(start, header_end),
        ),
        Header::Break => return Err(err::unexpected_break(path, start)),
        Header::Bytes(Some(len)) => {
            let body = read_exact(decoder, len, path)?;
            let end = decoder.offset();
            simple_token(
                "Bytes",
                Value::String(hex::encode(&body)),
                Pos::new(start, end),
            )
        }
        Header::Bytes(None) => decode_indefinite_chunks(decoder, start, ChunkKind::Bytes, path)?,
        Header::Text(Some(len)) => {
            let body = read_exact(decoder, len, path)?;
            let end = decoder.offset();
            let text =
                String::from_utf8(body).map_err(|_| err::invalid_utf8(path, start, end - start))?;
            simple_token("String", Value::String(text), Pos::new(start, end))
        }
        Header::Text(None) => decode_indefinite_chunks(decoder, start, ChunkKind::Text, path)?,
        Header::Array(len) => {
            let frame = Open::Array {
                start,
                header_end,
                len,
                values: Vec::new(),
            };
            return open_frame(frame, open, decoder, bytes, path);
        }
        Header::Map(len) => {
            let frame = Open::Map {
                start,
                header_end,
                len,
                entries: Vec::new(),
                key_spans: Vec::new(),
                key_start: header_end,
                key: None,
            };
            return open_frame(frame, open, decoder, bytes, path);
        }
        Header::Tag(tag) => {
            let frame = Open::Tag {
                start,
                header_end,
                tag,
            };
            return open_frame(frame, open, decoder, bytes, path);
        }
    };
    Ok(Decoded::Item(item))
}

/// Put `frame` on the stack and step it to its first item, or close it
/// at once when it has none.
fn open_frame(
    mut frame: Open,
    open: &mut Vec<Open>,
    decoder: &mut CborDecoder<'_>,
    bytes: &[u8],
    path: &mut Path,
) -> DecodeResult<Decoded> {
    match advance(&mut frame, decoder, bytes, path) {
        Ok(None) => {
            open.push(frame);
            Ok(Decoded::Opened)
        }
        Ok(Some(value)) => Ok(Decoded::Item(value)),
        // Keep the frame so unwind can report a partial container.
        Err(error) => {
            open.push(frame);
            Err(error)
        }
    }
}

/// Step an open container on. Pushes the path segment of the next item
/// it takes and returns `None`, or returns its value once it has taken
/// them all, leaving the frame emptied for the caller to pop.
fn advance(
    frame: &mut Open,
    decoder: &mut CborDecoder<'_>,
    bytes: &[u8],
    path: &mut Path,
) -> DecodeResult<Option<Value>> {
    match frame {
        Open::Array {
            start,
            header_end,
            len,
            values,
        } => match next_index(*len, values, decoder, bytes, path)? {
            Some(i) => {
                path.push(PathSeg::ArrayIdx(i));
                Ok(None)
            }
            None => {
                let values = mem::take(values);
                Ok(Some(array_value(
                    *start,
                    *header_end,
                    decoder.offset(),
                    values,
                    *len,
                )))
            }
        },
        Open::Map {
            start,
            header_end,
            len,
            entries,
            key_spans,
            key_start,
            ..
        } => match next_index(*len, entries, decoder, bytes, path)? {
            Some(i) => {
                *key_start = decoder.offset();
                path.push(PathSeg::MapEntry(i, Side::Key));
                Ok(None)
            }
            None => {
                let entries = mem::take(entries);
                let key_spans = mem::take(key_spans);
                Ok(Some(map_value(
                    bytes,
                    *start,
                    *header_end,
                    decoder.offset(),
                    entries,
                    key_spans,
                    *len,
                )))
            }
        },
        Open::Tag { .. } => {
            path.push(PathSeg::TagInner);
            Ok(None)
        }
    }
}

/// The index of the next item a container takes, or `None` once it has
/// taken them all: its declared count of them, or the break that ends
/// an indefinite one, which is kept as its last item.
fn next_index(
    len: Option<usize>,
    items: &mut Vec<Value>,
    decoder: &mut CborDecoder<'_>,
    bytes: &[u8],
    path: &mut Path,
) -> DecodeResult<Option<usize>> {
    let next = items.len();
    match len {
        Some(n) => Ok((next < n).then_some(next)),
        None => match consume_break(decoder, bytes, path)? {
            Some(pos) => {
                items.push(simple_token("Break", Value::Null, pos));
                Ok(None)
            }
            None => Ok(Some(next)),
        },
    }
}

/// Fold open containers into the error's partial tree (innermost first).
fn unwind(
    mut error: CborDecodeError,
    open: Vec<Open>,
    path: &[PathSeg],
    end: usize,
) -> CborDecodeError {
    let mut partial = error.partial.take().map(DeepJson::into_inner);
    for (level, frame) in open.into_iter().enumerate().rev() {
        partial = Some(match frame {
            Open::Array {
                start,
                header_end,
                len,
                mut values,
            } => {
                if let Some(inner) = partial {
                    values.push(inner);
                }
                partial_array(start, header_end, end, values, len)
            }
            Open::Map {
                start,
                header_end,
                len,
                mut entries,
                key,
                ..
            } => {
                // Partial map entry: value if key held, else key if on path.
                if let Some((key, _)) = key {
                    entries.push(partial_map_entry(Some(key), partial, Side::Value));
                } else if path.len() > level {
                    entries.push(partial_map_entry(partial, None, Side::Key));
                }
                partial_map(start, header_end, end, entries, len)
            }
            Open::Tag {
                start,
                header_end,
                tag,
            } => partial_tag(start, header_end, end, tag, partial),
        });
    }
    error.partial = partial.map(DeepJson::new);
    error
}

fn array_value(
    start: usize,
    header_end: usize,
    end: usize,
    values: Vec<Value>,
    len: Option<usize>,
) -> Value {
    let oddities = if len.is_none() {
        vec![oddity(
            OddityKind::IndefiniteLength,
            "indefinite-length array",
        )]
    } else {
        Vec::new()
    };
    let obj = container_object("Array", start, header_end, end, len, values);
    attach_oddities(Value::Object(obj), oddities)
}

fn map_value(
    bytes: &[u8],
    start: usize,
    header_end: usize,
    end: usize,
    entries: Vec<Value>,
    key_spans: Vec<(usize, usize)>,
    len: Option<usize>,
) -> Value {
    let mut oddities: Vec<Oddity> = Vec::new();
    if len.is_none() {
        oddities.push(oddity(
            OddityKind::IndefiniteLength,
            "indefinite-length map",
        ));
    }
    if let Some(detail) = map_keys_not_sorted_detail(bytes, &key_spans) {
        oddities.push(oddity(OddityKind::MapKeysNotSorted, detail));
    }
    if let Some(detail) = duplicate_map_keys_detail(bytes, &key_spans) {
        oddities.push(oddity(OddityKind::DuplicateMapKeys, detail));
    }
    let obj = container_object("Map", start, header_end, end, len, entries);
    attach_oddities(Value::Object(obj), oddities)
}

fn map_keys_not_sorted_detail(bytes: &[u8], spans: &[(usize, usize)]) -> Option<String> {
    for pair in spans.windows(2) {
        let a = &bytes[pair[0].0..pair[0].1];
        let b = &bytes[pair[1].0..pair[1].1];
        if a > b {
            return Some(format!(
                "key at offset {} sorts after key at offset {}",
                pair[0].0, pair[1].0
            ));
        }
    }
    None
}

fn duplicate_map_keys_detail(bytes: &[u8], spans: &[(usize, usize)]) -> Option<String> {
    for (i, (ai, aj)) in spans.iter().enumerate() {
        for (bi, bj) in spans.iter().skip(i + 1) {
            if &bytes[*ai..*aj] == &bytes[*bi..*bj] {
                return Some(format!("duplicate key at offsets {} and {}", ai, bi));
            }
        }
    }
    None
}

fn tag_value(start: usize, header_end: usize, end: usize, tag: u64, inner: Value) -> Value {
    let oddities = bignum_oddities(tag, &inner);
    let mut obj = tag_object(start, header_end, end, tag);
    obj.insert("value".into(), inner);
    attach_oddities(Value::Object(obj), oddities)
}

/// Analyse a tag-2 (unsigned bignum) or tag-3 (negative bignum) payload for
/// canonical-form violations on the **outer tag node**.
fn bignum_oddities(tag: u64, inner: &Value) -> Vec<Oddity> {
    if tag != 2 && tag != 3 {
        return Vec::new();
    }
    let Some(hex_str) = inner
        .get("type")
        .and_then(Value::as_str)
        .filter(|t| *t == "Bytes")
        .and(inner.get("value"))
        .and_then(Value::as_str)
    else {
        return Vec::new();
    };
    let Ok(raw) = hex::decode(hex_str) else {
        return Vec::new();
    };

    let mut out = Vec::new();

    if raw.first() == Some(&0) {
        out.push(oddity(
            OddityKind::BignumLeadingZeroes,
            format!(
                "bignum byte string starts with {} zero byte(s)",
                leading_zero_count(&raw)
            ),
        ));
    }

    // A value fits in major-type 0/1 iff its unsigned magnitude is < 2^64.
    // For tag 2 the magnitude is the bytes as-is; for tag 3 it's bytes+1 (still < 2^64 when len <= 8 and not all-ones).
    if fits_native_cbor_int(tag, &raw) {
        let kind = if tag == 2 { "unsigned" } else { "negative" };
        out.push(oddity(
            OddityKind::BignumForSmallInt,
            format!(
                "{} bignum fits in a native CBOR integer ({} content bytes)",
                kind,
                raw.len()
            ),
        ));
    }

    out
}

fn leading_zero_count(raw: &[u8]) -> usize {
    raw.iter().take_while(|b| **b == 0).count()
}

fn fits_native_cbor_int(tag: u64, raw: &[u8]) -> bool {
    // Strip leading zeroes to compare magnitudes.
    let trimmed: &[u8] = {
        let mut i = 0;
        while i < raw.len() && raw[i] == 0 {
            i += 1;
        }
        &raw[i..]
    };
    if trimmed.len() > 8 {
        return false;
    }
    let mut magnitude: u64 = 0;
    for b in trimmed {
        magnitude = (magnitude << 8) | u64::from(*b);
    }
    match tag {
        2 => true,                 // any magnitude < 2^64 fits in Positive
        3 => magnitude < u64::MAX, // tag-3 encodes -(magnitude+1); needs magnitude+1 <= u64::MAX
        _ => false,
    }
}

#[derive(Clone, Copy)]
enum ChunkKind {
    Bytes,
    Text,
}

impl ChunkKind {
    fn type_name(self) -> &'static str {
        match self {
            ChunkKind::Bytes => "IndefiniteLengthBytes",
            ChunkKind::Text => "IndefiniteLengthString",
        }
    }

    fn chunk_type(self) -> &'static str {
        match self {
            ChunkKind::Bytes => "Bytes",
            ChunkKind::Text => "String",
        }
    }

    fn oddity_detail(self) -> &'static str {
        match self {
            ChunkKind::Bytes => "indefinite-length byte string",
            ChunkKind::Text => "indefinite-length text string",
        }
    }
}

fn decode_indefinite_chunks(
    decoder: &mut CborDecoder<'_>,
    start: usize,
    kind: ChunkKind,
    path: &mut Path,
) -> DecodeResult<Value> {
    let header_end = decoder.offset();
    let mut chunks = Vec::new();
    let mut chunk_idx = 0usize;
    loop {
        let chunk_start = decoder.offset();
        path.push(PathSeg::Chunk(chunk_idx));
        let header = match pull_header(decoder, path) {
            Ok(h) => h,
            Err(e) => {
                path.pop();
                let partial = partial_chunks(start, header_end, decoder.offset(), chunks, kind);
                return Err(e.with_partial(partial));
            }
        };
        let hdr_end = decoder.offset();
        match (kind, header) {
            (_, Header::Break) => {
                // Break is a terminator, not a chunk — drop the chunk[i] path
                // segment we just pushed.
                path.pop();
                let break_end = decoder.offset();
                chunks.push(simple_token(
                    "Break",
                    Value::Null,
                    Pos::new(chunk_start, break_end),
                ));
                break;
            }
            (ChunkKind::Bytes, Header::Bytes(Some(len))) => {
                match read_exact(decoder, len, path) {
                    Ok(body) => {
                        let end = decoder.offset();
                        chunks.push(simple_token(
                            kind.chunk_type(),
                            Value::String(hex::encode(&body)),
                            Pos::new(chunk_start, end),
                        ));
                        path.pop();
                    }
                    Err(e) => {
                        path.pop();
                        let partial =
                            partial_chunks(start, header_end, decoder.offset(), chunks, kind);
                        return Err(e.with_partial(partial));
                    }
                }
                let _ = hdr_end;
            }
            (ChunkKind::Text, Header::Text(Some(len))) => {
                match read_exact(decoder, len, path) {
                    Ok(body) => {
                        let end = decoder.offset();
                        match String::from_utf8(body) {
                            Ok(text) => {
                                chunks.push(simple_token(
                                    kind.chunk_type(),
                                    Value::String(text),
                                    Pos::new(chunk_start, end),
                                ));
                                path.pop();
                            }
                            Err(_) => {
                                let e = err::invalid_utf8(path, chunk_start, end - chunk_start);
                                path.pop();
                                let partial = partial_chunks(
                                    start,
                                    header_end,
                                    decoder.offset(),
                                    chunks,
                                    kind,
                                );
                                return Err(e.with_partial(partial));
                            }
                        }
                    }
                    Err(e) => {
                        path.pop();
                        let partial =
                            partial_chunks(start, header_end, decoder.offset(), chunks, kind);
                        return Err(e.with_partial(partial));
                    }
                }
                let _ = hdr_end;
            }
            _ => {
                let e = err::invalid_chunk(
                    path,
                    chunk_start,
                    match kind {
                        ChunkKind::Bytes => "bytes",
                        ChunkKind::Text => "text",
                    },
                );
                path.pop();
                let partial = partial_chunks(start, header_end, decoder.offset(), chunks, kind);
                return Err(e.with_partial(partial));
            }
        }
        chunk_idx += 1;
    }
    let end = decoder.offset();
    let mut obj = Map::new();
    obj.insert("type".into(), Value::String(kind.type_name().into()));
    obj.insert(
        "position_info".into(),
        Pos::new(start, header_end).to_value(),
    );
    obj.insert(
        "struct_position_info".into(),
        Pos::new(start, end).to_value(),
    );
    obj.insert("chunks".into(), Value::Array(chunks));

    let oddities = vec![oddity(OddityKind::IndefiniteLength, kind.oddity_detail())];
    Ok(attach_oddities(Value::Object(obj), oddities))
}

fn simple_token(type_name: &str, value: Value, pos: Pos) -> Value {
    let mut obj = Map::new();
    obj.insert("type".into(), Value::String(type_name.into()));
    obj.insert("position_info".into(), pos.to_value());
    obj.insert("value".into(), value);
    Value::Object(obj)
}

fn negative_value(v: u64, start: usize, end: usize, path: &[PathSeg]) -> DecodeResult<Value> {
    let signed = i128::from(v) ^ !0;
    let pos = Pos::new(start, end);
    let type_name = negative_type_name(start, end, signed);

    let number = if let Ok(fits) = i64::try_from(signed) {
        Value::Number(fits.into())
    } else {
        Number::from_i128(signed)
            .map(Value::Number)
            .ok_or_else(|| err::int_not_representable(path, start, signed))?
    };

    Ok(simple_token(type_name, number, pos))
}

fn positive_type_name(start: usize, end: usize) -> &'static str {
    match end - start {
        1 | 2 => "U8",
        3 => "U16",
        5 => "U32",
        _ => "U64",
    }
}

fn negative_type_name(start: usize, end: usize, value: i128) -> &'static str {
    let width = end - start;
    let fits_i8 = value >= i8::MIN as i128;
    let fits_i16 = value >= i16::MIN as i128;
    let fits_i32 = value >= i32::MIN as i128;
    let fits_i64 = value >= i64::MIN as i128;
    match width {
        1 | 2 if fits_i8 => "I8",
        3 if fits_i16 => "I16",
        5 if fits_i32 => "I32",
        9 if fits_i64 => "I64",
        _ => "Int",
    }
}

fn float_type_name(start: usize, end: usize) -> &'static str {
    match end - start {
        3 => "F16",
        5 => "F32",
        _ => "F64",
    }
}

fn number_from_f64(f: f64, offset: usize, path: &[PathSeg]) -> DecodeResult<Value> {
    Number::from_f64(f)
        .map(Value::Number)
        .ok_or_else(|| err::non_finite_float(path, offset))
}

/// The break marker that ends an indefinite-length container
/// (RFC 8949 §3.2.1).
const BREAK: u8 = 0xff;

/// Consume a following break (`0xff`), if present.
///
/// Peeks the raw byte — do not pull-and-unpull: non-shortest headers
/// rewind by the wrong length and corrupt later offsets (RFC 8949 §3).
fn consume_break(
    decoder: &mut CborDecoder<'_>,
    bytes: &[u8],
    path: &mut Path,
) -> DecodeResult<Option<Pos>> {
    let before = decoder.offset();
    match bytes.get(before) {
        Some(&BREAK) => {
            pull_header(decoder, path)?;
            Ok(Some(Pos::new(before, decoder.offset())))
        }
        Some(_) => Ok(None),
        // Out of input: let the pull report the truncation, so the
        // container ends the same way it always has.
        None => {
            pull_header(decoder, path)?;
            Ok(None)
        }
    }
}

fn pull_header(decoder: &mut CborDecoder<'_>, path: &[PathSeg]) -> DecodeResult<Header> {
    let before = decoder.offset();
    decoder.pull().map_err(|e| map_cbor_error(e, before, path))
}

/// Payload read/alloc chunk size — never allocate a declared length up front.
const READ_CHUNK: usize = 64 * 1024;

fn read_exact(
    decoder: &mut CborDecoder<'_>,
    len: usize,
    path: &[PathSeg],
) -> DecodeResult<Vec<u8>> {
    let before = decoder.offset();
    let mut buf: Vec<u8> = Vec::new();
    while buf.len() < len {
        let filled = buf.len();
        let step = (len - filled).min(READ_CHUNK);
        buf.resize(filled + step, 0);
        if let Err(e) = decoder.read_exact(&mut buf[filled..]) {
            return Err(if e.kind() == std::io::ErrorKind::UnexpectedEof {
                err::unexpected_eof(path, before)
            } else {
                err::io(path, Some(before), e.to_string())
            });
        }
    }
    Ok(buf)
}

fn map_cbor_error(
    error: CborError<std::io::Error>,
    start: usize,
    path: &[PathSeg],
) -> CborDecodeError {
    match error {
        CborError::Syntax(offset) => err::invalid_syntax(path, offset),
        CborError::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            err::unexpected_eof(path, start)
        }
        CborError::Io(e) => err::io(path, Some(start), e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_cbor_to_value, CborDecodeError, MAX_CBOR_DECODE_NESTING_DEPTH};
    use crate::cbor::errors::ErrorKind;
    use serde_json::{json, Value};

    fn decode(hex: &str) -> Value {
        let bytes = hex::decode(hex).expect("invalid test hex");
        decode_cbor_to_value(&bytes)
            .expect("decode failed")
            .into_inner()
    }

    fn decode_err(hex: &str) -> CborDecodeError {
        let bytes = hex::decode(hex).expect("invalid test hex");
        decode_cbor_to_value(&bytes)
            .err()
            .expect("expected decode error")
    }

    fn oddity_kinds(v: &Value) -> Vec<String> {
        v.get("oddities")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|o| o.get("kind").and_then(Value::as_str))
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn positive_int_widths_are_derived_from_wire_encoding() {
        assert_eq!(
            decode("00"),
            json!({"type": "U8", "position_info": {"offset": 0, "length": 1}, "value": 0})
        );
        assert_eq!(
            decode("1818"),
            json!({"type": "U8", "position_info": {"offset": 0, "length": 2}, "value": 24})
        );
        assert_eq!(
            decode("190100"),
            json!({"type": "U16", "position_info": {"offset": 0, "length": 3}, "value": 256})
        );
        assert_eq!(
            decode("1a00010000"),
            json!({"type": "U32", "position_info": {"offset": 0, "length": 5}, "value": 65536})
        );
        assert_eq!(
            decode("1b0000000100000000"),
            json!({
                "type": "U64",
                "position_info": {"offset": 0, "length": 9},
                "value": 4294967296u64
            })
        );
    }

    #[test]
    fn negative_int_widths_map_to_signed_types() {
        assert_eq!(
            decode("20"),
            json!({"type": "I8", "position_info": {"offset": 0, "length": 1}, "value": -1})
        );
        assert_eq!(
            decode("3818"),
            json!({"type": "I8", "position_info": {"offset": 0, "length": 2}, "value": -25})
        );
        assert_eq!(
            decode("390100"),
            json!({"type": "I16", "position_info": {"offset": 0, "length": 3}, "value": -257})
        );
        assert_eq!(
            decode("3a00010000"),
            json!({"type": "I32", "position_info": {"offset": 0, "length": 5}, "value": -65537})
        );
        assert_eq!(
            decode("3b0000000100000000"),
            json!({
                "type": "I64",
                "position_info": {"offset": 0, "length": 9},
                "value": -4294967297i64
            })
        );
    }

    #[test]
    fn negative_int_outside_i64_uses_int_type() {
        // 3bffffffffffffffff = -18446744073709551616 (i64::MIN - 1 range)
        assert_eq!(
            decode("3bffffffffffffffff"),
            json!({
                "type": "Int",
                "position_info": {"offset": 0, "length": 9},
                "value": -18446744073709551616i128
            })
        );
    }

    #[test]
    fn simple_value_bool_null_and_undefined() {
        assert_eq!(
            decode("f4"),
            json!({"type": "Bool", "position_info": {"offset": 0, "length": 1}, "value": false})
        );
        assert_eq!(
            decode("f5"),
            json!({"type": "Bool", "position_info": {"offset": 0, "length": 1}, "value": true})
        );
        assert_eq!(
            decode("f6"),
            json!({"type": "Null", "position_info": {"offset": 0, "length": 1}, "value": null})
        );
        assert_eq!(
            decode("f7"),
            json!({
                "type": "Undefined",
                "position_info": {"offset": 0, "length": 1},
                "value": null
            })
        );
    }

    #[test]
    fn simple_value_unreserved_keeps_simple_tag() {
        // 0xf0 = simple(16)
        assert_eq!(
            decode("f0"),
            json!({
                "type": "Simple",
                "position_info": {"offset": 0, "length": 1},
                "value": 16
            })
        );
    }

    #[test]
    fn float_widths_are_distinguished() {
        // f93c00 = half-precision 1.0
        assert_eq!(
            decode("f93c00"),
            json!({"type": "F16", "position_info": {"offset": 0, "length": 3}, "value": 1.0})
        );
    }

    #[test]
    fn non_finite_floats_produce_error() {
        // f97c00 = +Infinity half-precision — serde_json::Number rejects non-finite.
        let e = decode_err("f97c00");
        assert_eq!(e.kind, ErrorKind::NonFiniteFloat);
        assert_eq!(e.offset, Some(0));
        assert_eq!(e.path, "$");
    }

    #[test]
    fn definite_bytes_round_trip_as_hex_string() {
        // 4401020304 = bytes(0x01020304)
        assert_eq!(
            decode("4401020304"),
            json!({
                "type": "Bytes",
                "position_info": {"offset": 0, "length": 5},
                "value": "01020304"
            })
        );
    }

    #[test]
    fn empty_text_string() {
        assert_eq!(
            decode("60"),
            json!({
                "type": "String",
                "position_info": {"offset": 0, "length": 1},
                "value": ""
            })
        );
    }

    #[test]
    fn text_string_contents_and_position() {
        // 6568656c6c6f = "hello"
        assert_eq!(
            decode("6568656c6c6f"),
            json!({
                "type": "String",
                "position_info": {"offset": 0, "length": 6},
                "value": "hello"
            })
        );
    }

    #[test]
    fn text_string_with_invalid_utf8_is_rejected() {
        // 62c328 is a text header of length 2 followed by invalid UTF-8 bytes
        let e = decode_err("62c328");
        assert_eq!(e.kind, ErrorKind::InvalidUtf8);
        assert_eq!(e.offset, Some(0));
        assert_eq!(e.byte_span, Some((0, 3)));
        assert_eq!(e.path, "$");
    }

    #[test]
    fn definite_array_tracks_items_count_and_struct_position() {
        // 83010203 = [1, 2, 3]
        assert_eq!(
            decode("83010203"),
            json!({
                "type": "Array",
                "position_info": {"offset": 0, "length": 1},
                "struct_position_info": {"offset": 0, "length": 4},
                "items": 3,
                "values": [
                    {"type": "U8", "position_info": {"offset": 1, "length": 1}, "value": 1},
                    {"type": "U8", "position_info": {"offset": 2, "length": 1}, "value": 2},
                    {"type": "U8", "position_info": {"offset": 3, "length": 1}, "value": 3},
                ]
            })
        );
    }

    #[test]
    fn empty_map() {
        assert_eq!(
            decode("a0"),
            json!({
                "type": "Map",
                "position_info": {"offset": 0, "length": 1},
                "struct_position_info": {"offset": 0, "length": 1},
                "items": 0,
                "values": []
            })
        );
    }

    #[test]
    fn definite_map_entries_preserve_key_order() {
        // a26161016162820203 = {"a": 1, "b": [2, 3]}
        assert_eq!(
            decode("a26161016162820203"),
            json!({
                "type": "Map",
                "position_info": {"offset": 0, "length": 1},
                "struct_position_info": {"offset": 0, "length": 9},
                "items": 2,
                "values": [
                    {
                        "key": {"type": "String", "position_info": {"offset": 1, "length": 2}, "value": "a"},
                        "value": {"type": "U8", "position_info": {"offset": 3, "length": 1}, "value": 1},
                    },
                    {
                        "key": {"type": "String", "position_info": {"offset": 4, "length": 2}, "value": "b"},
                        "value": {
                            "type": "Array",
                            "position_info": {"offset": 6, "length": 1},
                            "struct_position_info": {"offset": 6, "length": 3},
                            "items": 2,
                            "values": [
                                {"type": "U8", "position_info": {"offset": 7, "length": 1}, "value": 2},
                                {"type": "U8", "position_info": {"offset": 8, "length": 1}, "value": 3},
                            ]
                        },
                    }
                ]
            })
        );
    }

    #[test]
    fn known_tag_is_named() {
        // c0_6474657374 = Tag(0, "test")
        assert_eq!(
            decode("c06474657374"),
            json!({
                "type": "Tag",
                "position_info": {"offset": 0, "length": 1},
                "struct_position_info": {"offset": 0, "length": 6},
                "tag": "DateTime",
                "value": {
                    "type": "String",
                    "position_info": {"offset": 1, "length": 5},
                    "value": "test"
                }
            })
        );
    }

    #[test]
    fn unassigned_tag_falls_back_to_unassigned_label() {
        // d8_66_01 = Tag(102, 1) — not in the named list
        assert_eq!(
            decode("d86601"),
            json!({
                "type": "Tag",
                "position_info": {"offset": 0, "length": 2},
                "struct_position_info": {"offset": 0, "length": 3},
                "tag": "Unassigned(102)",
                "value": {"type": "U8", "position_info": {"offset": 2, "length": 1}, "value": 1}
            })
        );
    }

    #[test]
    fn trailing_bytes_produce_error() {
        let e = decode_err("0100");
        assert_eq!(e.kind, ErrorKind::TrailingData);
        assert_eq!(e.offset, Some(1));
        assert_eq!(e.byte_span, Some((1, 1)));
    }

    #[test]
    fn unexpected_break_produces_error() {
        let e = decode_err("ff");
        assert_eq!(e.kind, ErrorKind::UnexpectedBreak);
        assert_eq!(e.offset, Some(0));
        assert_eq!(e.byte_span, Some((0, 1)));
        assert_eq!(e.path, "$");
    }

    #[test]
    fn truncated_input_is_reported() {
        let e = decode_err("18");
        assert_eq!(e.kind, ErrorKind::UnexpectedEof);
        assert_eq!(e.offset, Some(0), "{:?}", e);
    }

    #[test]
    fn malformed_minor_value_is_rejected() {
        let e = decode_err("1c");
        assert_eq!(e.kind, ErrorKind::InvalidSyntax);
        assert_eq!(e.offset, Some(0));
    }

    #[test]
    fn error_path_pinpoints_map_value_position() {
        // a2_6161_01_6162_ff = {"a": 1, "b": <break>}
        // The second value is 0xff (break outside indefinite container).
        let e = decode_err("a26161016162ff");
        assert_eq!(e.kind, ErrorKind::UnexpectedBreak);
        assert_eq!(e.path, "$.entries[1].value");
        assert_eq!(e.offset, Some(6));
    }

    /// Break lookahead must not shift offsets before non-shortest headers.
    #[test]
    fn item_offsets_survive_a_break_check_before_a_non_shortest_header() {
        for (hex, first_len, total) in [
            // [_ 1] with the 1 written at each header width.
            ("9f01ff", 1usize, 3usize),
            ("9f1801ff", 2, 4),
            ("9f190001ff", 3, 5),
            ("9f1a00000001ff", 5, 7),
            ("9f1b0000000000000001ff", 9, 11),
            // A float written wider than the value needs.
            ("9ffbbff0000000000000ff", 9, 11),
        ] {
            let tree = decode(hex);
            assert_eq!(
                tree["struct_position_info"],
                json!({"offset": 0, "length": total}),
                "{}",
                hex
            );
            assert_eq!(
                tree["values"][0]["position_info"],
                json!({"offset": 1, "length": first_len}),
                "{}",
                hex
            );
            // The break is the last byte, and it is where the container
            // says it ends.
            assert_eq!(
                tree["values"][1]["position_info"],
                json!({"offset": total - 1, "length": 1}),
                "{}",
                hex
            );
        }
        // Nested: the inner container is entered through the same
        // look-ahead as the outer one.
        let nested = decode("9f9f1801ffff");
        assert_eq!(
            nested["struct_position_info"],
            json!({"offset": 0, "length": 6}),
            "{}",
            nested
        );
        assert_eq!(
            nested["values"][0]["struct_position_info"],
            json!({"offset": 1, "length": 4}),
            "{}",
            nested
        );
        assert_eq!(
            nested["values"][0]["values"][0]["position_info"],
            json!({"offset": 2, "length": 2}),
            "{}",
            nested
        );
        // Map keys and values are reached through the same look-ahead.
        let tree = decode("bf18011802ff");
        assert_eq!(
            tree["values"][0]["key"]["position_info"],
            json!({"offset": 1, "length": 2}),
            "{}",
            tree
        );
        assert_eq!(
            tree["values"][0]["value"]["position_info"],
            json!({"offset": 3, "length": 2}),
            "{}",
            tree
        );
    }

    #[test]
    fn error_path_pinpoints_nested_array_position() {
        // 82_01_82_02_1c = [1, [2, <reserved-minor>]]
        // Inner array expects 2 items; the second slot holds 0x1c (invalid
        // CBOR minor), so the failure is at $[1][1].
        let e = decode_err("820182021c");
        assert_eq!(e.kind, ErrorKind::InvalidSyntax);
        assert_eq!(e.path, "$[1][1]");
        assert_eq!(e.offset, Some(4));
    }

    #[test]
    fn nested_array_positions_are_relative_to_root() {
        assert_eq!(
            decode("82810102"),
            json!({
                "type": "Array",
                "position_info": {"offset": 0, "length": 1},
                "struct_position_info": {"offset": 0, "length": 4},
                "items": 2,
                "values": [
                    {
                        "type": "Array",
                        "position_info": {"offset": 1, "length": 1},
                        "struct_position_info": {"offset": 1, "length": 2},
                        "items": 1,
                        "values": [
                            {"type": "U8", "position_info": {"offset": 2, "length": 1}, "value": 1}
                        ]
                    },
                    {"type": "U8", "position_info": {"offset": 3, "length": 1}, "value": 2}
                ]
            })
        );
    }

    // === Oddity detection ===

    #[test]
    fn canonical_small_int_has_no_oddity() {
        assert!(oddity_kinds(&decode("0f")).is_empty()); // 15
        assert!(oddity_kinds(&decode("1864")).is_empty()); // 100
    }

    #[test]
    fn overlong_positive_int_is_flagged() {
        // 0f canonical; 180f, 19000f, 1a0000000f, 1b000000000000000f are overlong.
        for hex_str in ["180f", "19000f", "1a0000000f", "1b000000000000000f"] {
            let v = decode(hex_str);
            assert_eq!(
                oddity_kinds(&v),
                vec!["IntNotShortest".to_string()],
                "hex: {}",
                hex_str
            );
        }
    }

    #[test]
    fn overlong_negative_int_is_flagged() {
        // 20 = -1, shortest; 3800 = -1 overlong.
        assert!(oddity_kinds(&decode("20")).is_empty());
        assert_eq!(
            oddity_kinds(&decode("3800")),
            vec!["IntNotShortest".to_string()]
        );
    }

    #[test]
    fn overlong_float_is_flagged() {
        // 1.0 canonical: f93c00 (F16). fa3f800000 (F32) and fb3ff0000000000000 (F64) are overlong.
        assert!(oddity_kinds(&decode("f93c00")).is_empty());
        assert_eq!(
            oddity_kinds(&decode("fa3f800000")),
            vec!["FloatNotShortest".to_string()]
        );
        assert_eq!(
            oddity_kinds(&decode("fb3ff0000000000000")),
            vec!["FloatNotShortest".to_string()]
        );
    }

    #[test]
    fn f64_with_full_precision_not_flagged() {
        // 0.1 is not representable in F16 or F32 exactly, so F64 is shortest.
        // fb3fb999999999999a = 0.1
        assert!(oddity_kinds(&decode("fb3fb999999999999a")).is_empty());
    }

    #[test]
    fn indefinite_array_is_flagged() {
        // 9f0102ff = [_ 1, 2]
        let v = decode("9f0102ff");
        assert_eq!(oddity_kinds(&v), vec!["IndefiniteLength".to_string()]);
    }

    #[test]
    fn indefinite_map_is_flagged() {
        // bf_6161_01_6162_02_ff
        let v = decode("bf616101616202ff");
        assert_eq!(oddity_kinds(&v), vec!["IndefiniteLength".to_string()]);
    }

    #[test]
    fn indefinite_bytes_and_text_are_flagged() {
        // 5f42010243030405ff
        let v = decode("5f42010243030405ff");
        assert_eq!(oddity_kinds(&v), vec!["IndefiniteLength".to_string()]);
        // 7f6548656c6c6f612065576f726c64ff
        let v = decode("7f6548656c6c6f612065576f726c64ff");
        assert_eq!(oddity_kinds(&v), vec!["IndefiniteLength".to_string()]);
    }

    #[test]
    fn indefinite_array_emits_break_token() {
        // 9f0102ff = [_ 1, 2]
        let v = decode("9f0102ff");
        let values = v.get("values").and_then(Value::as_array).expect("values");
        let last = values.last().expect("non-empty values");
        assert_eq!(last["type"], Value::String("Break".into()));
        assert_eq!(last["value"], Value::Null);
        assert_eq!(last["position_info"], json!({"offset": 3, "length": 1}));
    }

    #[test]
    fn indefinite_map_emits_break_token() {
        // bf_6161_01_6162_02_ff
        let v = decode("bf616101616202ff");
        let values = v.get("values").and_then(Value::as_array).expect("values");
        let last = values.last().expect("non-empty values");
        assert_eq!(last["type"], Value::String("Break".into()));
        assert_eq!(last["value"], Value::Null);
        assert_eq!(last["position_info"], json!({"offset": 7, "length": 1}));
    }

    #[test]
    fn indefinite_bytes_emits_break_token() {
        // 5f42010243030405ff
        let v = decode("5f42010243030405ff");
        let chunks = v.get("chunks").and_then(Value::as_array).expect("chunks");
        let last = chunks.last().expect("non-empty chunks");
        assert_eq!(last["type"], Value::String("Break".into()));
        assert_eq!(last["value"], Value::Null);
        assert_eq!(last["position_info"], json!({"offset": 8, "length": 1}));
    }

    #[test]
    fn indefinite_text_emits_break_token() {
        // 7f6548656c6c6f612065576f726c64ff
        let v = decode("7f6548656c6c6f612065576f726c64ff");
        let chunks = v.get("chunks").and_then(Value::as_array).expect("chunks");
        let last = chunks.last().expect("non-empty chunks");
        assert_eq!(last["type"], Value::String("Break".into()));
        assert_eq!(last["value"], Value::Null);
        assert_eq!(last["position_info"], json!({"offset": 15, "length": 1}));
    }

    #[test]
    fn sorted_map_keys_no_oddity() {
        // a2_01_61 61_02_61 62 → {1:"a", 2:"b"} — bytewise sorted.
        assert!(oddity_kinds(&decode("a2016161026162")).is_empty());
    }

    #[test]
    fn unsorted_map_keys_are_flagged() {
        // a2_02_61 62_01_61 61 → {2:"b", 1:"a"}
        let v = decode("a2026162016161");
        assert_eq!(oddity_kinds(&v), vec!["MapKeysNotSorted".to_string()]);
    }

    #[test]
    fn duplicate_map_keys_are_flagged() {
        // a2_01_61 61_01_61 62 → {1:"a", 1:"b"}
        let v = decode("a2016161016162");
        let kinds = oddity_kinds(&v);
        assert!(
            kinds.contains(&"DuplicateMapKeys".to_string()),
            "got: {:?}",
            kinds
        );
    }

    #[test]
    fn bignum_wrapping_small_int_is_flagged() {
        // c2_42_0100 = tag 2, bytes(0x0100) = 256. Fits in U16.
        let v = decode("c2420100");
        let kinds = oddity_kinds(&v);
        assert!(
            kinds.contains(&"BignumForSmallInt".to_string()),
            "got: {:?}",
            kinds
        );
    }

    #[test]
    fn bignum_with_leading_zero_is_flagged() {
        // c2_43_000100 = tag 2, bytes(0x000100) — leading zero.
        let v = decode("c243000100");
        let kinds = oddity_kinds(&v);
        assert!(
            kinds.contains(&"BignumLeadingZeroes".to_string()),
            "got: {:?}",
            kinds
        );
    }

    #[test]
    fn large_bignum_not_flagged_as_small() {
        // tag 2, bytes of length 9 (> 8): does NOT fit in native int.
        // c2_49_010000000000000000 = 2^64
        let v = decode("c249010000000000000000");
        let kinds = oddity_kinds(&v);
        assert!(
            !kinds.contains(&"BignumForSmallInt".to_string()),
            "got: {:?}",
            kinds
        );
    }

    #[test]
    fn canonical_input_has_no_oddities_anywhere() {
        // A small, fully canonical CBOR document: {"a": [1, 2]}
        fn collect(v: &Value, acc: &mut Vec<String>) {
            if let Some(arr) = v.get("oddities").and_then(Value::as_array) {
                for o in arr {
                    if let Some(k) = o.get("kind").and_then(Value::as_str) {
                        acc.push(k.to_string());
                    }
                }
            }
            if let Some(arr) = v.get("values").and_then(Value::as_array) {
                for it in arr {
                    collect(it, acc);
                    if let Some(inner) = it.get("key") {
                        collect(inner, acc);
                    }
                    if let Some(inner) = it.get("value") {
                        collect(inner, acc);
                    }
                }
            }
            if let Some(inner) = v.get("value") {
                if inner.is_object() {
                    collect(inner, acc);
                }
            }
        }
        let v = decode("a16161820102");
        let mut all = Vec::new();
        collect(&v, &mut all);
        assert!(all.is_empty(), "unexpected oddities: {:?}", all);
    }

    // === Partial-tree recovery on decode errors ===

    #[test]
    fn trailing_data_returns_the_complete_prefix_as_partial() {
        // 01 decodes as U8(1); 00 trailing. Partial is the completed prefix.
        let e = decode_err("0100");
        let partial = e.partial.as_ref().expect("partial present");
        assert_eq!(
            &**partial,
            &json!({"type": "U8", "position_info": {"offset": 0, "length": 1}, "value": 1})
        );
    }

    #[test]
    fn array_failure_returns_partial_with_decoded_prefix_and_incomplete_flag() {
        // 83_01_02_1c = [1, 2, <invalid minor>] — declared 3 items, 2 decoded.
        let e = decode_err("8301021c");
        assert_eq!(e.kind, ErrorKind::InvalidSyntax);
        assert_eq!(e.path, "$[2]");
        let partial = e.partial.as_ref().expect("partial present");
        assert_eq!(partial["type"], Value::String("Array".into()));
        assert_eq!(partial["incomplete"], Value::Bool(true));
        // `items` keeps the wire-declared count (3) even though only 2 parsed.
        assert_eq!(partial["items"], json!(3));
        let values = partial["values"].as_array().expect("values");
        assert_eq!(values.len(), 2);
        assert_eq!(values[0]["value"], json!(1));
        assert_eq!(values[1]["value"], json!(2));
    }

    #[test]
    fn nested_array_failure_bubbles_partials_all_the_way_up() {
        // 82_01_82_02_1c — outer [1, inner], inner = [2, <invalid>].
        let e = decode_err("820182021c");
        assert_eq!(e.path, "$[1][1]");
        let partial = e.partial.as_ref().expect("outer partial");
        assert_eq!(partial["incomplete"], Value::Bool(true));
        let outer_values = partial["values"].as_array().unwrap();
        // Outer has [1, inner-partial] — two slots filled (first complete, second partial).
        assert_eq!(outer_values.len(), 2);
        assert_eq!(outer_values[0]["value"], json!(1));
        let inner = &outer_values[1];
        assert_eq!(inner["type"], Value::String("Array".into()));
        assert_eq!(inner["incomplete"], Value::Bool(true));
        let inner_values = inner["values"].as_array().unwrap();
        assert_eq!(inner_values.len(), 1);
        assert_eq!(inner_values[0]["value"], json!(2));
    }

    #[test]
    fn map_value_failure_marks_entry_incomplete_and_records_side() {
        // a2_6161_01_6162_1c — {"a": 1, "b": <invalid>}. Fails at entry 1 value.
        let e = decode_err("a261610161621c");
        assert_eq!(e.path, "$.entries[1].value");
        let partial = e.partial.as_ref().expect("partial map");
        assert_eq!(partial["type"], Value::String("Map".into()));
        let entries = partial["values"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        // First entry is complete.
        assert!(entries[0].get("incomplete").is_none());
        // Second entry: key decoded, value missing, marked incomplete at "value".
        assert_eq!(entries[1]["incomplete"], Value::Bool(true));
        assert_eq!(entries[1]["incomplete_at"], Value::String("value".into()));
        assert_eq!(entries[1]["key"]["value"], Value::String("b".into()));
        assert!(entries[1].get("value").is_none());
    }

    #[test]
    fn indefinite_bytes_failure_returns_decoded_chunks_as_partial() {
        // 5f_42_0102_43_030405_1c — indefinite bytes, two good chunks, then invalid.
        let e = decode_err("5f4201024303040518");
        assert_eq!(e.kind, ErrorKind::UnexpectedEof);
        let partial = e.partial.as_ref().expect("partial chunks");
        assert_eq!(
            partial["type"],
            Value::String("IndefiniteLengthBytes".into())
        );
        assert_eq!(partial["incomplete"], Value::Bool(true));
        let chunks = partial["chunks"].as_array().unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0]["value"], Value::String("0102".into()));
        assert_eq!(chunks[1]["value"], Value::String("030405".into()));
    }

    #[test]
    fn indefinite_map_surfaces_break_as_trailing_node() {
        // bf_00_01_02_03_ff — indefinite map {0: 1, 2: 3}. Like indefinite
        // arrays/strings, the terminating break is surfaced as the last child
        // (a bare Break node), so the raw wire structure is shown in full. The
        // real {key, value} entries precede it.
        let v = decode("bf0001 0203 ff".replace(' ', "").as_str());
        assert_eq!(v["type"], Value::String("Map".into()));
        assert_eq!(v["items"], Value::String("Indefinite".into()));
        assert_eq!(oddity_kinds(&v), vec!["IndefiniteLength".to_string()]);
        let entries = v["values"].as_array().unwrap();
        assert_eq!(entries.len(), 3);
        // First two are real key/value pairs.
        assert_eq!(entries[0]["key"]["value"], json!(0));
        assert_eq!(entries[0]["value"]["value"], json!(1));
        assert_eq!(entries[1]["key"]["value"], json!(2));
        assert_eq!(entries[1]["value"]["value"], json!(3));
        // Last is the bare Break marker: a node with no `key`, mirroring arrays.
        assert_eq!(entries[2]["type"], Value::String("Break".into()));
        assert!(entries[2].get("key").is_none());
        assert_eq!(entries[2]["value"], Value::Null);
    }

    // === Partial trees built by the unwind of the explicit stack ===

    /// A key that fails leaves an entry with no key, marked at the key.
    #[test]
    fn map_key_failure_marks_entry_incomplete_at_key_without_a_key() {
        // a2_6161_01_1c — {"a": 1, <invalid key>}.
        let e = decode_err("a26161011c");
        assert_eq!(e.kind, ErrorKind::InvalidSyntax);
        assert_eq!(e.path, "$.entries[1].key");
        let partial = e.partial.as_ref().expect("partial map");
        assert_eq!(partial["incomplete"], json!(true));
        let entries = partial["values"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].get("incomplete").is_none());
        assert_eq!(entries[1]["incomplete_at"], json!("key"));
        assert!(entries[1].get("key").is_none());
        assert!(entries[1].get("value").is_none());
    }

    /// A key that is itself a container which fails is handed back as
    /// the entry's partial key.
    #[test]
    fn partial_container_key_is_kept_on_the_incomplete_entry() {
        // a1_82_01_1c — {[1, <invalid>]: …}.
        let e = decode_err("a182011c");
        assert_eq!(e.path, "$.entries[0].key[1]");
        let partial = e.partial.as_ref().expect("partial map");
        let entries = partial["values"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["incomplete_at"], json!("key"));
        assert_eq!(entries[0]["key"]["type"], json!("Array"));
        assert_eq!(entries[0]["key"]["incomplete"], json!(true));
        assert_eq!(entries[0]["key"]["values"].as_array().unwrap().len(), 1);
        assert!(entries[0].get("value").is_none());
    }

    /// A value that is a container which fails is handed back as the
    /// entry's partial value, next to its complete key.
    #[test]
    fn partial_container_value_is_kept_on_the_incomplete_entry() {
        // a1_00_82_01_1c — {0: [1, <invalid>]}.
        let e = decode_err("a10082011c");
        assert_eq!(e.path, "$.entries[0].value[1]");
        let partial = e.partial.as_ref().expect("partial map");
        let entries = partial["values"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["incomplete_at"], json!("value"));
        assert_eq!(entries[0]["key"]["value"], json!(0));
        assert_eq!(entries[0]["value"]["type"], json!("Array"));
        assert_eq!(entries[0]["value"]["incomplete"], json!(true));
    }

    /// An indefinite map cut off between entries has no entry open, so
    /// the partial holds only the entries it completed.
    #[test]
    fn indefinite_map_truncated_between_entries_adds_no_partial_entry() {
        // bf_00_01 — {0: 1, <input ends before the next key or the break>}.
        let e = decode_err("bf0001");
        assert_eq!(e.kind, ErrorKind::UnexpectedEof);
        assert_eq!(e.path, "$");
        let partial = e.partial.as_ref().expect("partial map");
        assert_eq!(partial["items"], json!("Indefinite"));
        assert_eq!(partial["incomplete"], json!(true));
        let entries = partial["values"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].get("incomplete").is_none());
        assert_eq!(entries[0]["key"]["value"], json!(0));
        assert_eq!(entries[0]["value"]["value"], json!(1));
    }

    /// The same for an indefinite array cut off between items.
    #[test]
    fn indefinite_array_truncated_between_items_keeps_only_decoded_items() {
        let e = decode_err("9f0102");
        assert_eq!(e.kind, ErrorKind::UnexpectedEof);
        assert_eq!(e.path, "$");
        let partial = e.partial.as_ref().expect("partial array");
        assert_eq!(partial["incomplete"], json!(true));
        let values = partial["values"].as_array().unwrap();
        assert_eq!(values.len(), 2);
        assert_eq!(values[1]["value"], json!(2));
    }

    /// A tag around a container that fails carries the partial container.
    #[test]
    fn tag_failure_keeps_the_partial_inner_container() {
        // c1_82_01_1c — tag(1) around [1, <invalid>].
        let e = decode_err("c182011c");
        assert_eq!(e.path, "$.tag[1]");
        let partial = e.partial.as_ref().expect("partial tag");
        assert_eq!(partial["type"], json!("Tag"));
        assert_eq!(partial["incomplete"], json!(true));
        assert_eq!(partial["value"]["type"], json!("Array"));
        assert_eq!(partial["value"]["incomplete"], json!(true));
        assert_eq!(partial["value"]["values"].as_array().unwrap().len(), 1);
    }

    /// Every container open around a failure is closed innermost first,
    /// each with what it had decoded, and all of them end where the
    /// decode stopped.
    #[test]
    fn partials_nest_through_every_container_kind_around_the_failure() {
        // 82_00_a1_01_c2_9f_02_1c — [0, {1: tag(2)([_ 2, <invalid>])}].
        let e = decode_err("8200a101c29f021c");
        assert_eq!(e.kind, ErrorKind::InvalidSyntax);
        assert_eq!(e.path, "$[1].entries[0].value.tag[1]");
        assert_eq!(e.offset, Some(7));
        let root = e.partial.as_ref().expect("partial root");
        assert_eq!(root["type"], json!("Array"));
        assert_eq!(root["incomplete"], json!(true));
        let root_values = root["values"].as_array().unwrap();
        assert_eq!(root_values.len(), 2);
        assert_eq!(root_values[0]["value"], json!(0));
        let map = &root_values[1];
        assert_eq!(map["type"], json!("Map"));
        assert_eq!(map["incomplete"], json!(true));
        let entry = &map["values"][0];
        assert_eq!(entry["incomplete_at"], json!("value"));
        assert_eq!(entry["key"]["value"], json!(1));
        let tag = &entry["value"];
        assert_eq!(tag["type"], json!("Tag"));
        assert_eq!(tag["incomplete"], json!(true));
        let array = &tag["value"];
        assert_eq!(array["type"], json!("Array"));
        assert_eq!(array["items"], json!("Indefinite"));
        assert_eq!(array["incomplete"], json!(true));
        assert_eq!(array["values"].as_array().unwrap().len(), 1);
        let end = |v: &Value| {
            let span = &v["struct_position_info"];
            span["offset"].as_u64().unwrap() + span["length"].as_u64().unwrap()
        };
        assert_eq!(end(root), end(map));
        assert_eq!(end(map), end(tag));
        assert_eq!(end(tag), end(array));
        assert!(end(array) >= 7);
    }

    #[test]
    fn tag_failure_returns_partial_tag_without_value_when_inner_lost() {
        // d8_66_1c — tag(102) wrapping a byte that's an invalid CBOR minor.
        let e = decode_err("d8661c");
        assert_eq!(e.kind, ErrorKind::InvalidSyntax);
        assert_eq!(e.path, "$.tag");
        let partial = e.partial.as_ref().expect("partial tag");
        assert_eq!(partial["type"], Value::String("Tag".into()));
        assert_eq!(partial["incomplete"], Value::Bool(true));
        // Inner wasn't recoverable, so `value` is absent.
        assert!(partial.get("value").is_none());
    }

    // ============================================================
    // Nesting limit
    // ============================================================

    fn nested_arrays_hex(levels: usize) -> String {
        let mut s = String::with_capacity(levels * 2 + 2);
        for _ in 0..levels {
            s.push_str("81");
        }
        s.push_str("05");
        s
    }

    /// Decode succeeds for documents nested exactly to the depth limit.
    #[test]
    fn decode_accepts_cbor_nested_to_the_limit() {
        let hex = nested_arrays_hex(MAX_CBOR_DECODE_NESTING_DEPTH);
        let bytes = hex::decode(&hex).unwrap();
        let value = decode_cbor_to_value(&bytes).expect("expected a full decode");
        // Walk to the bottom to prove nothing was silently truncated.
        let mut node: &Value = &value;
        for level in 0..MAX_CBOR_DECODE_NESTING_DEPTH {
            assert!(
                node.get("incomplete").is_none(),
                "level {} is incomplete",
                level
            );
            node = &node["values"][0];
        }
        assert_eq!(node["value"], json!(5));
    }

    #[test]
    fn decode_rejects_cbor_nested_past_the_limit() {
        let hex = nested_arrays_hex(MAX_CBOR_DECODE_NESTING_DEPTH + 1);
        let bytes = hex::decode(&hex).unwrap();
        let e = decode_cbor_to_value(&bytes).expect_err("expected a rejection");
        assert_eq!(e.kind, ErrorKind::NestingTooDeep);
        assert_eq!(e.kind.as_str(), "nesting_too_deep");
        // The path names one segment per enclosing container.
        assert_eq!(
            e.path.matches('[').count(),
            MAX_CBOR_DECODE_NESTING_DEPTH + 1
        );
        assert_eq!(e.offset, Some(MAX_CBOR_DECODE_NESTING_DEPTH + 1));
        // Partial prefix nests to the bound.
        let partial = e.partial.as_ref().expect("expected a partial tree");
        assert_eq!(partial["type"], Value::String("Array".into()));
        assert_eq!(partial["incomplete"], Value::Bool(true));
        let mut node: &Value = partial;
        for _ in 0..MAX_CBOR_DECODE_NESTING_DEPTH {
            node = &node["values"][0];
        }
        assert_eq!(node["type"], Value::String("Array".into()));
        assert_eq!(node["incomplete"], Value::Bool(true));
        assert_eq!(node["values"].as_array().map(Vec::len), Some(0));
    }

    /// The guard counts every kind of nesting, not only definite arrays.
    #[test]
    fn nesting_limit_counts_maps_tags_and_indefinite_containers() {
        // Indefinite maps: `bf` opens, key `01`, value is the next
        // container, `ff` closes.
        let mut indefinite_maps = String::new();
        for _ in 0..MAX_CBOR_DECODE_NESTING_DEPTH + 1 {
            indefinite_maps.push_str("bf01");
        }
        indefinite_maps.push_str("05");
        indefinite_maps.push_str(&"ff".repeat(MAX_CBOR_DECODE_NESTING_DEPTH + 1));

        // Definite maps: `a1` then key `01` then the value.
        let mut definite_maps = String::new();
        for _ in 0..MAX_CBOR_DECODE_NESTING_DEPTH + 1 {
            definite_maps.push_str("a101");
        }
        definite_maps.push_str("05");

        // Indefinite arrays.
        let mut indefinite_arrays = "9f".repeat(MAX_CBOR_DECODE_NESTING_DEPTH + 1);
        indefinite_arrays.push_str("05");
        indefinite_arrays.push_str(&"ff".repeat(MAX_CBOR_DECODE_NESTING_DEPTH + 1));

        // A chain of tag 1 headers.
        let mut tags = "c1".repeat(MAX_CBOR_DECODE_NESTING_DEPTH + 1);
        tags.push_str("05");

        for (label, hex) in [
            ("indefinite maps", indefinite_maps),
            ("definite maps", definite_maps),
            ("indefinite arrays", indefinite_arrays),
            ("tag chain", tags),
        ] {
            let bytes = hex::decode(&hex).unwrap();
            let e = decode_cbor_to_value(&bytes)
                .err()
                .unwrap_or_else(|| panic!("{} was not rejected", label));
            assert_eq!(e.kind, ErrorKind::NestingTooDeep, "{}", label);
        }
    }

    /// Indefinite string chunks are not nesting levels (match pre-scan).
    #[test]
    fn indefinite_string_chunks_are_not_a_nesting_level() {
        // An indefinite byte string sitting at the deepest allowed
        // level, with chunks inside it.
        let mut hex = "81".repeat(MAX_CBOR_DECODE_NESTING_DEPTH);
        hex.push_str("5f41014102ff");
        let bytes = hex::decode(&hex).unwrap();
        assert!(decode_cbor_to_value(&bytes).is_ok(), "{}", hex);
        assert_eq!(
            crate::cbor::limits::cbor_nesting_depth_capped(&bytes, usize::MAX),
            MAX_CBOR_DECODE_NESTING_DEPTH
        );

        // One level further out and it is past the limit for both.
        let mut hex = "81".repeat(MAX_CBOR_DECODE_NESTING_DEPTH + 1);
        hex.push_str("5f4101ff");
        let bytes = hex::decode(&hex).unwrap();
        assert!(decode_cbor_to_value(&bytes).is_err());
        assert_eq!(
            crate::cbor::limits::cbor_nesting_depth_capped(&bytes, usize::MAX),
            MAX_CBOR_DECODE_NESTING_DEPTH + 1
        );
    }

    /// The same shapes one level shallower must still decode, so the
    /// counting above is a boundary and not a blanket refusal.
    #[test]
    fn maps_tags_and_chunks_at_the_limit_still_decode() {
        let mut definite_maps = String::new();
        for _ in 0..MAX_CBOR_DECODE_NESTING_DEPTH {
            definite_maps.push_str("a101");
        }
        definite_maps.push_str("05");

        let mut tags = "c1".repeat(MAX_CBOR_DECODE_NESTING_DEPTH);
        tags.push_str("05");

        let mut indefinite_arrays = "9f".repeat(MAX_CBOR_DECODE_NESTING_DEPTH);
        indefinite_arrays.push_str("05");
        indefinite_arrays.push_str(&"ff".repeat(MAX_CBOR_DECODE_NESTING_DEPTH));

        for (label, hex) in [
            ("definite maps", definite_maps),
            ("indefinite arrays", indefinite_arrays),
            ("tag chain", tags),
        ] {
            let bytes = hex::decode(&hex).unwrap();
            assert!(
                decode_cbor_to_value(&bytes).is_ok(),
                "{} at the limit was rejected",
                label
            );
        }
    }

    /// Declared length of 2^64-1 must error, not abort on allocation.
    #[test]
    fn a_declared_length_no_input_could_carry_is_an_error_not_an_abort() {
        for (hex, offset) in [
            // Byte string, text string, array and map, each declaring
            // 2^64-1 of content with nothing after the header.
            ("5bffffffffffffffff", 9),
            ("7bffffffffffffffff", 9),
            ("9bffffffffffffffff", 9),
            ("bbffffffffffffffff", 9),
            // Representable but still unbacked: 2 GiB and 4 GiB.
            ("5a7fffffff", 5),
            ("5b0000000100000000", 9),
            // A chunk of an indefinite-length string, one level in.
            ("5f5bffffffffffffffff", 10),
        ] {
            let e = decode_err(hex);
            assert_eq!(e.kind, ErrorKind::UnexpectedEof, "{}", hex);
            assert_eq!(e.offset, Some(offset), "{}", hex);
        }
    }

    /// The same bound must not cost anything for a payload that really
    /// is there: a byte string is read in one pass whatever its size.
    #[test]
    fn a_backed_payload_longer_than_one_read_chunk_still_decodes() {
        let len = super::READ_CHUNK * 2 + 7;
        let mut bytes = vec![0x5a];
        bytes.extend_from_slice(&(len as u32).to_be_bytes());
        bytes.extend(std::iter::repeat(0xabu8).take(len));
        let value = decode_cbor_to_value(&bytes).expect("payload is backed by real bytes");
        assert_eq!(value["type"], Value::String("Bytes".into()));
        assert_eq!(
            value["value"].as_str().map(str::len),
            Some(len * 2),
            "the whole payload has to come back"
        );
    }
}

//! Schemas and documents shared by the `cbor` tests: a made-up inventory
//! ledger, built here rather than taken from any real protocol, so the
//! tests depend on nothing outside the crate and describe the validator's
//! behaviour rather than one schema's.
//!
//! The schema family stands in for a protocol that grew over several
//! versions: every version declares the same roots (`record`, `record_body`,
//! `datum`, `payload`), each adds rules and optional members, and one
//! document is valid against all of them. The largest version is on the
//! scale of a real ledger schema — well over a hundred rules — which is what
//! the tests of cost, of error budgets and of the rule outline need.

#![cfg(test)]

use ciborium::value::{Integer, Value};
use std::sync::LazyLock;

// ---------------------------------------------------------------------------
// The schema family

/// The rules every version shares. `record` mirrors the shape of a signed
/// ledger transaction — a body keyed by small integers, a witness map, a
/// validity flag and optional auxiliary data — without being one.
const BASE_RULES: &str = r#"
; Inventory ledger, version 1.
record =
  [ body           : record_body
  , witness        : record_witness
  , is_valid       : bool
  , aux            : record_aux / null
  ]

record_body =
  { 0 : set<ref>                  ; inputs consumed
  , 1 : [* entry]                 ; entries produced
  , 2 : amount                    ; fee
  , ? 3 : uint                    ; time to live
  , ? 4 : [* note]
  , ? 5 : {* label => amount}
  , ? 6 : hash32
  , ? 7 : hash32
  , ? 8 : uint
  , ? 9 : stock
  , ? 11 : hash32
  , ? 13 : set<ref>
  , ? 14 : [* hash28]
  , ? 15 : uint
  , ? 16 : entry
  , ? 17 : amount
  , ? 18 : set<ref>
  }

ref = [hash32, index]
index = uint .size 2

entry = legacy_entry / rich_entry
legacy_entry = [address, value, ? hash32]
rich_entry =
  { 0 : address
  , 1 : value
  , ? 2 : datum_option
  , ? 3 : payload
  }
datum_option = [0, hash32 // 1, payload]

address = bytes .size (29..57)
value = amount / [amount, stock]
amount = uint
stock = {* bucket => {* label => int64}}
bucket = hash28
label = bytes .size (0..32)
int64 = -9223372036854775808 .. 9223372036854775807
negative_int64 = -9223372036854775808 .. -1
positive_int64 = 1 .. 9223372036854775807

note = [tag: note_tag, hash32]
note_tag = 0 / 1 / 2

record_witness =
  { ? 0 : nonempty_set<signature>
  , ? 1 : nonempty_set<native_script>
  , ? 3 : nonempty_set<payload>
  , ? 4 : nonempty_set<datum>
  , ? 5 : nonempty_set<redeemer>
  }

signature = [public_key, bytes .size 64]
public_key = bytes .size 32
native_script =
  [ 0, hash28
  // 1, [* native_script]
  // 2, [* native_script]
  // 3, uint, [* native_script]
  // 4, uint
  // 5, uint
  ]
redeemer = [tag: 0 .. 3, index: uint, data: datum, units: [uint, uint]]

record_aux = {* uint => metadatum} / [{* uint => metadatum}, [* native_script]]
metadatum = {* metadatum => metadatum} / [* metadatum] / int / bytes .size (0..64) / text .size (0..64)

payload = #6.24(bytes .cbor datum)
datum =
    constr<datum>
  / {* datum => datum}
  / [* datum]
  / big_int
  / bounded_bytes
constr<a> =
    #6.121([* a])
  / #6.122([* a])
  / #6.123([* a])
  / #6.124([* a])
  / #6.125([* a])
  / #6.126([* a])
  / #6.127([* a])
  / #6.102([uint, [* a]])
big_int = int / big_uint / big_nint
big_uint = #6.2(bounded_bytes)
big_nint = #6.3(bounded_bytes)
bounded_bytes = bytes .size (0..64)

hash28 = bytes .size 28
hash32 = bytes .size 32

set<a> = #6.258([* a]) / [* a]
nonempty_set<a> = #6.258([+ a]) / [+ a]
"#;

/// Version 2: settings.
const V2_RULES: &str = r#"
; Version 2 additions.
settings =
  { ? 0 : uint
  , ? 1 : uint
  , ? 2 : [uint, uint]
  , ? 3 : version
  , ? 4 : {* text => uint}
  }
version = [major: uint, minor: uint]
"#;

/// Version 3: certificates, with a group choice per kind.
const V3_RULES: &str = r#"
; Version 3 additions.
certificate =
  [ 0, credential
  // 1, credential, hash28
  // 2, credential, uint
  // 3, credential, credential, amount
  ]
credential = [0, hash28 // 1, hash28]
"#;

/// Version 4: sockets and plugs, and a rule that is its own reference.
const V4_RULES: &str = r#"
; Version 4 additions.
$extension_kind /= 0
$extension_kind /= 1
extension = [$extension_kind, bytes]
tree = [* tree] / text
"#;

/// Version 5: controls over text and byte strings.
const V5_RULES: &str = r#"
; Version 5 additions.
url = text .size (0..128)
dns_name = text .size (0..64)
ipv4 = bytes .size 4
ipv6 = bytes .size 16
port = uint .le 65535
relay =
  [ 0, port / null, ipv4 / null, ipv6 / null
  // 1, port / null, dns_name
  // 2, dns_name
  ]
"#;

/// Version 6: enough further rules to reach the size of a real protocol's
/// schema, each a small variation so the outline has something to list.
static V6_RULES: LazyLock<String> = LazyLock::new(|| {
    let mut out = String::from("\n; Version 6 additions.\n");
    for i in 0..80u32 {
        out.push_str(&format!(
            "widget_{i} = [id: uint, name: text .size (1..32), ? weight: widget_weight_{i}]\n\
             widget_weight_{i} = {min} .. {max}\n",
            min = i,
            max = i + 1000,
        ));
    }
    out.push_str("widgets = [* widget_0 / widget_1 / widget_2]\n");
    out
});

pub static V1_CDDL: LazyLock<String> = LazyLock::new(|| BASE_RULES.to_string());
pub static V2_CDDL: LazyLock<String> = LazyLock::new(|| format!("{BASE_RULES}{V2_RULES}"));
pub static V3_CDDL: LazyLock<String> =
    LazyLock::new(|| format!("{BASE_RULES}{V2_RULES}{V3_RULES}"));
pub static V4_CDDL: LazyLock<String> =
    LazyLock::new(|| format!("{BASE_RULES}{V2_RULES}{V3_RULES}{V4_RULES}"));
pub static V5_CDDL: LazyLock<String> =
    LazyLock::new(|| format!("{BASE_RULES}{V2_RULES}{V3_RULES}{V4_RULES}{V5_RULES}"));
pub static V6_CDDL: LazyLock<String> = LazyLock::new(|| {
    format!(
        "{BASE_RULES}{V2_RULES}{V3_RULES}{V4_RULES}{V5_RULES}{}",
        V6_RULES.as_str()
    )
});

/// The newest, largest version — what a test reaches for when it wants "a
/// real-sized schema".
pub fn ledger_cddl() -> &'static str {
    V6_CDDL.as_str()
}

/// Every version, oldest first, paired with its name.
pub fn schema_suite() -> Vec<(&'static str, &'static str)> {
    vec![
        ("v1", V1_CDDL.as_str()),
        ("v2", V2_CDDL.as_str()),
        ("v3", V3_CDDL.as_str()),
        ("v4", V4_CDDL.as_str()),
        ("v5", V5_CDDL.as_str()),
        ("v6", V6_CDDL.as_str()),
    ]
}

// ---------------------------------------------------------------------------
// The documents

fn int(n: i64) -> Value {
    Value::Integer(Integer::from(n))
}
fn bytes(n: usize, seed: u8) -> Value {
    Value::Bytes((0..n).map(|i| seed.wrapping_add(i as u8)).collect())
}
fn text(s: &str) -> Value {
    Value::Text(s.to_string())
}
fn tagged(tag: u64, v: Value) -> Value {
    Value::Tag(tag, Box::new(v))
}
fn map(entries: Vec<(Value, Value)>) -> Value {
    Value::Map(entries)
}
fn array(items: Vec<Value>) -> Value {
    Value::Array(items)
}

fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("fixture encodes");
    out
}

fn reference(i: u8) -> Value {
    array(vec![bytes(32, i), int(i as i64 % 4)])
}

fn stock(seed: u8) -> Value {
    map(vec![(
        bytes(28, seed),
        map(vec![
            (bytes(5, seed.wrapping_add(1)), int(1_000_000)),
            (bytes(0, 0), int(-42)),
            (
                bytes(12, seed.wrapping_add(2)),
                int(9_223_372_036_854_775_807),
            ),
        ]),
    )])
}

/// A datum of `depth` levels: constructors, lists and maps nested in turn,
/// ending in integers and byte strings.
fn datum(depth: usize, seed: u8) -> Value {
    if depth == 0 {
        return if seed % 2 == 0 {
            int(seed as i64 * 7)
        } else {
            bytes(seed as usize % 20, seed)
        };
    }
    match depth % 3 {
        0 => tagged(
            121 + (seed as u64 % 7),
            array(vec![
                datum(depth - 1, seed.wrapping_add(1)),
                int(depth as i64),
            ]),
        ),
        1 => array(vec![datum(depth - 1, seed.wrapping_add(3)), bytes(4, seed)]),
        _ => map(vec![(
            int(depth as i64),
            datum(depth - 1, seed.wrapping_add(5)),
        )]),
    }
}

fn payload(depth: usize, seed: u8) -> Value {
    tagged(24, Value::Bytes(encode(&datum(depth, seed))))
}

fn entry(i: u8) -> Value {
    if i % 2 == 0 {
        array(vec![bytes(57, i), int(2_000_000 + i as i64)])
    } else {
        map(vec![
            (int(0), bytes(29, i)),
            (int(1), array(vec![int(5_000_000), stock(i)])),
            (int(2), array(vec![int(1), payload(6, i)])),
        ])
    }
}

/// A record valid against `record` in every version of the schema: a
/// dozen entries with stock, a few notes, a witness set with signatures
/// and datums, and metadata — a few kilobytes, as a real one is.
pub fn record_doc() -> Vec<u8> {
    let body = map(vec![
        (int(0), tagged(258, array((0..3).map(reference).collect()))),
        (int(1), array((0..12).map(entry).collect())),
        (int(2), int(178_129)),
        (int(3), int(133_419_075)),
        (
            int(4),
            array(vec![
                array(vec![int(0), bytes(32, 9)]),
                array(vec![int(2), bytes(32, 10)]),
            ]),
        ),
        (int(9), stock(0xA0)),
        (int(11), bytes(32, 0xB0)),
        (int(13), array(vec![reference(7)])),
        (int(17), int(1_000)),
    ]);
    let witness = map(vec![
        (
            int(0),
            tagged(
                258,
                array(
                    (0..4u8)
                        .map(|i| array(vec![bytes(32, 0xC0 + i), bytes(64, 0xD0 + i)]))
                        .collect(),
                ),
            ),
        ),
        (
            int(1),
            array(vec![array(vec![
                int(3),
                int(1),
                array(vec![
                    array(vec![int(0), bytes(28, 1)]),
                    array(vec![int(0), bytes(28, 2)]),
                ]),
            ])]),
        ),
        (int(4), array(vec![datum(4, 1), datum(2, 2)])),
        (
            int(5),
            array(vec![array(vec![
                int(0),
                int(0),
                datum(3, 3),
                array(vec![int(1000), int(2000)]),
            ])]),
        ),
    ]);
    let aux = map(vec![
        (
            int(674),
            map(vec![(
                text("msg"),
                array(vec![text("inventory"), text("fixture")]),
            )]),
        ),
        (
            int(721),
            map(vec![(
                bytes(28, 5),
                map(vec![(text("name"), text("widget"))]),
            )]),
        ),
    ]);
    encode(&array(vec![body, witness, Value::Bool(true), aux]))
}

/// A datum nested deeper than anything in `record_doc` — what the depth
/// and bound tests measure headroom against.
pub fn datum_doc() -> Vec<u8> {
    encode(&datum(40, 0))
}

/// `record_doc` as the hex text the library's entry points take.
pub static RECORD_DOC_HEX: LazyLock<String> = LazyLock::new(|| hex::encode(record_doc()));
/// `datum_doc` as hex text.
pub static DATUM_DOC_HEX: LazyLock<String> = LazyLock::new(|| hex::encode(datum_doc()));

/// Run `f` on a 64 MiB stack. Libtest threads are too small for deep
/// nesting; overflow aborts the whole test binary.
pub fn on_large_stack<R: Send + 'static>(f: impl FnOnce() -> R + Send + 'static) -> R {
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(f)
        .expect("failed to spawn test thread")
        .join()
        .expect("test thread panicked")
}

#[cfg(test)]
mod fixture_tests {
    use super::*;
    use crate::cbor::validation::validate_cbor_bytes_against_cddl;
    use serde_json::json;

    #[test]
    fn the_record_is_valid_in_every_version() {
        let doc = record_doc();
        for (version, cddl) in schema_suite() {
            let result = validate_cbor_bytes_against_cddl(&doc, cddl, "record");
            assert_eq!(result["valid"], json!(true), "{version}: {result}");
        }
    }

    #[test]
    fn the_datum_is_valid_and_the_record_is_not_a_datum() {
        let result = validate_cbor_bytes_against_cddl(&datum_doc(), ledger_cddl(), "datum");
        assert_eq!(result["valid"], json!(true), "{result}");
        let result = validate_cbor_bytes_against_cddl(&record_doc(), ledger_cddl(), "datum");
        assert_eq!(result["valid"], json!(false));
    }

    #[test]
    fn the_family_grows_and_the_largest_is_real_sized() {
        let sizes: Vec<usize> = schema_suite().iter().map(|(_, s)| s.len()).collect();
        assert!(sizes.windows(2).all(|w| w[0] < w[1]), "{:?}", sizes);
        assert!(ledger_cddl().len() > 8_000, "{}", ledger_cddl().len());
        assert!(record_doc().len() > 2_000, "{}", record_doc().len());
    }
}

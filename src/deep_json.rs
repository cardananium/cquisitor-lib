//! Non-recursive free/write for deep `serde_json::Value` trees.
//!
//! Drop and serialize recurse by default; on `wasm32` that can overflow
//! the host stack and trap the instance even if decode was iterative.
//! [`DeepJson`] frees via [`dismantle_json`]; [`write_json`] matches
//! `serde_json::to_string`, boxing integers outside the JS safe range.

use std::fmt::{self, Write as _};
use std::mem;
use std::ops::{Deref, DerefMut};

use serde_json::{Number, Value};

/// A `serde_json::Value` freed without recursion.
///
/// Deref to the held value; [`DeepJson::into_inner`] extracts it for
/// embedding in a larger tree that must also be held this way.
pub(crate) struct DeepJson(Value);

impl DeepJson {
    pub(crate) fn new(value: Value) -> DeepJson {
        DeepJson(value)
    }

    /// Take the tree out of the owner.
    pub(crate) fn into_inner(mut self) -> Value {
        mem::take(&mut self.0)
    }
}

impl Deref for DeepJson {
    type Target = Value;

    fn deref(&self) -> &Value {
        &self.0
    }
}

impl DerefMut for DeepJson {
    fn deref_mut(&mut self) -> &mut Value {
        &mut self.0
    }
}

impl Drop for DeepJson {
    fn drop(&mut self) {
        dismantle_json(mem::take(&mut self.0));
    }
}

/// How much of a tree's text a `Debug` rendering shows.
const DEBUG_PREVIEW_BYTES: usize = 512;

impl fmt::Debug for DeepJson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = write_json(&self.0);
        let mut end = text.len().min(DEBUG_PREVIEW_BYTES);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        f.write_str("DeepJson(")?;
        f.write_str(&text[..end])?;
        if end < text.len() {
            write!(f, "… {} bytes", text.len())?;
        }
        f.write_str(")")
    }
}

/// Free `value` without recursing over its nesting.
///
/// Move each container's children onto a worklist before dropping it, so
/// generated drops only see empty containers. Worklist size is at most
/// the siblings along the path being freed.
pub(crate) fn dismantle_json(value: Value) {
    let mut pending: Vec<Value> = Vec::new();
    let mut next = value;
    loop {
        match next {
            Value::Array(items) => pending.extend(items),
            Value::Object(entries) => pending.extend(entries.into_iter().map(|(_, v)| v)),
            _ => {}
        }
        match pending.pop() {
            Some(value) => next = value,
            None => return,
        }
    }
}

/// `value` as JSON text, rendered without recursing over its nesting.
pub(crate) fn write_json(value: &Value) -> String {
    let mut out = String::new();
    write_json_into(&mut out, value);
    out
}

/// One open container: remaining items and whether the first was written.
enum Frame<'a> {
    Array {
        items: std::slice::Iter<'a, Value>,
        first: bool,
    },
    Object {
        entries: serde_json::map::Iter<'a>,
        first: bool,
    },
}

/// Append `root` to `out` as JSON text.
pub(crate) fn write_json_into(out: &mut String, root: &Value) {
    let mut stack: Vec<Frame<'_>> = Vec::new();
    let mut next = Some(root);
    loop {
        // Scalar written in place; container opened as the new innermost.
        if let Some(value) = next.take() {
            match value {
                Value::Array(items) => {
                    out.push('[');
                    stack.push(Frame::Array {
                        items: items.iter(),
                        first: true,
                    });
                }
                Value::Object(entries) => {
                    out.push('{');
                    stack.push(Frame::Object {
                        entries: entries.iter(),
                        first: true,
                    });
                }
                scalar => write_scalar(out, scalar),
            }
        }
        // Advance or close the innermost container.
        let Some(top) = stack.last_mut() else {
            return;
        };
        match top {
            Frame::Array { items, first } => match items.next() {
                Some(item) => {
                    if !*first {
                        out.push(',');
                    }
                    *first = false;
                    next = Some(item);
                }
                None => {
                    out.push(']');
                    stack.pop();
                }
            },
            Frame::Object { entries, first } => match entries.next() {
                Some((key, item)) => {
                    if !*first {
                        out.push(',');
                    }
                    *first = false;
                    write_string(out, key);
                    out.push(':');
                    next = Some(item);
                }
                None => {
                    out.push('}');
                    stack.pop();
                }
            },
        }
    }
}

fn write_scalar(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => write_number(out, n),
        Value::String(s) => write_string(out, s),
        Value::Array(_) | Value::Object(_) => unreachable!("containers are written by frames"),
    }
}

/// Largest magnitude a JavaScript number holds as an exact integer.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Key used when serialising a number as digit text rather than a machine word.
const NUMBER_TOKEN: &str = "$serde_json::private::Number";

/// Digits when a JS number reads them back exactly; otherwise boxed as
/// `{"$serde_json::private::Number": "digits"}` to match other crate paths.
fn write_number(out: &mut String, n: &Number) {
    let exact = match n.as_i64() {
        Some(i) => i.unsigned_abs() <= MAX_SAFE_INTEGER,
        None => n.is_f64(),
    };
    if exact {
        write!(out, "{}", n).expect("writing to a String cannot fail");
    } else {
        out.push_str("{\"");
        out.push_str(NUMBER_TOKEN);
        out.push_str("\":\"");
        write!(out, "{}", n).expect("writing to a String cannot fail");
        out.push_str("\"}");
    }
}

/// `s` as a JSON string literal, escaped like `serde_json` (quote,
/// backslash, and controls only).
pub(crate) fn write_string(out: &mut String, s: &str) {
    out.push('"');
    let bytes = s.as_bytes();
    let mut start = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        let escape: Option<&str> = match byte {
            b'"' => Some("\\\""),
            b'\\' => Some("\\\\"),
            0x08 => Some("\\b"),
            0x0c => Some("\\f"),
            b'\n' => Some("\\n"),
            b'\r' => Some("\\r"),
            b'\t' => Some("\\t"),
            0x00..=0x1f => None,
            _ => continue,
        };
        out.push_str(&s[start..i]);
        match escape {
            Some(text) => out.push_str(text),
            None => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.push_str("\\u00");
                out.push(HEX[(byte >> 4) as usize] as char);
                out.push(HEX[(byte & 0xf) as usize] as char);
            }
        }
        start = i + 1;
    }
    out.push_str(&s[start..]);
    out.push('"');
}

#[cfg(test)]
mod tests {
    use std::process::{Command, Stdio};

    use serde_json::{json, Map, Value};

    use super::{dismantle_json, write_json, DeepJson};

    /// `levels` single-element arrays around 5, built leaf-outward.
    fn nested_arrays(levels: usize) -> Value {
        let mut value = Value::from(5);
        for _ in 0..levels {
            value = Value::Array(vec![value]);
        }
        value
    }

    /// `levels` single-entry objects around 5 (positional-decoder shape).
    fn nested_objects(levels: usize) -> Value {
        let mut value = Value::from(5);
        for _ in 0..levels {
            let mut entry = Map::new();
            entry.insert("values".into(), Value::Array(vec![value]));
            value = Value::Object(entry);
        }
        value
    }

    /// Shallow values covering escapes and number kinds a document decodes to.
    fn shallow_values() -> Vec<Value> {
        let mut control = String::new();
        for c in 0u8..0x20 {
            control.push(c as char);
        }
        vec![
            Value::Null,
            json!(true),
            json!(false),
            json!(0),
            json!(-1),
            json!(u64::MAX / (1 << 12)),
            json!(-(i64::MAX / (1 << 12))),
            json!(1.5),
            json!(-0.0),
            json!(1e300),
            json!(2.5e-8),
            json!(""),
            json!("plain"),
            json!("quote \" backslash \\ slash / unicode é ☃ 𝄞 del \u{7f}"),
            Value::String(control),
            json!([]),
            json!({}),
            json!([[], {}, [[]], {"a": {}}]),
            json!({"type": "Array", "items": 2, "values": [{"type": "U8", "value": 5}, null]}),
            json!([1, "two", 3.0, true, null, {"k": [1, [2, [3]]]}]),
        ]
    }

    /// Byte-for-byte match with `serde_json::to_string` for JS-safe numbers.
    #[test]
    fn the_writer_renders_what_serde_json_renders() {
        for value in shallow_values() {
            assert_eq!(
                write_json(&value),
                serde_json::to_string(&value).unwrap(),
                "{:?}",
                value
            );
        }
        // Object key order is preserved.
        let mut ordered = Map::new();
        for key in ["z", "a", "10", "2", "m"] {
            ordered.insert(key.into(), Value::from(key.len()));
        }
        let value = Value::Object(ordered);
        assert_eq!(write_json(&value), r#"{"z":1,"a":1,"10":2,"2":1,"m":1}"#);
        assert_eq!(write_json(&value), serde_json::to_string(&value).unwrap());
    }

    /// Integers outside ±2^53−1 are boxed; floats of any magnitude stay digits.
    #[test]
    fn an_integer_a_javascript_number_cannot_hold_is_boxed() {
        let safe = (1u64 << 53) - 1;
        assert_eq!(write_json(&json!(safe)), "9007199254740991");
        assert_eq!(write_json(&json!(-(safe as i64))), "-9007199254740991");
        assert_eq!(
            write_json(&json!(safe + 1)),
            r#"{"$serde_json::private::Number":"9007199254740992"}"#
        );
        assert_eq!(
            write_json(&json!(-(safe as i64) - 1)),
            r#"{"$serde_json::private::Number":"-9007199254740992"}"#
        );
        assert_eq!(
            write_json(&json!(u64::MAX)),
            r#"{"$serde_json::private::Number":"18446744073709551615"}"#
        );
        assert_eq!(
            write_json(&json!(i64::MIN)),
            r#"{"$serde_json::private::Number":"-9223372036854775808"}"#
        );
        // Floats stay digits (same rounding on round-trip).
        for float in [json!(1e300), json!(9007199254740993.0), json!(-1e-300)] {
            let text = write_json(&float);
            assert_eq!(text, serde_json::to_string(&float).unwrap());
            assert!(!text.contains('{'), "{}", text);
        }

        // Box is valid JSON carrying digits verbatim.
        let boxed: Value = serde_json::from_str(&write_json(&json!(u64::MAX))).unwrap();
        assert_eq!(boxed, json!(u64::MAX));
        // Box sits where the number sat inside a tree.
        let tree = json!({"value": u64::MAX, "next": [1, u64::MAX]});
        assert_eq!(
            write_json(&tree),
            r#"{"value":{"$serde_json::private::Number":"18446744073709551615"},"next":[1,{"$serde_json::private::Number":"18446744073709551615"}]}"#
        );
    }

    /// Writer output parses back to the original value.
    #[test]
    fn the_text_reads_back_to_the_value() {
        for value in shallow_values() {
            let back: Value = serde_json::from_str(&write_json(&value)).unwrap();
            assert_eq!(back, value, "{}", write_json(&value));
        }
    }

    /// Trees deeper than a typical JSON reader follows are still written whole.
    #[test]
    fn a_deep_tree_is_written_whole() {
        let levels = 5000;
        let tree = DeepJson::new(nested_objects(levels));
        let text = write_json(&tree);
        assert_eq!(text.matches("{\"values\":[").count(), levels);
        assert!(text.ends_with(&format!("5{}", "]}".repeat(levels))));
        let tree = DeepJson::new(nested_arrays(levels));
        let text = write_json(&tree);
        assert_eq!(
            text,
            format!("{}5{}", "[".repeat(levels), "]".repeat(levels))
        );
    }

    #[test]
    fn the_owner_hands_its_tree_back_and_reads_through_to_it() {
        let tree = DeepJson::new(json!({"type": "Array", "values": [5]}));
        assert_eq!(tree["type"], Value::from("Array"));
        assert_eq!(
            tree.get("values").and_then(Value::as_array).map(Vec::len),
            Some(1)
        );
        let value = tree.into_inner();
        assert_eq!(value["values"][0], Value::from(5));
        // No nesting: dismantle is a no-op cost.
        dismantle_json(Value::from(5));
    }

    #[test]
    fn the_debug_rendering_is_bounded_however_deep_the_tree_is() {
        let shallow = format!("{:?}", DeepJson::new(json!([1, 2])));
        assert_eq!(shallow, "DeepJson([1,2])");
        let deep = format!("{:?}", DeepJson::new(nested_arrays(10_000)));
        assert!(deep.len() < 600, "{}", deep.len());
        assert!(deep.ends_with(" bytes)"), "{}", deep);
    }

    // ============================================================
    // Stack cost of a deep tree, measured from a child process
    // ============================================================

    /// Nesting depth for the probe (far past decoder output).
    const PROBE_LEVELS: usize = 100_000;

    /// Probe thread stack; too small for a frame per level on any profile.
    const PROBE_STACK: usize = 64 * 1024;

    /// Selects the shape the probe child builds.
    const PROBE_SPEC: &str = "CQUISITOR_DEEP_JSON_PROBE";

    /// Libtest name of [`deep_tree_probe`].
    const PROBE_TEST: &str = "deep_json::tests::deep_tree_probe";

    /// Printed when a probe child finishes its walk.
    const PROBE_WALKED: &str = "the probe walked";

    /// Build, write, and free [`PROBE_LEVELS`] on [`PROBE_STACK`] bytes.
    ///
    /// Ignored entry point: stack exhaustion aborts the process, so
    /// calibration runs this in a child where abort is an assertion.
    #[test]
    #[ignore = "an entry point the child-process tests drive, not a check of its own"]
    fn deep_tree_probe() {
        let shape = match std::env::var(PROBE_SPEC) {
            Ok(shape) => shape,
            Err(_) => return,
        };
        std::thread::Builder::new()
            .stack_size(PROBE_STACK)
            .spawn(move || {
                let tree = match shape.as_str() {
                    "arrays" => nested_arrays(PROBE_LEVELS),
                    "objects" => nested_objects(PROBE_LEVELS),
                    other => panic!("no probe shape named {}", other),
                };
                let tree = DeepJson::new(tree);
                let text = write_json(&tree);
                assert!(text.len() > PROBE_LEVELS * 2, "{}", text.len());
                assert!(text.ends_with(']') || text.ends_with('}'));
                drop(tree);
            })
            .expect("failed to spawn the probe thread")
            .join()
            .expect("the walk did not hold");
        println!("{}", PROBE_WALKED);
    }

    /// Run the probe on `shape` in a child and require it to finish.
    fn probe_walks(shape: &str) {
        let output = Command::new(std::env::current_exe().expect("the test binary's own path"))
            .args([
                "--exact",
                PROBE_TEST,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(PROBE_SPEC, shape)
            .stdin(Stdio::null())
            .output()
            .expect("failed to run the probe child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success() && stdout.contains(PROBE_WALKED),
            "a tree of {} levels of {} did not survive being written and freed on a {} byte stack:\n{}{}",
            PROBE_LEVELS,
            shape,
            PROBE_STACK,
            stdout,
            stderr
        );
    }

    #[test]
    fn a_hundred_thousand_nested_arrays_are_written_and_freed_on_a_small_stack() {
        probe_walks("arrays");
    }

    #[test]
    fn a_hundred_thousand_nested_objects_are_written_and_freed_on_a_small_stack() {
        probe_walks("objects");
    }
}

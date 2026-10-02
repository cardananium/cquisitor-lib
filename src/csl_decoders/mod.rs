pub mod universal_decoder;
pub mod specific_decoders;
pub mod params;

use serde_json::Value;

/// A typed decoder's answer: JSON text.
///
/// The text crosses the wasm boundary as a string and is parsed by the
/// host (the TypeScript wrappers use `parseJsonExact`). Nothing between the
/// serialization library's own rendering and the host walks the document
/// again, so no layer of this crate adds host-stack recursion per level:
/// no `serde_json::Value` tree is built from the rendering, dropped, or
/// converted into JS objects level by level.
pub(crate) type Answer = String;

/// JSON text the serialization library rendered (`to_json`), compacted
/// but not parsed.
pub(crate) struct Rendered(String);

impl Rendered {
    /// The rendered text.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Take the serialization library's JSON rendering as it is, compacted.
///
/// The text is not read back into a value: a reader (and the tree it
/// builds, and that tree's drop) recurses once per level, and the
/// library's rendering can nest several JSON levels per CBOR level.
/// Insignificant whitespace is removed in one iterative pass (the library
/// pretty-prints some types, which costs indentation quadratic in depth).
pub(crate) fn rendered_json(json: &str) -> Result<Rendered, String> {
    Ok(Rendered(compact_json(json)))
}

/// `json` without whitespace outside string literals. Iterative; the text
/// is assumed to be JSON (it is the library's own rendering).
pub(crate) fn compact_json(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    let mut in_string = false;
    let mut escaped = false;
    for c in json.chars() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
        } else {
            match c {
                ' ' | '\n' | '\r' | '\t' => {}
                '"' => {
                    in_string = true;
                    out.push(c);
                }
                _ => out.push(c),
            }
        }
    }
    out
}

/// What a decoder answers with, turned into its JSON text.
pub(crate) trait IntoAnswer {
    fn into_answer(self) -> Answer;
}

impl IntoAnswer for Value {
    fn into_answer(self) -> Answer {
        crate::deep_json::write_json(&self)
    }
}

impl IntoAnswer for Rendered {
    fn into_answer(self) -> Answer {
        self.0
    }
}

/// `value` as the decoder's answer. Infallible; returns `Result` so a
/// decoder can end in `return answer(value);`.
pub(crate) fn answer<T: IntoAnswer>(value: T) -> Result<Answer, String> {
    Ok(value.into_answer())
}

/// A field of an answer object: a value built here, or the library's rendering.
pub(crate) enum Part {
    Value(Value),
    Rendered(Rendered),
}

/// `{"name": part, ...}` as JSON text, the rendered parts spliced in verbatim.
pub(crate) fn object_answer(fields: Vec<(&str, Part)>) -> Answer {
    let mut out = String::from("{");
    for (i, (name, part)) in fields.into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        crate::deep_json::write_string(&mut out, name);
        out.push(':');
        match part {
            Part::Value(value) => crate::deep_json::write_json_into(&mut out, &value),
            Part::Rendered(rendered) => out.push_str(rendered.as_str()),
        }
    }
    out.push('}');
    out
}

#[cfg(test)]
pub(crate) mod tests;

pub mod universal_decoder;
pub mod specific_decoders;
pub mod params;

/// The JSON text a typed decoder renders, read back as a value. The
/// reader's own nesting limit is lifted: the document behind the text was
/// already held to the typed decoders' bound before it was decoded, and a
/// level of it renders as up to a few levels of JSON, more than the
/// reader's default allows.
pub(crate) fn parse_rendered_json(json: &str) -> Result<serde_json::Value, String> {
    let mut deserializer = serde_json::Deserializer::from_str(json);
    deserializer.disable_recursion_limit();
    serde::Deserialize::deserialize(&mut deserializer)
        .map_err(|e| format!("Failed to parse JSON: {}", e))
}

#[cfg(test)]
mod tests;
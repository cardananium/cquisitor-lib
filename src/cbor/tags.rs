/// Human-readable CBOR tag name. Falls back to `Unassigned(n)` for tags
/// without a standard name.
pub fn tag_name(tag: u64) -> String {
    match tag {
        0 => "DateTime".to_string(),
        1 => "Timestamp".to_string(),
        2 => "PosBignum".to_string(),
        3 => "NegBignum".to_string(),
        4 => "Decimal".to_string(),
        5 => "Bigfloat".to_string(),
        21 => "ToBase64Url".to_string(),
        22 => "ToBase64".to_string(),
        23 => "ToBase16".to_string(),
        24 => "Cbor".to_string(),
        32 => "Uri".to_string(),
        33 => "Base64Url".to_string(),
        34 => "Base64".to_string(),
        35 => "Regex".to_string(),
        36 => "Mime".to_string(),
        other => format!("Unassigned({})", other),
    }
}
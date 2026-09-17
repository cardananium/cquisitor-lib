/// The tags with a name of their own, paired with the name each is shown
/// under.
///
/// One table serves both directions, so a name a decoded node carries always
/// reads back as the tag it was produced from.
const NAMED_TAGS: &[(u64, &str)] = &[
    (0, "DateTime"),
    (1, "Timestamp"),
    (2, "PosBignum"),
    (3, "NegBignum"),
    (4, "Decimal"),
    (5, "Bigfloat"),
    (21, "ToBase64Url"),
    (22, "ToBase64"),
    (23, "ToBase16"),
    (24, "Cbor"),
    (32, "Uri"),
    (33, "Base64Url"),
    (34, "Base64"),
    (35, "Regex"),
    (36, "Mime"),
];

/// How a tag without a name of its own is shown, around its number.
const UNASSIGNED_PREFIX: &str = "Unassigned(";
const UNASSIGNED_SUFFIX: &str = ")";

/// Human-readable CBOR tag name. Falls back to `Unassigned(n)` for tags
/// without a standard name.
pub fn tag_name(tag: u64) -> String {
    NAMED_TAGS
        .iter()
        .find(|(n, _)| *n == tag)
        .map(|(_, name)| (*name).to_string())
        .unwrap_or_else(|| format!("{}{}{}", UNASSIGNED_PREFIX, tag, UNASSIGNED_SUFFIX))
}

/// The tag a name produced by [`tag_name`] stands for, so a decoded node can
/// be described by number where the number is what a reader expects
/// (`#6.121`). `None` for anything [`tag_name`] does not produce.
pub fn tag_number(name: &str) -> Option<u64> {
    if let Some((tag, _)) = NAMED_TAGS.iter().find(|(_, n)| *n == name) {
        return Some(*tag);
    }
    name.strip_prefix(UNASSIGNED_PREFIX)?
        .strip_suffix(UNASSIGNED_SUFFIX)?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::{tag_name, tag_number};

    /// Every name the decoder can put on a node reads back as the tag it
    /// was made from, named and unassigned alike.
    #[test]
    fn tag_names_round_trip_through_their_number() {
        for tag in (0u64..40).chain([121, 255, 1004, u64::MAX]) {
            assert_eq!(tag_number(&tag_name(tag)), Some(tag), "tag {}", tag);
        }
    }

    /// A name no tag is shown under has no number.
    #[test]
    fn text_that_is_not_a_tag_name_has_no_number() {
        for name in [
            "",
            "Bytes",
            "Unassigned()",
            "Unassigned(x)",
            "Unassigned(-1)",
        ] {
            assert_eq!(tag_number(name), None, "name {:?}", name);
        }
    }
}

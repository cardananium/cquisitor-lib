//! Helper for converting UTF-8 byte offsets into UTF-16 code unit
//! offsets — what JS / TypeScript consumers naturally work with via
//! `string.length`, `string.slice`, etc. ASCII-only sources see
//! identical offsets either way.

use serde_json::{json, Value};

/// Pre-computed lookup: `byte_to_utf16[i]` is the number of UTF-16
/// code units in `source[..i]`. Stored as a flat `Vec` so any
/// arbitrary byte offset (even mid-character) maps to the start of
/// the enclosing character's UTF-16 position. The table has length
/// `source.len() + 1` so that the past-the-end byte position is also
/// valid.
pub struct Utf16Index {
    byte_to_utf16: Vec<usize>,
}

impl Utf16Index {
    pub fn new(source: &str) -> Self {
        let mut byte_to_utf16 = vec![0usize; source.len() + 1];
        let mut u16_count = 0usize;
        for (byte_i, ch) in source.char_indices() {
            let next = byte_i + ch.len_utf8();
            for j in byte_i..next {
                byte_to_utf16[j] = u16_count;
            }
            u16_count += ch.len_utf16();
        }
        byte_to_utf16[source.len()] = u16_count;
        Utf16Index { byte_to_utf16 }
    }

    /// Translate a byte offset into a UTF-16 code unit offset. Saturates
    /// at the end of the source.
    pub fn char_offset(&self, byte_offset: usize) -> usize {
        self.byte_to_utf16
            .get(byte_offset)
            .copied()
            .unwrap_or_else(|| {
                self.byte_to_utf16.last().copied().unwrap_or(0)
            })
    }
}

/// Build a JSON span object with both byte and UTF-16 char fields.
/// `byte_start` and `byte_end` are byte offsets in `source`; `line` is
/// 1-indexed.
pub fn span_json(idx: &Utf16Index, byte_start: usize, byte_end: usize, line: usize) -> Value {
    let byte_length = byte_end.saturating_sub(byte_start);
    let char_start = idx.char_offset(byte_start);
    let char_end = idx.char_offset(byte_end);
    let char_length = char_end.saturating_sub(char_start);
    json!({
        "offset": byte_start,
        "length": byte_length,
        "char_offset": char_start,
        "char_length": char_length,
        "line": line,
    })
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_only_byte_and_char_match() {
        let s = "alpha = uint";
        let idx = Utf16Index::new(s);
        assert_eq!(idx.char_offset(0), 0);
        assert_eq!(idx.char_offset(5), 5);
        assert_eq!(idx.char_offset(s.len()), s.len());
    }

    #[test]
    fn non_ascii_diverges_after_multi_byte_char() {
        // `; кириллица\nfoo = int` — `; ` (2 bytes, 2 chars), then 9
        // cyrillic chars (2 bytes / 1 UTF-16 unit each = 18 bytes / 9
        // units), then `\n`, then ASCII.
        let s = "; кириллица\nfoo = int";
        let idx = Utf16Index::new(s);
        // After `; ` (byte 2): 2 chars.
        assert_eq!(idx.char_offset(0), 0);
        assert_eq!(idx.char_offset(2), 2);
        // After `; кириллица` (byte 20 = 2 + 18): 11 chars.
        assert_eq!(idx.char_offset(20), 11);
        // After `; кириллица\n` (byte 21): 12 chars.
        assert_eq!(idx.char_offset(21), 12);
        // Past the end maps to total UTF-16 count.
        let total: usize = s.chars().map(|c| c.len_utf16()).sum();
        assert_eq!(idx.char_offset(s.len()), total);
    }

    #[test]
    fn span_json_carries_both_fields() {
        let s = "alpha = uint";
        let idx = Utf16Index::new(s);
        let span = span_json(&idx, 0, 5, 1);
        assert_eq!(span["offset"], 0);
        assert_eq!(span["length"], 5);
        assert_eq!(span["char_offset"], 0);
        assert_eq!(span["char_length"], 5);
        assert_eq!(span["line"], 1);
    }

    #[test]
    fn surrogate_pair_emoji_counts_two_utf16_units() {
        // 🦀 is U+1F980 = 4 UTF-8 bytes, 2 UTF-16 code units (surrogate pair).
        let s = "; 🦀 rust";
        let idx = Utf16Index::new(s);
        // After `; ` (2 bytes, 2 chars): same.
        assert_eq!(idx.char_offset(2), 2);
        // After `; 🦀` (2 + 4 = 6 bytes): UTF-16 = 2 + 2 = 4.
        assert_eq!(idx.char_offset(6), 4);
    }
}

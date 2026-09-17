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
    /// Byte offset of the first character of each line, ascending.
    /// `line_starts[0]` is always 0.
    line_starts: Vec<usize>,
}

impl Utf16Index {
    pub fn new(source: &str) -> Self {
        let mut byte_to_utf16 = vec![0usize; source.len() + 1];
        let mut line_starts = vec![0usize];
        let mut u16_count = 0usize;
        for (byte_i, ch) in source.char_indices() {
            let next = byte_i + ch.len_utf8();
            for j in byte_i..next {
                byte_to_utf16[j] = u16_count;
            }
            u16_count += ch.len_utf16();
            if ch == '\n' {
                line_starts.push(next);
            }
        }
        byte_to_utf16[source.len()] = u16_count;
        Utf16Index {
            byte_to_utf16,
            line_starts,
        }
    }

    /// 1-indexed line containing `byte_offset`. Offsets past the end of
    /// the source report the last line.
    pub fn line_at(&self, byte_offset: usize) -> usize {
        match self.line_starts.binary_search(&byte_offset) {
            Ok(i) => i + 1,
            Err(i) => i,
        }
    }

    /// Translate a byte offset into a UTF-16 code unit offset. An offset
    /// inside a character reports the start of that character. Saturates
    /// at the end of the source.
    pub fn char_offset(&self, byte_offset: usize) -> usize {
        self.byte_to_utf16
            .get(byte_offset)
            .copied()
            .unwrap_or_else(|| self.byte_to_utf16.last().copied().unwrap_or(0))
    }

    /// UTF-16 offset at the *end* of the character containing `byte_offset`
    /// (for range ends). Saturates at EOF.
    pub fn char_offset_ceil(&self, byte_offset: usize) -> usize {
        if self.is_char_boundary(byte_offset) {
            return self.char_offset(byte_offset);
        }
        // Advance to the next character boundary (≤4 bytes).
        let inside = self.byte_to_utf16[byte_offset];
        let mut i = byte_offset + 1;
        while self.byte_to_utf16.get(i) == Some(&inside) {
            i += 1;
        }
        self.byte_to_utf16.get(i).copied().unwrap_or(inside)
    }

    /// True if `byte_offset` is a character boundary (or past EOF).
    fn is_char_boundary(&self, byte_offset: usize) -> bool {
        match byte_offset {
            0 => true,
            i if i >= self.byte_to_utf16.len() => true,
            i => self.byte_to_utf16[i] != self.byte_to_utf16[i - 1],
        }
    }
}

/// A span of the source, in the fields every span of CDDL text is
/// reported with: the byte range, the UTF-16 code unit range, and the
/// 1-indexed line the span starts on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceSpan {
    pub offset: usize,
    pub length: usize,
    pub char_offset: usize,
    pub char_length: usize,
    pub line: usize,
}

/// Span `byte_start..byte_end` with 1-indexed `line`.
///
/// Char range rounds outward to character boundaries; empty byte ranges
/// stay empty (carets), so they are not expanded into a highlight.
pub fn source_span(
    idx: &Utf16Index,
    byte_start: usize,
    byte_end: usize,
    line: usize,
) -> SourceSpan {
    let byte_length = byte_end.saturating_sub(byte_start);
    let char_start = idx.char_offset(byte_start);
    let char_end = if byte_length == 0 {
        char_start
    } else {
        idx.char_offset_ceil(byte_end)
    };
    SourceSpan {
        offset: byte_start,
        length: byte_length,
        char_offset: char_start,
        char_length: char_end.saturating_sub(char_start),
        line,
    }
}

/// Build a JSON span object with both byte and UTF-16 char fields:
/// [`source_span`] as the object it is reported as.
pub fn span_json(idx: &Utf16Index, byte_start: usize, byte_end: usize, line: usize) -> Value {
    let span = source_span(idx, byte_start, byte_end, line);
    json!({
        "offset": span.offset,
        "length": span.length,
        "char_offset": span.char_offset,
        "char_length": span.char_length,
        "line": span.line,
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
    fn line_at_counts_newlines_before_the_offset() {
        let s = "a = uint\n\nb = tstr\nc = bool";
        let idx = Utf16Index::new(s);
        for (offset, _) in s.char_indices() {
            assert_eq!(
                idx.line_at(offset),
                s[..offset].matches('\n').count() + 1,
                "offset {} of {:?}",
                offset,
                s
            );
        }
        // Past the end stays on the last line.
        assert_eq!(idx.line_at(s.len()), 4);
        assert_eq!(idx.line_at(s.len() + 100), 4);
    }

    #[test]
    fn line_at_handles_a_source_with_no_newline() {
        let idx = Utf16Index::new("a = uint");
        assert_eq!(idx.line_at(0), 1);
        assert_eq!(idx.line_at(7), 1);
        assert_eq!(Utf16Index::new("").line_at(0), 1);
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

    /// A parser's byte offsets can land inside a character. A byte span
    /// that is not empty has to come back as a char span that is not
    /// empty, or a consumer slicing by it highlights nothing.
    #[test]
    fn a_span_inside_one_character_still_covers_that_character() {
        // `é` is 2 UTF-8 bytes and 1 UTF-16 unit; `🦀` is 4 and 2.
        for (source, byte_start, byte_end, expected) in [
            ("é", 0usize, 1usize, (0usize, 1usize)),
            ("é", 1, 2, (0, 1)),
            ("aéb", 2, 3, (1, 1)),
            ("🦀", 1, 3, (0, 2)),
            ("🦀", 0, 4, (0, 2)),
        ] {
            let idx = Utf16Index::new(source);
            let span = span_json(&idx, byte_start, byte_end, 1);
            assert_eq!(
                (
                    span["char_offset"].as_u64().unwrap() as usize,
                    span["char_length"].as_u64().unwrap() as usize,
                ),
                expected,
                "{:?} bytes {}..{}",
                source,
                byte_start,
                byte_end
            );
        }
    }

    /// The negative half: rounding outward must not stretch a span that
    /// already sits on character boundaries, and an empty byte span
    /// stays empty.
    #[test]
    fn a_span_on_character_boundaries_is_left_alone() {
        let source = "aéb🦀c";
        let idx = Utf16Index::new(source);
        // Every boundary-to-boundary span reports exactly the characters
        // between them.
        let boundaries: Vec<usize> = source
            .char_indices()
            .map(|(i, _)| i)
            .chain(std::iter::once(source.len()))
            .collect();
        for (n, &start) in boundaries.iter().enumerate() {
            for &end in &boundaries[n..] {
                let span = span_json(&idx, start, end, 1);
                let expected: usize = source[start..end].chars().map(char::len_utf16).sum();
                assert_eq!(
                    span["char_length"].as_u64().unwrap() as usize,
                    expected,
                    "bytes {}..{}",
                    start,
                    end
                );
            }
        }
        // Empty byte span → empty char span (caret, not highlight).
        for offset in 0..=source.len() {
            assert_eq!(
                span_json(&idx, offset, offset, 1)["char_length"],
                0,
                "byte {}",
                offset
            );
        }
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

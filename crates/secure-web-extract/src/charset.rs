//! Body decoding. UTF-8 (lossy) by default; `windows-1252` and its WHATWG aliases
//! (`iso-8859-1`, `latin1`, `us-ascii`, …) are decoded exactly. Other charsets fall back to lossy
//! UTF-8 (`docs/backlog.md`: a full WHATWG decoder is deferred).

use std::borrow::Cow;

/// `windows-1252` code points for bytes `0x80..=0x9F` (WHATWG index).
const WINDOWS_1252_HIGH: [char; 32] = [
    '\u{20AC}', '\u{0081}', '\u{201A}', '\u{0192}', '\u{201E}', '\u{2026}', '\u{2020}', '\u{2021}',
    '\u{02C6}', '\u{2030}', '\u{0160}', '\u{2039}', '\u{0152}', '\u{008D}', '\u{017D}', '\u{008F}',
    '\u{0090}', '\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}', '\u{2022}', '\u{2013}', '\u{2014}',
    '\u{02DC}', '\u{2122}', '\u{0161}', '\u{203A}', '\u{0153}', '\u{009D}', '\u{017E}', '\u{0178}',
];

/// WHATWG labels that decode as `windows-1252`.
const WINDOWS_1252_LABELS: [&str; 17] = [
    "ansi_x3.4-1968",
    "ascii",
    "cp1252",
    "cp819",
    "csisolatin1",
    "ibm819",
    "iso-8859-1",
    "iso-ir-100",
    "iso8859-1",
    "iso88591",
    "iso_8859-1",
    "iso_8859-1:1987",
    "l1",
    "latin1",
    "us-ascii",
    "windows-1252",
    "x-cp1252",
];

/// Decode `body` using the `charset` parameter.
pub(crate) fn decode<'a>(body: &'a [u8], charset: Option<&str>) -> Cow<'a, str> {
    let label = charset.map(|c| c.trim().to_ascii_lowercase());
    match label.as_deref() {
        Some(label) if WINDOWS_1252_LABELS.contains(&label) => {
            Cow::Owned(body.iter().map(|&b| windows_1252(b)).collect())
        }
        None | Some("utf-8" | "utf8" | "unicode-1-1-utf-8") => String::from_utf8_lossy(body),
        Some(_) => {
            tracing::debug!("unsupported charset; decoding as lossy UTF-8");
            String::from_utf8_lossy(body)
        }
    }
}

fn windows_1252(byte: u8) -> char {
    match byte {
        0x80..=0x9F => WINDOWS_1252_HIGH[usize::from(byte - 0x80)],
        _ => char::from(byte),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_is_default_and_lossy() {
        assert_eq!(decode("héllo".as_bytes(), None), "héllo");
        assert_eq!(decode(b"a\xffb", Some("utf-8")), "a\u{FFFD}b");
    }

    #[test]
    fn windows_1252_aliases_decode_exactly() {
        assert_eq!(decode(b"caf\xe9 \x80", Some("ISO-8859-1")), "café €");
        assert_eq!(
            decode(b"\x93q\x94", Some("windows-1252")),
            "\u{201C}q\u{201D}"
        );
    }

    #[test]
    fn unknown_charset_falls_back_to_utf8() {
        assert_eq!(decode("ok".as_bytes(), Some("shift_jis")), "ok");
    }
}

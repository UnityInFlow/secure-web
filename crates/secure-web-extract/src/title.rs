//! Model-facing metadata normalization (`docs/security-policy.md` §7, threat T13).

use unicode_normalization::char::is_combining_mark;
use unicode_normalization::UnicodeNormalization;

use crate::textclean;

/// Longest normalized title, in characters.
pub const MAX_TITLE_CHARS: usize = 200;

/// Longest slug, in bytes (ASCII).
pub const MAX_SLUG_LEN: usize = 48;

/// Normalize an untrusted title: invisible/control characters stripped
/// ([`textclean::is_stripped`]), Unicode NFC, whitespace collapsed, at most
/// [`MAX_TITLE_CHARS`] characters. `None` when nothing is left.
pub fn normalize_title(raw: &str) -> Option<String> {
    let cleaned = textclean::clean(raw);
    let nfc: String = cleaned.nfc().collect();
    let collapsed = textclean::collapse(&nfc);
    let capped: String = collapsed.chars().take(MAX_TITLE_CHARS).collect();
    let trimmed = capped.trim_end();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// A filename slug from a title or path: ASCII `[a-z0-9-]{0,48}`, no leading, trailing or
/// doubled `-`. Accents are folded (`é` → `e`); every other character becomes a separator.
pub fn slug(source: &str) -> String {
    let mut out = String::with_capacity(MAX_SLUG_LEN);
    let mut dash = false;
    for c in source.nfkd().filter(|c| !is_combining_mark(*c)) {
        if out.len() >= MAX_SLUG_LEN {
            break;
        }
        if c.is_ascii_alphanumeric() {
            if dash && !out.is_empty() {
                out.push('-');
                if out.len() >= MAX_SLUG_LEN {
                    break;
                }
            }
            dash = false;
            out.push(c.to_ascii_lowercase());
        } else {
            dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn title_is_cleaned_nfc_and_capped() {
        assert_eq!(
            normalize_title("  Cafe\u{0301}\u{202E}\u{0007}\n\t menu ").as_deref(),
            Some("Café menu")
        );
        assert_eq!(normalize_title(" \u{200B} "), None);
        let long = "x".repeat(10_000);
        assert_eq!(
            normalize_title(&long).map(|t| t.chars().count()),
            Some(MAX_TITLE_CHARS)
        );
    }

    #[test]
    fn slug_is_ascii_and_bounded() {
        assert_eq!(slug("Getting Started — Café!"), "getting-started-cafe");
        assert_eq!(slug("../../etc/passwd"), "etc-passwd");
        assert_eq!(slug("日本語"), "");
        assert_eq!(slug(&"ab ".repeat(40)).len(), 47);
    }
}

//! Character filtering shared by `security_text`, display text and titles.
//!
//! The same filter runs on both outputs so the scanner always sees what the model sees: an
//! invisible character that could split a word for the scanner (`ig\u{200B}nore`) is removed
//! from both, and a character that reaches the model is never hidden from the scanner.

/// Whether `c` is removed from every extracted text: control characters (except `\n` and
/// `\t`), bidirectional overrides/isolates, zero-width and other invisible format characters,
/// Unicode tag characters and variation selectors (used for invisible "ASCII smuggling").
pub fn is_stripped(c: char) -> bool {
    if c == '\n' || c == '\t' {
        return false;
    }
    if c.is_control() {
        return true;
    }
    matches!(
        c,
        '\u{00AD}'                    // soft hyphen
            | '\u{034F}'              // combining grapheme joiner
            | '\u{0600}'..='\u{0605}' // Arabic number signs
            | '\u{061C}'              // Arabic letter mark
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{115F}'..='\u{1160}' // Hangul fillers
            | '\u{17B4}'..='\u{17B5}'
            | '\u{180B}'..='\u{180F}' // Mongolian variation selectors / vowel separator
            | '\u{200B}'..='\u{200F}' // zero-width space/joiners, LRM, RLM
            | '\u{202A}'..='\u{202E}' // bidi embeddings and overrides
            | '\u{2060}'..='\u{206F}' // word joiner, invisible operators, bidi isolates
            | '\u{3164}'              // Hangul filler
            | '\u{FE00}'..='\u{FE0F}' // variation selectors
            | '\u{FEFF}'              // BOM / zero-width no-break space
            | '\u{FFA0}'
            | '\u{FFF0}'..='\u{FFFB}' // interlinear annotations
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E007F}' // tag characters
            | '\u{E0100}'..='\u{E01EF}' // variation selectors supplement
    )
}

/// `text` with [`is_stripped`] characters removed and `\r\n` / `\r` turned into `\n`.
pub fn clean(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            out.push('\n');
        } else if !is_stripped(c) {
            out.push(c);
        }
    }
    out
}

/// Append `text` to `out`, cleaned, with every whitespace run collapsed to one space. `pending`
/// carries "a space is owed" across calls so inline boundaries collapse too; leading whitespace
/// of the whole run is dropped when `out` is empty.
pub(crate) fn push_collapsed(out: &mut String, text: &str, pending: &mut bool) {
    for c in text.chars() {
        if c.is_whitespace() || c == '\r' {
            *pending = true;
        } else if !is_stripped(c) {
            if *pending && !out.is_empty() {
                out.push(' ');
            }
            *pending = false;
            out.push(c);
        }
    }
}

/// `text` cleaned and whitespace-collapsed to single spaces, trimmed.
pub fn collapse(text: &str) -> String {
    let mut out = String::new();
    let mut pending = false;
    push_collapsed(&mut out, text, &mut pending);
    out
}

/// `text` cleaned for the scanner: horizontal whitespace runs become one space, runs containing
/// a line break become one `\n` (line structure is kept for multi-line scanning).
pub(crate) fn collapse_for_scan(out: &mut String, text: &str) {
    let mut run: Option<char> = None;
    for c in text.chars() {
        if c.is_whitespace() || c == '\r' {
            let newline = matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}');
            run = Some(match run {
                Some('\n') => '\n',
                _ if newline => '\n',
                _ => ' ',
            });
        } else if !is_stripped(c) {
            if let Some(ws) = run.take() {
                out.push(ws);
            }
            out.push(c);
        }
    }
    if let Some(ws) = run {
        out.push(ws);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_invisible_and_control_characters() {
        assert_eq!(
            clean("ig\u{200B}no\u{202E}re\u{E0041}\u{0007} a\r\nb\rc\td"),
            "ignore a\nb\nc\td"
        );
    }

    #[test]
    fn collapse_joins_whitespace_runs_and_trims() {
        assert_eq!(collapse("  a \n\t b\u{00A0}\u{00A0}c  "), "a b c");
        assert_eq!(collapse("\u{200B}"), "");
    }

    #[test]
    fn scan_collapse_keeps_line_breaks() {
        let mut out = String::new();
        collapse_for_scan(&mut out, "a  b\n\n  c\u{200B}d ");
        assert_eq!(out, "a b\ncd ");
    }
}

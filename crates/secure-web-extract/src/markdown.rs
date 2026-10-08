//! Deterministic Markdown from a [`StructuredDocument`] (`docs/contracts/manifest-schema.md`,
//! "Page file format").
//!
//! Output rules: ATX headings, fenced code (the fence is longer than any backtick run in the
//! code), pipe tables, `-` / `1.` lists, one blank line between blocks, `\n` line endings, no
//! trailing whitespace, exactly one final newline (empty document → empty string). Links render
//! inline as `[text](href)`.
//!
//! **No raw HTML passthrough:** every character of page text that Markdown could interpret
//! (`<`, `>`, `&`, `*`, `_`, `` ` ``, `[`, `]`, `|`, `~`, `\`, and block markers at line
//! start) is backslash-escaped, so the output never contains an HTML tag, entity, emphasis or
//! link the page did not have as structure.
//!
//! The title is **not** rendered: the corpus store emits the normalized title as the page's
//! first heading (and the title is scanned separately), so `render` only covers the body.

use secure_web_core::model::{Block, Inline, StructuredDocument};

/// Render `doc` to Markdown. Pure function of its input: byte-identical for equal documents.
pub fn render(doc: &StructuredDocument) -> String {
    render_body(&doc.blocks)
}

/// [`render`] of a document body (the title is never rendered).
pub(crate) fn render_body(blocks: &[Block]) -> String {
    let lines = render_blocks(blocks);
    let mut out = String::new();
    for line in lines {
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// Render blocks to lines, one blank line between blocks.
fn render_blocks(blocks: &[Block]) -> Vec<String> {
    let mut lines = Vec::new();
    for block in blocks {
        let rendered = render_block(block);
        if rendered.is_empty() {
            continue;
        }
        if !lines.is_empty() {
            lines.push(String::new());
        }
        lines.extend(rendered);
    }
    lines
}

fn render_block(block: &Block) -> Vec<String> {
    match block {
        Block::Heading { level, text } => {
            let text = escape_heading(text);
            if text.is_empty() {
                return Vec::new();
            }
            let level = usize::from((*level).clamp(1, 6));
            vec![format!("{} {text}", "#".repeat(level))]
        }
        Block::Paragraph(inlines) => {
            let text = render_inlines(inlines, false);
            if text.is_empty() {
                Vec::new()
            } else {
                vec![text]
            }
        }
        Block::Code { lang, text } => render_code(lang.as_deref(), text),
        Block::List { ordered, items } => render_list(*ordered, items),
        Block::Table { rows } => render_table(rows),
        Block::Quote(blocks) => render_blocks(blocks)
            .into_iter()
            .map(|line| {
                if line.is_empty() {
                    ">".to_owned()
                } else {
                    format!("> {line}")
                }
            })
            .collect(),
    }
}

fn render_code(lang: Option<&str>, text: &str) -> Vec<String> {
    let longest_run = longest_backtick_run(text);
    let fence = "`".repeat(longest_run.max(2) + 1);
    let lang = lang
        .filter(|l| {
            !l.is_empty()
                && l.len() <= 32
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"+#._-".contains(&b))
        })
        .unwrap_or("");
    let mut lines = vec![format!("{fence}{lang}")];
    lines.extend(text.split('\n').map(|line| {
        line.chars()
            .filter(|&c| c == '\t' || !crate::textclean::is_stripped(c))
            .collect::<String>()
            .trim_end()
            .to_owned()
    }));
    lines.push(fence);
    lines
}

fn longest_backtick_run(text: &str) -> usize {
    let mut longest = 0;
    let mut run = 0;
    for c in text.chars() {
        if c == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    longest
}

fn render_list(ordered: bool, items: &[Vec<Block>]) -> Vec<String> {
    let mut lines = Vec::new();
    let mut number = 0usize;
    for item in items {
        let body = render_item(item);
        if body.is_empty() {
            continue;
        }
        number += 1;
        let marker = if ordered {
            format!("{number}. ")
        } else {
            "- ".to_owned()
        };
        let indent = " ".repeat(marker.len());
        for (i, line) in body.into_iter().enumerate() {
            if i == 0 {
                lines.push(format!("{marker}{line}"));
            } else if line.is_empty() {
                lines.push(String::new());
            } else {
                lines.push(format!("{indent}{line}"));
            }
        }
    }
    lines
}

/// An item's blocks: a nested list follows its paragraph directly (tight), other blocks are
/// separated by a blank line.
fn render_item(blocks: &[Block]) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for block in blocks {
        let rendered = render_block(block);
        if rendered.is_empty() {
            continue;
        }
        if !lines.is_empty() && !matches!(block, Block::List { .. }) {
            lines.push(String::new());
        }
        lines.extend(rendered);
    }
    lines
}

fn render_table(rows: &[Vec<Vec<Inline>>]) -> Vec<String> {
    let width = rows.iter().map(Vec::len).max().unwrap_or(0);
    if width == 0 {
        return Vec::new();
    }
    let render_row = |row: &Vec<Vec<Inline>>| {
        let cells: Vec<String> = (0..width)
            .map(|i| {
                row.get(i)
                    .map(|c| render_inlines(c, true))
                    .unwrap_or_default()
            })
            .collect();
        format!("| {} |", cells.join(" | "))
    };
    let mut lines = Vec::with_capacity(rows.len() + 1);
    let mut rows = rows.iter();
    if let Some(header) = rows.next() {
        lines.push(render_row(header));
        lines.push(format!("|{}", " --- |".repeat(width)));
    }
    lines.extend(rows.map(render_row));
    lines
}

/// Inline content on one line. In a table cell a `|` inside inline code is escaped too (GFM
/// splits cells before parsing code spans).
fn render_inlines(inlines: &[Inline], in_table: bool) -> String {
    let mut out = String::new();
    for inline in inlines {
        let at_start = out.is_empty();
        match inline {
            Inline::Text(text) => out.push_str(&escape_text(text, at_start)),
            Inline::Code(text) => {
                let code = inline_code(text);
                if in_table {
                    out.push_str(&code.replace('|', "\\|"));
                } else {
                    out.push_str(&code);
                }
            }
            Inline::Link { href, text } => {
                let text = escape_text(text, false);
                if text.is_empty() {
                    continue;
                }
                out.push('[');
                out.push_str(&text);
                out.push_str("](");
                out.push_str(&escape_destination(href.as_str()));
                out.push(')');
            }
        }
    }
    out.trim().to_owned()
}

fn inline_code(text: &str) -> String {
    let text: String = text
        .chars()
        .map(|c| if c == '\n' || c == '\t' { ' ' } else { c })
        .filter(|&c| !crate::textclean::is_stripped(c))
        .collect();
    if text.trim().is_empty() {
        return String::new();
    }
    let fence = "`".repeat(longest_backtick_run(&text) + 1);
    let pad = if text.starts_with('`') || text.ends_with('`') {
        " "
    } else {
        ""
    };
    format!("{fence}{pad}{text}{pad}{fence}")
}

/// Characters escaped anywhere in text.
fn always_escaped(c: char) -> bool {
    matches!(
        c,
        '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '&' | '|' | '~'
    )
}

/// Escape one line of page text for use in a paragraph, cell or link text. `at_line_start`
/// additionally neutralizes block markers (`#`, `-`, `+`, `=`, `1.`).
fn escape_text(text: &str, at_line_start: bool) -> String {
    let text: String = text
        .chars()
        .map(|c| if c == '\n' || c == '\t' { ' ' } else { c })
        .filter(|&c| !crate::textclean::is_stripped(c))
        .collect();
    let mut out = String::with_capacity(text.len() + 8);
    let mut leading_digits = at_line_start;
    for (i, c) in text.char_indices() {
        let line_start_marker = at_line_start && i == 0 && matches!(c, '#' | '-' | '+' | '=');
        // `1.` / `1)` followed by a space or the end of the line starts an ordered list.
        let ordered_marker = leading_digits
            && (c == '.' || c == ')')
            && i > 0
            && text[..i].bytes().all(|b| b.is_ascii_digit())
            && text[i + 1..].chars().next().is_none_or(char::is_whitespace);
        if !c.is_ascii_digit() {
            leading_digits = false;
        }
        if always_escaped(c) || line_start_marker || ordered_marker {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Heading text: escaped, and every `#` escaped so no closing sequence can form.
fn escape_heading(text: &str) -> String {
    let escaped = escape_text(text, true);
    let mut out = String::with_capacity(escaped.len());
    let mut previous_backslash = false;
    for c in escaped.chars() {
        if c == '#' && !previous_backslash {
            out.push('\\');
        }
        previous_backslash = c == '\\' && !previous_backslash;
        out.push(c);
    }
    out.trim().to_owned()
}

/// A link destination: backslash-escape the characters that would end or break it.
fn escape_destination(href: &str) -> String {
    let mut out = String::with_capacity(href.len());
    for c in href.chars() {
        if matches!(c, '(' | ')' | '\\' | '<' | '>' | ' ') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::*;

    fn text(s: &str) -> Inline {
        Inline::Text(s.to_owned())
    }

    fn doc(blocks: Vec<Block>) -> StructuredDocument {
        StructuredDocument {
            title: Some("ignored".into()),
            blocks,
        }
    }

    #[test]
    fn renders_every_block_kind() {
        let href = Url::parse("https://example.com/a_(b)").unwrap();
        let md = render(&doc(vec![
            Block::Heading {
                level: 2,
                text: "Install #1".into(),
            },
            Block::Paragraph(vec![
                text("See "),
                Inline::Link {
                    href,
                    text: "the guide".into(),
                },
                text(" and run "),
                Inline::Code("a`b".into()),
                text("."),
            ]),
            Block::Code {
                lang: Some("rust".into()),
                text: "fn main() {}\n```\n".into(),
            },
            Block::List {
                ordered: true,
                items: vec![
                    vec![
                        Block::Paragraph(vec![text("one")]),
                        Block::List {
                            ordered: false,
                            items: vec![vec![Block::Paragraph(vec![text("nested")])]],
                        },
                    ],
                    vec![Block::Paragraph(vec![text("two")])],
                ],
            },
            Block::Table {
                rows: vec![
                    vec![vec![text("k")], vec![text("v")]],
                    vec![vec![text("a|b")]],
                ],
            },
            Block::Quote(vec![
                Block::Paragraph(vec![text("q1")]),
                Block::Paragraph(vec![text("q2")]),
            ]),
        ]));
        assert_eq!(
            md,
            "## Install \\#1\n\
             \n\
             See [the guide](https://example.com/a_\\(b\\)) and run ``a`b``.\n\
             \n\
             ````rust\n\
             fn main() {}\n\
             ```\n\
             \n\
             ````\n\
             \n\
             1. one\n   - nested\n2. two\n\
             \n\
             | k | v |\n\
             | --- | --- |\n\
             | a\\|b |  |\n\
             \n\
             > q1\n\
             >\n\
             > q2\n"
        );
    }

    #[test]
    fn page_text_cannot_become_markup() {
        let md = render(&doc(vec![
            Block::Paragraph(vec![text("<script>alert(1)</script> &amp; *x* [a](b)")]),
            Block::Paragraph(vec![text("# not a heading")]),
            Block::Paragraph(vec![text("1. not a list")]),
            Block::Paragraph(vec![text("- not a list")]),
        ]));
        assert_eq!(
            md,
            "\\<script\\>alert(1)\\</script\\> \\&amp; \\*x\\* \\[a\\](b)\n\
             \n\
             \\# not a heading\n\
             \n\
             1\\. not a list\n\
             \n\
             \\- not a list\n"
        );
    }

    #[test]
    fn pipes_in_table_code_do_not_split_cells() {
        let md = render(&doc(vec![Block::Table {
            rows: vec![vec![vec![Inline::Code("a|b".into())], vec![text("c")]]],
        }]));
        assert_eq!(md, "| `a\\|b` | c |\n| --- | --- |\n");
    }

    #[test]
    fn empty_document_renders_empty() {
        assert_eq!(render(&StructuredDocument::default()), "");
    }
}

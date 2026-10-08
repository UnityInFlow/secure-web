//! Display extraction and Markdown rendering (SW-007): chrome removed, `<main>` preferred,
//! structure kept, no raw HTML passthrough, and the non-HTML extractors.
// Test helpers outside `#[test]` fns are not covered by clippy.toml's allow-*-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "../support/extract.rs"]
mod extract;

use extract::{extract_html, extract_str, fetch_extract, Harness};
use pulldown_cmark::{Event, Parser};
use secure_web_core::model::Block;
use secure_web_extract::markdown::render;
use secure_web_extract::{ExtractLimits, SourceKind};

fn md(html: &str) -> String {
    render(&extract_html(html).display)
}

fn assert_no_raw_html(markdown: &str) {
    for event in Parser::new(markdown) {
        assert!(
            !matches!(event, Event::Html(_) | Event::InlineHtml(_)),
            "raw HTML {event:?} in {markdown:?}"
        );
    }
}

#[test]
fn chrome_is_removed() {
    let out = md(
        "<body><header><p>Site</p></header><nav>Menu</nav><aside>Side</aside>\
         <div role=\"navigation\">Nav2</div><div role=\"banner\">Ban</div>\
         <p>Body text</p><div role=\"contentinfo\">Info</div><footer>Foot</footer></body>",
    );
    assert_eq!(out, "Body text\n");
}

#[test]
fn main_is_preferred_over_body() {
    let out = md("<body><p>outside</p><main><p>inside</p></main><p>after</p></body>");
    assert_eq!(out, "inside\n");
    // A hidden <main> is not chosen.
    let out = md("<body><main hidden><p>x</p></main><p>body</p></body>");
    assert_eq!(out, "body\n");
}

#[test]
fn article_headers_are_content_but_page_headers_are_not() {
    let out = md(
        "<header>Site</header><article><header><h1>Post</h1></header><p>Text</p>\
         <footer>By me</footer></article>",
    );
    assert_eq!(out, "# Post\n\nText\n\nBy me\n");
}

#[test]
fn headings_code_tables_lists_and_quotes_are_kept() {
    let out = md("<h2>Title <a href=\"/x\">link</a></h2>\
         <pre class=\"language-rust\">fn main() {\n    println!(\"&lt;hi&gt;\");   \n}\n</pre>\
         <table><tr><th>a</th><th>b</th></tr><tr><td>1</td><td><a href=\"/t\">2</a></td></tr></table>\
         <ul><li>one<ul><li>nested</li></ul></li><li>two</li></ul>\
         <blockquote><p>quoted</p></blockquote>");
    assert_eq!(
        out,
        "## Title link\n\
         \n\
         ```rust\n\
         fn main() {\n    println!(\"<hi>\");\n}\n\
         ```\n\
         \n\
         | a | b |\n\
         | --- | --- |\n\
         | 1 | [2](http://fixture.test/t) |\n\
         \n\
         - one\n  - nested\n- two\n\
         \n\
         > quoted\n"
    );
}

#[test]
fn pre_keeps_code_verbatim_but_drops_hidden_parts() {
    let out = md("<pre><code class=\"lang-sh\">echo  one\n<span style=\"display:none\">SECRET</span>echo two</code></pre>");
    assert_eq!(out, "```sh\necho  one\necho two\n```\n");
}

#[test]
fn images_forms_and_embedded_content_are_not_displayed() {
    let out = md(
        "<p>a</p><img alt=\"pic\"><svg><text>svg</text></svg><canvas>c</canvas>\
         <select><option>o</option></select><button>b</button><textarea>t</textarea>\
         <video>v</video><iframe>i</iframe><object>obj</object><p>z</p>",
    );
    assert_eq!(out, "a\n\nz\n");
}

#[test]
fn no_raw_html_passthrough_for_hostile_text() {
    let out = md(
        "<p>&lt;img src=x onerror=alert(1)&gt; &lt;!-- c --&gt; &amp;amp; \
         &lt;a href=&quot;javascript:x&quot;&gt;x&lt;/a&gt;</p>\
         <h3>&lt;script&gt;</h3>\
         <table><tr><td>&lt;b&gt;|x</td></tr></table>\
         <ul><li>&lt;div&gt;</li></ul>\
         <p><code>&lt;/code&gt;&lt;script&gt;</code></p>\
         <p><a href=\"/p\">&lt;i&gt;x&lt;/i&gt;</a></p>\
         <pre>&lt;/pre&gt;&lt;script&gt;alert(1)&lt;/script&gt;\n```\n</pre>",
    );
    assert_no_raw_html(&out);
    assert!(!out.contains("<img") || out.contains("\\<img"));
}

#[test]
fn whitespace_is_collapsed_across_inline_boundaries() {
    let out = md("<p>  a <b> b </b><i>c</i>\n\n d <a href=\"/x\"> link </a>e<br>f  </p>");
    assert_eq!(out, "a b c d [link](http://fixture.test/x) e f\n");
}

#[test]
fn rendering_twice_is_byte_equal() {
    let doc = extract_html("<h1>A</h1><p>b <a href=\"/c\">c</a></p><ol><li>d</li></ol>");
    assert_eq!(render(&doc.display), render(&doc.display));
    assert_eq!(
        extract_html("<h1>A</h1><p>b</p>"),
        extract_html("<h1>A</h1><p>b</p>")
    );
}

#[test]
fn plain_text_becomes_paragraphs() {
    let doc = extract_str(
        "Release notes\r\n\r\n0.2.0 adds <b>dry-run</b>.\n0.1.0 first.\n\n\n",
        SourceKind::PlainText,
        "http://fixture.test/notes",
        ExtractLimits::default(),
    )
    .unwrap();
    assert_eq!(doc.display.blocks.len(), 2);
    assert_eq!(
        render(&doc.display),
        "Release notes\n\n0.2.0 adds \\<b\\>dry-run\\</b\\>. 0.1.0 first.\n"
    );
    assert!(doc.security_text.contains("<b>dry-run</b>"));
    assert_eq!(doc.title, None);
    assert!(doc.links.is_empty());
}

#[test]
fn markdown_keeps_structure_and_strips_raw_html() {
    let source = "# Guide\n\nSee [the docs](/docs#x) and `code`.\n\n\
                  <div style=\"display:none\">HIDDEN-MD</div>\n\n\
                  <!-- COMMENT-MD -->\n\n\
                  Inline <span>html</span> <script>bad()</script> text.\n\n\
                  | a | b |\n|---|---|\n| 1 | 2 |\n\n\
                  ```rust\nfn x() {}\n```\n";
    let doc = extract_str(
        source,
        SourceKind::Markdown,
        "http://fixture.test/guide",
        ExtractLimits::default(),
    )
    .unwrap();
    let out = render(&doc.display);
    assert_eq!(
        out,
        "# Guide\n\
         \n\
         See [the docs](http://fixture.test/docs) and `code`.\n\
         \n\
         Inline html text.\n\
         \n\
         | a | b |\n\
         | --- | --- |\n\
         | 1 | 2 |\n\
         \n\
         ```rust\n\
         fn x() {}\n\
         ```\n"
    );
    assert_no_raw_html(&out);
    // The source (raw HTML included) is the scanner input.
    for hidden in ["HIDDEN-MD", "COMMENT-MD", "bad()"] {
        assert!(doc.security_text.contains(hidden), "{hidden}");
        assert!(!out.contains(hidden), "{hidden}");
    }
    assert_eq!(doc.title.as_deref(), Some("Guide"));
    assert!(doc.security_text.ends_with("[hidden:title]\nGuide\n"));
    assert_eq!(
        doc.links.iter().map(|u| u.url.as_str()).collect::<Vec<_>>(),
        ["http://fixture.test/docs"]
    );
}

#[test]
fn json_is_pretty_printed_in_a_fenced_block() {
    let doc = extract_str(
        "{\"b\": [1, 2], \"a\": \"x```y\\u0000\"}",
        SourceKind::Json,
        "http://fixture.test/data",
        ExtractLimits::default(),
    )
    .unwrap();
    let out = render(&doc.display);
    assert_eq!(
        out,
        "````json\n{\n  \"a\": \"x```y\\u0000\",\n  \"b\": [\n    1,\n    2\n  ]\n}\n````\n"
    );
    assert!(doc.security_text.contains("\"a\": \"x```y\\u0000\""));
    assert!(matches!(doc.display.blocks[0], Block::Code { .. }));
    // Invalid JSON is shown as text, still fenced.
    let doc = extract_str(
        "{not json <b>",
        SourceKind::Json,
        "http://fixture.test/data",
        ExtractLimits::default(),
    )
    .unwrap();
    assert_eq!(render(&doc.display), "```json\n{not json <b>\n```\n");
}

#[tokio::test]
async fn fetched_clean_page_renders() {
    let harness = Harness::start().await;
    let doc = fetch_extract(&harness, "/clean/a").await;
    assert_eq!(doc.title.as_deref(), Some("Getting started"));
    let out = render(&doc.display);
    assert!(out.starts_with("# Getting started\n\nThis page explains"));
    assert!(out.contains("```\ncargo install example-tool\n```"));
    assert!(out.contains(&format!("[guide]({})", harness.url("/clean/guide"))));
}

mod properties {
    use proptest::prelude::*;
    use secure_web_core::model::{Block, Inline, StructuredDocument};
    use secure_web_extract::markdown::render;
    use url::Url;

    use super::{assert_no_raw_html, extract_html};

    fn hostile_text() -> impl Strategy<Value = String> {
        "[<>&`*_\\[\\]|~#=+\\-!()\\\\/a-z0-9 .\n]{0,40}"
    }

    proptest! {
        #[test]
        fn page_text_never_renders_as_raw_html(
            a in hostile_text(),
            b in hostile_text(),
            c in hostile_text(),
        ) {
            let href = Url::parse("https://example.com/p").unwrap();
            let doc = StructuredDocument {
                title: None,
                blocks: vec![
                    Block::Heading { level: 2, text: a.clone() },
                    Block::Paragraph(vec![
                        Inline::Text(a.clone()),
                        Inline::Code(b.clone()),
                        Inline::Link { href, text: c.clone() },
                    ]),
                    Block::Table {
                        rows: vec![vec![vec![Inline::Text(b.clone())], vec![Inline::Code(c.clone())]]],
                    },
                    Block::List {
                        ordered: false,
                        items: vec![vec![Block::Paragraph(vec![Inline::Text(c.clone())])]],
                    },
                    Block::Quote(vec![Block::Paragraph(vec![Inline::Text(a)])]),
                    Block::Code { lang: None, text: b },
                ],
            };
            let first = render(&doc);
            assert_no_raw_html(&first);
            prop_assert_eq!(render(&doc), first);
        }

        #[test]
        fn extracted_markup_never_renders_as_raw_html(html in "[<>&/=\"'a-z !-]{0,200}") {
            let doc = extract_html(&html);
            assert_no_raw_html(&render(&doc.display));
        }
    }
}

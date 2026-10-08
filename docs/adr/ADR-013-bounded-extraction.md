# ADR-013 — Bounded extraction: in-crate tokenizer, one parse, scanner sees what the model sees

Status: Accepted (2026-09-25) — supersedes the "html5ever-based HTML parser" line in `CLAUDE.md`
§Dependencies for the extractor.

## Context
PR-04 builds `secure-web-extract` (threats T3/T4/T13, `docs/security-policy.md` §3, §7): one
parse of an untrusted page (≤ 5 MiB, `fetch.maxPageBytes`) must yield `security_text` (every
textual signal, for the scanner) and `display` (readable blocks, for the model). The brief asked
for a bake-off between `scraper` (html5ever DOM) and a streaming parser, defaulting to the DOM.
The extractor runs on attacker-chosen bytes, so its cost must be bounded by the input size:
anything super-linear, and any recursion proportional to document structure, is a DoS on the
whole server (a stack overflow aborts the process).

Bake-off (release build, Apple M-series; inputs well under the 5 MiB cap):

| Input | `scraper` 0.27 (html5ever DOM) | html5ever 0.40 tokenizer only | html5gum 0.8.4 | lol_html 3.0.1 | in-crate tokenizer |
|---|---|---|---|---|---|
| 50 000 anchors (`/links/huge`, 2.1 MB) | 34 ms | 23 ms | 20 ms | 10 ms | full extraction ≈ 0.6 s unoptimized (test gate: < 2 s) |
| 100 000 nested `<div>` (0.5 MB) | **17.6 s** (open-element-stack scans, quadratic) | 11 ms | 15 ms | 15 ms | linear |
| one tag, 100 000 attributes (0.7 MB) | ≥ 2 s (same tokenizer) | **2.07 s** (duplicate check is a linear scan, quadratic) | 23 ms | 2 ms | linear |
| one tag, 600 000 quoted attributes (5 MB) | ~75 s (extrapolated) | ~75 s (extrapolated) | **stack overflow → abort** (`inline_next_state` recursion per attribute) | not measured | linear |
| character references in text | decoded | decoded | decoded | **not decoded** (rewriter; raw text) | decoded (`htmlize`) |

The whole hostile suite (`tests/security/extract_bounds.rs`: 500 000 nested blocks, 700 000
nested inlines, 300 000 nested tables, a 5 MiB attribute list, 1.7 M nodes, pathological
Markdown and JSON) runs in 1.2 s in a release build and ~12 s in the unoptimized test build.

## Decision
1. **Parser.** No third-party HTML parser. `secure-web-extract::tokenizer` is a small,
   single-pass, non-recursive tokenizer that follows the WHATWG rules deciding where tags,
   attributes (quoted/unquoted), comments (`-->`, `--!>`, `<!-->`), doctypes, bogus comments
   and raw-text elements (`script`, `style`, `title`, `textarea`, `noscript`, `iframe`, …)
   begin and end. Duplicate attributes are dropped with a hash set (first wins). Character
   references are decoded exactly once by `htmlize` (full WHATWG named table, attribute-context
   legacy rule). Markup cut off by the end of input, and attributes on end tags, are kept as
   `[hidden:unparsed]` text rather than dropped. Documented simplifications (script-data escape
   states, CDATA in foreign content) only change display precision.
2. **Tree.** `dom` builds an arena (`Vec<Node>`, index links) with a simplified tree builder:
   void elements, implied `</p>` / `</li>` / `</td>` / `</tr>` / `</option>` / heading ends,
   `</body>` and `</html>` ignored, self-closing honoured only inside `svg`/`math`. End tags
   search at most 128 open elements, implied-end rules at most 16, so each token is O(1) stack
   work at any depth. At most 1 000 000 nodes, else `CONTENT_TOO_LARGE`. All traversals are
   iterative (parent/sibling links); dropping the arena is flat.
3. **security_text** (scanner input) has two parts. The first is one walk over the **whole**
   document, in document order:
   - visible text in place;
   - each hidden subtree behind one `[hidden:<kind>]` marker line (`css`, `zero-size`,
     `offscreen`, `hidden-attribute`, `aria-hidden`, `dialog`, `script`, `style`, `noscript`,
     `template`, `frame`, `embedded`, `title`);
   - comments, doctype, `<meta>` attribute values and unparsed markup as their own marked
     segments (the enclosing hidden kind is re-announced after them);
   - then every other attribute value of the document (`alt`, `title`, `aria-*`, `data-*`,
     `href`, `src`, `srcdoc`, `value`, …), deduplicated, in one `[hidden:attr]` segment.

   Whitespace runs collapse (line breaks kept). The second part is the **model-facing
   sections**, each string byte for byte as the model gets it:

   ```text
   [visible]        the rendered display Markdown (markdown::render), verbatim
   [links]          every exposed link URL (ExtractedDocument.links, Url::as_str), one per line
   [url]            the page URL that relative links resolve against
   [hidden:title]   the normalized title, verbatim (always last)
   ```

   Some walk lines are **left out**: a line made only of text that display rendered is dropped
   when that exact line (spaces trimmed) occurs in the `[visible]` section, which the scanner
   reads anyway. Every other line stays:
   - hidden text, and unrendered text (`nav`, `aside`, form controls, …);
   - rendered lines whose Markdown differs, so they keep their raw form. Examples are escapes
     such as `system\_prompt`, link syntax, and collapsed `<pre>` indentation.

   The lookup is a forward cursor over the rendered Markdown with a linear credit budget: each
   search may scan twice the line, plus a credit of the rendered length and 256 bytes per line.
   A miss only keeps the line, so the heuristic can cost space but never skips scanning.
   Everything counts towards `extract.maxSecurityTextBytes`; over it is `CONTENT_TOO_LARGE`.
   Plain text and JSON use the same layout with the source as the walk (every line is
   rendered), and have no `[links]` or title.
4. **Hidden detection** is heuristic and inline-only (no stylesheet cascade): inline `style`
   (`display:none`, `visibility:hidden|collapse`, `opacity:0`, `color:transparent`,
   `font-size:0`, zero box with `overflow:hidden`, zero `clip`/`clip-path`, far-negative
   `left/top/right/bottom/text-indent/margin/translate`), `hidden`, `aria-hidden="true"`,
   `width`/`height` of `0`, closed `<dialog>`, and the non-rendered elements above. A false
   positive only removes text from display; the text is scanned either way.
5. **The scanner sees what the model sees.** Invariant (CLAUDE.md invariant 8): every
   model-facing string the extractor produces (the rendered display Markdown, the title, and
   each exposed link URL exactly as exposed) is a **contiguous substring** of
   `security_text`, for every source kind (HTML, Markdown, plain text, JSON). A property test
   in `tests/security/injection_hidden.rs` checks each field on its own, independently of how
   the extractor builds `security_text`. Its inputs include HTML with chrome, image-only links,
   `<area>` and hrefs that resolution rewrites; generated valid JSON; and random caps. The
   document-order walk alone is not enough. Display joins words that the walk keeps apart with
   marker lines and hidden text (`Ignore<span hidden>.</span> all<!--x--> previous
   instructions` reads as one sentence but walks as four scanner lines). Plain-text/Markdown
   soft line breaks join lines. Link resolution rewrites URLs (IDNA/NFKC hosts, tab/newline
   stripping, dot segments, `\` → `/`, percent-encoding) and exposes `nav`/`aside`/image-only
   links that display never renders. The model-facing sections (rule 3) close those gaps.
   `display` reaches the model only through `markdown::render`. The in-place walk is kept so
   hidden text is scanned in context, and so rendered lines that Markdown changes keep their
   raw form. Two further rules keep every display word a substring of `security_text`:
   - the same character filter runs on both outputs and on titles (`textclean::is_stripped`:
     C0/C1 controls except `\n`/`\t`, bidi embeddings/overrides/isolates, zero-width and other
     invisible format characters, Unicode tag characters, variation selectors), so an
     invisible character cannot split a word for the scanner but not for the model;
   - display never joins text across a boundary that `security_text` breaks: a skipped node
     (hidden element, comment, chrome, image, form control) and a block element inside a link,
     heading, table cell or `<pre>` separate words. `ig<span hidden>x</span>nore` displays as
     `ig nore`, not `ignore`.
   For `text/markdown`, `security_text` is the source **plus** the HTML-path `security_text` of
   the rendered Markdown, because Markdown syntax can join what the source keeps apart
   (`ig*no*re`).
6. **display** starts at the first visible `<main>`, else `<body>`, else the document. It drops
   hidden nodes, `script/style/noscript/template/iframe/object/svg/math/canvas`, `head`,
   images/media, form controls, `nav`, `aside`, `role=navigation|banner|contentinfo|
   complementary|search`, and page-level `header`/`footer` (those inside `<article>`/`<main>`
   are content). Lists and quotes nest at most 8 deep (deeper ones flatten), tables keep at most
   64 columns. Links render only for URLs kept in the page's link list; others become text.
7. **Markdown rendering** (`markdown::render`) is a pure function; all page text is
   backslash-escaped so it can never form raw HTML, entities, emphasis, links or block markers;
   code fences are longer than any backtick run inside. The title is not rendered (the store
   emits it as the page heading, `docs/contracts/manifest-schema.md`).
8. **Links** come from `<a href>`/`<area href>` outside hidden subtrees (a hidden link is a
   crawler trap, not content) anywhere in the document, including `nav` (crawlable, not
   displayed): resolved against the final URL (`<base href>` ignored), `http(s)` only, no
   credentials, fragment removed, fragment-only hrefs dropped, deduplicated in document order,
   capped at `extract.maxLinksPerPage` with `links_truncated`. Every exposed link is also written
   verbatim to the `[links]` section of `security_text` (rule 3).
9. **Non-HTML.** `text/plain`: paragraphs split on blank lines. `text/markdown`: CommonMark
   (tables, strikethrough) via `pulldown-cmark` to HTML, then the HTML display path (raw HTML is
   parsed and dropped, never passed through). JSON: `serde_json` (recursion limit 128) pretty
   print, keys sorted, in one fenced `json` block; invalid or too-deep JSON is shown as text.
   Bodies are UTF-8 (lossy) or `windows-1252` and its WHATWG aliases.

## Consequences
- No DOM or tokenizer dependency to track for HTML; the tokenizer is ~400 lines with unit tests
  and the property tests above. Browser-exact tree construction (adoption agency, foster
  parenting, foreign-content rules) is out of scope; divergences only change which text is
  displayed, never whether it is scanned.
- `display` can differ from a browser rendering in word spacing around hidden/skipped nodes.
  That is deliberate (rule 5).
- Rendered text is stored once when rendering leaves its line unchanged. When Markdown changes
  it, it is stored twice: raw in place and escaped in `[visible]`. The 50 000-anchor
  `/links/huge` fixture (2.1 MB) needs 1.60 MB of `security_text` at default limits, which
  fits the 2 MB default:

  | Section | Size |
  |---|---|
  | walk | 74 B |
  | `[hidden:attr]` | 0.89 MB |
  | `[visible]` | 0.63 MB |
  | `[links]`, `[url]`, title | 83 KB |

  Text-heavy pages whose lines Markdown escapes reach the cap sooner and fail closed with
  `CONTENT_TOO_LARGE`.
- Class- or stylesheet-based hiding (`.sr-only`, `.hidden`) is not detected; such text is
  displayed and scanned (backlog).
- New dependencies: `htmlize` (MIT/Apache-2.0; pulls `phf`, `memchr`, `pastey`),
  `pulldown-cmark` (MIT, `html` feature only), `unicode-normalization`; dev: `insta`, `proptest`.

# PR-04 — Security-text + display extraction, deterministic Markdown (SW-004, SW-007)

Read first: `docs/security-policy.md` §3, §7; `docs/threat-model.md` T3/T4/T13; `docs/contracts/manifest-schema.md`
(page file format); deep-dive §18–19, §78.

## Goal
`secure-web-extract::HtmlExtractor` implementing `Extractor`: one parse → `ExtractedDocument {
security_text, display: StructuredDocument, links, title }`, and `markdown::render(&StructuredDocument) -> String`
that is byte-deterministic. Also plain-text, Markdown and bounded JSON extractors.

## Design
- Library bake-off (30 min max, document result in the PR description): `scraper` (html5ever DOM)
  vs a streaming approach. Choose DOM unless memory on `/links/huge` is unacceptable; page size is
  already capped at 5 MB.
- `security_text` builder walks the **entire** DOM including `<head>`, comments, `<script>`/`<style>`
  text, `<noscript>`, `<template>`, attributes (`alt`, `title`, `aria-*`, `data-*`, `content` of
  `<meta>`, `href`/`src` text). Hidden detection: inline style `display:none|visibility:hidden|opacity:0|
  font-size:0`, `hidden` attribute, `aria-hidden="true"`, `width/height="0"`, offscreen
  (`left:-9999px`-style). Each hidden/comment/script segment is emitted as `\n[hidden:<kind>]\n<text>\n`.
  HTML entities decoded once. Cap at `extract.maxSecurityTextBytes` → `CONTENT_TOO_LARGE`.
- `display` builder: remove `script/style/noscript/template/iframe/svg/canvas`, hidden nodes,
  `nav/header/footer/aside` and elements with `role=navigation|banner|contentinfo` (keep `<main>`
  if present, else body). Produce `Block::{Heading(level,text), Paragraph, Code{lang}, List{ordered, items},
  Table{rows}, Quote}` and `Link{href(absolute), text}`. Preserve `<pre><code>` verbatim.
- Title: `<title>` → `og:title` → first `<h1>`; normalized (NFC, strip control chars, collapse
  whitespace, ≤ 200 chars). Title text is also appended to `security_text`.
- Links: resolve relative to `final_url`, keep only `http(s)`, drop fragments, dedupe preserving
  order, cap `extract.maxLinksPerPage` (set `links_truncated`).
- Markdown renderer: ATX headings, fenced code with language, pipe tables, `-` lists, blank line
  between blocks, no trailing whitespace, `\n` line endings, final newline. Links rendered inline
  `[text](href)`. No HTML passthrough.
- Non-HTML: `text/plain` → single paragraph blocks split on blank lines; `text/markdown` → passed
  through a normalizer (strip raw HTML, keep structure); JSON → pretty-printed inside a fenced block
  (bounded) — security_text = the same text.

## Tests
- Snapshot tests: each file under `tests/corpus/clean/**` renders to the committed
  `tests/corpus/snapshots/<same path>.md` (insta). Determinism: render twice, compare bytes.
- `tests/security/injection_hidden.rs`-precursor (unit): for `/injection/{hidden-css,comment,title,alt}`
  fixtures assert canary ∈ `security_text` and canary ∉ `render(display)`.
- Link extraction: `/link/c` yields only same-scheme absolute http(s) links; mailto/fragment/javascript dropped.
- `/links/huge` → exactly `maxLinksPerPage`, `links_truncated=true`, bounded time (< 2 s).
- Title normalization: control chars, 10 000-char title, RTL override, path-traversal-looking title
  → normalized/capped; slug function (`docs/security-policy.md` §7) property-tested with proptest
  to match `^[a-z0-9-]{0,48}$`.

## Done when
- [ ] hidden/comment/attribute text reaches `security_text` but never Markdown
- [ ] snapshots committed for all clean fixtures; render is deterministic
- [ ] bake-off result recorded in PR description
- [ ] fmt/clippy/test green

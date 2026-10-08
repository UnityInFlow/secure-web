# PR-09 — Lexical `web_find` (SW-012)

Read first: `docs/contracts/mcp-contract.md` (`web_find`), `docs/contracts/manifest-schema.md`;
deep-dive §11.4, §26, §46.

## Goal
`secure-web-store::find::find(manifest, query, opts) -> Vec<Match>` over accepted documents only;
`web_find` MCP tool; `secure-web find <runId> <query> [--limit N]` CLI. No embeddings, no
SQLite/FTS, no external index — plain in-memory lexical scoring.

## Design
- Load manifest; candidate set = `documents` with `decision ∈ {SAFE, WARN}` (WARN excluded when
  `includeWarned=false`), skipping `duplicateOf != null`. Never open `quarantine/` or anything in `blocked`.
- Tokenize query and text: lowercase, NFKC, ASCII-fold diacritics, split on non-alphanumeric,
  drop tokens < 2 chars, keep a stopword list of ~50 English words. Also keep the raw query for
  exact-phrase matching.
- Per document: parse Markdown lightly (frontmatter, `#` headings, body lines). Score =
  `4·titleHits + 3·headingHits + 2·exactPhraseHits + 1·(tokenOverlap/queryTokens)`, normalized to
  `[0,1]` by dividing by the max possible; stable sort by `(score desc, path asc)`.
- Excerpt: the first line containing the phrase, else the line with most token hits; ±1 line of
  context; ≤ 512 chars; report `excerptLine`.
- `limit` clamp 1..50. Result comes from files under `pages/` only (path-prefix check against run dir).
- Performance: ≤ 1 000 docs × 5 MB worst case is fine sequentially; read files lazily; stop early
  if `limit` exact matches found? No — score all, then take top K (determinism over speed).

## Tests
- `tests/store/find_ranking.rs`: crafted 6-doc corpus; assert exact ordering for title vs heading
  vs body matches; tie → path order; determinism (run 3×, byte-equal JSON).
- `tests/security/find_no_blocked.rs`: manifest with a blocked entry whose URL matches the query →
  zero matches from it; a fabricated `pages/000099-evil.md` not referenced by the manifest is never read.
- Excerpt bound: 512-char cap; unicode safe (no split inside a grapheme).
- Integration: after the PR-08 hostile-site crawl, `web_find(crawlId, "install")` returns the docs page.
- Contract snapshot for `web_find` output; `NOT_FOUND` for unknown `crawlId`; `INVALID_ARGUMENT` for empty query.

## Done when
- [ ] find reads only manifest-listed accepted files
- [ ] ranking deterministic and documented in `docs/contracts/mcp-contract.md`
- [ ] CLI + MCP tool registered, snapshot updated
- [ ] fmt/clippy/test green

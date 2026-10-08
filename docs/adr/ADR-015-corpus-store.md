# ADR-015 — Corpus store: generated paths, no-follow atomic writes, checkpoints, private audit

Status: Accepted (2026-09-25)

## Context
PR-06 adds `secure-web-store::FsCorpusStore`, the first component that writes Internet-derived
content to disk where an agent can read it (`<workspace>/runs/<runId>/`, mounted into agent
sandboxes). ADR-005 says blocked text is never agent-visible; threat T13 says titles and URLs
must not pick paths; T17 says "safe" is only meaningful under a known scanner/policy version.
Implementing the store surfaced decisions the contract and those ADRs do not spell out:

1. How a page-derived string (title, URL path) becomes a file name without ever choosing a
   location, and what happens to symbolic links or pre-existing entries in the workspace.
2. What a killed run leaves behind: the contract promises "a valid partial manifest", but the
   status enum only has terminal values.
3. Where `WARN` pages go under `warnHandling: quarantine`, and how a reader tells them apart.
4. What the store trusts about an `AcceptedDocument` (its construction is not sealed yet —
   `docs/backlog.md`, PR-07).

## Decision
Paths (T13):

- Every name the store creates is generated: `runs/<runId>/` (a parsed `RunId`), fixed
  sub-directories, `NNNNNN[-slug].md` / `NNNNNN.json`, `<docId>.raw|.sectext`. The slug is
  `secure_web_extract::title::slug` (ASCII `[a-z0-9-]`, ≤ 48) of the normalized title, else of
  the URL path, else absent (`NNNNNN.md`). Each name is re-checked (`[a-z0-9._-]`, ≤ 96 bytes,
  no leading dot) and page names against the contract pattern before any write.
- Directories are created one level at a time and opened as directory file descriptors
  (`O_DIRECTORY|O_NOFOLLOW`, via `rustix`): `<workspace>` and `runs/` when the store opens,
  the run directory and its subdirectories in `begin_run`. Every later `mkdirat`, `openat`
  (`O_NOFOLLOW`), `renameat`, `unlinkat` and `fsync` is relative to one of those descriptors;
  no pathname is resolved again. Swapping a run directory, a subdirectory or any ancestor for a
  symbolic link therefore cannot redirect a write — it lands in the directory the store created
  (wherever that directory was moved to) or fails (tested with a concurrent swap loop). The run
  directory itself must not exist: a run is never reopened, and an entry of any kind at
  `runs/<runId>` (including a planted symlink) is `RunExists`. `runs/` being a symlink is
  refused at startup. The workspace root itself (user configuration) may be a symlink; it is
  resolved once, when the store opens.
- Writes are `openat(O_CREAT|O_EXCL|O_NOFOLLOW)` on `.<name>.tmp`, `fsync`, then `renameat`
  onto the final name through the same directory descriptor (`renameat` replaces a symlink at
  the destination; it never writes through it). A leftover temp entry is unlinked (never
  followed) and the write retried once.
- Durability order per checkpoint: file `fsync` → `renameat` → `fsync` of `pages/`,
  `metadata/`, `quarantine/` and `security/` → manifest write (same steps) → `fsync` of the run
  directory. `begin_run` fsyncs the new run directory and `runs/` before the first manifest. A
  crash can lose the newest checkpoint, never leave a durable manifest listing a page whose
  directory entry was lost (asserted on the recorded sync order).
- What this does not cover: a local user with write access to the workspace can still move or
  delete files after they were written, or move a whole run directory elsewhere — the store
  guarantees only that it never creates a file in a directory it did not create. Non-Unix
  builds fall back to pathname checks immediately before each write (no protection against a
  concurrent swap); v0.1 ships Unix binaries only.

Content:

- The page body is the normalized title rendered as an H1 through the extractor's Markdown
  renderer (escaped exactly like page headings — no raw HTML, no extra structure) followed by
  `AcceptedDocument.markdown`. The title must already equal `normalize_title(title)`: the
  scanner saw that exact string (ADR-013/014), so a title in any other form is refused
  (`InvalidDocument`), never re-normalized. `contentHash` = sha256 of the body (no
  frontmatter). The frontmatter holds only generated fields and `url`-crate-serialized URLs.
- Defence in depth on `AcceptedDocument` until it is sealed: decision must be `SAFE`/`WARN`;
  scanner and policy versions must equal the run's (T17 — one manifest, one policy); finding ids
  must be scanner pattern ids and match the `StoreContext.findings` that fill
  `security/findings.json` (id, severity, detector only); the content type must be a MIME
  essence. Any failure writes nothing.
- Blocked documents produce a metadata file and a manifest entry with ids, URLs, enums and sizes
  only — no title, path, hash or text (ADR-005). An invalid response `contentType` is dropped.
  Failed URLs produce a manifest entry only.
- Document ids are issued by the run writer (`next_doc_id`, fetch-completion order) and each can
  be recorded once; an id the writer did not issue, or a second record of one, is refused, so
  no call can overwrite another document's files.
- Dedupe is per area: an identical body in `pages/` is referenced, not rewritten; a quarantined
  body is only ever deduplicated against `quarantine/`, so a `SAFE` page never points into
  quarantine and a `WARN` page never becomes visible through a `pages/` duplicate.

Quarantine (`warnHandling: quarantine`, ADR-014 follow-up): `WARN` pages are written to
`quarantine/NNNNNN[-slug].md` and listed in `documents` with that `path` (metadata
`"quarantined": true`). `Manifest::accepted_documents()` — what `web_find` reads — excludes
them. The run directory stays one tree (the contract layout); PR-09 must never open
`quarantine/`.

Checkpoints: the run starts with a manifest of status **`RUNNING`** and `finishedAt: null`, and
is rewritten (with `security/summary.json` and `security/findings.json`, manifest last) after
every 25 recorded entries (documents, blocked or failed — at least as often as "every 25 stored
documents") and on `checkpoint()`. `RUNNING` is added to the manifest status enum: a checkpoint
is not a finished run, and reporting it as `CANCELLED` or `COMPLETE` would be false for a run
that is still going. Dropping a writer leaves the last checkpoint; pages written after it exist
but are unlisted. `finish()` requires a terminal status and recomputes the manifest's counts from
its own arrays.

Private audit (`debug.retainRaw`): raw bytes and `security_text` are written to
`<audit root>/<runId>/<docId>.raw|.sectext`, directories `0700`, files `0600`, with the same
no-follow atomic writes. The audit root defaults to `<workspace>/private-audit`; a custom root
must be a directory named `private-audit` and may not be equal to, inside, or an ancestor of
`runs/`, compared after canonicalization so symlinked aliases are caught (startup error).
Without `retainRaw` nothing is written there and the raw content passed in `StoreContext` is
dropped.

Audit events: one `tracing::info!(event = "document_security_decision", …)` per stored or blocked
document with `run_id`, `document_id`, `url_hash` (sha256 of the requested URL), decision,
reason, severity, finding ids and scanner version — no URL text, title or body. File I/O runs on
Tokio's blocking pool with the caller's `tracing` dispatcher and span.

## Consequences
+ No page-derived string reaches a path component; hostile titles/URLs (`../`, NUL, RTL,
  5 000 chars, empty) land in `pages/NNNNNN[-slug].md` (tested).
+ A killed crawl always leaves a valid manifest whose paths exist.
+ `WARN` handling is enforced by the store, not only documented.
- The manifest status enum gains `RUNNING`; readers must treat it as "incomplete". The contract
  doc, JSON schema and snapshot change together (invariant 9).
- `StoreContext.findings` must be supplied by the page processor, but `scan_and_accept` does
  not return the findings today; PR-07 has to thread them through (`docs/backlog.md`).
- Every write costs an fsync, plus up to five directory fsyncs per checkpoint. Acceptable at ≤ 1 000
  pages; revisit if crawl volume grows.
- Pages written after the last checkpoint of a killed run are orphans on disk (not in the
  manifest). They were accepted content, so this is a completeness issue, not a leak.

# Corpus & manifest contract v1

The manifest is the agent's entry point into a crawl. Layout and schema are contracts pinned by
`tests/contracts/manifest_v1.rs` (snapshot + JSON Schema `tests/contracts/manifest_v1.schema.json`).
Written by `secure-web-store::FsCorpusStore` (ADR-015).

## Directory layout

```text
<workspace>/runs/<runId>/          # runId = crawl_<12 hex> | open_<12 hex>
  manifest.json
  pages/
    000001-getting-started.md      # only SAFE (and non-quarantined WARN) documents
    000002-auth.md
    000003.md                      # no slug (title and URL path have no [a-z0-9])
  metadata/
    000001.json                    # one per fetched doc, including blocked (no content)
  security/
    summary.json                   # counts + policy/scanner versions
    findings.json                  # [{documentId, findingId, severity, detector}] — ids only
  quarantine/                      # only when warnHandling=quarantine; same file naming
<workspace>/private-audit/<runId>/ # <docId>.raw / <docId>.sectext when debug.retainRaw=true (0600);
                                   # never in agent mount, never under runs/
```

Sequence numbers are assigned in fetch-completion order and are zero-padded to 6 digits
(`doc_NNNNNN` ↔ `NNNNNN`). Page files are `NNNNNN-<slug>.md`, or `NNNNNN.md` when the slug is
empty; the slug rule is in `docs/security-policy.md` §7 and no page-derived string ever picks a
path. Files are written atomically (write to `.<name>.tmp`, fsync, rename; symbolic links are
never followed). A run directory is created once: an existing `runs/<runId>` is an error.
`manifest.json` is written when the run starts (status `RUNNING`), rewritten after every 25
recorded entries (stored, blocked or failed) and at the end of the run, so a cancelled/killed crawl
still leaves a valid partial manifest whose `path`s exist. `security/summary.json` and
`security/findings.json` are rewritten with it (before it).

## manifest.json

```json
{
  "version": 1,
  "runId": "crawl_f21a9b0c1d2e",
  "kind": "CRAWL",                              // CRAWL | OPEN
  "rootUrl": "https://docs.example.com",
  "status": "COMPLETE",                         // RUNNING | COMPLETE | LIMIT_REACHED | CANCELLED | FAILED
  "startedAt": "2026-09-24T18:00:00Z",
  "finishedAt": "2026-09-24T18:00:08Z",         // null while RUNNING
  "versions": { "secureWeb": "0.1.0", "scanner": "0.1.0", "policy": "9f1c2a3b4d5e" },
  "policy": { "maxDepth": 2, "maxPages": 100, "maxTotalBytes": 104857600, "maxPageBytes": 5242880,
              "maxDurationMs": 120000, "scope": "SAME_ORIGIN", "allowedHosts": [] },
  "stats": { "discovered": 132, "fetched": 92, "safe": 88, "warned": 2, "blocked": 2, "failed": 4,
             "totalBytes": 4823001 },
  "documents": [
    { "id": "doc_000001", "seq": 1, "url": "https://docs.example.com/", "finalUrl": "https://docs.example.com/",
      "path": "pages/000001-home.md", "title": "Home", "depth": 0, "decision": "SAFE",
      "maxSeverity": null, "findingIds": [], "contentHash": "sha256:…", "contentBytes": 12345,
      "httpStatus": 200, "contentType": "text/html", "retrievedAt": "2026-09-24T18:00:01Z",
      "duplicateOf": null }                      // documentId when content-hash dedupe applied
  ],
  "blocked": [
    { "id": "doc_000019", "url": "https://docs.example.com/evil", "finalUrl": "https://docs.example.com/evil",
      "depth": 1, "reason": "PROMPT_INJECTION", "maxSeverity": "CRITICAL", "findingIds": ["PI001"],
      "httpStatus": 200, "contentType": "text/html", "retrievedAt": "…" }
                                                 // finalUrl/httpStatus/contentType/retrievedAt are
                                                 // null when no response was received;
                                                 // finalUrl is also null when it differs from
                                                 // url (a server-chosen redirect target, ADR-016)
  ],
  "failed": [
    { "url": "https://docs.example.com/big", "depth": 1, "code": "CONTENT_TOO_LARGE", "retryable": false }
  ]
}
```

Rules:
- `documents[*].path` exists on disk; `blocked[*]` and `failed[*]` have no `path`, `title` or hash.
- `documents[*].decision` is `SAFE` or `WARN` — a blocked document is only ever in `blocked`.
  A `quarantine/` path is always `WARN`; a first copy's file is named after its own `seq`; a
  duplicate's `path` and `contentHash` equal those of the earlier entry named by `duplicateOf`;
  no id appears twice across `documents` and `blocked`. `Manifest::load` refuses a manifest that
  breaks any of these, and `Manifest::accepted_documents()` (what `web_find` reads) re-checks
  decision and location on every call: it yields only `SAFE`/`WARN` entries under `pages/`.
- `blocked` entries never contain text beyond URL/ids/enums.
- `status: RUNNING` (with `finishedAt: null`) marks a checkpoint of a run that has not finished,
  or was killed; every other status is terminal and has a `finishedAt` no earlier than
  `startedAt`. Both the JSON Schema and `Manifest::load` refuse `RUNNING` with a timestamp and a
  terminal status with `null`. Entries recorded after the last checkpoint of a
  killed run are not listed.
- Dedupe: identical `contentHash` within a run stores one file; later duplicates get
  `duplicateOf` and `path` of the first. Quarantined and non-quarantined pages are deduplicated
  separately (a `pages/` entry never points into `quarantine/` or vice versa).
- Quarantine (`warnHandling: quarantine`): `WARN` documents are listed in `documents` with a
  `path` under `quarantine/`. They are not part of the agent corpus; readers (`web_find`) skip
  every `documents` entry whose path starts with `quarantine/`.
- `stats.safe/warned/blocked/failed` equal the entry counts (duplicates and quarantined pages
  count under their decision); `fetched = documents + blocked`.
- `kind: OPEN` manifests have exactly one entry across `documents`/`blocked`/`failed`, except a
  `CANCELLED` one (the call was cancelled before the page was decided), which has none.
- `kind: CRAWL`: `policy` records the budgets and scope the crawl actually ran under (the
  `web_crawl` arguments after clamping). `stats.discovered` counts the root plus every link
  queued or dropped at a full frontier (`maxFrontier`); links out of scope, past `maxDepth` or
  already seen are not counted. A page that did not fit the remaining `maxTotalBytes` budget is a
  `failed` entry with code `CRAWL_LIMIT_REACHED` (never a `blocked` one), and `totalBytes` never
  exceeds `policy.maxTotalBytes`. A crawled page's `url` is the resolved link URL, which was a
  line of an accepted parent page's scanned text (ADR-018).
- `versions.scanner` / `versions.policy` are the versions every entry was decided under; the
  store refuses a document decided under another scanner or policy version (T17).

## metadata/NNNNNN.json (provenance)

```json
{ "id": "doc_000001", "seq": 1, "requestedUrl": "…", "finalUrl": "…", "redirectChain": ["…"],
  "httpStatus": 200, "contentType": "text/html; charset=utf-8", "retrievedAt": "…",
  "rawBytes": 48211, "extractedBytes": 12345, "securityTextBytes": 15200, "linksFound": 41,
  "linksTruncated": false, "title": "Home", "depth": 0,
  "security": { "decision": "SAFE", "maxSeverity": null, "findingIds": [], "scannerVersion": "injection-scanner 0.1.0",
                "policyVersion": "9f1c2a3b4d5e", "scanDurationMs": 11 },
  "contentHash": "sha256:…" }
```

Also: `secureWebVersion`; `duplicateOf` (when deduplicated) and `"quarantined": true` (when in
`quarantine/`) for accepted documents; `security.reason` (the `BlockReason`) for blocked ones.
For blocked documents `title` is omitted and there is no `contentHash`; `finalUrl`,
`httpStatus`, `contentType`, `retrievedAt` and `security.scannerVersion` are `null` when unknown.
A blocked document's `finalUrl` is also `null` when it differs from `requestedUrl`, and its
`redirectChain` is empty: redirect targets are server-chosen text (ADR-016). An accepted
document's `redirectChain` holds only the final hop (`[finalUrl]` when redirected, `[]`
otherwise): intermediate hops are never scanned, so they are not recorded (ADR-018).
Failed URLs have no metadata file.

## security/summary.json and security/findings.json

```json
{ "version": 1, "runId": "crawl_f21a9b0c1d2e", "status": "COMPLETE",
  "versions": { "secureWeb": "0.1.0", "scanner": "injection-scanner 0.1.0", "policy": "9f1c2a3b4d5e" },
  "counts": { "safe": 88, "warned": 2, "quarantined": 0, "blocked": 2, "failed": 4,
              "duplicates": 1, "findings": 7 } }
```

```json
[ { "documentId": "doc_000019", "findingId": "PI001", "severity": "CRITICAL",
    "detector": "ignore-previous-instructions" } ]
```

`findings.json` lists the findings of accepted and blocked documents, in recording order: ids,
severities and detector names only (no line numbers, no text).

`scannerVersion` is the verbatim `<exe> --version` output (`injection-scanner X.Y.Z`), not a bare
semver — see `docs/security-policy.md` §4.

## Page file format

```markdown
---
secureWeb: 1
documentId: doc_000001
url: https://docs.example.com/
finalUrl: https://docs.example.com/
retrievedAt: 2026-09-24T18:00:01Z
decision: SAFE
---
# Home

…deterministic Markdown from StructuredDocument…
```

The frontmatter contains only fields Secure Web generated. Title is emitted as the first H1 from
the normalized title (by the store, escaped by `markdown::render` like any heading; no H1 when
the page has no title); `contentHash` is the sha256 of everything after the frontmatter. The
body below the title is `secure_web_extract::markdown::render`
of the page's `display`, which never renders the title itself and never contains raw HTML
(ADR-013). Extraction output must be byte-for-byte deterministic for the same input
(fixture snapshot tests).

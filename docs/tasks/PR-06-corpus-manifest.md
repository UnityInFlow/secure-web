# PR-06 — Corpus store + manifest v1 (SW-008)

Read first: `docs/contracts/manifest-schema.md`, `docs/security-policy.md` §7–8, `docs/threat-model.md`
T11/T13/T17; deep-dive §24–25, §45, §51–52, §78–81.

## Goal
`secure-web-store::FsCorpusStore` implementing `CorpusStore`: writes accepted pages, metadata,
security summary and manifest under `<workspace>/runs/<runId>/` exactly as the contract says;
records blocked/failed entries with no content; content-hash dedupe; atomic writes; partial-manifest
checkpoints; optional private-audit raw retention.

## Design
```rust
pub struct FsCorpusStore { root: PathBuf, audit_root: PathBuf, retain_raw: bool }
pub struct RunWriter { … }           // one per run; holds seq counter, hash index, manifest builder
impl RunWriter {
    pub async fn store(&self, doc: AcceptedDocument, ctx: &StoreContext) -> Result<StoredDocument, StoreError>;
    pub async fn record_blocked(&self, b: &BlockedDocument, ctx: &StoreContext) -> Result<(), StoreError>;
    pub async fn record_failed(&self, url: &Url, depth: u32, code: ErrorCode, retryable: bool) -> Result<(), StoreError>;
    pub async fn checkpoint(&self) -> Result<(), StoreError>;          // every 25 stored docs
    pub async fn finish(self, status: RunStatus, stats: RunStats) -> Result<Manifest, StoreError>;
}
```
- Sequence + slug + `pages/NNNNNN-<slug>.md` per `docs/security-policy.md` §7. Reject any computed
  path that escapes the run dir (defensive `canonicalize` + prefix check).
- Page file = frontmatter + Markdown per contract; hash = sha256 of the Markdown body (excluding frontmatter).
- Dedupe: `HashMap<contentHash, DocumentId>`; duplicates produce a manifest entry with `duplicateOf`
  and `path` of the original; no second file.
- Manifest builder keeps `documents`, `blocked`, `failed` vectors; `checkpoint()` and `finish()`
  serialize with `serde_json::to_string_pretty` + atomic rename. Version stamps from `StoreContext`.
- `security/summary.json` (counts, versions) and `security/findings.json` (documentId, findingId, severity, detector).
- Private audit: when `retain_raw`, write `raw_bytes` and `security_text` to
  `<audit_root>/<runId>/<docId>.raw` and `.sectext` with 0600 perms; never under `runs/`.
- Audit event: emit `tracing::info!(event="document_security_decision", url_hash, decision, reason, severity, finding_ids, scanner_version)` per doc.
- `Manifest::load(path)` + `Manifest::accepted_documents()` helper for `web_find` later.

## Tests
- `tests/contracts/manifest_v1.rs`: build a run with 3 safe, 1 warn, 1 blocked, 1 failed, 1
  duplicate → manifest snapshot; JSON schema (`jsonschema` crate) from `tests/contracts/manifest_v1.schema.json`.
- `tests/security/sanitized_paths.rs`: titles with `../`, NUL, unicode RTL, 5 000 chars, empty → path
  stays inside run dir and matches slug regex.
- `tests/store/atomic.rs`: kill/abort mid-run (drop writer) → last checkpointed manifest is valid JSON.
- `tests/security/no_leak_canary.rs` extension: store a blocked canary doc → grep run dir, no canary;
  with `retain_raw=true` canary exists only under audit root.
- Dedupe: `/dup/a`,`/dup/b` content → one page file, two manifest entries.

## Done when
- [ ] manifest snapshot + schema validation green
- [ ] blocked/failed entries carry no title/path/hash/text
- [ ] audit files never under `runs/`
- [ ] fmt/clippy/test green

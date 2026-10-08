Closes #

## What
<!-- One sentence. Which task brief (docs/tasks/PR-NN-*.md) this delivers. -->

## Security invariants (CLAUDE.md)
- [ ] Single processing path preserved (`PageProcessor` only)
- [ ] SSRF re-checked after DNS and on every redirect (if network code touched)
- [ ] Scanner errors fail closed
- [ ] No blocked text in MCP output, corpus, `Debug`, or logs — canary grep extended to new surfaces
- [ ] Budgets exact; blocked pages yield no links (if crawler touched)
- [ ] Contract docs + snapshots updated together (or: no contract change)
- [ ] ADR added (or: not security-affecting because …)

## Rust
- [ ] No `unwrap()`/`expect()` outside tests; no `unsafe`
- [ ] New dependencies pinned; `cargo deny check` + `cargo audit` clean
- [ ] Tests offline (fixture server + stub scanner)

## Verification
```
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked --workspace
cargo run -- --help
```
<!-- paste the last lines of each -->

## Review notes
<!-- Anything a reviewer should look at first: risky areas, open questions, follow-ups. -->

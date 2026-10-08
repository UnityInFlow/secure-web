# ADR-011 — Test-only loopback allowance for the fixture server

Status: Accepted (2026-09-25)

## Context
Every network test runs against the in-process fixture server (`docs/testing.md`), which binds
`127.0.0.1:<ephemeral>`. The URL guard blocks `127.0.0.0/8` unconditionally (invariant 2,
ADR-010), and the fetcher only accepts a `ValidatedTarget`, which only the guard produces. Tests
therefore need *some* way for the guard to let the fixture through. The obvious shortcuts are all
unacceptable: a config key (`allowLoopback`) or env var would be settable in production; a
public constructor for `ValidatedTarget` would break the sealed-type guarantee; a fetcher that
takes a raw URL "for tests" would be a second code path. The fixture must also stay a *real*
private target: `/redirect/private` redirects to `http://127.0.0.1:<port>/…`, and that must be
blocked even though it is the fixture's own socket.

## Decision
1. `secure-web-security` gets a **non-default cargo feature `test-support`**. Only under that
   feature does `UrlGuard::with_test_fixture(host, socket)` exist (and the guard field it sets);
   without the feature the code is not compiled at all. There is no config key, env var or CLI
   flag, so production configuration cannot reach it.
2. The allowance is as narrow as possible. An address is exempted from the range check only when
   **all** hold: the URL host is a **domain name** equal to `host` (never an IP literal), the URL
   port equals `socket.port()`, and the resolved address equals `socket.ip()`. Every other
   address in the same DNS answer is still checked (a mixed answer is still refused).
   `with_test_fixture` refuses anything but a reserved `*.test` name (RFC 6761) and a loopback,
   non-zero-port socket.
3. Tests reach the fixture as `http://fixture.test:<port>/`, resolved by the offline stub resolver
   (`tests/support/resolver.rs`). Because `fixture.test` exists only in the stub, a successful
   fetch also proves the fetcher connected to the guard-validated address (no second lookup).
4. The feature is enabled only as a **dev-dependency** feature of the root package. With Cargo
   resolver 2, dev-dependency features are not unified into `cargo build --bin secure-web`. CI's
   `release-build` job asserts it: `cargo tree -e normal,build,features -i secure-web-security`
   for the release target must not mention `test-support`.

5. **Compiler flags cannot switch it on either** (round-2 review). `cfg(feature = "test-support")`
   can also be set with `--cfg` through `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`,
   `CARGO_BUILD_RUSTFLAGS`, `CARGO_TARGET_<triple>_RUSTFLAGS`, `build.rustflags` /
   `target.*.rustflags` in `.cargo/config*` or `--config`, none of which show in the dependency
   graph. Three independent layers:
   - `crates/secure-web-security/build.rs` receives the crate's final flags from Cargo
     (`CARGO_ENCODED_RUSTFLAGS`, whatever their source), asks `rustc --print cfg` which cfgs they
     set (so escapes such as `test\x2dsupport` and `@argfile`s are interpreted exactly as the real
     compile will) and **fails the build** if they set `feature="test-support"`; a flag set it
     cannot evaluate also fails the build. A real cargo feature is passed by Cargo outside the
     rustflags, so tests are unaffected. This holds for every local and CI build.
   - CI's `release-build` job (`tools/ci/test-support-guard.sh flags`) refuses to build if any
     rustflags variable, `RUSTC`, `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER` (or their
     `CARGO_BUILD_*` forms) is set, or if any Cargo config file the build would read mentions
     `rustflags` or `rustc`. This also covers what a build script cannot see: a replacement
     compiler or wrapper that adds `--cfg` to the command line.
   - After building, `tools/ci/test-support-guard.sh artifacts` scans every file Cargo reports
     for the release build (the binary and the `secure-web-security` rlib/rmeta) for a marker
     byte string that exists only in the `test-support` code (`TEST_SUPPORT_MARKER`; rustc keeps
     it in the crate metadata) and fails if it is found. A positive-control build with the
     feature enabled must contain the marker, so the scan cannot silently become vacuous.

   **What is guaranteed:** the release artifacts built by our CI do not contain the test-only
   code, and any ordinary local `cargo build` with injected flags fails. **What is not:** a
   determined local builder controls their own toolchain and source and can always patch the
   check out (edit `build.rs`, use a wrapper and skip CI). Only CI-built artifacts are
   release artifacts.

## Consequences
+ production builds contain no loopback exemption at all; the guard's policy is unchanged.
+ `http://127.0.0.1:<fixture port>/` stays blocked in tests, so redirect-to-private tests exercise
  the real rule against a real listening socket.
- `cargo test` and `cargo clippy --all-features` compile the feature (it is test code there).
- A future crate that enables `test-support` in its normal dependencies would ship it; the CI
  graph check and the artifact scan are the guard rails against that.
- `secure-web-security` has a build script, and a build with rustflags runs `rustc --print cfg`
  once more. Setting `RUSTC_WRAPPER` (e.g. sccache) locally still works; CI's release job refuses
  it.

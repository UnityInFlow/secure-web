#!/usr/bin/env bash
# ADR-011: keep the guard's `test-support` code out of release artifacts.
#
#   test-support-guard.sh flags               refuse compiler-flag / compiler overrides
#   test-support-guard.sh artifacts <target>  scan release artifacts for the marker, with a
#                                             positive control proving the scan can see it
#
# `secure-web-security/build.rs` already refuses flags that set cfg(feature="test-support");
# this script is the CI-side second layer, and also covers what a build script cannot see
# (a RUSTC / RUSTC_WRAPPER that injects flags on the compiler command line).
set -euo pipefail

MARKER='secure-web:test-support:compiled-in!'
MARKER_SOURCE='crates/secure-web-security/src/ssrf/mod.rs'

fail() {
  echo "::error::$*" >&2
  exit 1
}

check_flags() {
  local bad=0 name value
  # Every channel that can add compiler flags or replace the compiler.
  for name in $(compgen -e); do
    case "$name" in
      RUSTFLAGS | CARGO_ENCODED_RUSTFLAGS | CARGO_BUILD_RUSTFLAGS | CARGO_TARGET_*_RUSTFLAGS | \
        RUSTC | RUSTC_WRAPPER | RUSTC_WORKSPACE_WRAPPER | CARGO_BUILD_RUSTC | \
        CARGO_BUILD_RUSTC_WRAPPER | CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER)
        value=${!name}
        if [[ -n "$value" ]]; then
          echo "::error::$name is set for the release build (ADR-011 refuses compiler-flag overrides)" >&2
          bad=1
        fi
        ;;
    esac
  done
  # Cargo reads .cargo/config{,.toml} in the working directory, every ancestor, and CARGO_HOME.
  local dir config
  local -a candidates=()
  dir=$(pwd -P)
  while :; do
    candidates+=("$dir/.cargo/config" "$dir/.cargo/config.toml")
    [[ "$dir" == / ]] && break
    dir=$(dirname "$dir")
  done
  candidates+=("${CARGO_HOME:-$HOME/.cargo}/config" "${CARGO_HOME:-$HOME/.cargo}/config.toml")
  for config in "${candidates[@]}"; do
    if [[ -f "$config" ]] && grep -Eiq 'rustflags|rustc' "$config"; then
      echo "::error::$config sets rustflags or a rustc/wrapper (ADR-011 refuses compiler-flag overrides)" >&2
      bad=1
    fi
  done
  [[ "$bad" == 0 ]] || exit 1
  echo "no compiler-flag or compiler overrides"
}

# The files cargo produced for a build (from its JSON messages; a no-op rebuild still lists them),
# so stale artifacts of other builds in the same target directory are neither scanned nor trusted.
artifacts_of() {
  cargo build --locked --release "$@" --message-format=json |
    grep -o '"filenames":\[[^]]*\]' |
    sed -e 's/^"filenames":\[//' -e 's/\]$//' |
    tr ',' '\n' |
    sed -e 's/^"//' -e 's/"$//'
}

# Files among $1 (newline-separated) that contain the marker.
with_marker() {
  local file
  while IFS= read -r file; do
    if [[ -f "$file" ]] && grep -qaF -- "$MARKER" "$file"; then
      echo "$file"
    fi
  done <<<"$1"
}

check_artifacts() {
  local target=$1 files found
  grep -qF -- "$MARKER" "$MARKER_SOURCE" || fail "marker not found in $MARKER_SOURCE; scan would be vacuous"

  files=$(artifacts_of --target "$target" --bin secure-web) || fail "release build failed"
  grep -q '/libsecure_web_security-[^/]*\.rmeta$' <<<"$files" ||
    fail "secure-web-security is not among the release artifacts; scan would be vacuous"
  grep -q "/release/secure-web$" <<<"$files" || fail "release binary not among the artifacts"
  found=$(with_marker "$files")
  [[ -z "$found" ]] || fail "test-support code compiled into release artifacts: $found"
  echo "release artifacts are free of test-support code:"
  echo "$files" | sed 's/^/  /'

  # Positive control: the same scan must see the marker when the feature *is* compiled.
  files=$(artifacts_of -p secure-web-security --features test-support --target "$target" \
    --target-dir target/test-support-control) || fail "positive-control build failed"
  found=$(with_marker "$files")
  [[ -n "$found" ]] || fail "positive control: marker not found in a test-support build; scan is vacuous"
  echo "positive control: marker detected in $found"
}

case "${1:-}" in
  flags) check_flags ;;
  artifacts) check_artifacts "${2:?usage: $0 artifacts <target>}" ;;
  *) fail "usage: $0 flags | artifacts <target>" ;;
esac

#!/usr/bin/env bash
set -euo pipefail

run_step() {
  local name="$1"
  shift
  if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    echo "::group::${name}"
  else
    printf '==> %s\n' "${name}"
  fi
  "$@"
  if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    echo "::endgroup::"
  fi
}

run_step "format" cargo fmt --all -- --check
run_step "repository text policy" scripts/check_no_emoji.sh
run_step "workspace check" cargo check --workspace --all-targets
run_step "workspace library tests" cargo test --workspace --lib
run_step "service contract tests" cargo test -p dae-daemon --test service_contract
run_step "workspace clippy" cargo clippy --workspace --all-targets -- -D warnings
run_step "resident production panic surface" scripts/check_resident_production_panics.sh

if [[ "${DAENEXT_RELEASE_GATE_AUDIT:-0}" == "1" ]]; then
  if ! command -v cargo-audit >/dev/null 2>&1; then
    echo "cargo-audit is required when DAENEXT_RELEASE_GATE_AUDIT=1" >&2
    exit 1
  fi
  run_step "cargo audit" cargo audit
fi

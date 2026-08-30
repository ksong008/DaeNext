#!/usr/bin/env bash
set -euo pipefail

release_gate_profile="${DAENEXT_RELEASE_GATE_PROFILE:-production-performance}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"

cargo_profile_args=(--locked --profile "$release_gate_profile")

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
run_step "architecture dependency policy" python3 scripts/architecture/check_dependencies.py
run_step "architecture dependency checker tests" python3 scripts/architecture/test_check_dependencies.py
run_step "generation fence ownership" python3 scripts/architecture/check_generation_fence.py
run_step "generation fence ownership tests" python3 scripts/architecture/test_check_generation_fence.py
run_step "recovery boundary" python3 scripts/architecture/check_recovery_boundaries.py
run_step "recovery boundary checker tests" python3 scripts/architecture/test_check_recovery_boundaries.py
run_step "large source boundary gate" python3 scripts/architecture/check_source_boundaries.py
run_step "large source boundary checker tests" python3 scripts/architecture/test_check_source_boundaries.py
run_step "product physical boundaries" python3 scripts/architecture/check_product_boundaries.py
run_step "product boundary checker tests" python3 scripts/architecture/test_check_product_boundaries.py
run_step "product adapter boundary" python3 scripts/architecture/check_product_adapters.py
run_step "product adapter boundary checker tests" python3 scripts/architecture/test_check_product_adapters.py
run_step "production dependency surface" scripts/check_production_deps.sh --all-features
run_step "workspace check" cargo check --workspace --all-targets "${cargo_profile_args[@]}"
run_step "workspace library tests" cargo test --workspace --lib "${cargo_profile_args[@]}" -- --test-threads=1
run_step "resident dataplane architecture tests" cargo test -p dae-resident-dataplane --test architecture_boundaries "${cargo_profile_args[@]}"
run_step "resident transport architecture tests" cargo test -p dae-resident-transport --test architecture_boundaries "${cargo_profile_args[@]}"
run_step "service contract tests" cargo test -p dae-daemon --test service_contract "${cargo_profile_args[@]}"
run_step "workspace clippy" cargo clippy --workspace --all-targets "${cargo_profile_args[@]}" -- -D warnings
run_step "resident production panic surface" scripts/check_resident_production_panics.sh

if [[ "${DAENEXT_RELEASE_GATE_AUDIT:-0}" == "1" ]]; then
  if ! command -v cargo-audit >/dev/null 2>&1; then
    echo "cargo-audit is required when DAENEXT_RELEASE_GATE_AUDIT=1" >&2
    exit 1
  fi
  run_step "cargo audit" cargo audit
fi

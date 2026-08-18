#!/usr/bin/env bash
# Phase 0 / N-01 dependency gate: 生产（normal）依赖树禁止引入
# rustls / tokio-rustls / aws-lc-* / rcgen。
# 用法：scripts/check_production_deps.sh [--all-features]
set -euo pipefail
cd "$(dirname "$0")/.."

FORBIDDEN='rustls|tokio-rustls|aws-lc|rcgen'
EXTRA_ARGS=()
if [[ "${1:-}" == "--all-features" ]]; then
  EXTRA_ARGS+=(--all-features)
fi

mapfile -t PKGS < <(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print("\n".join(sorted(p["name"] for p in json.load(sys.stdin)["packages"])))')

fail=0
for pkg in "${PKGS[@]}"; do
  if hits=$(cargo tree -p "$pkg" -e normal "${EXTRA_ARGS[@]}" 2>/dev/null | grep -E "$FORBIDDEN" || true); then
    if [[ -n "$hits" ]]; then
      echo "FAIL: $pkg production tree contains forbidden dependency:"
      echo "$hits"
      fail=1
    fi
  fi
done

if [[ $fail -eq 0 ]]; then
  echo "OK: ${#PKGS[@]} workspace members: no forbidden deps (rustls/tokio-rustls/aws-lc/rcgen) in production trees"
else
  echo "GATE FAILED"
  exit 1
fi

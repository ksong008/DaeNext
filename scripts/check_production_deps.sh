#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

FORBIDDEN='rustls|tokio-rustls|aws-lc|rcgen'
EXTRA_ARGS=()
case "${1:-}" in
  "") ;;
  --all-features) EXTRA_ARGS+=(--all-features) ;;
  *)
    echo "usage: $0 [--all-features]" >&2
    exit 2
    ;;
esac

mapfile -t PKGS < <(cargo metadata --locked --no-deps --format-version 1 | python3 -c 'import json,sys; print("\n".join(sorted(p["name"] for p in json.load(sys.stdin)["packages"])))')

fail=0
for pkg in "${PKGS[@]}"; do
  if hits=$(cargo tree --locked -p "$pkg" -e normal "${EXTRA_ARGS[@]}" 2>/dev/null | grep -E "$FORBIDDEN" || true); then
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

release_tree="$(cargo tree --locked --workspace -e normal,build,features --prefix none 2>/dev/null)"
release_test_support="$({ printf '%s\n' "$release_tree" | grep -F 'feature "test-support"' || true; } | sort -u)"
if [[ -n "$release_test_support" ]]; then
  echo "FAIL: release feature graph contains test-support:" >&2
  printf '%s\n' "$release_test_support" >&2
  exit 1
fi

test_tree="$(cargo tree --locked --workspace --all-features -e normal,build,dev,features --prefix none 2>/dev/null)"
test_support="$({ printf '%s\n' "$test_tree" | grep -F 'feature "test-support"' || true; } | sort -u)"
if [[ -z "$test_support" ]]; then
  echo "FAIL: all-feature test graph does not exercise test-support" >&2
  exit 1
fi

release_nodes="$(printf '%s\n' "$release_tree" | sort -u | wc -l | tr -d ' ')"
test_nodes="$(printf '%s\n' "$test_tree" | sort -u | wc -l | tr -d ' ')"
test_support_nodes="$(printf '%s\n' "$test_support" | wc -l | tr -d ' ')"
echo "OK: release/test feature graphs compared: release_nodes=${release_nodes}, test_nodes=${test_nodes}, release_test_support=0, test_support_nodes=${test_support_nodes}"

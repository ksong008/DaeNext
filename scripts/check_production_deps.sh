#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
case "$#:${1:-}" in
  0:|1:--all-features) ;;
  *) echo "usage: $0 [--all-features]" >&2; exit 2 ;;
esac
exec python3 scripts/architecture/check_release_features.py "$@"

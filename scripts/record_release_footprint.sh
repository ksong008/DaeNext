#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

source_identity="$(git rev-parse HEAD)"
short_identity="${source_identity:0:12}"
run_id="${RUN_ID:-$(date +%Y%m%d%H%M%S)-$$}"
output_root="${OUTPUT_ROOT:-/tmp/daenext-release-footprint-${short_identity}-${run_id}}"
target_dir="${CARGO_TARGET_DIR:-$output_root/target}"
report="${REPORT:-$output_root/release-footprint.md}"
build_log="$output_root/release-build.log"
analysis_binary="$output_root/daed.unstripped"
release_binary="$output_root/daed.stripped"
target_cpu="${RUST_TARGET_CPU:-native}"
features="${DAED_FEATURES:-default}"
version_shape="${DAE_DAEMON_VERSION:-auto-git-product-identity}"

mkdir -p "$output_root" "$(dirname "$report")" "$target_dir"

build_args=(build --release -p dae-daemon --bin daed)
if [[ "$features" != "default" ]]; then
  build_args+=(--no-default-features --features "$features")
fi

RUSTFLAGS="${RUSTFLAGS:-} -C target-cpu=$target_cpu" \
  CARGO_TARGET_DIR="$target_dir" \
  cargo "${build_args[@]}" >"$build_log" 2>&1

cp "$target_dir/release/daed" "$analysis_binary"
cp "$analysis_binary" "$release_binary"

strip_tool=""
for candidate in llvm-strip rust-llvm-strip strip; do
  if command -v "$candidate" >/dev/null 2>&1; then
    strip_tool="$candidate"
    break
  fi
done
if [[ -z "$strip_tool" ]]; then
  printf 'no supported strip tool found\n' >&2
  exit 1
fi
"$strip_tool" --strip-debug "$release_binary"

readelf -SW "$analysis_binary" >"$output_root/sections.txt"
nm -S --size-sort --radix=d "$analysis_binary" >"$output_root/symbols.txt" 2>"$output_root/symbols.err" || true
tail -n 200 "$output_root/symbols.txt" >"$output_root/largest-symbols.txt"

if command -v cargo-bloat >/dev/null 2>&1; then
  RUSTFLAGS="${RUSTFLAGS:-} -C target-cpu=$target_cpu" \
    CARGO_TARGET_DIR="$target_dir" \
    cargo bloat --release -p dae-daemon --bin daed --crates \
    >"$output_root/crates.txt" 2>"$output_root/crates.err" || true
else
  printf 'cargo-bloat unavailable\n' >"$output_root/crates.txt"
fi

find "$target_dir/release/build" -type f \
  \( -name 'dae-native-bpf_bpfel.o' -o -name 'dae-native-bpf-pname-core_bpfel.o' \) \
  -print0 2>/dev/null \
  | sort -z \
  | xargs -0 -r stat --printf='%n\t%s\n' >"$output_root/embedded-bpf.tsv"

section_bytes() {
  local name="$1"
  local value
  value="$(awk -v wanted="$name" '{ for (field = 1; field <= NF; field += 1) { if ($field == wanted) { print $(field + 4); found = 1; exit } } } END { if (!found) print "0" }' \
    "$output_root/sections.txt")"
  printf '%d\n' "$((16#$value))"
}

tool_version() {
  "$@" 2>&1 | head -n 1
}

{
  printf '# DaeNext release footprint\n\n'
  printf -- '- Recorded: `%s`\n' "$(date --iso-8601=seconds)"
  printf -- '- Source: `%s`\n' "$source_identity"
  printf -- '- Worktree dirty: `%s`\n' "$(if git diff --quiet && git diff --cached --quiet; then printf false; else printf true; fi)"
  printf -- '- Rust: `%s`\n' "$(tool_version rustc --version --verbose | tr '\n' ' ')"
  printf -- '- Cargo: `%s`\n' "$(tool_version cargo --version)"
  printf -- '- LLVM readelf: `%s`\n' "$(tool_version readelf --version)"
  printf -- '- Target CPU: `%s`\n' "$target_cpu"
  printf -- '- Feature set: `%s`\n' "$features"
  printf -- '- Allocator: `%s`\n' "$(if [[ "$features" == *allocator-system* ]]; then printf system; else printf jemalloc; fi)"
  printf -- '- Product version shape: `%s`\n' "$version_shape"
  printf -- '- Strip policy: `%s --strip-debug`\n' "$strip_tool"
  printf -- '- Unstripped bytes: `%s`\n' "$(stat -c %s "$analysis_binary")"
  printf -- '- Stripped bytes: `%s`\n' "$(stat -c %s "$release_binary")"
  printf -- '- `.text` bytes: `%s`\n' "$(section_bytes .text)"
  printf -- '- `.rodata` bytes: `%s`\n' "$(section_bytes .rodata)"
  printf -- '- `.gcc_except_table` bytes: `%s`\n' "$(section_bytes .gcc_except_table)"
  printf -- '- `.eh_frame` bytes: `%s`\n' "$(section_bytes .eh_frame)"
  printf -- '- `.data` bytes: `%s`\n' "$(section_bytes .data)"
  printf -- '- `.bss` bytes: `%s`\n' "$(section_bytes .bss)"
  printf -- '- Embedded BPF inventory: `%s`\n' "$output_root/embedded-bpf.tsv"
  printf -- '- Crate attribution: `%s`\n' "$output_root/crates.txt"
  printf -- '- Largest symbols: `%s`\n' "$output_root/largest-symbols.txt"
  printf -- '- Build log: `%s`\n' "$build_log"
} >"$report"

printf '%s\n' "$report"

#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

python3 - <<'PY'
from __future__ import annotations

import json
import pathlib
import re
import subprocess


ROOT = pathlib.Path.cwd()
metadata = json.loads(
    subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
)
workspace_ids = set(metadata["workspace_members"])
packages = sorted(
    (package for package in metadata["packages"] if package["id"] in workspace_ids),
    key=lambda package: package["name"],
)
workspace_names = {package["name"] for package in packages}
panic_call = re.compile(r"\b(?:unwrap|expect)\s*\(")


def is_path_classified_test(path: pathlib.Path) -> bool:
    relative = path.relative_to(ROOT)
    return (
        "tests" in relative.parts
        or path.name == "tests.rs"
        or path.name.endswith("_test.rs")
        or path.name.endswith("_tests.rs")
        or any(part.endswith("_tests") for part in relative.parts)
    )


print(f"workspace_members\t{len(packages)}")
print("crate\tproduction_path_lines\ttest_path_lines\tproduction_path_panic_calls\ttest_support_marked_files")
for package in packages:
    manifest = pathlib.Path(package["manifest_path"])
    source_root = manifest.parent / "src"
    rust_files = sorted(source_root.rglob("*.rs")) if source_root.is_dir() else []
    production_lines = 0
    test_path_lines = 0
    production_panic_calls = 0
    test_support_marked_files = 0
    for path in rust_files:
        text = path.read_text(encoding="utf-8")
        line_count = text.count("\n") + (0 if not text or text.endswith("\n") else 1)
        if is_path_classified_test(path):
            test_path_lines += line_count
        else:
            production_lines += line_count
            production_panic_calls += len(panic_call.findall(text))
        if 'feature = "test-support"' in text:
            test_support_marked_files += 1
    print(
        "\t".join(
            [
                package["name"],
                str(production_lines),
                str(test_path_lines),
                str(production_panic_calls),
                str(test_support_marked_files),
            ]
        )
    )

print("dependency_from\tdependency_to")
edges: set[tuple[str, str]] = set()
for package in packages:
    for dependency in package["dependencies"]:
        dependency_name = dependency["name"]
        if dependency_name in workspace_names and dependency["kind"] != "dev":
            edges.add((package["name"], dependency_name))
for source, target in sorted(edges):
    print(f"{source}\t{target}")
PY

feature_hits="$({
  cargo tree --workspace -e normal,build,features --prefix none 2>/dev/null \
    | grep -F 'feature "test-support"' || true
} | sort -u)"

if [[ -n "$feature_hits" ]]; then
  echo "production_test_support_feature\tpresent"
  printf '%s\n' "$feature_hits"
  exit 1
fi

printf 'production_test_support_feature\tabsent\n'

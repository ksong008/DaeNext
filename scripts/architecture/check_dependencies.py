#!/usr/bin/env python3
"""Enforce the workspace's declared architecture dependency policy."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
from collections import defaultdict
from typing import Any


DEPENDENCY_KINDS = ("normal", "build", "dev")
FORBIDDEN_DEFAULT_FEATURES = frozenset(
    {"test-support", "benchmark-support", "dns-runtime-tests"}
)
WORKSPACE_CRATE_PATH = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*::")
WORKSPACE_CRATE_IMPORT = re.compile(
    r"\b(?:extern\s+crate|(?:pub\s+)?use)\s+([A-Za-z_][A-Za-z0-9_]*)\b"
)
PATH_ATTRIBUTE = re.compile(r"#\[\s*path\s*=\s*\"([^\"]+)\"\s*\]")
CFG_ATTRIBUTE = re.compile(r"#\[\s*cfg\s*\(([^\n]*)\)\]")
BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
LINE_COMMENT = re.compile(r"//[^\n]*")


def load_metadata(root: pathlib.Path) -> dict[str, Any]:
    result = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def load_policy(path: pathlib.Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as source:
        return json.load(source)


def workspace_packages(metadata: dict[str, Any]) -> dict[str, dict[str, Any]]:
    workspace_ids = set(metadata["workspace_members"])
    return {
        package["name"]: package
        for package in metadata["packages"]
        if package["id"] in workspace_ids
    }


def validate_default_features(packages: dict[str, dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for package_name, package in sorted(packages.items()):
        features = package.get("features", {})
        default_features = features.get("default", []) if isinstance(features, dict) else []
        for feature in sorted(set(default_features) & FORBIDDEN_DEFAULT_FEATURES):
            errors.append(
                f"{package_name}: test-only feature {feature!r} must not be enabled by default"
            )
    return errors


def dependency_kind(dependency: dict[str, Any]) -> str:
    kind = dependency.get("kind")
    return "normal" if kind is None else kind


def workspace_edges(
    packages: dict[str, dict[str, Any]]
) -> dict[str, dict[str, set[str]]]:
    edges = {
        package_name: {kind: set() for kind in DEPENDENCY_KINDS}
        for package_name in packages
    }
    for package_name, package in packages.items():
        for dependency in package["dependencies"]:
            target = dependency["name"]
            kind = dependency_kind(dependency)
            if target in packages and kind in DEPENDENCY_KINDS:
                edges[package_name][kind].add(target)
    return edges


def validate_policy_shape(
    policy: dict[str, Any], packages: dict[str, dict[str, Any]]
) -> list[str]:
    errors: list[str] = []
    if policy.get("version") != 1:
        errors.append("architecture policy must declare version 1")
    if policy.get("default_deny") is not True:
        errors.append("architecture policy must enable default_deny")

    layers = policy.get("layers")
    if not isinstance(layers, list) or not all(isinstance(layer, str) for layer in layers):
        errors.append("architecture policy layers must be a list of names")
        known_layers: set[str] = set()
    else:
        known_layers = set(layers)
        if len(known_layers) != len(layers):
            errors.append("architecture policy contains duplicate layer names")

    package_policy = policy.get("packages")
    if not isinstance(package_policy, dict):
        return errors + ["architecture policy packages must be an object"]

    missing = sorted(set(packages) - set(package_policy))
    unknown = sorted(set(package_policy) - set(packages))
    errors.extend(f"workspace package is missing from policy: {name}" for name in missing)
    errors.extend(f"policy names non-workspace package: {name}" for name in unknown)

    for package_name, entry in sorted(package_policy.items()):
        if package_name not in packages or not isinstance(entry, dict):
            continue
        layer = entry.get("layer")
        if layer not in known_layers:
            errors.append(f"{package_name}: unknown architecture layer {layer!r}")
        for kind in DEPENDENCY_KINDS:
            targets = entry.get(kind)
            if not isinstance(targets, list) or not all(
                isinstance(target, str) for target in targets
            ):
                errors.append(f"{package_name}: {kind} policy must be a list of names")
                continue
            if len(set(targets)) != len(targets):
                errors.append(f"{package_name}: duplicate {kind} policy dependency")
            for target in targets:
                if target not in packages:
                    errors.append(
                        f"{package_name}: policy names non-workspace dependency {target}"
                    )
    forbidden = policy.get("forbidden", {})
    if not isinstance(forbidden, dict):
        errors.append("architecture policy forbidden must be an object")
    else:
        for source, targets in sorted(forbidden.items()):
            if source not in packages:
                errors.append(f"forbidden policy names non-workspace package: {source}")
                continue
            if not isinstance(targets, list) or not all(
                isinstance(target, str) for target in targets
            ):
                errors.append(f"{source}: forbidden policy must be a list of names")
                continue
            if len(set(targets)) != len(targets):
                errors.append(f"{source}: duplicate forbidden dependency")
            for target in targets:
                if target not in packages:
                    errors.append(
                        f"{source}: forbidden policy names non-workspace dependency {target}"
                    )
    return errors


def format_edge(
    source: str,
    target: str,
    kind: str,
    package_policy: dict[str, Any],
) -> str:
    source_layer = package_policy.get(source, {}).get("layer", "<unknown>")
    target_layer = package_policy.get(target, {}).get("layer", "<unknown>")
    return f"{source}[{source_layer}] --{kind}--> {target}[{target_layer}]"


def validate_declared_edges(
    edges: dict[str, dict[str, set[str]]], policy: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    package_policy = policy.get("packages", {})
    for source in sorted(edges):
        entry = package_policy.get(source, {})
        for kind in DEPENDENCY_KINDS:
            actual = edges[source][kind]
            allowed = set(entry.get(kind, []))
            for target in sorted(actual - allowed):
                errors.append(
                    "undeclared architecture dependency: "
                    + format_edge(source, target, kind, package_policy)
                )
            for target in sorted(allowed - actual):
                errors.append(
                    "policy dependency is not declared by Cargo: "
                    + format_edge(source, target, kind, package_policy)
                )
    return errors


def validate_forbidden_edges(
    edges: dict[str, dict[str, set[str]]], policy: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    forbidden = policy.get("forbidden", {})
    for source, targets in sorted(forbidden.items()):
        actual = set().union(*(edges[source][kind] for kind in DEPENDENCY_KINDS))
        for target in sorted(actual & set(targets)):
            errors.append(
                "forbidden architecture dependency: "
                + format_edge(source, target, "any", policy.get("packages", {}))
            )
    return errors


def dependency_cycles(edges: dict[str, dict[str, set[str]]]) -> list[str]:
    graph = {
        source: set(edges[source]["normal"]) | set(edges[source]["build"])
        for source in edges
    }
    state: dict[str, int] = defaultdict(int)
    stack: list[str] = []
    cycles: list[str] = []

    def visit(node: str) -> None:
        state[node] = 1
        stack.append(node)
        for target in sorted(graph[node]):
            if state[target] == 0:
                visit(target)
            elif state[target] == 1:
                start = stack.index(target)
                cycle = stack[start:] + [target]
                rendered = " -> ".join(cycle)
                if rendered not in cycles:
                    cycles.append(rendered)
        stack.pop()
        state[node] = 2

    for node in sorted(graph):
        if state[node] == 0:
            visit(node)
    return cycles


def source_files(package: dict[str, Any]) -> list[tuple[pathlib.Path, str]]:
    manifest = pathlib.Path(package["manifest_path"])
    root = manifest.parent
    files: list[tuple[pathlib.Path, str]] = []
    source_root = root / "src"
    if source_root.is_dir():
        for path in sorted(source_root.rglob("*.rs")):
            relative = path.relative_to(source_root)
            if "tests" in relative.parts or any(
                part.endswith("_tests") for part in relative.parts
            ):
                continue
            if path.name in {"tests.rs", "benchmarks.rs"} or path.name.endswith(
                ("_tests.rs", "_benchmarks.rs")
            ):
                continue
            files.append((path, "normal"))
    build_script = root / "build.rs"
    if build_script.is_file():
        files.append((build_script, "build"))
    return files


def remove_comments(source: str) -> str:
    return LINE_COMMENT.sub("", BLOCK_COMMENT.sub("", source))


def path_attribute_is_test_only(attributes: list[str]) -> bool:
    if not attributes:
        return False
    cfg = " ".join(attributes)
    return bool(re.search(r"\btest\b", cfg)) and not bool(
        re.search(r"\bnot\s*\(\s*test\s*\)", cfg)
    ) and not bool(re.search(r"\bany\s*\([^\n]*\btest\b", cfg))


def validate_source_path_attributes(
    package: dict[str, Any], path: pathlib.Path, source: str
) -> list[str]:
    package_root = pathlib.Path(package["manifest_path"]).parent.resolve()
    errors: list[str] = []
    pending_attributes: list[str] = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()
        cfg_match = CFG_ATTRIBUTE.fullmatch(stripped)
        path_match = PATH_ATTRIBUTE.fullmatch(stripped)
        if cfg_match:
            pending_attributes.append(cfg_match.group(1))
            continue
        if path_match:
            target = (path.parent / path_match.group(1)).resolve()
            try:
                target.relative_to(package_root)
            except ValueError:
                if not path_attribute_is_test_only(pending_attributes):
                    errors.append(
                        "production source embeds an external crate with #[path]: "
                        f"{package['name']} {path.relative_to(package_root)}:{line_number} "
                        f"uses {path_match.group(1)!r}; external paths require a test-only cfg"
                    )
            pending_attributes.clear()
            continue
        if stripped.startswith("#"):
            continue
        pending_attributes.clear()
    return errors


def validate_source_imports(
    packages: dict[str, dict[str, Any]],
    policy: dict[str, Any],
) -> list[str]:
    module_to_package = {
        package_name.replace("-", "_"): package_name for package_name in packages
    }
    errors: list[str] = []
    package_policy = policy.get("packages", {})
    forbidden = policy.get("forbidden", {})
    for package_name, package in sorted(packages.items()):
        entry = package_policy.get(package_name, {})
        for path, source_kind in source_files(package):
            source = remove_comments(path.read_text(encoding="utf-8"))
            errors.extend(validate_source_path_attributes(package, path, source))
            for line_number, line in enumerate(source.splitlines(), start=1):
                module_names = set(WORKSPACE_CRATE_PATH.findall(line))
                module_names.update(WORKSPACE_CRATE_IMPORT.findall(line))
                for module_name in module_names:
                    target = module_to_package.get(module_name)
                    if target is None or target == package_name:
                        continue
                    if target in forbidden.get(package_name, []):
                        errors.append(
                            "source import crosses forbidden architecture edge: "
                            f"{package_name}[{entry.get('layer', '<unknown>')}] "
                            f"{path.relative_to(pathlib.Path(package['manifest_path']).parent)}:{line_number} "
                            f"imports {target}[{package_policy.get(target, {}).get('layer', '<unknown>')}]"
                        )
                    allowed = {
                        target
                        for kind in DEPENDENCY_KINDS
                        for target in entry.get(kind, [])
                    }
                    if target not in allowed:
                        errors.append(
                            "source import crosses undeclared architecture edge: "
                            f"{package_name}[{entry.get('layer', '<unknown>')}] "
                            f"{path.relative_to(pathlib.Path(package['manifest_path']).parent)}:{line_number} "
                            f"imports {target}[{package_policy.get(target, {}).get('layer', '<unknown>')}] "
                            f"but it is not an allowed {source_kind} dependency"
                        )
    return errors


def validate(
    metadata: dict[str, Any], policy: dict[str, Any], scan_sources: bool = True
) -> list[str]:
    packages = workspace_packages(metadata)
    errors = validate_policy_shape(policy, packages)
    errors.extend(validate_default_features(packages))
    edges = workspace_edges(packages)
    errors.extend(validate_declared_edges(edges, policy))
    errors.extend(validate_forbidden_edges(edges, policy))
    for cycle in dependency_cycles(edges):
        errors.append(f"workspace architecture dependency cycle: {cycle}")
    if scan_sources:
        errors.extend(validate_source_imports(packages, policy))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path(__file__).parents[2])
    parser.add_argument(
        "--policy",
        type=pathlib.Path,
        default=pathlib.Path(__file__).with_name("dependency_policy.json"),
    )
    parser.add_argument("--no-source-scan", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    policy = load_policy(args.policy.resolve())
    metadata = load_metadata(root)
    errors = validate(metadata, policy, scan_sources=not args.no_source_scan)
    if errors:
        print("architecture dependency gate: FAILED", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    packages = workspace_packages(metadata)
    print(
        "architecture dependency gate: PASS "
        f"({len(packages)} workspace packages, declared edges and source imports checked)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

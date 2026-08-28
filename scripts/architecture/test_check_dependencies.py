#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("check_dependencies.py")
SPEC = importlib.util.spec_from_file_location("check_dependencies", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def metadata(*packages: tuple[str, list[tuple[str, str | None]]]) -> dict:
    records = []
    members = []
    for name, dependencies in packages:
        package_id = f"path+file:///fixture/{name}#0.1.0"
        members.append(package_id)
        records.append(
            {
                "id": package_id,
                "name": name,
                "manifest_path": f"/fixture/{name}/Cargo.toml",
                "dependencies": [
                    {"name": target, "kind": kind} for target, kind in dependencies
                ],
            }
        )
    return {"workspace_members": members, "packages": records}


def policy(*packages: tuple[str, list[str], list[str], list[str]]) -> dict:
    return {
        "version": 1,
        "default_deny": True,
        "layers": ["test"],
        "packages": {
            name: {"layer": "test", "normal": normal, "build": build, "dev": dev}
            for name, normal, build, dev in packages
        },
    }


class ArchitectureDependencyCheckerTests(unittest.TestCase):
    def test_undeclared_edge_is_rejected(self) -> None:
        errors = CHECKER.validate(
            metadata(("a", [("b", None)]), ("b", [])),
            policy(("a", [], [], []), ("b", [], [], [])),
            scan_sources=False,
        )
        self.assertTrue(any("undeclared architecture dependency" in error for error in errors))

    def test_dev_dependency_has_separate_policy_slot(self) -> None:
        graph = metadata(("a", [("b", "dev")]), ("b", []))
        allowed = CHECKER.validate(
            graph,
            policy(("a", [], [], ["b"]), ("b", [], [], [])),
            scan_sources=False,
        )
        denied = CHECKER.validate(
            graph,
            policy(("a", ["b"], [], []), ("b", [], [], [])),
            scan_sources=False,
        )
        self.assertEqual(allowed, [])
        self.assertTrue(any("undeclared architecture dependency" in error for error in denied))

    def test_cycle_is_reported_even_when_edges_are_allowed(self) -> None:
        errors = CHECKER.validate(
            metadata(("a", [("b", None)]), ("b", [("a", None)])),
            policy(("a", ["b"], [], []), ("b", ["a"], [], [])),
            scan_sources=False,
        )
        self.assertTrue(any("dependency cycle" in error for error in errors))

    def test_forbidden_edge_is_rejected_even_when_declared(self) -> None:
        graph = metadata(("a", [("b", None)]), ("b", []))
        fixture_policy = policy(("a", ["b"], [], []), ("b", [], [], []))
        fixture_policy["forbidden"] = {"a": ["b"]}

        errors = CHECKER.validate(graph, fixture_policy, scan_sources=False)

        self.assertTrue(any("forbidden architecture dependency" in error for error in errors))

    def test_source_import_must_have_declared_edge(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source_root = root / "a" / "src"
            source_root.mkdir(parents=True)
            (source_root / "lib.rs").write_text(
                "use b;\nextern crate b;\n", encoding="utf-8"
            )
            graph = metadata(("a", []), ("b", []))
            graph["packages"][0]["manifest_path"] = str(root / "a" / "Cargo.toml")
            errors = CHECKER.validate(
                graph,
                policy(("a", [], [], []), ("b", [], [], [])),
                scan_sources=True,
            )
        source_errors = [error for error in errors if "source import crosses" in error]
        self.assertEqual(len(source_errors), 2)

    def test_forbidden_source_import_is_rejected_when_edge_is_declared(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source_root = root / "a" / "src"
            source_root.mkdir(parents=True)
            (source_root / "lib.rs").write_text("use b::item;\n", encoding="utf-8")
            graph = metadata(("a", [("b", None)]), ("b", []))
            graph["packages"][0]["manifest_path"] = str(root / "a" / "Cargo.toml")
            fixture_policy = policy(("a", ["b"], [], []), ("b", [], [], []))
            fixture_policy["forbidden"] = {"a": ["b"]}
            errors = CHECKER.validate(graph, fixture_policy, scan_sources=True)

        self.assertTrue(
            any("source import crosses forbidden architecture edge" in error for error in errors)
        )


if __name__ == "__main__":
    unittest.main()

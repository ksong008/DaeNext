#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("check_source_boundaries.py")
SPEC = importlib.util.spec_from_file_location("check_source_boundaries", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SourceBoundaryGateTests(unittest.TestCase):
    def root_with_sources(self, production: str, tests: str) -> pathlib.Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        source = root / "crates" / "fixture" / "src"
        (source / "tests").mkdir(parents=True)
        (source / "lib.rs").write_text(production, encoding="utf-8")
        (source / "tests" / "case.rs").write_text(tests, encoding="utf-8")
        return root

    def test_accepts_sources_within_budget(self) -> None:
        root = self.root_with_sources("one\ntwo\n", "test\n")
        self.assertEqual(
            MODULE.validate(root, {"packages": {"fixture": {"production": 2, "tests": 1}}}),
            [],
        )

    def test_rejects_production_growth(self) -> None:
        root = self.root_with_sources("one\ntwo\n", "test\n")
        errors = MODULE.validate(
            root, {"packages": {"fixture": {"production": 1, "tests": 1}}}
        )
        self.assertTrue(any("production source boundary grew" in error for error in errors))

    def test_subtree_growth_cannot_hide_in_package_budget(self) -> None:
        root = self.root_with_sources("one\ntwo\n", "test\n")
        sub = root / "crates/fixture/src/hotspot"
        sub.mkdir()
        (sub / "owner.rs").write_text("one\ntwo\n")
        policy = {"packages": {"fixture": {"production": 10, "tests": 1}},
                  "subtrees": {"crates/fixture/src/hotspot": {"production": 1, "tests": 0}}}
        self.assertTrue(any("hotspot" in error for error in MODULE.validate(root, policy)))
        policy["subtrees"]["crates/fixture/src/hotspot"]["production"] = 2
        self.assertEqual(MODULE.validate(root, policy), [])
        (sub / "owner.rs").unlink()
        sub.rmdir()
        self.assertTrue(any("missing" in error for error in MODULE.validate(root, policy)))

    def test_inline_tests_keep_the_legacy_counting_contract(self) -> None:
        root = self.root_with_sources("#[cfg(test)]\nmod inline {}\n", "test\n")
        self.assertEqual(MODULE.line_counts(root / "crates/fixture/src"), (2, 1))
        self.assertTrue(MODULE.is_test_path(pathlib.Path("src/domain_tests/case.rs")))
        self.assertTrue(MODULE.is_test_path(pathlib.Path("src/domain_tests.rs")))

    def test_rejects_subtree_escape(self) -> None:
        root = self.root_with_sources("one\n", "test\n")
        self.assertTrue(MODULE.validate(root, {"packages": {}, "subtrees": {"../outside": {}}}))


if __name__ == "__main__":
    unittest.main()

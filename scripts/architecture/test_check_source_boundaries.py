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


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("check_product_boundaries.py")
SPEC = importlib.util.spec_from_file_location("check_product_boundaries", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ProductBoundaryGateTests(unittest.TestCase):
    def fixture(self) -> pathlib.Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        for crate in MODULE.REQUIRED_CRATES:
            source = root / "crates" / crate / "src"
            source.mkdir(parents=True)
            (source / "lib.rs").write_text("pub struct Fixture;\n", encoding="utf-8")
        for relative in MODULE.REQUIRED_OWNERSHIP_FILES:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("pub struct Owner;\n", encoding="utf-8")
        (root / "crates" / "dae-daemon" / "src" / "daed_product").mkdir(
            parents=True
        )
        return root

    def test_accepts_complete_extracted_layout(self) -> None:
        self.assertEqual(MODULE.validate(self.fixture()), [])

    def test_rejects_missing_product_source(self) -> None:
        root = self.fixture()
        target = root / "crates" / MODULE.REQUIRED_CRATES[0] / "src"
        for path in target.iterdir():
            path.unlink()
        target.rmdir()
        errors = MODULE.validate(root)
        self.assertTrue(any("source directory is missing" in error for error in errors))

    def test_rejects_missing_product_owner_file(self) -> None:
        root = self.fixture()
        target = root / MODULE.REQUIRED_OWNERSHIP_FILES[0]
        target.unlink()
        errors = MODULE.validate(root)
        self.assertTrue(any("required product owner file is missing" in error for error in errors))

    def test_rejects_returned_daemon_implementation(self) -> None:
        root = self.fixture()
        returned = root / "crates" / "dae-daemon" / "src" / "daed_product" / "auth_runtime"
        returned.mkdir()
        (returned / "mod.rs").write_text("pub struct Returned;\n", encoding="utf-8")
        errors = MODULE.validate(root)
        self.assertTrue(any("returned to daemon" in error for error in errors))

    def test_rejects_returned_daemon_function(self) -> None:
        root = self.fixture()
        returned = root / "crates" / "dae-daemon" / "src" / "daed_product" / "adapter.rs"
        returned.write_text("fn list_subscriptions_value() {}\n", encoding="utf-8")
        errors = MODULE.validate(root)
        self.assertTrue(any("function returned to daemon" in error for error in errors))

    def test_rejects_product_to_daemon_reference(self) -> None:
        root = self.fixture()
        source = root / "crates" / MODULE.REQUIRED_CRATES[0] / "src" / "lib.rs"
        source.write_text("use dae_daemon::daed_product::State;\n", encoding="utf-8")
        errors = MODULE.validate(root)
        self.assertTrue(any("references daemon" in error for error in errors))

    def test_rejects_daemon_bypassing_resident_facade(self) -> None:
        root = self.fixture()
        source = root / "crates" / "dae-daemon" / "src" / "resident.rs"
        source.write_text("use dae_resident_tcp::State;\n", encoding="utf-8")
        errors = MODULE.validate(root)
        self.assertTrue(any("bypasses resident facade" in error for error in errors))


if __name__ == "__main__":
    unittest.main()

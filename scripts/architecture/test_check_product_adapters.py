#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("check_product_adapters.py")
SPEC = importlib.util.spec_from_file_location("check_product_adapters", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ProductAdapterGateTests(unittest.TestCase):
    def fixture(self) -> tuple[pathlib.Path, dict[str, object]]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        adapter = root / "crates" / "dae-daemon" / "src" / "daed_product"
        adapter.mkdir(parents=True)
        policy = {
            "root": "crates/dae-daemon/src/daed_product",
            "allowed_top_level": ["api_routes", "api_routes.rs", "tests"],
            "production_line_limits": {"api_routes": 2, "api_routes.rs": 2},
        }
        return root, policy

    def test_accepts_allowlisted_adapter_within_budget(self) -> None:
        root, policy = self.fixture()
        (root / "crates/dae-daemon/src/daed_product/api_routes").mkdir()
        (root / "crates/dae-daemon/src/daed_product/api_routes/router.rs").write_text(
            "one\ntwo\n", encoding="utf-8"
        )
        self.assertEqual(MODULE.validate(root, policy), [])

    def test_rejects_new_top_level_surface(self) -> None:
        root, policy = self.fixture()
        (root / "crates/dae-daemon/src/daed_product/new_domain.rs").write_text(
            "pub struct Returned;\n", encoding="utf-8"
        )
        errors = MODULE.validate(root, policy)
        self.assertTrue(any("unapproved" in error for error in errors))

    def test_rejects_adapter_growth(self) -> None:
        root, policy = self.fixture()
        (root / "crates/dae-daemon/src/daed_product/api_routes.rs").write_text(
            "one\ntwo\nthree\n", encoding="utf-8"
        )
        errors = MODULE.validate(root, policy)
        self.assertTrue(any("grew" in error for error in errors))


if __name__ == "__main__":
    unittest.main()

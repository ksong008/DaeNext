#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("check_recovery_boundaries.py")
SPEC = importlib.util.spec_from_file_location("check_recovery_boundaries", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class RecoveryBoundaryChecksTest(unittest.TestCase):
    def write_fixture(self, resident: str, product: str) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        resident_path = root / CHECKER.RESIDENT_SERVICE
        product_path = root / CHECKER.PRODUCT_SERVER
        resident_path.parent.mkdir(parents=True)
        product_path.parent.mkdir(parents=True)
        resident_path.write_text(resident, encoding="utf-8")
        product_path.write_text(product, encoding="utf-8")
        return root

    def test_separate_paths_are_allowed(self) -> None:
        root = self.write_fixture(
            "fn run_resident_service() {}\n",
            "fn run_product_server() { recover_product_durable_state(); }\n",
        )

        self.assertEqual(CHECKER.validate(root), [])

    def test_resident_recovery_is_rejected(self) -> None:
        root = self.write_fixture(
            "fn run_resident_service() { recover_product_durable_state(); }\n",
            "fn run_product_server() { recover_product_durable_state(); }\n",
        )

        errors = CHECKER.validate(root)

        self.assertEqual(len(errors), 1)
        self.assertIn("resident direct-service", errors[0])

    def test_missing_product_recovery_is_rejected(self) -> None:
        root = self.write_fixture(
            "fn run_resident_service() {}\n",
            "fn run_product_server() {}\n",
        )

        errors = CHECKER.validate(root)

        self.assertEqual(len(errors), 1)
        self.assertIn("product server path", errors[0])


if __name__ == "__main__":
    unittest.main()

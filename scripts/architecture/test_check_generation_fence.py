#!/usr/bin/env python3

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from check_generation_fence import validate


class GenerationFenceChecksTest(unittest.TestCase):
    @staticmethod
    def add_core(root: Path) -> None:
        core = root / "crates" / "dae-resident-core" / "src"
        core.mkdir(parents=True)

    def test_core_owned_guard_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.add_core(root)
            core = root / "crates" / "dae-resident-core" / "src"
            (core / "generation_fence.rs").write_text(
                "pub struct GenerationGate;\npub struct GenerationFence<T>(T);\n",
                encoding="utf-8",
            )
            other = root / "crates" / "dae-resident-dns" / "src"
            other.mkdir(parents=True)
            (other / "lib.rs").write_text(
                "use dae_resident_core::GenerationFence;\n",
                encoding="utf-8",
            )

            self.assertEqual(validate(root), [])

    def test_domain_guard_declaration_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.add_core(root)
            source = root / "crates" / "dae-resident-udp" / "src"
            source.mkdir(parents=True)
            (source / "lib.rs").write_text(
                "struct LocalGenerationGuard;\n",
                encoding="utf-8",
            )

            errors = validate(root)

            self.assertEqual(len(errors), 1)
            self.assertIn("LocalGenerationGuard", errors[0])

    def test_test_only_fixture_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.add_core(root)
            source = root / "crates" / "dae-resident-udp" / "src" / "tests"
            source.mkdir(parents=True)
            (source / "generation.rs").write_text(
                "struct FixtureGenerationFence;\n",
                encoding="utf-8",
            )

            self.assertEqual(validate(root), [])

    def test_local_active_generation_storage_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.add_core(root)
            source = root / "crates" / "dae-resident-tcp" / "src"
            source.mkdir(parents=True)
            (source / "lib.rs").write_text(
                "struct LocalOwner {\n"
                "    active_generation: std::sync::RwLock<Option<u64>>,\n"
                "}\n",
                encoding="utf-8",
            )

            errors = validate(root)

            self.assertEqual(len(errors), 1)
            self.assertIn("active_generation", errors[0])
            self.assertIn("not core-owned", errors[0])

    def test_core_generation_storage_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.add_core(root)
            source = root / "crates" / "dae-resident-udp" / "src"
            source.mkdir(parents=True)
            (source / "lib.rs").write_text(
                "use dae_resident_core::ActiveGenerationSlot;\n"
                "struct LocalOwner<T> {\n"
                "    active_generation: ActiveGenerationSlot<T>,\n"
                "}\n",
                encoding="utf-8",
            )

            self.assertEqual(validate(root), [])

    def test_epoch_fence_declaration_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.add_core(root)
            source = root / "crates" / "dae-resident-tcp" / "src"
            source.mkdir(parents=True)
            (source / "lib.rs").write_text(
                "struct LocalEpochFence;\n", encoding="utf-8"
            )

            errors = validate(root)

            self.assertEqual(len(errors), 1)
            self.assertIn("LocalEpochFence", errors[0])

    def test_generation_epoch_storage_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.add_core(root)
            source = root / "crates" / "dae-resident-udp" / "src"
            source.mkdir(parents=True)
            (source / "lib.rs").write_text(
                "struct LocalOwner {\n"
                "    current_epoch: std::sync::Arc<std::sync::atomic::AtomicU64>,\n"
                "}\n",
                encoding="utf-8",
            )

            errors = validate(root)

            self.assertEqual(len(errors), 1)
            self.assertIn("current_epoch", errors[0])


if __name__ == "__main__":
    unittest.main()

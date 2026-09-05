#!/usr/bin/env python3
"""Real, registry-free Cargo fixtures for production feature isolation."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import check_release_features as gate


class ReleaseFeaturesTests(unittest.TestCase):
    def fixture(self, dependencies, root_features="", name="helper", bench=False, target="x86_64-unknown-linux-gnu", edges="normal,build"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            members = ["product", "helper"] + (["bench"] if bench else [])
            (root / "Cargo.toml").write_text('[workspace]\nresolver = "2"\nmembers = ' + str(members).replace("'", '"') + '\n')
            for member in members:
                (root / member / "src").mkdir(parents=True)
                (root / member / "src/lib.rs").write_text("")
            (root / "helper/Cargo.toml").write_text(f'[package]\nname="{name}"\nversion="1.0.0"\n[features]\ntest-support=[]\nbenchmark-support=[]\n')
            (root / "product/Cargo.toml").write_text('[package]\nname="product"\nversion="1.0.0"\n' + dependencies + '\n' + root_features)
            if bench:
                (root / "bench/Cargo.toml").write_text('[package]\nname="bench"\nversion="1.0.0"\n[dependencies]\nhelper={path="../helper", features=["benchmark-support"]}\n')
            gate.command(["cargo", "generate-lockfile", "--offline"], root)
            return gate.tree(root, ["-p", "product"], target, edges)

    def test_direct_alias_and_build_features(self):
        for kind in ("dependencies", "build-dependencies"):
            for feature in ("test-support", "benchmark-support"):
                with self.subTest(kind=kind, feature=feature):
                    selected = self.fixture(f'[{kind}]\nhelper={{path="../helper",features=["{feature}"]}}')
                    self.assertTrue(gate.violations(selected))
        selected = self.fixture('[dependencies]\nhelper={path="../helper"}', '[features]\ndefault=["legacy-quic"]\nlegacy-quic=["helper/test-support"]')
        self.assertTrue(gate.violations(selected))

    def test_dev_and_unrelated_bench_are_separate(self):
        deps = '[dev-dependencies]\nhelper={path="../helper",features=["test-support"]}'
        self.assertFalse(gate.violations(self.fixture(deps, bench=True)))
        self.assertTrue(gate.violations(self.fixture(deps, edges="normal,build,dev")))

    def test_target_conditions(self):
        deps = '[target.\'cfg(windows)\'.dependencies]\nhelper={path="../helper",features=["test-support"]}'
        self.assertFalse(gate.violations(self.fixture(deps)))
        self.assertTrue(gate.violations(self.fixture(deps, target="x86_64-pc-windows-gnu")))

    def test_exact_provider_identity(self):
        for name in sorted(gate.PROVIDERS | {"rustls-pki-types"}):
            with self.subTest(name=name):
                selected = self.fixture(f'[dependencies]\n{name}={{path="../helper"}}', name=name)
                self.assertEqual(bool(gate.violations(selected)), name in gate.PROVIDERS)

    def test_parser_fails_closed_and_preserves_identity(self):
        for value in ("", "\n", "helper v1.0.0", "helper v1.0.0|bad feature", "helper v1.0.0|a||b"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                gate.parse_tree(value)
        selected = gate.parse_tree('helper v1.0.0 (/a)|test-support-extra\nhelper v2.0.0 (/b)|test-support (*)\nhelper v1.0.0 (/a)|default\n')
        self.assertEqual(len(selected), 2)
        self.assertEqual(len(gate.violations(selected)), 1)

    def test_cargo_failure_cannot_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(subprocess.CalledProcessError):
                gate.tree(Path(directory), ["-p", "missing"], "x86_64-unknown-linux-gnu")
        with patch("sys.argv", ["gate", "--product-only"]), patch.object(gate, "command", side_effect=OSError("cargo unavailable")):
            self.assertEqual(gate.main(), 1)


if __name__ == "__main__":
    unittest.main()

//go:build embedallowed

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestEmbeddedRustBpfLoaderPathRunsNativeContract(t *testing.T) {
	t.Setenv(rustBpfLoaderHelperEnv, "")

	path, err := embeddedRustBpfLoaderPath()
	if err != nil {
		t.Fatalf("embeddedRustBpfLoaderPath() error = %v", err)
	}
	if path == "" {
		t.Fatal("embeddedRustBpfLoaderPath() returned empty path")
	}
	if fi, err := os.Stat(path); err != nil {
		t.Fatalf("stat embedded helper: %v", err)
	} else if fi.Mode()&0100 == 0 {
		t.Fatalf("embedded helper mode = %v, want executable", fi.Mode())
	}

	out, err := exec.Command(path, "contract").CombinedOutput()
	if err != nil {
		t.Fatalf("embedded helper contract failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if !strings.Contains(string(out), `"compiled_native_ebpf":true`) {
		t.Fatalf("embedded helper contract missing native-ebpf marker: %s", strings.TrimSpace(string(out)))
	}
}

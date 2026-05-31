//go:build linux && cgo && rust_inprocess

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"strings"
	"testing"
)

func TestRustInprocessRoutingMapWriterEnabled(t *testing.T) {
	if !rustInprocessRoutingMapAvailable() {
		t.Fatal("Rust in-process routing map writer is not available")
	}
}

func TestRustOwnedInprocessRoutingMapOwnerRejectsEmptySnapshot(t *testing.T) {
	err := applyKernelRoutingMapsViaRustOwnedInprocess(rustRoutingMapApplyRequest{})
	if err == nil {
		t.Fatal("Rust in-process routing map owner accepted an empty snapshot")
	}
	if !strings.Contains(err.Error(), "missing fallback") {
		t.Fatalf("error = %v, want missing fallback", err)
	}
}

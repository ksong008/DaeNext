//go:build linux && cgo && rust_inprocess

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import "testing"

func TestRustInprocessRoutingMapWriterEnabled(t *testing.T) {
	if !rustInprocessRoutingMapAvailable() {
		t.Fatal("Rust in-process routing map writer is not available")
	}
}

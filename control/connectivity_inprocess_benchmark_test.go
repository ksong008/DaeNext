//go:build linux && cgo && rust_inprocess

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import "testing"

func BenchmarkOutboundConnectivityMapRustOwnedInprocessDuplicate(b *testing.B) {
	if !rustInprocessRoutingMapAvailable() {
		b.Skip("Rust in-process outbound connectivity owner is not enabled")
	}
	m := newBenchmarkConnectivityMap(b)
	defer m.Close()
	owner := newRustOutboundConnectivityOwner()
	defer owner.Close()
	if err := owner.Update(m, 2, 6, 4, true, true, false); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := owner.Update(m, 2, 6, 4, true, false, false); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOutboundConnectivityMapRustOwnedInprocessToggle(b *testing.B) {
	if !rustInprocessRoutingMapAvailable() {
		b.Skip("Rust in-process outbound connectivity owner is not enabled")
	}
	m := newBenchmarkConnectivityMap(b)
	defer m.Close()
	owner := newRustOutboundConnectivityOwner()
	defer owner.Close()
	if err := owner.Update(m, 2, 6, 4, true, true, false); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := owner.Update(m, 2, 6, 4, i%2 == 0, false, false); err != nil {
			b.Fatal(err)
		}
	}
}

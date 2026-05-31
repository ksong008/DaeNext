/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import "testing"

var reloadDnsDecisionBenchmarkSink bool

func BenchmarkReloadDnsCacheRestoreDecisionGoBool(b *testing.B) {
	var sink bool
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sink = true
	}
	reloadDnsDecisionBenchmarkSink = sink
}

func BenchmarkReloadDnsCacheRestoreDecisionRustOwned(b *testing.B) {
	if !rustInprocessRoutingMapAvailable() {
		b.Skip("Rust in-process reload DNS cache plan is not enabled")
	}
	var sink bool
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sink = RustOwnedReloadDnsCacheRestoreAllowed(true)
	}
	reloadDnsDecisionBenchmarkSink = sink
}

func BenchmarkRustOwnedRuntimeStateReport(b *testing.B) {
	if !rustInprocessRoutingMapAvailable() {
		b.Skip("Rust in-process runtime state report is not enabled")
	}
	var sink bool
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		report, err := BuildRustOwnedRuntimeStateReport()
		if err != nil {
			b.Fatal(err)
		}
		sink = report.ReadyForDefaultControlPlane
	}
	reloadDnsDecisionBenchmarkSink = sink
}

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"

	"github.com/cilium/ebpf"
)

func BenchmarkOutboundConnectivityMapGoUpdate(b *testing.B) {
	m := newBenchmarkConnectivityMap(b)
	defer m.Close()

	key := bpfOutboundConnectivityQuery{Outbound: 2, L4proto: 6, Ipversion: 4}
	value := uint32(1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := m.Update(key, value, ebpf.UpdateAny); err != nil {
			b.Fatal(err)
		}
	}
}

func newBenchmarkConnectivityMap(b *testing.B) *ebpf.Map {
	b.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "dae_conn_bench",
		Type:       ebpf.Hash,
		KeySize:    3,
		ValueSize:  4,
		MaxEntries: 1024,
	})
	if err != nil {
		b.Skipf("connectivity map benchmark requires BPF map create permission: %v", err)
	}
	return m
}

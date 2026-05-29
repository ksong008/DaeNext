/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func BenchmarkOutboundConnectivityMapGoUpdate(b *testing.B) {
	m := newBenchmarkConnectivityMap(b)
	defer m.Close()

	key := bpfOutboundConnectivityQuery{Outbound: 2, L4proto: 6, Ipversion: 4}
	value := uint32(1)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := m.Update(key, value, ebpf.UpdateAny); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOutboundConnectivityMapRustHelperUpdate(b *testing.B) {
	helper := strings.TrimSpace(os.Getenv(rustBpfLoaderHelperEnv))
	if helper == "" {
		b.Skipf("%s is not set", rustBpfLoaderHelperEnv)
	}
	b.Setenv(rustBpfLoaderHelperEnv, helper)

	m := newBenchmarkConnectivityMap(b)
	defer m.Close()
	mapID, err := bpfMapID(m)
	if err != nil {
		b.Fatal(err)
	}

	args := []string{
		"connectivity-map", "update",
		"--map-id", strconv.FormatUint(uint64(mapID), 10),
		"--outbound", "2",
		"--l4-proto", "6",
		"--ip-version", "4",
		"--alive", "true",
		"--is-init", "true",
		"--dryrun", "false",
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := runRustBpfLoaderHelperOutput(args...); err != nil {
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

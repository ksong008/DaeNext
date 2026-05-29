/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
)

func BenchmarkRoutingMapGoUpdate(b *testing.B) {
	m := newBenchmarkRoutingMap(b)
	defer m.Close()
	keys, values := benchmarkRoutingEntries()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := BpfMapBatchUpdate(m, keys, values, &ebpf.BatchOptions{
			ElemFlags: uint64(ebpf.UpdateAny),
		}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRoutingMapRustHelperUpdate(b *testing.B) {
	helperPath := strings.TrimSpace(os.Getenv(rustBpfLoaderHelperEnv))
	if helperPath == "" {
		b.Skipf("%s is not set", rustBpfLoaderHelperEnv)
	}
	b.Setenv(rustBpfLoaderHelperEnv, helperPath)
	m := newBenchmarkRoutingMap(b)
	defer m.Close()
	mapID, err := bpfMapID(m)
	if err != nil {
		b.Fatal(err)
	}
	_, values := benchmarkRoutingEntries()
	request := rustRoutingMapApplyRequest{
		RoutingMapID:   mapID,
		LpmArrayMapID:  mapID,
		LpmEntries:     []rustLpmArrayMapEntry{},
		RoutingEntries: make([]rustRoutingMapEntry, 0, len(values)),
	}
	for index, value := range values {
		request.RoutingEntries = append(request.RoutingEntries, rustRoutingMapEntry{
			Index: uint32(index),
			Value: rustBpfMatchSet{
				Value:    value.Value,
				Not:      value.Not,
				Type:     value.Type,
				Outbound: value.Outbound,
				Must:     value.Must,
				Mark:     value.Mark,
			},
		})
	}
	payload, err := json.Marshal(request)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := runRustBpfLoaderHelperInput(payload, "routing-map", "apply"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDomainRoutingMapGoUpdate(b *testing.B) {
	m := newBenchmarkDomainRoutingMap(b)
	defer m.Close()
	key, value := benchmarkDomainRoutingEntry()
	keys := [][4]uint32{key}
	values := []bpfDomainRouting{value}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := BpfMapBatchUpdate(m, keys, values, &ebpf.BatchOptions{
			ElemFlags: uint64(ebpf.UpdateAny),
		}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDomainRoutingMapRustHelperUpdate(b *testing.B) {
	helperPath := strings.TrimSpace(os.Getenv(rustBpfLoaderHelperEnv))
	if helperPath == "" {
		b.Skipf("%s is not set", rustBpfLoaderHelperEnv)
	}
	b.Setenv(rustBpfLoaderHelperEnv, helperPath)
	m := newBenchmarkDomainRoutingMap(b)
	defer m.Close()
	mapID, err := bpfMapID(m)
	if err != nil {
		b.Fatal(err)
	}
	key, value := benchmarkDomainRoutingEntry()
	payload, err := json.Marshal(rustDomainRoutingMapApplyRequest{
		MapID: mapID,
		Updates: []rustDomainRoutingMapUpdate{{
			Key:    key,
			Bitmap: value.Bitmap,
		}},
		Deletes: [][4]uint32{},
	})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := runRustBpfLoaderHelperInput(payload, "domain-routing-map", "apply"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDomainRoutingMapRustPersistentHelperUpdate(b *testing.B) {
	helperPath := strings.TrimSpace(os.Getenv(rustBpfLoaderHelperEnv))
	if helperPath == "" {
		b.Skipf("%s is not set", rustBpfLoaderHelperEnv)
	}
	b.Setenv(rustBpfLoaderHelperEnv, helperPath)
	m := newBenchmarkDomainRoutingMap(b)
	defer m.Close()
	mapID, err := bpfMapID(m)
	if err != nil {
		b.Fatal(err)
	}
	key, value := benchmarkDomainRoutingEntry()
	request := rustDomainRoutingMapApplyRequest{
		MapID: mapID,
		Updates: []rustDomainRoutingMapUpdate{{
			Key:    key,
			Bitmap: value.Bitmap,
		}},
		Deletes: [][4]uint32{},
	}
	helper := newRustDomainRoutingHelper()
	defer helper.Close()
	if err := helper.Update(request); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := helper.Update(request); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkRoutingEntries() ([]uint32, []bpfMatchSet) {
	keys := []uint32{0, 1, 2, 3}
	values := []bpfMatchSet{
		{Type: 3, Outbound: 2},
		{Type: 4, Outbound: 2, Must: true},
		{Type: 10, Outbound: 2, Mark: 0x08000000},
		{Type: 11, Outbound: 2},
	}
	values[0].Value[0] = 6
	values[1].Value[0] = 4
	return keys, values
}

func benchmarkDomainRoutingEntry() ([4]uint32, bpfDomainRouting) {
	var value bpfDomainRouting
	value.Bitmap[0] = 0x1
	return [4]uint32{0, 0, 0xffff, 0xcb00710a}, value
}

func newBenchmarkRoutingMap(b *testing.B) *ebpf.Map {
	b.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "dae_route_bench",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  uint32(unsafe.Sizeof(bpfMatchSet{})),
		MaxEntries: 1024,
	})
	if err != nil {
		b.Skipf("routing map benchmark requires BPF map create permission: %v", err)
	}
	return m
}

func newBenchmarkDomainRoutingMap(b *testing.B) *ebpf.Map {
	b.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "dae_domain_bench",
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof([4]uint32{})),
		ValueSize:  uint32(unsafe.Sizeof(bpfDomainRouting{})),
		MaxEntries: 128,
	})
	if err != nil {
		b.Skipf("domain routing map benchmark requires BPF map create permission: %v", err)
	}
	return m
}

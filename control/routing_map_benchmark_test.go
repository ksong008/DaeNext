/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"golang.org/x/sys/unix"
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

func BenchmarkRoutingMapGoUpdateWithLpmBuild(b *testing.B) {
	routingMap := newBenchmarkRoutingMap(b)
	defer routingMap.Close()
	lpmTemplate := newBenchmarkLpmTemplateMap(b)
	defer lpmTemplate.Close()
	lpmArrayMap := newBenchmarkLpmArrayMap(b)
	defer lpmArrayMap.Close()
	objects := &bpfObjects{
		bpfMaps: bpfMaps{
			RoutingMap:    routingMap,
			LpmArrayMap:   lpmArrayMap,
			UnusedLpmType: lpmTemplate,
		},
	}
	routingKeys, routingValues := benchmarkRoutingEntriesWithLpm()
	lpmKeys := []_bpfLpmKey{cidrToBpfLpmKey(netip.MustParsePrefix("203.0.113.0/24"))}
	lpmValues := []uint32{1}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		inner, err := objects.newLpmMap(lpmKeys, lpmValues)
		if err != nil {
			b.Fatal(err)
		}
		if err := lpmArrayMap.Update(uint32(0), inner, ebpf.UpdateAny); err != nil {
			_ = inner.Close()
			b.Fatal(err)
		}
		if err := inner.Close(); err != nil {
			b.Fatal(err)
		}
		if _, err := BpfMapBatchUpdate(routingMap, routingKeys, routingValues, &ebpf.BatchOptions{
			ElemFlags: uint64(ebpf.UpdateAny),
		}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRoutingMapRustHelperUpdateWithLpmBuild(b *testing.B) {
	helperPath := strings.TrimSpace(os.Getenv(rustBpfLoaderHelperEnv))
	if helperPath == "" {
		b.Skipf("%s is not set", rustBpfLoaderHelperEnv)
	}
	b.Setenv(rustBpfLoaderHelperEnv, helperPath)
	routingMap := newBenchmarkRoutingMap(b)
	defer routingMap.Close()
	lpmTemplate := newBenchmarkLpmTemplateMap(b)
	defer lpmTemplate.Close()
	lpmArrayMap := newBenchmarkLpmArrayMap(b)
	defer lpmArrayMap.Close()
	routingMapID, err := bpfMapID(routingMap)
	if err != nil {
		b.Fatal(err)
	}
	lpmArrayMapID, err := bpfMapID(lpmArrayMap)
	if err != nil {
		b.Fatal(err)
	}
	_, values := benchmarkRoutingEntriesWithLpm()
	lpmKey := cidrToBpfLpmKey(netip.MustParsePrefix("203.0.113.0/24"))
	request := rustRoutingMapApplyRequest{
		RoutingMapID:  routingMapID,
		LpmArrayMapID: lpmArrayMapID,
		LpmEntries:    []rustLpmArrayMapEntry{},
		LpmMaps: []rustLpmMapBuildSpec{{
			Index:      0,
			Flags:      lpmTemplate.Flags(),
			MaxEntries: lpmTemplate.MaxEntries(),
			KeySize:    lpmTemplate.KeySize(),
			ValueSize:  lpmTemplate.ValueSize(),
			Entries: []rustLpmMapEntry{{
				Key: rustBpfLpmKey{
					PrefixLen: lpmKey.PrefixLen,
					Data:      lpmKey.Data,
				},
				Value: 1,
			}},
		}},
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

func benchmarkRoutingEntriesWithLpm() ([]uint32, []bpfMatchSet) {
	keys := []uint32{0, 1}
	values := []bpfMatchSet{
		{Type: uint8(consts.MatchType_IpSet), Outbound: uint8(consts.OutboundBlock)},
		{Type: uint8(consts.MatchType_Fallback), Outbound: uint8(consts.OutboundDirect)},
	}
	values[0].Value[0] = 0
	return keys, values
}

func benchmarkDomainRoutingEntry() ([4]uint32, bpfDomainRouting) {
	var value bpfDomainRouting
	value.Bitmap[0] = 0x1
	return [4]uint32{0, 0, 0xffff, 0xcb00710a}, value
}

func benchmarkLpmMapSpec() *ebpf.MapSpec {
	return &ebpf.MapSpec{
		Name:       "dae_lpm_bench",
		Type:       ebpf.LPMTrie,
		Flags:      unix.BPF_F_NO_PREALLOC,
		MaxEntries: 2048,
		KeySize:    uint32(unsafe.Sizeof(_bpfLpmKey{})),
		ValueSize:  uint32(unsafe.Sizeof(uint32(0))),
	}
}

func newBenchmarkLpmTemplateMap(b *testing.B) *ebpf.Map {
	b.Helper()
	m, err := ebpf.NewMap(benchmarkLpmMapSpec())
	if err != nil {
		b.Skipf("LPM template benchmark requires BPF map create permission: %v", err)
	}
	return m
}

func newBenchmarkLpmArrayMap(b *testing.B) *ebpf.Map {
	b.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "dae_lpm_array_bench",
		Type:       ebpf.ArrayOfMaps,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1024,
		InnerMap:   benchmarkLpmMapSpec(),
	})
	if err != nil {
		b.Skipf("LPM array benchmark requires BPF map create permission: %v", err)
	}
	return m
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

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
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

var routingNativePlanBenchmarkSink uint64

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
	_, values := benchmarkRoutingEntriesWithFallback()
	request := rustRoutingMapApplyRequest{
		RoutingMapID:   mapID,
		LpmArrayMapID:  mapID,
		LpmEntries:     []rustLpmArrayMapEntry{},
		LpmMaps:        []rustLpmMapBuildSpec{},
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

func BenchmarkRoutingMapRustInprocessUpdate(b *testing.B) {
	if !rustInprocessRoutingMapAvailable() {
		b.Skip("Rust in-process routing map writer is not enabled")
	}
	m := newBenchmarkRoutingMap(b)
	defer m.Close()
	mapID, err := bpfMapID(m)
	if err != nil {
		b.Fatal(err)
	}
	_, values := benchmarkRoutingEntriesWithFallback()
	request := rustRoutingMapApplyRequest{
		RoutingMapID:   mapID,
		LpmArrayMapID:  mapID,
		LpmEntries:     []rustLpmArrayMapEntry{},
		LpmMaps:        []rustLpmMapBuildSpec{},
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
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := applyKernelRoutingMapsViaRustInprocess(request); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRoutingMapRustOwnedInprocessUpdate(b *testing.B) {
	if !rustInprocessRoutingMapAvailable() {
		b.Skip("Rust in-process routing map owner is not enabled")
	}
	m := newBenchmarkRoutingMap(b)
	defer m.Close()
	mapID, err := bpfMapID(m)
	if err != nil {
		b.Fatal(err)
	}
	_, values := benchmarkRoutingEntriesWithFallback()
	request := rustRoutingMapApplyRequest{
		RoutingMapID:   mapID,
		LpmArrayMapID:  mapID,
		LpmEntries:     []rustLpmArrayMapEntry{},
		LpmMaps:        []rustLpmMapBuildSpec{},
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
	if err := applyKernelRoutingMapsViaRustOwnedInprocess(request); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := applyKernelRoutingMapsViaRustOwnedInprocess(request); err != nil {
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

func BenchmarkRoutingMapRustInprocessUpdateWithLpmBuild(b *testing.B) {
	if !rustInprocessRoutingMapAvailable() {
		b.Skip("Rust in-process routing map writer is not enabled")
	}
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
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := applyKernelRoutingMapsViaRustInprocess(request); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRoutingMapRustOwnedInprocessUpdateWithLpmBuild(b *testing.B) {
	if !rustInprocessRoutingMapAvailable() {
		b.Skip("Rust in-process routing map owner is not enabled")
	}
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
	if err := applyKernelRoutingMapsViaRustOwnedInprocess(request); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := applyKernelRoutingMapsViaRustOwnedInprocess(request); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRoutingNativePlanGoBuildWithLpm(b *testing.B) {
	rules := benchmarkRoutingNativePlanRules()
	var checksum uint64
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		routingEntries, lpmMaps := buildBenchmarkRoutingNativePlan(rules)
		checksum ^= benchmarkRoutingNativePlanChecksum(routingEntries, lpmMaps)
	}
	routingNativePlanBenchmarkSink = checksum
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

func BenchmarkDomainRoutingMapRustReloadClear(b *testing.B) {
	helperPath := strings.TrimSpace(os.Getenv(rustBpfLoaderHelperEnv))
	if helperPath == "" {
		b.Skipf("%s is not set", rustBpfLoaderHelperEnv)
	}
	b.Setenv(rustBpfLoaderHelperEnv, helperPath)
	m := newBenchmarkDomainRoutingMap(b)
	defer m.Close()
	key, value := benchmarkDomainRoutingEntry()
	keys := [][4]uint32{
		key,
		{0, 0, 0xffff, 0xcb00710b},
	}
	core := &controlPlaneCore{
		bpf: &bpfObjects{
			bpfMaps: bpfMaps{
				DomainRoutingMap: m,
			},
		},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		for _, key := range keys {
			if err := m.Update(key, value, ebpf.UpdateAny); err != nil {
				b.Fatal(err)
			}
		}
		b.StartTimer()
		if err := core.clearDomainRoutingMapForReload(); err != nil {
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

func BenchmarkDomainRoutingMapRustInprocessUpdate(b *testing.B) {
	if !rustInprocessRoutingMapAvailable() {
		b.Skip("Rust in-process domain routing map writer is not enabled")
	}
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
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := updateDomainRoutingMapViaRustInprocess(request); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDomainRoutingMapRustOwnedInprocessDuplicate(b *testing.B) {
	if !rustInprocessRoutingMapAvailable() {
		b.Skip("Rust in-process domain routing map owner is not enabled")
	}
	m := newBenchmarkDomainRoutingMap(b)
	defer m.Close()
	key, value := benchmarkDomainRoutingEntry()
	owner := newRustDomainRoutingOwner()
	defer owner.Close()
	snapshot := domainRoutingOwnerSnapshot{
		bitmap: value,
		ips: map[[4]uint32]struct{}{
			key: {},
		},
	}
	if err := owner.Update(m, "bench-owner", snapshot); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := owner.Update(m, "bench-owner", snapshot); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDomainRoutingMapRustOwnedInprocessToggle(b *testing.B) {
	if !rustInprocessRoutingMapAvailable() {
		b.Skip("Rust in-process domain routing map owner is not enabled")
	}
	m := newBenchmarkDomainRoutingMap(b)
	defer m.Close()
	key, value := benchmarkDomainRoutingEntry()
	owner := newRustDomainRoutingOwner()
	defer owner.Close()
	snapshots := [2]domainRoutingOwnerSnapshot{
		{
			bitmap: value,
			ips: map[[4]uint32]struct{}{
				key: {},
			},
		},
		{
			bitmap: bpfDomainRouting{Bitmap: [32]uint32{0x3}},
			ips: map[[4]uint32]struct{}{
				key: {},
			},
		},
	}
	if err := owner.Update(m, "bench-owner", snapshots[0]); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := owner.Update(m, "bench-owner", snapshots[i%2]); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDomainRoutingMapRustOwnedDnsEventDuplicate(b *testing.B) {
	if !rustInprocessRoutingMapAvailable() {
		b.Skip("Rust in-process domain routing DNS event owner is not enabled")
	}
	m := newBenchmarkDomainRoutingMap(b)
	defer m.Close()
	_, value := benchmarkDomainRoutingEntry()
	owner := newRustDomainRoutingOwner()
	defer owner.Close()
	cache := benchmarkDomainRoutingDnsCache("bench-owner", value, netip.MustParseAddr("203.0.113.10"))
	if err := owner.UpdateDnsCacheEvent(m, cache); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := owner.UpdateDnsCacheEvent(m, cache); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDomainRoutingMapRustOwnedDnsEventToggle(b *testing.B) {
	if !rustInprocessRoutingMapAvailable() {
		b.Skip("Rust in-process domain routing DNS event owner is not enabled")
	}
	m := newBenchmarkDomainRoutingMap(b)
	defer m.Close()
	_, value := benchmarkDomainRoutingEntry()
	alternate := bpfDomainRouting{Bitmap: [32]uint32{0x3}}
	owner := newRustDomainRoutingOwner()
	defer owner.Close()
	caches := [2]*DnsCache{
		benchmarkDomainRoutingDnsCache("bench-owner", value, netip.MustParseAddr("203.0.113.10")),
		benchmarkDomainRoutingDnsCache("bench-owner", alternate, netip.MustParseAddr("203.0.113.10")),
	}
	if err := owner.UpdateDnsCacheEvent(m, caches[0]); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := owner.UpdateDnsCacheEvent(m, caches[i%2]); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDomainRoutingMapRustInprocessReloadClear(b *testing.B) {
	if !rustInprocessRoutingMapAvailable() {
		b.Skip("Rust in-process domain routing map writer is not enabled")
	}
	m := newBenchmarkDomainRoutingMap(b)
	defer m.Close()
	key, value := benchmarkDomainRoutingEntry()
	keys := [][4]uint32{
		key,
		{0, 0, 0xffff, 0xcb00710b},
	}
	core := &controlPlaneCore{
		bpf: &bpfObjects{
			bpfMaps: bpfMaps{
				DomainRoutingMap: m,
			},
		},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		for _, key := range keys {
			if err := m.Update(key, value, ebpf.UpdateAny); err != nil {
				b.Fatal(err)
			}
		}
		b.StartTimer()
		if err := core.clearDomainRoutingMapForReload(); err != nil {
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

func benchmarkRoutingEntriesWithFallback() ([]uint32, []bpfMatchSet) {
	keys := []uint32{0, 1}
	values := []bpfMatchSet{
		{Type: uint8(consts.MatchType_Port), Outbound: uint8(consts.OutboundBlock)},
		{Type: uint8(consts.MatchType_Fallback), Outbound: uint8(consts.OutboundDirect)},
	}
	values[0].Value[0] = 0xbb
	values[0].Value[1] = 0x01
	values[0].Value[2] = 0xbb
	values[0].Value[3] = 0x01
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

type benchmarkRoutingNativeRule struct {
	matchType uint8
	outbound  uint8
	not       bool
	mark      uint32
	must      bool
	prefixes  []netip.Prefix
	ports     [][2]uint16
	value     uint8
	macs      [][6]byte
}

type benchmarkRoutingNativeLpmMapSpec struct {
	index      uint32
	flags      uint32
	maxEntries uint32
	keySize    uint32
	valueSize  uint32
	entries    []benchmarkRoutingNativeLpmMapEntry
}

type benchmarkRoutingNativeLpmMapEntry struct {
	key   _bpfLpmKey
	value uint32
}

func benchmarkRoutingNativePlanRules() []benchmarkRoutingNativeRule {
	return []benchmarkRoutingNativeRule{
		{
			matchType: uint8(consts.MatchType_IpSet),
			outbound:  uint8(consts.OutboundBlock),
			prefixes: []netip.Prefix{
				netip.MustParsePrefix("203.0.113.0/24"),
				netip.MustParsePrefix("2001:db8::/48"),
			},
		},
		{
			matchType: uint8(consts.MatchType_SourceIpSet),
			outbound:  uint8(consts.OutboundLogicalAnd),
			prefixes: []netip.Prefix{
				netip.MustParsePrefix("198.51.100.0/24"),
				netip.MustParsePrefix("2001:db8:1::/48"),
			},
		},
		{
			matchType: uint8(consts.MatchType_Port),
			outbound:  uint8(consts.OutboundDirect),
			ports: [][2]uint16{
				{80, 80},
				{443, 443},
				{8443, 8443},
			},
		},
		{
			matchType: uint8(consts.MatchType_L4Proto),
			outbound:  uint8(consts.OutboundDirect),
			value:     uint8(consts.L4ProtoType_TCP),
		},
		{
			matchType: uint8(consts.MatchType_IpVersion),
			outbound:  uint8(consts.OutboundDirect),
			value:     uint8(consts.IpVersion_4),
		},
		{
			matchType: uint8(consts.MatchType_Mac),
			outbound:  uint8(consts.OutboundUserDefinedMin),
			mark:      consts.TproxyMark,
			must:      true,
			macs:      [][6]byte{{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}},
		},
	}
}

func buildBenchmarkRoutingNativePlan(rules []benchmarkRoutingNativeRule) ([]bpfMatchSet, []benchmarkRoutingNativeLpmMapSpec) {
	routingEntries := make([]bpfMatchSet, 0, len(rules)+3)
	lpmMaps := make([]benchmarkRoutingNativeLpmMapSpec, 0, 3)
	for _, rule := range rules {
		switch consts.MatchType(rule.matchType) {
		case consts.MatchType_IpSet, consts.MatchType_SourceIpSet:
			lpmIndex := uint32(len(lpmMaps))
			entries := make([]benchmarkRoutingNativeLpmMapEntry, 0, len(rule.prefixes))
			for _, prefix := range rule.prefixes {
				entries = append(entries, benchmarkRoutingNativeLpmMapEntry{
					key:   cidrToBpfLpmKey(prefix),
					value: 1,
				})
			}
			lpmMaps = append(lpmMaps, benchmarkRoutingNativeLpmMapSpec{
				index:      lpmIndex,
				flags:      unix.BPF_F_NO_PREALLOC,
				maxEntries: 2048000,
				keySize:    uint32(unsafe.Sizeof(_bpfLpmKey{})),
				valueSize:  uint32(unsafe.Sizeof(uint32(0))),
				entries:    entries,
			})
			matchSet := benchmarkRoutingNativeBaseMatchSet(rule)
			binary.LittleEndian.PutUint32(matchSet.Value[:], lpmIndex)
			routingEntries = append(routingEntries, matchSet)
		case consts.MatchType_Mac:
			lpmIndex := uint32(len(lpmMaps))
			entries := make([]benchmarkRoutingNativeLpmMapEntry, 0, len(rule.macs))
			for _, mac := range rule.macs {
				entries = append(entries, benchmarkRoutingNativeLpmMapEntry{
					key:   benchmarkMacToBpfLpmKey(mac),
					value: 1,
				})
			}
			lpmMaps = append(lpmMaps, benchmarkRoutingNativeLpmMapSpec{
				index:      lpmIndex,
				flags:      unix.BPF_F_NO_PREALLOC,
				maxEntries: 2048000,
				keySize:    uint32(unsafe.Sizeof(_bpfLpmKey{})),
				valueSize:  uint32(unsafe.Sizeof(uint32(0))),
				entries:    entries,
			})
			matchSet := benchmarkRoutingNativeBaseMatchSet(rule)
			binary.LittleEndian.PutUint32(matchSet.Value[:], lpmIndex)
			routingEntries = append(routingEntries, matchSet)
		case consts.MatchType_Port, consts.MatchType_SourcePort:
			for index, ports := range rule.ports {
				matchSet := benchmarkRoutingNativeBaseMatchSet(rule)
				if index+1 != len(rule.ports) {
					matchSet.Outbound = uint8(consts.OutboundLogicalOr)
				}
				binary.LittleEndian.PutUint16(matchSet.Value[:2], ports[0])
				binary.LittleEndian.PutUint16(matchSet.Value[2:4], ports[1])
				routingEntries = append(routingEntries, matchSet)
			}
		case consts.MatchType_L4Proto, consts.MatchType_IpVersion, consts.MatchType_Dscp:
			matchSet := benchmarkRoutingNativeBaseMatchSet(rule)
			matchSet.Value[0] = rule.value
			routingEntries = append(routingEntries, matchSet)
		default:
			routingEntries = append(routingEntries, benchmarkRoutingNativeBaseMatchSet(rule))
		}
	}
	routingEntries = append(routingEntries, bpfMatchSet{
		Type:     uint8(consts.MatchType_Fallback),
		Outbound: uint8(consts.OutboundDirect),
	})
	return routingEntries, lpmMaps
}

func benchmarkRoutingNativeBaseMatchSet(rule benchmarkRoutingNativeRule) bpfMatchSet {
	return bpfMatchSet{
		Type:     rule.matchType,
		Not:      rule.not,
		Outbound: rule.outbound,
		Must:     rule.must,
		Mark:     rule.mark,
	}
}

func benchmarkMacToBpfLpmKey(mac [6]byte) _bpfLpmKey {
	var addr16 [16]byte
	copy(addr16[10:], mac[:])
	return cidrToBpfLpmKey(netip.PrefixFrom(netip.AddrFrom16(addr16), 128))
}

func benchmarkRoutingNativePlanChecksum(routingEntries []bpfMatchSet, lpmMaps []benchmarkRoutingNativeLpmMapSpec) uint64 {
	out := uint64(len(routingEntries)) ^ (uint64(len(lpmMaps)) << 32)
	for _, entry := range routingEntries {
		out = out*1315423911 + uint64(entry.Type)
		out = out*1315423911 + uint64(entry.Outbound)
		out = out*1315423911 + uint64(entry.Mark)
		if entry.Not {
			out ^= 0x100
		}
		if entry.Must {
			out ^= 0x200
		}
		for _, value := range entry.Value {
			out = out*1315423911 + uint64(value)
		}
	}
	for _, spec := range lpmMaps {
		out = out*1315423911 + uint64(spec.index)
		out = out*1315423911 + uint64(spec.flags)
		out = out*1315423911 + uint64(spec.maxEntries)
		out = out*1315423911 + uint64(spec.keySize)
		out = out*1315423911 + uint64(spec.valueSize)
		for _, entry := range spec.entries {
			out = out*1315423911 + uint64(entry.key.PrefixLen)
			out = out*1315423911 + uint64(entry.value)
			for _, word := range entry.key.Data {
				out = out*1315423911 + uint64(word)
			}
		}
	}
	return out
}

func benchmarkDomainRoutingEntry() ([4]uint32, bpfDomainRouting) {
	var value bpfDomainRouting
	value.Bitmap[0] = 0x1
	return [4]uint32{0, 0, 0xffff, 0xcb00710a}, value
}

func benchmarkDomainRoutingDnsCache(ownerKey string, bitmap bpfDomainRouting, ips ...netip.Addr) *DnsCache {
	return &DnsCache{
		RouteOwnerKey: ownerKey,
		DomainBitmap:  append([]uint32(nil), bitmap.Bitmap[:]...),
		IPs:           append([]netip.Addr(nil), ips...),
		HasAnyIP:      len(ips) > 0,
	}
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

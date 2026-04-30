/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func testLoaderNetns(t *testing.T) *DaeNetns {
	t.Helper()

	hostNs, err := netns.Get()
	if err != nil {
		t.Fatalf("netns.Get: %v", err)
	}
	t.Cleanup(func() { _ = hostNs.Close() })

	links, err := netlink.LinkList()
	if err != nil {
		t.Fatalf("netlink.LinkList: %v", err)
	}
	var selected netlink.Link
	for _, link := range links {
		if len(link.Attrs().HardwareAddr) >= 6 {
			selected = link
			break
		}
	}
	if selected == nil {
		t.Fatal("no link with hardware address available for BPF loader test")
	}

	return &DaeNetns{
		log:      logrus.New(),
		dae0:     selected,
		dae0peer: selected,
		daeNs:    hostNs,
	}
}

func testLoadBpfObjects(t *testing.T, pinPath string) *bpfObjects {
	t.Helper()

	objs := new(bpfObjects)
	if err := fullLoadBpfObjects(logrus.New(), testLoaderNetns(t), objs, &loadBpfOptions{
		PinPath:             pinPath,
		BigEndianTproxyPort: uint32(common.Htons(12345)),
		CollectionOptions: &ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{
				PinPath: pinPath,
			},
			Programs: ebpf.ProgramOptions{
				LogLevel:     ebpf.LogLevelBranch,
				LogSizeStart: 64 * 1024 * 10,
			},
		},
	}); err != nil {
		t.Fatalf("fullLoadBpfObjects(%s): %v", pinPath, err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	return objs
}

func TestFullLoadBpfObjectsPinnedReuse(t *testing.T) {
	pinPath, err := os.MkdirTemp("/sys/fs/bpf", "dae-loader-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(pinPath)

	first := testLoadBpfObjects(t, pinPath)
	if _, err := os.Stat(filepath.Join(pinPath, "routing_tuples_map")); err != nil {
		t.Fatalf("expected pinned routing_tuples_map: %v", err)
	}

	second := testLoadBpfObjects(t, pinPath)
	if first.RoutingTuplesMap.Type() != second.RoutingTuplesMap.Type() {
		t.Fatalf("routing_tuples_map type mismatch: %v vs %v", first.RoutingTuplesMap.Type(), second.RoutingTuplesMap.Type())
	}
}

func TestFullLoadBpfObjectsDeletesIncompatiblePinnedMap(t *testing.T) {
	pinPath, err := os.MkdirTemp("/sys/fs/bpf", "dae-loader-incompat-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(pinPath)

	incompatibleMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "routing_tuples_map",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	if err != nil {
		t.Fatalf("NewMap: %v", err)
	}
	defer incompatibleMap.Close()

	pinnedPath := filepath.Join(pinPath, "routing_tuples_map")
	if err := incompatibleMap.Pin(pinnedPath); err != nil {
		t.Fatalf("Pin: %v", err)
	}

	objs := testLoadBpfObjects(t, pinPath)

	reloadedMap, err := ebpf.LoadPinnedMap(pinnedPath, nil)
	if err != nil {
		t.Fatalf("LoadPinnedMap: %v", err)
	}
	defer reloadedMap.Close()

	if reloadedMap.Type() != objs.RoutingTuplesMap.Type() {
		t.Fatalf("expected pinned map type %v after reload, got %v", objs.RoutingTuplesMap.Type(), reloadedMap.Type())
	}
}

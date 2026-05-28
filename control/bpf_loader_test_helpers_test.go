/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func ensureMemlock(t *testing.T) {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("skipping loader test: RemoveMemlock failed: %v", err)
	}
}

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

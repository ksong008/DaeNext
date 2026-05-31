//go:build linux && cgo && rust_inprocess

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestRustOutboundConnectivityOwnerUpdatesMap(t *testing.T) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "dae_conn_owner_test",
		Type:       ebpf.Hash,
		KeySize:    3,
		ValueSize:  4,
		MaxEntries: 1024,
	})
	if err != nil {
		t.Skipf("connectivity owner test requires BPF map create permission: %v", err)
	}
	defer m.Close()

	owner := newRustOutboundConnectivityOwner()
	defer owner.Close()
	if err := owner.Update(m, 2, 6, 4, true, true, false); err != nil {
		t.Fatal(err)
	}
	var alive uint32
	if err := m.Lookup(bpfOutboundConnectivityQuery{
		Outbound:  2,
		L4proto:   6,
		Ipversion: 4,
	}, &alive); err != nil {
		t.Fatalf("lookup connectivity map: %v", err)
	}
	if alive != 1 {
		t.Fatalf("alive=%d, want 1", alive)
	}
	if err := owner.Update(m, 2, 6, 4, false, false, false); err != nil {
		t.Fatal(err)
	}
	if err := m.Lookup(bpfOutboundConnectivityQuery{
		Outbound:  2,
		L4proto:   6,
		Ipversion: 4,
	}, &alive); err != nil {
		t.Fatalf("lookup updated connectivity map: %v", err)
	}
	if alive != 0 {
		t.Fatalf("alive=%d, want 0", alive)
	}
}

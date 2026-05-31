//go:build !linux || !cgo || !rust_inprocess

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type rustOutboundConnectivityOwner struct{}

type rustOutboundConnectivityApplyReport struct {
	mapID        uint32
	mapChanged   bool
	accepted     bool
	changed      bool
	skipped      bool
	entries      int
	stateEntries int
}

func newRustOutboundConnectivityOwner() *rustOutboundConnectivityOwner {
	return &rustOutboundConnectivityOwner{}
}

func (o *rustOutboundConnectivityOwner) Close() error {
	return nil
}

func (o *rustOutboundConnectivityOwner) Update(m *ebpf.Map, outbound, l4proto, ipversion uint8, alive, isInit, dryrun bool) error {
	return fmt.Errorf("Rust in-process outbound connectivity owner is not enabled")
}

func (o *rustOutboundConnectivityOwner) ApplyEvent(m *ebpf.Map, outbound, l4proto, ipversion uint8, alive, isInit, dryrun bool) (rustOutboundConnectivityApplyReport, error) {
	return rustOutboundConnectivityApplyReport{}, fmt.Errorf("Rust in-process outbound connectivity owner is not enabled")
}

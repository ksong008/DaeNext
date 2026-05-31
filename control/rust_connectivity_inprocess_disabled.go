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

func newRustOutboundConnectivityOwner() *rustOutboundConnectivityOwner {
	return &rustOutboundConnectivityOwner{}
}

func (o *rustOutboundConnectivityOwner) Close() error {
	return nil
}

func (o *rustOutboundConnectivityOwner) Update(m *ebpf.Map, outbound, l4proto, ipversion uint8, alive, isInit, dryrun bool) error {
	return fmt.Errorf("Rust in-process outbound connectivity owner is not enabled")
}

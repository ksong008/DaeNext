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

type rustDomainRoutingOwner struct{}

func rustInprocessRoutingMapAvailable() bool {
	return false
}

func applyKernelRoutingMapsViaRustInprocess(request rustRoutingMapApplyRequest) error {
	return fmt.Errorf("Rust in-process routing map writer is not enabled")
}

func applyKernelRoutingMapsViaRustOwnedInprocess(request rustRoutingMapApplyRequest) error {
	return fmt.Errorf("Rust in-process routing map owner is not enabled")
}

func updateDomainRoutingMapViaRustInprocess(request rustDomainRoutingMapApplyRequest) error {
	return fmt.Errorf("Rust in-process domain routing map writer is not enabled")
}

func newRustDomainRoutingOwner() *rustDomainRoutingOwner {
	return &rustDomainRoutingOwner{}
}

func (o *rustDomainRoutingOwner) Close() error {
	return nil
}

func (o *rustDomainRoutingOwner) Update(m *ebpf.Map, ownerKey string, snapshot domainRoutingOwnerSnapshot) error {
	return fmt.Errorf("Rust in-process domain routing owner is not enabled")
}

func (o *rustDomainRoutingOwner) PrepareReload(m *ebpf.Map, keys [][4]uint32) error {
	return fmt.Errorf("Rust in-process domain routing reload owner is not enabled")
}

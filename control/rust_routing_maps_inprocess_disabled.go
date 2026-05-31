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

type rustReloadDnsCachePlan struct {
	dnsConfigUnchanged    bool
	bpfPresent            bool
	restoreCache          bool
	clearDomainRoutingMap bool
	snapshotEntries       int
}

type RustOwnedRuntimeStateReport struct {
	SchemaVersion               uint32
	RustOwnedRuntime            bool
	ReloadStateAvailable        bool
	BackendStateAvailable       bool
	RoutingOwnerAvailable       bool
	DomainOwnerAvailable        bool
	ConnectivityOwnerAvailable  bool
	ActiveHandoffAvailable      bool
	APICompatible               bool
	ReadyForDefaultControlPlane bool
}

func rustInprocessRoutingMapAvailable() bool {
	return false
}

func BuildRustOwnedRuntimeStateReport() (RustOwnedRuntimeStateReport, error) {
	return RustOwnedRuntimeStateReport{
		SchemaVersion: 1,
		APICompatible: true,
	}, nil
}

func RustOwnedReloadDnsCacheRestoreAllowed(dnsConfigUnchanged bool) bool {
	return dnsConfigUnchanged
}

func rustReloadDnsCachePlanForReload(dnsConfigUnchanged bool, bpfPresent bool, snapshotEntries int) (rustReloadDnsCachePlan, error) {
	if snapshotEntries < 0 {
		snapshotEntries = 0
	}
	return rustReloadDnsCachePlan{
		dnsConfigUnchanged:    dnsConfigUnchanged,
		bpfPresent:            bpfPresent,
		restoreCache:          dnsConfigUnchanged && snapshotEntries > 0,
		clearDomainRoutingMap: bpfPresent,
		snapshotEntries:       snapshotEntries,
	}, nil
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

func (o *rustDomainRoutingOwner) UpdateDnsCacheEvent(m *ebpf.Map, event domainRoutingDnsEvent) error {
	return fmt.Errorf("Rust in-process domain routing DNS event owner is not enabled")
}

func (o *rustDomainRoutingOwner) RemoveDnsCacheEvent(m *ebpf.Map, ownerKey string) error {
	return fmt.Errorf("Rust in-process domain routing DNS event owner is not enabled")
}

func (o *rustDomainRoutingOwner) PrepareReload(m *ebpf.Map, keys [][4]uint32) error {
	return fmt.Errorf("Rust in-process domain routing reload owner is not enabled")
}

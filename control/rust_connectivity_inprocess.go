//go:build linux && cgo && rust_inprocess

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

/*
#cgo linux LDFLAGS: ${SRCDIR}/../rust/target/release/libdae_control.a -ldl -lpthread -lm
#include <stdint.h>
#include <stdlib.h>

typedef struct dae_control_outbound_connectivity_owner dae_control_outbound_connectivity_owner;

typedef struct {
	uint8_t outbound;
	uint8_t l4proto;
	uint8_t ipversion;
	uint8_t alive;
	uint8_t is_init;
	uint8_t dryrun;
	uint8_t padding[2];
} dae_control_connectivity_event;

typedef struct {
	uint32_t map_id;
	uint8_t map_id_changed;
	uint8_t accepted;
	uint8_t changed;
	uint8_t skipped;
	size_t entries_updated;
	size_t len;
} dae_control_outbound_connectivity_owner_apply_report;

extern dae_control_outbound_connectivity_owner *dae_control_outbound_connectivity_owner_new(void);
extern void dae_control_outbound_connectivity_owner_free(dae_control_outbound_connectivity_owner *owner);
extern int32_t dae_control_outbound_connectivity_owner_apply_event_by_id(
	dae_control_outbound_connectivity_owner *owner,
	uint32_t map_id,
	dae_control_connectivity_event event,
	dae_control_outbound_connectivity_owner_apply_report *report
);
*/
import "C"

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
)

type rustOutboundConnectivityOwner struct {
	mu     sync.Mutex
	ptr    *C.dae_control_outbound_connectivity_owner
	mapPtr *ebpf.Map
	mapID  uint32
}

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
	if o == nil {
		return nil
	}
	o.mu.Lock()
	ptr := o.ptr
	o.ptr = nil
	o.mapPtr = nil
	o.mapID = 0
	o.mu.Unlock()
	if ptr != nil {
		C.dae_control_outbound_connectivity_owner_free(ptr)
	}
	return nil
}

func (o *rustOutboundConnectivityOwner) ensureLocked() error {
	if o.ptr != nil {
		return nil
	}
	o.ptr = C.dae_control_outbound_connectivity_owner_new()
	if o.ptr == nil {
		return fmt.Errorf("create Rust in-process outbound connectivity owner")
	}
	return nil
}

func (o *rustOutboundConnectivityOwner) mapIDLocked(m *ebpf.Map) (uint32, error) {
	if m == nil {
		return 0, nil
	}
	if o.mapPtr == m && o.mapID != 0 {
		return o.mapID, nil
	}
	mapID, err := bpfMapID(m)
	if err != nil {
		return 0, err
	}
	o.mapPtr = m
	o.mapID = mapID
	return mapID, nil
}

func (o *rustOutboundConnectivityOwner) Update(m *ebpf.Map, outbound, l4proto, ipversion uint8, alive, isInit, dryrun bool) error {
	_, err := o.ApplyEvent(m, outbound, l4proto, ipversion, alive, isInit, dryrun)
	return err
}

func (o *rustOutboundConnectivityOwner) ApplyEvent(m *ebpf.Map, outbound, l4proto, ipversion uint8, alive, isInit, dryrun bool) (rustOutboundConnectivityApplyReport, error) {
	if m == nil {
		return rustOutboundConnectivityApplyReport{}, nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	mapID, err := o.mapIDLocked(m)
	if err != nil {
		return rustOutboundConnectivityApplyReport{}, err
	}
	if err := o.ensureLocked(); err != nil {
		return rustOutboundConnectivityApplyReport{}, err
	}
	event := C.dae_control_connectivity_event{
		outbound:  C.uint8_t(outbound),
		l4proto:   C.uint8_t(l4proto),
		ipversion: C.uint8_t(ipversion),
		alive:     cUint8Bool(alive),
		is_init:   cUint8Bool(isInit),
		dryrun:    cUint8Bool(dryrun),
	}
	var report C.dae_control_outbound_connectivity_owner_apply_report
	rc := C.dae_control_outbound_connectivity_owner_apply_event_by_id(
		o.ptr,
		C.uint32_t(mapID),
		event,
		&report,
	)
	if rc != 0 {
		return rustOutboundConnectivityApplyReport{}, fmt.Errorf("Rust in-process outbound connectivity owner failed: %s", rustInprocessLastError())
	}
	return rustOutboundConnectivityApplyReport{
		mapID:        uint32(report.map_id),
		mapChanged:   report.map_id_changed != 0,
		accepted:     report.accepted != 0,
		changed:      report.changed != 0,
		skipped:      report.skipped != 0,
		entries:      int(report.entries_updated),
		stateEntries: int(report.len),
	}, nil
}

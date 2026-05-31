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

typedef struct {
	uint32_t prefix_len;
	uint32_t data[4];
} dae_control_bpf_lpm_key;

typedef struct {
	uint8_t value[16];
	uint8_t not_;
	uint8_t kind;
	uint8_t outbound;
	uint8_t must;
	uint32_t mark;
} dae_control_bpf_match_set;

typedef struct {
	uint32_t index;
	dae_control_bpf_match_set value;
} dae_control_routing_map_entry;

typedef struct {
	dae_control_bpf_lpm_key key;
	uint32_t value;
} dae_control_lpm_map_entry;

typedef struct {
	uint32_t index;
	uint32_t flags;
	uint32_t max_entries;
	uint32_t key_size;
	uint32_t value_size;
	const dae_control_lpm_map_entry *entries;
	size_t entries_len;
} dae_control_lpm_map_build_spec;

typedef struct {
	uint32_t key[4];
	uint32_t bitmap[32];
} dae_control_domain_routing_update;

typedef struct dae_control_routing_owner dae_control_routing_owner;

typedef struct {
	uint32_t routing_map_id;
	uint32_t lpm_array_map_id;
	uint8_t map_changed;
	uint8_t plan_changed;
	uint8_t skipped;
	uint8_t padding;
	uint64_t checksum;
	size_t routing_entries_updated;
	size_t lpm_maps_created;
} dae_control_routing_owner_apply_report;

extern uint32_t dae_control_ffi_abi_version(void);
extern const char *dae_control_last_error_message(void);
extern dae_control_routing_owner *dae_control_routing_owner_new(void);
extern void dae_control_routing_owner_free(dae_control_routing_owner *owner);
extern int32_t dae_control_apply_routing_maps_with_lpm_build_by_id(
	uint32_t routing_map_id,
	uint32_t lpm_array_map_id,
	const dae_control_routing_map_entry *routing_entries,
	size_t routing_entries_len,
	const dae_control_lpm_map_build_spec *lpm_maps,
	size_t lpm_maps_len
);
extern int32_t dae_control_apply_domain_routing_map_by_id(
	uint32_t map_id,
	const dae_control_domain_routing_update *updates,
	size_t updates_len,
	const uint32_t (*deletes)[4],
	size_t deletes_len
);
extern int32_t dae_control_routing_owner_apply_snapshot_by_id(
	dae_control_routing_owner *owner,
	uint32_t routing_map_id,
	uint32_t lpm_array_map_id,
	const dae_control_routing_map_entry *routing_entries,
	size_t routing_entries_len,
	const dae_control_lpm_map_build_spec *lpm_maps,
	size_t lpm_maps_len,
	dae_control_routing_owner_apply_report *report
);
*/
import "C"

import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

var rustRoutingOwnerState struct {
	sync.Mutex
	ptr *C.dae_control_routing_owner
}

func rustInprocessRoutingMapAvailable() bool {
	return C.dae_control_ffi_abi_version() == 1
}

func applyKernelRoutingMapsViaRustOwnedInprocess(request rustRoutingMapApplyRequest) error {
	if len(request.LpmEntries) != 0 {
		return fmt.Errorf("Rust in-process routing map owner does not accept prebuilt LPM entries")
	}
	routingEntries := cRoutingMapEntries(request.RoutingEntries)
	lpmMaps, freeLpmMaps, err := cLpmMapBuildSpecs(request.LpmMaps)
	if err != nil {
		return err
	}
	defer freeLpmMaps()

	var routingPtr *C.dae_control_routing_map_entry
	if len(routingEntries) > 0 {
		routingPtr = &routingEntries[0]
	}
	rustRoutingOwnerState.Lock()
	defer rustRoutingOwnerState.Unlock()
	if rustRoutingOwnerState.ptr == nil {
		rustRoutingOwnerState.ptr = C.dae_control_routing_owner_new()
		if rustRoutingOwnerState.ptr == nil {
			return fmt.Errorf("create Rust in-process routing map owner")
		}
	}
	var report C.dae_control_routing_owner_apply_report
	rc := C.dae_control_routing_owner_apply_snapshot_by_id(
		rustRoutingOwnerState.ptr,
		C.uint32_t(request.RoutingMapID),
		C.uint32_t(request.LpmArrayMapID),
		routingPtr,
		C.size_t(len(routingEntries)),
		lpmMaps,
		C.size_t(len(request.LpmMaps)),
		&report,
	)
	runtime.KeepAlive(routingEntries)
	if rc != 0 {
		return fmt.Errorf("Rust in-process routing map owner failed: %s", rustInprocessLastError())
	}
	return nil
}

func applyKernelRoutingMapsViaRustInprocess(request rustRoutingMapApplyRequest) error {
	if len(request.LpmEntries) != 0 {
		return fmt.Errorf("Rust in-process routing map writer does not accept prebuilt LPM entries")
	}
	routingEntries := cRoutingMapEntries(request.RoutingEntries)
	lpmMaps, freeLpmMaps, err := cLpmMapBuildSpecs(request.LpmMaps)
	if err != nil {
		return err
	}
	defer freeLpmMaps()

	var routingPtr *C.dae_control_routing_map_entry
	if len(routingEntries) > 0 {
		routingPtr = &routingEntries[0]
	}
	rc := C.dae_control_apply_routing_maps_with_lpm_build_by_id(
		C.uint32_t(request.RoutingMapID),
		C.uint32_t(request.LpmArrayMapID),
		routingPtr,
		C.size_t(len(routingEntries)),
		lpmMaps,
		C.size_t(len(request.LpmMaps)),
	)
	runtime.KeepAlive(routingEntries)
	if rc != 0 {
		return fmt.Errorf("Rust in-process routing map writer failed: %s", rustInprocessLastError())
	}
	return nil
}

func updateDomainRoutingMapViaRustInprocess(request rustDomainRoutingMapApplyRequest) error {
	updates := make([]C.dae_control_domain_routing_update, len(request.Updates))
	for i, update := range request.Updates {
		for j, word := range update.Key {
			updates[i].key[j] = C.uint32_t(word)
		}
		for j, word := range update.Bitmap {
			updates[i].bitmap[j] = C.uint32_t(word)
		}
	}
	deletes := make([][4]C.uint32_t, len(request.Deletes))
	for i, key := range request.Deletes {
		for j, word := range key {
			deletes[i][j] = C.uint32_t(word)
		}
	}
	var updatesPtr *C.dae_control_domain_routing_update
	if len(updates) > 0 {
		updatesPtr = &updates[0]
	}
	var deletesPtr *[4]C.uint32_t
	if len(deletes) > 0 {
		deletesPtr = &deletes[0]
	}
	rc := C.dae_control_apply_domain_routing_map_by_id(
		C.uint32_t(request.MapID),
		updatesPtr,
		C.size_t(len(updates)),
		deletesPtr,
		C.size_t(len(deletes)),
	)
	runtime.KeepAlive(updates)
	runtime.KeepAlive(deletes)
	if rc != 0 {
		return fmt.Errorf("Rust in-process domain routing map writer failed: %s", rustInprocessLastError())
	}
	return nil
}

func cUint8Bool(v bool) C.uint8_t {
	if v {
		return 1
	}
	return 0
}

func cRoutingMapEntries(entries []rustRoutingMapEntry) []C.dae_control_routing_map_entry {
	routingEntries := make([]C.dae_control_routing_map_entry, len(entries))
	for i, entry := range entries {
		routingEntries[i].index = C.uint32_t(entry.Index)
		for j, b := range entry.Value.Value {
			routingEntries[i].value.value[j] = C.uint8_t(b)
		}
		routingEntries[i].value.not_ = cUint8Bool(entry.Value.Not)
		routingEntries[i].value.kind = C.uint8_t(entry.Value.Type)
		routingEntries[i].value.outbound = C.uint8_t(entry.Value.Outbound)
		routingEntries[i].value.must = cUint8Bool(entry.Value.Must)
		routingEntries[i].value.mark = C.uint32_t(entry.Value.Mark)
	}
	return routingEntries
}

func cLpmMapBuildSpecs(specs []rustLpmMapBuildSpec) (*C.dae_control_lpm_map_build_spec, func(), error) {
	if len(specs) == 0 {
		return nil, func() {}, nil
	}
	specBytes := C.size_t(len(specs)) * C.size_t(C.sizeof_dae_control_lpm_map_build_spec)
	specPtr := C.malloc(specBytes)
	if specPtr == nil {
		return nil, func() {}, fmt.Errorf("allocate Rust in-process LPM map specs")
	}
	cSpecs := unsafe.Slice((*C.dae_control_lpm_map_build_spec)(specPtr), len(specs))
	entryPtrs := make([]unsafe.Pointer, 0, len(specs))
	for i, spec := range specs {
		cSpecs[i].index = C.uint32_t(spec.Index)
		cSpecs[i].flags = C.uint32_t(spec.Flags)
		cSpecs[i].max_entries = C.uint32_t(spec.MaxEntries)
		cSpecs[i].key_size = C.uint32_t(spec.KeySize)
		cSpecs[i].value_size = C.uint32_t(spec.ValueSize)
		cSpecs[i].entries_len = C.size_t(len(spec.Entries))
		cSpecs[i].entries = nil
		if len(spec.Entries) == 0 {
			continue
		}
		entryBytes := C.size_t(len(spec.Entries)) * C.size_t(C.sizeof_dae_control_lpm_map_entry)
		entryPtr := C.malloc(entryBytes)
		if entryPtr == nil {
			for _, ptr := range entryPtrs {
				C.free(ptr)
			}
			C.free(specPtr)
			return nil, func() {}, fmt.Errorf("allocate Rust in-process LPM map entries")
		}
		entryPtrs = append(entryPtrs, entryPtr)
		cEntries := unsafe.Slice((*C.dae_control_lpm_map_entry)(entryPtr), len(spec.Entries))
		for j, entry := range spec.Entries {
			cEntries[j].key.prefix_len = C.uint32_t(entry.Key.PrefixLen)
			for k, word := range entry.Key.Data {
				cEntries[j].key.data[k] = C.uint32_t(word)
			}
			cEntries[j].value = C.uint32_t(entry.Value)
		}
		cSpecs[i].entries = (*C.dae_control_lpm_map_entry)(entryPtr)
	}
	return (*C.dae_control_lpm_map_build_spec)(specPtr), func() {
		for _, ptr := range entryPtrs {
			C.free(ptr)
		}
		C.free(specPtr)
	}, nil
}

func rustInprocessLastError() string {
	msg := C.dae_control_last_error_message()
	if msg == nil {
		return ""
	}
	return C.GoString(msg)
}

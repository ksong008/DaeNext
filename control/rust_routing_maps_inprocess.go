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

typedef struct dae_control_domain_routing_owner dae_control_domain_routing_owner;

typedef struct {
	uint32_t map_id;
	uint8_t map_id_changed;
	uint8_t skipped;
	uint8_t padding[2];
	size_t entries_updated;
	size_t entries_deleted;
	size_t owner_count;
	size_t ip_count;
} dae_control_domain_routing_owner_apply_report;

typedef struct {
	uint32_t map_id;
	uint8_t map_id_changed;
	uint8_t padding[3];
	size_t entries_deleted;
	size_t owner_count;
	size_t ip_count;
} dae_control_domain_routing_reload_clear_report;

typedef struct {
	uint8_t dns_config_unchanged;
	uint8_t bpf_present;
	uint8_t restore_cache;
	uint8_t clear_domain_routing_map;
	size_t snapshot_entries;
} dae_control_reload_dns_cache_plan_report;

typedef struct {
	uint32_t schema_version;
	uint8_t rust_owned_runtime;
	uint8_t reload_state_available;
	uint8_t backend_state_available;
	uint8_t routing_owner_available;
	uint8_t domain_owner_available;
	uint8_t connectivity_owner_available;
	uint8_t active_handoff_available;
	uint8_t api_compatible;
	uint8_t ready_for_default_control_plane;
	uint8_t padding[2];
} dae_control_runtime_state_report_result;

extern uint32_t dae_control_ffi_abi_version(void);
extern const char *dae_control_last_error_message(void);
extern dae_control_routing_owner *dae_control_routing_owner_new(void);
extern void dae_control_routing_owner_free(dae_control_routing_owner *owner);
extern dae_control_domain_routing_owner *dae_control_domain_routing_owner_new(void);
extern void dae_control_domain_routing_owner_free(dae_control_domain_routing_owner *owner);
extern int32_t dae_control_reload_dns_cache_plan(
	uint8_t dns_config_unchanged,
	uint8_t bpf_present,
	size_t snapshot_entries,
	dae_control_reload_dns_cache_plan_report *report
);
extern int32_t dae_control_runtime_state_report(
	uint8_t rust_owned_runtime,
	uint8_t reload_state_available,
	uint8_t backend_state_available,
	uint8_t routing_owner_available,
	uint8_t domain_owner_available,
	uint8_t connectivity_owner_available,
	uint8_t active_handoff_available,
	uint8_t api_compatible,
	dae_control_runtime_state_report_result *report
);
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
extern int32_t dae_control_domain_routing_owner_apply_snapshot_by_id(
	dae_control_domain_routing_owner *owner,
	uint32_t map_id,
	const char *owner_key,
	const uint32_t (*bitmap)[32],
	const uint32_t (*ips)[4],
	size_t ips_len,
	dae_control_domain_routing_owner_apply_report *report
);
extern int32_t dae_control_domain_routing_owner_apply_snapshot_bytes_by_id(
	dae_control_domain_routing_owner *owner,
	uint32_t map_id,
	const uint8_t *owner_key,
	size_t owner_key_len,
	const uint32_t (*bitmap)[32],
	const uint32_t (*ips)[4],
	size_t ips_len,
	dae_control_domain_routing_owner_apply_report *report
);
extern int32_t dae_control_domain_routing_owner_apply_dns_event_by_id(
	dae_control_domain_routing_owner *owner,
	uint32_t map_id,
	const uint8_t *owner_key,
	size_t owner_key_len,
	const uint32_t (*bitmap)[32],
	const uint32_t (*ips)[4],
	size_t ips_len,
	dae_control_domain_routing_owner_apply_report *report
);
extern int32_t dae_control_domain_routing_owner_prepare_reload_map_by_id(
	dae_control_domain_routing_owner *owner,
	uint32_t map_id,
	const uint32_t (*existing_keys)[4],
	size_t existing_keys_len,
	dae_control_domain_routing_reload_clear_report *report
);
*/
import "C"

import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
)

var rustRoutingOwnerState struct {
	sync.Mutex
	ptr *C.dae_control_routing_owner
}

type rustDomainRoutingOwner struct {
	mu     sync.Mutex
	ptr    *C.dae_control_domain_routing_owner
	mapPtr *ebpf.Map
	mapID  uint32
}

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
	return C.dae_control_ffi_abi_version() == 1
}

func BuildRustOwnedRuntimeStateReport() (RustOwnedRuntimeStateReport, error) {
	if !rustInprocessRoutingMapAvailable() {
		return RustOwnedRuntimeStateReport{APICompatible: true}, nil
	}
	var report C.dae_control_runtime_state_report_result
	rc := C.dae_control_runtime_state_report(
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		&report,
	)
	if rc != 0 {
		return RustOwnedRuntimeStateReport{}, fmt.Errorf("Rust in-process runtime state report failed: %s", rustInprocessLastError())
	}
	return RustOwnedRuntimeStateReport{
		SchemaVersion:               uint32(report.schema_version),
		RustOwnedRuntime:            report.rust_owned_runtime != 0,
		ReloadStateAvailable:        report.reload_state_available != 0,
		BackendStateAvailable:       report.backend_state_available != 0,
		RoutingOwnerAvailable:       report.routing_owner_available != 0,
		DomainOwnerAvailable:        report.domain_owner_available != 0,
		ConnectivityOwnerAvailable:  report.connectivity_owner_available != 0,
		ActiveHandoffAvailable:      report.active_handoff_available != 0,
		APICompatible:               report.api_compatible != 0,
		ReadyForDefaultControlPlane: report.ready_for_default_control_plane != 0,
	}, nil
}

func RustOwnedReloadDnsCacheRestoreAllowed(dnsConfigUnchanged bool) bool {
	if !rustInprocessRoutingMapAvailable() {
		return dnsConfigUnchanged
	}
	plan, err := rustReloadDnsCachePlanForReload(dnsConfigUnchanged, false, 1)
	if err != nil {
		return dnsConfigUnchanged
	}
	return plan.restoreCache
}

func rustReloadDnsCachePlanForReload(dnsConfigUnchanged bool, bpfPresent bool, snapshotEntries int) (rustReloadDnsCachePlan, error) {
	if snapshotEntries < 0 {
		snapshotEntries = 0
	}
	var report C.dae_control_reload_dns_cache_plan_report
	rc := C.dae_control_reload_dns_cache_plan(
		cUint8Bool(dnsConfigUnchanged),
		cUint8Bool(bpfPresent),
		C.size_t(snapshotEntries),
		&report,
	)
	if rc != 0 {
		return rustReloadDnsCachePlan{}, fmt.Errorf("Rust in-process reload DNS cache plan failed: %s", rustInprocessLastError())
	}
	return rustReloadDnsCachePlan{
		dnsConfigUnchanged:    report.dns_config_unchanged != 0,
		bpfPresent:            report.bpf_present != 0,
		restoreCache:          report.restore_cache != 0,
		clearDomainRoutingMap: report.clear_domain_routing_map != 0,
		snapshotEntries:       int(report.snapshot_entries),
	}, nil
}

func newRustDomainRoutingOwner() *rustDomainRoutingOwner {
	return &rustDomainRoutingOwner{}
}

func (o *rustDomainRoutingOwner) Close() error {
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
		C.dae_control_domain_routing_owner_free(ptr)
	}
	return nil
}

func (o *rustDomainRoutingOwner) ensureLocked() error {
	if o.ptr != nil {
		return nil
	}
	o.ptr = C.dae_control_domain_routing_owner_new()
	if o.ptr == nil {
		return fmt.Errorf("create Rust in-process domain routing owner")
	}
	return nil
}

func (o *rustDomainRoutingOwner) mapIDLocked(m *ebpf.Map) (uint32, error) {
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

func (o *rustDomainRoutingOwner) Update(m *ebpf.Map, ownerKey string, snapshot domainRoutingOwnerSnapshot) error {
	if m == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	mapID, err := o.mapIDLocked(m)
	if err != nil {
		return err
	}
	if err := o.ensureLocked(); err != nil {
		return err
	}
	var ownerKeyPtr *C.uint8_t
	if len(ownerKey) > 0 {
		ownerKeyPtr = (*C.uint8_t)(unsafe.Pointer(unsafe.StringData(ownerKey)))
	}
	var bitmap [32]C.uint32_t
	for i, word := range snapshot.bitmap.Bitmap {
		bitmap[i] = C.uint32_t(word)
	}
	var ips [][4]C.uint32_t
	var ipsPtr *[4]C.uint32_t
	ipsLen := len(snapshot.ips)
	if ipsLen == 1 {
		var one [1][4]C.uint32_t
		for key := range snapshot.ips {
			for i, word := range key {
				one[0][i] = C.uint32_t(word)
			}
		}
		ipsPtr = &one[0]
		var report C.dae_control_domain_routing_owner_apply_report
		rc := C.dae_control_domain_routing_owner_apply_snapshot_bytes_by_id(
			o.ptr,
			C.uint32_t(mapID),
			ownerKeyPtr,
			C.size_t(len(ownerKey)),
			(*[32]C.uint32_t)(&bitmap),
			ipsPtr,
			C.size_t(ipsLen),
			&report,
		)
		runtime.KeepAlive(ownerKey)
		if rc != 0 {
			return fmt.Errorf("Rust in-process domain routing owner failed: %s", rustInprocessLastError())
		}
		return nil
	}
	ips = cDomainRoutingIPKeys(snapshot.ips)
	if len(ips) > 0 {
		ipsPtr = &ips[0]
	}
	var report C.dae_control_domain_routing_owner_apply_report
	rc := C.dae_control_domain_routing_owner_apply_snapshot_bytes_by_id(
		o.ptr,
		C.uint32_t(mapID),
		ownerKeyPtr,
		C.size_t(len(ownerKey)),
		(*[32]C.uint32_t)(&bitmap),
		ipsPtr,
		C.size_t(len(ips)),
		&report,
	)
	runtime.KeepAlive(ownerKey)
	runtime.KeepAlive(ips)
	if rc != 0 {
		return fmt.Errorf("Rust in-process domain routing owner failed: %s", rustInprocessLastError())
	}
	return nil
}

func (o *rustDomainRoutingOwner) UpdateDnsCacheEvent(m *ebpf.Map, event domainRoutingDnsEvent) error {
	if m == nil || event.ownerKey == "" {
		return nil
	}
	if len(event.domainBitmap) != len(bpfDomainRouting{}.Bitmap) {
		return fmt.Errorf("domain bitmap length not sync with kern program")
	}
	var bitmap [32]C.uint32_t
	for i, word := range event.domainBitmap {
		bitmap[i] = C.uint32_t(word)
	}

	ips := event.ips
	if len(ips) == 1 {
		var one [1][4]C.uint32_t
		ip16 := ips[0].As16()
		key := common.Ipv6ByteSliceToUint32Array(ip16[:])
		for i, word := range key {
			one[0][i] = C.uint32_t(word)
		}
		return o.applyDnsCacheEvent(m, event.ownerKey, &bitmap, &one[0], 1)
	}

	var keys [][4]C.uint32_t
	if len(ips) > 0 {
		keys = make([][4]C.uint32_t, len(ips))
		for i, ip := range ips {
			ip16 := ip.As16()
			key := common.Ipv6ByteSliceToUint32Array(ip16[:])
			for j, word := range key {
				keys[i][j] = C.uint32_t(word)
			}
		}
	}
	var keysPtr *[4]C.uint32_t
	if len(keys) > 0 {
		keysPtr = &keys[0]
	}
	err := o.applyDnsCacheEvent(m, event.ownerKey, &bitmap, keysPtr, len(keys))
	runtime.KeepAlive(keys)
	return err
}

func (o *rustDomainRoutingOwner) RemoveDnsCacheEvent(m *ebpf.Map, ownerKey string) error {
	if m == nil || ownerKey == "" {
		return nil
	}
	var bitmap [32]C.uint32_t
	return o.applyDnsCacheEvent(m, ownerKey, &bitmap, nil, 0)
}

func (o *rustDomainRoutingOwner) applyDnsCacheEvent(
	m *ebpf.Map,
	ownerKey string,
	bitmap *[32]C.uint32_t,
	ips *[4]C.uint32_t,
	ipsLen int,
) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	mapID, err := o.mapIDLocked(m)
	if err != nil {
		return err
	}
	if err := o.ensureLocked(); err != nil {
		return err
	}
	var ownerKeyPtr *C.uint8_t
	if len(ownerKey) > 0 {
		ownerKeyPtr = (*C.uint8_t)(unsafe.Pointer(unsafe.StringData(ownerKey)))
	}
	var report C.dae_control_domain_routing_owner_apply_report
	rc := C.dae_control_domain_routing_owner_apply_dns_event_by_id(
		o.ptr,
		C.uint32_t(mapID),
		ownerKeyPtr,
		C.size_t(len(ownerKey)),
		bitmap,
		ips,
		C.size_t(ipsLen),
		&report,
	)
	runtime.KeepAlive(ownerKey)
	if rc != 0 {
		return fmt.Errorf("Rust in-process domain routing DNS event failed: %s", rustInprocessLastError())
	}
	return nil
}

func (o *rustDomainRoutingOwner) PrepareReload(m *ebpf.Map, keys [][4]uint32) error {
	if m == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	mapID, err := o.mapIDLocked(m)
	if err != nil {
		return err
	}
	if err := o.ensureLocked(); err != nil {
		return err
	}
	cKeys := cDomainRoutingKeys(keys)
	var keysPtr *[4]C.uint32_t
	if len(cKeys) > 0 {
		keysPtr = &cKeys[0]
	}
	var report C.dae_control_domain_routing_reload_clear_report
	rc := C.dae_control_domain_routing_owner_prepare_reload_map_by_id(
		o.ptr,
		C.uint32_t(mapID),
		keysPtr,
		C.size_t(len(cKeys)),
		&report,
	)
	runtime.KeepAlive(cKeys)
	if rc != 0 {
		return fmt.Errorf("Rust in-process domain routing reload owner failed: %s", rustInprocessLastError())
	}
	return nil
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

func cDomainRoutingIPKeys(keys map[[4]uint32]struct{}) [][4]C.uint32_t {
	if len(keys) == 0 {
		return nil
	}
	out := make([][4]C.uint32_t, 0, len(keys))
	for key := range keys {
		var cKey [4]C.uint32_t
		for i, word := range key {
			cKey[i] = C.uint32_t(word)
		}
		out = append(out, cKey)
	}
	return out
}

func cDomainRoutingKeys(keys [][4]uint32) [][4]C.uint32_t {
	if len(keys) == 0 {
		return nil
	}
	out := make([][4]C.uint32_t, len(keys))
	for i, key := range keys {
		for j, word := range key {
			out[i][j] = C.uint32_t(word)
		}
	}
	return out
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

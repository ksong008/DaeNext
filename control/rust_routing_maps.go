/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/json"
	"fmt"

	"github.com/cilium/ebpf"
)

type rustRoutingMapApplyRequest struct {
	RoutingMapID   uint32                 `json:"routing_map_id"`
	LpmArrayMapID  uint32                 `json:"lpm_array_map_id"`
	LpmEntries     []rustLpmArrayMapEntry `json:"lpm_entries"`
	LpmMaps        []rustLpmMapBuildSpec  `json:"lpm_maps"`
	RoutingEntries []rustRoutingMapEntry  `json:"routing_entries"`
}

type rustLpmArrayMapEntry struct {
	Index uint32 `json:"index"`
	MapID uint32 `json:"map_id"`
}

type rustLpmMapBuildSpec struct {
	Index      uint32            `json:"index"`
	Flags      uint32            `json:"flags"`
	MaxEntries uint32            `json:"max_entries"`
	KeySize    uint32            `json:"key_size"`
	ValueSize  uint32            `json:"value_size"`
	Entries    []rustLpmMapEntry `json:"entries"`
}

type rustLpmMapEntry struct {
	Key   rustBpfLpmKey `json:"key"`
	Value uint32        `json:"value"`
}

type rustBpfLpmKey struct {
	PrefixLen uint32    `json:"prefix_len"`
	Data      [4]uint32 `json:"data"`
}

type rustRoutingMapEntry struct {
	Index uint32          `json:"index"`
	Value rustBpfMatchSet `json:"value"`
}

type rustBpfMatchSet struct {
	Value    [16]uint8 `json:"value"`
	Not      bool      `json:"not"`
	Type     uint8     `json:"type"`
	Outbound uint8     `json:"outbound"`
	Must     bool      `json:"must"`
	Mark     uint32    `json:"mark"`
}

type rustDomainRoutingMapApplyRequest struct {
	MapID   uint32                       `json:"map_id"`
	Updates []rustDomainRoutingMapUpdate `json:"updates"`
	Deletes [][4]uint32                  `json:"deletes"`
}

type rustDomainRoutingMapUpdate struct {
	Key    [4]uint32  `json:"key"`
	Bitmap [32]uint32 `json:"bitmap"`
}

func (b *RoutingMatcherBuilder) updateKernelRoutingMapsViaRustHelper() error {
	if b == nil || b.bpf == nil || b.bpf.RoutingMap == nil || b.bpf.LpmArrayMap == nil || b.bpf.UnusedLpmType == nil {
		return fmt.Errorf("routing maps are not initialized")
	}
	routingMapID, err := bpfMapID(b.bpf.RoutingMap)
	if err != nil {
		return err
	}
	lpmArrayMapID, err := bpfMapID(b.bpf.LpmArrayMap)
	if err != nil {
		return err
	}
	request := rustRoutingMapApplyRequest{
		RoutingMapID:   routingMapID,
		LpmArrayMapID:  lpmArrayMapID,
		LpmEntries:     []rustLpmArrayMapEntry{},
		LpmMaps:        make([]rustLpmMapBuildSpec, 0, len(b.simulatedLpmTries)),
		RoutingEntries: make([]rustRoutingMapEntry, 0, len(b.rules)),
	}
	for index, cidrs := range b.simulatedLpmTries {
		spec := rustLpmMapBuildSpec{
			Index:      uint32(index),
			Flags:      b.bpf.UnusedLpmType.Flags(),
			MaxEntries: b.bpf.UnusedLpmType.MaxEntries(),
			KeySize:    b.bpf.UnusedLpmType.KeySize(),
			ValueSize:  b.bpf.UnusedLpmType.ValueSize(),
			Entries:    make([]rustLpmMapEntry, 0, len(cidrs)),
		}
		for _, cidr := range cidrs {
			key := cidrToBpfLpmKey(cidr)
			spec.Entries = append(spec.Entries, rustLpmMapEntry{
				Key: rustBpfLpmKey{
					PrefixLen: key.PrefixLen,
					Data:      key.Data,
				},
				Value: 1,
			})
		}
		request.LpmMaps = append(request.LpmMaps, spec)
	}
	for index, rule := range b.rules {
		request.RoutingEntries = append(request.RoutingEntries, rustRoutingMapEntry{
			Index: uint32(index),
			Value: rustBpfMatchSet{
				Value:    rule.Value,
				Not:      rule.Not,
				Type:     rule.Type,
				Outbound: rule.Outbound,
				Must:     rule.Must,
				Mark:     rule.Mark,
			},
		})
	}
	if rustInprocessRoutingMapAvailable() {
		return applyKernelRoutingMapsViaRustOwnedInprocess(request)
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("encode Rust routing map request: %w", err)
	}
	out, err := runRustBpfLoaderHelperInput(payload, "routing-map", "apply")
	if err != nil {
		return err
	}
	var decoded struct {
		Status                string `json:"status"`
		RoutingEntriesUpdated int    `json:"routing_entries_updated"`
		LpmEntriesUpdated     int    `json:"lpm_entries_updated"`
		LpmMapsCreated        int    `json:"lpm_maps_created"`
	}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		return fmt.Errorf("decode Rust routing map output: %w", err)
	}
	if decoded.Status != "pass" ||
		decoded.RoutingEntriesUpdated != len(request.RoutingEntries) ||
		decoded.LpmEntriesUpdated != len(request.LpmEntries)+len(request.LpmMaps) ||
		decoded.LpmMapsCreated != len(request.LpmMaps) {
		return fmt.Errorf("unexpected Rust routing map output: %s", out)
	}
	return nil
}

func (c *controlPlaneCore) updateDomainRoutingMapViaRustHelper(
	m *ebpf.Map,
	updates []rustDomainRoutingMapUpdate,
	deletes [][4]uint32,
) error {
	if m == nil {
		return nil
	}
	if updates == nil {
		updates = []rustDomainRoutingMapUpdate{}
	}
	if deletes == nil {
		deletes = [][4]uint32{}
	}
	mapID, err := bpfMapID(m)
	if err != nil {
		return err
	}
	request := rustDomainRoutingMapApplyRequest{
		MapID:   mapID,
		Updates: updates,
		Deletes: deletes,
	}
	if rustInprocessRoutingMapAvailable() {
		return updateDomainRoutingMapViaRustInprocess(request)
	}
	if c != nil {
		if err := c.getRustDomainRoutingHelper().Update(request); err == nil {
			return nil
		}
	}
	return updateDomainRoutingMapViaRustProcessHelper(request)
}

func updateDomainRoutingMapViaRustProcessHelperForMap(
	m *ebpf.Map,
	updates []rustDomainRoutingMapUpdate,
	deletes [][4]uint32,
) error {
	if m == nil {
		return nil
	}
	if updates == nil {
		updates = []rustDomainRoutingMapUpdate{}
	}
	if deletes == nil {
		deletes = [][4]uint32{}
	}
	mapID, err := bpfMapID(m)
	if err != nil {
		return err
	}
	return updateDomainRoutingMapViaRustProcessHelper(rustDomainRoutingMapApplyRequest{
		MapID:   mapID,
		Updates: updates,
		Deletes: deletes,
	})
}

func updateDomainRoutingMapViaRustProcessHelper(request rustDomainRoutingMapApplyRequest) error {
	if request.Updates == nil {
		request.Updates = []rustDomainRoutingMapUpdate{}
	}
	if request.Deletes == nil {
		request.Deletes = [][4]uint32{}
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("encode Rust domain routing map request: %w", err)
	}
	out, err := runRustBpfLoaderHelperInput(payload, "domain-routing-map", "apply")
	if err != nil {
		return err
	}
	var decoded struct {
		Status         string `json:"status"`
		EntriesUpdated int    `json:"entries_updated"`
		EntriesDeleted int    `json:"entries_deleted"`
	}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		return fmt.Errorf("decode Rust domain routing map output: %w", err)
	}
	if decoded.Status != "pass" ||
		decoded.EntriesUpdated != len(request.Updates) ||
		decoded.EntriesDeleted != len(request.Deletes) {
		return fmt.Errorf("unexpected Rust domain routing map output: %s", out)
	}
	return nil
}

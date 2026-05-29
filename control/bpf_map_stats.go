/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/cilium/ebpf"
)

type BPFMapStats struct {
	RedirectTrackEntries int `json:"redirectTrackEntries"`
	RoutingTuplesEntries int `json:"routingTuplesEntries"`
	DomainRoutingEntries int `json:"domainRoutingEntries"`
	UdpConnStateEntries  int `json:"udpConnStateEntries"`
	CookiePidEntries     int `json:"cookiePidEntries"`
	TgidPnameEntries     int `json:"tgidPnameEntries"`
}

func (c *controlPlaneCore) BPFMapStats() (stats BPFMapStats, err error) {
	if c == nil || c.bpf == nil {
		return stats, nil
	}
	if stats, err = c.bpfMapStatsViaRustHelper(); err == nil {
		return stats, nil
	}
	return c.bpfMapStatsViaGo()
}

func (c *controlPlaneCore) bpfMapStatsViaGo() (stats BPFMapStats, err error) {
	if stats.RedirectTrackEntries, err = countMapEntries[bpfRedirectTuple, bpfRedirectEntry](c.bpf.RedirectTrack); err != nil {
		return stats, err
	}
	if stats.RoutingTuplesEntries, err = countMapEntries[bpfTuplesKey, bpfRoutingResult](c.bpf.RoutingTuplesMap); err != nil {
		return stats, err
	}
	if stats.DomainRoutingEntries, err = countMapEntries[[4]uint32, bpfDomainRouting](c.bpf.DomainRoutingMap); err != nil {
		return stats, err
	}
	if stats.UdpConnStateEntries, err = countMapEntries[bpfTuplesKey, bpfUdpConnState](c.bpf.UdpConnStateMap); err != nil {
		return stats, err
	}
	if stats.CookiePidEntries, err = countMapEntries[uint64, bpfPidPname](c.bpf.CookiePidMap); err != nil {
		return stats, err
	}
	if stats.TgidPnameEntries, err = countMapEntries[uint32, [4]uint32](c.bpf.TgidPnameMap); err != nil {
		return stats, err
	}
	return stats, nil
}

func (c *controlPlaneCore) bpfMapStatsViaRustHelper() (BPFMapStats, error) {
	maps := []struct {
		name string
		m    *ebpf.Map
	}{
		{"redirect_track", c.bpf.RedirectTrack},
		{"routing_tuples_map", c.bpf.RoutingTuplesMap},
		{"domain_routing_map", c.bpf.DomainRoutingMap},
		{"udp_conn_state_map", c.bpf.UdpConnStateMap},
		{"cookie_pid_map", c.bpf.CookiePidMap},
		{"tgid_pname_map", c.bpf.TgidPnameMap},
	}
	args := []string{"map-stats", "count"}
	for _, item := range maps {
		id, err := bpfMapID(item.m)
		if err != nil {
			return BPFMapStats{}, err
		}
		args = append(args, "--map", item.name+":"+strconv.FormatUint(uint64(id), 10))
	}
	out, err := runRustBpfLoaderHelperOutput(args...)
	if err != nil {
		return BPFMapStats{}, err
	}
	var decoded struct {
		Counts []struct {
			Name    string `json:"name"`
			Entries int    `json:"entries"`
		} `json:"counts"`
	}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		return BPFMapStats{}, fmt.Errorf("decode rust map stats output: %w", err)
	}
	var stats BPFMapStats
	for _, count := range decoded.Counts {
		switch count.Name {
		case "redirect_track":
			stats.RedirectTrackEntries = count.Entries
		case "routing_tuples_map":
			stats.RoutingTuplesEntries = count.Entries
		case "domain_routing_map":
			stats.DomainRoutingEntries = count.Entries
		case "udp_conn_state_map":
			stats.UdpConnStateEntries = count.Entries
		case "cookie_pid_map":
			stats.CookiePidEntries = count.Entries
		case "tgid_pname_map":
			stats.TgidPnameEntries = count.Entries
		default:
			return BPFMapStats{}, fmt.Errorf("unexpected rust map stats name %q", count.Name)
		}
	}
	return stats, nil
}

func bpfMapID(m *ebpf.Map) (uint32, error) {
	if m == nil {
		return 0, fmt.Errorf("nil BPF map")
	}
	info, err := m.Info()
	if err != nil {
		return 0, err
	}
	id, ok := info.ID()
	if !ok {
		return 0, fmt.Errorf("BPF map %q has no kernel id", info.Name)
	}
	return uint32(id), nil
}

func countMapEntries[K any, V any](m *ebpf.Map) (int, error) {
	if m == nil {
		return 0, nil
	}
	iter := m.Iterate()
	var (
		key   K
		value V
		n     int
	)
	for iter.Next(&key, &value) {
		n++
	}
	if err := iter.Err(); err != nil {
		return 0, err
	}
	return n, nil
}

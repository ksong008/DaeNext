/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import "github.com/cilium/ebpf"

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

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package trace

const (
	maxTrackedSkbs   = 4096
	maxEventsPerSkb  = 64
	maxSymbolsPerSkb = 64
)

type traceEventRecord struct {
	Pc          uint64
	Skb         uint64
	SecondParam uint64
	Mark        uint32
	Netns       uint32
	Ifindex     uint32
	Pid         uint32
	Ifname      [16]uint8
	Pname       [32]uint8
	Saddr       [16]byte
	Daddr       [16]byte
	Sport       uint16
	Dport       uint16
	L3Proto     uint16
	L4Proto     uint8
	TcpFlags    uint8
	PayloadLen  uint16
}

type skbTraceTracker struct {
	events   map[uint64][]traceEventRecord
	symNames map[uint64][]string
	lastSeen map[uint64]uint64
	sequence uint64
}

func newSkbTraceTracker() *skbTraceTracker {
	return &skbTraceTracker{
		events:   make(map[uint64][]traceEventRecord),
		symNames: make(map[uint64][]string),
		lastSeen: make(map[uint64]uint64),
	}
}

func (t *skbTraceTracker) Add(event traceEventRecord, symName string) {
	t.sequence++
	t.events[event.Skb] = appendCapped(t.events[event.Skb], event, maxEventsPerSkb)
	t.symNames[event.Skb] = appendCapped(t.symNames[event.Skb], symName, maxSymbolsPerSkb)
	t.lastSeen[event.Skb] = t.sequence
	if len(t.events) > maxTrackedSkbs {
		t.evictOldest()
	}
}

func (t *skbTraceTracker) Events(skb uint64) []traceEventRecord {
	return t.events[skb]
}

func (t *skbTraceTracker) SymNames(skb uint64) []string {
	return t.symNames[skb]
}

func (t *skbTraceTracker) Delete(skb uint64) {
	delete(t.events, skb)
	delete(t.symNames, skb)
	delete(t.lastSeen, skb)
}

func (t *skbTraceTracker) evictOldest() {
	var (
		oldestSkb uint64
		oldestSeq uint64
		found     bool
	)
	for skb, seq := range t.lastSeen {
		if !found || seq < oldestSeq {
			oldestSkb = skb
			oldestSeq = seq
			found = true
		}
	}
	if found {
		t.Delete(oldestSkb)
	}
}

func appendCapped[T any](items []T, item T, limit int) []T {
	if limit <= 0 {
		return items
	}
	if len(items) < limit {
		return append(items, item)
	}
	copy(items, items[1:])
	items[len(items)-1] = item
	return items
}

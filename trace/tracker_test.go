/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package trace

import "testing"

func TestSkbTraceTrackerEvictsOldestTrackedSkb(t *testing.T) {
	tracker := newSkbTraceTracker()
	for i := uint64(0); i < maxTrackedSkbs+1; i++ {
		tracker.Add(traceEventRecord{Skb: i}, "sym")
	}
	if len(tracker.events) != maxTrackedSkbs {
		t.Fatalf("tracked skb count = %d, want %d", len(tracker.events), maxTrackedSkbs)
	}
	if _, ok := tracker.events[0]; ok {
		t.Fatalf("expected oldest skb to be evicted")
	}
	if _, ok := tracker.events[maxTrackedSkbs]; !ok {
		t.Fatalf("expected newest skb to remain tracked")
	}
}

func TestSkbTraceTrackerCapsPerSkbSlices(t *testing.T) {
	tracker := newSkbTraceTracker()
	for i := 0; i < maxEventsPerSkb+10; i++ {
		tracker.Add(traceEventRecord{Skb: 1, PayloadLen: uint16(i)}, "sym")
	}
	events := tracker.Events(1)
	syms := tracker.SymNames(1)
	if len(events) != maxEventsPerSkb {
		t.Fatalf("event slice len = %d, want %d", len(events), maxEventsPerSkb)
	}
	if len(syms) != maxSymbolsPerSkb {
		t.Fatalf("symbol slice len = %d, want %d", len(syms), maxSymbolsPerSkb)
	}
	if events[0].PayloadLen != 10 {
		t.Fatalf("oldest retained payload = %d, want %d", events[0].PayloadLen, 10)
	}
	if events[len(events)-1].PayloadLen != maxEventsPerSkb+9 {
		t.Fatalf("newest retained payload = %d, want %d", events[len(events)-1].PayloadLen, maxEventsPerSkb+9)
	}
}

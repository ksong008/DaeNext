/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"sync"
	"time"
)

type LatenciesN struct {
	N             int
	lastNLatencies []time.Duration
	head          int
	length        int
	SumNLatencies time.Duration

	mu sync.Mutex
}

func NewLatenciesN(n int) *LatenciesN {
	if n <= 0 {
		n = 1
	}
	return &LatenciesN{
		N:              n,
		lastNLatencies: make([]time.Duration, n),
		SumNLatencies:  0,
	}
}

// AppendLatency appends a new latency to the back and keep the number in the list. Appending a fixed duration for
// failed or timeout situation is recommended.
//
// It is thread-safe.
func (ln *LatenciesN) AppendLatency(l time.Duration) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if ln.length < ln.N {
		index := (ln.head + ln.length) % ln.N
		ln.lastNLatencies[index] = l
		ln.length++
		ln.SumNLatencies += l
		return
	}

	ln.SumNLatencies -= ln.lastNLatencies[ln.head]
	ln.lastNLatencies[ln.head] = l
	ln.head = (ln.head + 1) % ln.N
	ln.SumNLatencies += l
}

func (ln *LatenciesN) LastLatency() (time.Duration, bool) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if ln.length == 0 {
		return 0, false
	}
	index := (ln.head + ln.length - 1) % ln.N
	return ln.lastNLatencies[index], true
}

func (ln *LatenciesN) AvgLatency() (time.Duration, bool) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if ln.length == 0 {
		return 0, false
	}
	return ln.SumNLatencies / time.Duration(ln.length), true
}

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync"
	"testing"
	"time"
)

func TestUdpTaskPoolSerializesTasksPerKey(t *testing.T) {
	pool := NewUdpTaskPool()
	defer pool.Close()

	var (
		mu      sync.Mutex
		results []int
		wg      sync.WaitGroup
	)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		i := i
		pool.EmitTask("same-key", func() {
			defer wg.Done()
			mu.Lock()
			results = append(results, i)
			mu.Unlock()
		})
	}
	wg.Wait()

	for i, got := range results {
		if got != i {
			t.Fatalf("expected task order %d at index %d, got %d", i, i, got)
		}
	}
}

func TestUdpTaskPoolSweepExpiredQueues(t *testing.T) {
	pool := NewUdpTaskPool()
	defer pool.Close()

	now := time.Now()
	pool.now = func() time.Time { return now }

	pool.EmitTask("idle-key", func() {})
	time.Sleep(10 * time.Millisecond)
	if pool.Count() != 1 {
		t.Fatalf("expected one queue after first task, got %d", pool.Count())
	}

	pool.mu.Lock()
	pool.m["idle-key"].agingTime = time.Second
	pool.m["idle-key"].lastActive = now.Add(-2 * time.Second)
	pool.mu.Unlock()

	pool.sweepExpiredQueues(now)
	if pool.Count() != 0 {
		t.Fatalf("expected expired queue to be swept, got %d queues", pool.Count())
	}
}

func TestUdpTaskPoolDoesNotSweepRunningQueue(t *testing.T) {
	pool := NewUdpTaskPool()
	defer pool.Close()

	now := time.Now()
	pool.now = func() time.Time { return now }

	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	pool.EmitTask("busy-key", func() {
		close(started)
		<-release
		close(done)
	})
	<-started

	pool.mu.Lock()
	pool.m["busy-key"].agingTime = time.Second
	pool.m["busy-key"].lastActive = now.Add(-2 * time.Second)
	pool.mu.Unlock()

	pool.sweepExpiredQueues(now)
	if pool.Count() != 1 {
		t.Fatalf("expected running queue to remain, got %d queues", pool.Count())
	}

	close(release)
	<-done
}

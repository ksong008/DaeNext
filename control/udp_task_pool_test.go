/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"strconv"
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

func TestUdpTaskPoolEvictsOldestIdleQueueWhenFull(t *testing.T) {
	pool := NewUdpTaskPool()
	defer pool.Close()

	now := time.Now()
	pool.now = func() time.Time { return now }

	pool.mu.Lock()
	for i := 0; i < udpTaskPoolMaxQueues; i++ {
		key := "idle-" + strconv.Itoa(i)
		ctx, cancel := context.WithCancel(context.Background())
		ch := make(chan UdpTask, UdpTaskQueueLength)
		q := &UdpTaskQueue{
			key:        key,
			p:          pool,
			ch:         ch,
			agingTime:  24 * time.Hour,
			ctx:        ctx,
			cancel:     cancel,
			closed:     make(chan struct{}),
			lastActive: now.Add(time.Duration(i-udpTaskPoolMaxQueues) * time.Second),
		}
		go q.convoy()
		pool.m[key] = q
	}
	pool.mu.Unlock()

	done := make(chan struct{})
	pool.EmitTask("fresh-key", func() {
		close(done)
	})
	<-done

	if pool.Count() != udpTaskPoolMaxQueues {
		t.Fatalf("expected queue count to remain capped at %d, got %d", udpTaskPoolMaxQueues, pool.Count())
	}

	pool.mu.Lock()
	_, oldestStillExists := pool.m["idle-0"]
	_, freshExists := pool.m["fresh-key"]
	pool.mu.Unlock()

	if oldestStillExists {
		t.Fatal("expected oldest idle queue to be evicted")
	}
	if !freshExists {
		t.Fatal("expected fresh queue to be created")
	}
}

func TestUdpTaskPoolDropsWhenQueueIsFullWithoutBlocking(t *testing.T) {
	pool := NewUdpTaskPool()
	defer pool.Close()

	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	if !pool.EmitTask("busy-key", func() {
		close(started)
		<-release
		close(done)
	}) {
		t.Fatal("expected first task to be accepted")
	}
	<-started

	for i := 0; i < UdpTaskQueueLength; i++ {
		if !pool.EmitTask("busy-key", func() {}) {
			t.Fatalf("expected queued task %d to be accepted before overflow", i)
		}
	}

	result := make(chan bool, 1)
	go func() {
		result <- pool.EmitTask("busy-key", func() {
			t.Fatal("overflow task should not run")
		})
	}()

	select {
	case queued := <-result:
		if queued {
			t.Fatal("expected overflow task to be dropped")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("EmitTask blocked on a full queue")
	}
	if drops := pool.DropCount(); drops != 1 {
		t.Fatalf("expected one dropped task after overflow, got %d", drops)
	}

	close(release)
	<-done
}

func TestUdpTaskPoolFlushClearsQueues(t *testing.T) {
	pool := NewUdpTaskPool()
	defer pool.Close()

	if ok := pool.EmitTask("client", func() {}); !ok {
		t.Fatal("EmitTask() rejected initial task")
	}
	if pool.Count() == 0 {
		t.Fatal("expected a queue before flush")
	}
	pool.Flush()
	if got := pool.Count(); got != 0 {
		t.Fatalf("Count() after Flush() = %d, want 0", got)
	}
}

func TestUdpTaskPoolFlushDoesNotBlockBehindRunningTask(t *testing.T) {
	pool := NewUdpTaskPool()
	defer pool.Close()

	started := make(chan struct{})
	releaseOld := make(chan struct{})
	oldDone := make(chan struct{})
	if !pool.EmitTask("client", func() {
		close(started)
		<-releaseOld
		close(oldDone)
	}) {
		t.Fatal("EmitTask() rejected old task")
	}
	<-started

	flushReturned := make(chan struct{})
	go func() {
		pool.Flush()
		close(flushReturned)
	}()
	select {
	case <-flushReturned:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Flush() blocked behind a running task")
	}
	if got := pool.Count(); got != 0 {
		t.Fatalf("Count() after non-blocking Flush() = %d, want 0", got)
	}

	newDone := make(chan struct{})
	if !pool.EmitTask("client", func() {
		close(newDone)
	}) {
		t.Fatal("EmitTask() rejected new task after flush")
	}
	select {
	case <-newDone:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("new task did not run after flush created a new queue")
	}

	close(releaseOld)
	select {
	case <-oldDone:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("old task did not finish after release")
	}
}

func TestUdpTaskPoolConcurrentFlushAndEmitStress(t *testing.T) {
	pool := NewUdpTaskPool()
	defer pool.Close()

	const emitters = 16
	const rounds = 256
	var wg sync.WaitGroup
	for i := 0; i < emitters; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			for round := 0; round < rounds; round++ {
				key := "client-" + strconv.Itoa((i+round)%32)
				pool.EmitTask(key, func() {})
				if round%17 == 0 {
					pool.Flush()
				}
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent EmitTask/Flush stress timed out")
	}
	pool.Flush()
	if got := pool.Count(); got != 0 {
		t.Fatalf("Count() after final Flush() = %d, want 0", got)
	}
}

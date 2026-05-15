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
	q := pool.m["idle-key"]
	pool.mu.Unlock()
	q.mu.Lock()
	q.agingTime = time.Second
	q.lastActive = now.Add(-2 * time.Second)
	q.mu.Unlock()

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
	q := pool.m["busy-key"]
	pool.mu.Unlock()
	q.mu.Lock()
	q.agingTime = time.Second
	q.lastActive = now.Add(-2 * time.Second)
	q.mu.Unlock()

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

func TestUdpTaskPoolEvictionDoesNotWaitForQueueClose(t *testing.T) {
	pool := NewUdpTaskPool()
	defer pool.Close()

	now := time.Now()
	pool.now = func() time.Time { return now }

	var oldest *UdpTaskQueue
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
		if i == 0 {
			oldest = q
		} else {
			go q.convoy()
		}
		pool.m[key] = q
	}
	pool.mu.Unlock()

	freshDone := make(chan struct{})
	result := make(chan bool, 1)
	go func() {
		result <- pool.EmitTask("fresh-key", func() {
			close(freshDone)
		})
	}()

	select {
	case accepted := <-result:
		if !accepted {
			t.Fatal("expected fresh task to be accepted after evicting idle queue")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("EmitTask waited for evicted queue to close")
	}
	close(oldest.closed)

	select {
	case <-freshDone:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("fresh task did not run after idle eviction")
	}
}

func TestUdpTaskPoolDropsNewKeyWhenFullWithoutIdleQueue(t *testing.T) {
	pool := NewUdpTaskPool()

	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		pool.Close()
	})

	started := make(chan struct{}, udpTaskPoolMaxQueues)
	for i := 0; i < udpTaskPoolMaxQueues; i++ {
		key := "running-" + strconv.Itoa(i)
		if !pool.EmitTask(key, func() {
			started <- struct{}{}
			<-release
		}) {
			t.Fatalf("task for %s was rejected before the pool reached capacity", key)
		}
	}
	if got := pool.Count(); got != udpTaskPoolMaxQueues {
		t.Fatalf("expected queue count to reach cap %d, got %d", udpTaskPoolMaxQueues, got)
	}
	for i := 0; i < udpTaskPoolMaxQueues; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("only %d capped queues started running", i)
		}
	}

	result := make(chan bool, 1)
	go func() {
		result <- pool.EmitTask("overflow-new-key", func() {})
	}()

	select {
	case accepted := <-result:
		if accepted {
			t.Fatal("expected new key task to be dropped when all capped queues are busy")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("EmitTask blocked when the full pool had no idle queue to evict")
	}
	if got := pool.Count(); got != udpTaskPoolMaxQueues {
		t.Fatalf("queue count exceeded cap: got %d want %d", got, udpTaskPoolMaxQueues)
	}
	if drops := pool.DropCount(); drops != 1 {
		t.Fatalf("expected one dropped task after capped busy-pool overflow, got %d", drops)
	}

	releaseOnce.Do(func() { close(release) })
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
	overflowRan := make(chan struct{}, 1)
	go func() {
		result <- pool.EmitTask("busy-key", func() {
			overflowRan <- struct{}{}
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
	select {
	case <-overflowRan:
		t.Fatal("overflow task should not run")
	default:
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

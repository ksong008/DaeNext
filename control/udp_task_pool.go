/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
*/

package control

import (
	"context"
	"sync"
	"time"
)

const UdpTaskQueueLength = 128
const udpTaskSweepInterval = time.Second
const udpTaskPoolMaxQueues = 2048

type UdpTask = func()

// UdpTaskQueue make sure packets with the same key (4 tuples) will be sent in order.
type UdpTaskQueue struct {
	key       string
	p         *UdpTaskPool
	ch        chan UdpTask
	agingTime time.Duration
	ctx       context.Context
	cancel    context.CancelFunc
	closed    chan struct{}
	mu        sync.Mutex
	lastActive time.Time
	running   bool
}

func (q *UdpTaskQueue) convoy() {
	for {
		select {
		case <-q.ctx.Done():
			close(q.closed)
			return
		case task := <-q.ch:
			q.mu.Lock()
			q.running = true
			q.mu.Unlock()
			task()
			q.mu.Lock()
			q.running = false
			q.lastActive = time.Now()
			q.mu.Unlock()
		}
	}
}

func (q *UdpTaskQueue) touch(now time.Time) {
	q.mu.Lock()
	q.lastActive = now
	q.mu.Unlock()
}

func (q *UdpTaskQueue) expired(now time.Time) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return !q.running && len(q.ch) == 0 && !q.lastActive.Add(q.agingTime).After(now)
}

type UdpTaskPool struct {
	queueChPool sync.Pool
	// mu protects m
	mu sync.Mutex
	m  map[string]*UdpTaskQueue
	ctx context.Context
	cancel context.CancelFunc
	cleanupWg sync.WaitGroup
	now func() time.Time
}

func (p *UdpTaskPool) evictOldestIdleQueueLocked(now time.Time) *UdpTaskQueue {
	var (
		oldestKey  string
		oldest     *UdpTaskQueue
		oldestTime time.Time
		oldestSeen bool
	)

	for key, q := range p.m {
		q.mu.Lock()
		running := q.running
		lastActive := q.lastActive
		pending := len(q.ch)
		agingTime := q.agingTime
		q.mu.Unlock()

		if running || pending > 0 {
			continue
		}
		if !lastActive.Add(agingTime).After(now) {
			delete(p.m, key)
			return q
		}
		if !oldestSeen || lastActive.Before(oldestTime) {
			oldestKey = key
			oldest = q
			oldestTime = lastActive
			oldestSeen = true
		}
	}

	if !oldestSeen {
		return nil
	}
	delete(p.m, oldestKey)
	return oldest
}

func NewUdpTaskPool() *UdpTaskPool {
	ctx, cancel := context.WithCancel(context.Background())
	p := &UdpTaskPool{
		queueChPool: sync.Pool{New: func() any {
			return make(chan UdpTask, UdpTaskQueueLength)
		}},
		mu: sync.Mutex{},
		m:  map[string]*UdpTaskQueue{},
		ctx: ctx,
		cancel: cancel,
		now: time.Now,
	}
	p.startCleanup()
	return p
}

func (p *UdpTaskPool) startCleanup() {
	p.cleanupWg.Add(1)
	go func() {
		defer p.cleanupWg.Done()
		ticker := time.NewTicker(udpTaskSweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-p.ctx.Done():
				return
			case <-ticker.C:
				p.sweepExpiredQueues(p.now())
			}
		}
	}()
}

func (p *UdpTaskPool) Count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.m)
}

func (p *UdpTaskPool) sweepExpiredQueues(now time.Time) {
	var expired []*UdpTaskQueue
	p.mu.Lock()
	for key, q := range p.m {
		if !q.expired(now) {
			continue
		}
		delete(p.m, key)
		expired = append(expired, q)
	}
	p.mu.Unlock()
	for _, q := range expired {
		q.cancel()
		<-q.closed
		if len(q.ch) == 0 {
			p.queueChPool.Put(q.ch)
		}
	}
}

func (p *UdpTaskPool) Close() {
	p.cancel()
	p.cleanupWg.Wait()
	var queues []*UdpTaskQueue
	p.mu.Lock()
	for key, q := range p.m {
		delete(p.m, key)
		queues = append(queues, q)
	}
	p.mu.Unlock()
	for _, q := range queues {
		q.cancel()
		<-q.closed
		if len(q.ch) == 0 {
			p.queueChPool.Put(q.ch)
		}
	}
}

// EmitTask: Make sure packets with the same key (4 tuples) will be sent in order.
func (p *UdpTaskPool) EmitTask(key string, task UdpTask) {
	now := p.now()
	var evicted *UdpTaskQueue
	p.mu.Lock()
	q, ok := p.m[key]
	if !ok {
		if len(p.m) >= udpTaskPoolMaxQueues {
			evicted = p.evictOldestIdleQueueLocked(now)
		}
		ch := p.queueChPool.Get().(chan UdpTask)
		ctx, cancel := context.WithCancel(context.Background())
		q = &UdpTaskQueue{
			key:       key,
			p:         p,
			ch:        ch,
			agingTime: DefaultNatTimeout,
			ctx:       ctx,
			cancel:    cancel,
			closed:    make(chan struct{}),
			lastActive: now,
		}
		p.m[key] = q
		go q.convoy()
	} else {
		q.touch(now)
	}
	p.mu.Unlock()
	if evicted != nil {
		evicted.cancel()
		<-evicted.closed
		if len(evicted.ch) == 0 {
			p.queueChPool.Put(evicted.ch)
		}
	}
	// if task cannot be executed within 180s(DefaultNatTimeout), GC may be triggered, so skip the task when GC occurs
	select {
	case q.ch <- task:
	case <-q.ctx.Done():
	}
}

var (
	DefaultUdpTaskPool = NewUdpTaskPool()
)

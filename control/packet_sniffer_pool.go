/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/daeuniverse/dae/component/sniffing"
)

const (
	PacketSnifferTtl = 3 * time.Second
	packetSnifferSweepInterval = time.Second
)

type PacketSniffer struct {
	*sniffing.Sniffer
	Mu         sync.Mutex
	Ttl        time.Duration
	lastActive time.Time
	closeOnce  sync.Once
}

// PacketSnifferPool is a full-cone udp conn pool
type PacketSnifferPool struct {
	pool        sync.Map
	createMuMap sync.Map
	ctx         context.Context
	cancel      context.CancelFunc
	cleanupWg   sync.WaitGroup
	now         func() time.Time
}
type PacketSnifferOptions struct {
	Ttl time.Duration
}
type PacketSnifferKey struct {
	LAddr netip.AddrPort
	RAddr netip.AddrPort
}

var DefaultPacketSnifferSessionMgr = NewPacketSnifferPool()

func NewPacketSnifferPool() *PacketSnifferPool {
	ctx, cancel := context.WithCancel(context.Background())
	p := &PacketSnifferPool{
		ctx:       ctx,
		cancel:    cancel,
		cleanupWg: sync.WaitGroup{},
		now:       time.Now,
	}
	p.startCleanup()
	return p
}

func (p *PacketSnifferPool) Remove(key PacketSnifferKey, sniffer *PacketSniffer) (err error) {
	if ue, ok := p.pool.Load(key); ok {
		if ue != sniffer {
			sniffer.Close()
			return fmt.Errorf("target udp endpoint is not in the pool")
		}
		if p.pool.CompareAndDelete(key, sniffer) {
			sniffer.Close()
		}
	}
	return nil
}

func (p *PacketSnifferPool) Get(key PacketSnifferKey) *PacketSniffer {
	_qs, ok := p.pool.Load(key)
	if !ok {
		return nil
	}
	return _qs.(*PacketSniffer)
}

func (p *PacketSnifferPool) Count() (n int) {
	p.pool.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

func (p *PacketSnifferPool) startCleanup() {
	p.cleanupWg.Add(1)
	go func() {
		defer p.cleanupWg.Done()
		ticker := time.NewTicker(packetSnifferSweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-p.ctx.Done():
				return
			case <-ticker.C:
				p.sweepExpired(p.now())
			}
		}
	}()
}

func (p *PacketSnifferPool) sweepExpired(now time.Time) {
	p.pool.Range(func(key, value any) bool {
		sniffer := value.(*PacketSniffer)
		if !sniffer.Expired(now) {
			return true
		}
		if p.pool.CompareAndDelete(key, sniffer) {
			sniffer.Close()
		}
		return true
	})
}

func (p *PacketSnifferPool) Close() error {
	p.cancel()
	p.cleanupWg.Wait()
	p.pool.Range(func(key, value any) bool {
		sniffer := value.(*PacketSniffer)
		p.pool.Delete(key)
		sniffer.Close()
		return true
	})
	return nil
}

func (p *PacketSnifferPool) GetOrCreate(key PacketSnifferKey, createOption *PacketSnifferOptions) (qs *PacketSniffer, isNew bool) {
	_qs, ok := p.pool.Load(key)
begin:
	if !ok {
		createMu, _ := p.createMuMap.LoadOrStore(key, &sync.Mutex{})
		createMu.(*sync.Mutex).Lock()
		defer createMu.(*sync.Mutex).Unlock()
		defer p.createMuMap.Delete(key)
		_qs, ok = p.pool.Load(key)
		if ok {
			goto begin
		}
		// Create an PacketSniffer.
		if createOption == nil {
			createOption = &PacketSnifferOptions{}
		}
		if createOption.Ttl == 0 {
			createOption.Ttl = PacketSnifferTtl
		}

		qs = &PacketSniffer{
			Sniffer:    sniffing.NewPacketSniffer(nil, createOption.Ttl),
			Mu:         sync.Mutex{},
			Ttl:        createOption.Ttl,
			lastActive: p.now(),
		}
		_qs = qs
		p.pool.Store(key, qs)
		// Receive UDP messages.
		isNew = true
	} else {
		_qs.(*PacketSniffer).Touch(p.now())
	}
	return _qs.(*PacketSniffer), isNew
}

func (q *PacketSniffer) Touch(now time.Time) {
	q.Mu.Lock()
	q.lastActive = now
	q.Mu.Unlock()
}

func (q *PacketSniffer) Expired(now time.Time) bool {
	q.Mu.Lock()
	defer q.Mu.Unlock()
	return !q.lastActive.Add(q.Ttl).After(now)
}

func (q *PacketSniffer) Close() error {
	var err error
	q.closeOnce.Do(func() {
		err = q.Sniffer.Close()
	})
	return err
}

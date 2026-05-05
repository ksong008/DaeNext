/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
)

const (
	udpEndpointSweepInterval  = time.Second
	udpEndpointPoolMaxEntries = 2048
)

type UdpHandler func(data []byte, from netip.AddrPort) error

type UdpEndpoint struct {
	conn       netproxy.PacketConn
	mu         sync.Mutex
	handler    UdpHandler
	NatTimeout time.Duration
	lastActive time.Time
	onInactive func()
	closeOnce  sync.Once

	Dialer   *dialer.Dialer
	Outbound *outbound.DialerGroup

	// Non-empty indicates this UDP Endpoint is related with a sniffed domain.
	SniffedDomain string
	DialTarget    string
}

func (ue *UdpEndpoint) start() {
	buf := pool.GetFullCap(consts.EthernetMtu)
	defer pool.Put(buf)
	defer func() {
		if ue.onInactive != nil {
			ue.onInactive()
		}
	}()
	for {
		n, from, err := ue.conn.ReadFrom(buf[:])
		if err != nil {
			break
		}
		ue.Touch(time.Now())
		if err = ue.handler(buf[:n], from); err != nil {
			break
		}
	}
}

func (ue *UdpEndpoint) WriteTo(b []byte, addr string) (int, error) {
	return ue.conn.WriteTo(b, addr)
}

func (ue *UdpEndpoint) Touch(now time.Time) {
	ue.mu.Lock()
	ue.lastActive = now
	ue.mu.Unlock()
}

func (ue *UdpEndpoint) Expired(now time.Time) bool {
	ue.mu.Lock()
	defer ue.mu.Unlock()
	return !ue.lastActive.Add(ue.NatTimeout).After(now)
}

func (ue *UdpEndpoint) Close() error {
	var err error
	ue.closeOnce.Do(func() {
		err = ue.conn.Close()
	})
	return err
}

// UdpEndpointPool is a full-cone udp conn pool
type UdpEndpointPool struct {
	pool        sync.Map
	createMuMap sync.Map
	ctx         context.Context
	cancel      context.CancelFunc
	cleanupWg   sync.WaitGroup
	now         func() time.Time
}
type UdpEndpointOptions struct {
	Handler    UdpHandler
	NatTimeout time.Duration
	// GetTarget is useful only if the underlay does not support Full-cone.
	GetDialOption func() (option *DialOption, err error)
}

var DefaultUdpEndpointPool = NewUdpEndpointPool()

func NewUdpEndpointPool() *UdpEndpointPool {
	ctx, cancel := context.WithCancel(context.Background())
	p := &UdpEndpointPool{
		ctx:       ctx,
		cancel:    cancel,
		cleanupWg: sync.WaitGroup{},
		now:       time.Now,
	}
	p.startCleanup()
	return p
}

func (p *UdpEndpointPool) startCleanup() {
	p.cleanupWg.Add(1)
	go func() {
		defer p.cleanupWg.Done()
		ticker := time.NewTicker(udpEndpointSweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-p.ctx.Done():
				return
			case <-ticker.C:
				p.sweepExpiredEndpoints(p.now())
			}
		}
	}()
}

func (p *UdpEndpointPool) sweepExpiredEndpoints(now time.Time) {
	p.pool.Range(func(key, value any) bool {
		ue := value.(*UdpEndpoint)
		if !ue.Expired(now) {
			return true
		}
		if p.pool.CompareAndDelete(key, ue) {
			ue.Close()
		}
		return true
	})
}

func (p *UdpEndpointPool) evictOldestEndpoint(now time.Time) *UdpEndpoint {
	var (
		oldestKey  netip.AddrPort
		oldest     *UdpEndpoint
		oldestTime time.Time
		oldestSeen bool
	)

	p.pool.Range(func(key, value any) bool {
		addr := key.(netip.AddrPort)
		ue := value.(*UdpEndpoint)
		if ue.Expired(now) {
			if p.pool.CompareAndDelete(addr, ue) {
				oldestKey = addr
				oldest = ue
				oldestTime = time.Time{}
				oldestSeen = true
				return false
			}
			return true
		}

		ue.mu.Lock()
		lastActive := ue.lastActive
		ue.mu.Unlock()
		if !oldestSeen || lastActive.Before(oldestTime) {
			oldestKey = addr
			oldest = ue
			oldestTime = lastActive
			oldestSeen = true
		}
		return true
	})

	if oldest == nil {
		return nil
	}
	if oldestTime.IsZero() {
		return oldest
	}
	if p.pool.CompareAndDelete(oldestKey, oldest) {
		return oldest
	}
	return nil
}

func (p *UdpEndpointPool) Close() error {
	p.cancel()
	p.cleanupWg.Wait()
	return p.Flush()
}

func (p *UdpEndpointPool) Flush() error {
	var errs []error
	p.pool.Range(func(key, value any) bool {
		ue := value.(*UdpEndpoint)
		p.pool.Delete(key)
		if err := ue.Close(); err != nil {
			errs = append(errs, err)
		}
		return true
	})
	return errors.Join(errs...)
}

func (p *UdpEndpointPool) Remove(lAddr netip.AddrPort, udpEndpoint *UdpEndpoint) (err error) {
	if ue, ok := p.pool.Load(lAddr); ok {
		if ue != udpEndpoint {
			udpEndpoint.Close()
			return fmt.Errorf("target udp endpoint is not in the pool")
		}
		if p.pool.CompareAndDelete(lAddr, udpEndpoint) {
			return udpEndpoint.Close()
		}
	}
	return nil
}

func (p *UdpEndpointPool) Get(lAddr netip.AddrPort) (udpEndpoint *UdpEndpoint, ok bool) {
	_ue, ok := p.pool.Load(lAddr)
	if !ok {
		return nil, ok
	}
	return _ue.(*UdpEndpoint), ok
}

func (p *UdpEndpointPool) Count() (n int) {
	p.pool.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

func (p *UdpEndpointPool) GetOrCreate(lAddr netip.AddrPort, createOption *UdpEndpointOptions) (udpEndpoint *UdpEndpoint, isNew bool, err error) {
	_ue, ok := p.pool.Load(lAddr)
begin:
	if !ok {
		createMu, _ := p.createMuMap.LoadOrStore(lAddr, &sync.Mutex{})
		createMu.(*sync.Mutex).Lock()
		defer createMu.(*sync.Mutex).Unlock()
		defer p.createMuMap.Delete(lAddr)
		_ue, ok = p.pool.Load(lAddr)
		if ok {
			goto begin
		}
		// Create an UdpEndpoint.
		if createOption == nil {
			createOption = &UdpEndpointOptions{}
		}
		if createOption.NatTimeout == 0 {
			createOption.NatTimeout = DefaultNatTimeout
		}
		if createOption.Handler == nil {
			return nil, true, fmt.Errorf("createOption.Handler cannot be nil")
		}

		dialOption, err := createOption.GetDialOption()
		if err != nil {
			return nil, false, err
		}
		ctx, cancel := context.WithTimeout(context.TODO(), consts.DefaultDialTimeout)
		defer cancel()
		udpConn, err := dialOption.Dialer.DialContext(ctx, dialOption.Network, dialOption.Target)
		if err != nil {
			return nil, true, err
		}
		packetConn, ok := udpConn.(netproxy.PacketConn)
		if !ok {
			_ = udpConn.Close()
			return nil, true, fmt.Errorf("protocol does not support udp")
		}
		ue := &UdpEndpoint{
			conn:          packetConn,
			handler:       createOption.Handler,
			NatTimeout:    createOption.NatTimeout,
			lastActive:    p.now(),
			Dialer:        dialOption.Dialer,
			Outbound:      dialOption.Outbound,
			SniffedDomain: dialOption.SniffedDomain,
			DialTarget:    dialOption.Target,
		}
		ue.onInactive = func() {
			if p.pool.CompareAndDelete(lAddr, ue) {
				_ = ue.Close()
			}
		}
		_ue = ue
		if p.Count() >= udpEndpointPoolMaxEntries {
			if evicted := p.evictOldestEndpoint(p.now()); evicted != nil {
				_ = evicted.Close()
			}
		}
		p.pool.Store(lAddr, ue)
		// Receive UDP messages.
		go ue.start()
		isNew = true
	} else {
		ue := _ue.(*UdpEndpoint)
		ue.Touch(p.now())
	}
	return _ue.(*UdpEndpoint), isNew, nil
}

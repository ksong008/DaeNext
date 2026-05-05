/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
)

const (
	udpEndpointSweepInterval         = time.Second
	defaultUdpEndpointPoolMaxEntries = 4096
)

type UdpHandler func(data []byte, from netip.AddrPort) error

type UdpEndpoint struct {
	conn               netproxy.PacketConn
	handler            UdpHandler
	NatTimeout         time.Duration
	lastActiveUnixNano atomic.Int64
	onInactive         func()
	closeOnce          sync.Once

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
	ue.lastActiveUnixNano.Store(now.UnixNano())
}

func (ue *UdpEndpoint) lastActive() time.Time {
	return time.Unix(0, ue.lastActiveUnixNano.Load())
}

func (ue *UdpEndpoint) Expired(now time.Time) bool {
	lastActive := ue.lastActiveUnixNano.Load()
	if lastActive == 0 {
		return false
	}
	return time.Duration(now.UnixNano()-lastActive) >= ue.NatTimeout
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
	count       atomic.Int64
	maxEntries  atomic.Int64
}
type UdpEndpointOptions struct {
	Handler    UdpHandler
	NatTimeout time.Duration
	// GetTarget is useful only if the underlay does not support Full-cone.
	GetDialOption func() (option *DialOption, err error)
}

var DefaultUdpEndpointPool = NewUdpEndpointPool()

func NewUdpEndpointPool() *UdpEndpointPool {
	return NewUdpEndpointPoolWithMaxEntries(defaultUdpEndpointPoolMaxEntries)
}

func NewUdpEndpointPoolWithMaxEntries(maxEntries int) *UdpEndpointPool {
	ctx, cancel := context.WithCancel(context.Background())
	p := &UdpEndpointPool{
		ctx:       ctx,
		cancel:    cancel,
		cleanupWg: sync.WaitGroup{},
		now:       time.Now,
	}
	p.SetMaxEntries(maxEntries)
	p.startCleanup()
	return p
}

func normalizeUdpEndpointPoolMaxEntries(maxEntries int) int {
	if maxEntries <= 0 {
		return defaultUdpEndpointPoolMaxEntries
	}
	return maxEntries
}

func udpEndpointPoolTrimTarget(maxEntries int) int {
	trimWindow := maxEntries / 20
	if trimWindow < 1 {
		trimWindow = 1
	}
	target := maxEntries - trimWindow
	if target < 0 {
		return 0
	}
	return target
}

func (p *UdpEndpointPool) SetMaxEntries(maxEntries int) {
	p.maxEntries.Store(int64(normalizeUdpEndpointPoolMaxEntries(maxEntries)))
}

func (p *UdpEndpointPool) MaxEntries() int {
	return int(p.maxEntries.Load())
}

func (p *UdpEndpointPool) storeEndpoint(lAddr netip.AddrPort, ue *UdpEndpoint) {
	p.pool.Store(lAddr, ue)
	p.count.Add(1)
}

func (p *UdpEndpointPool) deleteEndpoint(lAddr netip.AddrPort, ue *UdpEndpoint) bool {
	if !p.pool.CompareAndDelete(lAddr, ue) {
		return false
	}
	p.count.Add(-1)
	return true
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
		addr := key.(netip.AddrPort)
		ue := value.(*UdpEndpoint)
		if !ue.Expired(now) {
			return true
		}
		if p.deleteEndpoint(addr, ue) {
			_ = ue.Close()
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
			if p.deleteEndpoint(addr, ue) {
				oldestKey = addr
				oldest = ue
				oldestTime = time.Time{}
				oldestSeen = true
				return false
			}
			return true
		}

		lastActive := ue.lastActive()
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
	if p.deleteEndpoint(oldestKey, oldest) {
		return oldest
	}
	return nil
}

type udpEndpointEvictionCandidate struct {
	addr       netip.AddrPort
	ue         *UdpEndpoint
	lastActive int64
}

type udpEndpointNewestHeap []udpEndpointEvictionCandidate

func (h udpEndpointNewestHeap) Len() int { return len(h) }

func (h udpEndpointNewestHeap) Less(i, j int) bool {
	return h[i].lastActive > h[j].lastActive
}

func (h udpEndpointNewestHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

func (h *udpEndpointNewestHeap) Push(x any) {
	*h = append(*h, x.(udpEndpointEvictionCandidate))
}

func (h *udpEndpointNewestHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

func (p *UdpEndpointPool) removeCandidates(candidates []udpEndpointEvictionCandidate, maxRemove int) (removed int) {
	for _, candidate := range candidates {
		if maxRemove > 0 && removed >= maxRemove {
			break
		}
		if p.deleteEndpoint(candidate.addr, candidate.ue) {
			_ = candidate.ue.Close()
			removed++
		}
	}
	return removed
}

func (p *UdpEndpointPool) trimToLimit(now time.Time) {
	maxEntries := p.MaxEntries()
	if maxEntries <= 0 {
		return
	}
	current := p.count.Load()
	if current < int64(maxEntries) {
		return
	}

	targetCount := udpEndpointPoolTrimTarget(maxEntries)
	removeBudget := int(current-int64(targetCount)) + 1
	if removeBudget < 1 {
		removeBudget = 1
	}

	nowUnixNano := now.UnixNano()
	expired := make([]udpEndpointEvictionCandidate, 0)
	oldest := make(udpEndpointNewestHeap, 0, removeBudget)

	p.pool.Range(func(key, value any) bool {
		addr := key.(netip.AddrPort)
		ue := value.(*UdpEndpoint)
		lastActive := ue.lastActiveUnixNano.Load()
		if lastActive == 0 {
			lastActive = nowUnixNano
		}
		if time.Duration(nowUnixNano-lastActive) >= ue.NatTimeout {
			expired = append(expired, udpEndpointEvictionCandidate{
				addr:       addr,
				ue:         ue,
				lastActive: lastActive,
			})
			return true
		}

		candidate := udpEndpointEvictionCandidate{
			addr:       addr,
			ue:         ue,
			lastActive: lastActive,
		}
		if len(oldest) < removeBudget {
			heap.Push(&oldest, candidate)
			return true
		}
		if candidate.lastActive < oldest[0].lastActive {
			oldest[0] = candidate
			heap.Fix(&oldest, 0)
		}
		return true
	})

	removed := p.removeCandidates(expired, removeBudget)
	if removed >= removeBudget {
		return
	}
	if len(oldest) == 0 {
		return
	}
	candidates := make([]udpEndpointEvictionCandidate, 0, len(oldest))
	for oldest.Len() > 0 {
		candidates = append(candidates, heap.Pop(&oldest).(udpEndpointEvictionCandidate))
	}
	for i, j := 0, len(candidates)-1; i < j; i, j = i+1, j-1 {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	}
	_ = p.removeCandidates(candidates, removeBudget-removed)
}

func (p *UdpEndpointPool) Close() error {
	p.cancel()
	p.cleanupWg.Wait()
	return p.Flush()
}

func (p *UdpEndpointPool) Flush() error {
	var errs []error
	p.pool.Range(func(key, value any) bool {
		addr := key.(netip.AddrPort)
		ue := value.(*UdpEndpoint)
		if p.deleteEndpoint(addr, ue) {
			if err := ue.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		return true
	})
	return errors.Join(errs...)
}

func (p *UdpEndpointPool) Remove(lAddr netip.AddrPort, udpEndpoint *UdpEndpoint) (err error) {
	if ue, ok := p.pool.Load(lAddr); ok {
		if ue != udpEndpoint {
			_ = udpEndpoint.Close()
			return fmt.Errorf("target udp endpoint is not in the pool")
		}
		if p.deleteEndpoint(lAddr, udpEndpoint) {
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

func (p *UdpEndpointPool) Count() int {
	return int(p.count.Load())
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
			Dialer:        dialOption.Dialer,
			Outbound:      dialOption.Outbound,
			SniffedDomain: dialOption.SniffedDomain,
			DialTarget:    dialOption.Target,
		}
		ue.Touch(p.now())
		ue.onInactive = func() {
			if p.deleteEndpoint(lAddr, ue) {
				_ = ue.Close()
			}
		}
		_ue = ue
		p.storeEndpoint(lAddr, ue)
		p.trimToLimit(p.now())
		// Receive UDP messages.
		go ue.start()
		isNew = true
	} else {
		ue := _ue.(*UdpEndpoint)
		ue.Touch(p.now())
	}
	return _ue.(*UdpEndpoint), isNew, nil
}

/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"golang.org/x/sys/unix"
)

const (
	anyfromSweepInterval  = time.Second
	anyfromPoolMaxEntries = 256
)

type Anyfrom struct {
	*net.UDPConn
	mu         sync.Mutex
	ttl        time.Duration
	lastActive time.Time
	closeOnce  sync.Once
	closeFunc  func() error
	// GSO support is modified from quic-go with many thanks.
	gso         bool
	gotGSOError bool
}

func (a *Anyfrom) afterWrite(err error) {
	if !a.gotGSOError && isGSOError(err) {
		a.gotGSOError = true
	}
	a.RefreshTtl()
}
func (a *Anyfrom) RefreshTtl() {
	if a.ttl <= 0 {
		return
	}
	a.mu.Lock()
	a.lastActive = time.Now()
	a.mu.Unlock()
}
func (a *Anyfrom) Touch(now time.Time) {
	if a.ttl <= 0 {
		return
	}
	a.mu.Lock()
	a.lastActive = now
	a.mu.Unlock()
}
func (a *Anyfrom) Expired(now time.Time) bool {
	if a.ttl <= 0 {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return !a.lastActive.Add(a.ttl).After(now)
}
func (a *Anyfrom) SupportGso(size int) bool {
	if size > math.MaxUint16 {
		return false
	}
	return a.gso && !a.gotGSOError
}
func (a *Anyfrom) ReadFrom(b []byte) (int, net.Addr, error) {
	defer a.RefreshTtl()
	return a.UDPConn.ReadFrom(b)
}
func (a *Anyfrom) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
	defer a.RefreshTtl()
	return a.UDPConn.ReadFromUDP(b)
}
func (a *Anyfrom) ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error) {
	defer a.RefreshTtl()
	return a.UDPConn.ReadFromUDPAddrPort(b)
}
func (a *Anyfrom) ReadMsgUDP(b []byte, oob []byte) (n int, oobn int, flags int, addr *net.UDPAddr, err error) {
	defer a.RefreshTtl()
	return a.UDPConn.ReadMsgUDP(b, oob)
}
func (a *Anyfrom) ReadMsgUDPAddrPort(b []byte, oob []byte) (n int, oobn int, flags int, addr netip.AddrPort, err error) {
	defer a.RefreshTtl()
	return a.UDPConn.ReadMsgUDPAddrPort(b, oob)
}
func (a *Anyfrom) SyscallConn() (syscall.RawConn, error) {
	defer a.RefreshTtl()
	return a.UDPConn.SyscallConn()
}
func (a *Anyfrom) WriteMsgUDP(b []byte, oob []byte, addr *net.UDPAddr) (n int, oobn int, err error) {
	defer func() { a.afterWrite(err) }()
	if a.SupportGso(len(b)) {
		return a.UDPConn.WriteMsgUDP(b, appendUDPSegmentSizeMsg(oob, uint16(len(b))), addr)
	}
	return a.UDPConn.WriteMsgUDP(b, oob, addr)
}
func (a *Anyfrom) WriteMsgUDPAddrPort(b []byte, oob []byte, addr netip.AddrPort) (n int, oobn int, err error) {
	defer func() { a.afterWrite(err) }()
	if a.SupportGso(len(b)) {
		return a.UDPConn.WriteMsgUDPAddrPort(b, appendUDPSegmentSizeMsg(oob, uint16(len(b))), addr)
	}
	return a.UDPConn.WriteMsgUDPAddrPort(b, oob, addr)
}
func (a *Anyfrom) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	defer func() { a.afterWrite(err) }()
	if a.SupportGso(len(b)) {
		n, _, err = a.UDPConn.WriteMsgUDP(b, appendUDPSegmentSizeMsg(nil, uint16(len(b))), addr.(*net.UDPAddr))
		return n, err
	}
	return a.UDPConn.WriteTo(b, addr)
}
func (a *Anyfrom) WriteToUDP(b []byte, addr *net.UDPAddr) (n int, err error) {
	defer func() { a.afterWrite(err) }()
	if a.SupportGso(len(b)) {
		n, _, err = a.UDPConn.WriteMsgUDP(b, appendUDPSegmentSizeMsg(nil, uint16(len(b))), addr)
		return n, err
	}
	return a.UDPConn.WriteToUDP(b, addr)
}
func (a *Anyfrom) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (n int, err error) {
	defer func() { a.afterWrite(err) }()
	if a.SupportGso(len(b)) {
		n, _, err = a.UDPConn.WriteMsgUDPAddrPort(b, appendUDPSegmentSizeMsg(nil, uint16(len(b))), addr)
		return n, err
	}
	return a.UDPConn.WriteToUDPAddrPort(b, addr)
}

// isGSOSupported tests if the kernel supports GSO.
// Sending with GSO might still fail later on, if the interface doesn't support it (see isGSOError).
func isGSOSupported(_ *net.UDPConn) bool {
	// TODO: We disable GSO because we haven't thought through how to design to use larger packets (we assume the max size of packet is 1500).
	// See https://github.com/daeuniverse/dae/blob/cab1e4290967340923d7d5ca52b80f781711c18e/control/control_plane.go#L721C37-L721C37.
	return false
}
func isGSOError(err error) bool {
	var serr *os.SyscallError
	if errors.As(err, &serr) {
		// EIO is returned by udp_send_skb() if the device driver does not have tx checksums enabled,
		// which is a hard requirement of UDP_SEGMENT. See:
		// https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/tree/man7/udp.7?id=806eabd74910447f21005160e90957bde4db0183#n228
		// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/udp.c?h=v6.2&id=c9c3395d5e3dcc6daee66c6908354d47bf98cb0c#n942
		return serr.Err == unix.EIO || serr.Err == unix.EINVAL
	}
	return false
}
func appendUDPSegmentSizeMsg(b []byte, size uint16) []byte {
	startLen := len(b)
	const dataLen = 2 // payload is a uint16
	b = append(b, make([]byte, unix.CmsgSpace(dataLen))...)
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[startLen]))
	h.Level = syscall.IPPROTO_UDP
	h.Type = unix.UDP_SEGMENT
	h.SetLen(unix.CmsgLen(dataLen))

	// UnixRights uses the private `data` method, but I *think* this achieves the same goal.
	offset := startLen + unix.CmsgSpace(0)
	*(*uint16)(unsafe.Pointer(&b[offset])) = size
	return b
}

// AnyfromPool is a full-cone udp listener pool
type AnyfromPool struct {
	pool      map[string]*Anyfrom
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
	cleanupWg sync.WaitGroup
	now       func() time.Time
	netns     *DaeNetns
}

var DefaultAnyfromPool = NewAnyfromPool()

func NewAnyfromPool() *AnyfromPool {
	return NewAnyfromPoolWithNetns(nil)
}

func NewAnyfromPoolWithNetns(netns *DaeNetns) *AnyfromPool {
	ctx, cancel := context.WithCancel(context.Background())
	p := &AnyfromPool{
		pool:   make(map[string]*Anyfrom, 64),
		mu:     sync.RWMutex{},
		ctx:    ctx,
		cancel: cancel,
		now:    time.Now,
		netns:  netns,
	}
	p.startCleanup()
	return p
}

func (p *AnyfromPool) daeNetns() *DaeNetns {
	if p.netns != nil {
		return p.netns
	}
	return GetDaeNetns()
}

func (p *AnyfromPool) startCleanup() {
	p.cleanupWg.Add(1)
	go func() {
		defer p.cleanupWg.Done()
		ticker := time.NewTicker(anyfromSweepInterval)
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

func (p *AnyfromPool) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.pool)
}

func (p *AnyfromPool) sweepExpired(now time.Time) {
	var expired []*Anyfrom
	p.mu.Lock()
	for key, af := range p.pool {
		if !af.Expired(now) {
			continue
		}
		delete(p.pool, key)
		expired = append(expired, af)
	}
	p.mu.Unlock()
	for _, af := range expired {
		_ = af.Close()
	}
}

func (p *AnyfromPool) evictOldestLocked(now time.Time) *Anyfrom {
	var (
		oldestKey  string
		oldest     *Anyfrom
		oldestTime time.Time
		oldestSeen bool
	)

	for key, af := range p.pool {
		if af.Expired(now) {
			delete(p.pool, key)
			return af
		}

		af.mu.Lock()
		lastActive := af.lastActive
		af.mu.Unlock()
		if !oldestSeen || lastActive.Before(oldestTime) {
			oldestKey = key
			oldest = af
			oldestTime = lastActive
			oldestSeen = true
		}
	}

	if !oldestSeen {
		return nil
	}
	delete(p.pool, oldestKey)
	return oldest
}

func (p *AnyfromPool) Close() error {
	p.cancel()
	p.cleanupWg.Wait()
	return p.Flush()
}

func (p *AnyfromPool) Flush() error {
	var errs []error
	p.mu.Lock()
	all := p.pool
	p.pool = make(map[string]*Anyfrom, 64)
	p.mu.Unlock()
	for _, af := range all {
		if err := af.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func udpConnFromPacketConn(pc net.PacketConn) (*net.UDPConn, error) {
	uConn, ok := pc.(*net.UDPConn)
	if ok {
		return uConn, nil
	}
	if pc != nil {
		_ = pc.Close()
	}
	return nil, fmt.Errorf("expected *net.UDPConn, got %T", pc)
}

func (p *AnyfromPool) GetOrCreate(lAddr string, ttl time.Duration) (conn *Anyfrom, isNew bool, err error) {
	p.mu.RLock()
	af, ok := p.pool[lAddr]
	if !ok {
		p.mu.RUnlock()
		p.mu.Lock()
		defer p.mu.Unlock()
		if af, ok = p.pool[lAddr]; ok {
			return af, false, nil
		}
		// Create an Anyfrom.
		isNew = true
		d := net.ListenConfig{
			Control: func(network string, address string, c syscall.RawConn) error {
				return dialer.TransparentControl(c)
			},
			KeepAlive: 0,
		}
		var pc net.PacketConn
		daens := p.daeNetns()
		if daens == nil {
			return nil, true, errors.New("dae netns is not initialized")
		}
		if err = daens.With(func() error {
			var listenErr error
			pc, listenErr = d.ListenPacket(context.Background(), "udp", lAddr)
			return listenErr
		}); err != nil {
			return nil, true, err
		}
		uConn, err := udpConnFromPacketConn(pc)
		if err != nil {
			return nil, true, err
		}
		af = &Anyfrom{
			UDPConn:     uConn,
			ttl:         ttl,
			lastActive:  p.now(),
			closeFunc:   uConn.Close,
			gotGSOError: false,
			gso:         isGSOSupported(uConn),
		}

		if ttl > 0 {
			if len(p.pool) >= anyfromPoolMaxEntries {
				if evicted := p.evictOldestLocked(p.now()); evicted != nil {
					_ = evicted.Close()
				}
			}
			p.pool[lAddr] = af
		}
		return af, true, nil
	} else {
		af.RefreshTtl()
		p.mu.RUnlock()
		return af, false, nil
	}
}

func (a *Anyfrom) Close() error {
	var err error
	a.closeOnce.Do(func() {
		if a.closeFunc != nil {
			err = a.closeFunc()
			return
		}
		if a.UDPConn != nil {
			err = a.UDPConn.Close()
		}
	})
	return err
}

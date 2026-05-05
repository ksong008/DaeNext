/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

type fakePacketConn struct {
	closeCount int
}

func (f *fakePacketConn) Read([]byte) (int, error)  { return 0, nil }
func (f *fakePacketConn) Write([]byte) (int, error) { return 0, nil }
func (f *fakePacketConn) ReadFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, nil
}
func (f *fakePacketConn) WriteTo([]byte, string) (int, error) { return 0, nil }
func (f *fakePacketConn) Close() error {
	f.closeCount++
	return nil
}
func (f *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (f *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }

type parkedPacketConn struct {
	closeCh    chan struct{}
	closeOnce  sync.Once
	closeCount atomic.Int32
}

func newParkedPacketConn() *parkedPacketConn {
	return &parkedPacketConn{
		closeCh: make(chan struct{}),
	}
}

func (p *parkedPacketConn) Read([]byte) (int, error)  { return 0, errors.New("unsupported") }
func (p *parkedPacketConn) Write([]byte) (int, error) { return 0, errors.New("unsupported") }
func (p *parkedPacketConn) ReadFrom([]byte) (int, netip.AddrPort, error) {
	<-p.closeCh
	return 0, netip.AddrPort{}, net.ErrClosed
}
func (p *parkedPacketConn) WriteTo([]byte, string) (int, error) { return 0, nil }
func (p *parkedPacketConn) Close() error {
	p.closeOnce.Do(func() {
		p.closeCount.Add(1)
		close(p.closeCh)
	})
	return nil
}
func (p *parkedPacketConn) SetDeadline(time.Time) error      { return nil }
func (p *parkedPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (p *parkedPacketConn) SetWriteDeadline(time.Time) error { return nil }

type closingPacketConn struct{}

func (c *closingPacketConn) Read([]byte) (int, error)  { return 0, net.ErrClosed }
func (c *closingPacketConn) Write([]byte) (int, error) { return 0, net.ErrClosed }
func (c *closingPacketConn) ReadFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, net.ErrClosed
}
func (c *closingPacketConn) WriteTo([]byte, string) (int, error) { return 0, net.ErrClosed }
func (c *closingPacketConn) Close() error                        { return nil }
func (c *closingPacketConn) SetDeadline(time.Time) error         { return nil }
func (c *closingPacketConn) SetReadDeadline(time.Time) error     { return nil }
func (c *closingPacketConn) SetWriteDeadline(time.Time) error    { return nil }

type fakePlainConn struct {
	closeCount int
}

func (f *fakePlainConn) Read([]byte) (int, error)         { return 0, nil }
func (f *fakePlainConn) Write([]byte) (int, error)        { return 0, nil }
func (f *fakePlainConn) Close() error                     { f.closeCount++; return nil }
func (f *fakePlainConn) SetDeadline(time.Time) error      { return nil }
func (f *fakePlainConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakePlainConn) SetWriteDeadline(time.Time) error { return nil }

type fakeUnsupportedPacketDialer struct {
	conn netproxy.Conn
}

func (f *fakeUnsupportedPacketDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return f.conn, nil
}

type fakeCountingPacketDialer struct {
	calls atomic.Int32
}

func (f *fakeCountingPacketDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	f.calls.Add(1)
	return newParkedPacketConn(), nil
}

type fakeClosingPacketDialer struct{}

func (f *fakeClosingPacketDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return &closingPacketConn{}, nil
}

func newTestUdpEndpoint(conn netproxy.PacketConn, natTimeout time.Duration, lastActive time.Time) *UdpEndpoint {
	ue := &UdpEndpoint{
		conn:       conn,
		NatTimeout: natTimeout,
	}
	ue.Touch(lastActive)
	return ue
}

func TestUdpEndpointPoolSweepExpiredEndpoints(t *testing.T) {
	pool := NewUdpEndpointPool()
	defer pool.Close()

	now := time.Now()
	pool.now = func() time.Time { return now }

	addr := netip.MustParseAddrPort("127.0.0.1:12345")
	conn := &fakePacketConn{}
	ue := newTestUdpEndpoint(conn, time.Second, now.Add(-2*time.Second))
	pool.storeEndpoint(addr, ue)

	pool.sweepExpiredEndpoints(now)
	if _, ok := pool.Get(addr); ok {
		t.Fatal("expected expired endpoint to be removed from pool")
	}
	if conn.closeCount != 1 {
		t.Fatalf("expected expired endpoint conn to be closed once, got %d", conn.closeCount)
	}
}

func TestUdpEndpointPoolOnInactiveRemovesEndpoint(t *testing.T) {
	pool := NewUdpEndpointPool()
	defer pool.Close()

	addr := netip.MustParseAddrPort("127.0.0.1:12346")
	conn := &fakePacketConn{}
	ue := newTestUdpEndpoint(conn, time.Second, time.Now())
	ue.onInactive = func() {
		if pool.deleteEndpoint(addr, ue) {
			_ = ue.Close()
		}
	}
	pool.storeEndpoint(addr, ue)

	ue.onInactive()
	if _, ok := pool.Get(addr); ok {
		t.Fatal("expected endpoint to be removed by inactive callback")
	}
	if conn.closeCount != 1 {
		t.Fatalf("expected conn to be closed once, got %d", conn.closeCount)
	}
}

func TestUdpEndpointPoolCloseClosesEntries(t *testing.T) {
	pool := NewUdpEndpointPool()

	addr := netip.MustParseAddrPort("127.0.0.1:12347")
	conn := &fakePacketConn{}
	pool.storeEndpoint(addr, newTestUdpEndpoint(conn, time.Second, time.Now()))

	if err := pool.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := pool.Get(addr); ok {
		t.Fatal("expected pool close to remove endpoint")
	}
	if conn.closeCount != 1 {
		t.Fatalf("expected pool close to close conn once, got %d", conn.closeCount)
	}
}

func TestUdpEndpointPoolEvictOldestEndpoint(t *testing.T) {
	pool := NewUdpEndpointPool()
	defer pool.Close()

	now := time.Now()
	pool.now = func() time.Time { return now }

	oldestAddr := netip.MustParseAddrPort("127.0.0.1:20001")
	oldestConn := &fakePacketConn{}
	pool.storeEndpoint(oldestAddr, newTestUdpEndpoint(oldestConn, time.Minute, now.Add(-2*time.Minute)))

	newerAddr := netip.MustParseAddrPort("127.0.0.1:20002")
	newerConn := &fakePacketConn{}
	pool.storeEndpoint(newerAddr, newTestUdpEndpoint(newerConn, time.Minute, now.Add(-30*time.Second)))

	evicted := pool.evictOldestEndpoint(now)
	if evicted == nil {
		t.Fatal("expected an endpoint to be evicted")
	}
	if err := evicted.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := pool.Get(oldestAddr); ok {
		t.Fatal("expected oldest endpoint to be removed")
	}
	if _, ok := pool.Get(newerAddr); !ok {
		t.Fatal("expected newer endpoint to remain")
	}
	if oldestConn.closeCount != 1 {
		t.Fatalf("expected oldest endpoint conn to be closed once, got %d", oldestConn.closeCount)
	}
	if newerConn.closeCount != 0 {
		t.Fatalf("expected newer endpoint conn to remain open, got %d closes", newerConn.closeCount)
	}
}

func TestUdpEndpointPoolClosesConnWhenPacketConnUnsupported(t *testing.T) {
	pool := NewUdpEndpointPool()
	defer pool.Close()

	conn := &fakePlainConn{}
	d := dialer.NewDialer(
		&fakeUnsupportedPacketDialer{conn: conn},
		&dialer.GlobalOption{Log: logrus.New()},
		dialer.InstanceOption{DisableCheck: true},
		&dialer.Property{},
	)
	_, _, err := pool.GetOrCreate(netip.MustParseAddrPort("127.0.0.1:20003"), &UdpEndpointOptions{
		Handler: func([]byte, netip.AddrPort) error { return nil },
		GetDialOption: func() (*DialOption, error) {
			return &DialOption{
				Dialer:  d,
				Network: "udp",
				Target:  "127.0.0.1:53",
			}, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "protocol does not support udp") {
		t.Fatalf("GetOrCreate() error = %v, want unsupported udp", err)
	}
	if conn.closeCount != 1 {
		t.Fatalf("unsupported conn close count = %d, want 1", conn.closeCount)
	}
}

func TestUdpEndpointPoolTrimToLimitBatchesEvictions(t *testing.T) {
	pool := NewUdpEndpointPoolWithMaxEntries(20)
	defer pool.Close()

	now := time.Now()
	pool.now = func() time.Time { return now }

	for i := 0; i < 20; i++ {
		addr := netip.MustParseAddrPort("127.0.0.1:" + strconv.Itoa(30000+i))
		pool.storeEndpoint(addr, newTestUdpEndpoint(&fakePacketConn{}, time.Minute, now.Add(-time.Duration(i)*time.Second)))
	}
	if got := pool.Count(); got != 20 {
		t.Fatalf("Count() before trim = %d, want 20", got)
	}

	pool.trimToLimit(now)

	wantMax := udpEndpointPoolTrimTarget(pool.MaxEntries())
	if got := pool.Count(); got > wantMax {
		t.Fatalf("Count() after trim = %d, want <= %d", got, wantMax)
	}
}

func TestUdpEndpointPoolConcurrentGetOrCreateSameAddrCreatesOnce(t *testing.T) {
	pool := NewUdpEndpointPoolWithMaxEntries(32)
	defer pool.Close()

	rawDialer := &fakeCountingPacketDialer{}
	d := dialer.NewDialer(
		rawDialer,
		&dialer.GlobalOption{Log: logrus.New()},
		dialer.InstanceOption{DisableCheck: true},
		&dialer.Property{},
	)

	addr := netip.MustParseAddrPort("127.0.0.1:31000")
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := pool.GetOrCreate(addr, &UdpEndpointOptions{
				Handler: func([]byte, netip.AddrPort) error { return nil },
				GetDialOption: func() (*DialOption, error) {
					return &DialOption{
						Dialer:  d,
						Network: "udp",
						Target:  "127.0.0.1:53",
					}, nil
				},
			})
			if err != nil {
				t.Errorf("GetOrCreate() error = %v", err)
			}
		}()
	}
	wg.Wait()

	if got := rawDialer.calls.Load(); got != 1 {
		t.Fatalf("DialContext() calls = %d, want 1", got)
	}
	if got := pool.Count(); got != 1 {
		t.Fatalf("Count() after concurrent create = %d, want 1", got)
	}
}

func benchmarkUdpEndpointPoolTrimToLimit(b *testing.B, maxEntries int) {
	b.Helper()
	b.ReportAllocs()

	baseAddr := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	now := time.Unix(1_746_000_000, 0)
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		pool := NewUdpEndpointPoolWithMaxEntries(maxEntries)
		pool.now = func() time.Time { return now }
		for j := 0; j < maxEntries; j++ {
			addr := netip.AddrPortFrom(baseAddr, uint16(20_000+j))
			pool.storeEndpoint(addr, newTestUdpEndpoint(&fakePacketConn{}, time.Minute, now.Add(-time.Duration(j)*time.Millisecond)))
		}
		b.StartTimer()
		pool.trimToLimit(now)
		b.StopTimer()
		_ = pool.Close()
	}
}

func BenchmarkUdpEndpointPoolTrimToLimit4096(b *testing.B) {
	benchmarkUdpEndpointPoolTrimToLimit(b, 4096)
}

func BenchmarkUdpEndpointPoolTrimToLimit8192(b *testing.B) {
	benchmarkUdpEndpointPoolTrimToLimit(b, 8192)
}

func BenchmarkUdpEndpointPoolGetOrCreateSameAddrParallel(b *testing.B) {
	pool := NewUdpEndpointPoolWithMaxEntries(32)
	defer pool.Close()

	d := dialer.NewDialer(
		&fakeCountingPacketDialer{},
		&dialer.GlobalOption{Log: logrus.New()},
		dialer.InstanceOption{DisableCheck: true},
		&dialer.Property{},
	)
	addr := netip.MustParseAddrPort("127.0.0.1:32000")
	opt := &UdpEndpointOptions{
		Handler: func([]byte, netip.AddrPort) error { return nil },
		GetDialOption: func() (*DialOption, error) {
			return &DialOption{
				Dialer:  d,
				Network: "udp",
				Target:  "127.0.0.1:53",
			}, nil
		},
	}

	if _, _, err := pool.GetOrCreate(addr, opt); err != nil {
		b.Fatalf("warmup GetOrCreate() error = %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, _, err := pool.GetOrCreate(addr, opt); err != nil {
				b.Fatalf("GetOrCreate() error = %v", err)
			}
		}
	})
}

func TestUdpEndpointPoolLocalMemoryProfile(t *testing.T) {
	if os.Getenv("DAE_LOCAL_UDP_ENDPOINT_MEMPROFILE") == "" {
		t.Skip("set DAE_LOCAL_UDP_ENDPOINT_MEMPROFILE=1 for local-only memory profiling")
	}

	type sample struct {
		name string
		size int
	}
	samples := []sample{
		{name: "2048", size: 2048},
		{name: "4096", size: 4096},
		{name: "8192", size: 8192},
	}

	baseStats := readRuntimeMemStats()
	baseGoroutines := runtime.NumGoroutine()
	t.Logf("baseline heap_alloc=%d stack_inuse=%d heap_objects=%d goroutines=%d",
		baseStats.HeapAlloc, baseStats.StackInuse, baseStats.HeapObjects, baseGoroutines)

	for _, sample := range samples {
		stats, goroutines, cleanupStats, cleanupGoroutines := profileUdpEndpointPoolMemory(t, sample.size)
		t.Logf("pool=%s endpoints=%d heap_alloc_delta=%d stack_inuse_delta=%d heap_objects_delta=%d goroutines_delta=%d cleanup_heap_delta=%d cleanup_stack_delta=%d cleanup_goroutines_delta=%d",
			sample.name,
			sample.size,
			int64(stats.HeapAlloc)-int64(baseStats.HeapAlloc),
			int64(stats.StackInuse)-int64(baseStats.StackInuse),
			int64(stats.HeapObjects)-int64(baseStats.HeapObjects),
			goroutines-baseGoroutines,
			int64(cleanupStats.HeapAlloc)-int64(baseStats.HeapAlloc),
			int64(cleanupStats.StackInuse)-int64(baseStats.StackInuse),
			cleanupGoroutines-baseGoroutines,
		)
	}
}

func profileUdpEndpointPoolMemory(t *testing.T, size int) (runtime.MemStats, int, runtime.MemStats, int) {
	t.Helper()

	pool := NewUdpEndpointPoolWithMaxEntries(size + 1)
	d := dialer.NewDialer(
		&fakeCountingPacketDialer{},
		&dialer.GlobalOption{Log: logrus.New()},
		dialer.InstanceOption{DisableCheck: true},
		&dialer.Property{},
	)

	for i := 0; i < size; i++ {
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(10000+i))
		_, _, err := pool.GetOrCreate(addr, &UdpEndpointOptions{
			Handler: func([]byte, netip.AddrPort) error { return nil },
			GetDialOption: func() (*DialOption, error) {
				return &DialOption{
					Dialer:  d,
					Network: "udp",
					Target:  "127.0.0.1:53",
				}, nil
			},
		})
		if err != nil {
			t.Fatalf("GetOrCreate(%d) error = %v", i, err)
		}
	}
	if got := pool.Count(); got != size {
		t.Fatalf("pool.Count() = %d, want %d", got, size)
	}

	time.Sleep(50 * time.Millisecond)
	stats := readRuntimeMemStats()
	goroutines := runtime.NumGoroutine()

	if err := pool.Close(); err != nil {
		t.Fatalf("pool.Close() error = %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	cleanupStats := readRuntimeMemStats()
	cleanupGoroutines := runtime.NumGoroutine()
	return stats, goroutines, cleanupStats, cleanupGoroutines
}

func readRuntimeMemStats() runtime.MemStats {
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats
}

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"
	"time"
)

type fakePacketConn struct {
	closeCount int
}

func (f *fakePacketConn) Read([]byte) (int, error) { return 0, nil }
func (f *fakePacketConn) Write([]byte) (int, error) { return 0, nil }
func (f *fakePacketConn) ReadFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, nil
}
func (f *fakePacketConn) WriteTo([]byte, string) (int, error) { return 0, nil }
func (f *fakePacketConn) Close() error {
	f.closeCount++
	return nil
}
func (f *fakePacketConn) SetDeadline(time.Time) error { return nil }
func (f *fakePacketConn) SetReadDeadline(time.Time) error { return nil }
func (f *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestUdpEndpointPoolSweepExpiredEndpoints(t *testing.T) {
	pool := NewUdpEndpointPool()
	defer pool.Close()

	now := time.Now()
	pool.now = func() time.Time { return now }

	addr := netip.MustParseAddrPort("127.0.0.1:12345")
	conn := &fakePacketConn{}
	ue := &UdpEndpoint{
		conn:       conn,
		NatTimeout: time.Second,
		lastActive: now.Add(-2 * time.Second),
	}
	pool.pool.Store(addr, ue)

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
	ue := &UdpEndpoint{
		conn:       conn,
		NatTimeout: time.Second,
		lastActive: time.Now(),
	}
	ue.onInactive = func() {
		if pool.pool.CompareAndDelete(addr, ue) {
			_ = ue.Close()
		}
	}
	pool.pool.Store(addr, ue)

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
	pool.pool.Store(addr, &UdpEndpoint{
		conn:       conn,
		NatTimeout: time.Second,
		lastActive: time.Now(),
	})

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
	pool.pool.Store(oldestAddr, &UdpEndpoint{
		conn:       oldestConn,
		NatTimeout: time.Minute,
		lastActive: now.Add(-2 * time.Minute),
	})

	newerAddr := netip.MustParseAddrPort("127.0.0.1:20002")
	newerConn := &fakePacketConn{}
	pool.pool.Store(newerAddr, &UdpEndpoint{
		conn:       newerConn,
		NatTimeout: time.Minute,
		lastActive: now.Add(-time.Minute),
	})

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

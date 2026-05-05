/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

type fakeStdPacketConn struct {
	closed bool
}

func (f *fakeStdPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("not implemented")
}

func (f *fakeStdPacketConn) WriteTo([]byte, net.Addr) (int, error) {
	return 0, errors.New("not implemented")
}

func (f *fakeStdPacketConn) Close() error {
	f.closed = true
	return nil
}

func (f *fakeStdPacketConn) LocalAddr() net.Addr {
	return nil
}

func (f *fakeStdPacketConn) SetDeadline(time.Time) error {
	return nil
}

func (f *fakeStdPacketConn) SetReadDeadline(time.Time) error {
	return nil
}

func (f *fakeStdPacketConn) SetWriteDeadline(time.Time) error {
	return nil
}

func TestUDPConnFromPacketConnRejectsNonUDPConn(t *testing.T) {
	pc := &fakeStdPacketConn{}
	conn, err := udpConnFromPacketConn(pc)
	if err == nil {
		t.Fatal("expected non-UDP packet conn to be rejected")
	}
	if conn != nil {
		t.Fatalf("conn = %#v, want nil", conn)
	}
	if !pc.closed {
		t.Fatal("expected rejected packet conn to be closed")
	}
}

func TestAnyfromPoolSweepExpired(t *testing.T) {
	pool := NewAnyfromPool()
	defer pool.Close()

	now := time.Now()
	pool.now = func() time.Time { return now }

	closeCount := 0
	pool.pool["127.0.0.1:12345"] = &Anyfrom{
		ttl:        time.Second,
		lastActive: now.Add(-2 * time.Second),
		closeFunc: func() error {
			closeCount++
			return nil
		},
	}

	pool.sweepExpired(now)
	if pool.Count() != 0 {
		t.Fatalf("expected expired anyfrom to be removed, got %d entries", pool.Count())
	}
	if closeCount != 1 {
		t.Fatalf("expected expired anyfrom to be closed once, got %d", closeCount)
	}
}

func TestAnyfromPoolDoesNotSweepFreshEntries(t *testing.T) {
	pool := NewAnyfromPool()
	defer pool.Close()

	now := time.Now()
	pool.now = func() time.Time { return now }

	pool.pool["127.0.0.1:12346"] = &Anyfrom{
		ttl:        time.Second,
		lastActive: now,
		closeFunc:  func() error { return nil },
	}

	pool.sweepExpired(now)
	if pool.Count() != 1 {
		t.Fatalf("expected fresh anyfrom to remain, got %d entries", pool.Count())
	}
}

func TestAnyfromRefreshTtl(t *testing.T) {
	now := time.Now()
	af := &Anyfrom{
		ttl:        time.Second,
		lastActive: now.Add(-time.Minute),
	}
	af.Touch(now)
	if af.Expired(now) {
		t.Fatal("expected touched anyfrom to be active")
	}
}

func TestAnyfromPoolCloseClosesEntries(t *testing.T) {
	pool := NewAnyfromPool()

	closeCount := 0
	pool.pool["127.0.0.1:12347"] = &Anyfrom{
		ttl:        time.Second,
		lastActive: time.Now(),
		closeFunc: func() error {
			closeCount++
			return nil
		},
	}

	if err := pool.Close(); err != nil {
		t.Fatal(err)
	}
	if closeCount != 1 {
		t.Fatalf("expected pool close to close entry once, got %d", closeCount)
	}
	if pool.Count() != 0 {
		t.Fatalf("expected pool to be empty after close, got %d entries", pool.Count())
	}
}

func TestAnyfromPoolEvictsOldestWhenFull(t *testing.T) {
	pool := NewAnyfromPool()
	defer pool.Close()

	now := time.Now()
	pool.now = func() time.Time { return now }

	closeCount := 0
	for i := 0; i < anyfromPoolMaxEntries; i++ {
		pool.pool[fmt.Sprintf("127.0.0.1:%d", 20000+i)] = &Anyfrom{
			ttl:        time.Minute,
			lastActive: now.Add(time.Duration(-i) * time.Second),
			closeFunc: func() error {
				closeCount++
				return nil
			},
		}
	}

	evicted := pool.evictOldestLocked(now)
	if evicted == nil {
		t.Fatal("expected oldest entry to be evicted")
	}
	if pool.Count() != anyfromPoolMaxEntries-1 {
		t.Fatalf("expected one entry to be evicted, got %d entries", pool.Count())
	}
	if err := evicted.Close(); err != nil {
		t.Fatal(err)
	}
	if closeCount != 1 {
		t.Fatalf("expected evicted entry to close once, got %d", closeCount)
	}
}

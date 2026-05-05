/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package sniffing

import (
	"io"
	"sync"
	"testing"
	"time"
)

func TestDataReturnsDetachedCopies(t *testing.T) {
	sniffer := NewPacketSniffer([]byte("hello"), time.Second)
	data := sniffer.Data()
	if len(data) != 1 || string(data[0]) != "hello" {
		t.Fatalf("unexpected detached data: %q", data)
	}
	if len(sniffer.data) != 1 || len(sniffer.data[0]) != 5 {
		t.Fatalf("unexpected internal data: %q", sniffer.data)
	}
	if &data[0][0] == &sniffer.data[0][0] {
		t.Fatal("expected Data() to detach returned bytes from internal buffer")
	}

	data[0][0] = 'H'
	if string(sniffer.data[0]) != "hello" {
		t.Fatalf("expected detached mutation to leave internal data unchanged, got %q", sniffer.data[0])
	}
}

func TestCloseReturnsBufferEvenWhenUnread(t *testing.T) {
	sniffer := NewPacketSniffer([]byte("hello"), time.Second)
	if err := sniffer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sniffer.Close(); err != nil {
		t.Fatal(err)
	}
	if sniffer.buf != nil {
		t.Fatal("expected Close() to release the internal buffer")
	}
	if sniffer.data != nil {
		t.Fatal("expected Close() to clear retained packet slices")
	}
}

type blockingSniffReader struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *blockingSniffReader) Read([]byte) (int, error) {
	r.once.Do(func() {
		close(r.started)
	})
	<-r.release
	return 0, io.ErrClosedPipe
}

func TestCloseWaitsForActiveStreamReadBeforeReleasingBuffer(t *testing.T) {
	reader := &blockingSniffReader{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	sniffer := NewStreamSniffer(reader, time.Second)
	sniffDone := make(chan struct{})
	go func() {
		_, _ = sniffer.SniffTcp()
		close(sniffDone)
	}()
	<-reader.started

	closeDone := make(chan struct{})
	go func() {
		if err := sniffer.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
		close(closeDone)
	}()

	select {
	case <-closeDone:
		t.Fatal("Close returned before active read finished")
	case <-time.After(20 * time.Millisecond):
	}

	close(reader.release)
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("Close did not return after active read finished")
	}
	select {
	case <-sniffDone:
	case <-time.After(time.Second):
		t.Fatal("SniffTcp did not return after reader release")
	}
	if sniffer.buf != nil {
		t.Fatal("expected Close() to release the internal buffer")
	}
}

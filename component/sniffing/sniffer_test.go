/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package sniffing

import (
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

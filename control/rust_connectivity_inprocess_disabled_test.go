//go:build !linux || !cgo || !rust_inprocess

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestRustOutboundConnectivityUpdateIOParsesOwnerReport(t *testing.T) {
	const mapID uint32 = 1001
	var response [8]byte
	response[0] = 0
	response[1] = 1
	response[2] = 1
	response[3] = 1
	binary.LittleEndian.PutUint32(response[4:8], mapID)

	var stdin bytes.Buffer
	stdout := bytes.NewReader(response[:])
	result := rustOutboundConnectivityUpdateIO(&stdin, stdout, mapID, 2, 6, 4, true, true, false)
	if result.err != nil {
		t.Fatal(result.err)
	}
	if stdin.Len() != 8 {
		t.Fatalf("request length = %d, want 8", stdin.Len())
	}
	report := result.report
	if report.mapID != mapID || !report.mapChanged || !report.accepted || !report.changed || report.skipped || report.entries != 1 {
		t.Fatalf("connectivity report = %+v, want changed accepted owner report", report)
	}
}

func TestRustOutboundConnectivityUpdateIOParsesDryrunNoop(t *testing.T) {
	const mapID uint32 = 1001
	var response [8]byte
	response[0] = 0
	binary.LittleEndian.PutUint32(response[4:8], mapID)

	var stdin bytes.Buffer
	stdout := bytes.NewReader(response[:])
	result := rustOutboundConnectivityUpdateIO(&stdin, stdout, mapID, 2, 6, 4, true, false, true)
	if result.err != nil {
		t.Fatal(result.err)
	}
	report := result.report
	if report.mapChanged || report.accepted || report.changed || !report.skipped || report.entries != 0 {
		t.Fatalf("connectivity dryrun report = %+v, want rejected skipped no-op", report)
	}
}

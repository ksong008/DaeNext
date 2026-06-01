//go:build !linux || !cgo || !rust_inprocess

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bufio"
	"bytes"
	"encoding/json"
	"testing"
)

func TestRustDomainRoutingOwnerUpdateIOParsesResidentReport(t *testing.T) {
	const mapID uint32 = 1001
	response := []byte(`{"status":"pass","loader":"rust","scope":"domain-routing-map-owner","owner":"dae-control","op":"sync_owner","map_id":1001,"entries_updated":1,"entries_deleted":0,"owner_count":1,"ip_count":1}` + "\n")
	var stdin bytes.Buffer
	result := rustDomainRoutingOwnerUpdateIO(&stdin, bufio.NewReader(bytes.NewReader(response)), rustDomainRoutingOwnerRequest{
		Op:       "sync_owner",
		MapID:    mapID,
		OwnerKey: "q=example.test|type=A|class=IN",
		Bitmap:   [32]uint32{0x1},
		IPs:      [][4]uint32{{0, 0, 65535, 1}},
	})
	if result.err != nil {
		t.Fatal(result.err)
	}
	var request rustDomainRoutingOwnerRequest
	if err := json.Unmarshal(stdin.Bytes(), &request); err != nil {
		t.Fatalf("decode written request: %v", err)
	}
	if request.Op != "sync_owner" || request.MapID != mapID || request.OwnerKey == "" || len(request.IPs) != 1 {
		t.Fatalf("request = %+v, want sync owner map request", request)
	}
	if result.response.Owner != "dae-control" || result.response.EntriesUpdated != 1 || result.response.OwnerCount != 1 {
		t.Fatalf("response = %+v, want dae-control owner report", result.response)
	}
}

func TestRustDomainRoutingOwnerUpdateIORejectsWrongOwnerMarker(t *testing.T) {
	response := []byte(`{"status":"pass","owner":"other","op":"sync_owner","map_id":7}` + "\n")
	var stdin bytes.Buffer
	result := rustDomainRoutingOwnerUpdateIO(&stdin, bufio.NewReader(bytes.NewReader(response)), rustDomainRoutingOwnerRequest{
		Op:    "sync_owner",
		MapID: 7,
	})
	if result.err == nil {
		t.Fatal("expected wrong owner marker error")
	}
}

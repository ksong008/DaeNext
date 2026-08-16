package main

import (
	"bytes"
	"testing"
)

type fixtureExtension struct {
	typeID uint16
	data   []byte
}

func TestNormalizeClientHelloRecordLeavesCleanRecordUnchanged(t *testing.T) {
	record := buildClientHelloRecord(
		[]uint16{0x1301, 0x1302, 0x1303},
		[]fixtureExtension{{typeID: 0x0017}, {typeID: 0x0015, data: make([]byte, 4)}},
	)

	got, err := normalizeClientHelloRecord(record)
	if err != nil {
		t.Fatalf("normalize clean record: %v", err)
	}
	if !bytes.Equal(got, record) {
		t.Fatal("clean record changed")
	}
}

func TestNormalizeClientHelloRecordDeduplicatesCipherAndPreservesEMS(t *testing.T) {
	record := buildClientHelloRecord(
		[]uint16{0x1301, 0x1302, 0x1302, 0x1303},
		[]fixtureExtension{{typeID: 0x0017}, {typeID: 0x0015, data: make([]byte, 4)}},
	)
	want := buildClientHelloRecord(
		[]uint16{0x1301, 0x1302, 0x1303},
		[]fixtureExtension{{typeID: 0x0017}, {typeID: 0x0015, data: make([]byte, 6)}},
	)

	got, err := normalizeClientHelloRecord(record)
	if err != nil {
		t.Fatalf("normalize cipher duplicate: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("cipher normalization did not preserve EMS and compensate padding")
	}
}

func TestNormalizeClientHelloRecordDeduplicatesSignatureScheme(t *testing.T) {
	record := buildClientHelloRecord(
		[]uint16{0x1301, 0x1302},
		[]fixtureExtension{
			{typeID: 0x000d, data: signatureSchemes(0x0403, 0x0805, 0x0805, 0x0401)},
			{typeID: 0x0017},
			{typeID: 0x0015, data: make([]byte, 2)},
		},
	)
	want := buildClientHelloRecord(
		[]uint16{0x1301, 0x1302},
		[]fixtureExtension{
			{typeID: 0x000d, data: signatureSchemes(0x0403, 0x0805, 0x0401)},
			{typeID: 0x0017},
			{typeID: 0x0015, data: make([]byte, 4)},
		},
	)

	got, err := normalizeClientHelloRecord(record)
	if err != nil {
		t.Fatalf("normalize signature duplicate: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("signature normalization did not preserve EMS and compensate padding")
	}
}

func TestNormalizeClientHelloRecordCompensatesAllRemovedBytes(t *testing.T) {
	record := buildClientHelloRecord(
		[]uint16{0x1301, 0x1302, 0x1302, 0x1303},
		[]fixtureExtension{
			{typeID: 0x000d, data: signatureSchemes(0x0403, 0x0805, 0x0805, 0x0401)},
			{typeID: 0x0015, data: make([]byte, 3)},
		},
	)
	want := buildClientHelloRecord(
		[]uint16{0x1301, 0x1302, 0x1303},
		[]fixtureExtension{
			{typeID: 0x000d, data: signatureSchemes(0x0403, 0x0805, 0x0401)},
			{typeID: 0x0015, data: make([]byte, 7)},
		},
	)

	got, err := normalizeClientHelloRecord(record)
	if err != nil {
		t.Fatalf("normalize combined duplicates: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("combined normalization did not compensate every removed byte")
	}
}

func TestNormalizeMalformedRecordsReturnErrors(t *testing.T) {
	cipherBlockAtEnd := make([]byte, 0, 39)
	cipherBlockAtEnd = append(cipherBlockAtEnd, 0x03, 0x03)
	cipherBlockAtEnd = append(cipherBlockAtEnd, make([]byte, 32)...)
	cipherBlockAtEnd = append(cipherBlockAtEnd, 0x00)
	cipherBlockAtEnd = appendUint16(cipherBlockAtEnd, 2)
	cipherBlockAtEnd = appendUint16(cipherBlockAtEnd, 0x1301)

	cases := []struct {
		name   string
		record []byte
	}{
		{name: "empty"},
		{name: "record shorter than declared", record: []byte{0x16, 0x03, 0x01, 0x00, 0x01}},
		{name: "not a handshake record", record: []byte{0x15, 0x03, 0x01, 0x00, 0x00}},
		{name: "handshake missing", record: []byte{0x16, 0x03, 0x01, 0x00, 0x00}},
		{name: "cipher block ends at record end", record: wrapClientHelloBody(cipherBlockAtEnd)},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := normalizeClientHelloRecord(testCase.record); err == nil {
				t.Fatal("malformed record was accepted")
			}
		})
	}
}

func buildClientHelloRecord(ciphers []uint16, extensions []fixtureExtension) []byte {
	body := make([]byte, 0, 128)
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)
	body = appendUint16(body, len(ciphers)*2)
	for _, cipher := range ciphers {
		body = appendUint16(body, int(cipher))
	}
	body = append(body, 0x01, 0x00)

	extensionBlock := make([]byte, 0, 64)
	for _, extension := range extensions {
		extensionBlock = appendUint16(extensionBlock, int(extension.typeID))
		extensionBlock = appendUint16(extensionBlock, len(extension.data))
		extensionBlock = append(extensionBlock, extension.data...)
	}
	body = appendUint16(body, len(extensionBlock))
	body = append(body, extensionBlock...)
	return wrapClientHelloBody(body)
}

func wrapClientHelloBody(body []byte) []byte {
	handshake := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	record := []byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}
	return append(record, handshake...)
}

func signatureSchemes(schemes ...uint16) []byte {
	out := make([]byte, 0, 2+len(schemes)*2)
	out = appendUint16(out, len(schemes)*2)
	for _, scheme := range schemes {
		out = appendUint16(out, int(scheme))
	}
	return out
}

func appendUint16(out []byte, value int) []byte {
	return append(out, byte(value>>8), byte(value))
}

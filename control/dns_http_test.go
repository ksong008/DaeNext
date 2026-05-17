/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"

	componentdns "github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
)

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newTestHTTPResponse(statusCode int, contentType string, body []byte) *http.Response {
	header := make(http.Header)
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}
	return &http.Response{
		StatusCode: statusCode,
		Status:     fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

func TestBuildDoHRequestUsesGetForSmallPayload(t *testing.T) {
	upstream := &componentdns.Upstream{
		Hostname: "dns.example.com",
		Path:     "/dns-query",
	}
	data := []byte{0x12, 0x34, 0x56, 0x78}

	req, err := buildDoHRequest(context.Background(), "1.1.1.1:443", upstream, data)
	if err != nil {
		t.Fatalf("buildDoHRequest() returned error: %v", err)
	}
	if req.Method != http.MethodGet {
		t.Fatalf("expected GET request, got %s", req.Method)
	}
	if got := req.Header.Get("Accept"); got != doHMediaType {
		t.Fatalf("unexpected Accept header: %q", got)
	}
	if got := req.Header.Get("Content-Type"); got != "" {
		t.Fatalf("expected empty Content-Type for GET request, got %q", got)
	}
	if req.Host != upstream.Hostname {
		t.Fatalf("unexpected Host header: %q", req.Host)
	}
	if req.URL.Path != upstream.Path {
		t.Fatalf("unexpected path: %q", req.URL.Path)
	}

	encoded := req.URL.Query().Get("dns")
	if encoded == "" {
		t.Fatal("expected dns query parameter")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("failed to decode dns query parameter: %v", err)
	}
	want := dnsDataWithZeroID(data)
	if !bytes.Equal(decoded, want) {
		t.Fatalf("unexpected encoded dns payload: got %v, want %v", decoded, want)
	}
}

func BenchmarkBuildDoHRequestGet(b *testing.B) {
	upstream := &componentdns.Upstream{
		Hostname: "dns.example.com",
		Path:     "/dns-query",
	}
	data := []byte{0x12, 0x34, 0x56, 0x78}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req, err := buildDoHRequest(context.Background(), "1.1.1.1:443", upstream, data)
		if err != nil {
			b.Fatal(err)
		}
		if req.Method != http.MethodGet {
			b.Fatalf("unexpected method: %s", req.Method)
		}
	}
}

func TestBuildDoHRequestUsesPostForLargePayload(t *testing.T) {
	upstream := &componentdns.Upstream{
		Hostname: "dns.example.com",
		Path:     "/dns-query",
	}
	data := append([]byte{0x12, 0x34}, bytes.Repeat([]byte{0xab}, doHGetMaxEncodedQueryBytes)...)

	req, err := buildDoHRequest(context.Background(), "1.1.1.1:443", upstream, data)
	if err != nil {
		t.Fatalf("buildDoHRequest() returned error: %v", err)
	}
	if req.Method != http.MethodPost {
		t.Fatalf("expected POST request, got %s", req.Method)
	}
	if got := req.Header.Get("Accept"); got != doHMediaType {
		t.Fatalf("unexpected Accept header: %q", got)
	}
	if got := req.Header.Get("Content-Type"); got != doHMediaType {
		t.Fatalf("unexpected Content-Type header: %q", got)
	}
	if got := req.URL.Query().Get("dns"); got != "" {
		t.Fatalf("expected empty dns query parameter for POST request, got %q", got)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("failed to read POST body: %v", err)
	}
	want := dnsDataWithZeroID(data)
	if !bytes.Equal(body, want) {
		t.Fatalf("unexpected POST body: got %d bytes, want %d bytes", len(body), len(want))
	}
}

func TestSendHttpDNSRejectsNonOKStatus(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return newTestHTTPResponse(http.StatusBadGateway, doHMediaType, []byte("bad gateway")), nil
		}),
	}

	before := snapshotDnsObservabilityStats()
	_, err := sendHttpDNS(context.Background(), client, "1.1.1.1:443", &componentdns.Upstream{
		Hostname: "dns.example.com",
		Path:     "/dns-query",
	}, []byte{0x12, 0x34, 0x56, 0x78})
	after := snapshotDnsObservabilityStats()
	if err == nil {
		t.Fatal("expected non-OK DoH status to fail")
	}
	if got := err.Error(); got != "doh server returned status 502 Bad Gateway" {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := after.DnsDoHStatusFailureTotal - before.DnsDoHStatusFailureTotal; got != 1 {
		t.Fatalf("expected one DoH status failure to be recorded, got %d", got)
	}
}

func TestSendHttpDNSRejectsUnexpectedContentType(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return newTestHTTPResponse(http.StatusOK, "text/html; charset=utf-8", []byte("<html></html>")), nil
		}),
	}

	before := snapshotDnsObservabilityStats()
	_, err := sendHttpDNS(context.Background(), client, "1.1.1.1:443", &componentdns.Upstream{
		Hostname: "dns.example.com",
		Path:     "/dns-query",
	}, []byte{0x12, 0x34, 0x56, 0x78})
	after := snapshotDnsObservabilityStats()
	if err == nil {
		t.Fatal("expected unexpected content type to fail")
	}
	if got := err.Error(); got != `unexpected doh content-type "text/html; charset=utf-8"` {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := after.DnsDoHContentTypeFailureTotal - before.DnsDoHContentTypeFailureTotal; got != 1 {
		t.Fatalf("expected one DoH content-type failure to be recorded, got %d", got)
	}
}

func TestSendHttpDNSAcceptsContentTypeWithParameters(t *testing.T) {
	respMsg := newTestDnsResponse("example.com.", dnsmessage.TypeA, newTestARecord("example.com.", "4.4.4.4"), false)
	packed, err := respMsg.Pack()
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return newTestHTTPResponse(http.StatusOK, "application/dns-message; charset=binary", packed), nil
		}),
	}

	got, err := sendHttpDNS(context.Background(), client, "1.1.1.1:443", &componentdns.Upstream{
		Hostname: "dns.example.com",
		Path:     "/dns-query",
	}, []byte{0x12, 0x34, 0x56, 0x78})
	if err != nil {
		t.Fatalf("sendHttpDNS() returned error: %v", err)
	}
	if len(got.Answer) != 1 {
		t.Fatalf("expected one DNS answer, got %d", len(got.Answer))
	}
}

func TestSendHttpDNSUsesPostFallbackForLargePayload(t *testing.T) {
	respMsg := newTestDnsResponse("example.com.", dnsmessage.TypeA, newTestARecord("example.com.", "5.5.5.5"), false)
	packed, err := respMsg.Pack()
	if err != nil {
		t.Fatal(err)
	}

	data := append([]byte{0x12, 0x34}, bytes.Repeat([]byte{0xcd}, doHGetMaxEncodedQueryBytes)...)
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Method != http.MethodPost {
				t.Fatalf("expected POST request, got %s", req.Method)
			}
			if req.URL.Path != "/dns-query" {
				t.Fatalf("unexpected request path: %q", req.URL.Path)
			}
			if got := req.Header.Get("Content-Type"); got != doHMediaType {
				t.Fatalf("unexpected Content-Type: %q", got)
			}
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("failed to read DoH POST body: %v", err)
			}
			if !bytes.Equal(body, dnsDataWithZeroID(data)) {
				t.Fatalf("unexpected DoH POST body length: got %d want %d", len(body), len(data))
			}
			return newTestHTTPResponse(http.StatusOK, doHMediaType, packed), nil
		}),
	}

	got, err := sendHttpDNS(context.Background(), client, "1.1.1.1:443", &componentdns.Upstream{
		Hostname: "dns.example.com",
		Path:     "/dns-query",
	}, data)
	if err != nil {
		t.Fatalf("sendHttpDNS() returned error: %v", err)
	}
	answer, ok := got.Answer[0].(*dnsmessage.A)
	if !ok {
		t.Fatalf("unexpected answer type: %T", got.Answer[0])
	}
	if answer.A.String() != "5.5.5.5" {
		t.Fatalf("unexpected answer IP: %v", answer.A.String())
	}
}

func TestValidateDoHResponseRejectsInvalidContentTypeHeader(t *testing.T) {
	resp := newTestHTTPResponse(http.StatusOK, string([]byte{0x7f}), nil)
	if err := validateDoHResponse(resp); err == nil {
		t.Fatal("expected invalid content-type header to fail")
	}
}

func TestBuildDoHRequestPreservesTargetPathEscaping(t *testing.T) {
	upstream := &componentdns.Upstream{
		Hostname: "dns.example.com",
		Path:     "/custom/dns-query",
	}
	req, err := buildDoHRequest(context.Background(), "1.1.1.1:443", upstream, []byte{0x12, 0x34, 0x56, 0x78})
	if err != nil {
		t.Fatalf("buildDoHRequest() returned error: %v", err)
	}
	if _, err := url.Parse(req.URL.String()); err != nil {
		t.Fatalf("expected valid URL, got error: %v", err)
	}
	if req.URL.Path != upstream.Path {
		t.Fatalf("unexpected path: %q", req.URL.Path)
	}
}

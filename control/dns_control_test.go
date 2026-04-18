/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	componentdns "github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func TestDNSForwarderReusable(t *testing.T) {
	tests := []struct {
		name     string
		upstream *componentdns.Upstream
		dialArg  dialArgument
		want     bool
	}{
		{
			name: "https over tcp is reusable",
			upstream: &componentdns.Upstream{
				Scheme: componentdns.UpstreamScheme_HTTPS,
			},
			dialArg: dialArgument{l4proto: consts.L4ProtoStr_TCP},
			want:    true,
		},
		{
			name: "udp dns is not reusable",
			upstream: &componentdns.Upstream{
				Scheme: componentdns.UpstreamScheme_UDP,
			},
			dialArg: dialArgument{l4proto: consts.L4ProtoStr_UDP},
			want:    false,
		},
		{
			name: "doq is reusable",
			upstream: &componentdns.Upstream{
				Scheme: componentdns.UpstreamScheme_QUIC,
			},
			dialArg: dialArgument{l4proto: consts.L4ProtoStr_UDP},
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dnsForwarderReusable(tt.upstream, tt.dialArg)
			if got != tt.want {
				t.Fatalf("dnsForwarderReusable(%v, %v) = %v, want %v", tt.upstream.Scheme, tt.dialArg.l4proto, got, tt.want)
			}
		})
	}
}

func TestShouldReportDnsDialFailure(t *testing.T) {
	timeoutErr := &net.DNSError{IsTimeout: true}
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "deadline exceeded", err: context.DeadlineExceeded, want: true},
		{name: "canceled", err: context.Canceled, want: false},
		{name: "timeout net error", err: timeoutErr, want: true},
		{name: "wrapped timeout", err: fmt.Errorf("wrapped: %w", timeoutErr), want: true},
		{name: "plain string error", err: errors.New(timeoutErr.Error()), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldReportDnsDialFailure(tt.err)
			if got != tt.want {
				t.Fatalf("shouldReportDnsDialFailure(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestLookupDnsRespCacheRemovesExpiredEntry(t *testing.T) {
	removed := 0
	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log: logrus.New(),
		CacheAccessCallback: func(*DnsCache) error {
			return nil
		},
		CacheRemoveCallback: func(*DnsCache) error {
			removed++
			return nil
		},
		NewCache: func(_ string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			return &DnsCache{
				Answer:           answers,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
		BestDialerChooser:     func(*udpRequest, *componentdns.Upstream) (*dialArgument, error) { return nil, nil },
		TimeoutExceedCallback: func(*dialArgument, error) {},
	})
	if err != nil {
		t.Fatalf("NewDnsController() returned error: %v", err)
	}

	cacheKey := controller.cacheKey("example.com.", dnsmessage.TypeA)
	controller.dnsCache[cacheKey] = &DnsCache{
		Deadline:         time.Now().Add(-time.Second),
		OriginalDeadline: time.Now().Add(-time.Second),
	}

	cache := controller.LookupDnsRespCache(cacheKey, false)
	if cache != nil {
		t.Fatal("expected expired cache lookup to miss")
	}
	if removed != 1 {
		t.Fatalf("expected 1 cache removal callback, got %d", removed)
	}
	if _, ok := controller.dnsCache[cacheKey]; ok {
		t.Fatal("expected expired cache entry to be removed from cache map")
	}
}

func TestDnsDataWithZeroIDDoesNotMutateInput(t *testing.T) {
	original := []byte{0x12, 0x34, 0x56}
	cloned := dnsDataWithZeroID(original)
	if original[0] != 0x12 || original[1] != 0x34 {
		t.Fatalf("dnsDataWithZeroID mutated input: %v", original)
	}
	if cloned[0] != 0x00 || cloned[1] != 0x00 {
		t.Fatalf("dnsDataWithZeroID did not zero id: %v", cloned[:2])
	}
}

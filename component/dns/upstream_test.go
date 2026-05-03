/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
)

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestUpstreamResolverUsesCacheBeforeRefresh(t *testing.T) {
	now := time.Unix(100, 0)
	resolveCalls := 0
	resolver := &UpstreamResolver{
		Raw:             mustParseURL(t, "udp://dns.example.com:53"),
		Network:         "udp",
		RefreshInterval: 10 * time.Minute,
		Now:             func() time.Time { return now },
		Resolve: func(ctx context.Context, upstream *url.URL, resolverNetwork string) (*Upstream, error) {
			resolveCalls++
			return &Upstream{
				Scheme:   UpstreamScheme_UDP,
				Hostname: upstream.Hostname(),
				Port:     53,
				Index:    consts.DnsRequestOutboundIndex(1),
				Ip46: &netutils.Ip46{
					Ip4: netip.MustParseAddr("1.1.1.1"),
				},
			}, nil
		},
	}

	first, err := resolver.GetUpstream()
	if err != nil {
		t.Fatal(err)
	}
	second, err := resolver.GetUpstream()
	if err != nil {
		t.Fatal(err)
	}
	if resolveCalls != 1 {
		t.Fatalf("expected one resolve call, got %d", resolveCalls)
	}
	if first != second {
		t.Fatal("expected cached upstream pointer to be reused before refresh interval")
	}
}

func TestUpstreamResolverRefreshesAfterInterval(t *testing.T) {
	now := time.Unix(100, 0)
	resolveCalls := 0
	callbackCalls := 0
	resolver := &UpstreamResolver{
		Raw:             mustParseURL(t, "udp://dns.example.com:53"),
		Network:         "udp",
		RefreshInterval: time.Minute,
		Now:             func() time.Time { return now },
		FinishInitCallback: func(raw *url.URL, upstream *Upstream) error {
			callbackCalls++
			return nil
		},
		Resolve: func(ctx context.Context, upstream *url.URL, resolverNetwork string) (*Upstream, error) {
			resolveCalls++
			return &Upstream{
				Scheme:   UpstreamScheme_UDP,
				Hostname: upstream.Hostname(),
				Port:     53,
				Index:    consts.DnsRequestOutboundIndex(1),
				Ip46: &netutils.Ip46{
					Ip4: netip.AddrFrom4([4]byte{1, 1, 1, byte(resolveCalls)}),
				},
			}, nil
		},
	}

	first, err := resolver.GetUpstream()
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	second, err := resolver.GetUpstream()
	if err != nil {
		t.Fatal(err)
	}
	if resolveCalls != 2 {
		t.Fatalf("expected two resolve calls, got %d", resolveCalls)
	}
	if callbackCalls != 2 {
		t.Fatalf("expected two callback calls, got %d", callbackCalls)
	}
	if first == second {
		t.Fatal("expected refreshed upstream pointer after refresh interval")
	}
	if second.Ip4.String() != "1.1.1.2" {
		t.Fatalf("unexpected refreshed IP: %v", second.Ip4)
	}
}

func TestUpstreamResolverKeepsPreviousUpstreamOnRefreshFailure(t *testing.T) {
	now := time.Unix(100, 0)
	resolveCalls := 0
	resolver := &UpstreamResolver{
		Raw:             mustParseURL(t, "udp://dns.example.com:53"),
		Network:         "udp",
		RefreshInterval: time.Minute,
		RetryInterval:   30 * time.Second,
		Now:             func() time.Time { return now },
		Resolve: func(ctx context.Context, upstream *url.URL, resolverNetwork string) (*Upstream, error) {
			resolveCalls++
			if resolveCalls == 1 {
				return &Upstream{
					Scheme:   UpstreamScheme_UDP,
					Hostname: upstream.Hostname(),
					Port:     53,
					Index:    consts.DnsRequestOutboundIndex(1),
					Ip46: &netutils.Ip46{
						Ip4: netip.MustParseAddr("1.1.1.1"),
					},
				}, nil
			}
			return nil, errors.New("refresh failed")
		},
	}

	before := SnapshotUpstreamResolverStats()
	first, err := resolver.GetUpstream()
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	second, err := resolver.GetUpstream()
	if err != nil {
		t.Fatal(err)
	}
	after := SnapshotUpstreamResolverStats()
	if resolveCalls != 2 {
		t.Fatalf("expected two resolve calls, got %d", resolveCalls)
	}
	if first != second {
		t.Fatal("expected stale upstream to be kept on refresh failure")
	}
	if !resolver.nextRefresh.Equal(now.Add(30 * time.Second)) {
		t.Fatalf("unexpected retry deadline: %v", resolver.nextRefresh)
	}
	if got := after.RefreshSuccessTotal - before.RefreshSuccessTotal; got != 1 {
		t.Fatalf("expected one refresh success to be recorded, got %d", got)
	}
	if got := after.RefreshFailureTotal - before.RefreshFailureTotal; got != 1 {
		t.Fatalf("expected one refresh failure to be recorded, got %d", got)
	}
	if got := after.StaleReuseTotal - before.StaleReuseTotal; got != 1 {
		t.Fatalf("expected one stale reuse to be recorded, got %d", got)
	}
}

func TestUpstreamResolverDeduplicatesConcurrentRefresh(t *testing.T) {
	now := time.Unix(100, 0)
	resolveCalls := 0
	releaseResolve := make(chan struct{})
	resolver := &UpstreamResolver{
		Raw:             mustParseURL(t, "udp://dns.example.com:53"),
		Network:         "udp",
		RefreshInterval: time.Minute,
		Now:             func() time.Time { return now },
		Resolve: func(ctx context.Context, upstream *url.URL, resolverNetwork string) (*Upstream, error) {
			resolveCalls++
			<-releaseResolve
			return &Upstream{
				Scheme:   UpstreamScheme_UDP,
				Hostname: upstream.Hostname(),
				Port:     53,
				Index:    consts.DnsRequestOutboundIndex(1),
				Ip46: &netutils.Ip46{
					Ip4: netip.MustParseAddr("1.1.1.1"),
				},
			}, nil
		},
	}

	results := make([]*Upstream, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range results {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = resolver.GetUpstream()
		}()
	}

	close(releaseResolve)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for concurrent refresh")
	}

	if resolveCalls != 1 {
		t.Fatalf("expected one resolve call, got %d", resolveCalls)
	}
	for i, err := range errs {
		if err != nil {
			t.Fatalf("unexpected error from call %d: %v", i, err)
		}
	}
	if results[0] == nil || results[1] == nil {
		t.Fatal("expected non-nil upstreams")
	}
	if results[0] != results[1] {
		t.Fatal("expected concurrent callers to share the refreshed upstream")
	}
}

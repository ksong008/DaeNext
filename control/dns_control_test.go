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
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	componentdns "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type fakeDnsForwarder struct {
	closeCount int
	err        error
}

func (f *fakeDnsForwarder) ForwardDNS(context.Context, []byte) (*dnsmessage.Msg, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &dnsmessage.Msg{}, nil
}

func (f *fakeDnsForwarder) Close() error {
	f.closeCount++
	return nil
}

type blockingDnsForwarder struct {
	ctxCh chan context.Context
}

func (f *blockingDnsForwarder) ForwardDNS(ctx context.Context, _ []byte) (*dnsmessage.Msg, error) {
	if f.ctxCh != nil {
		f.ctxCh <- ctx
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (f *blockingDnsForwarder) Close() error {
	return nil
}

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

func TestLookupDnsRespCacheUsesPackedResponse(t *testing.T) {
	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log: logrus.New(),
		CacheAccessCallback: func(*DnsCache) error {
			return nil
		},
		CacheRemoveCallback: func(*DnsCache) error { return nil },
		NewCache: func(_ string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			return &DnsCache{Answer: answers, Deadline: deadline, OriginalDeadline: originalDeadline}, nil
		},
		BestDialerChooser:     func(*udpRequest, *componentdns.Upstream) (*dialArgument, error) { return nil, nil },
		TimeoutExceedCallback: func(*dialArgument, error) {},
	})
	if err != nil {
		t.Fatalf("NewDnsController() returned error: %v", err)
	}
	defer controller.Close()

	answer := &dnsmessage.A{
		Hdr: dnsmessage.RR_Header{
			Name:   dnsmessage.CanonicalName("example.com."),
			Rrtype: dnsmessage.TypeA,
			Class:  dnsmessage.ClassINET,
			Ttl:    0,
		},
		A: net.ParseIP("1.1.1.1").To4(),
	}
	if err := controller.UpdateDnsCacheTtl("example.com.", dnsmessage.TypeA, []dnsmessage.RR{answer}, 60); err != nil {
		t.Fatal(err)
	}

	msg := new(dnsmessage.Msg)
	msg.SetQuestion("example.com.", dnsmessage.TypeA)
	msg.Id = 0x4321
	resp := controller.LookupDnsRespCache_(msg, controller.cacheKey("example.com.", dnsmessage.TypeA), false)
	if len(resp) < 2 {
		t.Fatal("expected packed response bytes")
	}
	if got := uint16(resp[0])<<8 | uint16(resp[1]); got != msg.Id {
		t.Fatalf("expected response id %x, got %x", msg.Id, got)
	}
}

func TestSweepDnsCacheUsesLatestDeadline(t *testing.T) {
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
	defer controller.Close()

	now := time.Now()
	cacheKey := controller.cacheKey("example.com.", dnsmessage.TypeA)
	controller.dnsCache[cacheKey] = &DnsCache{
		Deadline:         now.Add(-time.Minute),
		OriginalDeadline: now.Add(time.Minute),
	}

	controller.sweepDnsCache(now)
	if removed != 0 {
		t.Fatalf("expected no removal while original deadline is still valid, got %d", removed)
	}
	if _, ok := controller.dnsCache[cacheKey]; !ok {
		t.Fatal("expected cache entry to remain while latest deadline is valid")
	}

	controller.sweepDnsCache(now.Add(2 * time.Minute))
	if removed != 1 {
		t.Fatalf("expected one removal after both deadlines expired, got %d", removed)
	}
	if _, ok := controller.dnsCache[cacheKey]; ok {
		t.Fatal("expected cache entry to be removed after expiry")
	}
}

func TestSweepDnsForwarderCacheRemovesIdleEntries(t *testing.T) {
	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log: logrus.New(),
		CacheAccessCallback: func(*DnsCache) error {
			return nil
		},
		CacheRemoveCallback: func(*DnsCache) error { return nil },
		NewCache: func(_ string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			return &DnsCache{}, nil
		},
		BestDialerChooser:     func(*udpRequest, *componentdns.Upstream) (*dialArgument, error) { return nil, nil },
		TimeoutExceedCallback: func(*dialArgument, error) {},
	})
	if err != nil {
		t.Fatalf("NewDnsController() returned error: %v", err)
	}
	defer controller.Close()

	now := time.Now()
	stale := &fakeDnsForwarder{}
	fresh := &fakeDnsForwarder{}
	controller.dnsForwarderCache[dnsForwarderKey{upstream: "stale"}] = &cachedDnsForwarder{
		forwarder: stale,
		lastUsed:  now.Add(-dnsForwarderIdleTimeout - time.Second),
	}
	controller.dnsForwarderCache[dnsForwarderKey{upstream: "fresh"}] = &cachedDnsForwarder{
		forwarder: fresh,
		lastUsed:  now,
	}

	controller.sweepDnsForwarderCache(now, false)
	if stale.closeCount != 1 {
		t.Fatalf("expected stale forwarder to be closed once, got %d", stale.closeCount)
	}
	if fresh.closeCount != 0 {
		t.Fatalf("expected fresh forwarder to stay open, got %d closes", fresh.closeCount)
	}
	if _, ok := controller.dnsForwarderCache[dnsForwarderKey{upstream: "stale"}]; ok {
		t.Fatal("expected stale forwarder entry to be removed")
	}
	if _, ok := controller.dnsForwarderCache[dnsForwarderKey{upstream: "fresh"}]; !ok {
		t.Fatal("expected fresh forwarder entry to remain")
	}
}

func TestGetDnsForwarderEvictsOldestWhenCacheFull(t *testing.T) {
	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log: logrus.New(),
		CacheAccessCallback: func(*DnsCache) error {
			return nil
		},
		CacheRemoveCallback: func(*DnsCache) error { return nil },
		NewCache: func(_ string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			return &DnsCache{}, nil
		},
		BestDialerChooser:     func(*udpRequest, *componentdns.Upstream) (*dialArgument, error) { return nil, nil },
		TimeoutExceedCallback: func(*dialArgument, error) {},
	})
	if err != nil {
		t.Fatalf("NewDnsController() returned error: %v", err)
	}
	defer controller.Close()

	now := time.Now()
	controller.now = func() time.Time { return now }

	created := 0
	closedForwarders := make([]*fakeDnsForwarder, 0, dnsForwarderCacheMaxEntries+1)
	controller.forwarderFactory = func(upstream *componentdns.Upstream, dialArgument dialArgument) (DnsForwarder, error) {
		created++
		f := &fakeDnsForwarder{}
		closedForwarders = append(closedForwarders, f)
		return f, nil
	}

	for i := 0; i < dnsForwarderCacheMaxEntries; i++ {
		key := dnsForwarderKey{upstream: fmt.Sprintf("upstream-%d", i)}
		controller.dnsForwarderCache[key] = &cachedDnsForwarder{
			forwarder: &fakeDnsForwarder{},
			lastUsed:  now.Add(time.Duration(i-dnsForwarderCacheMaxEntries) * time.Second),
		}
	}

	forwarder, key, entry, reusable, err := controller.getDnsForwarder(&componentdns.Upstream{
		Scheme:   componentdns.UpstreamScheme_HTTPS,
		Hostname: "dns.example.com",
		Port:     443,
		Index:    consts.DnsRequestOutboundIndex(9),
		Ip46: &netutils.Ip46{
			Ip4: netip.MustParseAddr("1.1.1.1"),
		},
	}, &dialArgument{
		l4proto:    consts.L4ProtoStr_TCP,
		ipversion:  consts.IpVersionStr_4,
		bestTarget: netip.MustParseAddrPort("1.1.1.1:443"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reusable {
		t.Fatal("expected HTTPS forwarder to be reusable")
	}
	if created != 1 {
		t.Fatalf("expected one created forwarder, got %d", created)
	}
	if len(controller.dnsForwarderCache) != dnsForwarderCacheMaxEntries {
		t.Fatalf("expected cache size to stay capped at %d, got %d", dnsForwarderCacheMaxEntries, len(controller.dnsForwarderCache))
	}
	if releaseErr := controller.releaseDnsForwarder(key, entry, forwarder, reusable, false); releaseErr != nil {
		t.Fatal(releaseErr)
	}
}

func TestReleaseDnsForwarderRemovesFailedReusableEntry(t *testing.T) {
	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log:                 logrus.New(),
		CacheAccessCallback: func(*DnsCache) error { return nil },
		CacheRemoveCallback: func(*DnsCache) error { return nil },
		NewCache: func(_ string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			return &DnsCache{}, nil
		},
		BestDialerChooser:     func(*udpRequest, *componentdns.Upstream) (*dialArgument, error) { return nil, nil },
		TimeoutExceedCallback: func(*dialArgument, error) {},
	})
	if err != nil {
		t.Fatalf("NewDnsController() returned error: %v", err)
	}
	defer controller.Close()

	now := time.Now()
	controller.now = func() time.Time { return now }

	forwarder := &fakeDnsForwarder{}
	key := dnsForwarderKey{upstream: "https://dns.example.com"}
	entry := &cachedDnsForwarder{
		forwarder: forwarder,
		lastUsed:  now,
		refs:      1,
	}
	controller.dnsForwarderCache[key] = entry

	if err := controller.releaseDnsForwarder(key, entry, forwarder, true, true); err != nil {
		t.Fatal(err)
	}
	if _, ok := controller.dnsForwarderCache[key]; ok {
		t.Fatal("expected failed reusable forwarder to be removed from cache")
	}
	if forwarder.closeCount != 1 {
		t.Fatalf("expected failed reusable forwarder to be closed once, got %d", forwarder.closeCount)
	}
}

func TestSweepDnsForwarderCacheKeepsInUseEntry(t *testing.T) {
	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log:                 logrus.New(),
		CacheAccessCallback: func(*DnsCache) error { return nil },
		CacheRemoveCallback: func(*DnsCache) error { return nil },
		NewCache: func(_ string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			return &DnsCache{}, nil
		},
		BestDialerChooser:     func(*udpRequest, *componentdns.Upstream) (*dialArgument, error) { return nil, nil },
		TimeoutExceedCallback: func(*dialArgument, error) {},
	})
	if err != nil {
		t.Fatalf("NewDnsController() returned error: %v", err)
	}
	defer controller.Close()

	now := time.Now()
	inUse := &fakeDnsForwarder{}
	key := dnsForwarderKey{upstream: "in-use"}
	controller.dnsForwarderCache[key] = &cachedDnsForwarder{
		forwarder: inUse,
		lastUsed:  now.Add(-dnsForwarderIdleTimeout - time.Second),
		refs:      1,
	}

	controller.sweepDnsForwarderCache(now, false)
	if _, ok := controller.dnsForwarderCache[key]; !ok {
		t.Fatal("expected in-use forwarder to stay cached during sweep")
	}
	if inUse.closeCount != 0 {
		t.Fatalf("expected in-use forwarder to stay open, got %d closes", inUse.closeCount)
	}
}

func TestDialSendUsesRequestContext(t *testing.T) {
	routing, err := componentdns.New(&config.Dns{
		Upstream: []config.KeyableString{
			"test:udp://1.1.1.1:53",
		},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Fallback: "test",
			},
			Response: config.DnsResponseRouting{
				Fallback: "accept",
			},
		},
	}, &componentdns.NewOption{
		Logger: logrus.New(),
		UpstreamReadyCallback: func(*componentdns.Upstream) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("failed to build dns routing: %v", err)
	}

	controller, err := NewDnsController(routing, &DnsControllerOption{
		Log:                 logrus.New(),
		CacheAccessCallback: func(*DnsCache) error { return nil },
		CacheRemoveCallback: func(*DnsCache) error { return nil },
		NewCache: func(_ string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			return &DnsCache{
				Answer:           answers,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
		BestDialerChooser: func(*udpRequest, *componentdns.Upstream) (*dialArgument, error) {
			return &dialArgument{
				l4proto:   consts.L4ProtoStr_UDP,
				ipversion: consts.IpVersionStr_4,
			}, nil
		},
		TimeoutExceedCallback: func(*dialArgument, error) {},
	})
	if err != nil {
		t.Fatalf("NewDnsController() returned error: %v", err)
	}
	defer controller.Close()

	ctxCh := make(chan context.Context, 1)
	controller.forwarderFactory = func(*componentdns.Upstream, dialArgument) (DnsForwarder, error) {
		return &blockingDnsForwarder{ctxCh: ctxCh}, nil
	}

	reqCtx, cancel := context.WithCancel(context.Background())
	cancel()

	req := &udpRequest{
		ctx:           reqCtx,
		realSrc:       netip.MustParseAddrPort("127.0.0.1:43210"),
		realDst:       netip.MustParseAddrPort("127.0.0.1:53"),
		src:           netip.MustParseAddrPort("127.0.0.1:43210"),
		routingResult: &bpfRoutingResult{},
	}

	msg := new(dnsmessage.Msg)
	msg.SetQuestion("example.com.", dnsmessage.TypeA)
	data, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}

	err = controller.dialSend(0, req, data, msg.Id, &componentdns.Upstream{
		Scheme:   componentdns.UpstreamScheme_UDP,
		Hostname: "1.1.1.1",
		Port:     53,
		Ip46: &netutils.Ip46{
			Ip4: netip.MustParseAddr("1.1.1.1"),
		},
	}, false)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled error, got %v", err)
	}

	select {
	case forwardCtx := <-ctxCh:
		if !errors.Is(forwardCtx.Err(), context.Canceled) {
			t.Fatalf("expected forwarded context to be canceled, got %v", forwardCtx.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for forwarded context")
	}
}

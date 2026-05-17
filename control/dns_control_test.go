/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	componentdns "github.com/daeuniverse/dae/component/dns"
	outbounddialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type fakeDnsForwarder struct {
	closeCount int
	err        error
	msg        *dnsmessage.Msg
	forward    func(context.Context, []byte) (*dnsmessage.Msg, error)
}

func (f *fakeDnsForwarder) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	if f.forward != nil {
		return f.forward(ctx, data)
	}
	if f.err != nil {
		return nil, f.err
	}
	if f.msg != nil {
		return f.msg.Copy(), nil
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

type timeoutNetError struct{}

func (timeoutNetError) Error() string   { return "i/o timeout" }
func (timeoutNetError) Timeout() bool   { return true }
func (timeoutNetError) Temporary() bool { return true }

type dnsConnReadStep struct {
	payload []byte
	err     error
}

type scriptedDNSConn struct {
	steps      []dnsConnReadStep
	readIndex  int
	writeCount int
}

func (c *scriptedDNSConn) Read(b []byte) (int, error) {
	if c.readIndex >= len(c.steps) {
		return 0, io.EOF
	}
	step := c.steps[c.readIndex]
	c.readIndex++
	if step.err != nil {
		return 0, step.err
	}
	n := copy(b, step.payload)
	return n, nil
}

func (c *scriptedDNSConn) Write(b []byte) (int, error) {
	c.writeCount++
	return len(b), nil
}

func (c *scriptedDNSConn) Close() error                { return nil }
func (c *scriptedDNSConn) SetDeadline(time.Time) error { return nil }
func (c *scriptedDNSConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *scriptedDNSConn) SetWriteDeadline(time.Time) error {
	return nil
}

type fakeNetproxyDialer struct {
	conn netproxy.Conn
	err  error
}

func (d *fakeNetproxyDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	if d.err != nil {
		return nil, d.err
	}
	return d.conn, nil
}

func newTestDnsResponse(qname string, qtype uint16, answer dnsmessage.RR, truncated bool) *dnsmessage.Msg {
	req := new(dnsmessage.Msg)
	req.SetQuestion(qname, qtype)
	resp := new(dnsmessage.Msg)
	resp.SetReply(req)
	resp.Truncated = truncated
	if answer != nil {
		resp.Answer = []dnsmessage.RR{answer}
	}
	return resp
}

func newTestARecord(qname, ip string) *dnsmessage.A {
	return &dnsmessage.A{
		Hdr: dnsmessage.RR_Header{
			Name:   dnsmessage.CanonicalName(qname),
			Rrtype: dnsmessage.TypeA,
			Class:  dnsmessage.ClassINET,
			Ttl:    60,
		},
		A: net.ParseIP(ip).To4(),
	}
}

func TestDnsCacheKeyIncludesQuestionTypeAndClass(t *testing.T) {
	inetA := newDnsCacheKey("Example.COM", dnsmessage.TypeA, dnsmessage.ClassINET)
	inetAAAA := newDnsCacheKey("example.com.", dnsmessage.TypeAAAA, dnsmessage.ClassINET)
	nonINETA := newDnsCacheKey("example.com.", dnsmessage.TypeA, 3)

	if inetA.qname != "example.com." {
		t.Fatalf("qname = %q, want canonical lowercase fqdn", inetA.qname)
	}
	if inetA == inetAAAA {
		t.Fatal("expected A and AAAA lookups to use different cache keys")
	}
	if inetA == nonINETA {
		t.Fatal("expected different DNS question classes to use different cache keys")
	}

	parsed, ok := parseDnsCacheKey(inetA.String())
	if !ok {
		t.Fatalf("failed to parse structured cache key %q", inetA.String())
	}
	if parsed != inetA {
		t.Fatalf("parsed structured key = %+v, want %+v", parsed, inetA)
	}

	legacy, ok := parseDnsCacheKey("example.com.1")
	if !ok {
		t.Fatal("failed to parse legacy dns cache key")
	}
	if legacy != inetA {
		t.Fatalf("parsed legacy key = %+v, want %+v", legacy, inetA)
	}
}

func TestNormalizeAndCacheDnsRespUsesQuestionClassInCacheKey(t *testing.T) {
	const testClass = uint16(3)

	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log:                 logrus.New(),
		CacheAccessCallback: func(*DnsCache) error { return nil },
		CacheRemoveCallback: func(*DnsCache) error { return nil },
		NewCache: func(_ string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			ips, hasAnyIP := summarizeDNSAnswers(answers)
			return &DnsCache{
				Answer:           answers,
				IPs:              ips,
				HasAnyIP:         hasAnyIP,
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
	controller.now = func() time.Time { return now }

	msg := new(dnsmessage.Msg)
	msg.SetQuestion("Example.COM.", dnsmessage.TypeA)
	msg.Question[0].Qclass = testClass
	msg.Response = true
	msg.Answer = []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   dnsmessage.CanonicalName("example.com."),
				Rrtype: dnsmessage.TypeA,
				Class:  testClass,
				Ttl:    60,
			},
			A: net.ParseIP("1.1.1.1").To4(),
		},
	}

	if err := controller.NormalizeAndCacheDnsResp_(msg); err != nil {
		t.Fatal(err)
	}

	customClassKey := controller.cacheKeyFromParts("example.com.", dnsmessage.TypeA, testClass)
	if cache := controller.LookupDnsRespCache(customClassKey, false); cache == nil {
		t.Fatal("expected cache hit for the original question class")
	}
	if cache := controller.LookupDnsRespCache(controller.cacheKey("example.com.", dnsmessage.TypeA), false); cache != nil {
		t.Fatal("expected INET lookup to miss when response was cached for a different question class")
	}

	req := new(dnsmessage.Msg)
	req.Question = []dnsmessage.Question{{
		Name:   dnsmessage.CanonicalName("example.com."),
		Qtype:  dnsmessage.TypeA,
		Qclass: testClass,
	}}
	resp := controller.LookupDnsRespCache_(req, customClassKey, false)
	if resp == nil {
		t.Fatal("expected packed cache response")
	}
	var respMsg dnsmessage.Msg
	if err := respMsg.Unpack(resp); err != nil {
		t.Fatal(err)
	}
	if got := respMsg.Question[0].Qclass; got != testClass {
		t.Fatalf("response question class = %d, want %d", got, testClass)
	}
	if got := respMsg.Answer[0].Header().Class; got != testClass {
		t.Fatalf("response answer class = %d, want %d", got, testClass)
	}
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

func TestResolveIp46SyntheticLookupRejectsAsIsOriginalTarget(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	routing, err := componentdns.New(&config.Dns{
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Fallback: "asis",
			},
			Response: config.DnsResponseRouting{
				Fallback: "accept",
			},
		},
	}, &componentdns.NewOption{
		Logger: log,
		UpstreamReadyCallback: func(*componentdns.Upstream) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("failed to build dns routing: %v", err)
	}

	usedOriginalTarget := make(chan struct{}, 2)
	controller, err := NewDnsController(routing, &DnsControllerOption{
		Log:                 log,
		CacheAccessCallback: func(*DnsCache) error { return nil },
		CacheRemoveCallback: func(*DnsCache) error { return nil },
		NewCache: func(_ string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			ips, hasAnyIP := summarizeDNSAnswers(answers)
			return &DnsCache{
				Answer:           answers,
				IPs:              ips,
				HasAnyIP:         hasAnyIP,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
		BestDialerChooser: func(_ *udpRequest, upstream *componentdns.Upstream) (*dialArgument, error) {
			if upstream != nil && upstream.Hostname == "93.184.216.34" && upstream.Port == 443 {
				usedOriginalTarget <- struct{}{}
			}
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

	controller.forwarderFactory = func(_ *componentdns.Upstream, _ dialArgument) (DnsForwarder, error) {
		return &fakeDnsForwarder{forward: func(_ context.Context, data []byte) (*dnsmessage.Msg, error) {
			req := new(dnsmessage.Msg)
			if err := req.Unpack(data); err != nil {
				return nil, err
			}
			resp := new(dnsmessage.Msg)
			resp.SetReply(req)
			switch req.Question[0].Qtype {
			case dnsmessage.TypeA:
				resp.Answer = []dnsmessage.RR{newTestARecord(req.Question[0].Name, "1.1.1.1")}
			case dnsmessage.TypeAAAA:
				resp.Answer = []dnsmessage.RR{&dnsmessage.AAAA{
					Hdr: dnsmessage.RR_Header{
						Name:   dnsmessage.CanonicalName(req.Question[0].Name),
						Rrtype: dnsmessage.TypeAAAA,
						Class:  dnsmessage.ClassINET,
						Ttl:    60,
					},
					AAAA: net.ParseIP("2001:db8::1").To16(),
				}}
			}
			return resp, nil
		}}, nil
	}

	req := &udpRequest{
		ctx:           context.Background(),
		realSrc:       netip.MustParseAddrPort("192.0.2.10:43210"),
		realDst:       netip.MustParseAddrPort("93.184.216.34:443"),
		src:           netip.MustParseAddrPort("192.0.2.10:43210"),
		routingResult: &bpfRoutingResult{},
	}

	ip46, err4, err6 := controller.ResolveIp46(context.Background(), req, "example.com")
	if ip46.Ip4.IsValid() || ip46.Ip6.IsValid() {
		t.Fatalf("expected synthetic asis lookup to stay unverified, got ip4=%v ip6=%v", ip46.Ip4, ip46.Ip6)
	}
	if err4 == nil && err6 == nil {
		t.Fatal("expected synthetic asis lookup to return an error")
	}
	select {
	case <-usedOriginalTarget:
		t.Fatal("synthetic domain verification used the original traffic target as DNS upstream")
	default:
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

func TestLookupDnsRespCacheTracksHitAndExpiredRemovalCounters(t *testing.T) {
	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log: logrus.New(),
		CacheAccessCallback: func(*DnsCache) error {
			return nil
		},
		CacheRemoveCallback: func(*DnsCache) error {
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
	controller.now = func() time.Time { return now }

	liveKey := controller.cacheKey("live.example.", dnsmessage.TypeA)
	expiredKey := controller.cacheKey("expired.example.", dnsmessage.TypeA)
	controller.dnsCache[liveKey] = &DnsCache{
		Deadline:         now.Add(time.Minute),
		OriginalDeadline: now.Add(time.Minute),
	}
	controller.dnsCache[expiredKey] = &DnsCache{
		Deadline:         now.Add(-time.Minute),
		OriginalDeadline: now.Add(-time.Minute),
	}

	before := snapshotDnsObservabilityStats()
	if cache := controller.LookupDnsRespCache(liveKey, false); cache == nil {
		t.Fatal("expected live cache hit")
	}
	if cache := controller.LookupDnsRespCache(expiredKey, false); cache != nil {
		t.Fatal("expected expired cache miss")
	}
	after := snapshotDnsObservabilityStats()

	if got := after.DnsCacheHitTotal - before.DnsCacheHitTotal; got != 1 {
		t.Fatalf("expected one dns cache hit to be recorded, got %d", got)
	}
	if got := after.DnsCacheExpiredRemovalTotal - before.DnsCacheExpiredRemovalTotal; got != 1 {
		t.Fatalf("expected one expired dns cache removal to be recorded, got %d", got)
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

func BenchmarkDnsCacheKey(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		key := newDnsCacheKey("Example.COM", dnsmessage.TypeA, dnsmessage.ClassINET)
		if key.String() != "example.com.|1|1" {
			b.Fatalf("unexpected dns cache key: %s", key.String())
		}
	}
}

func BenchmarkDnsDataWithZeroID(b *testing.B) {
	payload := []byte{0x12, 0x34, 0x56, 0x78}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		got := dnsDataWithZeroID(payload)
		if got[0] != 0 || got[1] != 0 || payload[0] != 0x12 || payload[1] != 0x34 {
			b.Fatalf("unexpected zero-id payload: got=%v original=%v", got, payload)
		}
	}
}

func BenchmarkValidateDnsResponseForRequest(b *testing.B) {
	req := new(dnsmessage.Msg)
	req.Id = 0x1111
	req.SetQuestion("example.com.", dnsmessage.TypeA)
	resp := newTestDnsResponse("example.com.", dnsmessage.TypeA, newTestARecord("example.com.", "1.1.1.1"), false)
	resp.Id = req.Id
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := validateDnsResponseForRequest(req, resp, true); err != nil {
			b.Fatal(err)
		}
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

func TestCacheStatsCountsOnlyLiveDnsEntriesWithoutMutation(t *testing.T) {
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
	controller.now = func() time.Time { return now }
	expiredKey := controller.cacheKey("expired.example.", dnsmessage.TypeA)
	liveKey := controller.cacheKey("live.example.", dnsmessage.TypeA)
	controller.dnsCache[expiredKey] = &DnsCache{
		Deadline:         now.Add(-time.Minute),
		OriginalDeadline: now.Add(-time.Minute),
	}
	controller.dnsCache[liveKey] = &DnsCache{
		Deadline:         now.Add(-time.Minute),
		OriginalDeadline: now.Add(time.Minute),
	}

	dnsCacheEntries, dnsForwarderEntries := controller.CacheStats()
	if dnsCacheEntries != 1 {
		t.Fatalf("expected one live dns cache entry, got %d", dnsCacheEntries)
	}
	if dnsForwarderEntries != 0 {
		t.Fatalf("expected no dns forwarder cache entries, got %d", dnsForwarderEntries)
	}
	if removed != 0 {
		t.Fatalf("expected CacheStats not to invoke cacheRemoveCallback, got %d calls", removed)
	}
	if len(controller.dnsCache) != 2 {
		t.Fatalf("expected CacheStats not to mutate dns cache map, got len=%d", len(controller.dnsCache))
	}
	if _, ok := controller.dnsCache[expiredKey]; !ok {
		t.Fatal("expected expired cache entry to remain for normal cleanup path")
	}
	if _, ok := controller.dnsCache[liveKey]; !ok {
		t.Fatal("expected live cache entry to remain")
	}
}

func TestDoUDPForwardDNSTracksRetryCounter(t *testing.T) {
	respMsg := newTestDnsResponse("example.com.", dnsmessage.TypeA, newTestARecord("example.com.", "6.6.6.6"), false)
	packed, err := respMsg.Pack()
	if err != nil {
		t.Fatal(err)
	}

	conn := &scriptedDNSConn{
		steps: []dnsConnReadStep{
			{err: timeoutNetError{}},
			{payload: packed},
		},
	}
	bestDialer := outbounddialer.NewDialer(
		&fakeNetproxyDialer{conn: conn},
		&outbounddialer.GlobalOption{Log: logrus.New()},
		outbounddialer.InstanceOption{DisableCheck: true},
		&outbounddialer.Property{},
	)

	forwarder := &DoUDP{
		Upstream: componentdns.Upstream{
			Scheme: componentdns.UpstreamScheme_UDP,
		},
		dialArgument: dialArgument{
			bestDialer: bestDialer,
			bestTarget: netip.MustParseAddrPort("1.1.1.1:53"),
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	before := snapshotDnsObservabilityStats()
	got, err := forwarder.ForwardDNS(ctx, []byte{0x12, 0x34, 0x56, 0x78})
	if err != nil {
		t.Fatalf("ForwardDNS() returned error: %v", err)
	}
	after := snapshotDnsObservabilityStats()

	if got.Answer[0].(*dnsmessage.A).A.String() != "6.6.6.6" {
		t.Fatalf("unexpected answer: %v", got.Answer[0])
	}
	if conn.writeCount != 2 {
		t.Fatalf("expected two UDP writes after one retry, got %d", conn.writeCount)
	}
	if got := after.DnsUdpRetryTotal - before.DnsUdpRetryTotal; got != 1 {
		t.Fatalf("expected one UDP retry to be recorded, got %d", got)
	}
}

func TestNormalizeAndCacheDnsRespUsesMinimumAnswerTTL(t *testing.T) {
	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log:                 logrus.New(),
		CacheAccessCallback: func(*DnsCache) error { return nil },
		CacheRemoveCallback: func(*DnsCache) error { return nil },
		NewCache: func(_ string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			ips, hasAnyIP := summarizeDNSAnswers(answers)
			return &DnsCache{
				Answer:           answers,
				IPs:              ips,
				HasAnyIP:         hasAnyIP,
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
	controller.now = func() time.Time { return now }

	msg := new(dnsmessage.Msg)
	msg.SetQuestion("example.com.", dnsmessage.TypeA)
	msg.Response = true
	msg.Answer = []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   dnsmessage.CanonicalName("example.com."),
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			A: net.ParseIP("1.1.1.1").To4(),
		},
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   dnsmessage.CanonicalName("example.com."),
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    60,
			},
			A: net.ParseIP("2.2.2.2").To4(),
		},
	}

	if err := controller.NormalizeAndCacheDnsResp_(msg); err != nil {
		t.Fatal(err)
	}

	cacheKey := controller.cacheKey("example.com.", dnsmessage.TypeA)
	cache := controller.LookupDnsRespCache(cacheKey, false)
	if cache == nil {
		t.Fatal("expected dns cache entry")
	}
	wantDeadline := now.Add(60 * time.Second)
	if !cache.Deadline.Equal(wantDeadline) {
		t.Fatalf("unexpected effective deadline: got %v want %v", cache.Deadline, wantDeadline)
	}
	if !cache.OriginalDeadline.Equal(wantDeadline) {
		t.Fatalf("unexpected original deadline: got %v want %v", cache.OriginalDeadline, wantDeadline)
	}
}

func TestValidateDnsResponseForRequest(t *testing.T) {
	req := new(dnsmessage.Msg)
	req.SetQuestion("example.com.", dnsmessage.TypeA)

	t.Run("accepts matching question", func(t *testing.T) {
		resp := newTestDnsResponse("Example.COM.", dnsmessage.TypeA, newTestARecord("example.com.", "1.1.1.1"), false)
		if err := validateDnsResponseForRequest(req, resp, false); err != nil {
			t.Fatalf("validateDnsResponseForRequest() returned error: %v", err)
		}
	})

	t.Run("rejects missing question", func(t *testing.T) {
		resp := new(dnsmessage.Msg)
		resp.Response = true
		err := validateDnsResponseForRequest(req, resp, false)
		if err == nil {
			t.Fatal("expected missing response question to fail")
		}
		if !strings.Contains(err.Error(), "dns response missing question") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("rejects mismatched question", func(t *testing.T) {
		resp := newTestDnsResponse("other.example.", dnsmessage.TypeA, newTestARecord("other.example.", "2.2.2.2"), false)
		err := validateDnsResponseForRequest(req, resp, false)
		if err == nil {
			t.Fatal("expected mismatched response question to fail")
		}
		if !strings.Contains(err.Error(), "dns response question mismatch") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("rejects mismatched id when required", func(t *testing.T) {
		resp := newTestDnsResponse("example.com.", dnsmessage.TypeA, newTestARecord("example.com.", "4.4.4.4"), false)
		req.Id = 1234
		resp.Id = 5678
		err := validateDnsResponseForRequest(req, resp, true)
		if err == nil {
			t.Fatal("expected mismatched response id to fail")
		}
		if !strings.Contains(err.Error(), "dns response id mismatch") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("allows mismatched id when not required", func(t *testing.T) {
		resp := newTestDnsResponse("example.com.", dnsmessage.TypeA, newTestARecord("example.com.", "5.5.5.5"), false)
		req.Id = 4321
		resp.Id = 0
		if err := validateDnsResponseForRequest(req, resp, false); err != nil {
			t.Fatalf("expected mismatched response id to be ignored when not required, got: %v", err)
		}
	})
}

func TestNormalizeAndCacheDnsRespSkipsEmptySuccess(t *testing.T) {
	controller, err := NewDnsController(nil, &DnsControllerOption{
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
		BestDialerChooser:     func(*udpRequest, *componentdns.Upstream) (*dialArgument, error) { return nil, nil },
		TimeoutExceedCallback: func(*dialArgument, error) {},
	})
	if err != nil {
		t.Fatalf("NewDnsController() returned error: %v", err)
	}
	defer controller.Close()

	msg := new(dnsmessage.Msg)
	msg.SetQuestion("empty.example.", dnsmessage.TypeA)
	msg.Response = true

	if err := controller.NormalizeAndCacheDnsResp_(msg); err != nil {
		t.Fatal(err)
	}
	if len(controller.dnsCache) != 0 {
		t.Fatalf("expected empty success response not to be cached, got %d entries", len(controller.dnsCache))
	}
}

func TestUpdateDnsCacheTtlAppliesFixedDomainTTL(t *testing.T) {
	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log:                 logrus.New(),
		CacheAccessCallback: func(*DnsCache) error { return nil },
		CacheRemoveCallback: func(*DnsCache) error { return nil },
		NewCache: func(_ string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			ips, hasAnyIP := summarizeDNSAnswers(answers)
			return &DnsCache{
				Answer:           answers,
				IPs:              ips,
				HasAnyIP:         hasAnyIP,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
		BestDialerChooser:     func(*udpRequest, *componentdns.Upstream) (*dialArgument, error) { return nil, nil },
		TimeoutExceedCallback: func(*dialArgument, error) {},
		FixedDomainTtl:        map[string]int{"example.com": 10},
	})
	if err != nil {
		t.Fatalf("NewDnsController() returned error: %v", err)
	}
	defer controller.Close()

	now := time.Now()
	controller.now = func() time.Time { return now }

	if err := controller.UpdateDnsCacheTtl("example.com.", dnsmessage.TypeA, []dnsmessage.RR{newTestARecord("example.com.", "1.1.1.1")}, 60); err != nil {
		t.Fatal(err)
	}

	cache := controller.LookupDnsRespCache(controller.cacheKey("example.com.", dnsmessage.TypeA), false)
	if cache == nil {
		t.Fatal("expected dns cache entry")
	}
	if want := now.Add(10 * time.Second); !cache.Deadline.Equal(want) {
		t.Fatalf("unexpected effective deadline: got %v want %v", cache.Deadline, want)
	}
	if want := now.Add(60 * time.Second); !cache.OriginalDeadline.Equal(want) {
		t.Fatalf("unexpected original deadline: got %v want %v", cache.OriginalDeadline, want)
	}
}

func TestFixedDomainTTLZeroDisablesClientResponseCache(t *testing.T) {
	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log:                 logrus.New(),
		CacheAccessCallback: func(*DnsCache) error { return nil },
		CacheRemoveCallback: func(*DnsCache) error { return nil },
		NewCache: func(_ string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			ips, hasAnyIP := summarizeDNSAnswers(answers)
			return &DnsCache{
				Answer:           answers,
				IPs:              ips,
				HasAnyIP:         hasAnyIP,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
		BestDialerChooser:     func(*udpRequest, *componentdns.Upstream) (*dialArgument, error) { return nil, nil },
		TimeoutExceedCallback: func(*dialArgument, error) {},
		FixedDomainTtl:        map[string]int{"example.com": 0},
	})
	if err != nil {
		t.Fatalf("NewDnsController() returned error: %v", err)
	}
	defer controller.Close()

	now := time.Now()
	controller.now = func() time.Time { return now }

	if err := controller.UpdateDnsCacheTtl("example.com.", dnsmessage.TypeA, []dnsmessage.RR{newTestARecord("example.com.", "1.1.1.1")}, 60); err != nil {
		t.Fatal(err)
	}

	cacheKey := controller.cacheKey("example.com.", dnsmessage.TypeA)
	if cache := controller.LookupDnsRespCache(cacheKey, false); cache != nil {
		t.Fatal("expected fixed_domain_ttl: 0 to disable client response cache")
	}
	if _, ok := controller.dnsCache[cacheKey]; !ok {
		t.Fatal("expected internal DNS cache entry to remain for routing association")
	}
	if cache := controller.LookupDnsRespCache(cacheKey, true); cache == nil {
		t.Fatal("expected internal lookup to remain available until original upstream TTL")
	}
}

func TestUpdateDnsCacheDeadlineIgnoresFixedDomainTTL(t *testing.T) {
	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log:                 logrus.New(),
		CacheAccessCallback: func(*DnsCache) error { return nil },
		CacheRemoveCallback: func(*DnsCache) error { return nil },
		NewCache: func(_ string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			ips, hasAnyIP := summarizeDNSAnswers(answers)
			return &DnsCache{
				Answer:           answers,
				IPs:              ips,
				HasAnyIP:         hasAnyIP,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
		BestDialerChooser:     func(*udpRequest, *componentdns.Upstream) (*dialArgument, error) { return nil, nil },
		TimeoutExceedCallback: func(*dialArgument, error) {},
		FixedDomainTtl:        map[string]int{"upstream.example": 0},
	})
	if err != nil {
		t.Fatalf("NewDnsController() returned error: %v", err)
	}
	defer controller.Close()

	explicitDeadline := time.Now().Add(24 * time.Hour)
	if err := controller.UpdateDnsCacheDeadline("upstream.example", dnsmessage.TypeA, []dnsmessage.RR{newTestARecord("upstream.example.", "9.9.9.9")}, explicitDeadline); err != nil {
		t.Fatal(err)
	}

	cache := controller.LookupDnsRespCache(controller.cacheKey("upstream.example.", dnsmessage.TypeA), false)
	if cache == nil {
		t.Fatal("expected dns cache entry")
	}
	if !cache.Deadline.Equal(explicitDeadline) {
		t.Fatalf("unexpected explicit deadline: got %v want %v", cache.Deadline, explicitDeadline)
	}
	if !cache.OriginalDeadline.Equal(explicitDeadline) {
		t.Fatalf("unexpected original deadline: got %v want %v", cache.OriginalDeadline, explicitDeadline)
	}
}

func TestUpdateDnsCacheEvictsOldestWhenCacheFull(t *testing.T) {
	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log: logrus.New(),
		CacheAccessCallback: func(*DnsCache) error {
			return nil
		},
		CacheRemoveCallback: func(*DnsCache) error { return nil },
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
	for i := 0; i < dnsCacheMaxEntries; i++ {
		key := controller.cacheKey(fmt.Sprintf("old-%d.example.", i), dnsmessage.TypeA)
		controller.dnsCache[key] = &DnsCache{
			Deadline:         now.Add(time.Duration(i+1) * time.Second),
			OriginalDeadline: now.Add(time.Duration(i+1) * time.Second),
		}
	}

	if err := controller.UpdateDnsCacheDeadline("new.example", dnsmessage.TypeA, []dnsmessage.RR{}, now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(controller.dnsCache) != dnsCacheMaxEntries {
		t.Fatalf("expected cache size to stay capped at %d, got %d", dnsCacheMaxEntries, len(controller.dnsCache))
	}
	if _, ok := controller.dnsCache[controller.cacheKey("old-0.example.", dnsmessage.TypeA)]; ok {
		t.Fatal("expected oldest dns cache entry to be evicted")
	}
	if _, ok := controller.dnsCache[controller.cacheKey("new.example.", dnsmessage.TypeA)]; !ok {
		t.Fatal("expected new dns cache entry to be retained")
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

func TestDialSendRetriesTruncatedTCPUDPResponseOverTCP(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	routing, err := componentdns.New(&config.Dns{
		Upstream: []config.KeyableString{
			"test:tcp+udp://1.1.1.1:53",
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
		Logger: log,
		UpstreamReadyCallback: func(*componentdns.Upstream) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("failed to build dns routing: %v", err)
	}

	var chosenSchemes []componentdns.UpstreamScheme
	var usedProtos []consts.L4ProtoStr
	controller, err := NewDnsController(routing, &DnsControllerOption{
		Log:                 log,
		CacheAccessCallback: func(*DnsCache) error { return nil },
		CacheRemoveCallback: func(*DnsCache) error { return nil },
		NewCache: func(_ string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			ips, hasAnyIP := summarizeDNSAnswers(answers)
			return &DnsCache{
				Answer:           answers,
				IPs:              ips,
				HasAnyIP:         hasAnyIP,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
		BestDialerChooser: func(_ *udpRequest, upstream *componentdns.Upstream) (*dialArgument, error) {
			chosenSchemes = append(chosenSchemes, upstream.Scheme)
			switch upstream.Scheme {
			case componentdns.UpstreamScheme_TCP_UDP:
				return &dialArgument{
					l4proto:   consts.L4ProtoStr_UDP,
					ipversion: consts.IpVersionStr_4,
				}, nil
			case componentdns.UpstreamScheme_TCP:
				return &dialArgument{
					l4proto:   consts.L4ProtoStr_TCP,
					ipversion: consts.IpVersionStr_4,
				}, nil
			default:
				return nil, fmt.Errorf("unexpected upstream scheme: %v", upstream.Scheme)
			}
		},
		TimeoutExceedCallback: func(*dialArgument, error) {},
	})
	if err != nil {
		t.Fatalf("NewDnsController() returned error: %v", err)
	}
	defer controller.Close()

	var requestID uint16
	controller.forwarderFactory = func(_ *componentdns.Upstream, dialArg dialArgument) (DnsForwarder, error) {
		usedProtos = append(usedProtos, dialArg.l4proto)
		switch dialArg.l4proto {
		case consts.L4ProtoStr_UDP:
			resp := newTestDnsResponse(
				"example.com.",
				dnsmessage.TypeA,
				newTestARecord("example.com.", "1.1.1.1"),
				true,
			)
			resp.Id = requestID
			return &fakeDnsForwarder{
				msg: resp,
			}, nil
		case consts.L4ProtoStr_TCP:
			resp := newTestDnsResponse(
				"example.com.",
				dnsmessage.TypeA,
				newTestARecord("example.com.", "2.2.2.2"),
				false,
			)
			resp.Id = requestID
			return &fakeDnsForwarder{
				msg: resp,
			}, nil
		default:
			return nil, fmt.Errorf("unexpected l4proto: %v", dialArg.l4proto)
		}
	}

	req := &udpRequest{
		ctx:           context.Background(),
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
	requestID = msg.Id

	before := snapshotDnsObservabilityStats()
	err = controller.dialSend(0, req, data, msg.Id, &componentdns.Upstream{
		Scheme:   componentdns.UpstreamScheme_TCP_UDP,
		Hostname: "1.1.1.1",
		Port:     53,
		Index:    consts.DnsRequestOutboundIndex(0),
		Ip46: &netutils.Ip46{
			Ip4: netip.MustParseAddr("1.1.1.1"),
		},
	}, false)
	if err != nil {
		t.Fatalf("dialSend() returned error: %v", err)
	}
	after := snapshotDnsObservabilityStats()
	if len(chosenSchemes) != 2 || chosenSchemes[0] != componentdns.UpstreamScheme_TCP_UDP || chosenSchemes[1] != componentdns.UpstreamScheme_TCP {
		t.Fatalf("unexpected upstream schemes chosen: %v", chosenSchemes)
	}
	if len(usedProtos) != 2 || usedProtos[0] != consts.L4ProtoStr_UDP || usedProtos[1] != consts.L4ProtoStr_TCP {
		t.Fatalf("unexpected forwarder protocols: %v", usedProtos)
	}

	cache := controller.LookupDnsRespCache(controller.cacheKey("example.com.", dnsmessage.TypeA), false)
	if cache == nil {
		t.Fatal("expected DNS cache entry after successful fallback")
	}
	if !cache.IncludeIp(netip.MustParseAddr("2.2.2.2")) {
		t.Fatalf("expected cache to contain TCP fallback answer, got %v", cache.cachedIPs())
	}
	if cache.IncludeIp(netip.MustParseAddr("1.1.1.1")) {
		t.Fatalf("expected truncated UDP answer to be replaced, got %v", cache.cachedIPs())
	}
	if got := after.DnsTruncatedTcpFallbackTotal - before.DnsTruncatedTcpFallbackTotal; got != 1 {
		t.Fatalf("expected one truncated TCP fallback to be recorded, got %d", got)
	}
}

func TestDialSendDoesNotRetryTruncatedPureUDPResponseOverTCP(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

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
		Logger: log,
		UpstreamReadyCallback: func(*componentdns.Upstream) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("failed to build dns routing: %v", err)
	}

	var chosenSchemes []componentdns.UpstreamScheme
	var usedProtos []consts.L4ProtoStr
	controller, err := NewDnsController(routing, &DnsControllerOption{
		Log:                 log,
		CacheAccessCallback: func(*DnsCache) error { return nil },
		CacheRemoveCallback: func(*DnsCache) error { return nil },
		NewCache: func(_ string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			ips, hasAnyIP := summarizeDNSAnswers(answers)
			return &DnsCache{
				Answer:           answers,
				IPs:              ips,
				HasAnyIP:         hasAnyIP,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
		BestDialerChooser: func(_ *udpRequest, upstream *componentdns.Upstream) (*dialArgument, error) {
			chosenSchemes = append(chosenSchemes, upstream.Scheme)
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

	var requestID uint16
	controller.forwarderFactory = func(_ *componentdns.Upstream, dialArg dialArgument) (DnsForwarder, error) {
		usedProtos = append(usedProtos, dialArg.l4proto)
		resp := newTestDnsResponse(
			"example.com.",
			dnsmessage.TypeA,
			newTestARecord("example.com.", "3.3.3.3"),
			true,
		)
		resp.Id = requestID
		return &fakeDnsForwarder{
			msg: resp,
		}, nil
	}

	req := &udpRequest{
		ctx:           context.Background(),
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
	requestID = msg.Id

	before := snapshotDnsObservabilityStats()
	err = controller.dialSend(0, req, data, msg.Id, &componentdns.Upstream{
		Scheme:   componentdns.UpstreamScheme_UDP,
		Hostname: "1.1.1.1",
		Port:     53,
		Index:    consts.DnsRequestOutboundIndex(0),
		Ip46: &netutils.Ip46{
			Ip4: netip.MustParseAddr("1.1.1.1"),
		},
	}, false)
	if err != nil {
		t.Fatalf("dialSend() returned error: %v", err)
	}
	after := snapshotDnsObservabilityStats()
	if len(chosenSchemes) != 1 || chosenSchemes[0] != componentdns.UpstreamScheme_UDP {
		t.Fatalf("unexpected upstream schemes chosen: %v", chosenSchemes)
	}
	if len(usedProtos) != 1 || usedProtos[0] != consts.L4ProtoStr_UDP {
		t.Fatalf("unexpected forwarder protocols: %v", usedProtos)
	}
	if got := after.DnsTruncatedTcpFallbackTotal - before.DnsTruncatedTcpFallbackTotal; got != 0 {
		t.Fatalf("expected no truncated TCP fallback to be recorded, got %d", got)
	}
}

func TestDialSendRejectsMismatchedResponseQuestion(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

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
		Logger: log,
		UpstreamReadyCallback: func(*componentdns.Upstream) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("failed to build dns routing: %v", err)
	}

	controller, err := NewDnsController(routing, &DnsControllerOption{
		Log:                 log,
		CacheAccessCallback: func(*DnsCache) error { return nil },
		CacheRemoveCallback: func(*DnsCache) error { return nil },
		NewCache: func(_ string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			ips, hasAnyIP := summarizeDNSAnswers(answers)
			return &DnsCache{
				Answer:           answers,
				IPs:              ips,
				HasAnyIP:         hasAnyIP,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
		BestDialerChooser: func(_ *udpRequest, upstream *componentdns.Upstream) (*dialArgument, error) {
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

	var requestID uint16
	controller.forwarderFactory = func(_ *componentdns.Upstream, dialArg dialArgument) (DnsForwarder, error) {
		resp := newTestDnsResponse(
			"other.example.",
			dnsmessage.TypeA,
			newTestARecord("other.example.", "3.3.3.3"),
			false,
		)
		resp.Id = requestID
		return &fakeDnsForwarder{
			msg: resp,
		}, nil
	}

	req := &udpRequest{
		ctx:           context.Background(),
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
	requestID = msg.Id

	err = controller.dialSend(0, req, data, msg.Id, &componentdns.Upstream{
		Scheme:   componentdns.UpstreamScheme_UDP,
		Hostname: "1.1.1.1",
		Port:     53,
		Index:    consts.DnsRequestOutboundIndex(0),
		Ip46: &netutils.Ip46{
			Ip4: netip.MustParseAddr("1.1.1.1"),
		},
	}, false)
	if err == nil {
		t.Fatal("expected dialSend() to reject mismatched response question")
	}
	if !strings.Contains(err.Error(), "dns response question mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
	if cache := controller.LookupDnsRespCache(controller.cacheKey("example.com.", dnsmessage.TypeA), false); cache != nil {
		t.Fatal("expected no dns cache entry after mismatched response question")
	}
}

func TestDialSendRejectsMismatchedResponseIDForUdpUpstream(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

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
		Logger: log,
		UpstreamReadyCallback: func(*componentdns.Upstream) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("failed to build dns routing: %v", err)
	}

	controller, err := NewDnsController(routing, &DnsControllerOption{
		Log:                 log,
		CacheAccessCallback: func(*DnsCache) error { return nil },
		CacheRemoveCallback: func(*DnsCache) error { return nil },
		NewCache: func(_ string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			ips, hasAnyIP := summarizeDNSAnswers(answers)
			return &DnsCache{
				Answer:           answers,
				IPs:              ips,
				HasAnyIP:         hasAnyIP,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
		BestDialerChooser: func(_ *udpRequest, upstream *componentdns.Upstream) (*dialArgument, error) {
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

	controller.forwarderFactory = func(_ *componentdns.Upstream, dialArg dialArgument) (DnsForwarder, error) {
		resp := newTestDnsResponse(
			"example.com.",
			dnsmessage.TypeA,
			newTestARecord("example.com.", "6.6.6.6"),
			false,
		)
		resp.Id = 9999
		return &fakeDnsForwarder{msg: resp}, nil
	}

	req := &udpRequest{
		ctx:           context.Background(),
		realSrc:       netip.MustParseAddrPort("127.0.0.1:43210"),
		realDst:       netip.MustParseAddrPort("127.0.0.1:53"),
		src:           netip.MustParseAddrPort("127.0.0.1:43210"),
		routingResult: &bpfRoutingResult{},
	}
	msg := new(dnsmessage.Msg)
	msg.SetQuestion("example.com.", dnsmessage.TypeA)
	msg.Id = 1234
	data, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}

	err = controller.dialSend(0, req, data, msg.Id, &componentdns.Upstream{
		Scheme:   componentdns.UpstreamScheme_UDP,
		Hostname: "1.1.1.1",
		Port:     53,
		Index:    consts.DnsRequestOutboundIndex(0),
		Ip46: &netutils.Ip46{
			Ip4: netip.MustParseAddr("1.1.1.1"),
		},
	}, false)
	if err == nil {
		t.Fatal("expected dialSend() to reject mismatched response id")
	}
	if !strings.Contains(err.Error(), "dns response id mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
	if cache := controller.LookupDnsRespCache(controller.cacheKey("example.com.", dnsmessage.TypeA), false); cache != nil {
		t.Fatal("expected no dns cache entry after mismatched response id")
	}
}

func TestDialSendAllowsZeroResponseIDForDoH(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	routing, err := componentdns.New(&config.Dns{
		Upstream: []config.KeyableString{
			"test:https://dns.example.com/dns-query",
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
		Logger: log,
		UpstreamReadyCallback: func(*componentdns.Upstream) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("failed to build dns routing: %v", err)
	}

	controller, err := NewDnsController(routing, &DnsControllerOption{
		Log:                 log,
		CacheAccessCallback: func(*DnsCache) error { return nil },
		CacheRemoveCallback: func(*DnsCache) error { return nil },
		NewCache: func(_ string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			ips, hasAnyIP := summarizeDNSAnswers(answers)
			return &DnsCache{
				Answer:           answers,
				IPs:              ips,
				HasAnyIP:         hasAnyIP,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
		BestDialerChooser: func(_ *udpRequest, upstream *componentdns.Upstream) (*dialArgument, error) {
			return &dialArgument{
				l4proto:   consts.L4ProtoStr_TCP,
				ipversion: consts.IpVersionStr_4,
			}, nil
		},
		TimeoutExceedCallback: func(*dialArgument, error) {},
	})
	if err != nil {
		t.Fatalf("NewDnsController() returned error: %v", err)
	}
	defer controller.Close()

	controller.forwarderFactory = func(_ *componentdns.Upstream, dialArg dialArgument) (DnsForwarder, error) {
		resp := newTestDnsResponse(
			"example.com.",
			dnsmessage.TypeA,
			newTestARecord("example.com.", "7.7.7.7"),
			false,
		)
		resp.Id = 0
		return &fakeDnsForwarder{msg: resp}, nil
	}

	req := &udpRequest{
		ctx:           context.Background(),
		realSrc:       netip.MustParseAddrPort("127.0.0.1:43210"),
		realDst:       netip.MustParseAddrPort("127.0.0.1:53"),
		src:           netip.MustParseAddrPort("127.0.0.1:43210"),
		routingResult: &bpfRoutingResult{},
	}
	msg := new(dnsmessage.Msg)
	msg.SetQuestion("example.com.", dnsmessage.TypeA)
	msg.Id = 2468
	data, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}

	err = controller.dialSend(0, req, data, msg.Id, &componentdns.Upstream{
		Scheme:   componentdns.UpstreamScheme_HTTPS,
		Hostname: "dns.example.com",
		Port:     443,
		Path:     "/dns-query",
		Index:    consts.DnsRequestOutboundIndex(0),
		Ip46: &netutils.Ip46{
			Ip4: netip.MustParseAddr("1.1.1.1"),
		},
	}, false)
	if err != nil {
		t.Fatalf("expected DoH-style zero response id to be accepted, got: %v", err)
	}
	cache := controller.LookupDnsRespCache(controller.cacheKey("example.com.", dnsmessage.TypeA), false)
	if cache == nil {
		t.Fatal("expected dns cache entry after accepted DoH-style zero response id")
	}
	if !cache.IncludeIp(netip.MustParseAddr("7.7.7.7")) {
		t.Fatalf("expected cache to contain DoH answer, got %v", cache.cachedIPs())
	}
}

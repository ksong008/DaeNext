/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"net/netip"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func newDnsCacheRestoreTestController(t *testing.T, domainBitmaps map[string][]uint32) *DnsController {
	t.Helper()
	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log: logrus.New(),
		NewCache: func(fqdn string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			ips, hasAnyIP := summarizeDNSAnswers(answers)
			return &DnsCache{
				DomainBitmap:     append([]uint32(nil), domainBitmaps[fqdn]...),
				Answer:           answers,
				IPs:              ips,
				HasAnyIP:         hasAnyIP,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewDnsController() returned error: %v", err)
	}
	t.Cleanup(func() {
		_ = controller.Close()
	})
	return controller
}

func TestRestoreDnsCacheSnapshotParsesLegacyAndStructuredKeys(t *testing.T) {
	deadline := time.Now().Add(time.Hour)
	controller := newDnsCacheRestoreTestController(t, map[string][]uint32{
		"legacy.example.": domainRoutingBitmap(0x10),
		"class.example.":  domainRoutingBitmap(0x20),
	})

	restoreDnsCacheSnapshot(logrus.New(), controller, map[string]*DnsCache{
		"legacy.example.1": {
			DomainBitmap:     domainRoutingBitmap(0x1),
			IPs:              []netip.Addr{netip.MustParseAddr("203.0.113.10")},
			HasAnyIP:         true,
			Deadline:         deadline,
			OriginalDeadline: deadline,
		},
		newDnsCacheKey("class.example.", dnsmessage.TypeA, 3).String(): {
			DomainBitmap:     domainRoutingBitmap(0x2),
			IPs:              []netip.Addr{netip.MustParseAddr("203.0.113.11")},
			HasAnyIP:         true,
			Deadline:         deadline,
			OriginalDeadline: deadline,
		},
	})

	legacyCache := controller.LookupDnsRespCache(controller.cacheKey("legacy.example.", dnsmessage.TypeA), false)
	if legacyCache == nil {
		t.Fatal("expected legacy-format cache key to be restored")
	}
	if got := legacyCache.DomainBitmap[0]; got != 0x10 {
		t.Fatalf("legacy cache domain bitmap = %#x, want recomputed bitmap %#x", got, uint32(0x10))
	}
	if !legacyCache.Deadline.Equal(deadline) || !legacyCache.OriginalDeadline.Equal(deadline) {
		t.Fatal("expected restored cache to preserve snapshot deadlines")
	}

	structuredKey := controller.cacheKeyFromParts("class.example.", dnsmessage.TypeA, 3)
	structuredCache := controller.LookupDnsRespCache(structuredKey, false)
	if structuredCache == nil {
		t.Fatal("expected structured qclass cache key to be restored")
	}
	if got := structuredCache.DomainBitmap[0]; got != 0x20 {
		t.Fatalf("structured cache domain bitmap = %#x, want recomputed bitmap %#x", got, uint32(0x20))
	}
	if cache := controller.LookupDnsRespCache(controller.cacheKey("class.example.", dnsmessage.TypeA), false); cache != nil {
		t.Fatal("expected INET-class lookup to miss for non-INET restored cache")
	}

	req := new(dnsmessage.Msg)
	req.Question = []dnsmessage.Question{{
		Name:   dnsmessage.CanonicalName("class.example."),
		Qtype:  dnsmessage.TypeA,
		Qclass: 3,
	}}
	resp := controller.LookupDnsRespCache_(req, structuredKey, false)
	if resp == nil {
		t.Fatal("expected restored structured cache to produce a DNS response")
	}
	var respMsg dnsmessage.Msg
	if err := respMsg.Unpack(resp); err != nil {
		t.Fatal(err)
	}
	if got := respMsg.Answer[0].Header().Class; got != 3 {
		t.Fatalf("restored response class = %d, want 3", got)
	}
}

func TestRestoreDnsCacheSnapshotPreservesPackedCNAMEAndQuestionDomainBitmap(t *testing.T) {
	deadline := time.Now().Add(time.Hour)
	alias := dnsmessage.CanonicalName("alias.example.")
	target := dnsmessage.CanonicalName("target.example.")

	req := new(dnsmessage.Msg)
	req.SetQuestion(alias, dnsmessage.TypeA)
	resp := new(dnsmessage.Msg)
	resp.SetReply(req)
	resp.Answer = []dnsmessage.RR{
		&dnsmessage.CNAME{
			Hdr: dnsmessage.RR_Header{
				Name:   alias,
				Rrtype: dnsmessage.TypeCNAME,
				Class:  dnsmessage.ClassINET,
				Ttl:    60,
			},
			Target: target,
		},
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   target,
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    60,
			},
			A: net.ParseIP("203.0.113.20").To4(),
		},
	}
	packed, err := resp.Pack()
	if err != nil {
		t.Fatal(err)
	}

	controller := newDnsCacheRestoreTestController(t, map[string][]uint32{
		alias:  domainRoutingBitmap(0x40),
		target: domainRoutingBitmap(0x80),
	})
	cacheKey := newDnsCacheKey(alias, dnsmessage.TypeA, dnsmessage.ClassINET)
	restoreDnsCacheSnapshot(logrus.New(), controller, map[string]*DnsCache{
		cacheKey.String(): {
			DomainBitmap:     domainRoutingBitmap(0x1),
			PackedResponse:   packed,
			Deadline:         deadline,
			OriginalDeadline: deadline,
		},
	})

	cache := controller.LookupDnsRespCache(cacheKey, false)
	if cache == nil {
		t.Fatal("expected packed CNAME cache to be restored")
	}
	if got := cache.DomainBitmap[0]; got != 0x40 {
		t.Fatalf("restored CNAME cache domain bitmap = %#x, want original question bitmap %#x", got, uint32(0x40))
	}
	if !cache.IncludeIp(netip.MustParseAddr("203.0.113.20")) {
		t.Fatal("expected restored CNAME cache to retain target A IP for domain routing")
	}

	respBytes := controller.LookupDnsRespCache_(req, cacheKey, false)
	if respBytes == nil {
		t.Fatal("expected restored CNAME cache to produce a packed response")
	}
	var restored dnsmessage.Msg
	if err := restored.Unpack(respBytes); err != nil {
		t.Fatal(err)
	}
	if len(restored.Answer) != 2 {
		t.Fatalf("restored answer count = %d, want 2", len(restored.Answer))
	}
	if _, ok := restored.Answer[0].(*dnsmessage.CNAME); !ok {
		t.Fatalf("restored first answer type = %T, want CNAME", restored.Answer[0])
	}
	if a, ok := restored.Answer[1].(*dnsmessage.A); !ok {
		t.Fatalf("restored second answer type = %T, want A", restored.Answer[1])
	} else if got := netip.MustParseAddr(a.A.String()); got != netip.MustParseAddr("203.0.113.20") {
		t.Fatalf("restored target A = %s, want 203.0.113.20", got)
	}
}

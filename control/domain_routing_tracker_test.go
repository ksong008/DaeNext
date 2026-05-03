/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"net"
	"net/netip"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/daeuniverse/dae/common"
	dnsmessage "github.com/miekg/dns"
)

func newDomainRoutingTestMap(t *testing.T) *ebpf.Map {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("requires ebpf memlock privileges: %v", err)
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof([4]uint32{})),
		ValueSize:  uint32(unsafe.Sizeof(bpfDomainRouting{})),
		MaxEntries: 128,
	})
	if err != nil {
		t.Fatalf("ebpf.NewMap(): %v", err)
	}
	t.Cleanup(func() {
		_ = m.Close()
	})
	return m
}

func domainRoutingBitmap(words ...uint32) []uint32 {
	bitmap := make([]uint32, len(bpfDomainRouting{}.Bitmap))
	copy(bitmap, words)
	return bitmap
}

func domainRoutingACache(ownerKey string, ip string, bitmap []uint32) *DnsCache {
	return &DnsCache{
		RouteOwnerKey: ownerKey,
		DomainBitmap:  bitmap,
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "shared.test.",
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP(ip).To4(),
			},
		},
	}
}

func TestDomainRoutingTrackerMergesSharedIPAcrossOwners(t *testing.T) {
	domainMap := newDomainRoutingTestMap(t)
	core := &controlPlaneCore{
		bpf: &bpfObjects{
			bpfMaps: bpfMaps{
				DomainRoutingMap: domainMap,
			},
		},
		domainRouting: newDomainRoutingTracker(),
	}

	cacheA := domainRoutingACache("cache-a", "203.0.113.10", domainRoutingBitmap(0x1))
	cacheB := domainRoutingACache("cache-b", "203.0.113.10", domainRoutingBitmap(0x2))
	ip := netip.MustParseAddr("203.0.113.10")
	ip16 := ip.As16()
	ipKey := common.Ipv6ByteSliceToUint32Array(ip16[:])

	if err := core.BatchUpdateDomainRouting(cacheA); err != nil {
		t.Fatalf("BatchUpdateDomainRouting(cacheA): %v", err)
	}
	if err := core.BatchUpdateDomainRouting(cacheB); err != nil {
		t.Fatalf("BatchUpdateDomainRouting(cacheB): %v", err)
	}

	var got bpfDomainRouting
	if err := domainMap.Lookup(&ipKey, &got); err != nil {
		t.Fatalf("Lookup(shared ip): %v", err)
	}
	if got.Bitmap[0] != 0x3 {
		t.Fatalf("merged bitmap[0] = %#x, want %#x", got.Bitmap[0], uint32(0x3))
	}

	if err := core.BatchRemoveDomainRouting(cacheA); err != nil {
		t.Fatalf("BatchRemoveDomainRouting(cacheA): %v", err)
	}
	if err := domainMap.Lookup(&ipKey, &got); err != nil {
		t.Fatalf("Lookup(shared ip after remove A): %v", err)
	}
	if got.Bitmap[0] != 0x2 {
		t.Fatalf("bitmap after removing A = %#x, want %#x", got.Bitmap[0], uint32(0x2))
	}

	if err := core.BatchRemoveDomainRouting(cacheB); err != nil {
		t.Fatalf("BatchRemoveDomainRouting(cacheB): %v", err)
	}
	if err := domainMap.Lookup(&ipKey, &got); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("Lookup(shared ip after remove B) err = %v, want %v", err, ebpf.ErrKeyNotExist)
	}
}

func TestDomainRoutingTrackerReplacesOwnerSnapshotWithoutLeakingRefs(t *testing.T) {
	domainMap := newDomainRoutingTestMap(t)
	core := &controlPlaneCore{
		bpf: &bpfObjects{
			bpfMaps: bpfMaps{
				DomainRoutingMap: domainMap,
			},
		},
		domainRouting: newDomainRoutingTracker(),
	}

	first := &DnsCache{
		RouteOwnerKey: "cache-owner",
		DomainBitmap:  domainRoutingBitmap(0x4),
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "replace.test.",
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP("203.0.113.20").To4(),
			},
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "replace.test.",
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP("203.0.113.21").To4(),
			},
		},
	}
	second := domainRoutingACache("cache-owner", "203.0.113.20", domainRoutingBitmap(0x4))

	ip20Addr := netip.MustParseAddr("203.0.113.20")
	ip20Bytes := ip20Addr.As16()
	ip20 := common.Ipv6ByteSliceToUint32Array(ip20Bytes[:])
	ip21Addr := netip.MustParseAddr("203.0.113.21")
	ip21Bytes := ip21Addr.As16()
	ip21 := common.Ipv6ByteSliceToUint32Array(ip21Bytes[:])

	if err := core.BatchUpdateDomainRouting(first); err != nil {
		t.Fatalf("BatchUpdateDomainRouting(first): %v", err)
	}
	if err := core.BatchUpdateDomainRouting(second); err != nil {
		t.Fatalf("BatchUpdateDomainRouting(second): %v", err)
	}
	if err := core.BatchUpdateDomainRouting(second); err != nil {
		t.Fatalf("BatchUpdateDomainRouting(second repeat): %v", err)
	}

	var got bpfDomainRouting
	if err := domainMap.Lookup(&ip20, &got); err != nil {
		t.Fatalf("Lookup(ip20): %v", err)
	}
	if got.Bitmap[0] != 0x4 {
		t.Fatalf("bitmap for ip20 = %#x, want %#x", got.Bitmap[0], uint32(0x4))
	}
	if err := domainMap.Lookup(&ip21, &got); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("Lookup(ip21) err = %v, want %v", err, ebpf.ErrKeyNotExist)
	}

	if err := core.BatchRemoveDomainRouting(second); err != nil {
		t.Fatalf("BatchRemoveDomainRouting(second): %v", err)
	}
	if err := domainMap.Lookup(&ip20, &got); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("Lookup(ip20 after remove) err = %v, want %v", err, ebpf.ErrKeyNotExist)
	}
}

func TestUpdateDnsCacheDeadlineAssignsRouteOwnerKey(t *testing.T) {
	controller, err := NewDnsController(nil, &DnsControllerOption{
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
	})
	if err != nil {
		t.Fatalf("NewDnsController(): %v", err)
	}
	defer controller.Close()

	if err := controller.UpdateDnsCacheTtl("owner.example.", dnsmessage.TypeA, []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "owner.example.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    60,
			},
			A: net.ParseIP("203.0.113.88").To4(),
		},
	}, 60); err != nil {
		t.Fatalf("UpdateDnsCacheTtl(): %v", err)
	}

	cache := controller.LookupDnsRespCache(controller.cacheKey("owner.example.", dnsmessage.TypeA), false)
	if cache == nil {
		t.Fatal("expected dns cache entry")
	}
	if cache.RouteOwnerKey != controller.cacheKey("owner.example.", dnsmessage.TypeA) {
		t.Fatalf("RouteOwnerKey = %q, want %q", cache.RouteOwnerKey, controller.cacheKey("owner.example.", dnsmessage.TypeA))
	}
}

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"net/netip"
	"time"

	dnsmessage "github.com/miekg/dns"
	"github.com/mohae/deepcopy"
)

type DnsCache struct {
	DomainBitmap     []uint32
	Answer           []dnsmessage.RR
	IPs              []netip.Addr
	HasAnyIP         bool
	Deadline         time.Time
	OriginalDeadline time.Time // This field is not impacted by `fixed_domain_ttl`.
	PackedResponse   []byte
}

func (c *DnsCache) Clone() *DnsCache {
	if c == nil {
		return nil
	}
	clone := *c
	clone.DomainBitmap = append([]uint32(nil), c.DomainBitmap...)
	clone.Answer = append([]dnsmessage.RR(nil), c.Answer...)
	clone.IPs = append([]netip.Addr(nil), c.IPs...)
	clone.PackedResponse = append([]byte(nil), c.PackedResponse...)
	return &clone
}

func summarizeDNSAnswers(answers []dnsmessage.RR) (ips []netip.Addr, hasAnyIP bool) {
	if len(answers) == 0 {
		return nil, false
	}

	ips = make([]netip.Addr, 0, len(answers))
	for _, ans := range answers {
		switch body := ans.(type) {
		case *dnsmessage.A:
			hasAnyIP = true
			if ip, ok := netip.AddrFromSlice(body.A); ok && !ip.IsUnspecified() {
				ips = append(ips, ip)
			}
		case *dnsmessage.AAAA:
			hasAnyIP = true
			if ip, ok := netip.AddrFromSlice(body.AAAA); ok && !ip.IsUnspecified() {
				ips = append(ips, ip)
			}
		}
	}
	return ips, hasAnyIP
}

func (c *DnsCache) cachedIPs() []netip.Addr {
	if len(c.IPs) > 0 || len(c.Answer) == 0 {
		return c.IPs
	}
	ips, _ := summarizeDNSAnswers(c.Answer)
	return ips
}

func (c *DnsCache) cachedHasAnyIP() bool {
	if c.HasAnyIP || len(c.Answer) == 0 {
		return c.HasAnyIP
	}
	_, hasAnyIP := summarizeDNSAnswers(c.Answer)
	return hasAnyIP
}

func (c *DnsCache) FillInto(req *dnsmessage.Msg) {
	if len(c.Answer) == 0 && len(c.PackedResponse) >= 2 {
		b := append([]byte(nil), c.PackedResponse...)
		binary.BigEndian.PutUint16(b[:2], req.Id)
		if err := req.Unpack(b); err == nil {
			return
		}
	}
	if len(c.Answer) == 0 {
		req.Answer = nil
	} else {
		req.Answer = deepcopy.Copy(c.Answer).([]dnsmessage.RR)
	}
	req.Rcode = dnsmessage.RcodeSuccess
	req.Response = true
	req.RecursionAvailable = true
	req.Truncated = false
}

func (c *DnsCache) FillPackedResponse(msgID uint16) []byte {
	if len(c.PackedResponse) < 2 {
		return nil
	}
	b := append([]byte(nil), c.PackedResponse...)
	binary.BigEndian.PutUint16(b[:2], msgID)
	return b
}

func (c *DnsCache) IncludeIp(ip netip.Addr) bool {
	for _, cachedIP := range c.cachedIPs() {
		if cachedIP == ip {
			return true
		}
	}
	return false
}

func (c *DnsCache) IncludeAnyIp() bool {
	return c.cachedHasAnyIP()
}

func (c *DnsCache) AnswersForHostQType(host string, dnsTyp uint16) []dnsmessage.RR {
	fqdn := dnsmessage.CanonicalName(host)
	answers := make([]dnsmessage.RR, 0, len(c.cachedIPs()))
	for _, ip := range c.cachedIPs() {
		switch dnsTyp {
		case dnsmessage.TypeA:
			if !(ip.Is4() || ip.Is4In6()) {
				continue
			}
			answers = append(answers, &dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   fqdn,
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    0,
				},
				A: ip.Unmap().AsSlice(),
			})
		case dnsmessage.TypeAAAA:
			if !ip.Is6() || ip.Is4In6() {
				continue
			}
			answers = append(answers, &dnsmessage.AAAA{
				Hdr: dnsmessage.RR_Header{
					Name:   fqdn,
					Rrtype: dnsmessage.TypeAAAA,
					Class:  dnsmessage.ClassINET,
					Ttl:    0,
				},
				AAAA: ip.AsSlice(),
			})
		}
	}
	return answers
}

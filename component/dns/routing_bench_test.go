/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing/domain_matcher"
	"github.com/daeuniverse/dae/pkg/trie"
	"github.com/sirupsen/logrus"
)

func BenchmarkRequestMatcherSelect(b *testing.B) {
	matcher := benchRequestMatcher(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		got, err := matcher.Match("www.example.com.", 1)
		if err != nil {
			b.Fatal(err)
		}
		if got != consts.DnsRequestOutboundIndex(2) {
			b.Fatalf("unexpected request upstream: %v", got)
		}
	}
}

func BenchmarkResponseMatcherSelect(b *testing.B) {
	matcher := benchResponseMatcher(b)
	ips := []netip.Addr{netip.MustParseAddr("203.0.113.42")}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		got, err := matcher.Match("www.example.com.", 1, ips, consts.DnsRequestOutboundIndex(2))
		if err != nil {
			b.Fatal(err)
		}
		if got != consts.DnsResponseOutboundIndex_Accept {
			b.Fatalf("unexpected response upstream: %v", got)
		}
	}
}

func benchRequestMatcher(b testing.TB) *RequestMatcher {
	b.Helper()
	matcher := domain_matcher.NewAhocorasickSlimtrie(logrus.New(), consts.MaxMatchSetLen)
	matcher.AddSet(0, []string{"example.com"}, consts.RoutingDomainKey_Suffix)
	if err := matcher.Build(); err != nil {
		b.Fatal(err)
	}
	return &RequestMatcher{
		domainMatcher: matcher,
		matches: []requestMatchSet{
			{Type: consts.MatchType_DomainSet, Upstream: uint8(consts.DnsRequestOutboundIndex_LogicalAnd)},
			{Type: consts.MatchType_QType, Value: 1, Upstream: 2},
			{Type: consts.MatchType_Fallback, Upstream: uint8(consts.DnsRequestOutboundIndex_AsIs)},
		},
	}
}

func benchResponseMatcher(b testing.TB) *ResponseMatcher {
	b.Helper()
	domainMatcher := domain_matcher.NewAhocorasickSlimtrie(logrus.New(), consts.MaxMatchSetLen)
	domainMatcher.AddSet(0, []string{"example.com"}, consts.RoutingDomainKey_Suffix)
	if err := domainMatcher.Build(); err != nil {
		b.Fatal(err)
	}
	ipSet, err := trie.NewTrieFromPrefixes([]netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/24"),
	})
	if err != nil {
		b.Fatal(err)
	}
	return &ResponseMatcher{
		domainMatcher: domainMatcher,
		ipSet:         []*trie.Trie{ipSet},
		matches: []responseMatchSet{
			{Type: consts.MatchType_DomainSet, Upstream: uint8(consts.DnsResponseOutboundIndex_LogicalAnd)},
			{Type: consts.MatchType_QType, Value: 1, Upstream: uint8(consts.DnsResponseOutboundIndex_LogicalAnd)},
			{Type: consts.MatchType_IpSet, Value: 0, Upstream: uint8(consts.DnsResponseOutboundIndex_LogicalAnd)},
			{Type: consts.MatchType_Upstream, Value: 2, Upstream: uint8(consts.DnsResponseOutboundIndex_Accept)},
			{Type: consts.MatchType_Fallback, Upstream: uint8(consts.DnsResponseOutboundIndex_Reject)},
		},
	}
}

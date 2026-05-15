package control

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing/domain_matcher"
	"github.com/daeuniverse/dae/pkg/trie"
	"github.com/sirupsen/logrus"
)

func testRoutingMatcherAddr(t testing.TB, value string) []byte {
	t.Helper()
	addr := netip.MustParseAddr(value).As16()
	return addr[:]
}

func testRoutingMatcherMatch(t testing.TB, matcher *RoutingMatcher, dest string, domain string) consts.OutboundIndex {
	return testRoutingMatcherMatchPort(t, matcher, dest, domain, 443)
}

func testRoutingMatcherMatchPort(t testing.TB, matcher *RoutingMatcher, dest string, domain string, destPort uint16) consts.OutboundIndex {
	t.Helper()
	outbound, _, _, err := matcher.Match(
		testRoutingMatcherAddr(t, "10.0.0.2"),
		testRoutingMatcherAddr(t, dest),
		12345,
		destPort,
		consts.IpVersion_4,
		consts.L4ProtoType_TCP,
		domain,
		[16]uint8{},
		0,
		testRoutingMatcherAddr(t, "::aabb:ccdd:eeff"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return outbound
}

func newTestFallbackRoutingMatcher(t testing.TB) *RoutingMatcher {
	t.Helper()
	domainMatcher := domain_matcher.NewAhocorasickSlimtrie(logrus.New(), consts.MaxMatchSetLen)
	if err := domainMatcher.Build(); err != nil {
		t.Fatal(err)
	}
	return &RoutingMatcher{
		domainMatcher: domainMatcher,
		matches: []bpfMatchSet{
			{
				Type:     uint8(consts.MatchType_Fallback),
				Outbound: uint8(consts.OutboundDirect),
			},
		},
	}
}

func newTestDomainRoutingMatcher(t testing.TB) *RoutingMatcher {
	t.Helper()
	domainMatcher := domain_matcher.NewAhocorasickSlimtrie(logrus.New(), consts.MaxMatchSetLen)
	domainMatcher.AddSet(0, []string{"example.com"}, consts.RoutingDomainKey_Suffix)
	if err := domainMatcher.Build(); err != nil {
		t.Fatal(err)
	}
	return &RoutingMatcher{
		domainMatcher: domainMatcher,
		matches: []bpfMatchSet{
			{
				Type:     uint8(consts.MatchType_DomainSet),
				Outbound: uint8(consts.OutboundDirect),
			},
			{
				Type:     uint8(consts.MatchType_Fallback),
				Outbound: uint8(consts.OutboundBlock),
			},
		},
	}
}

func newTestIpPortRoutingMatcher(t testing.TB) *RoutingMatcher {
	t.Helper()
	domainMatcher := domain_matcher.NewAhocorasickSlimtrie(logrus.New(), consts.MaxMatchSetLen)
	if err := domainMatcher.Build(); err != nil {
		t.Fatal(err)
	}
	ipTrie, err := trie.NewTrieFromPrefixes([]netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/24"),
	})
	if err != nil {
		t.Fatal(err)
	}
	value := [16]byte{}
	binary.LittleEndian.PutUint32(value[:], 0)
	return &RoutingMatcher{
		lpmMatcher:    []*trie.Trie{ipTrie},
		domainMatcher: domainMatcher,
		matches: []bpfMatchSet{
			{
				Type:     uint8(consts.MatchType_IpSet),
				Value:    value,
				Outbound: uint8(consts.OutboundLogicalOr),
			},
			{
				Type:     uint8(consts.MatchType_Port),
				Value:    _bpfPortRange{PortStart: 443, PortEnd: 443}.Encode(),
				Outbound: uint8(consts.OutboundDirect),
			},
			{
				Type:     uint8(consts.MatchType_Fallback),
				Outbound: uint8(consts.OutboundBlock),
			},
		},
	}
}

func TestRoutingMatcherUserspaceFallback(t *testing.T) {
	if got := testRoutingMatcherMatch(t, newTestFallbackRoutingMatcher(t), "203.0.113.42", ""); got != consts.OutboundDirect {
		t.Fatalf("expected direct fallback, got %v", got)
	}
}

func TestRoutingMatcherUserspaceDomain(t *testing.T) {
	matcher := newTestDomainRoutingMatcher(t)
	if got := testRoutingMatcherMatch(t, matcher, "203.0.113.42", "www.example.com"); got != consts.OutboundDirect {
		t.Fatalf("expected direct domain match, got %v", got)
	}
	if got := testRoutingMatcherMatch(t, matcher, "203.0.113.42", "www.invalid.test"); got != consts.OutboundBlock {
		t.Fatalf("expected block fallback, got %v", got)
	}
}

func TestRoutingMatcherUserspaceIpPort(t *testing.T) {
	matcher := newTestIpPortRoutingMatcher(t)
	if got := testRoutingMatcherMatch(t, matcher, "203.0.113.42", ""); got != consts.OutboundDirect {
		t.Fatalf("expected direct ip+port match, got %v", got)
	}
	if got := testRoutingMatcherMatchPort(t, matcher, "198.51.100.42", "", 8443); got != consts.OutboundBlock {
		t.Fatalf("expected block fallback, got %v", got)
	}
}

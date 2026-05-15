package routing

import (
	"net/netip"
	"testing"
)

func TestParsePrefixesUsesHostPrefixForBareAddresses(t *testing.T) {
	prefixes, err := parsePrefixes([]string{
		"192.0.2.1",
		"2001:db8::1",
		"2001:db8::/48",
	})
	if err != nil {
		t.Fatalf("parsePrefixes() returned error: %v", err)
	}
	if len(prefixes) != 3 {
		t.Fatalf("parsePrefixes() returned %d prefixes, want 3", len(prefixes))
	}

	want := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.1/32"),
		netip.MustParsePrefix("2001:db8::1/128"),
		netip.MustParsePrefix("2001:db8::/48"),
	}
	for i := range want {
		if prefixes[i] != want[i] {
			t.Fatalf("prefixes[%d] = %v, want %v", i, prefixes[i], want[i])
		}
	}
}

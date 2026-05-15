package control

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

type groupOverrideCloneCacheTestDialer struct{}

func (d *groupOverrideCloneCacheTestDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return nil, nil
}

func newGroupOverrideCloneCacheTestDialer(t *testing.T, name string) *dialer.Dialer {
	t.Helper()
	option := newGroupOverrideCloneCacheTestOption([]string{"https://global.example/generate_204"}, []string{"8.8.8.8:53"}, 30*time.Second, 0)
	return dialer.NewDialer(&groupOverrideCloneCacheTestDialer{}, option, dialer.InstanceOption{}, &dialer.Property{
		Property: D.Property{
			Name: name,
			Link: "test://" + name,
		},
		Link: "test://" + name,
	})
}

func newGroupOverrideCloneCacheTestOption(tcpCheckURL, udpCheckDNS []string, interval, tolerance time.Duration) *dialer.GlobalOption {
	return &dialer.GlobalOption{
		Log: logrus.New(),
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{
			Raw:             tcpCheckURL,
			ResolverNetwork: "udp",
			Method:          "HEAD",
			ResolverDNS:     netip.MustParseAddrPort("1.1.1.1:53"),
		},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{
			Raw:             udpCheckDNS,
			ResolverNetwork: "udp",
			Somark:          123,
			ResolverDNS:     netip.MustParseAddrPort("1.1.1.1:53"),
		},
		CheckInterval:  interval,
		CheckTolerance: tolerance,
		CheckDnsTcp:    true,
	}
}

func TestGroupOverrideCloneCacheReusesIdenticalProfileForSameBaseDialer(t *testing.T) {
	base := newGroupOverrideCloneCacheTestDialer(t, "node-a")
	defer base.Close()

	var created []*dialer.Dialer
	cache := newGroupOverrideCloneCache(func(d *dialer.Dialer) {
		created = append(created, d)
	})
	optionA := newGroupOverrideCloneCacheTestOption([]string{"https://check.example/generate_204"}, []string{"8.8.8.8:53"}, 15*time.Second, 10*time.Millisecond)
	optionB := newGroupOverrideCloneCacheTestOption([]string{"https://check.example/generate_204"}, []string{"8.8.8.8:53"}, 15*time.Second, 10*time.Millisecond)

	cloneA := cache.clone(base, optionA)
	cloneB := cache.clone(base, optionB)
	defer cloneA.Close()

	if cloneA == base {
		t.Fatal("override clone should not reuse the base dialer wrapper")
	}
	if cloneA != cloneB {
		t.Fatal("identical health profile should reuse the same override clone")
	}
	if got := len(created); got != 1 {
		t.Fatalf("expected one created clone, got %d", got)
	}
	if cloneA.GlobalOption != optionA {
		t.Fatal("cached clone should keep the first equivalent profile option")
	}
}

func TestGroupOverrideCloneCacheSeparatesDifferentProfilesAndBaseDialers(t *testing.T) {
	baseA := newGroupOverrideCloneCacheTestDialer(t, "node-a")
	baseB := newGroupOverrideCloneCacheTestDialer(t, "node-b")
	defer baseA.Close()
	defer baseB.Close()

	cache := newGroupOverrideCloneCache(nil)
	optionA := newGroupOverrideCloneCacheTestOption([]string{"https://check.example/generate_204"}, []string{"8.8.8.8:53"}, 15*time.Second, 10*time.Millisecond)
	optionDifferentInterval := newGroupOverrideCloneCacheTestOption([]string{"https://check.example/generate_204"}, []string{"8.8.8.8:53"}, 30*time.Second, 10*time.Millisecond)
	optionDifferentDNS := newGroupOverrideCloneCacheTestOption([]string{"https://check.example/generate_204"}, []string{"1.1.1.1:53"}, 15*time.Second, 10*time.Millisecond)
	optionDifferentResolver := newGroupOverrideCloneCacheTestOption([]string{"https://check.example/generate_204"}, []string{"8.8.8.8:53"}, 15*time.Second, 10*time.Millisecond)
	optionDifferentResolver.TcpCheckOptionRaw.ResolverDialer = &groupOverrideCloneCacheTestDialer{}

	cloneA := cache.clone(baseA, optionA)
	cloneDifferentInterval := cache.clone(baseA, optionDifferentInterval)
	cloneDifferentDNS := cache.clone(baseA, optionDifferentDNS)
	cloneDifferentResolver := cache.clone(baseA, optionDifferentResolver)
	cloneDifferentBase := cache.clone(baseB, optionA)
	defer cloneA.Close()
	defer cloneDifferentInterval.Close()
	defer cloneDifferentDNS.Close()
	defer cloneDifferentResolver.Close()
	defer cloneDifferentBase.Close()

	if cloneA == cloneDifferentInterval {
		t.Fatal("different check interval must not share an override clone")
	}
	if cloneA == cloneDifferentDNS {
		t.Fatal("different udp check DNS must not share an override clone")
	}
	if cloneA == cloneDifferentResolver {
		t.Fatal("different resolver dialer must not share an override clone")
	}
	if cloneA == cloneDifferentBase {
		t.Fatal("different base dialers must not share an override clone")
	}
}

func TestStringSliceProfileKeyPreservesNilEmptyAndBoundaries(t *testing.T) {
	tests := []struct {
		name string
		a    []string
		b    []string
	}{
		{
			name: "nil and empty",
			a:    nil,
			b:    []string{},
		},
		{
			name: "value boundary",
			a:    []string{"ab", "c"},
			b:    []string{"a", "bc"},
		},
		{
			name: "empty element boundary",
			a:    []string{"", "a"},
			b:    []string{"a", ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if stringSliceProfileKey(tt.a) == stringSliceProfileKey(tt.b) {
				t.Fatalf("profile keys should differ for %#v and %#v", tt.a, tt.b)
			}
		})
	}
}

func TestCountGroupOverrideHealthProfiles(t *testing.T) {
	log := logrus.New()
	global := config.Global{
		TcpCheckUrl:        []string{"https://global.example/generate_204"},
		TcpCheckHttpMethod: "HEAD",
		UdpCheckDns:        []string{"8.8.8.8:53"},
		CheckInterval:      30 * time.Second,
	}
	baseOption := dialer.NewGlobalOption(&global, log)
	baseOption.ResolverDialer = &groupOverrideCloneCacheTestDialer{}
	baseOption.ResolverFullconeDialer = &groupOverrideCloneCacheTestDialer{}
	baseOption.ResolverDNS = netip.MustParseAddrPort("1.1.1.1:53")

	groups := []config.Group{
		{Name: "no-override"},
		{Name: "shared-a", TcpCheckUrl: []string{"https://shared.example/generate_204"}, CheckInterval: 15 * time.Second},
		{Name: "shared-b", TcpCheckUrl: []string{"https://shared.example/generate_204"}, CheckInterval: 15 * time.Second},
		{Name: "unique", TcpCheckUrl: []string{"https://unique.example/generate_204"}, CheckInterval: 15 * time.Second},
	}

	counts := countGroupOverrideHealthProfiles(groups, global, baseOption, log)
	if got := len(counts); got != 2 {
		t.Fatalf("expected two override health profiles, got %d", got)
	}

	sharedOption, err := ParseGroupOverrideOption(groups[1], global, log)
	if err != nil {
		t.Fatal(err)
	}
	inheritGroupOverrideResolverOption(sharedOption, baseOption)
	if got := counts[groupOverrideHealthProfile(sharedOption)]; got != 2 {
		t.Fatalf("expected shared profile count 2, got %d", got)
	}

	uniqueOption, err := ParseGroupOverrideOption(groups[3], global, log)
	if err != nil {
		t.Fatal(err)
	}
	inheritGroupOverrideResolverOption(uniqueOption, baseOption)
	if got := counts[groupOverrideHealthProfile(uniqueOption)]; got != 1 {
		t.Fatalf("expected unique profile count 1, got %d", got)
	}
}

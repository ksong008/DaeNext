package control

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	componentdns "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func TestRuntimeDepsWithDefaultsCreatesFreshInstances(t *testing.T) {
	deps := (RuntimeDeps{}).withDefaults(logrus.New())
	defer deps.UdpEndpointPool.Close()
	defer deps.UdpTaskPool.Close()
	defer deps.AnyfromPool.Close()

	if deps.Netns == nil {
		t.Fatal("expected netns to be created")
	}
	if deps.UdpEndpointPool == nil {
		t.Fatal("expected udp endpoint pool to be created")
	}
	if deps.UdpTaskPool == nil {
		t.Fatal("expected udp task pool to be created")
	}
	if deps.AnyfromPool == nil {
		t.Fatal("expected anyfrom pool to be created")
	}
	if deps.UdpEndpointPool == DefaultUdpEndpointPool {
		t.Fatal("expected fresh udp endpoint pool instead of package global default")
	}
	if deps.UdpTaskPool == DefaultUdpTaskPool {
		t.Fatal("expected fresh udp task pool instead of package global default")
	}
	if deps.AnyfromPool == DefaultAnyfromPool {
		t.Fatal("expected fresh anyfrom pool instead of package global default")
	}
	if deps.AnyfromPool.netns != deps.Netns {
		t.Fatal("expected anyfrom pool to inherit the created netns")
	}
	if global := GetDaeNetns(); global != nil && deps.Netns == global {
		t.Fatal("expected fresh netns instead of package global default")
	}
}

func TestChooseDialTargetUsesDomainForUnspecifiedDest(t *testing.T) {
	c := &ControlPlane{
		log:      logrus.New(),
		dialMode: consts.DialMode_Ip,
	}
	target, _, dialIP := c.ChooseDialTarget(
		context.Background(),
		netip.MustParseAddrPort("0.0.0.0:0"),
		&bpfRoutingResult{},
		consts.OutboundDirect,
		netip.MustParseAddrPort("0.0.0.0:443"),
		"example.com",
	)
	if target != "example.com:443" {
		t.Fatalf("target = %q, want example.com:443", target)
	}
	if dialIP {
		t.Fatal("dialIP = true, want false for domain-only target")
	}
}

func TestChooseDialTargetDomainModeDoesNotRerouteAfterActiveResolve(t *testing.T) {
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

	controller.forwarderFactory = func(_ *componentdns.Upstream, _ dialArgument) (DnsForwarder, error) {
		return &fakeDnsForwarder{forward: func(_ context.Context, data []byte) (*dnsmessage.Msg, error) {
			req := new(dnsmessage.Msg)
			if err := req.Unpack(data); err != nil {
				return nil, err
			}
			resp := new(dnsmessage.Msg)
			resp.SetReply(req)
			if req.Question[0].Qtype == dnsmessage.TypeA {
				resp.Answer = []dnsmessage.RR{newTestARecord(req.Question[0].Name, "1.1.1.1")}
			}
			return resp, nil
		}}, nil
	}

	c := &ControlPlane{
		log:               log,
		dialMode:          consts.DialMode_Domain,
		dnsController:     controller,
		muRealDomainCache: sync.Mutex{},
		realDomainCache:   make(map[string]realDomainCacheEntry),
	}
	target, shouldReroute, dialIP := c.ChooseDialTarget(
		context.Background(),
		netip.MustParseAddrPort("192.0.2.10:43210"),
		&bpfRoutingResult{},
		consts.OutboundUserDefinedMin,
		netip.MustParseAddrPort("93.184.216.34:443"),
		"example.com",
	)
	if target != "example.com:443" {
		t.Fatalf("target = %q, want example.com:443", target)
	}
	if shouldReroute {
		t.Fatal("shouldReroute = true, want false for dial_mode domain")
	}
	if dialIP {
		t.Fatal("dialIP = true, want false after domain rewrite")
	}
}

func TestRuntimeDepsWithDefaultsPreservesProvidedInstances(t *testing.T) {
	netns := NewDaeNetns(logrus.New())
	udpPool := NewUdpEndpointPool()
	udpTaskPool := NewUdpTaskPool()
	anyfromPool := NewAnyfromPoolWithNetns(netns)
	defer udpPool.Close()
	defer udpTaskPool.Close()
	defer anyfromPool.Close()

	deps := (RuntimeDeps{
		Netns:           netns,
		UdpEndpointPool: udpPool,
		UdpTaskPool:     udpTaskPool,
		AnyfromPool:     anyfromPool,
	}).withDefaults(logrus.New())

	if deps.Netns != netns {
		t.Fatal("expected provided netns to be preserved")
	}
	if deps.UdpEndpointPool != udpPool {
		t.Fatal("expected provided udp endpoint pool to be preserved")
	}
	if deps.UdpTaskPool != udpTaskPool {
		t.Fatal("expected provided udp task pool to be preserved")
	}
	if deps.AnyfromPool != anyfromPool {
		t.Fatal("expected provided anyfrom pool to be preserved")
	}
}

func TestControlPlaneCloseReturnsCleanupErrors(t *testing.T) {
	expected := errors.New("cleanup failed")
	plane := &ControlPlane{
		cancel: func() {},
		deferFuncs: []func() error{
			func() error { return expected },
		},
	}

	if err := plane.Close(); !errors.Is(err, expected) {
		t.Fatalf("Close() error = %v, want cleanup error", err)
	}
}

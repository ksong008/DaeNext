package control

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
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

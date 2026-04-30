package control

import (
	"testing"

	"github.com/sirupsen/logrus"
)

func TestRuntimeDepsWithDefaultsCreatesFreshInstances(t *testing.T) {
	deps := (RuntimeDeps{}).withDefaults(logrus.New())
	defer deps.UdpEndpointPool.Close()
	defer deps.AnyfromPool.Close()

	if deps.Netns == nil {
		t.Fatal("expected netns to be created")
	}
	if deps.UdpEndpointPool == nil {
		t.Fatal("expected udp endpoint pool to be created")
	}
	if deps.AnyfromPool == nil {
		t.Fatal("expected anyfrom pool to be created")
	}
	if deps.UdpEndpointPool == DefaultUdpEndpointPool {
		t.Fatal("expected fresh udp endpoint pool instead of package global default")
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

func TestRuntimeDepsWithDefaultsPreservesProvidedInstances(t *testing.T) {
	netns := NewDaeNetns(logrus.New())
	udpPool := NewUdpEndpointPool()
	anyfromPool := NewAnyfromPoolWithNetns(netns)
	defer udpPool.Close()
	defer anyfromPool.Close()

	deps := (RuntimeDeps{
		Netns:           netns,
		UdpEndpointPool: udpPool,
		AnyfromPool:     anyfromPool,
	}).withDefaults(logrus.New())

	if deps.Netns != netns {
		t.Fatal("expected provided netns to be preserved")
	}
	if deps.UdpEndpointPool != udpPool {
		t.Fatal("expected provided udp endpoint pool to be preserved")
	}
	if deps.AnyfromPool != anyfromPool {
		t.Fatal("expected provided anyfrom pool to be preserved")
	}
}

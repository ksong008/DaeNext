/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

const (
	stage22MagicMark  = 1234
	stage22MagicMptcp = true
)

type stage22MagicCaptureDialer struct {
	mu       sync.Mutex
	networks []string
	addrs    []string
}

func (d *stage22MagicCaptureDialer) DialContext(_ context.Context, network, addr string) (netproxy.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.networks = append(d.networks, network)
	d.addrs = append(d.addrs, addr)
	return &stage22MagicPacketConn{}, nil
}

func (d *stage22MagicCaptureDialer) lastNetwork(t testing.TB) string {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.networks) == 0 {
		t.Fatal("fake dialer was not called")
	}
	return d.networks[len(d.networks)-1]
}

type stage22MagicPacketConn struct{}

func (c *stage22MagicPacketConn) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (c *stage22MagicPacketConn) Write(p []byte) (int, error) {
	return len(p), nil
}

func (c *stage22MagicPacketConn) ReadFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}

func (c *stage22MagicPacketConn) WriteTo(p []byte, _ string) (int, error) {
	return len(p), nil
}

func (c *stage22MagicPacketConn) Close() error {
	return nil
}

func (c *stage22MagicPacketConn) SetDeadline(time.Time) error {
	return nil
}

func (c *stage22MagicPacketConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *stage22MagicPacketConn) SetWriteDeadline(time.Time) error {
	return nil
}

func newStage22MagicControlPlane(t testing.TB, capture *stage22MagicCaptureDialer) (*ControlPlane, func()) {
	t.Helper()

	log := logrus.New()
	log.SetOutput(io.Discard)
	option := &dialer.GlobalOption{
		Log:         log,
		CheckDnsTcp: false,
	}
	wrappedDialer := dialer.NewDialer(capture, option, dialer.InstanceOption{DisableCheck: true}, &dialer.Property{
		Property: D.Property{
			Name: "stage22_magic_capture",
			Link: "capture://stage22",
		},
		Link: "capture://stage22",
	})
	group := outbound.NewDialerGroup(
		option,
		"stage22_magic_group",
		[]*dialer.Dialer{wrappedDialer},
		[]*dialer.Annotation{{}},
		outbound.DialerSelectionPolicy{
			Policy:     consts.DialerSelectionPolicy_Fixed,
			FixedIndex: 0,
		},
		func(bool, *dialer.NetworkType, bool) {},
	)
	udpEndpointPool := NewUdpEndpointPoolWithMaxEntries(16)
	ctl := &ControlPlane{
		log:             log,
		outbounds:       []*outbound.DialerGroup{group},
		dialMode:        consts.DialMode_Ip,
		soMarkFromDae:   stage22MagicMark,
		mptcp:           stage22MagicMptcp,
		udpEndpointPool: udpEndpointPool,
	}
	cleanup := func() {
		_ = udpEndpointPool.Close()
		_ = group.Close()
		_ = wrappedDialer.Close()
	}
	return ctl, cleanup
}

func assertMagicNetwork(t testing.TB, encoded, wantNetwork string) {
	t.Helper()
	parsed, err := netproxy.ParseMagicNetwork(encoded)
	if err != nil {
		t.Fatalf("ParseMagicNetwork() error = %v", err)
	}
	if parsed.Network != wantNetwork || parsed.Mark != stage22MagicMark || parsed.Mptcp != stage22MagicMptcp {
		t.Fatalf("MagicNetwork = {Network:%q Mark:%d Mptcp:%v}, want {%q %d %v}",
			parsed.Network, parsed.Mark, parsed.Mptcp, wantNetwork, stage22MagicMark, stage22MagicMptcp)
	}
}

func TestActiveRouteDialTcpUsesMagicNetworkMarkMptcp(t *testing.T) {
	capture := &stage22MagicCaptureDialer{}
	ctl, cleanup := newStage22MagicControlPlane(t, capture)
	defer cleanup()

	conn, err := ctl.RouteDialTcp(&RouteDialParam{
		Ctx:      context.Background(),
		Outbound: consts.OutboundDirect,
		Src:      netip.MustParseAddrPort("10.220.0.2:38190"),
		Dest:     netip.MustParseAddrPort("198.18.0.1:18080"),
	})
	if err != nil {
		t.Fatalf("RouteDialTcp() error = %v", err)
	}
	_ = conn.Close()

	assertMagicNetwork(t, capture.lastNetwork(t), "tcp")
}

func TestActiveUdpEndpointUsesMagicNetworkMarkMptcp(t *testing.T) {
	capture := &stage22MagicCaptureDialer{}
	ctl, cleanup := newStage22MagicControlPlane(t, capture)
	defer cleanup()

	err := ctl.handlePkt(
		context.Background(),
		nil,
		[]byte("stage22-udp-proxy"),
		netip.MustParseAddrPort("10.220.0.2:47890"),
		netip.MustParseAddrPort("198.18.0.1:18081"),
		netip.MustParseAddrPort("198.18.0.1:18081"),
		&bpfRoutingResult{Outbound: uint8(consts.OutboundDirect)},
		true,
	)
	if err != nil {
		t.Fatalf("handlePkt() error = %v", err)
	}

	assertMagicNetwork(t, capture.lastNetwork(t), "udp")
}

func TestDnsUdpForwarderUsesMagicNetworkMarkMptcp(t *testing.T) {
	capture := &stage22MagicCaptureDialer{}
	ctl, cleanup := newStage22MagicControlPlane(t, capture)
	defer cleanup()

	forwarder := &DoUDP{
		dialArgument: dialArgument{
			bestDialer: ctl.outbounds[consts.OutboundDirect].Dialers[0],
			bestTarget: netip.MustParseAddrPort("127.0.0.1:10530"),
			mark:       ctl.soMarkFromDae,
			mptcp:      ctl.mptcp,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	_, _ = forwarder.ForwardDNS(ctx, []byte("stage22-dns-proxy"))

	assertMagicNetwork(t, capture.lastNetwork(t), "udp")
}

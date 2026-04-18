/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/logger"
	"github.com/sirupsen/logrus"
)

const (
	testTcpCheckUrl = "https://connectivitycheck.gstatic.com/generate_204"
	testUdpCheckDns = "https://connectivitycheck.gstatic.com/generate_204"
)

var TestNetworkType = &dialer.NetworkType{
	L4Proto:   consts.L4ProtoStr_TCP,
	IpVersion: consts.IpVersionStr_4,
	IsDns:     false,
}

var log = logrus.New()

func init() {
	logger.SetLogger(log, "trace", false, nil)
}

func newDirectDialer(option *dialer.GlobalOption, fullcone bool) *dialer.Dialer {
	_d, p := dialer.NewDirectDialer(option, true)
	d := dialer.NewDialer(_d, option, dialer.InstanceOption{DisableCheck: false}, p)
	return d
}

func annotationsFor(dialers []*dialer.Dialer) []*dialer.Annotation {
	annotations := make([]*dialer.Annotation, len(dialers))
	for i := range annotations {
		annotations[i] = &dialer.Annotation{}
	}
	return annotations
}

func TestDialerGroup_Select_Fixed(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
		CheckDnsTcp:       false,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option, true),
		newDirectDialer(option, false),
	}
	fixedIndex := 1
	g := NewDialerGroup(option, "test-group", dialers, annotationsFor(dialers),
		DialerSelectionPolicy{
			Policy:     consts.DialerSelectionPolicy_Fixed,
			FixedIndex: fixedIndex,
		}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})
	for i := 0; i < 10; i++ {
		d, _, err := g.Select(TestNetworkType, false)
		if err != nil {
			t.Fatal(err)
		}
		if d != dialers[fixedIndex] {
			t.Fail()
		}
	}

	fixedIndex = 0
	g.selectionPolicy.FixedIndex = fixedIndex
	for i := 0; i < 10; i++ {
		d, _, err := g.Select(TestNetworkType, false)
		if err != nil {
			t.Fatal(err)
		}
		if d != dialers[fixedIndex] {
			t.Fail()
		}
	}
}

func TestDialerGroup_Select_MinLastLatency(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}

	tests := []struct {
		name      string
		latencies []time.Duration
		alive     []bool
		wantIndex int
	}{
		{
			name:      "selects fastest alive dialer",
			latencies: []time.Duration{200 * time.Millisecond, 100 * time.Millisecond, 300 * time.Millisecond, 150 * time.Millisecond},
			alive:     []bool{true, true, true, true},
			wantIndex: 1,
		},
		{
			name:      "ignores faster dead dialer",
			latencies: []time.Duration{50 * time.Millisecond, 300 * time.Millisecond, 120 * time.Millisecond, 250 * time.Millisecond},
			alive:     []bool{false, true, true, true},
			wantIndex: 2,
		},
		{
			name:      "handles alive state transitions",
			latencies: []time.Duration{400 * time.Millisecond, 220 * time.Millisecond, 180 * time.Millisecond, 190 * time.Millisecond},
			alive:     []bool{true, false, true, true},
			wantIndex: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dialers := make([]*dialer.Dialer, len(tt.latencies))
			for i := range dialers {
				dialers[i] = newDirectDialer(option, false)
			}
			g := NewDialerGroup(option, "test-group", dialers, annotationsFor(dialers),
				DialerSelectionPolicy{
					Policy: consts.DialerSelectionPolicy_MinLastLatency,
				}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})

			for i, d := range dialers {
				d.MustGetLatencies10(TestNetworkType).AppendLatency(tt.latencies[i])
				g.MustGetAliveDialerSet(TestNetworkType).NotifyLatencyChange(d, tt.alive[i])
			}

			d, _, err := g.Select(TestNetworkType, false)
			if err != nil {
				t.Fatal(err)
			}
			if d != dialers[tt.wantIndex] {
				gotIndex := -1
				for i := range dialers {
					if d == dialers[i] {
						gotIndex = i
						break
					}
				}
				t.Fatalf("expected dialers[%d], got dialers[%d]", tt.wantIndex, gotIndex)
			}
		})
	}
}

func TestDialerGroup_Select_Random(t *testing.T) {

	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option, false),
		newDirectDialer(option, false),
		newDirectDialer(option, false),
		newDirectDialer(option, false),
		newDirectDialer(option, false),
	}
	g := NewDialerGroup(option, "test-group", dialers, annotationsFor(dialers),
		DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_Random,
		}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})
	count := make([]int, len(dialers))
	for i := 0; i < 100; i++ {
		d, _, err := g.Select(TestNetworkType, false)
		if err != nil {
			t.Fatal(err)
		}
		for j, dd := range dialers {
			if d == dd {
				count[j]++
				break
			}
		}
	}
	total := 0
	for i, c := range count {
		total += c
		t.Logf("count[%v]: %v", i, c)
	}
	if total != 100 {
		t.Fatalf("unexpected total selections: %d", total)
	}
}

func TestDialerGroup_SetAlive(t *testing.T) {

	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option, false),
		newDirectDialer(option, false),
		newDirectDialer(option, false),
		newDirectDialer(option, false),
		newDirectDialer(option, false),
	}
	g := NewDialerGroup(option, "test-group", dialers, annotationsFor(dialers),
		DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_Random,
		}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})
	zeroTarget := 3
	g.MustGetAliveDialerSet(TestNetworkType).NotifyLatencyChange(dialers[zeroTarget], false)
	count := make([]int, len(dialers))
	for i := 0; i < 100; i++ {
		d, _, err := g.Select(TestNetworkType, false)
		if err != nil {
			t.Fatal(err)
		}
		for j, dd := range dialers {
			if d == dd {
				count[j]++
				break
			}
		}
	}
	total := 0
	for i, c := range count {
		total += c
		t.Logf("count[%v]: %v", i, c)
	}
	if count[zeroTarget] != 0 {
		t.Fatalf("dead dialer[%d] was selected %d times", zeroTarget, count[zeroTarget])
	}
	if total != 100 {
		t.Fatalf("unexpected total selections: %d", total)
	}
}

func TestDialerGroup_Select_ReSelectsWhenCurrentBestWorsens(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option, false),
		newDirectDialer(option, false),
	}
	g := NewDialerGroup(option, "test-group", dialers, annotationsFor(dialers),
		DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_MinLastLatency,
		}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})

	g.MustGetAliveDialerSet(TestNetworkType).NotifyLatencyChange(dialers[0], true)
	g.MustGetAliveDialerSet(TestNetworkType).NotifyLatencyChange(dialers[1], true)

	dialers[0].MustGetLatencies10(TestNetworkType).AppendLatency(100 * time.Millisecond)
	g.MustGetAliveDialerSet(TestNetworkType).NotifyLatencyChange(dialers[0], true)
	dialers[1].MustGetLatencies10(TestNetworkType).AppendLatency(200 * time.Millisecond)
	g.MustGetAliveDialerSet(TestNetworkType).NotifyLatencyChange(dialers[1], true)

	d, _, err := g.Select(TestNetworkType, false)
	if err != nil {
		t.Fatal(err)
	}
	if d != dialers[0] {
		t.Fatalf("expected first dialer before slowdown, got %q", d.Property().Name)
	}

	dialers[0].MustGetLatencies10(TestNetworkType).AppendLatency(500 * time.Millisecond)
	g.MustGetAliveDialerSet(TestNetworkType).NotifyLatencyChange(dialers[0], true)

	d, _, err = g.Select(TestNetworkType, false)
	if err != nil {
		t.Fatal(err)
	}
	if d != dialers[1] {
		t.Fatalf("expected second dialer after slowdown, got %q", d.Property().Name)
	}
}

func TestDialerGroup_Select_DoesNotMutateNetworkTypeOnFallback(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option, false),
	}
	g := NewDialerGroup(option, "test-group", dialers, annotationsFor(dialers),
		DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_Random,
		}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})

	ipv4 := &dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStr_4,
		IsDns:     false,
	}
	ipv6 := &dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStr_6,
		IsDns:     false,
	}

	g.MustGetAliveDialerSet(ipv4).NotifyLatencyChange(dialers[0], false)
	g.MustGetAliveDialerSet(ipv6).NotifyLatencyChange(dialers[0], true)

	networkType := &dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStr_4,
		IsDns:     false,
	}
	if _, _, err := g.Select(networkType, false); err != nil {
		t.Fatal(err)
	}
	if networkType.IpVersion != consts.IpVersionStr_4 {
		t.Fatalf("expected Select to preserve input ip version, got %v", networkType.IpVersion)
	}
}

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package engine

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

func TestReloadWithContextReturnsWhenRuntimeNotServing(t *testing.T) {
	e := New(Options{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	err := e.ReloadWithContext(ctx, EmptyConfig())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ReloadWithContext() error = %v, want context deadline exceeded", err)
	}
}

func TestReloadWithContextDryRuntime(t *testing.T) {
	e := New(Options{})
	log := logrus.New()
	done := make(chan error, 1)
	go func() {
		done <- e.Run(log, EmptyConfig(), nil, true, true)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := e.ReloadWithContext(ctx, EmptyConfig()); err != nil {
		t.Fatalf("ReloadWithContext() on dry runtime: %v", err)
	}
	if err := e.Stop(time.Second); err != nil {
		t.Fatalf("Stop() dry runtime: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for dry runtime stop")
	}
}

func TestNewControlPlaneRejectsInvalidFallbackResolver(t *testing.T) {
	conf := EmptyConfig()
	conf.Global.FallbackResolver = "bad-resolver"
	e := New(Options{})

	_, err := e.newControlPlane(logrus.New(), nil, nil, conf, nil)
	if err == nil {
		t.Fatal("expected newControlPlane() to reject invalid fallback_resolver")
	}
	if !strings.Contains(err.Error(), "invalid global.fallback_resolver") {
		t.Fatalf("expected fallback_resolver error, got: %v", err)
	}
}

func TestMaybePostStartupGCCooldown(t *testing.T) {
	e := &Engine{}
	log := logrus.New()
	calls := 0
	heapReads := 0

	original := postStartupGC
	originalHeap := currentHeapAllocBytes
	postStartupGC = func() { calls++ }
	currentHeapAllocBytes = func() uint64 {
		heapReads++
		switch heapReads {
		case 1:
			return 256 << 20
		case 2:
			return 96 << 20
		case 3:
			return 120 << 20
		case 4:
			return 200 << 20
		case 5:
			return 110 << 20
		default:
			return 110 << 20
		}
	}
	t.Cleanup(func() {
		postStartupGC = original
		currentHeapAllocBytes = originalHeap
	})

	e.maybePostStartupGC(log, true)
	first := e.lastPostStartupGC
	if calls != 1 {
		t.Fatalf("postStartupGC calls = %d, want 1", calls)
	}
	if first.IsZero() {
		t.Fatal("expected first post-startup GC timestamp to be recorded")
	}
	if got := e.lastPostStartupHeapAlloc; got != 96<<20 {
		t.Fatalf("lastPostStartupHeapAlloc = %d, want %d", got, 96<<20)
	}

	skipAt := time.Now().Add(-postStartupGCMinInterval - time.Second)
	e.lastPostStartupGC = skipAt
	e.maybePostStartupGC(log, false)
	if calls != 1 {
		t.Fatalf("postStartupGC calls below threshold = %d, want 1", calls)
	}
	if !e.lastPostStartupGC.Equal(skipAt) {
		t.Fatal("expected GC timestamp to stay unchanged below threshold")
	}

	e.lastPostStartupGC = time.Now().Add(-postStartupGCMinInterval - time.Second)
	e.maybePostStartupGC(log, false)
	if calls != 2 {
		t.Fatalf("postStartupGC calls above threshold = %d, want 2", calls)
	}
}

func TestPrepareRuntimeConfigViewDoesNotMutateSource(t *testing.T) {
	conf := &config.Config{
		Global: config.Global{
			LanInterface:     []string{"lan0"},
			WanInterface:     []string{"wan0"},
			FallbackResolver: "8.8.8.8:53",
		},
		Routing: config.Routing{
			Rules: []*config_parser.RoutingRule{{}},
		},
		Dns: config.Dns{
			Routing: config.DnsRouting{
				Request:  config.DnsRequestRouting{Rules: []*config_parser.RoutingRule{{}}},
				Response: config.DnsResponseRouting{Rules: []*config_parser.RoutingRule{{}}},
			},
		},
	}

	globalConf, routingConf, dnsConf, err := prepareRuntimeConfigView(conf)
	if err != nil {
		t.Fatalf("prepareRuntimeConfigView() error = %v", err)
	}

	globalConf.LanInterface[0] = "mutated-lan"
	globalConf.WanInterface[0] = "mutated-wan"
	routingConf.Rules = nil
	dnsConf.Routing.Request.Rules = nil
	dnsConf.Routing.Response.Rules = nil

	if got := conf.Global.LanInterface[0]; got != "lan0" {
		t.Fatalf("source LanInterface = %q, want lan0", got)
	}
	if got := conf.Global.WanInterface[0]; got != "wan0" {
		t.Fatalf("source WanInterface = %q, want wan0", got)
	}
	if conf.Routing.Rules == nil {
		t.Fatal("source routing rules unexpectedly mutated")
	}
	if conf.Dns.Routing.Request.Rules == nil {
		t.Fatal("source dns request rules unexpectedly mutated")
	}
	if conf.Dns.Routing.Response.Rules == nil {
		t.Fatal("source dns response rules unexpectedly mutated")
	}
}

func TestRouteAwareDialTargetAvoidsSystemResolutionForDomain(t *testing.T) {
	domain, dest, err := routeAwareDialTarget("example.com", "443")
	if err != nil {
		t.Fatalf("routeAwareDialTarget() error = %v", err)
	}
	if domain != "example.com" {
		t.Fatalf("domain = %q, want example.com", domain)
	}
	if !dest.Addr().IsUnspecified() || dest.Port() != 443 {
		t.Fatalf("dest = %v, want unspecified:443", dest)
	}
}

func TestRouteAwareDialTargetKeepsIPLiteral(t *testing.T) {
	domain, dest, err := routeAwareDialTarget("203.0.113.1", "8443")
	if err != nil {
		t.Fatalf("routeAwareDialTarget() error = %v", err)
	}
	if domain != "" {
		t.Fatalf("domain = %q, want empty", domain)
	}
	if dest.String() != "203.0.113.1:8443" {
		t.Fatalf("dest = %v, want 203.0.113.1:8443", dest)
	}
}

func TestGetRuntimeOverviewIncludesDnsObservabilityStats(t *testing.T) {
	originalSnapshotRuntimeStats := snapshotRuntimeStats
	snapshotRuntimeStats = func(activeConnections int, udpSessions int, windowSec int, maxPoints int) control.RuntimeStatsSnapshot {
		if activeConnections != 0 {
			t.Fatalf("expected zero active connections without control plane, got %d", activeConnections)
		}
		if udpSessions != 0 {
			t.Fatalf("expected zero udp sessions without pool, got %d", udpSessions)
		}
		if windowSec != 45 {
			t.Fatalf("expected windowSec 45, got %d", windowSec)
		}
		if maxPoints != 90 {
			t.Fatalf("expected maxPoints 90, got %d", maxPoints)
		}
		return control.RuntimeStatsSnapshot{
			UpdatedAt:         time.Unix(1_700_000_300, 0),
			UploadRate:        10,
			DownloadRate:      20,
			UploadTotal:       30,
			DownloadTotal:     40,
			ActiveConnections: 0,
			UDPSessions:       0,
			RSSBytes:          50,
			HeapAllocBytes:    60,
			Goroutines:        70,
			DnsObservabilityStats: control.DnsObservabilityStats{
				DnsCacheHitTotal:                  101,
				DnsCacheExpiredRemovalTotal:       102,
				DnsUdpRetryTotal:                  103,
				DnsTruncatedTcpFallbackTotal:      104,
				DnsDoHStatusFailureTotal:          105,
				DnsDoHContentTypeFailureTotal:     106,
				DnsUpstreamRefreshSuccessTotal:    107,
				DnsUpstreamRefreshFailureTotal:    108,
				DnsUpstreamRefreshStaleReuseTotal: 109,
			},
			Samples: []control.RuntimeTrafficSample{
				{
					Timestamp:    time.Unix(1_700_000_300, 0),
					UploadRate:   11,
					DownloadRate: 22,
				},
			},
		}
	}
	defer func() {
		snapshotRuntimeStats = originalSnapshotRuntimeStats
	}()

	overview, err := (&Engine{}).GetRuntimeOverview(45, 90)
	if err != nil {
		t.Fatalf("GetRuntimeOverview() returned error: %v", err)
	}

	if overview.DnsCacheHitTotal != 101 {
		t.Fatalf("expected dns cache hit total 101, got %d", overview.DnsCacheHitTotal)
	}
	if overview.DnsCacheExpiredRemovalTotal != 102 {
		t.Fatalf("expected dns cache expired removal total 102, got %d", overview.DnsCacheExpiredRemovalTotal)
	}
	if overview.DnsUdpRetryTotal != 103 {
		t.Fatalf("expected dns udp retry total 103, got %d", overview.DnsUdpRetryTotal)
	}
	if overview.DnsTruncatedTcpFallbackTotal != 104 {
		t.Fatalf("expected dns truncated tcp fallback total 104, got %d", overview.DnsTruncatedTcpFallbackTotal)
	}
	if overview.DnsDoHStatusFailureTotal != 105 {
		t.Fatalf("expected dns doh status failure total 105, got %d", overview.DnsDoHStatusFailureTotal)
	}
	if overview.DnsDoHContentTypeFailureTotal != 106 {
		t.Fatalf("expected dns doh content-type failure total 106, got %d", overview.DnsDoHContentTypeFailureTotal)
	}
	if overview.DnsUpstreamRefreshSuccessTotal != 107 {
		t.Fatalf("expected dns upstream refresh success total 107, got %d", overview.DnsUpstreamRefreshSuccessTotal)
	}
	if overview.DnsUpstreamRefreshFailureTotal != 108 {
		t.Fatalf("expected dns upstream refresh failure total 108, got %d", overview.DnsUpstreamRefreshFailureTotal)
	}
	if overview.DnsUpstreamRefreshStaleReuseTotal != 109 {
		t.Fatalf("expected dns upstream refresh stale reuse total 109, got %d", overview.DnsUpstreamRefreshStaleReuseTotal)
	}
	if len(overview.Samples) != 1 {
		t.Fatalf("expected one runtime sample, got %d", len(overview.Samples))
	}
	if overview.Samples[0].UploadRate != 11 || overview.Samples[0].DownloadRate != 22 {
		t.Fatalf("unexpected runtime sample: %+v", overview.Samples[0])
	}
}

func TestGetRuntimeOverviewUsesScopedUdpTaskPoolTelemetry(t *testing.T) {
	originalSnapshotRuntimeStats := snapshotRuntimeStats
	snapshotRuntimeStats = func(activeConnections int, udpSessions int, windowSec int, maxPoints int) control.RuntimeStatsSnapshot {
		return control.RuntimeStatsSnapshot{
			UpdatedAt:             time.Unix(1_700_000_400, 0),
			UDPTaskQueues:         99,
			UDPTaskDropTotal:      88,
			PacketSnifferSessions: 77,
		}
	}
	defer func() {
		snapshotRuntimeStats = originalSnapshotRuntimeStats
	}()

	pool := control.NewUdpTaskPool()
	defer pool.Close()
	started := make(chan struct{})
	release := make(chan struct{})
	if !pool.EmitTask("client", func() {
		close(started)
		<-release
	}) {
		t.Fatal("EmitTask() rejected test task")
	}
	<-started
	defer close(release)

	overview, err := (&Engine{udpTaskPool: pool}).GetRuntimeOverview(60, 16)
	if err != nil {
		t.Fatalf("GetRuntimeOverview() returned error: %v", err)
	}
	if overview.UDPTaskQueues != 1 {
		t.Fatalf("UDPTaskQueues = %d, want scoped pool count 1", overview.UDPTaskQueues)
	}
	if overview.UDPTaskDropTotal != 0 {
		t.Fatalf("UDPTaskDropTotal = %d, want scoped pool drop count 0", overview.UDPTaskDropTotal)
	}
	if overview.PacketSnifferSessions != 77 {
		t.Fatalf("PacketSnifferSessions = %d, want snapshot value 77", overview.PacketSnifferSessions)
	}
}

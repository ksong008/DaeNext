package engine

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/control"
)

func BenchmarkEngineRuntimeOverviewScopedUdpTaskPool(b *testing.B) {
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
	started := make(chan struct{})
	release := make(chan struct{})
	if !pool.EmitTask("client", func() {
		close(started)
		<-release
	}) {
		b.Fatal("EmitTask() rejected benchmark task")
	}
	<-started
	defer func() {
		close(release)
		pool.Close()
	}()

	e := &Engine{udpTaskPool: pool}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		overview, err := e.GetRuntimeOverview(60, 16)
		if err != nil {
			b.Fatal(err)
		}
		if overview.UDPTaskQueues != 1 || overview.UDPTaskDropTotal != 0 {
			b.Fatalf("unexpected scoped overview: %+v", overview)
		}
	}
}

func BenchmarkEngineRouteAwareTarget(b *testing.B) {
	inputs := []struct {
		host string
		port string
	}{
		{"example.com", "443"},
		{"192.0.2.1", "8443"},
		{"2001:db8::1", "9443"},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, input := range inputs {
			domain, dest, err := routeAwareDialTarget(input.host, input.port)
			if err != nil {
				b.Fatal(err)
			}
			if domain == "" && !dest.Addr().IsValid() {
				b.Fatalf("unexpected route aware target: domain=%q dest=%v", domain, dest)
			}
		}
	}
}

func BenchmarkEngineNecessaryOutbounds(b *testing.B) {
	globalSection := `global {
    log_level: debug
    udp_endpoint_pool_size: 8192
}`
	routingSection := `routing {
    domain(suffix: example.com) -> must_proxy
    domain(full: force.example.com) -> must_rules
    fallback: must_direct
}`
	conf, err := ParseConfig(&globalSection, nil, &routingSection)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		outbounds := NecessaryOutbounds(&conf.Routing)
		if len(outbounds) != 3 || outbounds[0] != "direct" {
			b.Fatalf("unexpected necessary outbounds: %v", outbounds)
		}
	}
}

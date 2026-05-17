/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

const engineGoldenUpdateEnv = "DAE_UPDATE_REBUILD_GOLDEN"

func TestWriteEngineRuntimeGoldenFixtures(t *testing.T) {
	writeOrCheckEngineGolden(t, "../testdata/rebuild-golden/engine/dry_runtime/reload_stop.json", rebuildGoldenEngineDryRuntime(t))
	writeOrCheckEngineGolden(t, "../testdata/rebuild-golden/engine/route_aware/target.json", rebuildGoldenEngineRouteAwareTarget())
	writeOrCheckEngineGolden(t, "../testdata/rebuild-golden/engine/runtime_overview/basic.json", rebuildGoldenEngineRuntimeOverview(t))
	writeOrCheckEngineGolden(t, "../testdata/rebuild-golden/engine/config_api/empty_parse.json", rebuildGoldenEngineConfigApi(t))
	writeOrCheckEngineGolden(t, "../testdata/rebuild-golden/engine/subscription/persist_cleanup.json", rebuildGoldenEngineSubscriptionPersistCleanup(t))
}

func writeOrCheckEngineGolden(t *testing.T, path string, value any) {
	t.Helper()

	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	data = append(data, '\n')

	if os.Getenv(engineGoldenUpdateEnv) == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, data, 0644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !engineJSONEqual(want, data) {
		t.Fatalf("%s does not match generated golden; run %s=1 go test ./engine -run TestWriteEngineRuntimeGoldenFixtures", path, engineGoldenUpdateEnv)
	}
}

func engineJSONEqual(a, b []byte) bool {
	var av any
	var bv any
	if err := json.Unmarshal(a, &av); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &bv); err != nil {
		return false
	}
	return reflect.DeepEqual(av, bv)
}

func rebuildGoldenEngineDryRuntime(t *testing.T) any {
	beforeRunEngine := New(Options{})
	beforeRunCtx, beforeRunCancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer beforeRunCancel()
	beforeRunErr := beforeRunEngine.ReloadWithContext(beforeRunCtx, EmptyConfig())

	dryEngine := New(Options{})
	log := logrus.New()
	log.SetOutput(io.Discard)
	done := make(chan error, 1)
	go func() {
		done <- dryEngine.Run(log, EmptyConfig(), nil, true, true)
	}()

	reloadCtx, reloadCancel := context.WithTimeout(context.Background(), time.Second)
	defer reloadCancel()
	reloadErr := dryEngine.ReloadWithContext(reloadCtx, EmptyConfig())
	stopErr := dryEngine.Stop(time.Second)

	var runErr error
	select {
	case runErr = <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for dry runtime stop")
	}

	return map[string]any{
		"name": "engine-dry-runtime-reload-stop",
		"source": []string{
			"engine/runtime.go",
			"engine/runtime_test.go",
		},
		"notes": "API-only dry runtime accepts reload as a noop once Run is serving, stop exits the loop, and reload before Run waits until context deadline.",
		"before_run_reload": map[string]any{
			"context_timeout_ms": 10,
			"error":              errorClass(beforeRunErr),
			"is_deadline":        errors.Is(beforeRunErr, context.DeadlineExceeded),
		},
		"dry_runtime": map[string]any{
			"reload_error": errorClass(reloadErr),
			"stop_error":   errorClass(stopErr),
			"run_error":    errorClass(runErr),
		},
	}
}

func rebuildGoldenEngineRouteAwareTarget() any {
	cases := []map[string]string{
		{"name": "domain", "host": "example.com", "port": "443"},
		{"name": "ipv4", "host": "203.0.113.1", "port": "8443"},
		{"name": "ipv6", "host": "2001:db8::1", "port": "443"},
		{"name": "empty-host", "host": "", "port": "443"},
		{"name": "bad-port", "host": "example.com", "port": "70000"},
	}
	out := make([]map[string]any, 0, len(cases))
	for _, tc := range cases {
		domain, dest, err := routeAwareDialTarget(tc["host"], tc["port"])
		item := map[string]any{
			"name": tc["name"],
			"host": tc["host"],
			"port": tc["port"],
			"ok":   err == nil,
		}
		if err != nil {
			item["error"] = err.Error()
		} else {
			item["domain"] = domain
			item["dest"] = dest.String()
			item["dest_is_unspecified"] = dest.Addr().IsUnspecified()
		}
		out = append(out, item)
	}
	return map[string]any{
		"name": "engine-route-aware-target",
		"source": []string{
			"engine/runtime.go",
			"engine/runtime_test.go",
		},
		"notes": "Domain hosts must stay as domain + 0.0.0.0:port so route-aware HTTP transport does not perform system DNS resolution.",
		"cases": out,
	}
}

func rebuildGoldenEngineRuntimeOverview(t *testing.T) any {
	originalSnapshotRuntimeStats := snapshotRuntimeStats
	snapshotRuntimeStats = func(activeConnections int, udpSessions int, windowSec int, maxPoints int) control.RuntimeStatsSnapshot {
		return control.RuntimeStatsSnapshot{
			UpdatedAt:             time.Unix(1_700_000_300, 0),
			UploadRate:            10,
			DownloadRate:          20,
			UploadTotal:           30,
			DownloadTotal:         40,
			ActiveConnections:     activeConnections,
			UDPSessions:           udpSessions,
			UDPTaskQueues:         99,
			UDPTaskDropTotal:      88,
			PacketSnifferSessions: 77,
			RSSBytes:              50,
			HeapAllocBytes:        60,
			Goroutines:            70,
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
		t.Fatalf("GetRuntimeOverview() error: %v", err)
	}

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

	scoped, err := (&Engine{udpTaskPool: pool}).GetRuntimeOverview(60, 16)
	if err != nil {
		t.Fatalf("GetRuntimeOverview() scoped error: %v", err)
	}

	return map[string]any{
		"name": "engine-runtime-overview-basic",
		"source": []string{
			"engine/runtime.go",
			"engine/runtime_test.go",
			"control/runtime_stats.go",
		},
		"notes":            "RuntimeOverview must tolerate missing control plane, retain DNS observability fields and samples, and prefer Engine scoped UDP task pool telemetry.",
		"no_control_plane": projectRuntimeOverview(overview),
		"scoped_udp_task_pool": map[string]any{
			"udp_task_queues":      scoped.UDPTaskQueues,
			"udp_task_drop_total":  scoped.UDPTaskDropTotal,
			"packet_sniffer_kept":  scoped.PacketSnifferSessions,
			"snapshot_queue_input": 99,
			"snapshot_drop_input":  88,
		},
	}
}

func rebuildGoldenEngineConfigApi(t *testing.T) any {
	globalSection := `global {
    log_level: debug
    udp_endpoint_pool_size: 8192
}`
	routingSection := `routing {
    domain(suffix: example.com) -> must_proxy
    domain(full: force.example.com) -> must_rules
    fallback: must_direct
}`
	empty := EmptyConfig()
	parsed, err := ParseConfig(&globalSection, nil, &routingSection)
	if err != nil {
		t.Fatalf("ParseConfig() error: %v", err)
	}
	fallback := config.FunctionOrStringToFunction(parsed.Routing.Fallback)
	return map[string]any{
		"name": "engine-config-api-empty-parse",
		"source": []string{
			"engine/helpers.go",
			"engine/runtime_test.go",
		},
		"notes": "EmptyConfig and ParseConfig preserve section defaults and must_ outbound rewrite semantics for API-only callers.",
		"empty_config": map[string]any{
			"log_level":               empty.Global.LogLevel,
			"fallback_resolver":       empty.Global.FallbackResolver,
			"udp_endpoint_pool_size":  empty.Global.UdpEndpointPoolSize,
			"routing_fallback":        config.FunctionOrStringToFunction(empty.Routing.Fallback).Name,
			"dns_request_fallback":    config.FunctionOrStringToFunction(empty.Dns.Routing.Request.Fallback).Name,
			"dns_response_fallback":   config.FunctionOrStringToFunction(empty.Dns.Routing.Response.Fallback).Name,
			"group_count":             len(empty.Group),
			"subscription_count":      len(empty.Subscription),
			"node_count":              len(empty.Node),
			"routing_rule_count":      len(empty.Routing.Rules),
			"dns_request_rule_count":  len(empty.Dns.Routing.Request.Rules),
			"dns_response_rule_count": len(empty.Dns.Routing.Response.Rules),
		},
		"parse_config": map[string]any{
			"global_input":         globalSection,
			"routing_input":        routingSection,
			"log_level":            parsed.Global.LogLevel,
			"udp_pool_size":        parsed.Global.UdpEndpointPoolSize,
			"routing_rule_count":   len(parsed.Routing.Rules),
			"necessary_outbounds":  NecessaryOutbounds(&parsed.Routing),
			"first_rule_outbound":  projectFunction(&parsed.Routing.Rules[0].Outbound),
			"second_rule_outbound": projectFunction(&parsed.Routing.Rules[1].Outbound),
			"fallback":             projectFunction(fallback),
		},
	}
}

func rebuildGoldenEngineSubscriptionPersistCleanup(t *testing.T) any {
	configDir := t.TempDir()
	persistDir := filepath.Join(configDir, "persist.d")
	if err := os.MkdirAll(persistDir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"active.sub", "stale.sub", "note.txt"} {
		if err := os.WriteFile(filepath.Join(persistDir, name), []byte("payload"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	err := cleanupSubscriptionPersistFiles(configDir, map[string][]string{
		"active": {"ss://active"},
	})
	if err != nil {
		t.Fatalf("cleanupSubscriptionPersistFiles() error: %v", err)
	}
	entries, err := os.ReadDir(persistDir)
	if err != nil {
		t.Fatal(err)
	}
	remaining := make([]string, 0, len(entries))
	for _, entry := range entries {
		remaining = append(remaining, entry.Name())
	}
	sort.Strings(remaining)

	missingDirErr := cleanupSubscriptionPersistFiles(filepath.Join(configDir, "missing"), map[string][]string{})
	return map[string]any{
		"name": "engine-subscription-persist-cleanup",
		"source": []string{
			"engine/runtime.go",
			"common/subscription/subscription.go",
		},
		"notes":             "Current daenew cleanup trims a .sub suffix to derive the tag and removes any inactive persist.d entry; missing persist.d is ignored.",
		"input_files":       []string{"active.sub", "stale.sub", "note.txt"},
		"active_tags":       []string{"active"},
		"remaining_files":   remaining,
		"missing_dir_error": errorClass(missingDirErr),
		"concurrency_limit": subscriptionResolveConcurrency,
	}
}

func projectRuntimeOverview(overview *RuntimeOverview) map[string]any {
	samples := make([]map[string]any, 0, len(overview.Samples))
	for _, sample := range overview.Samples {
		samples = append(samples, map[string]any{
			"timestamp_unix": sample.Timestamp.Unix(),
			"upload_rate":    sample.UploadRate,
			"download_rate":  sample.DownloadRate,
		})
	}
	return map[string]any{
		"updated_at_unix":                        overview.UpdatedAt.Unix(),
		"upload_rate":                            overview.UploadRate,
		"download_rate":                          overview.DownloadRate,
		"upload_total":                           overview.UploadTotal,
		"download_total":                         overview.DownloadTotal,
		"active_connections":                     overview.ActiveConnections,
		"udp_sessions":                           overview.UDPSessions,
		"udp_task_queues":                        overview.UDPTaskQueues,
		"udp_task_drop_total":                    overview.UDPTaskDropTotal,
		"packet_sniffer_sessions":                overview.PacketSnifferSessions,
		"rss_bytes":                              overview.RSSBytes,
		"heap_alloc_bytes":                       overview.HeapAllocBytes,
		"goroutines":                             overview.Goroutines,
		"dns_cache_hit_total":                    overview.DnsCacheHitTotal,
		"dns_cache_expired_removal_total":        overview.DnsCacheExpiredRemovalTotal,
		"dns_udp_retry_total":                    overview.DnsUdpRetryTotal,
		"dns_truncated_tcp_fallback_total":       overview.DnsTruncatedTcpFallbackTotal,
		"dns_doh_status_failure_total":           overview.DnsDoHStatusFailureTotal,
		"dns_doh_content_type_failure_total":     overview.DnsDoHContentTypeFailureTotal,
		"dns_upstream_refresh_success_total":     overview.DnsUpstreamRefreshSuccessTotal,
		"dns_upstream_refresh_failure_total":     overview.DnsUpstreamRefreshFailureTotal,
		"dns_upstream_refresh_stale_reuse_total": overview.DnsUpstreamRefreshStaleReuseTotal,
		"samples":                                samples,
	}
}

func projectFunction(function *config_parser.Function) map[string]any {
	params := make([]map[string]string, 0, len(function.Params))
	for _, param := range function.Params {
		params = append(params, map[string]string{
			"key": param.Key,
			"val": param.Val,
		})
	}
	return map[string]any{
		"name":   function.Name,
		"not":    function.Not,
		"params": params,
	}
}

func errorClass(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "context deadline exceeded"
	}
	return err.Error()
}

func BenchmarkEngineRouteAwareDialTarget(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		domain, dest, err := routeAwareDialTarget("example.com", "443")
		if err != nil {
			b.Fatal(err)
		}
		if domain != "example.com" || !dest.Addr().IsUnspecified() || dest.Port() != 443 {
			b.Fatalf("unexpected target: %q %v", domain, dest)
		}
	}
}

func BenchmarkEngineRuntimeOverviewNoControlPlane(b *testing.B) {
	originalSnapshotRuntimeStats := snapshotRuntimeStats
	snapshotRuntimeStats = func(activeConnections int, udpSessions int, windowSec int, maxPoints int) control.RuntimeStatsSnapshot {
		return control.RuntimeStatsSnapshot{
			UpdatedAt:     time.Unix(1_700_000_300, 0),
			UploadRate:    10,
			DownloadRate:  20,
			UploadTotal:   30,
			DownloadTotal: 40,
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

	e := &Engine{}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		overview, err := e.GetRuntimeOverview(45, 90)
		if err != nil {
			b.Fatal(err)
		}
		if overview.UploadRate != 10 || len(overview.Samples) != 1 {
			b.Fatalf("unexpected overview: %+v", overview)
		}
	}
}

func BenchmarkEngineParseConfigAPI(b *testing.B) {
	globalSection := `global {
    log_level: debug
    udp_endpoint_pool_size: 8192
}`
	routingSection := `routing {
    domain(suffix: example.com) -> must_proxy
    fallback: must_direct
}`
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		conf, err := ParseConfig(&globalSection, nil, &routingSection)
		if err != nil {
			b.Fatal(err)
		}
		if conf.Global.LogLevel != "debug" || len(conf.Routing.Rules) != 1 {
			b.Fatalf("unexpected parsed config: %+v", conf)
		}
	}
}

func BenchmarkEngineSubscriptionPersistCleanup(b *testing.B) {
	configDir := b.TempDir()
	persistDir := filepath.Join(configDir, "persist.d")
	if err := os.MkdirAll(persistDir, 0700); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, name := range []string{"active.sub", "stale.sub", "note.txt"} {
			if err := os.WriteFile(filepath.Join(persistDir, name), []byte("payload"), 0600); err != nil {
				b.Fatal(err)
			}
		}
		if err := cleanupSubscriptionPersistFiles(configDir, map[string][]string{"active": {"ss://active"}}); err != nil {
			b.Fatal(err)
		}
	}
}

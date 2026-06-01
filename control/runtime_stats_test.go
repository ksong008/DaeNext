/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
	"time"
)

func TestRuntimeStatsSnapshotAggregatesAcrossShards(t *testing.T) {
	stats := newRuntimeStats(2)
	now := time.Unix(1_700_000_000, 125_000_000)

	stats.shards[0].record(100, 0, now)
	stats.shards[1].record(0, 200, now)

	snapshot := stats.snapshot(3, 4, 5, 6, 7, 30, 180, now.Add(runtimeBucketDuration))

	if snapshot.UploadTotal != 100 {
		t.Fatalf("expected upload total 100, got %d", snapshot.UploadTotal)
	}
	if snapshot.DownloadTotal != 200 {
		t.Fatalf("expected download total 200, got %d", snapshot.DownloadTotal)
	}
	if snapshot.ActiveConnections != 3 {
		t.Fatalf("expected active connections 3, got %d", snapshot.ActiveConnections)
	}
	if snapshot.UDPSessions != 4 {
		t.Fatalf("expected udp sessions 4, got %d", snapshot.UDPSessions)
	}
	if snapshot.UDPTaskQueues != 5 {
		t.Fatalf("expected udp task queues 5, got %d", snapshot.UDPTaskQueues)
	}
	if snapshot.UDPTaskDropTotal != 6 {
		t.Fatalf("expected udp task drop total 6, got %d", snapshot.UDPTaskDropTotal)
	}
	if snapshot.PacketSnifferSessions != 7 {
		t.Fatalf("expected packet sniffer sessions 7, got %d", snapshot.PacketSnifferSessions)
	}
	if len(snapshot.Samples) == 0 {
		t.Fatal("expected at least one runtime sample")
	}
	if snapshot.UploadRate == 0 {
		t.Fatal("expected aggregated upload rate to be non-zero")
	}
	if snapshot.DownloadRate == 0 {
		t.Fatal("expected aggregated download rate to be non-zero")
	}
}

func TestRuntimeStatsSnapshotIncludesCPUUsagePercent(t *testing.T) {
	originalCPUUsagePercent := currentCPUUsagePercent
	currentCPUUsagePercent = func() float64 {
		return 12.5
	}
	defer func() {
		currentCPUUsagePercent = originalCPUUsagePercent
	}()

	stats := newRuntimeStats(1)
	snapshot := stats.snapshot(0, 0, 0, 0, 0, 30, 180, time.Unix(1_700_000_010, 0))

	if snapshot.CPUUsagePercent != 12.5 {
		t.Fatalf("expected cpu usage 12.5, got %f", snapshot.CPUUsagePercent)
	}
}

func TestRuntimeStatsSnapshotIncludesRecordsFromMultipleBuckets(t *testing.T) {
	stats := newRuntimeStats(2)
	base := time.Unix(1_700_000_100, 0)

	stats.shards[0].record(120, 0, base)
	stats.shards[1].record(0, 80, base.Add(runtimeBucketDuration))

	snapshot := stats.snapshot(0, 0, 0, 0, 0, 30, 180, base.Add(2*runtimeBucketDuration))

	if snapshot.UploadTotal != 120 {
		t.Fatalf("expected upload total 120, got %d", snapshot.UploadTotal)
	}
	if snapshot.DownloadTotal != 80 {
		t.Fatalf("expected download total 80, got %d", snapshot.DownloadTotal)
	}
	if len(snapshot.Samples) < 2 {
		t.Fatalf("expected samples from at least two buckets, got %d", len(snapshot.Samples))
	}
}

func TestSnapshotRuntimeStatsIncludesDnsObservabilityStats(t *testing.T) {
	originalHook := runtimeStatsDnsObservabilitySnapshot
	runtimeStatsDnsObservabilitySnapshot = func() DnsObservabilityStats {
		return DnsObservabilityStats{
			DnsCacheHitTotal:                  11,
			DnsCacheExpiredRemovalTotal:       12,
			DnsUdpRetryTotal:                  13,
			DnsTruncatedTcpFallbackTotal:      14,
			DnsDoHStatusFailureTotal:          15,
			DnsDoHContentTypeFailureTotal:     16,
			DnsUpstreamRefreshSuccessTotal:    17,
			DnsUpstreamRefreshFailureTotal:    18,
			DnsUpstreamRefreshStaleReuseTotal: 19,
		}
	}
	defer func() {
		runtimeStatsDnsObservabilitySnapshot = originalHook
	}()

	snapshot := SnapshotRuntimeStats(1, 2, 30, 180)

	if snapshot.DnsCacheHitTotal != 11 {
		t.Fatalf("expected dns cache hit total 11, got %d", snapshot.DnsCacheHitTotal)
	}
	if snapshot.DnsCacheExpiredRemovalTotal != 12 {
		t.Fatalf("expected dns cache expired removal total 12, got %d", snapshot.DnsCacheExpiredRemovalTotal)
	}
	if snapshot.DnsUdpRetryTotal != 13 {
		t.Fatalf("expected dns udp retry total 13, got %d", snapshot.DnsUdpRetryTotal)
	}
	if snapshot.DnsTruncatedTcpFallbackTotal != 14 {
		t.Fatalf("expected dns truncated tcp fallback total 14, got %d", snapshot.DnsTruncatedTcpFallbackTotal)
	}
	if snapshot.DnsDoHStatusFailureTotal != 15 {
		t.Fatalf("expected doh status failure total 15, got %d", snapshot.DnsDoHStatusFailureTotal)
	}
	if snapshot.DnsDoHContentTypeFailureTotal != 16 {
		t.Fatalf("expected doh content-type failure total 16, got %d", snapshot.DnsDoHContentTypeFailureTotal)
	}
	if snapshot.DnsUpstreamRefreshSuccessTotal != 17 {
		t.Fatalf("expected upstream refresh success total 17, got %d", snapshot.DnsUpstreamRefreshSuccessTotal)
	}
	if snapshot.DnsUpstreamRefreshFailureTotal != 18 {
		t.Fatalf("expected upstream refresh failure total 18, got %d", snapshot.DnsUpstreamRefreshFailureTotal)
	}
	if snapshot.DnsUpstreamRefreshStaleReuseTotal != 19 {
		t.Fatalf("expected upstream refresh stale reuse total 19, got %d", snapshot.DnsUpstreamRefreshStaleReuseTotal)
	}
}

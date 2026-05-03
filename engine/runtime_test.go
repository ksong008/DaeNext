/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package engine

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/control"
)

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

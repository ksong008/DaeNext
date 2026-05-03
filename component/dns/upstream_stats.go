/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import "sync/atomic"

type UpstreamResolverStatsSnapshot struct {
	RefreshSuccessTotal uint64
	RefreshFailureTotal uint64
	StaleReuseTotal     uint64
}

type upstreamResolverCounters struct {
	refreshSuccessTotal atomic.Uint64
	refreshFailureTotal atomic.Uint64
	staleReuseTotal     atomic.Uint64
}

var globalUpstreamResolverCounters upstreamResolverCounters

func recordUpstreamResolverRefreshSuccess() {
	globalUpstreamResolverCounters.refreshSuccessTotal.Add(1)
}

func recordUpstreamResolverRefreshFailure() {
	globalUpstreamResolverCounters.refreshFailureTotal.Add(1)
}

func recordUpstreamResolverStaleReuse() {
	globalUpstreamResolverCounters.staleReuseTotal.Add(1)
}

func SnapshotUpstreamResolverStats() UpstreamResolverStatsSnapshot {
	return UpstreamResolverStatsSnapshot{
		RefreshSuccessTotal: globalUpstreamResolverCounters.refreshSuccessTotal.Load(),
		RefreshFailureTotal: globalUpstreamResolverCounters.refreshFailureTotal.Load(),
		StaleReuseTotal:     globalUpstreamResolverCounters.staleReuseTotal.Load(),
	}
}

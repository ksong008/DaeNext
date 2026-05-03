/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync/atomic"

	componentdns "github.com/daeuniverse/dae/component/dns"
)

type DnsObservabilityStats struct {
	DnsCacheHitTotal                  uint64 `json:"dnsCacheHitTotal"`
	DnsCacheExpiredRemovalTotal       uint64 `json:"dnsCacheExpiredRemovalTotal"`
	DnsUdpRetryTotal                  uint64 `json:"dnsUdpRetryTotal"`
	DnsTruncatedTcpFallbackTotal      uint64 `json:"dnsTruncatedTcpFallbackTotal"`
	DnsDoHStatusFailureTotal          uint64 `json:"dnsDohStatusFailureTotal"`
	DnsDoHContentTypeFailureTotal     uint64 `json:"dnsDohContentTypeFailureTotal"`
	DnsUpstreamRefreshSuccessTotal    uint64 `json:"dnsUpstreamRefreshSuccessTotal"`
	DnsUpstreamRefreshFailureTotal    uint64 `json:"dnsUpstreamRefreshFailureTotal"`
	DnsUpstreamRefreshStaleReuseTotal uint64 `json:"dnsUpstreamRefreshStaleReuseTotal"`
}

type dnsObservabilityCounters struct {
	cacheHitTotal              atomic.Uint64
	cacheExpiredRemovalTotal   atomic.Uint64
	udpRetryTotal              atomic.Uint64
	truncatedTcpFallbackTotal  atomic.Uint64
	doHStatusFailureTotal      atomic.Uint64
	doHContentTypeFailureTotal atomic.Uint64
}

var globalDnsObservabilityCounters dnsObservabilityCounters

func recordDnsCacheHit() {
	globalDnsObservabilityCounters.cacheHitTotal.Add(1)
}

func recordDnsCacheExpiredRemovals(n int) {
	if n <= 0 {
		return
	}
	globalDnsObservabilityCounters.cacheExpiredRemovalTotal.Add(uint64(n))
}

func recordDnsUDPRetry() {
	globalDnsObservabilityCounters.udpRetryTotal.Add(1)
}

func recordDnsTruncatedTcpFallback() {
	globalDnsObservabilityCounters.truncatedTcpFallbackTotal.Add(1)
}

func recordDoHStatusFailure() {
	globalDnsObservabilityCounters.doHStatusFailureTotal.Add(1)
}

func recordDoHContentTypeFailure() {
	globalDnsObservabilityCounters.doHContentTypeFailureTotal.Add(1)
}

func snapshotDnsObservabilityStats() DnsObservabilityStats {
	upstreamStats := componentdns.SnapshotUpstreamResolverStats()
	return DnsObservabilityStats{
		DnsCacheHitTotal:                  globalDnsObservabilityCounters.cacheHitTotal.Load(),
		DnsCacheExpiredRemovalTotal:       globalDnsObservabilityCounters.cacheExpiredRemovalTotal.Load(),
		DnsUdpRetryTotal:                  globalDnsObservabilityCounters.udpRetryTotal.Load(),
		DnsTruncatedTcpFallbackTotal:      globalDnsObservabilityCounters.truncatedTcpFallbackTotal.Load(),
		DnsDoHStatusFailureTotal:          globalDnsObservabilityCounters.doHStatusFailureTotal.Load(),
		DnsDoHContentTypeFailureTotal:     globalDnsObservabilityCounters.doHContentTypeFailureTotal.Load(),
		DnsUpstreamRefreshSuccessTotal:    upstreamStats.RefreshSuccessTotal,
		DnsUpstreamRefreshFailureTotal:    upstreamStats.RefreshFailureTotal,
		DnsUpstreamRefreshStaleReuseTotal: upstreamStats.StaleReuseTotal,
	}
}

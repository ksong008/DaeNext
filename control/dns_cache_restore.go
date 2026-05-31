/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

type dnsCacheRestoreStats struct {
	SnapshotEntries int
	RestoredEntries int
	InvalidKeys     int
	EmptyAnswers    int
	FailedEntries   int
}

func (s dnsCacheRestoreStats) Err() error {
	if s.FailedEntries == 0 {
		return nil
	}
	return fmt.Errorf("restore DNS cache snapshot failed: %d/%d entries failed", s.FailedEntries, s.SnapshotEntries)
}

func restoreDnsCacheSnapshot(log *logrus.Logger, controller *DnsController, dnsCache map[string]*DnsCache) dnsCacheRestoreStats {
	stats := dnsCacheRestoreStats{SnapshotEntries: len(dnsCache)}
	if controller == nil || len(dnsCache) == 0 {
		return stats
	}
	for rawCacheKey, cache := range dnsCache {
		cacheKey, ok := parseDnsCacheKey(rawCacheKey)
		if !ok {
			stats.InvalidKeys++
			log.Warnln("Invalid cache key:", rawCacheKey)
			continue
		}
		answers := cache.answersForQuestion(cacheKey.qname, cacheKey.qtype, cacheKey.qclass)
		if len(answers) == 0 {
			stats.EmptyAnswers++
			continue
		}
		if err := controller.__updateDnsCacheDeadline(cacheKey.qname, cacheKey.qtype, cacheKey.qclass, answers, func(_ time.Time, _ string) (time.Time, time.Time) {
			return cache.Deadline, cache.OriginalDeadline
		}); err != nil {
			stats.FailedEntries++
			log.WithError(err).Warnf("Failed to restore DNS cache for %s", cacheKey.qname)
			continue
		}
		stats.RestoredEntries++
	}
	return stats
}

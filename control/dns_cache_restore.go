/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"time"

	"github.com/sirupsen/logrus"
)

func restoreDnsCacheSnapshot(log *logrus.Logger, controller *DnsController, dnsCache map[string]*DnsCache) {
	if controller == nil || len(dnsCache) == 0 {
		return
	}
	for rawCacheKey, cache := range dnsCache {
		cacheKey, ok := parseDnsCacheKey(rawCacheKey)
		if !ok {
			log.Warnln("Invalid cache key:", rawCacheKey)
			continue
		}
		answers := cache.answersForQuestion(cacheKey.qname, cacheKey.qtype, cacheKey.qclass)
		if len(answers) == 0 {
			continue
		}
		if err := controller.__updateDnsCacheDeadline(cacheKey.qname, cacheKey.qtype, cacheKey.qclass, answers, func(_ time.Time, _ string) (time.Time, time.Time) {
			return cache.Deadline, cache.OriginalDeadline
		}); err != nil {
			log.WithError(err).Warnf("Failed to restore DNS cache for %s", cacheKey.qname)
		}
	}
}

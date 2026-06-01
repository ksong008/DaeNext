/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"math"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxRuntimeHistorySeconds = 60
	defaultRuntimeWindowSec  = 60
	defaultRuntimeMaxPoints  = 240
	runtimeBucketDuration    = 250 * time.Millisecond
	runtimeRateWindow        = time.Second
	maxRuntimeHistoryBuckets = int((time.Duration(maxRuntimeHistorySeconds) * time.Second) / runtimeBucketDuration)
	runtimeHistoryTrimBatch  = 256
	runtimeStatsShardCount   = 16
)

type RuntimeTrafficSample struct {
	Timestamp    time.Time
	UploadRate   uint64
	DownloadRate uint64
}

type RuntimeStatsSnapshot struct {
	UpdatedAt             time.Time
	UploadRate            uint64
	DownloadRate          uint64
	UploadTotal           uint64
	DownloadTotal         uint64
	ActiveConnections     int
	UDPSessions           int
	UDPTaskQueues         int
	UDPTaskDropTotal      uint64
	PacketSnifferSessions int
	CPUUsagePercent       float64
	RSSBytes              uint64
	HeapAllocBytes        uint64
	Goroutines            int
	DnsObservabilityStats
	Samples []RuntimeTrafficSample
}

type runtimeBucket struct {
	Timestamp     time.Time
	UploadBytes   uint64
	DownloadBytes uint64
	Duration      time.Duration
}

type runtimeStatsShard struct {
	mu sync.Mutex

	currentBucketStart   time.Time
	currentUploadBytes   uint64
	currentDownloadBytes uint64

	uploadTotal   uint64
	downloadTotal uint64
	history       []runtimeBucket
}

type runtimeStats struct {
	nextShard uint32
	shards    []runtimeStatsShard
}

func newRuntimeStats(shardCount int) *runtimeStats {
	if shardCount <= 0 {
		shardCount = 1
	}
	return &runtimeStats{
		shards: make([]runtimeStatsShard, shardCount),
	}
}

var globalRuntimeStats = newRuntimeStats(runtimeStatsShardCount)

// runtimeStatsOccupancySnapshot keeps file-level runtime_stats tests buildable
// while allowing full package builds to sample live control-pool occupancy.
var runtimeStatsOccupancySnapshot = func() (udpTaskQueues int, udpTaskDropTotal uint64, packetSnifferSessions int) {
	return 0, 0, 0
}

var runtimeStatsDnsObservabilitySnapshot = snapshotDnsObservabilityStats
var globalRuntimeCPUSampler = &processCPUSampler{}
var currentCPUUsagePercent = func() float64 {
	return globalRuntimeCPUSampler.sample()
}

type processCPUSampler struct {
	mu sync.Mutex

	lastProcessTicks uint64
	lastTotalTicks   uint64
	lastPercent      float64
}

func RecordUploadTraffic(n int64) {
	if n <= 0 {
		return
	}
	globalRuntimeStats.record(uint64(n), 0, time.Now())
}

func RecordDownloadTraffic(n int64) {
	if n <= 0 {
		return
	}
	globalRuntimeStats.record(0, uint64(n), time.Now())
}

func SnapshotRuntimeStats(activeConnections int, udpSessions int, windowSec int, maxPoints int) RuntimeStatsSnapshot {
	udpTaskQueues, udpTaskDropTotal, packetSnifferSessions := runtimeStatsOccupancySnapshot()
	snapshot := globalRuntimeStats.snapshot(
		activeConnections,
		udpSessions,
		udpTaskQueues,
		udpTaskDropTotal,
		packetSnifferSessions,
		windowSec,
		maxPoints,
		time.Now(),
	)
	snapshot.DnsObservabilityStats = runtimeStatsDnsObservabilitySnapshot()
	return snapshot
}

func (s *runtimeStats) record(upload uint64, download uint64, now time.Time) {
	if len(s.shards) == 0 {
		return
	}
	idx := int(atomic.AddUint32(&s.nextShard, 1)-1) % len(s.shards)
	s.shards[idx].record(upload, download, now)
}

func (s *runtimeStatsShard) record(upload uint64, download uint64, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.advanceLocked(bucketStart(now))
	s.currentUploadBytes += upload
	s.currentDownloadBytes += download
	s.uploadTotal += upload
	s.downloadTotal += download
}

func (s *runtimeStats) snapshot(
	activeConnections int,
	udpSessions int,
	udpTaskQueues int,
	udpTaskDropTotal uint64,
	packetSnifferSessions int,
	windowSec int,
	maxPoints int,
	now time.Time,
) RuntimeStatsSnapshot {
	if windowSec <= 0 {
		windowSec = defaultRuntimeWindowSec
	}
	if maxPoints <= 0 {
		maxPoints = defaultRuntimeMaxPoints
	}

	nowBucketStart := bucketStart(now)
	startTime := now.Add(-time.Duration(windowSec) * time.Second)
	aggregatedBuckets := make(map[int64]runtimeBucket)
	var uploadTotal uint64
	var downloadTotal uint64
	for i := range s.shards {
		buckets, shardUploadTotal, shardDownloadTotal := s.shards[i].snapshotBuckets(nowBucketStart, startTime, now)
		uploadTotal += shardUploadTotal
		downloadTotal += shardDownloadTotal
		for _, bucket := range buckets {
			key := bucket.Timestamp.UnixNano()
			if aggregated, ok := aggregatedBuckets[key]; ok {
				aggregated.UploadBytes += bucket.UploadBytes
				aggregated.DownloadBytes += bucket.DownloadBytes
				if bucket.Duration > aggregated.Duration {
					aggregated.Duration = bucket.Duration
				}
				aggregatedBuckets[key] = aggregated
				continue
			}
			aggregatedBuckets[key] = bucket
		}
	}
	buckets := make([]runtimeBucket, 0, len(aggregatedBuckets))
	for _, bucket := range aggregatedBuckets {
		buckets = append(buckets, bucket)
	}
	sort.Slice(buckets, func(i, j int) bool {
		return buckets[i].Timestamp.Before(buckets[j].Timestamp)
	})

	uploadRate, downloadRate := ratesFromBuckets(buckets, now, runtimeRateWindow)
	samples := bucketizeRuntimeSamples(samplesFromBuckets(buckets), maxPoints)

	rssBytes := currentRSSBytes()
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return RuntimeStatsSnapshot{
		UpdatedAt:             now,
		UploadRate:            uploadRate,
		DownloadRate:          downloadRate,
		UploadTotal:           uploadTotal,
		DownloadTotal:         downloadTotal,
		ActiveConnections:     activeConnections,
		UDPSessions:           udpSessions,
		UDPTaskQueues:         udpTaskQueues,
		UDPTaskDropTotal:      udpTaskDropTotal,
		PacketSnifferSessions: packetSnifferSessions,
		CPUUsagePercent:       currentCPUUsagePercent(),
		RSSBytes:              rssBytes,
		HeapAllocBytes:        memStats.HeapAlloc,
		Goroutines:            runtime.NumGoroutine(),
		Samples:               samples,
	}
}

func (s *runtimeStatsShard) snapshotBuckets(nowBucketStart time.Time, startTime time.Time, now time.Time) ([]runtimeBucket, uint64, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.advanceLocked(nowBucketStart)

	buckets := make([]runtimeBucket, 0, len(s.history)+1)
	for _, bucket := range s.history {
		if !bucket.Timestamp.Before(startTime) {
			buckets = append(buckets, bucket)
		}
	}

	currentDuration := now.Sub(s.currentBucketStart)
	if currentDuration <= 0 {
		currentDuration = runtimeBucketDuration
	}
	buckets = append(buckets, runtimeBucket{
		Timestamp:     now,
		UploadBytes:   s.currentUploadBytes,
		DownloadBytes: s.currentDownloadBytes,
		Duration:      currentDuration,
	})
	return buckets, s.uploadTotal, s.downloadTotal
}

func (s *processCPUSampler) sample() float64 {
	processTicks, ok := currentProcessCPUTicks()
	if !ok {
		return 0
	}
	totalTicks, ok := currentTotalCPUTicks()
	if !ok {
		return 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.lastTotalTicks == 0 || totalTicks <= s.lastTotalTicks || processTicks < s.lastProcessTicks {
		s.lastProcessTicks = processTicks
		s.lastTotalTicks = totalTicks
		return s.lastPercent
	}

	processDelta := processTicks - s.lastProcessTicks
	totalDelta := totalTicks - s.lastTotalTicks
	s.lastProcessTicks = processTicks
	s.lastTotalTicks = totalTicks
	if totalDelta == 0 {
		return s.lastPercent
	}

	percent := float64(processDelta) / float64(totalDelta) * float64(runtime.NumCPU()) * 100
	if math.IsNaN(percent) || math.IsInf(percent, 0) || percent < 0 {
		return 0
	}
	s.lastPercent = percent
	return percent
}

func currentProcessCPUTicks() (uint64, bool) {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, false
	}
	stat := string(data)
	endComm := strings.LastIndexByte(stat, ')')
	if endComm < 0 || endComm+2 >= len(stat) {
		return 0, false
	}
	fields := strings.Fields(stat[endComm+2:])
	if len(fields) < 13 {
		return 0, false
	}
	utime, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return 0, false
	}
	stime, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return 0, false
	}
	return utime + stime, true
}

func currentTotalCPUTicks() (uint64, bool) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, false
	}
	lines := strings.SplitN(string(data), "\n", 2)
	fields := strings.Fields(lines[0])
	if len(fields) < 2 || fields[0] != "cpu" {
		return 0, false
	}
	var total uint64
	for _, field := range fields[1:] {
		ticks, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return 0, false
		}
		total += ticks
	}
	return total, total > 0
}

func currentRSSBytes() uint64 {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0
	}
	rssPages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return rssPages * uint64(os.Getpagesize())
}

func (s *runtimeStatsShard) advanceLocked(targetBucketStart time.Time) {
	if s.currentBucketStart.IsZero() {
		s.currentBucketStart = targetBucketStart
		return
	}
	if !targetBucketStart.After(s.currentBucketStart) {
		return
	}

	for s.currentBucketStart.Before(targetBucketStart) {
		s.history = append(s.history, runtimeBucket{
			Timestamp:     s.currentBucketStart.Add(runtimeBucketDuration),
			UploadBytes:   s.currentUploadBytes,
			DownloadBytes: s.currentDownloadBytes,
			Duration:      runtimeBucketDuration,
		})
		if len(s.history) > maxRuntimeHistoryBuckets+runtimeHistoryTrimBatch {
			drop := len(s.history) - maxRuntimeHistoryBuckets
			copy(s.history, s.history[drop:])
			for i := maxRuntimeHistoryBuckets; i < len(s.history); i++ {
				s.history[i] = runtimeBucket{}
			}
			s.history = s.history[:maxRuntimeHistoryBuckets]
		}
		s.currentBucketStart = s.currentBucketStart.Add(runtimeBucketDuration)
		s.currentUploadBytes = 0
		s.currentDownloadBytes = 0
	}
}

func bucketizeRuntimeSamples(samples []RuntimeTrafficSample, maxPoints int) []RuntimeTrafficSample {
	if len(samples) <= maxPoints {
		return samples
	}

	bucketSize := int(math.Ceil(float64(len(samples)) / float64(maxPoints)))
	result := make([]RuntimeTrafficSample, 0, maxPoints)

	for start := 0; start < len(samples); start += bucketSize {
		end := start + bucketSize
		if end > len(samples) {
			end = len(samples)
		}
		bucket := samples[start:end]
		last := bucket[len(bucket)-1]

		maxUpload := last.UploadRate
		maxDownload := last.DownloadRate
		for _, sample := range bucket[:len(bucket)-1] {
			if sample.UploadRate > maxUpload {
				maxUpload = sample.UploadRate
			}
			if sample.DownloadRate > maxDownload {
				maxDownload = sample.DownloadRate
			}
		}

		result = append(result, RuntimeTrafficSample{
			Timestamp:    last.Timestamp,
			UploadRate:   maxUpload,
			DownloadRate: maxDownload,
		})
	}

	return result
}

func bucketStart(now time.Time) time.Time {
	return now.Truncate(runtimeBucketDuration)
}

func rateFromBytes(bytes uint64, duration time.Duration) uint64 {
	if duration <= 0 {
		return 0
	}
	return uint64(float64(bytes) * float64(time.Second) / float64(duration))
}

func samplesFromBuckets(buckets []runtimeBucket) []RuntimeTrafficSample {
	samples := make([]RuntimeTrafficSample, 0, len(buckets))
	for _, bucket := range buckets {
		samples = append(samples, RuntimeTrafficSample{
			Timestamp:    bucket.Timestamp,
			UploadRate:   rateFromBytes(bucket.UploadBytes, bucket.Duration),
			DownloadRate: rateFromBytes(bucket.DownloadBytes, bucket.Duration),
		})
	}
	return samples
}

func ratesFromBuckets(buckets []runtimeBucket, now time.Time, window time.Duration) (uploadRate uint64, downloadRate uint64) {
	if len(buckets) == 0 {
		return 0, 0
	}

	windowStart := now.Add(-window)
	var (
		totalUpload   uint64
		totalDownload uint64
		totalDuration time.Duration
	)

	for _, bucket := range buckets {
		bucketEnd := bucket.Timestamp
		bucketStart := bucketEnd.Add(-bucket.Duration)
		if !bucketEnd.After(windowStart) {
			continue
		}

		effectiveStart := bucketStart
		if effectiveStart.Before(windowStart) {
			effectiveStart = windowStart
		}
		effectiveDuration := bucketEnd.Sub(effectiveStart)
		if effectiveDuration <= 0 {
			continue
		}

		ratio := float64(effectiveDuration) / float64(bucket.Duration)
		totalUpload += uint64(float64(bucket.UploadBytes) * ratio)
		totalDownload += uint64(float64(bucket.DownloadBytes) * ratio)
		totalDuration += effectiveDuration
	}

	if totalDuration <= 0 {
		return 0, 0
	}

	return rateFromBytes(totalUpload, totalDuration), rateFromBytes(totalDownload, totalDuration)
}

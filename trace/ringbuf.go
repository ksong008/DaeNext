/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package trace

import (
	"fmt"
	"math"
	"math/bits"
	"strconv"
	"strings"
)

const (
	DefaultRingbufSize      = "64MiB"
	minRingbufSizeBytes     = 4 << 10
	ringbufSizeAlignment    = 4 << 10
	defaultRingbufSizeBytes = 64 << 20
)

var ringbufSizeSuffixes = []struct {
	suffix     string
	multiplier uint64
}{
	{suffix: "gib", multiplier: 1 << 30},
	{suffix: "gb", multiplier: 1 << 30},
	{suffix: "g", multiplier: 1 << 30},
	{suffix: "mib", multiplier: 1 << 20},
	{suffix: "mb", multiplier: 1 << 20},
	{suffix: "m", multiplier: 1 << 20},
	{suffix: "kib", multiplier: 1 << 10},
	{suffix: "kb", multiplier: 1 << 10},
	{suffix: "k", multiplier: 1 << 10},
	{suffix: "b", multiplier: 1},
}

func ParseRingbufSizeBytes(value string) (uint32, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		raw = DefaultRingbufSize
	}

	size, err := parseBinaryByteSize(raw)
	if err != nil {
		return 0, err
	}
	if size < minRingbufSizeBytes {
		return 0, fmt.Errorf("ring buffer size %q is too small; expect at least %d bytes", raw, minRingbufSizeBytes)
	}
	if size%ringbufSizeAlignment != 0 {
		return 0, fmt.Errorf("ring buffer size %q must be aligned to %d bytes", raw, ringbufSizeAlignment)
	}
	if bits.OnesCount64(size) != 1 {
		return 0, fmt.Errorf("ring buffer size %q must be a power of two", raw)
	}
	if size > math.MaxUint32 {
		return 0, fmt.Errorf("ring buffer size %q exceeds uint32 map limit", raw)
	}
	return uint32(size), nil
}

func DefaultRingbufSizeBytes() uint32 {
	return defaultRingbufSizeBytes
}

func parseBinaryByteSize(value string) (uint64, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return 0, fmt.Errorf("ring buffer size cannot be empty")
	}

	multiplier := uint64(1)
	numberPart := normalized
	for _, suffix := range ringbufSizeSuffixes {
		if strings.HasSuffix(normalized, suffix.suffix) {
			multiplier = suffix.multiplier
			numberPart = strings.TrimSpace(normalized[:len(normalized)-len(suffix.suffix)])
			break
		}
	}
	if numberPart == "" {
		return 0, fmt.Errorf("ring buffer size %q is missing its numeric value", value)
	}

	base, err := strconv.ParseUint(numberPart, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid ring buffer size %q: %w", value, err)
	}
	if base > math.MaxUint64/multiplier {
		return 0, fmt.Errorf("ring buffer size %q overflows uint64", value)
	}
	return base * multiplier, nil
}

package trace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const traceGoldenUpdateEnv = "DAE_UPDATE_REBUILD_GOLDEN"

func TestWriteTraceGoldenFixtures(t *testing.T) {
	writeOrCheckTraceGolden(t, "../testdata/rebuild-golden/trace/ringbuf/size.json", rebuildGoldenTraceRingbuf())
	writeOrCheckTraceGolden(t, "../testdata/rebuild-golden/trace/tracker/bounded.json", rebuildGoldenTraceTracker())
	writeOrCheckTraceGolden(t, "../testdata/rebuild-golden/trace/cli/surface.json", rebuildGoldenTraceCliSurface())
}

func writeOrCheckTraceGolden(t *testing.T, path string, value any) {
	t.Helper()

	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	data = append(data, '\n')

	if os.Getenv(traceGoldenUpdateEnv) == "1" {
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
	if !traceJSONEqual(want, data) {
		t.Fatalf("%s does not match generated golden; run %s=1 go test ./trace -run TestWriteTraceGoldenFixtures", path, traceGoldenUpdateEnv)
	}
}

func traceJSONEqual(a, b []byte) bool {
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

func rebuildGoldenTraceRingbuf() any {
	cases := []map[string]any{}
	for _, tc := range []struct {
		name  string
		input string
	}{
		{"default_when_empty", ""},
		{"parse_mib_suffix", "64MiB"},
		{"parse_mb_suffix", "64mb"},
		{"parse_bytes", "67108864"},
		{"parse_kib_minimum", "4KiB"},
		{"reject_non_power_of_two", "96MiB"},
		{"reject_below_minimum", "2KiB"},
		{"reject_unaligned", "12KiB"},
		{"reject_over_uint32", "8GiB"},
		{"reject_missing_number", "MiB"},
		{"reject_invalid_text", "nope"},
	} {
		got, err := ParseRingbufSizeBytes(tc.input)
		item := map[string]any{
			"name":  tc.name,
			"input": tc.input,
			"ok":    err == nil,
		}
		if err != nil {
			item["error_contains"] = err.Error()
		} else {
			item["bytes"] = got
		}
		cases = append(cases, item)
	}
	return map[string]any{
		"name": "trace-ringbuf-size",
		"source": []string{
			"trace/ringbuf.go",
			"cmd/trace.go",
		},
		"default": map[string]any{
			"text":  DefaultRingbufSize,
			"bytes": DefaultRingbufSizeBytes(),
		},
		"min_bytes":       minRingbufSizeBytes,
		"alignment_bytes": ringbufSizeAlignment,
		"must_power2":     true,
		"max_uint32":      true,
		"cases":           cases,
	}
}

func rebuildGoldenTraceTracker() any {
	tracker := newSkbTraceTracker()
	for i := 0; i < maxEventsPerSkb+10; i++ {
		tracker.Add(traceEventRecord{Skb: 1, PayloadLen: uint16(i)}, "sym")
	}
	cappedEvents := tracker.Events(1)
	cappedSymbols := tracker.SymNames(1)

	evictionTracker := newSkbTraceTracker()
	for i := uint64(0); i < maxTrackedSkbs+1; i++ {
		evictionTracker.Add(traceEventRecord{Skb: i}, "sym")
	}
	_, oldestPresent := evictionTracker.events[0]
	_, newestPresent := evictionTracker.events[maxTrackedSkbs]

	return map[string]any{
		"name": "trace-skb-tracker-bounded",
		"source": []string{
			"trace/tracker.go",
			"trace/trace.go",
		},
		"caps": map[string]any{
			"max_tracked_skbs":    maxTrackedSkbs,
			"max_events_per_skb":  maxEventsPerSkb,
			"max_symbols_per_skb": maxSymbolsPerSkb,
		},
		"per_skb_cap": map[string]any{
			"input_events":            maxEventsPerSkb + 10,
			"retained_events":         len(cappedEvents),
			"retained_symbols":        len(cappedSymbols),
			"oldest_retained_payload": cappedEvents[0].PayloadLen,
			"newest_retained_payload": cappedEvents[len(cappedEvents)-1].PayloadLen,
			"expected_oldest_payload": 10,
			"expected_newest_payload": maxEventsPerSkb + 9,
			"slice_is_bounded":        len(cappedEvents) == maxEventsPerSkb && len(cappedSymbols) == maxSymbolsPerSkb,
		},
		"tracked_skb_eviction": map[string]any{
			"input_skbs":      maxTrackedSkbs + 1,
			"retained_skbs":   len(evictionTracker.events),
			"oldest_present":  oldestPresent,
			"newest_present":  newestPresent,
			"oldest_evicted":  !oldestPresent,
			"newest_retained": newestPresent,
		},
	}
}

func rebuildGoldenTraceCliSurface() any {
	return map[string]any{
		"name": "trace-cli-surface",
		"source": []string{
			"cmd/trace.go",
			"trace/trace.go",
			"trace/rust_aya_loader.go",
			"trace/ringbuf.go",
			"trace/tracker.go",
		},
		"feature_gated": true,
		"build_tag":     "trace",
		"use":           "trace",
		"short":         "To trace traffic",
		"defaults": map[string]any{
			"ipv4_when_unspecified": true,
			"l4_proto":              "tcp",
			"port":                  80,
			"drop_only":             false,
			"output":                "/dev/stdout",
			"ringbuf_size":          DefaultRingbufSize,
		},
		"flags": []map[string]any{
			{"name": "ipv4", "shorthand": "4", "default": false},
			{"name": "ipv6", "shorthand": "6", "default": false},
			{"name": "l4-proto", "shorthand": "p", "default": "tcp", "values": []string{"tcp", "udp"}},
			{"name": "port", "shorthand": "P", "default": 80},
			{"name": "drop-only", "shorthand": "", "default": false},
			{"name": "output", "shorthand": "o", "default": "/dev/stdout"},
			{"name": "ringbuf-size", "shorthand": "", "default": DefaultRingbufSize},
		},
		"output_fields": []string{
			"skb",
			"mark",
			"netns",
			"ifindex",
			"ifname",
			"pid",
			"pname",
			"src",
			"dst",
			"tcp_flags",
			"payload_len",
			"symbol",
			"drop_reason",
		},
		"target_discovery": map[string]any{
			"uses_kernel_btf":          true,
			"max_skb_arg_position":     5,
			"requires_attached_target": true,
		},
		"loader": map[string]any{
			"default":               "go",
			"enable_env":            "DAE_TRACE_RUST_AYA_LOADER=1",
			"helper_env":            rustTraceLoaderHelperEnv,
			"helper_default":        rustTraceLoaderHelperDefault,
			"strict_env":            "DAE_TRACE_RUST_AYA_LOADER_STRICT",
			"go_fallback_preserved": true,
			"default_daemon_path":   false,
		},
	}
}

func BenchmarkRebuildStage8TraceRingbufParse(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = ParseRingbufSizeBytes("64MiB")
	}
}

func BenchmarkRebuildStage8TraceTrackerAdd(b *testing.B) {
	tracker := newSkbTraceTracker()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tracker.Add(traceEventRecord{Skb: uint64(i % 4096)}, "sym")
	}
}

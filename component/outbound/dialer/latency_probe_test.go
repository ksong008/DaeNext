package dialer

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/sirupsen/logrus"
)

func TestRecordProbeLatencyResultUpdatesMinLastLatencySet(t *testing.T) {
	dialers := []*Dialer{
		newLazyStateTestDialer(t),
		newLazyStateTestDialer(t),
	}
	for _, d := range dialers {
		defer d.Close()
	}

	aliveSet := NewAliveDialerSet(logrus.New(), "test-group", lazyStateTestNetworkType, 0,
		consts.DialerSelectionPolicy_MinLastLatency,
		dialers, lazyStateAnnotations(dialers), func(bool) {}, true)
	for _, d := range dialers {
		d.RegisterAliveDialerSet(aliveSet)
	}

	opt := &CheckOption{networkType: lazyStateTestNetworkType}
	dialers[0].recordProbeLatencyResult(opt, true, 200*time.Millisecond, nil)
	checkedAt := dialers[1].recordProbeLatencyResult(opt, true, 40*time.Millisecond, nil)

	got, latency := aliveSet.GetMinLatency()
	if got != dialers[1] {
		t.Fatalf("expected manual probe result to select second dialer, got %p", got)
	}
	if latency != 40*time.Millisecond {
		t.Fatalf("latency = %v, want 40ms", latency)
	}
	_, _, snapshotCheckedAt, ok := dialers[1].LastLatencySnapshot(lazyStateTestNetworkType)
	if !ok {
		t.Fatal("expected latency snapshot after manual probe")
	}
	if !snapshotCheckedAt.Equal(checkedAt) {
		t.Fatalf("checkedAt = %v, want %v", snapshotCheckedAt, checkedAt)
	}
}

func TestRecordProbeLatencyResultUpdatesMinMovingAverageSet(t *testing.T) {
	dialers := []*Dialer{
		newLazyStateTestDialer(t),
		newLazyStateTestDialer(t),
	}
	for _, d := range dialers {
		defer d.Close()
	}

	aliveSet := NewAliveDialerSet(logrus.New(), "test-group", lazyStateTestNetworkType, 0,
		consts.DialerSelectionPolicy_MinMovingAverageLatencies,
		dialers, lazyStateAnnotations(dialers), func(bool) {}, true)
	for _, d := range dialers {
		d.RegisterAliveDialerSet(aliveSet)
	}

	opt := &CheckOption{networkType: lazyStateTestNetworkType}
	dialers[0].recordProbeLatencyResult(opt, true, 300*time.Millisecond, nil)
	dialers[1].recordProbeLatencyResult(opt, true, 80*time.Millisecond, nil)

	got, latency := aliveSet.GetMinLatency()
	if got != dialers[1] {
		t.Fatalf("expected manual probe result to select second dialer, got %p", got)
	}
	if latency != 40*time.Millisecond {
		t.Fatalf("moving average latency = %v, want 40ms", latency)
	}
}

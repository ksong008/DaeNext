package dialer

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/sirupsen/logrus"
)

var lazyStateTestNetworkType = &NetworkType{
	L4Proto:   consts.L4ProtoStr_TCP,
	IpVersion: consts.IpVersionStr_4,
	IsDns:     false,
}

func newLazyStateTestDialer(t *testing.T) *Dialer {
	t.Helper()
	return NewDialer(&stubDialer{}, &GlobalOption{Log: logrus.New()}, InstanceOption{}, &Property{
		Property: D.Property{
			Name: "test",
			Link: "test-link",
		},
		Link: "test-link",
	})
}

func lazyStateAnnotations(dialers []*Dialer) []*Annotation {
	annotations := make([]*Annotation, len(dialers))
	for i := range annotations {
		annotations[i] = &Annotation{}
	}
	return annotations
}

func TestNewDialerLazilyAllocatesHealthState(t *testing.T) {
	d := newLazyStateTestDialer(t)
	defer d.Close()

	if d.probeHTTPClient != nil || d.probeHTTPTransport != nil {
		t.Fatal("expected probe HTTP client and transport to be created lazily")
	}
	for i, collection := range d.collections {
		if collection != nil {
			t.Fatalf("expected collection[%d] to be created lazily", i)
		}
	}
	if d.HasAliveDialerSets() {
		t.Fatal("new dialer should not have registered alive dialer sets")
	}

	if latency, alive, ok := d.LastLatencySnapshot(lazyStateTestNetworkType); ok || latency != 0 || !alive {
		t.Fatalf("unexpected empty latency snapshot: latency=%v alive=%v ok=%v", latency, alive, ok)
	}
	if d.collections[collectionIndex(lazyStateTestNetworkType)] != nil {
		t.Fatal("LastLatencySnapshot should not allocate a collection")
	}

	if !d.MustGetAlive(lazyStateTestNetworkType) {
		t.Fatal("missing collection should preserve the default alive=true view")
	}
	if d.collections[collectionIndex(lazyStateTestNetworkType)] != nil {
		t.Fatal("MustGetAlive should not allocate a collection")
	}

	if d.MustGetLatencies10(lazyStateTestNetworkType) == nil {
		t.Fatal("MustGetLatencies10 should return a latency ring")
	}
	if d.collections[collectionIndex(lazyStateTestNetworkType)] == nil {
		t.Fatal("MustGetLatencies10 should create the target collection")
	}

	client := d.getProbeHTTPClient()
	if client == nil || d.probeHTTPClient == nil || d.probeHTTPTransport == nil {
		t.Fatal("expected probe HTTP client and transport after first use")
	}
	if got := d.getProbeHTTPClient(); got != client {
		t.Fatal("expected probe HTTP client to be reused")
	}
}

func TestRegisterAliveDialerSetCreatesOnlyRegisteredCollection(t *testing.T) {
	d := newLazyStateTestDialer(t)
	defer d.Close()

	aliveSet := &AliveDialerSet{CheckTyp: lazyStateTestNetworkType}
	d.RegisterAliveDialerSet(aliveSet)

	targetIndex := collectionIndex(lazyStateTestNetworkType)
	for i, collection := range d.collections {
		if i == targetIndex {
			if collection == nil {
				t.Fatalf("expected collection[%d] to be allocated", i)
			}
			continue
		}
		if collection != nil {
			t.Fatalf("expected unrelated collection[%d] to remain nil", i)
		}
	}
	if !d.HasAliveDialerSets() {
		t.Fatal("registered alive set should be visible")
	}

	d.UnregisterAliveDialerSet(aliveSet)
	if d.HasAliveDialerSets() {
		t.Fatal("unregistered alive set should not remain visible")
	}
}

func TestAliveDialerSetMinAverage10UsesLatencyRing(t *testing.T) {
	dialers := []*Dialer{
		newLazyStateTestDialer(t),
		newLazyStateTestDialer(t),
	}
	for _, d := range dialers {
		defer d.Close()
	}

	aliveSet := NewAliveDialerSet(logrus.New(), "test-group", lazyStateTestNetworkType, 0,
		consts.DialerSelectionPolicy_MinAverage10Latencies,
		dialers, lazyStateAnnotations(dialers), func(bool) {}, true)

	for _, latency := range []time.Duration{300 * time.Millisecond, 300 * time.Millisecond, 300 * time.Millisecond} {
		dialers[0].MustGetLatencies10(lazyStateTestNetworkType).AppendLatency(latency)
	}
	for _, latency := range []time.Duration{100 * time.Millisecond, 100 * time.Millisecond, 100 * time.Millisecond} {
		dialers[1].MustGetLatencies10(lazyStateTestNetworkType).AppendLatency(latency)
	}
	aliveSet.NotifyLatencyChange(dialers[0], true)
	aliveSet.NotifyLatencyChange(dialers[1], true)

	got, latency := aliveSet.GetMinLatency()
	if got != dialers[1] {
		t.Fatalf("expected second dialer to have minimum avg10 latency, got %p", got)
	}
	if latency != 100*time.Millisecond {
		t.Fatalf("expected 100ms avg10 latency, got %v", latency)
	}
}

func TestAliveDialerSetMinMovingAverageUsesMovingAverage(t *testing.T) {
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

	setMovingAverage(t, dialers[0], 400*time.Millisecond)
	setMovingAverage(t, dialers[1], 120*time.Millisecond)
	aliveSet.NotifyLatencyChange(dialers[0], true)
	aliveSet.NotifyLatencyChange(dialers[1], true)

	got, latency := aliveSet.GetMinLatency()
	if got != dialers[1] {
		t.Fatalf("expected second dialer to have minimum moving average latency, got %p", got)
	}
	if latency != 120*time.Millisecond {
		t.Fatalf("expected 120ms moving average latency, got %v", latency)
	}

	setMovingAverage(t, dialers[1], 800*time.Millisecond)
	aliveSet.NotifyLatencyChange(dialers[1], true)

	got, latency = aliveSet.GetMinLatency()
	if got != dialers[0] {
		t.Fatalf("expected first dialer after current best worsens, got %p", got)
	}
	if latency != 400*time.Millisecond {
		t.Fatalf("expected 400ms moving average latency, got %v", latency)
	}
}

func setMovingAverage(t *testing.T, d *Dialer, latency time.Duration) {
	t.Helper()
	collection := d.mustGetCollection(lazyStateTestNetworkType)
	collection.mu.Lock()
	collection.MovingAverage = latency
	collection.mu.Unlock()
}

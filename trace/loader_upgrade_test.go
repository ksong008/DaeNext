package trace

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestRewriteAndLoadBpf(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock: %v", err)
	}
	objs, err := rewriteAndLoadBpf(4, 6, 80, DefaultRingbufSizeBytes())
	if err != nil {
		t.Fatalf("rewriteAndLoadBpf: %v", err)
	}
	defer objs.Close()

	if objs.Events == nil {
		t.Fatal("expected events map to be loaded")
	}
	if objs.Events.Type() != ebpf.RingBuf {
		t.Fatalf("events map type = %v, want %v", objs.Events.Type(), ebpf.RingBuf)
	}
}

package trace

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestRewriteAndLoadBpf(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("skipping loader test: RemoveMemlock failed: %v", err)
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

func TestRustTraceAyaLoaderEnabledIsExplicitOptIn(t *testing.T) {
	old, ok := os.LookupEnv("DAE_TRACE_RUST_AYA_LOADER")
	os.Unsetenv("DAE_TRACE_RUST_AYA_LOADER")
	t.Cleanup(func() {
		if ok {
			os.Setenv("DAE_TRACE_RUST_AYA_LOADER", old)
		} else {
			os.Unsetenv("DAE_TRACE_RUST_AYA_LOADER")
		}
	})

	if rustTraceAyaLoaderEnabled() {
		t.Fatal("Rust/Aya trace loader must be disabled by default while CO-RE side-load is closed")
	}
	for _, value := range []string{"1", "true", "on", "yes", " TRUE "} {
		os.Setenv("DAE_TRACE_RUST_AYA_LOADER", value)
		if !rustTraceAyaLoaderEnabled() {
			t.Fatalf("Rust/Aya trace loader should be enabled for explicit opt-in %q", value)
		}
	}
	for _, value := range []string{"", "0", "false", "off", "no", "unexpected"} {
		os.Setenv("DAE_TRACE_RUST_AYA_LOADER", value)
		if rustTraceAyaLoaderEnabled() {
			t.Fatalf("Rust/Aya trace loader should stay disabled for %q", value)
		}
	}
}

package control

import (
	"testing"

	"github.com/vishvananda/netlink"
)

func TestParseTcAttachBackend(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want tcAttachBackend
	}{
		{name: "empty", raw: "", want: tcAttachBackendAuto},
		{name: "auto", raw: " AUTO ", want: tcAttachBackendAuto},
		{name: "tcx", raw: "tcx", want: tcAttachBackendTcx},
		{name: "tc", raw: "tc", want: tcAttachBackendTc},
		{name: "tc netlink", raw: "tc-netlink", want: tcAttachBackendTc},
		{name: "tc netlink underscore", raw: "tc_netlink", want: tcAttachBackendTc},
		{name: "tc command fallback", raw: "tc-command-fallback", want: tcAttachBackendTc},
		{name: "invalid", raw: "invalid", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseTcAttachBackend(tt.raw); got != tt.want {
				t.Fatalf("parseTcAttachBackend(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestCurrentTcAttachBackendDefaultsToAuto(t *testing.T) {
	t.Setenv("DAE_RUST_NATIVE_EBPF", "")
	t.Setenv("DAE_RUST_NATIVE_EBPF_BACKEND", "")
	t.Setenv("DAE_NATIVE_EBPF_BACKEND", "")
	if got := currentTcAttachBackend(); got != tcAttachBackendAuto {
		t.Fatalf("currentTcAttachBackend() = %q, want %q", got, tcAttachBackendAuto)
	}
}

func TestCurrentTcAttachBackendCanDisableNativeAttach(t *testing.T) {
	t.Setenv("DAE_RUST_NATIVE_EBPF", "0")
	t.Setenv("DAE_RUST_NATIVE_EBPF_BACKEND", "tcx")
	if got := currentTcAttachBackend(); got != tcAttachBackendTc {
		t.Fatalf("currentTcAttachBackend() = %q, want %q", got, tcAttachBackendTc)
	}
}

func TestTcxAnchorForPriorityMatchesTcOrdering(t *testing.T) {
	if got := tcxAnchorForPriority(1); got == nil {
		t.Fatalf("priority 1 should return a cilium link anchor")
	}
	if got := tcxAnchorForPriority(2); got == nil {
		t.Fatalf("priority 2 should return a cilium link anchor")
	}
}

func TestSummarizeTcAttachBackendsNeverReportsAuto(t *testing.T) {
	tests := []struct {
		name     string
		backends []tcAttachBackend
		want     string
	}{
		{name: "empty defaults to tc", want: "tc"},
		{name: "tc only", backends: []tcAttachBackend{tcAttachBackendTc}, want: "tc"},
		{name: "tcx only", backends: []tcAttachBackend{tcAttachBackendTcx}, want: "tcx"},
		{name: "mixed", backends: []tcAttachBackend{tcAttachBackendTcx, tcAttachBackendTc}, want: "tcx+tc"},
		{name: "auto ignored", backends: []tcAttachBackend{tcAttachBackendAuto}, want: "tc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := summarizeTcAttachBackends(tt.backends); got != tt.want {
				t.Fatalf("summarizeTcAttachBackends(%v) = %q, want %q", tt.backends, got, tt.want)
			}
		})
	}
}

func TestSameBpfFilterIdentityMatchesHandleOrName(t *testing.T) {
	want := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{Handle: 0x20230001},
		Name:        "daed_lan_ingress_l2",
	}
	if !sameBpfFilterIdentity(want, &netlink.BpfFilter{FilterAttrs: netlink.FilterAttrs{Handle: want.Handle}}) {
		t.Fatal("sameBpfFilterIdentity should match handle")
	}
	if !sameBpfFilterIdentity(&netlink.BpfFilter{Name: want.Name}, &netlink.BpfFilter{Name: want.Name}) {
		t.Fatal("sameBpfFilterIdentity should match name")
	}
	if sameBpfFilterIdentity(want, &netlink.BpfFilter{FilterAttrs: netlink.FilterAttrs{Handle: 0x20230002}, Name: "other"}) {
		t.Fatal("sameBpfFilterIdentity should reject unrelated filters")
	}
}

func TestRustTcAttachHelpersDeriveProgramAndBackend(t *testing.T) {
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{Parent: netlink.HANDLE_MIN_INGRESS},
		Name:        "dae_lan_ingress_l2",
	}
	programName, err := rustTcProgramNameForFilter(filter)
	if err != nil {
		t.Fatalf("rustTcProgramNameForFilter() error = %v", err)
	}
	if programName != "tproxy_lan_ingress_l2" {
		t.Fatalf("programName = %q", programName)
	}
	direction, err := rustTcDirectionForFilter(filter)
	if err != nil {
		t.Fatalf("rustTcDirectionForFilter() error = %v", err)
	}
	if direction != "ingress" {
		t.Fatalf("direction = %q", direction)
	}
	if got := rustTcAttachBackendArg(tcAttachBackendAuto); got != "auto" {
		t.Fatalf("auto backend arg = %q", got)
	}
	if got := rustTcAttachBackendArg(tcAttachBackendTc); got != "tc_netlink" {
		t.Fatalf("tc backend arg = %q", got)
	}
	if got, err := rustTcAttachBackendFromReport("tc_netlink"); err != nil || got != tcAttachBackendTc {
		t.Fatalf("rustTcAttachBackendFromReport(tc_netlink) = %q, %v", got, err)
	}
}

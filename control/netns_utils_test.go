package control

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netns"
)

func TestNewDaeNetnsInitializesClosedHandles(t *testing.T) {
	ns := NewDaeNetns(nil)
	if ns.hostNs != netns.None() {
		t.Fatalf("hostNs = %v, want closed handle", ns.hostNs)
	}
	if ns.daeNs != netns.None() {
		t.Fatalf("daeNs = %v, want closed handle", ns.daeNs)
	}
}

func TestParseNetnsLinkMode(t *testing.T) {
	tests := []struct {
		raw  string
		want netnsLinkMode
		ok   bool
	}{
		{"", netnsLinkModeAuto, true},
		{"AUTO", netnsLinkModeAuto, true},
		{" netkit ", netnsLinkModeNetkit, true},
		{"veth", netnsLinkModeVeth, true},
		{"bad", "", false},
	}
	for _, tt := range tests {
		got, err := parseNetnsLinkMode(tt.raw)
		if tt.ok && err != nil {
			t.Fatalf("parseNetnsLinkMode(%q) returned error: %v", tt.raw, err)
		}
		if !tt.ok && err == nil {
			t.Fatalf("parseNetnsLinkMode(%q) expected error", tt.raw)
		}
		if got != tt.want {
			t.Fatalf("parseNetnsLinkMode(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

func TestSetupLinkPairAndNetnsWithAutoUsesNetkitWhenAvailable(t *testing.T) {
	ns := NewDaeNetns(nil)
	var calls []string
	err := ns.setupLinkPairAndNetnsWith(
		netnsLinkModeAuto,
		func() error { calls = append(calls, "probe"); return nil },
		func() error { calls = append(calls, "netkit"); return nil },
		func() error { calls = append(calls, "veth"); return nil },
		func() { calls = append(calls, "cleanup") },
	)
	if err != nil {
		t.Fatalf("setupLinkPairAndNetnsWith(auto) returned error: %v", err)
	}
	if ns.linkMode != netnsLinkModeNetkit {
		t.Fatalf("linkMode = %q, want %q", ns.linkMode, netnsLinkModeNetkit)
	}
	if got := strings.Join(calls, ","); got != "probe,netkit" {
		t.Fatalf("calls = %s", got)
	}
}

func TestSetupLinkPairAndNetnsWithAutoFallsBackToVeth(t *testing.T) {
	ns := NewDaeNetns(nil)
	netkitErr := errors.New("netkit setup failed")
	var calls []string
	err := ns.setupLinkPairAndNetnsWith(
		netnsLinkModeAuto,
		func() error { calls = append(calls, "probe"); return nil },
		func() error { calls = append(calls, "netkit"); return netkitErr },
		func() error { calls = append(calls, "veth"); return nil },
		func() { calls = append(calls, "cleanup") },
	)
	if err != nil {
		t.Fatalf("setupLinkPairAndNetnsWith(auto) returned error: %v", err)
	}
	if ns.linkMode != netnsLinkModeVeth {
		t.Fatalf("linkMode = %q, want %q", ns.linkMode, netnsLinkModeVeth)
	}
	if got := strings.Join(calls, ","); got != "probe,netkit,cleanup,veth" {
		t.Fatalf("calls = %s", got)
	}
}

func TestSetupLinkPairAndNetnsWithForcedNetkitDoesNotFallback(t *testing.T) {
	ns := NewDaeNetns(nil)
	probeErr := errors.New("netkit unavailable")
	var calls []string
	err := ns.setupLinkPairAndNetnsWith(
		netnsLinkModeNetkit,
		func() error { calls = append(calls, "probe"); return probeErr },
		func() error { calls = append(calls, "netkit"); return nil },
		func() error { calls = append(calls, "veth"); return nil },
		func() { calls = append(calls, "cleanup") },
	)
	if !errors.Is(err, probeErr) {
		t.Fatalf("error = %v, want probe error", err)
	}
	if ns.linkMode != "" {
		t.Fatalf("linkMode = %q, want empty after failed forced netkit", ns.linkMode)
	}
	if got := strings.Join(calls, ","); got != "probe" {
		t.Fatalf("calls = %s", got)
	}
}

func TestDaeNetnsSetupRealLinkModes(t *testing.T) {
	if os.Getenv("DAE_TEST_NETNS_SETUP") != "1" {
		t.Skip("set DAE_TEST_NETNS_SETUP=1 to run real netns setup validation")
	}
	if os.Geteuid() != 0 {
		t.Skip("real netns setup validation requires root")
	}

	previousSysctl := sysctl
	manager, err := NewSysctlManager(logrus.New())
	if err != nil {
		t.Fatalf("NewSysctlManager(): %v", err)
	}
	sysctl = manager
	t.Cleanup(func() {
		_ = manager.Close()
		sysctl = previousSysctl
	})

	oldEnv, hadEnv := os.LookupEnv(netnsLinkEnv)
	t.Cleanup(func() {
		if hadEnv {
			_ = os.Setenv(netnsLinkEnv, oldEnv)
		} else {
			_ = os.Unsetenv(netnsLinkEnv)
		}
	})

	tests := []struct {
		name     string
		env      string
		wantMode netnsLinkMode
	}{
		{name: "forced-veth", env: string(netnsLinkModeVeth), wantMode: netnsLinkModeVeth},
		{name: "forced-netkit", env: string(netnsLinkModeNetkit), wantMode: netnsLinkModeNetkit},
		{name: "auto", env: string(netnsLinkModeAuto), wantMode: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = os.Setenv(netnsLinkEnv, tt.env)
			ns := NewDaeNetns(logrus.New())
			if err := ns.Setup(); err != nil {
				t.Fatalf("Setup(%s) returned error: %v", tt.env, err)
			}
			defer func() {
				if err := ns.Close(); err != nil {
					t.Fatalf("Close(%s): %v", tt.env, err)
				}
			}()
			gotMode := netnsLinkMode(ns.LinkMode())
			if tt.wantMode != "" && gotMode != tt.wantMode {
				t.Fatalf("LinkMode() = %q, want %q", gotMode, tt.wantMode)
			}
			if gotMode != netnsLinkModeVeth && gotMode != netnsLinkModeNetkit {
				t.Fatalf("LinkMode() = %q, want veth or netkit", gotMode)
			}
			if ns.Dae0() == nil || ns.Dae0Peer() == nil {
				t.Fatalf("expected dae0 and dae0peer to be initialized")
			}
			if ns.Dae0().Type() != string(gotMode) {
				t.Fatalf("dae0 type = %q, want %q", ns.Dae0().Type(), gotMode)
			}
			if ns.Dae0Peer().Type() != string(gotMode) {
				t.Fatalf("dae0peer type = %q, want %q", ns.Dae0Peer().Type(), gotMode)
			}
		})
	}
}

func TestDaeNetnsSetupRealFallbackToVethAfterNetkitProbeFailure(t *testing.T) {
	if os.Getenv("DAE_TEST_NETNS_SETUP") != "1" {
		t.Skip("set DAE_TEST_NETNS_SETUP=1 to run real netns setup validation")
	}
	if os.Geteuid() != 0 {
		t.Skip("real netns setup validation requires root")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ns := NewDaeNetns(logrus.New())
	hostNs, err := netns.Get()
	if err != nil {
		t.Fatalf("netns.Get(): %v", err)
	}
	ns.hostNs = hostNs
	t.Cleanup(func() {
		_ = netns.Set(hostNs)
		if err := ns.Close(); err != nil {
			t.Fatalf("Close(): %v", err)
		}
	})

	probeErr := errors.New("simulated netkit probe failure")
	err = ns.setupLinkPairAndNetnsWith(
		netnsLinkModeAuto,
		func() error { return probeErr },
		func() error { t.Fatal("netkit setup should not run after probe failure"); return nil },
		ns.setupVethAndNetns,
		ns.cleanupFailedLinkSetup,
	)
	if err != nil {
		t.Fatalf("setupLinkPairAndNetnsWith(auto fallback) returned error: %v", err)
	}
	if ns.LinkMode() != string(netnsLinkModeVeth) {
		t.Fatalf("LinkMode() = %q, want %q", ns.LinkMode(), netnsLinkModeVeth)
	}
	if ns.Dae0() == nil || ns.Dae0Peer() == nil {
		t.Fatal("expected dae0 and dae0peer to be initialized")
	}
	if ns.Dae0().Type() != string(netnsLinkModeVeth) {
		t.Fatalf("dae0 type = %q, want veth", ns.Dae0().Type())
	}
	if ns.Dae0Peer().Type() != string(netnsLinkModeVeth) {
		t.Fatalf("dae0peer type = %q, want veth", ns.Dae0Peer().Type())
	}
}

func TestDaeNetnsCloseCollectsErrorsAndResetsHandles(t *testing.T) {
	hostFile, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open host handle: %v", err)
	}
	daeFile, err := os.Open(os.DevNull)
	if err != nil {
		_ = hostFile.Close()
		t.Fatalf("open dae handle: %v", err)
	}

	ns := NewDaeNetns(nil)
	ns.hostNs = netns.NsHandle(hostFile.Fd())
	ns.daeNs = netns.NsHandle(daeFile.Fd())
	ns.setupDone.Store(true)

	deleteNetnsErr := errors.New("delete netns failed")
	deleteLinkErr := errors.New("delete link failed")
	err = ns.closeWith(
		func(name string) error {
			if name != NsName {
				t.Fatalf("delete netns name = %q, want %q", name, NsName)
			}
			return deleteNetnsErr
		},
		func(name string) error {
			if name != HostVethName {
				t.Fatalf("delete link name = %q, want %q", name, HostVethName)
			}
			return deleteLinkErr
		},
	)
	if !errors.Is(err, deleteNetnsErr) {
		t.Fatalf("Close error %v does not include netns delete error", err)
	}
	if !errors.Is(err, deleteLinkErr) {
		t.Fatalf("Close error %v does not include link delete error", err)
	}
	if ns.hostNs != netns.None() {
		t.Fatalf("hostNs = %v, want closed handle", ns.hostNs)
	}
	if ns.daeNs != netns.None() {
		t.Fatalf("daeNs = %v, want closed handle", ns.daeNs)
	}
	if ns.setupDone.Load() {
		t.Fatal("setupDone = true, want false after close")
	}
	if _, err := hostFile.Stat(); err == nil {
		t.Fatal("host handle fd is still open")
	}
	if _, err := daeFile.Stat(); err == nil {
		t.Fatal("dae handle fd is still open")
	}
}

func TestCloseNsHandleIgnoresUnsetHandles(t *testing.T) {
	handle := netns.None()
	if err := closeNsHandle("unset", &handle); err != nil {
		t.Fatalf("close unset handle: %v", err)
	}
	if handle != netns.None() {
		t.Fatalf("handle = %v, want closed handle", handle)
	}

	zero := netns.NsHandle(0)
	if err := closeNsHandle("zero", &zero); err != nil {
		t.Fatalf("close zero handle: %v", err)
	}
	if zero != netns.None() {
		t.Fatalf("zero handle = %v, want closed handle", zero)
	}
}

func TestDeleteMissingNetnsAndLinkAreNoop(t *testing.T) {
	if err := DeleteNamedNetns("dae-missing-test-netns"); err != nil {
		t.Fatalf("DeleteNamedNetns missing: %v", err)
	}
	if err := DeleteLink("daemiss0"); err != nil {
		t.Fatalf("DeleteLink missing: %v", err)
	}
}

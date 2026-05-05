package control

import (
	"errors"
	"os"
	"testing"

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

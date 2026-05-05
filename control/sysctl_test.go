/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestSysctlKeySetWithoutManagerReturnsError(t *testing.T) {
	previous := sysctl
	sysctl = nil
	t.Cleanup(func() { sysctl = previous })

	err := SysctlKey("/tmp/dae-missing-sysctl").Set("1", false)
	if err == nil {
		t.Fatal("expected uninitialized sysctl manager error")
	}
	if !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("error = %v, want not initialized", err)
	}
}

func TestSysctlManagerSetRollsBackWatchOnWriteError(t *testing.T) {
	manager, err := NewSysctlManager(logrus.New())
	if err != nil {
		t.Fatalf("NewSysctlManager() error: %v", err)
	}
	defer manager.Close()

	path := t.TempDir()
	err = manager.set(path, "1", true)
	if err == nil {
		t.Fatal("expected writing to a directory to fail")
	}
	manager.mux.Lock()
	_, ok := manager.expectations[path]
	manager.mux.Unlock()
	if ok {
		t.Fatal("expected failed watched set to roll back expectation")
	}
}

func TestInitSysctlManagerClosesPreviousManager(t *testing.T) {
	previousGlobal := sysctl
	t.Cleanup(func() { sysctl = previousGlobal })

	previous, err := NewSysctlManager(logrus.New())
	if err != nil {
		t.Fatalf("NewSysctlManager() previous error: %v", err)
	}
	sysctl = previous

	if err := InitSysctlManager(logrus.New()); err != nil {
		t.Fatalf("InitSysctlManager() error: %v", err)
	}
	t.Cleanup(func() {
		if sysctl != nil && sysctl != previousGlobal {
			_ = sysctl.Close()
		}
	})

	select {
	case <-previous.done:
	default:
		t.Fatal("expected previous sysctl manager watcher to be closed")
	}
}

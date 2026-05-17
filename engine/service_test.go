/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package engine

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestNativeServiceDryRunLifecycle(t *testing.T) {
	svc := NewNativeService(Options{})
	log := logrus.New()
	log.SetOutput(io.Discard)

	done := make(chan error, 1)
	go func() {
		done <- svc.Run(log, svc.EmptyConfig(), nil, true, true)
	}()
	waitNativeServiceRunning(t, svc)

	if err := svc.Reload(svc.EmptyConfig()); err != nil {
		t.Fatalf("Reload() in dry mode error = %v", err)
	}

	overview, err := svc.GetRuntimeOverview(60, 16)
	if err != nil {
		t.Fatalf("GetRuntimeOverview() error = %v", err)
	}
	if overview == nil {
		t.Fatal("GetRuntimeOverview() returned nil")
	}
	if transport, ok := svc.TryHTTPTransport(); ok || transport != nil {
		t.Fatalf("TryHTTPTransport() = (%T, %v), want unavailable without control plane", transport, ok)
	}

	if err := svc.Stop(2 * time.Second); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() returned error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for dry runtime to exit")
	}

	if err := svc.Reload(svc.EmptyConfig()); err != nil {
		t.Fatalf("Reload() after stop should restart dry runtime, got %v", err)
	}
	if err := svc.Stop(2 * time.Second); err != nil {
		t.Fatalf("Stop() restarted dry runtime error = %v", err)
	}
}

func TestNativeServiceReloadWithContextCanceledBeforeStart(t *testing.T) {
	svc := NewNativeService(Options{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := svc.ReloadWithContext(ctx, svc.EmptyConfig())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ReloadWithContext() error = %v, want context canceled", err)
	}
	if _, running := svc.CurrentRuntime(); running {
		t.Fatal("runtime should not start after canceled reload context")
	}
}

func TestNativeServiceNotInitializedAccessors(t *testing.T) {
	svc := NewNativeService(Options{})

	if _, err := svc.ControlPlane(); !errors.Is(err, ErrControlPlaneNotInit) {
		t.Fatalf("ControlPlane() error = %v, want ErrControlPlaneNotInit", err)
	}
	if got := svc.NetnsLinkMode(); got != "" {
		t.Fatalf("NetnsLinkMode() = %q, want empty", got)
	}
	if got := svc.CacheStats(); got != (CacheStats{}) {
		t.Fatalf("CacheStats() = %+v, want zero", got)
	}
	if got := svc.SnapshotNodeLatencies(); got != nil {
		t.Fatalf("SnapshotNodeLatencies() = %+v, want nil", got)
	}
	if _, ok := svc.TryHTTPTransport(); ok {
		t.Fatal("TryHTTPTransport() should be unavailable without a control plane")
	}

	_, err := svc.HTTPTransport().RoundTrip(&http.Request{})
	if !errors.Is(err, ErrControlPlaneNotInit) {
		t.Fatalf("HTTPTransport().RoundTrip() error = %v, want ErrControlPlaneNotInit", err)
	}
}

func TestNativeServiceSetLogLevelUpdatesCurrentLogger(t *testing.T) {
	originalLevel := logrus.GetLevel()
	t.Cleanup(func() {
		logrus.SetLevel(originalLevel)
	})

	svc := NewNativeService(Options{})
	log := logrus.New()
	log.SetOutput(io.Discard)
	done := make(chan error, 1)
	go func() {
		done <- svc.Run(log, svc.EmptyConfig(), nil, true, true)
	}()
	waitNativeServiceRunning(t, svc)

	svc.SetLogLevel(logrus.DebugLevel)
	if got := log.GetLevel(); got != logrus.DebugLevel {
		t.Fatalf("runtime logger level = %v, want debug", got)
	}
	if got := logrus.GetLevel(); got != logrus.DebugLevel {
		t.Fatalf("standard logger level = %v, want debug", got)
	}

	if err := svc.Stop(2 * time.Second); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() returned error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for dry runtime to exit")
	}
}

func waitNativeServiceRunning(t *testing.T, svc *NativeService) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for native service to run")
		case <-ticker.C:
			if _, running := svc.CurrentRuntime(); running {
				return
			}
		}
	}
}

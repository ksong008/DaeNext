/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package trace

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
)

const (
	rustTraceLoaderHelperEnv     = "DAE_RUST_BPF_LOADER_HELPER"
	rustTraceLoaderHelperDefault = "dae-aya-bpf-loader"
	rustTraceLoaderTimeout       = 90 * time.Second
)

func rewriteAndLoadBpf(ipVersion int, l4ProtoNo uint16, port int, ringbufSizeBytes uint32) (_ *bpfObjects, err error) {
	if rustTraceAyaLoaderEnabled() {
		objs, err := rewriteAndLoadBpfViaRustAya(ipVersion, l4ProtoNo, port, ringbufSizeBytes)
		if err == nil {
			return objs, nil
		}
		if rustTraceAyaLoaderStrict() {
			return nil, err
		}
		logrus.Warnf("Rust/Aya trace loader unavailable, falling back to Go trace loader: %v", err)
	}
	return rewriteAndLoadBpfViaGo(ipVersion, l4ProtoNo, port, ringbufSizeBytes)
}

func rewriteAndLoadBpfViaRustAya(ipVersion int, l4ProtoNo uint16, port int, ringbufSizeBytes uint32) (_ *bpfObjects, err error) {
	if ringbufSizeBytes == 0 {
		ringbufSizeBytes = DefaultRingbufSizeBytes()
	}
	workDir, err := os.MkdirTemp("", "dae-trace-rust-aya-*")
	if err != nil {
		return nil, err
	}
	defer func() {
		if cleanupErr := os.RemoveAll(workDir); cleanupErr != nil && err == nil {
			err = cleanupErr
		}
	}()

	objectPath := filepath.Join(workDir, "trace_bpf.o")
	if err := os.WriteFile(objectPath, _BpfBytes, 0600); err != nil {
		return nil, fmt.Errorf("write trace object for Rust/Aya loader: %w", err)
	}
	pinRoot := rustTraceAyaTempPinRoot()
	defer func() {
		if cleanupErr := os.RemoveAll(pinRoot); cleanupErr != nil && err == nil {
			err = cleanupErr
		}
	}()
	out, err := runRustTraceLoaderHelperOutput(
		"trace-loader", "load-pin",
		"--object", objectPath,
		"--pin-root", pinRoot,
		"--ip-version", strconv.Itoa(ipVersion),
		"--l4-proto", strconv.Itoa(int(l4ProtoNo)),
		"--port", strconv.Itoa(port),
		"--ringbuf-size", strconv.FormatUint(uint64(ringbufSizeBytes), 10),
	)
	if err != nil {
		return nil, err
	}
	var decoded struct {
		Status               string `json:"status"`
		GoTraceAdoptionReady bool   `json:"go_trace_adoption_ready"`
	}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		return nil, fmt.Errorf("decode Rust/Aya trace loader output: %w", err)
	}
	if decoded.Status != "pass" || !decoded.GoTraceAdoptionReady {
		return nil, fmt.Errorf("Rust/Aya trace loader did not report adoption-ready status")
	}
	return adoptRustAyaTracePinnedBpfObjects(pinRoot)
}

func rustTraceAyaTempPinRoot() string {
	return filepath.Join(
		"/sys/fs/bpf",
		fmt.Sprintf("dae_trace_loader_%d_%d", os.Getpid(), time.Now().UnixNano()),
	)
}

func adoptRustAyaTracePinnedBpfObjects(pinRoot string) (*bpfObjects, error) {
	var objs bpfObjects
	loadMap := func(name string) (*ebpf.Map, error) {
		return ebpf.LoadPinnedMap(filepath.Join(pinRoot, "maps", name), nil)
	}
	loadProgram := func(name string) (*ebpf.Program, error) {
		return ebpf.LoadPinnedProgram(filepath.Join(pinRoot, "programs", name), nil)
	}
	var err error
	if objs.Events, err = loadMap("events"); err != nil {
		return nil, closeTraceObjectsWithErr(&objs, err)
	}
	if objs.SkbAddresses, err = loadMap("skb_addresses"); err != nil {
		return nil, closeTraceObjectsWithErr(&objs, err)
	}
	if objs.KprobeSkb1, err = loadProgram("kprobe_skb_1"); err != nil {
		return nil, closeTraceObjectsWithErr(&objs, err)
	}
	if objs.KprobeSkb2, err = loadProgram("kprobe_skb_2"); err != nil {
		return nil, closeTraceObjectsWithErr(&objs, err)
	}
	if objs.KprobeSkb3, err = loadProgram("kprobe_skb_3"); err != nil {
		return nil, closeTraceObjectsWithErr(&objs, err)
	}
	if objs.KprobeSkb4, err = loadProgram("kprobe_skb_4"); err != nil {
		return nil, closeTraceObjectsWithErr(&objs, err)
	}
	if objs.KprobeSkb5, err = loadProgram("kprobe_skb_5"); err != nil {
		return nil, closeTraceObjectsWithErr(&objs, err)
	}
	if objs.KprobeSkbLifetimeTermination, err = loadProgram("kprobe_skb_lifetime_termination"); err != nil {
		return nil, closeTraceObjectsWithErr(&objs, err)
	}
	return &objs, nil
}

func closeTraceObjectsWithErr(objs *bpfObjects, err error) error {
	closeTraceObjects(objs)
	return err
}

func closeTraceObjects(objs *bpfObjects) {
	if objs == nil {
		return
	}
	closeMap := func(m *ebpf.Map) {
		if m != nil {
			_ = m.Close()
		}
	}
	closeProgram := func(p *ebpf.Program) {
		if p != nil {
			_ = p.Close()
		}
	}
	closeMap(objs.Events)
	closeMap(objs.SkbAddresses)
	closeProgram(objs.KprobeSkb1)
	closeProgram(objs.KprobeSkb2)
	closeProgram(objs.KprobeSkb3)
	closeProgram(objs.KprobeSkb4)
	closeProgram(objs.KprobeSkb5)
	closeProgram(objs.KprobeSkbLifetimeTermination)
}

func runRustTraceLoaderHelperOutput(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rustTraceLoaderTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, rustTraceLoaderHelperPath(), args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("rust trace loader helper timed out after %s", rustTraceLoaderTimeout)
	}
	if err != nil {
		message := strings.TrimSpace(string(out))
		if message == "" {
			message = err.Error()
		}
		return "", fmt.Errorf("rust trace loader helper %q failed: %s", rustTraceLoaderHelperPath(), message)
	}
	return string(out), nil
}

func rustTraceLoaderHelperPath() string {
	if helper := strings.TrimSpace(os.Getenv(rustTraceLoaderHelperEnv)); helper != "" {
		return helper
	}
	return rustTraceLoaderHelperDefault
}

func rustTraceAyaLoaderEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("DAE_TRACE_RUST_AYA_LOADER"))) {
	case "0", "false", "off", "no":
		return false
	default:
		return true
	}
}

func rustTraceAyaLoaderStrict() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("DAE_TRACE_RUST_AYA_LOADER_STRICT"))) {
	case "1", "true", "on", "yes":
		return true
	default:
		return false
	}
}

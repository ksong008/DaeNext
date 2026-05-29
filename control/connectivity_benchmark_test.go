/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func BenchmarkOutboundConnectivityMapGoUpdate(b *testing.B) {
	m := newBenchmarkConnectivityMap(b)
	defer m.Close()

	key := bpfOutboundConnectivityQuery{Outbound: 2, L4proto: 6, Ipversion: 4}
	value := uint32(1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := m.Update(key, value, ebpf.UpdateAny); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOutboundConnectivityMapRustHelperUpdate(b *testing.B) {
	helper := strings.TrimSpace(os.Getenv(rustBpfLoaderHelperEnv))
	if helper == "" {
		b.Skipf("%s is not set", rustBpfLoaderHelperEnv)
	}
	b.Setenv(rustBpfLoaderHelperEnv, helper)

	m := newBenchmarkConnectivityMap(b)
	defer m.Close()
	mapID, err := bpfMapID(m)
	if err != nil {
		b.Fatal(err)
	}

	args := []string{
		"connectivity-map", "update",
		"--map-id", strconv.FormatUint(uint64(mapID), 10),
		"--outbound", "2",
		"--l4-proto", "6",
		"--ip-version", "4",
		"--alive", "true",
		"--is-init", "true",
		"--dryrun", "false",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := runRustBpfLoaderHelperOutput(args...); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOutboundConnectivityMapRustPersistentHelperUpdate(b *testing.B) {
	helperPath := strings.TrimSpace(os.Getenv(rustBpfLoaderHelperEnv))
	if helperPath == "" {
		b.Skipf("%s is not set", rustBpfLoaderHelperEnv)
	}
	b.Setenv(rustBpfLoaderHelperEnv, helperPath)

	m := newBenchmarkConnectivityMap(b)
	defer m.Close()
	mapID, err := bpfMapID(m)
	if err != nil {
		b.Fatal(err)
	}
	helper := newRustConnectivityHelper()
	defer helper.Close()
	request := rustConnectivityMapRequest{
		MapID:     mapID,
		Outbound:  2,
		L4Proto:   6,
		IPVersion: 4,
		Alive:     true,
		IsInit:    true,
		Dryrun:    false,
	}
	if written, err := helper.Update(request); err != nil {
		b.Fatal(err)
	} else if !written {
		b.Fatal("persistent helper skipped non-dryrun update")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if written, err := helper.Update(request); err != nil {
			b.Fatal(err)
		} else if !written {
			b.Fatal("persistent helper skipped non-dryrun update")
		}
	}
}

func BenchmarkOutboundConnectivityMapRustBinaryPersistentHelperUpdate(b *testing.B) {
	helperPath := strings.TrimSpace(os.Getenv(rustBpfLoaderHelperEnv))
	if helperPath == "" {
		b.Skipf("%s is not set", rustBpfLoaderHelperEnv)
	}
	b.Setenv(rustBpfLoaderHelperEnv, helperPath)

	m := newBenchmarkConnectivityMap(b)
	defer m.Close()
	mapID, err := bpfMapID(m)
	if err != nil {
		b.Fatal(err)
	}
	cmd := exec.Command(helperPath, "connectivity-map", "serve-binary")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		b.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		b.Fatal(err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		b.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		b.Fatal(err)
	}
	go func() {
		_, _ = io.Copy(io.Discard, stderr)
	}()
	defer func() {
		_ = stdin.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	request := rustConnectivityMapRequest{
		MapID:     mapID,
		Outbound:  2,
		L4Proto:   6,
		IPVersion: 4,
		Alive:     true,
		IsInit:    true,
		Dryrun:    false,
	}
	if written, err := updateOutboundConnectivityMapViaRustBinaryPersistentHelper(stdin, stdout, request); err != nil {
		b.Fatal(err)
	} else if !written {
		b.Fatal("binary persistent helper skipped non-dryrun update")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if written, err := updateOutboundConnectivityMapViaRustBinaryPersistentHelper(stdin, stdout, request); err != nil {
			b.Fatal(err)
		} else if !written {
			b.Fatal("binary persistent helper skipped non-dryrun update")
		}
	}
}

func updateOutboundConnectivityMapViaRustBinaryPersistentHelper(stdin io.Writer, stdout io.Reader, request rustConnectivityMapRequest) (bool, error) {
	var payload [8]byte
	binary.LittleEndian.PutUint32(payload[0:4], request.MapID)
	payload[4] = request.Outbound
	payload[5] = request.L4Proto
	payload[6] = request.IPVersion
	if request.Alive {
		payload[7] |= 0x01
	}
	if request.IsInit {
		payload[7] |= 0x02
	}
	if request.Dryrun {
		payload[7] |= 0x04
	}
	if n, err := stdin.Write(payload[:]); err != nil {
		return false, fmt.Errorf("write binary persistent rust connectivity request: %w", err)
	} else if n != len(payload) {
		return false, fmt.Errorf("short binary persistent rust connectivity write: %d/%d", n, len(payload))
	}
	var response [8]byte
	if _, err := io.ReadFull(stdout, response[:]); err != nil {
		return false, fmt.Errorf("read binary persistent rust connectivity response: %w", err)
	}
	if response[0] != 0 {
		return false, fmt.Errorf("binary persistent rust connectivity helper returned status %d", response[0])
	}
	if got := binary.LittleEndian.Uint32(response[4:8]); got != request.MapID {
		return false, fmt.Errorf("binary persistent rust connectivity helper wrote map id %d, want %d", got, request.MapID)
	}
	return response[1] != 0, nil
}

func newBenchmarkConnectivityMap(b *testing.B) *ebpf.Map {
	b.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "dae_conn_bench",
		Type:       ebpf.Hash,
		KeySize:    3,
		ValueSize:  4,
		MaxEntries: 1024,
	})
	if err != nil {
		b.Skipf("connectivity map benchmark requires BPF map create permission: %v", err)
	}
	return m
}

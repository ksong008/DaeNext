//go:build !linux || !cgo || !rust_inprocess

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

const rustOutboundConnectivityOwnerTimeout = 5 * time.Second

type rustOutboundConnectivityOwner struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	cancel context.CancelFunc
	stdin  io.WriteCloser
	stdout io.Reader
	waitCh chan error
	mapPtr *ebpf.Map
	mapID  uint32
}

type rustOutboundConnectivityApplyReport struct {
	mapID        uint32
	mapChanged   bool
	accepted     bool
	changed      bool
	skipped      bool
	entries      int
	stateEntries int
}

func newRustOutboundConnectivityOwner() *rustOutboundConnectivityOwner {
	return &rustOutboundConnectivityOwner{}
}

func (o *rustOutboundConnectivityOwner) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.closeProcessLocked()
}

func (o *rustOutboundConnectivityOwner) Update(m *ebpf.Map, outbound, l4proto, ipversion uint8, alive, isInit, dryrun bool) error {
	_, err := o.ApplyEvent(m, outbound, l4proto, ipversion, alive, isInit, dryrun)
	return err
}

func (o *rustOutboundConnectivityOwner) ApplyEvent(m *ebpf.Map, outbound, l4proto, ipversion uint8, alive, isInit, dryrun bool) (rustOutboundConnectivityApplyReport, error) {
	if m == nil {
		return rustOutboundConnectivityApplyReport{skipped: true}, nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	mapID, err := o.mapIDLocked(m)
	if err != nil {
		return rustOutboundConnectivityApplyReport{}, err
	}
	if err := o.startLocked(); err != nil {
		return rustOutboundConnectivityApplyReport{}, err
	}
	stdin := o.stdin
	stdout := o.stdout
	done := make(chan rustOutboundConnectivityUpdateResult, 1)
	go func() {
		done <- rustOutboundConnectivityUpdateResult{
			report: rustOutboundConnectivityUpdateIO(stdin, stdout, mapID, outbound, l4proto, ipversion, alive, isInit, dryrun),
		}
	}()

	select {
	case result := <-done:
		if result.report.err != nil {
			_ = o.closeProcessLocked()
		}
		if result.report.err != nil {
			return rustOutboundConnectivityApplyReport{}, result.report.err
		}
		return result.report.report, nil
	case <-time.After(rustOutboundConnectivityOwnerTimeout):
		_ = o.closeProcessLocked()
		return rustOutboundConnectivityApplyReport{}, fmt.Errorf("Rust outbound connectivity owner timed out after %s", rustOutboundConnectivityOwnerTimeout)
	}
}

func (o *rustOutboundConnectivityOwner) mapIDLocked(m *ebpf.Map) (uint32, error) {
	if o.mapPtr == m && o.mapID != 0 {
		return o.mapID, nil
	}
	mapID, err := bpfMapID(m)
	if err != nil {
		return 0, err
	}
	o.mapPtr = m
	o.mapID = mapID
	return mapID, nil
}

func (o *rustOutboundConnectivityOwner) startLocked() error {
	if o.cmd != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd, err := rustBpfLoaderCommandContext(ctx, "connectivity-map", "serve-binary")
	if err != nil {
		cancel()
		return fmt.Errorf("resolve Rust outbound connectivity owner: %w", err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return fmt.Errorf("open Rust outbound connectivity owner stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return fmt.Errorf("open Rust outbound connectivity owner stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return fmt.Errorf("open Rust outbound connectivity owner stderr: %w", err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("start Rust outbound connectivity owner: %w", err)
	}
	go func() {
		_, _ = io.Copy(io.Discard, stderr)
	}()
	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()
	o.cmd = cmd
	o.cancel = cancel
	o.stdin = stdin
	o.stdout = stdout
	o.waitCh = waitCh
	return nil
}

func (o *rustOutboundConnectivityOwner) closeProcessLocked() error {
	if o.cmd == nil {
		return nil
	}
	if o.stdin != nil {
		_ = o.stdin.Close()
	}
	if o.cancel != nil {
		o.cancel()
	}
	if o.cmd.Process != nil {
		_ = o.cmd.Process.Kill()
	}
	var err error
	if o.waitCh != nil {
		select {
		case <-o.waitCh:
		case <-time.After(2 * time.Second):
			err = fmt.Errorf("Rust outbound connectivity owner did not exit after close")
		}
	}
	o.cmd = nil
	o.cancel = nil
	o.stdin = nil
	o.stdout = nil
	o.waitCh = nil
	return err
}

type rustOutboundConnectivityUpdateResult struct {
	report rustOutboundConnectivityIOReport
}

type rustOutboundConnectivityIOReport struct {
	report rustOutboundConnectivityApplyReport
	err    error
}

func rustOutboundConnectivityUpdateIO(
	stdin io.Writer,
	stdout io.Reader,
	mapID uint32,
	outbound, l4proto, ipversion uint8,
	alive, isInit, dryrun bool,
) rustOutboundConnectivityIOReport {
	var request [8]byte
	binary.LittleEndian.PutUint32(request[0:4], mapID)
	request[4] = outbound
	request[5] = l4proto
	request[6] = ipversion
	if alive {
		request[7] |= 0x01
	}
	if isInit {
		request[7] |= 0x02
	}
	if dryrun {
		request[7] |= 0x04
	}
	if _, err := stdin.Write(request[:]); err != nil {
		return rustOutboundConnectivityIOReport{err: fmt.Errorf("write Rust outbound connectivity request: %w", err)}
	}
	var response [8]byte
	if _, err := io.ReadFull(stdout, response[:]); err != nil {
		return rustOutboundConnectivityIOReport{err: fmt.Errorf("read Rust outbound connectivity response: %w", err)}
	}
	responseMapID := binary.LittleEndian.Uint32(response[4:8])
	if responseMapID != mapID {
		return rustOutboundConnectivityIOReport{err: fmt.Errorf("Rust outbound connectivity owner wrote map id %d, want %d", responseMapID, mapID)}
	}
	if response[0] != 0 {
		return rustOutboundConnectivityIOReport{err: fmt.Errorf("Rust outbound connectivity owner returned status %d", response[0])}
	}
	written := response[1] != 0
	return rustOutboundConnectivityIOReport{
		report: rustOutboundConnectivityApplyReport{
			mapID:        mapID,
			mapChanged:   false,
			accepted:     true,
			changed:      written,
			skipped:      !written,
			entries:      boolToInt(written),
			stateEntries: 0,
		},
	}
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"
)

const rustConnectivityHelperRequestTimeout = 5 * time.Second

type rustConnectivityHelper struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	cancel context.CancelFunc
	stdin  io.WriteCloser
	stdout *bufio.Reader
	waitCh chan error
}

type rustConnectivityMapRequest struct {
	MapID     uint32 `json:"map_id"`
	Outbound  uint8  `json:"outbound"`
	L4Proto   uint8  `json:"l4_proto"`
	IPVersion uint8  `json:"ip_version"`
	Alive     bool   `json:"alive"`
	IsInit    bool   `json:"is_init"`
	Dryrun    bool   `json:"dryrun"`
}

type rustConnectivityMapResponse struct {
	Status  string `json:"status"`
	MapID   uint32 `json:"map_id"`
	Written bool   `json:"written"`
	Error   string `json:"error"`
}

type rustConnectivityHelperUpdateResult struct {
	written bool
	err     error
}

func newRustConnectivityHelper() *rustConnectivityHelper {
	return &rustConnectivityHelper{}
}

func (h *rustConnectivityHelper) Update(request rustConnectivityMapRequest) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if err := h.startLocked(); err != nil {
		return false, err
	}
	stdin := h.stdin
	stdout := h.stdout
	done := make(chan rustConnectivityHelperUpdateResult, 1)
	go func() {
		written, err := rustConnectivityHelperUpdateIO(stdin, stdout, request)
		done <- rustConnectivityHelperUpdateResult{written: written, err: err}
	}()

	select {
	case result := <-done:
		if result.err != nil {
			_ = h.closeProcessLocked()
		}
		return result.written, result.err
	case <-time.After(rustConnectivityHelperRequestTimeout):
		_ = h.closeProcessLocked()
		return false, fmt.Errorf("persistent rust connectivity helper timed out after %s", rustConnectivityHelperRequestTimeout)
	}
}

func (h *rustConnectivityHelper) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closeProcessLocked()
}

func (h *rustConnectivityHelper) startLocked() error {
	if h.cmd != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, rustBpfLoaderHelperPath(), "connectivity-map", "serve")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return fmt.Errorf("open persistent rust connectivity helper stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return fmt.Errorf("open persistent rust connectivity helper stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return fmt.Errorf("open persistent rust connectivity helper stderr: %w", err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("start persistent rust connectivity helper: %w", err)
	}
	go func() {
		_, _ = io.Copy(io.Discard, stderr)
	}()
	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()
	h.cmd = cmd
	h.cancel = cancel
	h.stdin = stdin
	h.stdout = bufio.NewReader(stdout)
	h.waitCh = waitCh
	return nil
}

func (h *rustConnectivityHelper) closeProcessLocked() error {
	if h.cmd == nil {
		return nil
	}
	if h.stdin != nil {
		_ = h.stdin.Close()
	}
	if h.cancel != nil {
		h.cancel()
	}
	if h.cmd.Process != nil {
		_ = h.cmd.Process.Kill()
	}
	var err error
	if h.waitCh != nil {
		select {
		case <-h.waitCh:
		case <-time.After(2 * time.Second):
			err = fmt.Errorf("persistent rust connectivity helper did not exit after close")
		}
	}
	h.cmd = nil
	h.cancel = nil
	h.stdin = nil
	h.stdout = nil
	h.waitCh = nil
	return err
}

func rustConnectivityHelperUpdateIO(stdin io.Writer, stdout *bufio.Reader, request rustConnectivityMapRequest) (bool, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return false, fmt.Errorf("encode persistent rust connectivity request: %w", err)
	}
	payload = append(payload, '\n')
	if _, err := stdin.Write(payload); err != nil {
		return false, fmt.Errorf("write persistent rust connectivity request: %w", err)
	}
	line, err := stdout.ReadBytes('\n')
	if err != nil {
		return false, fmt.Errorf("read persistent rust connectivity response: %w", err)
	}
	var response rustConnectivityMapResponse
	if err := json.Unmarshal(line, &response); err != nil {
		return false, fmt.Errorf("decode persistent rust connectivity response: %w", err)
	}
	if response.Status != "pass" {
		if response.Error != "" {
			return false, fmt.Errorf("persistent rust connectivity helper returned %s: %s", response.Status, response.Error)
		}
		return false, fmt.Errorf("persistent rust connectivity helper returned status %q", response.Status)
	}
	if response.MapID != request.MapID {
		return false, fmt.Errorf("persistent rust connectivity helper wrote map id %d, want %d", response.MapID, request.MapID)
	}
	return response.Written, nil
}

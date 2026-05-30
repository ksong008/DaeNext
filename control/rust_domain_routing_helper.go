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

const rustDomainRoutingHelperRequestTimeout = 5 * time.Second

type rustDomainRoutingHelper struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	cancel context.CancelFunc
	stdin  io.WriteCloser
	stdout *bufio.Reader
	waitCh chan error
}

type rustDomainRoutingMapResponse struct {
	Status         string `json:"status"`
	MapID          uint32 `json:"map_id"`
	EntriesUpdated int    `json:"entries_updated"`
	EntriesDeleted int    `json:"entries_deleted"`
	Error          string `json:"error"`
}

type rustDomainRoutingHelperUpdateResult struct {
	err error
}

func newRustDomainRoutingHelper() *rustDomainRoutingHelper {
	return &rustDomainRoutingHelper{}
}

func (h *rustDomainRoutingHelper) Update(request rustDomainRoutingMapApplyRequest) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if err := h.startLocked(); err != nil {
		return err
	}
	stdin := h.stdin
	stdout := h.stdout
	done := make(chan rustDomainRoutingHelperUpdateResult, 1)
	go func() {
		done <- rustDomainRoutingHelperUpdateResult{
			err: rustDomainRoutingHelperUpdateIO(stdin, stdout, request),
		}
	}()

	select {
	case result := <-done:
		if result.err != nil {
			_ = h.closeProcessLocked()
		}
		return result.err
	case <-time.After(rustDomainRoutingHelperRequestTimeout):
		_ = h.closeProcessLocked()
		return fmt.Errorf("persistent rust domain routing helper timed out after %s", rustDomainRoutingHelperRequestTimeout)
	}
}

func (h *rustDomainRoutingHelper) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closeProcessLocked()
}

func (h *rustDomainRoutingHelper) startLocked() error {
	if h.cmd != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd, err := rustBpfLoaderCommandContext(ctx, "domain-routing-map", "serve")
	if err != nil {
		cancel()
		return fmt.Errorf("resolve persistent rust domain routing helper: %w", err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return fmt.Errorf("open persistent rust domain routing helper stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return fmt.Errorf("open persistent rust domain routing helper stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return fmt.Errorf("open persistent rust domain routing helper stderr: %w", err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("start persistent rust domain routing helper: %w", err)
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

func (h *rustDomainRoutingHelper) closeProcessLocked() error {
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
			err = fmt.Errorf("persistent rust domain routing helper did not exit after close")
		}
	}
	h.cmd = nil
	h.cancel = nil
	h.stdin = nil
	h.stdout = nil
	h.waitCh = nil
	return err
}

func rustDomainRoutingHelperUpdateIO(stdin io.Writer, stdout *bufio.Reader, request rustDomainRoutingMapApplyRequest) error {
	payload, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("encode persistent rust domain routing request: %w", err)
	}
	payload = append(payload, '\n')
	if _, err := stdin.Write(payload); err != nil {
		return fmt.Errorf("write persistent rust domain routing request: %w", err)
	}
	line, err := stdout.ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("read persistent rust domain routing response: %w", err)
	}
	var response rustDomainRoutingMapResponse
	if err := json.Unmarshal(line, &response); err != nil {
		return fmt.Errorf("decode persistent rust domain routing response: %w", err)
	}
	if response.Status != "pass" {
		if response.Error != "" {
			return fmt.Errorf("persistent rust domain routing helper returned %s: %s", response.Status, response.Error)
		}
		return fmt.Errorf("persistent rust domain routing helper returned status %q", response.Status)
	}
	if response.MapID != request.MapID {
		return fmt.Errorf("persistent rust domain routing helper wrote map id %d, want %d", response.MapID, request.MapID)
	}
	if response.EntriesUpdated != len(request.Updates) || response.EntriesDeleted != len(request.Deletes) {
		return fmt.Errorf("persistent rust domain routing helper updated/deleted %d/%d entries, want %d/%d",
			response.EntriesUpdated, response.EntriesDeleted, len(request.Updates), len(request.Deletes))
	}
	return nil
}

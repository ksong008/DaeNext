//go:build !linux || !cgo || !rust_inprocess

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
	"sort"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
)

const rustDomainRoutingOwnerTimeout = 5 * time.Second

type rustDomainRoutingOwner struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	cancel context.CancelFunc
	stdin  io.WriteCloser
	stdout *bufio.Reader
	waitCh chan error
	mapPtr *ebpf.Map
	mapID  uint32
}

type rustReloadDnsCachePlan struct {
	dnsConfigUnchanged    bool
	bpfPresent            bool
	restoreCache          bool
	clearDomainRoutingMap bool
	snapshotEntries       int
}

type RustOwnedRuntimeStateReport struct {
	SchemaVersion               uint32
	RustOwnedRuntime            bool
	ReloadStateAvailable        bool
	BackendStateAvailable       bool
	RoutingOwnerAvailable       bool
	DomainOwnerAvailable        bool
	ConnectivityOwnerAvailable  bool
	ActiveHandoffAvailable      bool
	APICompatible               bool
	ReadyForDefaultControlPlane bool
}

func rustInprocessRoutingMapAvailable() bool {
	return false
}

func BuildRustOwnedRuntimeStateReport() (RustOwnedRuntimeStateReport, error) {
	return RustOwnedRuntimeStateReport{
		SchemaVersion:              1,
		DomainOwnerAvailable:       true,
		ConnectivityOwnerAvailable: true,
		APICompatible:              true,
	}, nil
}

func RustOwnedReloadDnsCacheRestoreAllowed(dnsConfigUnchanged bool) bool {
	return dnsConfigUnchanged
}

func rustReloadDnsCachePlanForReload(dnsConfigUnchanged bool, bpfPresent bool, snapshotEntries int) (rustReloadDnsCachePlan, error) {
	if snapshotEntries < 0 {
		snapshotEntries = 0
	}
	return rustReloadDnsCachePlan{
		dnsConfigUnchanged:    dnsConfigUnchanged,
		bpfPresent:            bpfPresent,
		restoreCache:          dnsConfigUnchanged && snapshotEntries > 0,
		clearDomainRoutingMap: bpfPresent,
		snapshotEntries:       snapshotEntries,
	}, nil
}

func applyKernelRoutingMapsViaRustInprocess(request rustRoutingMapApplyRequest) error {
	return fmt.Errorf("Rust in-process routing map writer is not enabled")
}

func applyKernelRoutingMapsViaRustOwnedInprocess(request rustRoutingMapApplyRequest) error {
	return fmt.Errorf("Rust in-process routing map owner is not enabled")
}

func updateDomainRoutingMapViaRustInprocess(request rustDomainRoutingMapApplyRequest) error {
	return fmt.Errorf("Rust in-process domain routing map writer is not enabled")
}

func newRustDomainRoutingOwner() *rustDomainRoutingOwner {
	return &rustDomainRoutingOwner{}
}

func (o *rustDomainRoutingOwner) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.closeProcessLocked()
}

func (o *rustDomainRoutingOwner) Update(m *ebpf.Map, ownerKey string, snapshot domainRoutingOwnerSnapshot) error {
	if m == nil {
		return nil
	}
	request, err := o.newSyncOwnerRequest(m, ownerKey, snapshot.bitmap.Bitmap, domainRoutingSnapshotKeys(snapshot))
	if err != nil {
		return err
	}
	return o.apply(request)
}

func (o *rustDomainRoutingOwner) UpdateDnsCacheEvent(m *ebpf.Map, event domainRoutingDnsEvent) error {
	if m == nil || event.ownerKey == "" {
		return nil
	}
	if len(event.domainBitmap) != len(bpfDomainRouting{}.Bitmap) {
		return fmt.Errorf("domain bitmap length not sync with kern program")
	}
	request, err := o.newSyncOwnerRequest(m, event.ownerKey, array32FromWords(event.domainBitmap), domainRoutingEventKeys(event))
	if err != nil {
		return err
	}
	return o.apply(request)
}

func (o *rustDomainRoutingOwner) RemoveDnsCacheEvent(m *ebpf.Map, ownerKey string) error {
	if m == nil || ownerKey == "" {
		return nil
	}
	request, err := o.newSyncOwnerRequest(m, ownerKey, [32]uint32{}, nil)
	if err != nil {
		return err
	}
	return o.apply(request)
}

func (o *rustDomainRoutingOwner) PrepareReload(m *ebpf.Map, keys [][4]uint32) error {
	if m == nil {
		return nil
	}
	mapID, err := o.mapIDFor(m)
	if err != nil {
		return err
	}
	return o.apply(rustDomainRoutingOwnerRequest{
		Op:           "prepare_reload",
		MapID:        mapID,
		ExistingKeys: sortedDomainRoutingKeys(keys),
	})
}

func (o *rustDomainRoutingOwner) newSyncOwnerRequest(m *ebpf.Map, ownerKey string, bitmap [32]uint32, ips [][4]uint32) (rustDomainRoutingOwnerRequest, error) {
	if ownerKey == "" {
		return rustDomainRoutingOwnerRequest{}, fmt.Errorf("empty domain routing owner key")
	}
	mapID, err := o.mapIDFor(m)
	if err != nil {
		return rustDomainRoutingOwnerRequest{}, err
	}
	return rustDomainRoutingOwnerRequest{
		Op:       "sync_owner",
		MapID:    mapID,
		OwnerKey: ownerKey,
		Bitmap:   bitmap,
		IPs:      sortedDomainRoutingKeys(ips),
	}, nil
}

func (o *rustDomainRoutingOwner) mapIDFor(m *ebpf.Map) (uint32, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
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

func (o *rustDomainRoutingOwner) apply(request rustDomainRoutingOwnerRequest) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.startLocked(); err != nil {
		return err
	}
	stdin := o.stdin
	stdout := o.stdout
	done := make(chan rustDomainRoutingOwnerUpdateResult, 1)
	go func() {
		done <- rustDomainRoutingOwnerUpdateResult{
			response: rustDomainRoutingOwnerUpdateIO(stdin, stdout, request),
		}
	}()
	select {
	case result := <-done:
		if result.response.err != nil {
			_ = o.closeProcessLocked()
			return result.response.err
		}
		return nil
	case <-time.After(rustDomainRoutingOwnerTimeout):
		_ = o.closeProcessLocked()
		return fmt.Errorf("Rust domain routing owner timed out after %s", rustDomainRoutingOwnerTimeout)
	}
}

func (o *rustDomainRoutingOwner) startLocked() error {
	if o.cmd != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd, err := rustBpfLoaderCommandContext(ctx, "domain-routing-map", "serve-owner")
	if err != nil {
		cancel()
		return fmt.Errorf("resolve Rust domain routing owner: %w", err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return fmt.Errorf("open Rust domain routing owner stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return fmt.Errorf("open Rust domain routing owner stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return fmt.Errorf("open Rust domain routing owner stderr: %w", err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("start Rust domain routing owner: %w", err)
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
	o.stdout = bufio.NewReader(stdout)
	o.waitCh = waitCh
	return nil
}

func (o *rustDomainRoutingOwner) closeProcessLocked() error {
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
			err = fmt.Errorf("Rust domain routing owner did not exit after close")
		}
	}
	o.cmd = nil
	o.cancel = nil
	o.stdin = nil
	o.stdout = nil
	o.waitCh = nil
	return err
}

type rustDomainRoutingOwnerRequest struct {
	Op           string      `json:"op"`
	MapID        uint32      `json:"map_id"`
	OwnerKey     string      `json:"owner_key,omitempty"`
	Bitmap       [32]uint32  `json:"bitmap,omitempty"`
	IPs          [][4]uint32 `json:"ips,omitempty"`
	ExistingKeys [][4]uint32 `json:"existing_keys,omitempty"`
}

type rustDomainRoutingOwnerResponse struct {
	Status         string `json:"status"`
	MapID          uint32 `json:"map_id"`
	Owner          string `json:"owner"`
	Op             string `json:"op"`
	EntriesUpdated int    `json:"entries_updated"`
	EntriesDeleted int    `json:"entries_deleted"`
	OwnerCount     int    `json:"owner_count"`
	IPCount        int    `json:"ip_count"`
	Error          string `json:"error"`
}

type rustDomainRoutingOwnerUpdateResult struct {
	response rustDomainRoutingOwnerIOResponse
}

type rustDomainRoutingOwnerIOResponse struct {
	response rustDomainRoutingOwnerResponse
	err      error
}

func rustDomainRoutingOwnerUpdateIO(stdin io.Writer, stdout *bufio.Reader, request rustDomainRoutingOwnerRequest) rustDomainRoutingOwnerIOResponse {
	payload, err := json.Marshal(request)
	if err != nil {
		return rustDomainRoutingOwnerIOResponse{err: fmt.Errorf("encode Rust domain routing owner request: %w", err)}
	}
	payload = append(payload, '\n')
	if _, err := stdin.Write(payload); err != nil {
		return rustDomainRoutingOwnerIOResponse{err: fmt.Errorf("write Rust domain routing owner request: %w", err)}
	}
	line, err := stdout.ReadBytes('\n')
	if err != nil {
		return rustDomainRoutingOwnerIOResponse{err: fmt.Errorf("read Rust domain routing owner response: %w", err)}
	}
	var response rustDomainRoutingOwnerResponse
	if err := json.Unmarshal(line, &response); err != nil {
		return rustDomainRoutingOwnerIOResponse{err: fmt.Errorf("decode Rust domain routing owner response: %w", err)}
	}
	if response.Status != "pass" {
		if response.Error != "" {
			return rustDomainRoutingOwnerIOResponse{err: fmt.Errorf("Rust domain routing owner returned %s: %s", response.Status, response.Error)}
		}
		return rustDomainRoutingOwnerIOResponse{err: fmt.Errorf("Rust domain routing owner returned status %q", response.Status)}
	}
	if response.MapID != request.MapID {
		return rustDomainRoutingOwnerIOResponse{err: fmt.Errorf("Rust domain routing owner wrote map id %d, want %d", response.MapID, request.MapID)}
	}
	if response.Owner != "dae-control" {
		return rustDomainRoutingOwnerIOResponse{err: fmt.Errorf("Rust domain routing owner marker = %q, want dae-control", response.Owner)}
	}
	if response.Op != request.Op {
		return rustDomainRoutingOwnerIOResponse{err: fmt.Errorf("Rust domain routing owner op = %q, want %q", response.Op, request.Op)}
	}
	return rustDomainRoutingOwnerIOResponse{response: response}
}

func array32FromWords(words []uint32) [32]uint32 {
	var bitmap [32]uint32
	copy(bitmap[:], words)
	return bitmap
}

func domainRoutingSnapshotKeys(snapshot domainRoutingOwnerSnapshot) [][4]uint32 {
	keys := make([][4]uint32, 0, len(snapshot.ips))
	for key := range snapshot.ips {
		keys = append(keys, key)
	}
	return sortedDomainRoutingKeys(keys)
}

func domainRoutingEventKeys(event domainRoutingDnsEvent) [][4]uint32 {
	keys := make([][4]uint32, 0, len(event.ips))
	for _, ip := range event.ips {
		ip16 := ip.As16()
		keys = append(keys, common.Ipv6ByteSliceToUint32Array(ip16[:]))
	}
	return sortedDomainRoutingKeys(keys)
}

func sortedDomainRoutingKeys(keys [][4]uint32) [][4]uint32 {
	if len(keys) == 0 {
		return nil
	}
	out := append([][4]uint32(nil), keys...)
	sort.Slice(out, func(i, j int) bool {
		for word := range out[i] {
			if out[i][word] == out[j][word] {
				continue
			}
			return out[i][word] < out[j][word]
		}
		return false
	})
	dedup := out[:0]
	for _, key := range out {
		if len(dedup) == 0 || dedup[len(dedup)-1] != key {
			dedup = append(dedup, key)
		}
	}
	return dedup
}

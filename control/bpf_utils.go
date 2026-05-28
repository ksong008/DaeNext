/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
)

type _bpfTuples struct {
	Sip     [4]uint32
	Dip     [4]uint32
	Sport   uint16
	Dport   uint16
	L4proto uint8
	_       [3]byte
}

type _bpfLpmKey struct {
	PrefixLen uint32
	Data      [4]uint32
}

type _bpfPortRange struct {
	PortStart uint16
	PortEnd   uint16
}

func (r _bpfPortRange) Encode() (b [16]byte) {
	binary.LittleEndian.PutUint16(b[:2], r.PortStart)
	binary.LittleEndian.PutUint16(b[2:], r.PortEnd)
	return b
}

func ParsePortRange(b []byte) (portStart, portEnd uint16) {
	portStart = binary.LittleEndian.Uint16(b[:2])
	portEnd = binary.LittleEndian.Uint16(b[2:])
	return portStart, portEnd
}

func (o *bpfObjects) newLpmMap(keys []_bpfLpmKey, values []uint32) (m *ebpf.Map, err error) {
	m, err = ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.LPMTrie,
		Flags:      o.UnusedLpmType.Flags(),
		MaxEntries: o.UnusedLpmType.MaxEntries(),
		KeySize:    o.UnusedLpmType.KeySize(),
		ValueSize:  o.UnusedLpmType.ValueSize(),
	})
	if err != nil {
		return nil, err
	}
	if _, err = BpfMapBatchUpdate(m, keys, values, &ebpf.BatchOptions{
		ElemFlags: uint64(ebpf.UpdateAny),
	}); err != nil {
		if closeErr := m.Close(); closeErr != nil {
			return nil, errors.Join(err, fmt.Errorf("close lpm map after batch update failure: %w", closeErr))
		}
		return nil, err
	}
	return m, nil
}

func cidrToBpfLpmKey(prefix netip.Prefix) _bpfLpmKey {
	bits := prefix.Bits()
	if prefix.Addr().Is4() {
		bits += 96
	}
	ip := prefix.Addr().As16()
	return _bpfLpmKey{
		PrefixLen: uint32(bits),
		Data:      common.Ipv6ByteSliceToUint32Array(ip[:]),
	}
}

var bpfMapBatchUpdate = func(m *ebpf.Map, keys interface{}, values interface{}, opts *ebpf.BatchOptions) (n int, err error) {
	return m.BatchUpdate(keys, values, opts)
}

func BpfMapBatchUpdate(m *ebpf.Map, keys interface{}, values interface{}, opts *ebpf.BatchOptions) (n int, err error) {
	return bpfMapBatchUpdate(m, keys, values, opts)
}

// BpfMapBatchDelete deletes keys and ignores ErrKeyNotExist.
func BpfMapBatchDelete(m *ebpf.Map, keys interface{}) (n int, err error) {
	n, err = m.BatchDelete(keys, nil)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return n, nil
	}
	return n, err
}

// detectCgroupPath returns the first-found mount point of type cgroup2
// and stores it in the cgroupPath global variable.
// Copied from https://github.com/cilium/ebpf/blob/v0.10.0/examples/cgroup_skb/main.go
func detectCgroupPath() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// example fields: cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}

	return "", errors.New("cgroup2 not mounted")
}

type bpfIfParams struct {
	RxCksmOffload                  bool
	TxL4CksmIp4Offload             bool
	TxL4CksmIp6Offload             bool
	UseNonstandardOffloadAlgorithm bool
}

func (p bpfIfParams) CheckVersionRequirement(version *internal.Version) (err error) {
	if !p.TxL4CksmIp4Offload ||
		!p.TxL4CksmIp6Offload {
		// Need calc checksum on CPU. And need BPF_F_ADJ_ROOM_NO_CSUM_RESET.
		if version.Less(consts.ChecksumFeatureVersion) {
			return fmt.Errorf("your NIC does not support checksum offload and your kernel version %v does not support related BPF features; expect >=%v; upgrade your kernel and try again", version.String(),
				consts.ChecksumFeatureVersion.String())
		}
	}
	return nil
}

type loadBpfOptions struct {
	PinPath        string
	HostTproxyPort uint16
}

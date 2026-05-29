/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func FormatL4Proto(l4proto uint8) string {
	if l4proto == unix.IPPROTO_TCP {
		return "tcp"
	}
	if l4proto == unix.IPPROTO_UDP {
		return "udp"
	}
	return strconv.Itoa(int(l4proto))
}

func (c *controlPlaneCore) outboundAliveChangeCallback(outbound uint8, dryrun bool) func(alive bool, networkType *dialer.NetworkType, isInit bool) {
	return func(alive bool, networkType *dialer.NetworkType, isInit bool) {
		select {
		case <-c.closed.Done():
			return
		default:
		}
		if !isInit && dryrun {
			return
		}
		if !isInit || c.log.IsLevelEnabled(logrus.TraceLevel) {
			strAlive := "NOT ALIVE"
			if alive {
				strAlive = "ALIVE"
			}
			c.log.WithFields(logrus.Fields{
				"outboundId": outbound,
			}).Tracef("Outbound <%v> %v -> %v, notify the kernel program.", c.outboundId2Name[outbound], networkType.StringWithoutDns(), strAlive)
		}

		if written, err := c.updateOutboundConnectivityMapViaRustHelper(outbound, alive, networkType, isInit, dryrun); err == nil {
			if written {
				return
			}
		} else {
			c.log.WithFields(logrus.Fields{
				"alive":    alive,
				"network":  networkType.StringWithoutDns(),
				"outbound": c.outboundId2Name[outbound],
			}).Debugf("Rust outbound connectivity map writer unavailable, falling back to Go writer: %v", err)
		}
		if !isInit && dryrun {
			return
		}
		value := uint32(0)
		if alive {
			value = 1
		}
		if err := c.bpf.OutboundConnectivityMap.Update(bpfOutboundConnectivityQuery{
			Outbound:  outbound,
			L4proto:   networkType.L4Proto.ToL4Proto(),
			Ipversion: networkType.IpVersion.ToIpVersion(),
		}, value, ebpf.UpdateAny); err != nil {
			c.log.WithFields(logrus.Fields{
				"alive":    alive,
				"network":  networkType.StringWithoutDns(),
				"outbound": c.outboundId2Name[outbound],
			}).Warnf("Failed to notify the kernel program: %v", err)
		}
	}
}

func (c *controlPlaneCore) updateOutboundConnectivityMapViaRustHelper(outbound uint8, alive bool, networkType *dialer.NetworkType, isInit bool, dryrun bool) (bool, error) {
	if c == nil || c.bpf == nil || c.bpf.OutboundConnectivityMap == nil {
		return false, fmt.Errorf("outbound connectivity map is not initialized")
	}
	mapID, err := bpfMapID(c.bpf.OutboundConnectivityMap)
	if err != nil {
		return false, err
	}
	request := rustConnectivityMapRequest{
		MapID:     mapID,
		Outbound:  outbound,
		L4Proto:   networkType.L4Proto.ToL4Proto(),
		IPVersion: networkType.IpVersion.ToIpVersion(),
		Alive:     alive,
		IsInit:    isInit,
		Dryrun:    dryrun,
	}
	if written, err := c.getRustConnectivityHelper().Update(request); err == nil {
		return written, nil
	} else {
		c.log.WithFields(logrus.Fields{
			"alive":    alive,
			"network":  networkType.StringWithoutDns(),
			"outbound": c.outboundId2Name[outbound],
		}).Debugf("Persistent Rust outbound connectivity map writer unavailable, trying process helper: %v", err)
	}
	return updateOutboundConnectivityMapViaRustProcessHelper(request)
}

func updateOutboundConnectivityMapViaRustProcessHelper(request rustConnectivityMapRequest) (bool, error) {
	out, err := runRustBpfLoaderHelperOutput(
		"connectivity-map", "update",
		"--map-id", strconv.FormatUint(uint64(request.MapID), 10),
		"--outbound", strconv.Itoa(int(request.Outbound)),
		"--l4-proto", strconv.Itoa(int(request.L4Proto)),
		"--ip-version", strconv.Itoa(int(request.IPVersion)),
		"--alive", strconv.FormatBool(request.Alive),
		"--is-init", strconv.FormatBool(request.IsInit),
		"--dryrun", strconv.FormatBool(request.Dryrun),
	)
	if err != nil {
		return false, err
	}
	var decoded struct {
		Written bool `json:"written"`
	}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		return false, fmt.Errorf("decode rust connectivity map output: %w", err)
	}
	return decoded.Written, nil
}

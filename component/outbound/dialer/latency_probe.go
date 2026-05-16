/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"fmt"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/netproxy"
)

type LatencyProbeResult struct {
	Alive     bool
	Latency   time.Duration
	Message   string
	CheckedAt time.Time
}

const manualProbeTimeout = 4 * time.Second
const manualProbeScopeNote = "TCP-only"

func (d *Dialer) ProbeLatency() (*LatencyProbeResult, error) {
	checkOptions := d.latencyProbeCheckOptions()
	var (
		lastErr       error
		lastCheckedAt time.Time
	)

	for _, opt := range checkOptions {
		ok, latency, err := d.probeLatencyCheck(opt, manualProbeTimeout)
		checkedAt := d.recordProbeLatencyResult(opt, ok, latency, err)
		lastCheckedAt = checkedAt
		if err != nil {
			lastErr = err
		}
		if !ok {
			continue
		}
		return &LatencyProbeResult{
			Alive:     true,
			Latency:   latency,
			Message:   manualProbeScopeNote,
			CheckedAt: checkedAt,
		}, nil
	}

	if lastCheckedAt.IsZero() {
		lastCheckedAt = time.Now()
	}
	result := &LatencyProbeResult{
		CheckedAt: lastCheckedAt,
	}
	if lastErr != nil {
		result.Message = lastErr.Error()
		return result, nil
	}

	result.Message = "no latency result"
	return result, nil
}

func (d *Dialer) recordProbeLatencyResult(opt *CheckOption, ok bool, latency time.Duration, err error) time.Time {
	collection := d.mustGetCollection(opt.networkType)
	checkedAt := time.Now()
	if ok && err == nil {
		collection.Latencies10.AppendLatency(latency)
		collection.mu.Lock()
		collection.MovingAverage = (collection.MovingAverage + latency) / 2
		collection.Alive = true
		collection.CheckedAt = checkedAt
		collection.mu.Unlock()
	} else {
		d.logUnavailable(collection, opt.networkType, err, checkedAt)
	}
	d.informDialerGroupUpdate(collection)
	return checkedAt
}

func (d *Dialer) probeLatencyCheck(opt *CheckOption, timeout time.Duration) (ok bool, latency time.Duration, err error) {
	ctx, cancel := context.WithTimeout(context.TODO(), timeout)
	defer cancel()

	start := time.Now()
	ok, err = opt.CheckFunc(ctx, opt.networkType)
	if !ok || err != nil {
		return ok, 0, err
	}
	return true, time.Since(start), nil
}

func (d *Dialer) latencyProbeCheckOptions() []*CheckOption {
	return []*CheckOption{
		{
			networkType: &NetworkType{
				L4Proto:   consts.L4ProtoStr_TCP,
				IpVersion: consts.IpVersionStr_4,
				IsDns:     false,
			},
			CheckFunc: func(ctx context.Context, _ *NetworkType) (bool, error) {
				opt, err := d.TcpCheckOptionRaw.Option()
				if err != nil {
					return false, err
				}
				if !opt.Ip4.IsValid() {
					return false, nil
				}
				var tcpSomark uint32
				var mptcp bool
				if network, err := netproxy.ParseMagicNetwork(d.TcpCheckOptionRaw.ResolverNetwork); err == nil {
					tcpSomark = network.Mark
					mptcp = network.Mptcp
				}
				return d.HttpCheck(ctx, opt.Url, opt.Ip4, opt.Method, tcpSomark, mptcp)
			},
		},
		{
			networkType: &NetworkType{
				L4Proto:   consts.L4ProtoStr_TCP,
				IpVersion: consts.IpVersionStr_6,
				IsDns:     false,
			},
			CheckFunc: func(ctx context.Context, _ *NetworkType) (bool, error) {
				opt, err := d.TcpCheckOptionRaw.Option()
				if err != nil {
					return false, err
				}
				if !opt.Ip6.IsValid() {
					return false, nil
				}
				var tcpSomark uint32
				var mptcp bool
				if network, err := netproxy.ParseMagicNetwork(d.TcpCheckOptionRaw.ResolverNetwork); err == nil {
					tcpSomark = network.Mark
					mptcp = network.Mptcp
				}
				return d.HttpCheck(ctx, opt.Url, opt.Ip6, opt.Method, tcpSomark, mptcp)
			},
		},
	}
}

func FormatLatencyMessage(result *LatencyProbeResult) string {
	if result == nil {
		return "unknown"
	}
	if result.Alive {
		return fmt.Sprintf("%dms", result.Latency.Milliseconds())
	}
	if result.Message != "" {
		return result.Message
	}
	return "unavailable"
}

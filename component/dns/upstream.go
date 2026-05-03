/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
)

var (
	ErrFormat = fmt.Errorf("format error")
)

const (
	DefaultUpstreamRefreshInterval = 10 * time.Minute
	DefaultUpstreamRetryInterval   = time.Minute
)

type UpstreamScheme string

const (
	UpstreamScheme_TCP           UpstreamScheme = "tcp"
	UpstreamScheme_UDP           UpstreamScheme = "udp"
	UpstreamScheme_TCP_UDP       UpstreamScheme = "tcp+udp"
	upstreamScheme_TCP_UDP_Alias UpstreamScheme = "udp+tcp"
	UpstreamScheme_TLS           UpstreamScheme = "tls"
	UpstreamScheme_QUIC          UpstreamScheme = "quic"
	UpstreamScheme_HTTPS         UpstreamScheme = "https"
	upstreamScheme_H3_Alias      UpstreamScheme = "http3"
	UpstreamScheme_H3            UpstreamScheme = "h3"
)

func (s UpstreamScheme) ContainsTcp() bool {
	switch s {
	case UpstreamScheme_TCP,
		UpstreamScheme_TCP_UDP:
		return true
	default:
		return false
	}
}

func ParseRawUpstream(raw *url.URL) (scheme UpstreamScheme, hostname string, port uint16, path string, err error) {
	var __port string
	var __path string
	switch scheme = UpstreamScheme(raw.Scheme); scheme {
	case upstreamScheme_TCP_UDP_Alias:
		scheme = UpstreamScheme_TCP_UDP
		fallthrough
	case UpstreamScheme_TCP, UpstreamScheme_UDP, UpstreamScheme_TCP_UDP:
		__port = raw.Port()
		if __port == "" {
			__port = "53"
		}
	case upstreamScheme_H3_Alias:
		scheme = UpstreamScheme_H3
		fallthrough
	case UpstreamScheme_HTTPS, UpstreamScheme_H3:
		__port = raw.Port()
		if __port == "" {
			__port = "443"
		}
		__path = raw.Path
		if __path == "" {
			__path = "/dns-query"
		}
	case UpstreamScheme_QUIC, UpstreamScheme_TLS:
		__port = raw.Port()
		if __port == "" {
			__port = "853"
		}
	default:
		return "", "", 0, "", fmt.Errorf("unexpected scheme: %v", raw.Scheme)
	}
	_port, err := strconv.ParseUint(__port, 10, 16)
	if err != nil {
		return "", "", 0, "", fmt.Errorf("failed to parse dns_upstream port: %v", err)
	}
	port = uint16(_port)
	hostname = raw.Hostname()
	return scheme, hostname, port, __path, nil
}

type Upstream struct {
	Scheme   UpstreamScheme
	Hostname string
	Port     uint16
	Path     string
	Index    consts.DnsRequestOutboundIndex
	*netutils.Ip46
}

func NewUpstream(ctx context.Context, upstream *url.URL, resolverNetwork string) (up *Upstream, err error) {
	return NewUpstreamWithResolver(ctx, upstream, resolverNetwork, nil, netip.AddrPort{})
}

func NewUpstreamWithResolver(ctx context.Context, upstream *url.URL, resolverNetwork string, resolverDialer netproxy.Dialer, resolverDNS netip.AddrPort) (up *Upstream, err error) {
	scheme, hostname, port, path, err := ParseRawUpstream(upstream)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}

	systemDns := resolverDNS
	if !systemDns.IsValid() {
		systemDns, err = netutils.SystemDns()
		if err != nil {
			return nil, err
		}
	}
	defer func() {
		if err != nil {
			_ = netutils.TryUpdateSystemDnsElapse(time.Second)
		}
	}()

	if resolverDialer == nil {
		fallbackDNS := ""
		if resolverDNS.IsValid() {
			fallbackDNS = resolverDNS.String()
		}
		resolverDialer = direct.NewDirectDialerLaddr(netip.Addr{}, direct.Option{
			FallbackDNS: fallbackDNS,
		})
	}
	ip46, _, _ := netutils.ResolveIp46(ctx, resolverDialer, systemDns, hostname, resolverNetwork, false)
	if !ip46.Ip4.IsValid() && !ip46.Ip6.IsValid() {
		return nil, fmt.Errorf("dns_upstream %v has no record", upstream.String())
	}

	return &Upstream{
		Scheme:   scheme,
		Hostname: hostname,
		Port:     port,
		Path:     path,
		Ip46:     ip46,
	}, nil
}

func (u *Upstream) SupportedNetworks() (ipversions []consts.IpVersionStr, l4protos []consts.L4ProtoStr) {
	if u.Ip4.IsValid() && u.Ip6.IsValid() {
		ipversions = []consts.IpVersionStr{consts.IpVersionStr_4, consts.IpVersionStr_6}
	} else {
		if u.Ip4.IsValid() {
			ipversions = []consts.IpVersionStr{consts.IpVersionStr_4}
		} else {
			ipversions = []consts.IpVersionStr{consts.IpVersionStr_6}
		}
	}
	switch u.Scheme {
	case UpstreamScheme_TCP, UpstreamScheme_HTTPS, UpstreamScheme_TLS:
		l4protos = []consts.L4ProtoStr{consts.L4ProtoStr_TCP}
	case UpstreamScheme_UDP, UpstreamScheme_QUIC, UpstreamScheme_H3:
		l4protos = []consts.L4ProtoStr{consts.L4ProtoStr_UDP}
	case UpstreamScheme_TCP_UDP:
		// UDP first.
		l4protos = []consts.L4ProtoStr{consts.L4ProtoStr_UDP, consts.L4ProtoStr_TCP}
	}
	return ipversions, l4protos
}

func (u *Upstream) String() string {
	return string(u.Scheme) + "://" + net.JoinHostPort(u.Hostname, strconv.Itoa(int(u.Port))) + u.Path
}

type UpstreamResolver struct {
	Raw     *url.URL
	Network string
	// FinishInitCallback may be invoked again if err is not nil
	FinishInitCallback func(raw *url.URL, upstream *Upstream) (err error)
	Resolve            func(ctx context.Context, upstream *url.URL, resolverNetwork string) (*Upstream, error)
	Now                func() time.Time
	RefreshInterval    time.Duration
	RetryInterval      time.Duration
	mu                 sync.Mutex
	cond               *sync.Cond
	refreshing         bool
	upstream           *Upstream
	init               bool
	nextRefresh        time.Time
}

func (u *UpstreamResolver) GetUpstream() (_ *Upstream, err error) {
	u.mu.Lock()
	if u.cond == nil {
		u.cond = sync.NewCond(&u.mu)
	}

	nowFunc := u.Now
	if nowFunc == nil {
		nowFunc = time.Now
	}
	refreshInterval := u.RefreshInterval
	if refreshInterval <= 0 {
		refreshInterval = DefaultUpstreamRefreshInterval
	}
	retryInterval := u.RetryInterval
	if retryInterval <= 0 {
		retryInterval = DefaultUpstreamRetryInterval
	}
	resolve := u.Resolve
	if resolve == nil {
		resolve = NewUpstream
	}

	for {
		now := nowFunc()
		if u.init && now.Before(u.nextRefresh) {
			upstream := u.upstream
			u.mu.Unlock()
			return upstream, nil
		}
		if u.refreshing {
			u.cond.Wait()
			continue
		}

		u.refreshing = true
		oldUpstream := u.upstream
		raw := u.Raw
		network := u.Network
		finishInit := u.FinishInitCallback
		u.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		newUpstream, resolveErr := resolve(ctx, raw, network)
		cancel()

		var callbackErr error
		if resolveErr == nil && finishInit != nil {
			callbackErr = finishInit(raw, newUpstream)
		}

		u.mu.Lock()
		u.refreshing = false
		now = nowFunc()
		switch {
		case resolveErr != nil:
			recordUpstreamResolverRefreshFailure()
			if oldUpstream != nil {
				recordUpstreamResolverStaleReuse()
				u.nextRefresh = now.Add(retryInterval)
				u.cond.Broadcast()
				u.mu.Unlock()
				return oldUpstream, nil
			}
			u.cond.Broadcast()
			u.mu.Unlock()
			return nil, fmt.Errorf("failed to init dns upstream: %w", resolveErr)
		case callbackErr != nil:
			recordUpstreamResolverRefreshFailure()
			if oldUpstream != nil {
				recordUpstreamResolverStaleReuse()
				u.nextRefresh = now.Add(retryInterval)
				u.cond.Broadcast()
				u.mu.Unlock()
				return oldUpstream, nil
			}
			u.cond.Broadcast()
			u.mu.Unlock()
			return nil, callbackErr
		default:
			recordUpstreamResolverRefreshSuccess()
			u.upstream = newUpstream
			u.init = true
			u.nextRefresh = now.Add(refreshInterval)
			u.cond.Broadcast()
			upstream := u.upstream
			u.mu.Unlock()
			return upstream, nil
		}
	}
}

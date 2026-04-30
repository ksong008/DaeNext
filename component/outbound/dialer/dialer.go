/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/config"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

var (
	UnexpectedFieldErr  = fmt.Errorf("unexpected field")
	InvalidParameterErr = fmt.Errorf("invalid parameters")
)

type Dialer struct {
	*GlobalOption
	InstanceOption
	netproxy.Dialer
	property *Property

	collectionFineMu sync.RWMutex
	collections      [6]*collection

	tickerMu sync.Mutex
	ticker   *time.Ticker
	checkCh  chan time.Time
	ctx      context.Context
	cancel   context.CancelFunc

	probeHTTPTransport *http.Transport
	probeHTTPClient    *http.Client

	checkActivated bool
}

type GlobalOption struct {
	D.ExtraOption
	Log               *logrus.Logger
	TcpCheckOptionRaw TcpCheckOptionRaw // Lazy parse
	CheckDnsOptionRaw CheckDnsOptionRaw // Lazy parse
	CheckInterval     time.Duration
	CheckTolerance    time.Duration
	CheckDnsTcp       bool
	ResolverDialer    netproxy.Dialer
	ResolverFullconeDialer netproxy.Dialer
	ResolverDNS       netip.AddrPort
}

type InstanceOption struct {
	DisableCheck bool
}

type Property struct {
	D.Property
	SubscriptionTag string
	Link            string
}

type AliveDialerSetSet map[*AliveDialerSet]int

func NewGlobalOption(global *config.Global, log *logrus.Logger) *GlobalOption {
	return &GlobalOption{
		ExtraOption: D.ExtraOption{
			AllowInsecure:       global.AllowInsecure,
			TlsImplementation:   global.TlsImplementation,
			UtlsImitate:         global.UtlsImitate,
			BandwidthMaxTx:      global.BandwidthMaxTx,
			BandwidthMaxRx:      global.BandwidthMaxRx,
			TlsFragment:         global.TlsFragment,
			TlsFragmentLength:   global.TlsFragmentLength,
			TlsFragmentInterval: global.TlsFragmentInterval,
			UDPHopInterval:      global.UDPHopInterval,
		},
		Log:               log,
		TcpCheckOptionRaw: TcpCheckOptionRaw{Raw: global.TcpCheckUrl, Log: log, ResolverNetwork: common.MagicNetwork("udp", global.SoMarkFromDae, global.Mptcp), Method: global.TcpCheckHttpMethod},
		CheckDnsOptionRaw: CheckDnsOptionRaw{Raw: global.UdpCheckDns, ResolverNetwork: common.MagicNetwork("udp", global.SoMarkFromDae, global.Mptcp), Somark: global.SoMarkFromDae},
		CheckInterval:     global.CheckInterval,
		CheckTolerance:    global.CheckTolerance,
		CheckDnsTcp:       true,
	}
}

// NewDialer is for register in general.
func NewDialer(dialer netproxy.Dialer, option *GlobalOption, iOption InstanceOption, property *Property) *Dialer {
	var collections [6]*collection
	for i := range collections {
		collections[i] = newCollection()
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &Dialer{
		GlobalOption:     option,
		InstanceOption:   iOption,
		Dialer:           dialer,
		property:         property,
		collectionFineMu: sync.RWMutex{},
		collections:      collections,
		tickerMu:         sync.Mutex{},
		ticker:           nil,
		checkCh:          make(chan time.Time, 1),
		ctx:              ctx,
		cancel:           cancel,
	}
	d.probeHTTPTransport = &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			cfg, _ := ctx.Value(probeRequestContextKey{}).(*probeRequestConfig)
			if cfg == nil {
				return nil, fmt.Errorf("missing probe request config")
			}
			conn, err := d.Dialer.DialContext(ctx, common.MagicNetwork("tcp", cfg.soMark, cfg.mptcp), net.JoinHostPort(cfg.ip.String(), cfg.port))
			if err != nil {
				return nil, err
			}
			return &netproxy.FakeNetConn{
				Conn:  conn,
				LAddr: nil,
				RAddr: nil,
			}, nil
		},
	}
	d.probeHTTPClient = &http.Client{
		Transport: d.probeHTTPTransport,
	}
	option.Log.WithField("dialer", d.Property().Name).
		WithField("p", unsafe.Pointer(d)).
		Traceln("NewDialer")
	return d
}

func (d *Dialer) Clone() *Dialer {
	return NewDialer(d.Dialer, d.GlobalOption, d.InstanceOption, d.property)
}

func (d *Dialer) Close() error {
	d.cancel()
	d.tickerMu.Lock()
	if d.ticker != nil {
		d.ticker.Stop()
		d.ticker = nil
	}
	d.tickerMu.Unlock()
	if d.probeHTTPTransport != nil {
		d.probeHTTPTransport.CloseIdleConnections()
	}
	return nil
}

func (d *Dialer) Property() *Property {
	return d.property
}

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type Endpoint struct {
	TCP  bool
	UDP  bool
	Addr string
}

var ErrBadLocalDNSBindFormat = errors.New("bad local dns bind format")

func ParseEndpoint(raw string) (endpoint Endpoint, err error) {
	_, perr := netip.ParseAddrPort(raw)
	if perr == nil {
		// try ip addr first
		return Endpoint{false, true, raw}, nil
	}
	// try tcp+udp://127.0.0.1:5335
	u, perr := url.Parse(raw)
	if perr != nil {
		err = fmt.Errorf("%w: %v", ErrBadLocalDNSBindFormat, perr)
		return
	}

	// scheme maybe "tcp+udp"
	schemes := strings.Split(u.Scheme, "+")

	endpoint.Addr = u.Host
	for _, s := range schemes {
		switch s {
		case "udp":
			endpoint.UDP = true
		case "tcp":
			endpoint.TCP = true
		default:
			err = fmt.Errorf(
				"%w: unsupported protocol: %s for %s",
				ErrBadLocalDNSBindFormat, s, raw,
			)
			return
		}
	}

	return
}

type DNSListener struct {
	log        *logrus.Logger
	tcpServer  *dnsmessage.Server
	udpServer  *dnsmessage.Server
	endpoint   Endpoint
	controller *ControlPlane
	mu         sync.Mutex
}

// NewDNSListener creates a new DNS listener
func NewDNSListener(log *logrus.Logger, endpoint string, controller *ControlPlane) (*DNSListener, error) {
	e, err := ParseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}

	ret := &DNSListener{
		log:        log,
		controller: controller,
		endpoint:   e,
	}

	return ret, nil
}

func (d *DNSListener) Addr() string {
	return d.endpoint.Addr
}

// Start starts the DNS listener
func (d *DNSListener) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.udpServer != nil {
		return fmt.Errorf("DNS udp listener already started")
	}
	if d.tcpServer != nil {
		return fmt.Errorf("DNS tcp listener already started")
	}

	// Create DNS handler
	handler := &dnsHandler{
		controller: d.controller,
		log:        d.log,
	}

	startServer := func(server *dnsmessage.Server, started chan struct{}, bindErr error) error {
		if bindErr != nil {
			return bindErr
		}
		server.NotifyStartedFunc = func() {
			select {
			case <-started:
			default:
				close(started)
			}
		}
		go func() {
			if err := server.ActivateAndServe(); err != nil && !isExpectedDNSListenerClose(err) {
				d.log.Errorf("DNS %s listener stopped unexpectedly: %v", server.Net, err)
			}
		}()

		select {
		case <-started:
			return nil
		case <-time.After(time.Second):
			return fmt.Errorf("dns %s listener start timeout", server.Net)
		}
	}

	if d.endpoint.UDP {
		pc, err := net.ListenPacket("udp", d.Addr())
		if err != nil {
			return fmt.Errorf("listen udp dns: %w", err)
		}
		d.udpServer = &dnsmessage.Server{
			Net:        "udp",
			PacketConn: pc,
			Handler:    handler,
			UDPSize:    65535,
		}
		started := make(chan struct{})
		if err := startServer(d.udpServer, started, nil); err != nil {
			_ = d.udpServer.PacketConn.Close()
			d.udpServer = nil
			return err
		}
		d.log.Debugf("Started DNS UDP listener on %s", d.Addr())
	}
	// also for tcp server
	if d.endpoint.TCP {
		ln, err := net.Listen("tcp", d.Addr())
		if err != nil {
			if d.udpServer != nil {
				_ = d.udpServer.Shutdown()
				d.udpServer = nil
			}
			return fmt.Errorf("listen tcp dns: %w", err)
		}
		d.tcpServer = &dnsmessage.Server{
			Net:      "tcp",
			Listener: ln,
			Handler:  handler,
		}
		started := make(chan struct{})
		if err := startServer(d.tcpServer, started, nil); err != nil {
			_ = d.tcpServer.Listener.Close()
			d.tcpServer = nil
			if d.udpServer != nil {
				_ = d.udpServer.Shutdown()
				d.udpServer = nil
			}
			return err
		}
		d.log.Debugf("Started DNS TCP listener on %s", d.Addr())
	}

	return nil
}

// Stop stops the DNS listener
func (d *DNSListener) Stop() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	var errs []error

	// Stop UDP server
	if d.udpServer != nil {
		if err := d.udpServer.Shutdown(); err != nil {
			errs = append(errs, err)
		}
		d.udpServer = nil
	}

	// Stop TCP server
	if d.tcpServer != nil {
		if err := d.tcpServer.Shutdown(); err != nil {
			errs = append(errs, err)
		}
		d.tcpServer = nil
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to stop DNS servers: %v", errors.Join(errs...))
	}
	return nil
}

func isExpectedDNSListenerClose(err error) bool {
	if err == nil {
		return true
	}
	return strings.Contains(err.Error(), "server not started") ||
		strings.Contains(err.Error(), "use of closed network connection") ||
		errors.Is(err, net.ErrClosed)
}

// dnsHandler implements the dns.Handler interface
type dnsHandler struct {
	controller *ControlPlane
	log        *logrus.Logger
}

func addrPortFromNetAddr(addr net.Addr) (netip.AddrPort, error) {
	switch addr := addr.(type) {
	case *net.UDPAddr:
		return addrPortFromIPPort(addr.IP, addr.Port, addr.Zone)
	case *net.TCPAddr:
		return addrPortFromIPPort(addr.IP, addr.Port, addr.Zone)
	}

	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("failed to parse address %q: %w", addr.String(), err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("failed to parse port %q: %w", portStr, err)
	}
	return addrPortFromHostPort(host, port)
}

func addrPortFromIPPort(ip net.IP, port int, zone string) (netip.AddrPort, error) {
	if port < 0 || port > 65535 {
		return netip.AddrPort{}, fmt.Errorf("invalid port: %d", port)
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("failed to parse ip %q", ip.String())
	}
	addr = addr.Unmap()
	if zone != "" {
		addr = addr.WithZone(zone)
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}

func addrPortFromHostPort(host string, port int) (netip.AddrPort, error) {
	if port < 0 || port > 65535 {
		return netip.AddrPort{}, fmt.Errorf("invalid port: %d", port)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("failed to parse host %q: %w", host, err)
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}

// ServeDNS handles DNS requests
func (h *dnsHandler) ServeDNS(w dnsmessage.ResponseWriter, r *dnsmessage.Msg) {
	// Create a fake udpRequest to pass to the DNS controller
	clientIPPort, err := addrPortFromNetAddr(w.RemoteAddr())
	if err != nil {
		h.log.Errorf("Failed to parse client address: %v", err)
		return
	}
	localIPPort, err := addrPortFromNetAddr(w.LocalAddr())
	if err != nil {
		h.log.Errorf("Failed to parse local listener address: %v", err)
		return
	}

	// Create routing result (fake)
	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundControlPlaneRouting),
		Mark:     0,
		Must:     0,
		Mac:      [6]uint8{},
		Pname:    [16]uint8{},
		Pid:      0,
		Dscp:     0,
	}

	// Handle the DNS request using the existing DNS controller
	reqCtx, cancel := context.WithCancel(contextOrBackground(h.controller.ctx))
	defer cancel()
	udpReq := &udpRequest{
		ctx:           reqCtx,
		realSrc:       clientIPPort,
		realDst:       localIPPort,
		src:           clientIPPort,
		lConn:         nil, // Not used in this context
		routingResult: routingResult,
	}

	err = h.controller.dnsController.HandleWithResponseWriter_(r, udpReq, w)
	if err != nil {
		h.log.Errorf("Failed to handle DNS request: %v", err)
		// Send error response
		m := new(dnsmessage.Msg)
		m.SetRcode(r, dnsmessage.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}
}

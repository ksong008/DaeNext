/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"

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

	if d.endpoint.UDP {
		// create dns servers
		d.udpServer = &dnsmessage.Server{
			Addr:    d.Addr(),
			Net:     "udp",
			Handler: handler,
			UDPSize: 65535,
		}

		// Start UDP server in goroutine
		go func() {
			d.log.Infof("Starting DNS UDP listener on %s", d.udpServer.Addr)
			if err := d.udpServer.ListenAndServe(); err != nil {
				d.log.Errorf("Failed to start DNS UDP listener: %v", err)
			}
		}()

	}
	// also for tcp server
	if d.endpoint.TCP {
		d.tcpServer = &dnsmessage.Server{
			Addr:    d.Addr(),
			Net:     "tcp",
			Handler: handler,
		}
		// Start TCP server in goroutine
		go func() {
			d.log.Infof("Starting DNS TCP listener on %s", d.tcpServer.Addr)
			if err := d.tcpServer.ListenAndServe(); err != nil {
				d.log.Errorf("Failed to start DNS TCP listener: %v", err)
			}
		}()
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
	udpReq := &udpRequest{
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

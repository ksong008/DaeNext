/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
*/

package control

import (
	"context"
	"crypto/tls"
	"errors"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	tc "github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
	dnsmessage "github.com/miekg/dns"
)

type DnsForwarder interface {
	ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error)
	Close() error
}

func dnsForwarderReusable(upstream *dns.Upstream, dialArgument dialArgument) bool {
	switch dialArgument.l4proto {
	case consts.L4ProtoStr_TCP:
		return upstream.Scheme == dns.UpstreamScheme_HTTPS
	case consts.L4ProtoStr_UDP:
		return upstream.Scheme == dns.UpstreamScheme_H3 ||
			upstream.Scheme == dns.UpstreamScheme_QUIC
	default:
		return false
	}
}

func newDnsForwarder(upstream *dns.Upstream, dialArgument dialArgument) (DnsForwarder, error) {
	forwarder, err := func() (DnsForwarder, error) {
		switch dialArgument.l4proto {
		case consts.L4ProtoStr_TCP:
			switch upstream.Scheme {
			case dns.UpstreamScheme_TCP, dns.UpstreamScheme_TCP_UDP:
				return &DoTCP{Upstream: *upstream, Dialer: dialArgument.bestDialer, dialArgument: dialArgument}, nil
			case dns.UpstreamScheme_TLS:
				return &DoTLS{Upstream: *upstream, Dialer: dialArgument.bestDialer, dialArgument: dialArgument}, nil
			case dns.UpstreamScheme_HTTPS:
				return &DoH{Upstream: *upstream, Dialer: dialArgument.bestDialer, dialArgument: dialArgument, http3: false}, nil
			default:
				return nil, fmt.Errorf("unexpected scheme: %v", upstream.Scheme)
			}
		case consts.L4ProtoStr_UDP:
			switch upstream.Scheme {
			case dns.UpstreamScheme_UDP, dns.UpstreamScheme_TCP_UDP:
				return &DoUDP{Upstream: *upstream, Dialer: dialArgument.bestDialer, dialArgument: dialArgument}, nil
			case dns.UpstreamScheme_QUIC:
				return &DoQ{Upstream: *upstream, Dialer: dialArgument.bestDialer, dialArgument: dialArgument}, nil
			case dns.UpstreamScheme_H3:
				return &DoH{Upstream: *upstream, Dialer: dialArgument.bestDialer, dialArgument: dialArgument, http3: true}, nil
			default:
				return nil, fmt.Errorf("unexpected scheme: %v", upstream.Scheme)
			}
		default:
			return nil, fmt.Errorf("unexpected l4proto: %v", dialArgument.l4proto)
		}
	}()
	if err != nil {
		return nil, err
	}
	return forwarder, nil
}

type DoH struct {
	dns.Upstream
	netproxy.Dialer
	dialArgument dialArgument
	http3        bool
	mu           sync.Mutex
	client       *http.Client
	transport    http.RoundTripper
}

func (d *DoH) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	return sendHttpDNS(ctx, d.getClient(), d.dialArgument.bestTarget.String(), &d.Upstream, data)
}

func (d *DoH) getClient() *http.Client {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.client == nil {
		if d.http3 {
			d.transport = d.getHttp3RoundTripper()
		} else {
			d.transport = d.getHttpRoundTripper()
		}
		d.client = &http.Client{
			Transport: d.transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return fmt.Errorf("do not use a server that will redirect, upstream: %v", d.Upstream.String())
			},
		}
	}
	return d.client
}

func (d *DoH) getHttpRoundTripper() *http.Transport {
	httpTransport := http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         d.Upstream.Hostname,
			InsecureSkipVerify: false,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := d.dialArgument.bestDialer.DialContext(
				ctx,
				common.MagicNetwork("tcp", d.dialArgument.mark, d.dialArgument.mptcp),
				d.dialArgument.bestTarget.String(),
			)
			if err != nil {
				return nil, err
			}
			return &netproxy.FakeNetConn{Conn: conn}, nil
		},
	}

	return &httpTransport
}

func (d *DoH) getHttp3RoundTripper() *http3.RoundTripper {
	roundTripper := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			ServerName:         d.Upstream.Hostname,
			NextProtos:         []string{"h3"},
			InsecureSkipVerify: false,
		},
		QUICConfig: &quic.Config{},
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			udpAddr := net.UDPAddrFromAddrPort(d.dialArgument.bestTarget)
			conn, err := d.dialArgument.bestDialer.DialContext(
				ctx,
				common.MagicNetwork("udp", d.dialArgument.mark, d.dialArgument.mptcp),
				d.dialArgument.bestTarget.String(),
			)
			if err != nil {
				return nil, err
			}
			fakePkt := netproxy.NewFakeNetPacketConn(conn.(netproxy.PacketConn), net.UDPAddrFromAddrPort(tc.GetUniqueFakeAddrPort()), udpAddr)
			c, e := quic.DialEarly(ctx, fakePkt, udpAddr, tlsCfg, cfg)
			return c, e
		},
	}
	return roundTripper
}

func (d *DoH) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	var err error
	switch transport := d.transport.(type) {
	case interface{ Close() error }:
		err = transport.Close()
	case interface{ CloseIdleConnections() }:
		transport.CloseIdleConnections()
	}
	d.client = nil
	d.transport = nil
	return err
}

type DoQ struct {
	dns.Upstream
	netproxy.Dialer
	dialArgument dialArgument
	mu          sync.Mutex
	connection   quic.EarlyConnection
}

func (d *DoQ) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	conn, err := d.getConnection(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		conn, err = d.replaceConnection(ctx, conn)
		if err != nil {
			return nil, err
		}
		stream, err = conn.OpenStreamSync(ctx)
		if err != nil {
			return nil, err
		}
	}
	defer func() {
		_ = stream.Close()
	}()

	// According https://datatracker.ietf.org/doc/html/rfc9250#section-4.2.1
	// msg id should set to 0 when transport over QUIC.
	// thanks https://github.com/natesales/q/blob/1cb2639caf69bd0a9b46494a3c689130df8fb24a/transport/quic.go#L97
	msg, err := sendStreamDNS(stream, dnsDataWithZeroID(data))
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func (d *DoQ) getConnection(ctx context.Context) (quic.EarlyConnection, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.connection == nil {
		qc, err := d.createConnection(ctx)
		if err != nil {
			return nil, err
		}
		d.connection = qc
	}
	return d.connection, nil
}

func (d *DoQ) replaceConnection(ctx context.Context, stale quic.EarlyConnection) (quic.EarlyConnection, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if stale != nil && d.connection == stale {
		_ = stale.CloseWithError(0, "")
		d.connection = nil
	}
	if d.connection == nil {
		qc, err := d.createConnection(ctx)
		if err != nil {
			return nil, err
		}
		d.connection = qc
	}
	return d.connection, nil
}

func (d *DoQ) createConnection(ctx context.Context) (quic.EarlyConnection, error) {

	udpAddr := net.UDPAddrFromAddrPort(d.dialArgument.bestTarget)
	conn, err := d.dialArgument.bestDialer.DialContext(
		ctx,
		common.MagicNetwork("udp", d.dialArgument.mark, d.dialArgument.mptcp),
		d.dialArgument.bestTarget.String(),
	)
	if err != nil {
		return nil, err
	}

	fakePkt := netproxy.NewFakeNetPacketConn(conn.(netproxy.PacketConn), net.UDPAddrFromAddrPort(tc.GetUniqueFakeAddrPort()), udpAddr)
	tlsCfg := &tls.Config{
		NextProtos:         []string{"doq"},
		InsecureSkipVerify: false,
		ServerName:         d.Upstream.Hostname,
	}
	addr := net.UDPAddrFromAddrPort(d.dialArgument.bestTarget)
	qc, err := quic.DialEarly(ctx, fakePkt, addr, tlsCfg, nil)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return qc, nil

}

func (d *DoQ) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.connection != nil {
		err := d.connection.CloseWithError(0, "")
		d.connection = nil
		return err
	}
	return nil
}

type DoTLS struct {
	dns.Upstream
	netproxy.Dialer
	dialArgument dialArgument
	conn         netproxy.Conn
}

func (d *DoTLS) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	conn, err := d.dialArgument.bestDialer.DialContext(
		ctx,
		common.MagicNetwork("tcp", d.dialArgument.mark, d.dialArgument.mptcp),
		d.dialArgument.bestTarget.String(),
	)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(&netproxy.FakeNetConn{Conn: conn}, &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         d.Upstream.Hostname,
	})
	if err = tlsConn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	d.conn = tlsConn

	return sendStreamDNS(tlsConn, data)
}

func (d *DoTLS) Close() error {
	if d.conn != nil {
		conn := d.conn
		d.conn = nil
		return conn.Close()
	}
	return nil
}

type DoTCP struct {
	dns.Upstream
	netproxy.Dialer
	dialArgument dialArgument
	conn         netproxy.Conn
}

func (d *DoTCP) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	conn, err := d.dialArgument.bestDialer.DialContext(
		ctx,
		common.MagicNetwork("tcp", d.dialArgument.mark, d.dialArgument.mptcp),
		d.dialArgument.bestTarget.String(),
	)
	if err != nil {
		return nil, err
	}

	d.conn = conn
	return sendStreamDNS(conn, data)
}

func (d *DoTCP) Close() error {
	if d.conn != nil {
		conn := d.conn
		d.conn = nil
		return conn.Close()
	}
	return nil
}

type DoUDP struct {
	dns.Upstream
	netproxy.Dialer
	dialArgument dialArgument
	conn         netproxy.Conn
}

func (d *DoUDP) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	conn, err := d.dialArgument.bestDialer.DialContext(
		ctx,
		common.MagicNetwork("udp", d.dialArgument.mark, d.dialArgument.mptcp),
		d.dialArgument.bestTarget.String(),
	)
	if err != nil {
		return nil, err
	}
	d.conn = conn

	timeout := dnsForwardTimeout(ctx)
	if timeout <= 0 {
		return nil, context.DeadlineExceeded
	}
	deadline := time.Now().Add(timeout)

	respBuf := pool.GetFullCap(consts.EthernetMtu)
	defer pool.Put(respBuf)

	for attempt := 0; attempt < dnsUDPAttempts; attempt++ {
		perAttemptDeadline := deadline
		if attempt < dnsUDPAttempts-1 {
			if retryDeadline := time.Now().Add(dnsUDPRetryInterval); retryDeadline.Before(perAttemptDeadline) {
				perAttemptDeadline = retryDeadline
			}
		}
		if err := conn.SetDeadline(perAttemptDeadline); err != nil {
			return nil, err
		}
		if _, err = conn.Write(data); err != nil {
			return nil, err
		}
		n, err := conn.Read(respBuf)
		if err == nil {
			var msg dnsmessage.Msg
			if err = msg.Unpack(respBuf[:n]); err != nil {
				return nil, err
			}
			return &msg, nil
		}

		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !shouldRetryUDPQuery(err) || attempt == dnsUDPAttempts-1 || time.Now().After(deadline) {
			return nil, err
		}
	}
	return nil, context.DeadlineExceeded
}

func (d *DoUDP) Close() error {
	if d.conn != nil {
		conn := d.conn
		d.conn = nil
		return conn.Close()
	}
	return nil
}

const (
	dnsUDPAttempts      = 3
	dnsUDPRetryInterval = time.Second
	dnsUDPTimeout       = 5 * time.Second
)

func dnsForwardTimeout(ctx context.Context) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		timeout := time.Until(deadline)
		if timeout < dnsUDPTimeout {
			return timeout
		}
	}
	return dnsUDPTimeout
}

func shouldRetryUDPQuery(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func dnsDataWithZeroID(data []byte) []byte {
	cloned := append([]byte(nil), data...)
	if len(cloned) >= 2 {
		binary.BigEndian.PutUint16(cloned[0:2], 0)
	}
	return cloned
}

const doHMaxResponseBytes = 64 * 1024

func sendHttpDNS(ctx context.Context, client *http.Client, target string, upstream *dns.Upstream, data []byte) (respMsg *dnsmessage.Msg, err error) {
	serverURL := url.URL{
		Scheme: "https",
		Host:   target,
		Path:   upstream.Path,
	}
	q := serverURL.Query()
	// According https://datatracker.ietf.org/doc/html/rfc8484#section-4
	// msg id should set to 0 when transport over HTTPS for cache friendly.
	q.Set("dns", base64.RawURLEncoding.EncodeToString(dnsDataWithZeroID(data)))
	serverURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serverURL.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Host = upstream.Hostname
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	buf, err := io.ReadAll(io.LimitReader(resp.Body, doHMaxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(buf) > doHMaxResponseBytes {
		return nil, fmt.Errorf("dns response too large: %d bytes", len(buf))
	}
	var msg dnsmessage.Msg
	if err = msg.Unpack(buf); err != nil {
		return nil, err
	}
	return &msg, nil
}

func sendStreamDNS(stream io.ReadWriter, data []byte) (respMsg *dnsmessage.Msg, err error) {
	// We should write two byte length in the front of stream DNS request.
	bReq := pool.Get(2 + len(data))
	defer pool.Put(bReq)
	binary.BigEndian.PutUint16(bReq, uint16(len(data)))
	copy(bReq[2:], data)
	_, err = stream.Write(bReq)
	if err != nil {
		return nil, fmt.Errorf("failed to write DNS req: %w", err)
	}

	// Read two byte length.
	if _, err = io.ReadFull(stream, bReq[:2]); err != nil {
		return nil, fmt.Errorf("failed to read DNS resp payload length: %w", err)
	}
	respLen := int(binary.BigEndian.Uint16(bReq))
	// Try to reuse the buf.
	var buf []byte
	if len(bReq) < respLen {
		buf = pool.Get(respLen)
		defer pool.Put(buf)
	} else {
		buf = bReq
	}
	var n int
	if n, err = io.ReadFull(stream, buf[:respLen]); err != nil {
		return nil, fmt.Errorf("failed to read DNS resp payload: %w", err)
	}
	var msg dnsmessage.Msg
	if err = msg.Unpack(buf[:n]); err != nil {
		return nil, err
	}
	return &msg, nil
}

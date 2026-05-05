package netutils

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
)

type chunkedDNSDialer struct {
	conn    *chunkedDNSConn
	network string
	addr    string
}

func (d *chunkedDNSDialer) DialContext(_ context.Context, network, addr string) (netproxy.Conn, error) {
	d.network = network
	d.addr = addr
	return d.conn, nil
}

type chunkedDNSConn struct {
	chunks [][]byte
}

func (c *chunkedDNSConn) Read(p []byte) (int, error) {
	for len(c.chunks) > 0 && len(c.chunks[0]) == 0 {
		c.chunks = c.chunks[1:]
	}
	if len(c.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.chunks[0])
	c.chunks[0] = c.chunks[0][n:]
	return n, nil
}

func (c *chunkedDNSConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *chunkedDNSConn) Close() error                { return nil }
func (c *chunkedDNSConn) SetDeadline(time.Time) error { return nil }
func (c *chunkedDNSConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *chunkedDNSConn) SetWriteDeadline(time.Time) error {
	return nil
}

func TestResolveNetipTCPReadsFullResponseBody(t *testing.T) {
	req := new(dnsmessage.Msg)
	req.SetQuestion("example.com.", dnsmessage.TypeA)
	resp := new(dnsmessage.Msg)
	resp.SetReply(req)
	resp.Answer = []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   dnsmessage.CanonicalName("example.com."),
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    60,
			},
			A: net.ParseIP("1.2.3.4").To4(),
		},
	}
	payload, err := resp.Pack()
	if err != nil {
		t.Fatalf("pack dns response: %v", err)
	}
	wire := append([]byte{byte(len(payload) >> 8), byte(len(payload))}, payload...)
	chunks := make([][]byte, len(wire))
	for i, b := range wire {
		chunks[i] = []byte{b}
	}

	dialer := &chunkedDNSDialer{conn: &chunkedDNSConn{chunks: chunks}}
	addrs, err := ResolveNetip(context.Background(), dialer, netip.MustParseAddrPort("1.1.1.1:53"), "example.com", dnsmessage.TypeA, "tcp")
	if err != nil {
		t.Fatalf("ResolveNetip tcp: %v", err)
	}
	if dialer.network != "tcp" {
		t.Fatalf("network = %q, want tcp", dialer.network)
	}
	if dialer.addr != "1.1.1.1:53" {
		t.Fatalf("addr = %q, want 1.1.1.1:53", dialer.addr)
	}
	if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("1.2.3.4") {
		t.Fatalf("addrs = %v, want [1.2.3.4]", addrs)
	}
}

type packetDNSDialer struct {
	conn    *packetDNSConn
	network string
	addr    string
}

func (d *packetDNSDialer) DialContext(_ context.Context, network, addr string) (netproxy.Conn, error) {
	d.network = network
	d.addr = addr
	return d.conn, nil
}

type packetDNSConn struct {
	response []byte
	writeTo  string
}

func (c *packetDNSConn) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func (c *packetDNSConn) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func (c *packetDNSConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	n := copy(p, c.response)
	return n, netip.MustParseAddrPort("1.1.1.1:53"), nil
}

func (c *packetDNSConn) WriteTo(p []byte, addr string) (int, error) {
	c.writeTo = addr
	return len(p), nil
}

func (c *packetDNSConn) Close() error                { return nil }
func (c *packetDNSConn) SetDeadline(time.Time) error { return nil }
func (c *packetDNSConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *packetDNSConn) SetWriteDeadline(time.Time) error {
	return nil
}

func TestResolveNetipUDPUsesPacketConnSemantics(t *testing.T) {
	req := new(dnsmessage.Msg)
	req.SetQuestion("example.com.", dnsmessage.TypeA)
	resp := new(dnsmessage.Msg)
	resp.SetReply(req)
	resp.Answer = []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   dnsmessage.CanonicalName("example.com."),
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    60,
			},
			A: net.ParseIP("5.6.7.8").To4(),
		},
	}
	payload, err := resp.Pack()
	if err != nil {
		t.Fatalf("pack dns response: %v", err)
	}

	dialer := &packetDNSDialer{conn: &packetDNSConn{response: payload}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	addrs, err := ResolveNetip(ctx, dialer, netip.MustParseAddrPort("1.1.1.1:53"), "example.com", dnsmessage.TypeA, "udp")
	if err != nil {
		if strings.Contains(err.Error(), "io: read/write on closed pipe") {
			t.Fatalf("ResolveNetip udp used stream Write/Read instead of PacketConn helpers: %v", err)
		}
		t.Fatalf("ResolveNetip udp: %v", err)
	}
	if dialer.network != "udp" {
		t.Fatalf("network = %q, want udp", dialer.network)
	}
	if dialer.addr != "1.1.1.1:53" {
		t.Fatalf("addr = %q, want 1.1.1.1:53", dialer.addr)
	}
	if dialer.conn.writeTo != "1.1.1.1:53" {
		t.Fatalf("WriteTo addr = %q, want 1.1.1.1:53", dialer.conn.writeTo)
	}
	if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("5.6.7.8") {
		t.Fatalf("addrs = %v, want [5.6.7.8]", addrs)
	}
}

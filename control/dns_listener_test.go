/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	componentdns "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type fakeDNSResponseWriter struct {
	localAddr     net.Addr
	remoteAddr    net.Addr
	msg           *dnsmessage.Msg
	writeMsgCount int
}

func (f *fakeDNSResponseWriter) LocalAddr() net.Addr {
	return f.localAddr
}

func (f *fakeDNSResponseWriter) RemoteAddr() net.Addr {
	return f.remoteAddr
}

func (f *fakeDNSResponseWriter) WriteMsg(msg *dnsmessage.Msg) error {
	f.writeMsgCount++
	if msg != nil {
		f.msg = msg.Copy()
	}
	return nil
}

func (f *fakeDNSResponseWriter) Write([]byte) (int, error) {
	return 0, nil
}

func (f *fakeDNSResponseWriter) Close() error {
	return nil
}

func (f *fakeDNSResponseWriter) TsigStatus() error {
	return nil
}

func (f *fakeDNSResponseWriter) TsigTimersOnly(bool) {}

func (f *fakeDNSResponseWriter) Hijack() {}

func TestParseEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantTCP  bool
		wantUDP  bool
		wantAddr string
		wantErr  bool
	}{
		{
			name:     "raw addr defaults to udp",
			raw:      "127.0.0.1:5353",
			wantTCP:  false,
			wantUDP:  true,
			wantAddr: "127.0.0.1:5353",
		},
		{
			name:     "tcp and udp url",
			raw:      "tcp+udp://127.0.0.1:5353",
			wantTCP:  true,
			wantUDP:  true,
			wantAddr: "127.0.0.1:5353",
		},
		{
			name:    "bad scheme",
			raw:     "unix://127.0.0.1:5353",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseEndpoint(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tt.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseEndpoint(%q) returned error: %v", tt.raw, err)
			}
			if got.TCP != tt.wantTCP || got.UDP != tt.wantUDP || got.Addr != tt.wantAddr {
				t.Fatalf("ParseEndpoint(%q) = %+v, want TCP=%v UDP=%v Addr=%q", tt.raw, got, tt.wantTCP, tt.wantUDP, tt.wantAddr)
			}
		})
	}
}

func TestAddrPortFromNetAddr(t *testing.T) {
	tests := []struct {
		name string
		addr net.Addr
		want netip.AddrPort
	}{
		{
			name: "udp ipv4",
			addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353},
			want: netip.MustParseAddrPort("127.0.0.1:5353"),
		},
		{
			name: "tcp ipv6",
			addr: &net.TCPAddr{IP: net.ParseIP("::1"), Port: 853},
			want: netip.MustParseAddrPort("[::1]:853"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := addrPortFromNetAddr(tt.addr)
			if err != nil {
				t.Fatalf("addrPortFromNetAddr(%v) returned error: %v", tt.addr, err)
			}
			if got != tt.want {
				t.Fatalf("addrPortFromNetAddr(%v) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func TestHandleWithResponseWriterRejectsAsIsForLocalListener(t *testing.T) {
	routing, err := componentdns.New(&config.Dns{
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Fallback: "asis",
			},
			Response: config.DnsResponseRouting{
				Fallback: "accept",
			},
		},
	}, &componentdns.NewOption{
		Logger: logrus.New(),
		UpstreamReadyCallback: func(*componentdns.Upstream) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("failed to build dns routing: %v", err)
	}

	controller, err := NewDnsController(routing, &DnsControllerOption{
		Log: logrus.New(),
		CacheAccessCallback: func(*DnsCache) error {
			return nil
		},
		CacheRemoveCallback: func(*DnsCache) error {
			return nil
		},
		NewCache: func(_ string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			return &DnsCache{
				Answer:           answers,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
		BestDialerChooser: func(*udpRequest, *componentdns.Upstream) (*dialArgument, error) {
			t.Fatalf("BestDialerChooser should not be called when local dns listener uses asis")
			return nil, nil
		},
		TimeoutExceedCallback: func(*dialArgument, error) {},
	})
	if err != nil {
		t.Fatalf("failed to create dns controller: %v", err)
	}

	req := new(dnsmessage.Msg)
	req.SetQuestion("example.com.", dnsmessage.TypeA)

	err = controller.handleWithResponseWriter_(req, &udpRequest{
		ctx:     context.Background(),
		realSrc: netip.MustParseAddrPort("127.0.0.1:43210"),
		realDst: netip.MustParseAddrPort("127.0.0.1:5353"),
		src:     netip.MustParseAddrPort("127.0.0.1:43210"),
	}, true, &fakeDNSResponseWriter{
		localAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353},
		remoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 43210},
	})
	if err == nil {
		t.Fatal("expected local dns listener to reject asis")
	}
	if !strings.Contains(err.Error(), "asis") {
		t.Fatalf("expected error to mention asis, got: %v", err)
	}
}

func TestHandleWithResponseWriterWritesFirstMissFromUpstream(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	routing, err := componentdns.New(&config.Dns{
		Upstream: []config.KeyableString{
			"test:udp://1.1.1.1:53",
		},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Fallback: "test",
			},
			Response: config.DnsResponseRouting{
				Fallback: "accept",
			},
		},
	}, &componentdns.NewOption{
		Logger: log,
		UpstreamReadyCallback: func(*componentdns.Upstream) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("failed to build dns routing: %v", err)
	}

	controller, err := NewDnsController(routing, &DnsControllerOption{
		Log:                 log,
		CacheAccessCallback: func(*DnsCache) error { return nil },
		CacheRemoveCallback: func(*DnsCache) error { return nil },
		NewCache: func(_ string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			ips, hasAnyIP := summarizeDNSAnswers(answers)
			return &DnsCache{
				Answer:           answers,
				IPs:              ips,
				HasAnyIP:         hasAnyIP,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
		BestDialerChooser: func(*udpRequest, *componentdns.Upstream) (*dialArgument, error) {
			return &dialArgument{
				l4proto:   consts.L4ProtoStr_UDP,
				ipversion: consts.IpVersionStr_4,
			}, nil
		},
		TimeoutExceedCallback: func(*dialArgument, error) {},
	})
	if err != nil {
		t.Fatalf("failed to create dns controller: %v", err)
	}
	defer controller.Close()

	forwardCalls := 0
	controller.forwarderFactory = func(*componentdns.Upstream, dialArgument) (DnsForwarder, error) {
		return &fakeDnsForwarder{forward: func(_ context.Context, data []byte) (*dnsmessage.Msg, error) {
			forwardCalls++
			req := new(dnsmessage.Msg)
			if err := req.Unpack(data); err != nil {
				return nil, err
			}
			resp := new(dnsmessage.Msg)
			resp.SetReply(req)
			resp.Answer = []dnsmessage.RR{newTestARecord(req.Question[0].Name, "1.1.1.1")}
			return resp, nil
		}}, nil
	}

	req := new(dnsmessage.Msg)
	req.SetQuestion("first-miss.example.", dnsmessage.TypeA)
	req.Id = 0x1234
	writer := &fakeDNSResponseWriter{
		localAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353},
		remoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 43210},
	}

	err = controller.handleWithResponseWriter_(req, &udpRequest{
		ctx:     context.Background(),
		realSrc: netip.MustParseAddrPort("127.0.0.1:43210"),
		realDst: netip.MustParseAddrPort("127.0.0.1:5353"),
		src:     netip.MustParseAddrPort("127.0.0.1:43210"),
	}, true, writer)
	if err != nil {
		t.Fatalf("handleWithResponseWriter_() returned error: %v", err)
	}
	if forwardCalls != 1 {
		t.Fatalf("expected one upstream lookup for first miss, got %d", forwardCalls)
	}
	if writer.writeMsgCount != 1 {
		t.Fatalf("expected first miss to write through response writer once, got %d", writer.writeMsgCount)
	}
	if writer.msg == nil {
		t.Fatal("expected response writer to receive a DNS response")
	}
	if writer.msg.Id != req.Id {
		t.Fatalf("response id = %d, want %d", writer.msg.Id, req.Id)
	}
	if len(writer.msg.Answer) != 1 {
		t.Fatalf("response answers = %d, want 1", len(writer.msg.Answer))
	}
}

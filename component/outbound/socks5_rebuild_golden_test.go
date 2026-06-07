/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	outboundcommon "github.com/daeuniverse/outbound/common"
	outbounddialer "github.com/daeuniverse/outbound/dialer"
	_ "github.com/daeuniverse/outbound/dialer/socks"
	"github.com/daeuniverse/outbound/netproxy"
	outboundsocks "github.com/daeuniverse/outbound/protocol/infra/socks"
	outboundsocks5 "github.com/daeuniverse/outbound/protocol/socks5"
)

const outboundGoldenUpdateEnv = "DAE_UPDATE_REBUILD_GOLDEN"

func TestWriteSocks5NativeOptInGoldenFixture(t *testing.T) {
	writeOrCheckOutboundGolden(t,
		"../../testdata/rebuild-golden/outbound/protocol/socks5_native_optin.json",
		rebuildGoldenNativeSocks5NativeOptIn(t),
	)
}

func rebuildGoldenNativeSocks5NativeOptIn(t testing.TB) any {
	t.Helper()

	link := "manual-name:socks5://user:pass@127.0.0.1:1080#outer -> socks://127.0.0.2:1081#inner"
	overwrittenName, linklike := outboundcommon.GetTagFromLinkLikePlaintext(link)
	_, property, err := outbounddialer.NewNetproxyDialerFromLink(
		noDialSocks5Dialer{},
		&outbounddialer.ExtraOption{},
		link,
	)
	if err != nil {
		t.Fatalf("NewNetproxyDialerFromLink: %v", err)
	}

	return map[string]any{
		"name": "socks5-native-optin",
		"source": []string{
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.1",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.3",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.13",
			"/root/project/outbound/dialer/socks/socks.go",
			"/root/project/outbound/protocol/socks5/addr.go",
			"/root/project/outbound/protocol/socks5/client.go",
			"/root/project/outbound/protocol/socks5/packet.go",
		},
		"default_go_path":   true,
		"rust_adapter_mode": "native-opt-in",
		"protocol_scope": []string{
			"socks5",
		},
		"deferred_protocol_scope": []string{
			"http",
			"https",
			"shadowsocks",
			"shadowsocks-2022",
			"trojan",
			"vmess",
			"vless",
			"hysteria2",
			"tuic",
			"juicity",
			"anytls",
			"transport-combos",
		},
		"link_parser": map[string]any{
			"input":              link,
			"plaintext_tag":      overwrittenName,
			"linklike":           linklike,
			"chain_separator":    "->",
			"build_order":        "right-to-left",
			"name":               property.Name,
			"protocol":           property.Protocol,
			"address":            property.Address,
			"link":               property.Link,
			"socks_alias_scheme": "socks",
			"socks_alias_protocol": func() string {
				parsed, err := parseSocksProtocol("socks://127.0.0.1:1080#alias")
				if err != nil {
					t.Fatalf("parse socks alias: %v", err)
				}
				return parsed
			}(),
		},
		"address_codec": []map[string]any{
			rebuildSocks5AddressCase(t, "domain", "example.com:443"),
			rebuildSocks5AddressCase(t, "ipv4", "1.2.3.4:53"),
			rebuildSocks5AddressCase(t, "ipv6", "[2001:db8::1]:8443"),
		},
		"handshake": map[string]any{
			"version":                     outboundsocks5.Version,
			"auth_none":                   outboundsocks.AuthNone,
			"auth_password":               outboundsocks.AuthPassword,
			"greeting_no_auth_hex":        hex.EncodeToString(socks5Greeting("", "")),
			"greeting_with_auth_hex":      hex.EncodeToString(socks5Greeting("user", "pass")),
			"greeting_long_auth_user_hex": hex.EncodeToString(socks5Greeting(string(bytes.Repeat([]byte{'u'}, 256)), "pass")),
			"username_password_auth_hex":  hex.EncodeToString(socks5PasswordAuth("user", "pass")),
			"connect_example_com_443_hex": hex.EncodeToString(socks5Request(t, outboundsocks.CmdConnect, "example.com:443")),
			"udp_associate_0_0_0_0_0_hex": hex.EncodeToString(socks5Request(t, outboundsocks.CmdUDPAssociate, "0.0.0.0:0")),
			"success_reply_hex":           hex.EncodeToString(socks5SuccessReply(t, "127.0.0.1:5300")),
			"deadline_contract": []string{
				"DialContextWithDefaultTimeout applies a non-zero deadline around the SOCKS5 handshake",
				"deadline is reset to zero after handshake",
			},
		},
		"udp_packet": map[string]any{
			"target":                      "example.com:443",
			"payload_ascii":               "ping",
			"write_packet_hex":            hex.EncodeToString(socks5UdpPacket(t, "example.com:443", []byte("ping"))),
			"header_reserved":             []int{0, 0},
			"fragment":                    0,
			"control_connection_retained": true,
		},
		"magic_network": []map[string]any{
			rebuildSocks5MagicNetworkCase("tcp", consts.TproxyMark, true),
			rebuildSocks5MagicNetworkCase("udp", 0x123456, false),
		},
		"live_smoke_required": []string{
			"local fake SOCKS5 TCP CONNECT",
			"local fake SOCKS5 username/password auth",
			"local fake SOCKS5 UDP packet wrapper",
		},
	}
}

type noDialSocks5Dialer struct{}

func (noDialSocks5Dialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return nil, net.ErrClosed
}

func parseSocksProtocol(link string) (string, error) {
	_, property, err := outbounddialer.NewNetproxyDialerFromLink(
		noDialSocks5Dialer{},
		&outbounddialer.ExtraOption{},
		link,
	)
	if err != nil {
		return "", err
	}
	return property.Protocol, nil
}

func rebuildSocks5AddressCase(t testing.TB, name string, addr string) map[string]any {
	t.Helper()

	info, err := outboundsocks5.AddressFromString(addr)
	if err != nil {
		t.Fatalf("AddressFromString(%q): %v", addr, err)
	}
	buf := &bytes.Buffer{}
	if err := outboundsocks5.WriteAddrInfo(info, buf); err != nil {
		t.Fatalf("WriteAddrInfo(%q): %v", addr, err)
	}
	parsed, err := outboundsocks.ReadAddr(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadAddr(%q): %v", addr, err)
	}
	return map[string]any{
		"name":     name,
		"input":    addr,
		"type":     info.Type,
		"hostname": info.Hostname,
		"ip":       info.IP.String(),
		"port":     info.Port,
		"hex":      hex.EncodeToString(buf.Bytes()),
		"string":   parsed.String(),
	}
}

func socks5Greeting(user string, password string) []byte {
	if len(user) > 0 && len(user) < 256 && len(password) < 256 {
		return []byte{outboundsocks5.Version, 2, outboundsocks.AuthNone, outboundsocks.AuthPassword}
	}
	return []byte{outboundsocks5.Version, 1, outboundsocks.AuthNone}
}

func socks5PasswordAuth(user string, password string) []byte {
	buf := []byte{1, byte(len(user))}
	buf = append(buf, user...)
	buf = append(buf, byte(len(password)))
	buf = append(buf, password...)
	return buf
}

func socks5Request(t testing.TB, cmd byte, target string) []byte {
	t.Helper()

	addr, err := outboundsocks.ParseAddr(target)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", target, err)
	}
	buf := []byte{outboundsocks5.Version, cmd, 0}
	return append(buf, addr...)
}

func socks5SuccessReply(t testing.TB, bind string) []byte {
	t.Helper()

	addr, err := outboundsocks.ParseAddr(bind)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", bind, err)
	}
	buf := []byte{outboundsocks5.Version, 0, 0}
	return append(buf, addr...)
}

func socks5UdpPacket(t testing.TB, target string, payload []byte) []byte {
	t.Helper()

	addr, err := outboundsocks.ParseAddr(target)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", target, err)
	}
	buf := []byte{0, 0, 0}
	buf = append(buf, addr...)
	return append(buf, payload...)
}

func rebuildSocks5MagicNetworkCase(network string, mark uint32, mptcp bool) map[string]any {
	encoded := common.MagicNetwork(network, mark, mptcp)
	return map[string]any{
		"network":     network,
		"mark":        mark,
		"mptcp":       mptcp,
		"encoded_b64": base64.StdEncoding.EncodeToString([]byte(encoded)),
		"is_plain":    encoded == network,
	}
}

func writeOrCheckOutboundGolden(t *testing.T, path string, value any) {
	t.Helper()

	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	data = append(data, '\n')

	if os.Getenv(outboundGoldenUpdateEnv) == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, data, 0644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !outboundJsonEqual(want, data) {
		t.Fatalf("%s does not match generated golden; run %s=1 go test ./component/outbound -run TestWriteSocks5NativeOptInGoldenFixture", path, outboundGoldenUpdateEnv)
	}
}

func outboundJsonEqual(a []byte, b []byte) bool {
	var av any
	var bv any
	if err := json.Unmarshal(a, &av); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &bv); err != nil {
		return false
	}
	return reflect.DeepEqual(av, bv)
}

func BenchmarkSocks5NativeOptInAddressCodec(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		info, err := outboundsocks5.AddressFromString("example.com:443")
		if err != nil {
			b.Fatal(err)
		}
		buf := &bytes.Buffer{}
		if err := outboundsocks5.WriteAddrInfo(info, buf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSocks5NativeOptInHandshakeBytes(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = socks5Greeting("user", "pass")
		_ = socks5PasswordAuth("user", "pass")
		_ = socks5Request(b, outboundsocks.CmdConnect, "example.com:443")
	}
}

func BenchmarkSocks5NativeOptInUdpPacketWrap(b *testing.B) {
	payload := []byte("ping")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = socks5UdpPacket(b, "example.com:443", payload)
	}
}

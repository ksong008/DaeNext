/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/url"
	"strings"
	"testing"

	outbounddialer "github.com/daeuniverse/outbound/dialer"
	outboundanytls "github.com/daeuniverse/outbound/dialer/anytls"
	"github.com/daeuniverse/outbound/netproxy"
	outboundsocks "github.com/daeuniverse/outbound/protocol/infra/socks"
)

const anytlsMagicUdpDomain = "sp.v2.udp-over-tcp.arpa"

var anytlsDefaultPaddingScheme = []byte(`stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000`)

func TestWriteAnyTLSNativeOptInGoldenFixture(t *testing.T) {
	writeOrCheckOutboundGolden(t,
		"../../testdata/rebuild-golden/outbound/protocol/anytls_native_optin.json",
		rebuildGoldenStage15AnyTLSNativeOptIn(t),
	)
}

func rebuildGoldenStage15AnyTLSNativeOptIn(t testing.TB) any {
	t.Helper()

	basic := "anytls://auth@example.com:443?insecure=1&sni=sni.example#basic"
	peer := "anytls://auth@example.com:8443?sni=sni.example&peer=peer.example&insecure=true#peer"
	defaultSni := "anytls://auth@example.com:443#default-sni"

	return map[string]any{
		"name": "stage15-anytls-native-optin",
		"source": []string{
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.17",
			"/root/project/outbound/dialer/anytls/anytls.go",
			"/root/project/outbound/protocol/anytls/dialer.go",
			"/root/project/outbound/protocol/anytls/session.go",
			"/root/project/outbound/protocol/anytls/stream.go",
			"/root/project/outbound/protocol/anytls/padding.go",
			"/root/project/outbound/protocol/anytls/anytls.go",
		},
		"default_go_path":   true,
		"rust_adapter_mode": "native-opt-in",
		"protocol_scope": []string{
			"anytls",
		},
		"deferred_protocol_scope": []string{
			"transport-combos",
		},
		"link_parser": []map[string]any{
			rebuildAnyTLSLinkCase(t, "basic-insecure", basic, true),
			rebuildAnyTLSLinkCase(t, "peer-overrides-sni-insecure-true-is-false", peer, true),
			rebuildAnyTLSLinkCase(t, "default-sni-hostname", defaultSni, true),
		},
		"insecure_cases": []map[string]any{
			rebuildAnyTLSInsecureCase(t, "one", "anytls://auth@example.com:443?insecure=1#one"),
			rebuildAnyTLSInsecureCase(t, "true-string", "anytls://auth@example.com:443?insecure=true#true"),
			rebuildAnyTLSInsecureCase(t, "zero", "anytls://auth@example.com:443?insecure=0#zero"),
		},
		"tls_contract": map[string]any{
			"empty_sni_server_name": "127.0.0.1",
			"insecure_only_when":    "insecure=1",
			"peer_overrides_sni":    true,
		},
		"auth_key": map[string]any{
			"auth":       "auth",
			"sha256_hex": anytlsAuthKeyHex("auth"),
			"key_len":    sha256.Size,
		},
		"session_contract": map[string]any{
			"idle_session_reuse_map": true,
			"session_counter":        true,
			"first_handshake": map[string]any{
				"auth_key_then_zero_u16_hex": hex.EncodeToString(anytlsHandshakeAuthBytes("auth")),
			},
			"padding": map[string]any{
				"stop":         8,
				"raw":          string(anytlsDefaultPaddingScheme),
				"md5":          anytlsDefaultPaddingMD5(),
				"settings":     string(anytlsSettingsBytes()),
				"settings_hex": hex.EncodeToString(anytlsSettingsBytes()),
				"check_mark":   -1,
			},
			"frame": map[string]any{
				"header_overhead_size": 7,
				"cmd_waste":            0,
				"cmd_syn":              1,
				"cmd_psh":              2,
				"cmd_fin":              3,
				"cmd_settings":         4,
				"cmd_alert":            5,
				"cmd_update_padding":   6,
				"cmd_synack":           7,
				"cmd_heart_request":    8,
				"cmd_heart_response":   9,
				"cmd_server_settings":  10,
				"settings_frame_hex":   hex.EncodeToString(anytlsFrame(4, 1, anytlsSettingsBytes())),
				"syn_frame_hex":        hex.EncodeToString(anytlsFrame(1, 1, nil)),
				"psh_addr_frame_hex":   hex.EncodeToString(anytlsFrame(2, 1, anytlsSocksAddr(t, "example.com:443"))),
			},
		},
		"packet_stream": map[string]any{
			"udp_magic_domain":         anytlsMagicUdpDomain,
			"udp_input_target":         "example.com:53",
			"udp_stream_target":        net.JoinHostPort(anytlsMagicUdpDomain, "53"),
			"udp_original_packet_addr": "example.com:53",
			"first_write_hex":          hex.EncodeToString(anytlsPacketFirstWrite(t, "example.com:53", []byte("ping"))),
			"next_write_hex":           hex.EncodeToString(anytlsPacketNextWrite([]byte("ping"))),
		},
		"underlay_contract": map[string]any{
			"tcp_request":                      rebuildAnyTLSUnderlayCase(t, "tcp", 1234, true),
			"udp_request":                      rebuildAnyTLSUnderlayCase(t, "udp", 1234, true),
			"underlay_always_tcp":              true,
			"underlay_preserves_mark":          true,
			"underlay_preserves_mptcp":         true,
			"true_session_data_plane_deferred": 113,
		},
		"live_smoke_required": []string{
			"local parser smoke for AnyTLS",
			"local auth key / frame contract smoke",
			"local UDP magic domain / underlay contract smoke",
		},
	}
}

func rebuildAnyTLSLinkCase(t testing.TB, name string, raw string, buildProperty bool) map[string]any {
	t.Helper()

	parsed := parseAnyTLSLinkForFixture(t, raw)
	propertyName := parsed["name"].(string)
	propertyAddress := parsed["host"].(string)
	propertyProtocol := "anytls"
	propertyLink := raw
	if buildProperty {
		_, property, err := outboundanytls.NewAnytls(&outbounddialer.ExtraOption{}, noDialSocks5Dialer{}, raw)
		if err != nil {
			t.Fatalf("NewAnytls(%q): %v", raw, err)
		}
		propertyName = property.Name
		propertyAddress = property.Address
		propertyProtocol = property.Protocol
		propertyLink = property.Link
	}
	parsed["case"] = name
	parsed["property_name"] = propertyName
	parsed["property_address"] = propertyAddress
	parsed["property_protocol"] = propertyProtocol
	parsed["property_link"] = propertyLink
	return parsed
}

func rebuildAnyTLSInsecureCase(t testing.TB, name string, raw string) map[string]any {
	t.Helper()
	parsed := parseAnyTLSLinkForFixture(t, raw)
	return map[string]any{
		"name":     name,
		"input":    raw,
		"insecure": parsed["insecure"],
	}
}

func parseAnyTLSLinkForFixture(t testing.TB, raw string) map[string]any {
	t.Helper()
	if !strings.HasPrefix(raw, "anytls://") {
		t.Fatalf("bad AnyTLS scheme fixture: %q", raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	sni := u.Query().Get("peer")
	if sni == "" {
		sni = u.Query().Get("sni")
	}
	if sni == "" {
		sni = u.Hostname()
	}
	insecure := u.Query().Get("insecure") == "1"
	tlsServerName := sni
	if tlsServerName == "" {
		tlsServerName = "127.0.0.1"
	}
	return map[string]any{
		"input":           raw,
		"name":            u.Fragment,
		"auth":            u.User.Username(),
		"host":            u.Host,
		"hostname":        u.Hostname(),
		"sni":             sni,
		"tls_server_name": tlsServerName,
		"insecure":        insecure,
		"protocol":        "anytls",
		"link_preserved":  raw,
	}
}

func anytlsAuthKeyHex(auth string) string {
	sum := sha256.Sum256([]byte(auth))
	return hex.EncodeToString(sum[:])
}

func anytlsHandshakeAuthBytes(auth string) []byte {
	sum := sha256.Sum256([]byte(auth))
	out := append([]byte{}, sum[:]...)
	return append(out, 0, 0)
}

func anytlsDefaultPaddingMD5() string {
	return fmtMD5(anytlsDefaultPaddingScheme)
}

func anytlsSettingsBytes() []byte {
	return []byte("v=2\nclient=dae\npadding-md5=" + fmtMD5(anytlsDefaultPaddingScheme))
}

func fmtMD5(input []byte) string {
	sum := md5.Sum(input)
	return hex.EncodeToString(sum[:])
}

func anytlsFrame(cmd byte, sid uint32, data []byte) []byte {
	out := make([]byte, 7+len(data))
	out[0] = cmd
	binary.BigEndian.PutUint32(out[1:], sid)
	binary.BigEndian.PutUint16(out[5:], uint16(len(data)))
	copy(out[7:], data)
	return out
}

func anytlsSocksAddr(t testing.TB, target string) []byte {
	t.Helper()
	addr, err := outboundsocks.ParseAddr(target)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", target, err)
	}
	return addr
}

func anytlsPacketFirstWrite(t testing.TB, target string, payload []byte) []byte {
	t.Helper()
	addr := anytlsSocksAddr(t, target)
	out := make([]byte, 1+len(addr)+2+len(payload))
	out[0] = 1
	copy(out[1:], addr)
	binary.BigEndian.PutUint16(out[1+len(addr):], uint16(len(payload)))
	copy(out[1+len(addr)+2:], payload)
	return out
}

func anytlsPacketNextWrite(payload []byte) []byte {
	out := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(out, uint16(len(payload)))
	copy(out[2:], payload)
	return out
}

func rebuildAnyTLSUnderlayCase(t testing.TB, network string, mark uint32, mptcp bool) map[string]any {
	t.Helper()

	input := netproxy.MagicNetwork{Network: network, Mark: mark, Mptcp: mptcp}.Encode()
	parsed, err := netproxy.ParseMagicNetwork(input)
	if err != nil {
		t.Fatalf("ParseMagicNetwork(%q): %v", network, err)
	}
	output := netproxy.MagicNetwork{
		Network: "tcp",
		Mark:    parsed.Mark,
		Mptcp:   parsed.Mptcp,
	}.Encode()
	out, err := netproxy.ParseMagicNetwork(output)
	if err != nil {
		t.Fatalf("ParseMagicNetwork(output %q): %v", network, err)
	}
	return map[string]any{
		"input_network":      network,
		"input_mark":         mark,
		"input_mptcp":        mptcp,
		"input_b64":          base64.StdEncoding.EncodeToString([]byte(input)),
		"underlay_network":   out.Network,
		"underlay_mark":      out.Mark,
		"underlay_mptcp":     out.Mptcp,
		"underlay_b64":       base64.StdEncoding.EncodeToString([]byte(output)),
		"same_encoded_value": input == output,
	}
}

func BenchmarkAnyTLSNativeOptInNewDialer(b *testing.B) {
	link := "anytls://auth@example.com:443?insecure=1&sni=sni.example#basic"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := outboundanytls.NewAnytls(&outbounddialer.ExtraOption{}, noDialSocks5Dialer{}, link); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAnyTLSNativeOptInAuthKey(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = anytlsAuthKeyHex("auth")
	}
}

func BenchmarkAnyTLSNativeOptInFrame(b *testing.B) {
	settings := anytlsSettingsBytes()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = anytlsFrame(4, 1, settings)
	}
}

func BenchmarkAnyTLSNativeOptInUnderlay(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = rebuildAnyTLSUnderlayCase(b, "udp", 1234, true)
	}
}

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	outbounddialer "github.com/daeuniverse/outbound/dialer"
	outboundjuicity "github.com/daeuniverse/outbound/dialer/juicity"
	"github.com/daeuniverse/outbound/netproxy"
	outboundprotocol "github.com/daeuniverse/outbound/protocol"
	protocoljuicity "github.com/daeuniverse/outbound/protocol/juicity"
	outboundtuiccommon "github.com/daeuniverse/outbound/protocol/tuic/common"
)

func TestWriteJuicityNativeOptInGoldenFixture(t *testing.T) {
	writeOrCheckOutboundGolden(t,
		"../../testdata/rebuild-golden/outbound/protocol/juicity_native_optin.json",
		rebuildGoldenNativeJuicityNativeOptIn(t),
	)
}

func rebuildGoldenNativeJuicityNativeOptIn(t testing.TB) any {
	t.Helper()

	pinBytes := []byte{
		0xfb, 0xff, 0xfe, 0xfa, 0xef, 0xee, 0xab, 0xcd,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfb, 0xff, 0xfe, 0xfa, 0xef, 0xee, 0xab, 0xcd,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	}
	urlPin := base64.URLEncoding.EncodeToString(pinBytes)
	stdPin := base64.StdEncoding.EncodeToString(pinBytes)
	basic := "juicity://7c12c745-63a5-433d-9e60-022e469b5bd4:pass@example.com:443?congestion_control=bbr&pinned_certchain_sha256=" + url.QueryEscape(urlPin) + "#basic"
	peer := "juicity://7c12c745-63a5-433d-9e60-022e469b5bd4:pass@example.com:8443?sni=sni.example&peer=peer.example&allowInsecure=true#peer"
	hexPin := strings.Repeat("ab", 33)
	pinnedHex := "juicity://7c12c745-63a5-433d-9e60-022e469b5bd4:pass@example.com:443?sni=pin.example&pinned_certchain_sha256=" + hexPin + "#hex-pin"

	return map[string]any{
		"name": "juicity-native-optin",
		"source": []string{
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.16",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.21",
			"/root/project/outbound/dialer/juicity/juicity.go",
			"/root/project/outbound/protocol/juicity/dialer.go",
			"/root/project/outbound/protocol/juicity/transport_packet_conn.go",
			"/root/project/outbound/protocol/juicity/stream_packet_conn.go",
		},
		"default_go_path":   true,
		"rust_adapter_mode": "native-opt-in",
		"protocol_scope": []string{
			"juicity",
		},
		"deferred_protocol_scope": []string{
			"anytls",
			"transport-combos",
		},
		"link_parser": []map[string]any{
			rebuildJuicityLinkCase(t, "basic-urlbase64-pin", basic, true),
			rebuildJuicityLinkCase(t, "peer-overrides-sni", peer, true),
			rebuildJuicityLinkCase(t, "hex-pin", pinnedHex, true),
		},
		"allow_insecure_aliases": []map[string]any{
			rebuildJuicityAllowInsecureAlias(t, "allowInsecure", "juicity://7c12c745-63a5-433d-9e60-022e469b5bd4:pass@example.com:443?allowInsecure=1#alias"),
			rebuildJuicityAllowInsecureAlias(t, "allow_insecure", "juicity://7c12c745-63a5-433d-9e60-022e469b5bd4:pass@example.com:443?allow_insecure=true#alias"),
			rebuildJuicityAllowInsecureAlias(t, "allowinsecure", "juicity://7c12c745-63a5-433d-9e60-022e469b5bd4:pass@example.com:443?allowinsecure=true#alias"),
			rebuildJuicityAllowInsecureAlias(t, "skipVerify", "juicity://7c12c745-63a5-433d-9e60-022e469b5bd4:pass@example.com:443?skipVerify=1#alias"),
		},
		"pinned_certchain_sha256": []map[string]any{
			rebuildJuicityPinCase(t, "url-base64", urlPin),
			rebuildJuicityPinCase(t, "std-base64", stdPin),
			rebuildJuicityPinCase(t, "hex-fallback-non-multiple-of-4", hexPin),
			rebuildJuicityPinCase(t, "sha256-hex-looking-string-decodes-as-url-base64-first", hex.EncodeToString(pinBytes)),
			rebuildJuicityBadPinCase("bad-pin"),
		},
		"uuid_contract": map[string]any{
			"valid":          "7c12c745-63a5-433d-9e60-022e469b5bd4",
			"invalid":        "not-a-uuid",
			"invalid_error":  rebuildJuicityInvalidUUIDCase(t),
			"validated_by":   "/root/project/outbound/protocol/juicity/dialer.go",
			"parser_accepts": "URL parser preserves user; protocol.NewDialer rejects non-UUID user",
		},
		"quic_contract": map[string]any{
			"alpn":                               []string{"h3"},
			"tls_min_version":                    int(tls.VersionTLS13),
			"enable_datagrams":                   false,
			"keepalive_seconds":                  int((5 * time.Second) / time.Second),
			"handshake_idle_timeout_seconds":     int((8 * time.Second) / time.Second),
			"initial_stream_receive_window":      outboundtuiccommon.InitialStreamReceiveWindow,
			"max_stream_receive_window":          outboundtuiccommon.MaxStreamReceiveWindow,
			"initial_connection_receive_window":  outboundtuiccommon.InitialConnectionReceiveWindow,
			"max_connection_receive_window":      outboundtuiccommon.MaxConnectionReceiveWindow,
			"max_open_incoming_streams":          100,
			"quic_max_open_incoming_streams":     110,
			"reserved_streams_capability":        5,
			"underlay_auth_channel_capacity":     64,
			"congestion_default_or_unknown_uses": "bbr",
		},
		"underlay_contract": map[string]any{
			"tcp_request":                       rebuildJuicityUnderlayCase(t, "tcp", 1234, true),
			"udp_request":                       rebuildJuicityUnderlayCase(t, "udp", 1234, true),
			"tcp_underlay_uses_udp":             true,
			"tcp_underlay_preserves_mark":       true,
			"tcp_underlay_drops_mptcp":          true,
			"udp_underlay_uses_original":        true,
			"udp_port_zero_packet_conn":         "transport_packet_conn",
			"udp_nonzero_port_packet_conn":      "stream_packet_conn",
			"transport_packet_conn_uses_auth":   true,
			"transport_packet_conn_cipher_info": "juicity reused info",
			"true_quic_data_plane_deferred":     113,
		},
		"live_smoke_required": []string{
			"local parser smoke for Juicity",
			"local UUID validation smoke",
			"local pinned certchain decode smoke",
			"local QUIC/underlay contract smoke",
		},
	}
}

func rebuildJuicityLinkCase(t testing.TB, name string, raw string, buildProperty bool) map[string]any {
	t.Helper()

	juicity, err := outboundjuicity.ParseJuicityURL(raw)
	if err != nil {
		t.Fatalf("ParseJuicityURL(%q): %v", raw, err)
	}
	propertyName := juicity.Name
	propertyAddress := net.JoinHostPort(juicity.Server, strconv.Itoa(juicity.Port))
	propertyProtocol := "juicity"
	propertyLink := juicity.ExportToURL()
	if buildProperty {
		_, property, err := outboundjuicity.NewJuicity(&outbounddialer.ExtraOption{}, noDialSocks5Dialer{}, raw)
		if err != nil {
			t.Fatalf("NewJuicity(%q): %v", raw, err)
		}
		propertyName = property.Name
		propertyAddress = property.Address
		propertyProtocol = property.Protocol
		propertyLink = property.Link
	}
	return map[string]any{
		"name":                       name,
		"input":                      raw,
		"user":                       juicity.User,
		"password":                   juicity.Password,
		"server":                     juicity.Server,
		"port":                       juicity.Port,
		"sni":                        juicity.Sni,
		"allowInsecure":              juicity.AllowInsecure,
		"congestion_control":         juicity.CongestionControl,
		"pinned_certchain_sha256":    juicity.PinnedCertchainSha256,
		"pinned_certchain_decoded":   rebuildJuicityPinDecodeProjection(t, juicity.PinnedCertchainSha256),
		"protocol":                   juicity.Protocol,
		"export":                     juicity.ExportToURL(),
		"property_name":              propertyName,
		"property_address":           propertyAddress,
		"property_protocol":          propertyProtocol,
		"property_link":              propertyLink,
		"pin_forces_insecure_verify": juicity.PinnedCertchainSha256 != "",
	}
}

func rebuildJuicityAllowInsecureAlias(t testing.TB, name string, raw string) map[string]any {
	t.Helper()

	juicity, err := outboundjuicity.ParseJuicityURL(raw)
	if err != nil {
		t.Fatalf("ParseJuicityURL(%q): %v", raw, err)
	}
	return map[string]any{
		"name":          name,
		"input":         raw,
		"allowInsecure": juicity.AllowInsecure,
		"export":        juicity.ExportToURL(),
	}
}

func rebuildJuicityPinCase(t testing.TB, name string, input string) map[string]any {
	t.Helper()
	projection := rebuildJuicityPinDecodeProjection(t, input)
	projection["name"] = name
	projection["input"] = input
	return projection
}

func rebuildJuicityBadPinCase(input string) map[string]any {
	return map[string]any{
		"name":           "bad",
		"input":          input,
		"ok":             false,
		"error_contains": "failed to decode PinnedCertchainSha256",
	}
}

func rebuildJuicityPinDecodeProjection(t testing.TB, input string) map[string]any {
	t.Helper()
	if input == "" {
		return map[string]any{
			"ok":          true,
			"format":      "",
			"decoded_hex": "",
		}
	}
	decoded, format, err := decodeJuicityPinnedCertchainForFixture(input)
	if err != nil {
		t.Fatalf("decodeJuicityPinnedCertchainForFixture(%q): %v", input, err)
	}
	return map[string]any{
		"ok":          true,
		"format":      format,
		"decoded_hex": hex.EncodeToString(decoded),
	}
}

func decodeJuicityPinnedCertchainForFixture(input string) ([]byte, string, error) {
	if decoded, err := base64.URLEncoding.DecodeString(input); err == nil {
		return decoded, "url-base64", nil
	}
	if decoded, err := base64.StdEncoding.DecodeString(input); err == nil {
		return decoded, "std-base64", nil
	}
	if decoded, err := hex.DecodeString(input); err == nil {
		return decoded, "hex", nil
	}
	return nil, "", fmt.Errorf("failed to decode PinnedCertchainSha256")
}

func rebuildJuicityInvalidUUIDCase(t testing.TB) map[string]any {
	t.Helper()

	_, err := protocoljuicity.NewDialer(noDialSocks5Dialer{}, outboundprotocol.Header{
		ProxyAddress: "example.com:443",
		Feature1:     "bbr",
		TlsConfig:    &tls.Config{NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13, ServerName: "example.com"},
		User:         "not-a-uuid",
		Password:     "pass",
		IsClient:     true,
	})
	if err == nil {
		t.Fatalf("expected invalid UUID error")
	}
	return map[string]any{
		"ok":             false,
		"error_contains": "parse UUID:",
		"error":          err.Error(),
	}
}

func rebuildJuicityUnderlayCase(t testing.TB, network string, mark uint32, mptcp bool) map[string]any {
	t.Helper()

	input := netproxy.MagicNetwork{Network: network, Mark: mark, Mptcp: mptcp}.Encode()
	parsed, err := netproxy.ParseMagicNetwork(input)
	if err != nil {
		t.Fatalf("ParseMagicNetwork(%q): %v", network, err)
	}
	output := input
	if parsed.Network == "tcp" {
		output = netproxy.MagicNetwork{Network: "udp", Mark: parsed.Mark}.Encode()
	}
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

func BenchmarkJuicityNativeOptInParseLink(b *testing.B) {
	pin := base64.URLEncoding.EncodeToString([]byte{
		0xfb, 0xff, 0xfe, 0xfa, 0xef, 0xee, 0xab, 0xcd,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfb, 0xff, 0xfe, 0xfa, 0xef, 0xee, 0xab, 0xcd,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	})
	link := "juicity://7c12c745-63a5-433d-9e60-022e469b5bd4:pass@example.com:443?congestion_control=bbr&pinned_certchain_sha256=" + pin + "#basic"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := outboundjuicity.ParseJuicityURL(link); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJuicityNativeOptInExportLink(b *testing.B) {
	pin := base64.URLEncoding.EncodeToString([]byte{
		0xfb, 0xff, 0xfe, 0xfa, 0xef, 0xee, 0xab, 0xcd,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xef,
		0xfb, 0xff, 0xfe, 0xfa, 0xef, 0xee, 0xab, 0xcd,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	})
	juicity, err := outboundjuicity.ParseJuicityURL("juicity://7c12c745-63a5-433d-9e60-022e469b5bd4:pass@example.com:443?congestion_control=bbr&pinned_certchain_sha256=" + pin + "#basic")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = juicity.ExportToURL()
	}
}

func BenchmarkJuicityNativeOptInPinnedDecode(b *testing.B) {
	pin := base64.URLEncoding.EncodeToString([]byte{
		0xfb, 0xff, 0xfe, 0xfa, 0xef, 0xee, 0xab, 0xcd,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfb, 0xff, 0xfe, 0xfa, 0xef, 0xee, 0xab, 0xcd,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := decodeJuicityPinnedCertchainForFixture(pin); err != nil {
			b.Fatal(err)
		}
	}
}

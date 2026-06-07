/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"strings"
	"testing"

	outbounddialer "github.com/daeuniverse/outbound/dialer"
	outboundhysteria2 "github.com/daeuniverse/outbound/dialer/hysteria2"
)

func TestWriteHysteria2NativeOptInGoldenFixture(t *testing.T) {
	writeOrCheckOutboundGolden(t,
		"../../testdata/rebuild-golden/outbound/protocol/hysteria2_native_optin.json",
		rebuildGoldenNativeHysteria2NativeOptIn(t),
	)
}

func rebuildGoldenNativeHysteria2NativeOptIn(t testing.TB) any {
	t.Helper()

	basic := "hysteria2://user:pass@127.0.0.1:8443?insecure=1&sni=sni.example&pinSHA256=AA:BB-cc&maxTx=1000&maxRx=2000#basic"
	alias := "hy2://auth@example.com?sni=edge.example#alias"
	hopping := "hy2://user:pass@example.com:443,8443-8445?insecure=true&sni=hop.example&pinSHA256=AA-BB:CC&maxTx=4096&maxRx=8192#hop"
	partialBandwidth := "hysteria2://user@example.com:443?maxTx=1000&sni=sni.example#partial"

	return map[string]any{
		"name": "hysteria2-native-optin",
		"source": []string{
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.14",
			"/root/project/outbound/dialer/hysteria2/hysteria2.go",
			"/root/project/outbound/protocol/hysteria2/dialer.go",
			"/root/project/outbound/protocol/hysteria2/client/config.go",
			"/root/project/outbound/protocol/hysteria2/udphop",
		},
		"default_go_path":   true,
		"rust_adapter_mode": "native-opt-in",
		"protocol_scope": []string{
			"hysteria2",
			"hy2",
		},
		"deferred_protocol_scope": []string{
			"tuic",
			"juicity",
			"anytls",
			"transport-combos",
		},
		"link_parser": []map[string]any{
			rebuildHysteria2LinkCase(t, "basic", basic, true),
			rebuildHysteria2LinkCase(t, "hy2-alias-default-port", alias, false),
			rebuildHysteria2LinkCase(t, "port-hopping", hopping, false),
			rebuildHysteria2LinkCase(t, "partial-bandwidth-ignored", partialBandwidth, false),
		},
		"pin_sha256": []map[string]any{
			rebuildHysteria2PinCase("AA:BB-cc"),
			rebuildHysteria2PinCase("0011-2233:AAFF"),
		},
		"server_contract": []map[string]any{
			rebuildHysteria2ServerContract("example.com"),
			rebuildHysteria2ServerContract("example.com:443"),
			rebuildHysteria2ServerContract("example.com:443,8443-8445"),
		},
		"underlay_contract": map[string]any{
			"always_udp_underlay":                 true,
			"tcp_target_uses_hysteria2_client":    true,
			"udp_target_uses_hysteria2_client":    true,
			"preserve_mark":                       true,
			"preserve_mptcp_field_even_for_udp":   true,
			"route_cache_key_is_underlay_network": true,
			"port_hopping_detects_dash_or_comma":  true,
			"udp_hop_interval_from_extra_option":  true,
			"true_quic_data_plane_deferred_item":  113,
		},
		"live_smoke_required": []string{
			"local parser smoke for hysteria2 and hy2",
			"local pinSHA256 normalize smoke",
			"local UDP underlay / port hopping contract smoke",
		},
	}
}

func rebuildHysteria2LinkCase(t testing.TB, name string, raw string, buildProperty bool) map[string]any {
	t.Helper()

	hy2, err := outboundhysteria2.ParseHysteria2URL(raw)
	if err != nil {
		t.Fatalf("ParseHysteria2URL(%q): %v", raw, err)
	}
	propertyName := hy2.Name
	propertyAddress := hy2.Server
	propertyProtocol := "hysteria2"
	propertyLink := hy2.ExportToURL()
	if buildProperty {
		_, property, err := outboundhysteria2.NewHysteria2(&outbounddialer.ExtraOption{}, noDialSocks5Dialer{}, raw)
		if err != nil {
			t.Fatalf("NewHysteria2(%q): %v", raw, err)
		}
		propertyName = property.Name
		propertyAddress = property.Address
		propertyProtocol = property.Protocol
		propertyLink = property.Link
	}
	return map[string]any{
		"name":              name,
		"input":             raw,
		"user":              hy2.User,
		"password":          hy2.Password,
		"server":            hy2.Server,
		"insecure":          hy2.Insecure,
		"sni":               hy2.Sni,
		"pinSHA256":         hy2.PinSHA256,
		"pinSHA256_normal":  normalizeHysteria2PinForFixture(hy2.PinSHA256),
		"maxTx":             hy2.MaxTx,
		"maxRx":             hy2.MaxRx,
		"export":            hy2.ExportToURL(),
		"property_name":     propertyName,
		"property_address":  propertyAddress,
		"property_protocol": propertyProtocol,
		"property_link":     propertyLink,
	}
}

func rebuildHysteria2PinCase(input string) map[string]any {
	return map[string]any{
		"input":      input,
		"normalized": normalizeHysteria2PinForFixture(input),
	}
}

func rebuildHysteria2ServerContract(server string) map[string]any {
	host, port, hostPort := parseHysteria2ServerForFixture(server)
	return map[string]any{
		"server":       server,
		"host":         host,
		"port":         port,
		"host_port":    hostPort,
		"port_hopping": strings.Contains(port, "-") || strings.Contains(port, ","),
	}
}

func normalizeHysteria2PinForFixture(hash string) string {
	r := strings.ToLower(hash)
	r = strings.ReplaceAll(r, ":", "")
	r = strings.ReplaceAll(r, "-", "")
	return r
}

func parseHysteria2ServerForFixture(server string) (host, port, hostPort string) {
	if i := strings.LastIndex(server, ":"); i >= 0 && !strings.Contains(server[i+1:], "]") {
		return server[:i], server[i+1:], server
	}
	return server, "443", server + ":443"
}

func BenchmarkHysteria2NativeOptInParseLink(b *testing.B) {
	link := "hy2://user:pass@example.com:443,8443-8445?insecure=true&sni=hop.example&pinSHA256=AA-BB:CC&maxTx=4096&maxRx=8192#hop"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := outboundhysteria2.ParseHysteria2URL(link); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHysteria2NativeOptInExportLink(b *testing.B) {
	hy2, err := outboundhysteria2.ParseHysteria2URL("hy2://user:pass@example.com:443,8443-8445?insecure=true&sni=hop.example&pinSHA256=AA-BB:CC&maxTx=4096&maxRx=8192#hop")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = hy2.ExportToURL()
	}
}

func BenchmarkHysteria2NativeOptInPinNormalize(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = normalizeHysteria2PinForFixture("AA-BB:CC")
	}
}

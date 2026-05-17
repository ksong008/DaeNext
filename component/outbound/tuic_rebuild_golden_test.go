/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"crypto/tls"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	outbounddialer "github.com/daeuniverse/outbound/dialer"
	outboundtuic "github.com/daeuniverse/outbound/dialer/tuic"
	"github.com/daeuniverse/outbound/netproxy"
	outboundprotocol "github.com/daeuniverse/outbound/protocol"
	protocoltuic "github.com/daeuniverse/outbound/protocol/tuic"
	outboundtuiccommon "github.com/daeuniverse/outbound/protocol/tuic/common"
)

func TestWriteTuicNativeOptInGoldenFixture(t *testing.T) {
	writeOrCheckOutboundGolden(t,
		"../../testdata/rebuild-golden/outbound/protocol/tuic_native_optin.json",
		rebuildGoldenStage15TuicNativeOptIn(t),
	)
}

func rebuildGoldenStage15TuicNativeOptIn(t testing.TB) any {
	t.Helper()

	basic := "tuic://7c12c745-63a5-433d-9e60-022e469b5bd4:pass@example.com:443?congestion_control=bbr&alpn=h3,h2&udp_relay_mode=quic#basic"
	peer := "tuic://7c12c745-63a5-433d-9e60-022e469b5bd4:pass@example.com:8443?sni=sni.example&peer=peer.example&allowInsecure=true#peer"
	disableSni := "tuic://7c12c745-63a5-433d-9e60-022e469b5bd4:pass@example.com:443?disable_sni=true&sni=sni.example#no-sni"

	return map[string]any{
		"name": "stage15-tuic-native-optin",
		"source": []string{
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.15",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.21",
			"/root/project/outbound/dialer/tuic/tuic.go",
			"/root/project/outbound/protocol/tuic/dialer.go",
			"/root/project/outbound/protocol/tuic/common/congestion.go",
			"/root/project/outbound/protocol/tuic/common/type.go",
		},
		"default_go_path":   true,
		"rust_adapter_mode": "native-opt-in",
		"protocol_scope": []string{
			"tuic",
		},
		"deferred_protocol_scope": []string{
			"juicity",
			"anytls",
			"transport-combos",
		},
		"link_parser": []map[string]any{
			rebuildTuicLinkCase(t, "basic-quic-flag", basic, true),
			rebuildTuicLinkCase(t, "peer-overrides-sni", peer, true),
			rebuildTuicLinkCase(t, "disable-sni-forces-insecure", disableSni, true),
		},
		"allow_insecure_aliases": []map[string]any{
			rebuildTuicAllowInsecureAlias(t, "allowInsecure", "tuic://7c12c745-63a5-433d-9e60-022e469b5bd4:pass@example.com:443?allowInsecure=1#alias"),
			rebuildTuicAllowInsecureAlias(t, "allow_insecure", "tuic://7c12c745-63a5-433d-9e60-022e469b5bd4:pass@example.com:443?allow_insecure=true#alias"),
			rebuildTuicAllowInsecureAlias(t, "allowinsecure", "tuic://7c12c745-63a5-433d-9e60-022e469b5bd4:pass@example.com:443?allowinsecure=true#alias"),
			rebuildTuicAllowInsecureAlias(t, "skipVerify", "tuic://7c12c745-63a5-433d-9e60-022e469b5bd4:pass@example.com:443?skipVerify=1#alias"),
		},
		"uuid_contract": map[string]any{
			"valid":          "7c12c745-63a5-433d-9e60-022e469b5bd4",
			"invalid":        "not-a-uuid",
			"invalid_error":  rebuildTuicInvalidUUIDCase(t),
			"validated_by":   "/root/project/outbound/protocol/tuic/dialer.go",
			"parser_accepts": "URL parser preserves user; protocol.NewDialer rejects non-UUID user",
		},
		"quic_contract": map[string]any{
			"tls_min_version":                    int(tls.VersionTLS13),
			"enable_datagrams":                   true,
			"keepalive_seconds":                  int((3 * time.Second) / time.Second),
			"handshake_idle_timeout_seconds":     int((8 * time.Second) / time.Second),
			"initial_stream_receive_window":      outboundtuiccommon.InitialStreamReceiveWindow,
			"max_stream_receive_window":          outboundtuiccommon.MaxStreamReceiveWindow,
			"initial_connection_receive_window":  outboundtuiccommon.InitialConnectionReceiveWindow,
			"max_connection_receive_window":      outboundtuiccommon.MaxConnectionReceiveWindow,
			"max_udp_relay_packet_size":          1400,
			"congestion_default_or_unknown_uses": "bbr",
		},
		"udp_relay_mode": map[string]any{
			"query_value":                  "quic",
			"adapter_sets_flag":            true,
			"flag_value":                   uint64(outboundprotocol.Flags_Tuic_UdpRelayModeQuic),
			"go_protocol_effective_mode":   "native",
			"go_common_quic_numeric_value": uint8(outboundtuiccommon.QUIC),
			"go_common_native_value":       uint8(outboundtuiccommon.NATIVE),
			"quic_mode_fixme_deferred":     true,
		},
		"underlay_contract": map[string]any{
			"tcp_request":                   rebuildTuicUnderlayCase(t, "tcp", 1234, true),
			"udp_request":                   rebuildTuicUnderlayCase(t, "udp", 1234, true),
			"tcp_underlay_uses_udp":         true,
			"tcp_underlay_preserves_mark":   true,
			"tcp_underlay_drops_mptcp":      true,
			"udp_underlay_uses_original":    true,
			"true_quic_data_plane_deferred": 113,
		},
		"live_smoke_required": []string{
			"local parser smoke for TUIC",
			"local UUID validation smoke",
			"local QUIC/underlay contract smoke",
		},
	}
}

func rebuildTuicLinkCase(t testing.TB, name string, raw string, buildProperty bool) map[string]any {
	t.Helper()

	tuic, err := outboundtuic.ParseTuicURL(raw)
	if err != nil {
		t.Fatalf("ParseTuicURL(%q): %v", raw, err)
	}
	propertyName := tuic.Name
	propertyAddress := tuic.Server + ":" + intToStringForFixture(tuic.Port)
	propertyProtocol := "tuic"
	propertyLink := tuic.ExportToURL()
	if buildProperty {
		_, property, err := outboundtuic.NewTuic(&outbounddialer.ExtraOption{}, noDialSocks5Dialer{}, raw)
		if err != nil {
			t.Fatalf("NewTuic(%q): %v", raw, err)
		}
		propertyName = property.Name
		propertyAddress = property.Address
		propertyProtocol = property.Protocol
		propertyLink = property.Link
	}
	return map[string]any{
		"name":               name,
		"input":              raw,
		"user":               tuic.User,
		"password":           tuic.Password,
		"server":             tuic.Server,
		"port":               tuic.Port,
		"sni":                tuic.Sni,
		"allowInsecure":      tuic.AllowInsecure,
		"disable_sni":        tuic.DisableSni,
		"congestion_control": tuic.CongestionControl,
		"alpn":               tuic.Alpn,
		"udp_relay_mode":     tuic.UdpRelayMode,
		"protocol":           tuic.Protocol,
		"export":             tuic.ExportToURL(),
		"property_name":      propertyName,
		"property_address":   propertyAddress,
		"property_protocol":  propertyProtocol,
		"property_link":      propertyLink,
	}
}

func rebuildTuicAllowInsecureAlias(t testing.TB, name string, raw string) map[string]any {
	t.Helper()

	tuic, err := outboundtuic.ParseTuicURL(raw)
	if err != nil {
		t.Fatalf("ParseTuicURL(%q): %v", raw, err)
	}
	return map[string]any{
		"name":          name,
		"input":         raw,
		"allowInsecure": tuic.AllowInsecure,
		"export":        tuic.ExportToURL(),
	}
}

func rebuildTuicInvalidUUIDCase(t testing.TB) map[string]any {
	t.Helper()

	_, err := protocoltuic.NewDialer(noDialSocks5Dialer{}, outboundprotocol.Header{
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

func rebuildTuicUnderlayCase(t testing.TB, network string, mark uint32, mptcp bool) map[string]any {
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

func intToStringForFixture(value int) string {
	if value == 0 {
		return "0"
	}
	digits := make([]byte, 0, 8)
	for value > 0 {
		digits = append(digits, byte('0'+value%10))
		value /= 10
	}
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	return string(digits)
}

func BenchmarkTuicNativeOptInParseLink(b *testing.B) {
	link := "tuic://7c12c745-63a5-433d-9e60-022e469b5bd4:pass@example.com:443?congestion_control=bbr&alpn=h3,h2&udp_relay_mode=quic#basic"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := outboundtuic.ParseTuicURL(link); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTuicNativeOptInExportLink(b *testing.B) {
	tuic, err := outboundtuic.ParseTuicURL("tuic://7c12c745-63a5-433d-9e60-022e469b5bd4:pass@example.com:443?congestion_control=bbr&alpn=h3,h2&udp_relay_mode=quic#basic")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = tuic.ExportToURL()
	}
}

func BenchmarkTuicNativeOptInAlpnSplit(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		alpn := strings.Split("h3,h2,http/1.1", ",")
		for i := range alpn {
			alpn[i] = strings.TrimSpace(alpn[i])
		}
	}
}

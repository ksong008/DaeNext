/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	outbounddialer "github.com/daeuniverse/outbound/dialer"
	outboundtrojandialer "github.com/daeuniverse/outbound/dialer/trojan"
	outboundprotocol "github.com/daeuniverse/outbound/protocol"
	outboundtrojanc "github.com/daeuniverse/outbound/protocol/trojanc"
)

func TestWriteTrojanNativeOptInGoldenFixture(t *testing.T) {
	writeOrCheckOutboundGolden(t,
		"../../testdata/rebuild-golden/outbound/protocol/trojan_native_optin.json",
		rebuildGoldenStage15TrojanNativeOptIn(t),
	)
}

func rebuildGoldenStage15TrojanNativeOptIn(t testing.TB) any {
	t.Helper()

	return map[string]any{
		"name": "stage15-trojan-native-optin",
		"source": []string{
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.11",
			"/root/project/outbound/dialer/trojan/trojan.go",
			"/root/project/outbound/protocol/trojanc/addr.go",
			"/root/project/outbound/protocol/trojanc/conn.go",
			"/root/project/outbound/protocol/trojanc/dialer.go",
			"/root/project/outbound/protocol/trojanc/packet.go",
		},
		"default_go_path":   true,
		"rust_adapter_mode": "native-opt-in",
		"protocol_scope": []string{
			"trojan",
			"trojan-go",
			"trojanc",
		},
		"deferred_protocol_scope": []string{
			"vmess",
			"vless",
			"hysteria2",
			"tuic",
			"juicity",
			"anytls",
			"transport-combos",
		},
		"link_parser": []map[string]any{
			rebuildTrojanLinkCase(t, "trojan-peer-priority", "trojan://password@example.com:443?peer=peer.example&sni=sni.example&allow_insecure=true#node"),
			rebuildTrojanLinkCase(t, "trojan-default-sni", "trojan://password@example.com:443#plain"),
			rebuildTrojanLinkCase(t, "trojan-go-ws", "trojan-go://password@example.com:443?type=ws&host=front.example&path=/ws&sni=sni.example#ws"),
			rebuildTrojanLinkCase(t, "trojan-type-forces-trojan-go-grpc", "trojan://password@example.com:443?type=grpc&path=GunPath&sni=sni.example#grpc"),
			rebuildTrojanLinkCase(t, "trojan-go-httpupgrade", "trojan-go://password@example.com:443?type=httpupgrade&host=front.example&path=/up#hu"),
			rebuildTrojanLinkCase(t, "trojan-go-ss-encryption", "trojan-go://password@example.com:443?type=ws&host=front.example&path=/ws&encryption=ss%3Baes-128-gcm%3Bsecret#ss"),
		},
		"metadata": []map[string]any{
			rebuildTrojanMetadataCase(t, "domain-tcp", "tcp", "example.com:443"),
			rebuildTrojanMetadataCase(t, "domain-udp", "udp", "example.com:443"),
			rebuildTrojanMetadataCase(t, "ipv4-udp", "udp", "1.2.3.4:53"),
			rebuildTrojanMetadataCase(t, "ipv6-tcp", "tcp", "[2001:db8::1]:8443"),
		},
		"framing": map[string]any{
			"password":                   "password",
			"password_sha224_hex":        trojanPasswordHash("password"),
			"crlf_hex":                   hex.EncodeToString(outboundtrojanc.CRLF),
			"network_tcp":                outboundtrojanc.NetworkToByte("tcp"),
			"network_udp":                outboundtrojanc.NetworkToByte("udp"),
			"tcp_request_header":         rebuildTrojanTCPRequestHeaderCase(t, "password", "tcp", "example.com:443", []byte("ping")),
			"udp_packet":                 rebuildTrojanUDPPacketCase(t, "example.com:443", []byte("ping")),
			"udp_over_tcp_stream":        true,
			"magic_network_underlay_tcp": true,
		},
		"transport_contract": map[string]any{
			"default_trojan_tls_before_trojanc": true,
			"trojan_go_grpc_contains_tls":       true,
			"trojan_go_grpc_no_outer_tls":       true,
			"trojan_go_ss_inner_layer":          true,
			"shared_transport_deferred_to_item": 113,
		},
		"live_smoke_required": []string{
			"local parser smoke for trojan and trojan-go",
			"local trojanc TCP request header framing smoke",
			"local trojanc UDP packet-over-TCP framing smoke",
		},
	}
}

func rebuildTrojanLinkCase(t testing.TB, name string, raw string) map[string]any {
	t.Helper()

	trojan, err := outboundtrojandialer.ParseTrojanURL(raw)
	if err != nil {
		t.Fatalf("ParseTrojanURL(%q): %v", raw, err)
	}
	_, property, err := outbounddialer.NewNetproxyDialerFromLink(
		noDialSocks5Dialer{},
		&outbounddialer.ExtraOption{},
		raw,
	)
	if err != nil {
		t.Fatalf("NewNetproxyDialerFromLink(%q): %v", raw, err)
	}
	return map[string]any{
		"name":              name,
		"input":             raw,
		"server":            trojan.Server,
		"port":              trojan.Port,
		"password":          trojan.Password,
		"sni":               trojan.Sni,
		"type":              trojan.Type,
		"encryption":        trojan.Encryption,
		"host":              trojan.Host,
		"path":              trojan.Path,
		"serviceName":       trojan.ServiceName,
		"allowInsecure":     trojan.AllowInsecure,
		"protocol":          trojan.Protocol,
		"export":            trojan.ExportToURL(),
		"property_name":     property.Name,
		"property_address":  property.Address,
		"property_protocol": property.Protocol,
		"property_link":     property.Link,
	}
}

func rebuildTrojanMetadataCase(t testing.TB, name string, network string, target string) map[string]any {
	t.Helper()

	meta, err := outboundprotocol.ParseMetadata(target)
	if err != nil {
		t.Fatalf("ParseMetadata(%q): %v", target, err)
	}
	trojanMeta := outboundtrojanc.Metadata{
		Metadata: meta,
		Network:  network,
	}
	buf := make([]byte, trojanMeta.Len())
	n := trojanMeta.PackTo(buf)
	return map[string]any{
		"name":         name,
		"network":      network,
		"network_byte": outboundtrojanc.NetworkToByte(network),
		"input":        target,
		"type":         outboundtrojanc.MetadataTypeToByte(meta.Type),
		"hostname":     meta.Hostname,
		"port":         meta.Port,
		"len":          trojanMeta.Len(),
		"packed_len":   n,
		"hex":          hex.EncodeToString(buf[:n]),
	}
}

func rebuildTrojanTCPRequestHeaderCase(t testing.TB, password string, network string, target string, payload []byte) map[string]any {
	t.Helper()

	meta, err := outboundprotocol.ParseMetadata(target)
	if err != nil {
		t.Fatalf("ParseMetadata(%q): %v", target, err)
	}
	trojanMeta := outboundtrojanc.Metadata{
		Metadata: meta,
		Network:  network,
	}
	reqLen := trojanMeta.Len()
	buf := make([]byte, 56+2+1+reqLen+2+len(payload))
	copy(buf, []byte(trojanPasswordHash(password)))
	copy(buf[56:], outboundtrojanc.CRLF)
	buf[58] = outboundtrojanc.NetworkToByte(network)
	trojanMeta.PackTo(buf[59:])
	copy(buf[59+reqLen:], outboundtrojanc.CRLF)
	copy(buf[61+reqLen:], payload)
	return map[string]any{
		"network":       network,
		"network_byte":  outboundtrojanc.NetworkToByte(network),
		"target":        target,
		"payload_ascii": string(payload),
		"header_hex":    hex.EncodeToString(buf),
	}
}

func rebuildTrojanUDPPacketCase(t testing.TB, target string, payload []byte) map[string]any {
	t.Helper()

	meta, err := outboundprotocol.ParseMetadata(target)
	if err != nil {
		t.Fatalf("ParseMetadata(%q): %v", target, err)
	}
	trojanMeta := outboundtrojanc.Metadata{
		Metadata: meta,
		Network:  "udp",
	}
	buf := make([]byte, trojanMeta.Len()+4+len(payload))
	packet := outboundtrojanc.SealUDP(trojanMeta, buf, payload)
	return map[string]any{
		"target":        target,
		"payload_ascii": string(payload),
		"packet_hex":    hex.EncodeToString(packet),
		"length":        len(payload),
		"suffix_crlf":   true,
	}
}

func trojanPasswordHash(password string) string {
	hash := sha256.New224()
	hash.Write([]byte(password))
	return hex.EncodeToString(hash.Sum(nil))
}

func BenchmarkTrojanNativeOptInParseLink(b *testing.B) {
	link := "trojan-go://password@example.com:443?type=ws&host=front.example&path=/ws&encryption=ss%3Baes-128-gcm%3Bsecret#ss"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := outboundtrojandialer.ParseTrojanURL(link); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTrojanNativeOptInTCPRequestHeader(b *testing.B) {
	payload := []byte("ping")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = rebuildTrojanTCPRequestHeaderCase(b, "password", "tcp", "example.com:443", payload)
	}
}

func BenchmarkTrojanNativeOptInUDPPacket(b *testing.B) {
	payload := []byte("ping")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = rebuildTrojanUDPPacketCase(b, "example.com:443", payload)
	}
}

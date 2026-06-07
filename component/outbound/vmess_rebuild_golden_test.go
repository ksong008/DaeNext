/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	outboundcommon "github.com/daeuniverse/outbound/common"
	outbounddialer "github.com/daeuniverse/outbound/dialer"
	outboundv2ray "github.com/daeuniverse/outbound/dialer/v2ray"
	outboundprotocol "github.com/daeuniverse/outbound/protocol"
	outboundvmess "github.com/daeuniverse/outbound/protocol/vmess"
)

func TestWriteVMessNativeOptInGoldenFixture(t *testing.T) {
	writeOrCheckOutboundGolden(t,
		"../../testdata/rebuild-golden/outbound/protocol/vmess_native_optin.json",
		rebuildGoldenNativeVMessNativeOptIn(t),
	)
}

func rebuildGoldenNativeVMessNativeOptIn(t testing.TB) any {
	t.Helper()

	jsonLink := (&outboundv2ray.V2Ray{
		Ps:       "json-aead",
		Add:      "example.com",
		Port:     "443",
		ID:       "7c12c745-63a5-433d-9e60-022e469b5bd4",
		Aid:      "0",
		Net:      "ws",
		Type:     "none",
		Host:     "front.example",
		SNI:      "sni.example",
		Path:     "/ws",
		TLS:      "tls",
		Protocol: "vmess",
		V:        "2",
	}).ExportToURL()
	legacyRaw := "auto:7c12c745-63a5-433d-9e60-022e469b5bd4@legacy.example:8443"
	legacyLink := "vmess://" + base64.StdEncoding.EncodeToString([]byte(legacyRaw)) + "?remarks=legacy&obfs=websocket&path=/legacy&obfsParam=%7B%22host%22%3A%22legacy-front.example%22%7D&tls=1&peer=legacy-sni.example"
	hostPathLink := (&outboundv2ray.V2Ray{
		Ps:       "host-path",
		Add:      "example.com",
		Port:     "443",
		ID:       "7c12c745-63a5-433d-9e60-022e469b5bd4",
		Aid:      "0",
		Net:      "tcp",
		Type:     "none",
		Host:     "/moved-path",
		TLS:      "none",
		Protocol: "vmess",
		V:        "2",
	}).ExportToURL()
	grpcLink := (&outboundv2ray.V2Ray{
		Ps:       "grpc",
		Add:      "grpc.example",
		Port:     "443",
		ID:       "7c12c745-63a5-433d-9e60-022e469b5bd4",
		Aid:      "0",
		Net:      "grpc",
		Path:     "GunService",
		Host:     "grpc-host.example",
		SNI:      "grpc-sni.example",
		TLS:      "tls",
		Protocol: "vmess",
		V:        "2",
	}).ExportToURL()

	return map[string]any{
		"name": "vmess-native-optin",
		"source": []string{
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.4",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.5",
			"/root/project/outbound/dialer/v2ray/v2ray.go",
			"/root/project/outbound/protocol/vmess/dialer.go",
			"/root/project/outbound/protocol/vmess/addr.go",
			"/root/project/outbound/protocol/vmess/cipher.go",
			"/root/project/outbound/protocol/vmess/packetaddr.go",
		},
		"default_go_path":   true,
		"rust_adapter_mode": "native-opt-in",
		"protocol_scope": []string{
			"vmess",
		},
		"deferred_protocol_scope": []string{
			"vless",
			"hysteria2",
			"tuic",
			"juicity",
			"anytls",
			"transport-combos",
		},
		"link_parser": []map[string]any{
			rebuildVMessLinkCase(t, "json-aead-ws-tls", jsonLink),
			rebuildVMessLinkCase(t, "legacy-websocket-tls", legacyLink),
			rebuildVMessLinkCase(t, "host-leading-slash-moves-to-path", hostPathLink),
			rebuildVMessLinkCase(t, "grpc-transport-contract", grpcLink),
		},
		"unsupported": map[string]any{
			"non_aead_alter_id_error": rebuildVMessUnsupportedAidCase(t),
			"reality_error":           "only VLESS supports reality",
		},
		"uuid": map[string]any{
			"canonical":                     "7c12c745-63a5-433d-9e60-022e469b5bd4",
			"short_input":                   "short-id",
			"short_uuid5":                   outboundcommon.StringToUUID5("short-id"),
			"long_input":                    "0123456789abcdef0123456789abcdef-extra",
			"long_uuid5":                    outboundcommon.StringToUUID5("0123456789abcdef0123456789abcdef-extra"),
			"uuid5_when_len_lt_32_or_gt_36": true,
		},
		"metadata": []map[string]any{
			rebuildVMessMetadataCase(t, "domain-tcp", "tcp", "example.com:443"),
			rebuildVMessMetadataCase(t, "domain-udp", "udp", "example.com:443"),
			rebuildVMessMetadataCase(t, "ipv4-udp", "udp", "1.2.3.4:53"),
			rebuildVMessMetadataCase(t, "ipv6-tcp", "tcp", "[2001:db8::1]:8443"),
		},
		"header_contract": map[string]any{
			"version":                         1,
			"option_chunk_stream":             outboundvmess.OptionChunkStream,
			"option_chunk_length_masking":     outboundvmess.OptionChunkLengthMasking,
			"option_global_padding":           outboundvmess.OptionGlobalPadding,
			"security_auto_cipher":            outboundvmess.Cipher(outboundv2rayGetAutoCipher()).ToSecurity(),
			"network_tcp":                     outboundvmess.NetworkToByte("tcp"),
			"network_udp":                     outboundvmess.NetworkToByte("udp"),
			"network_mux":                     outboundvmess.NetworkToByte("mux"),
			"metadata_domain_type":            outboundvmess.MetadataTypeToByte(outboundprotocol.MetadataTypeDomain),
			"packet_addr_udp_domain_contract": true,
		},
		"transport_contract": map[string]any{
			"ws_tls_uses_wss":                   true,
			"grpc_default_service_name":         "GunService",
			"http_h2_httpupgrade_meek_xhttp":    "deferred-to-shared-transport",
			"vmess_reality_must_error":          true,
			"shared_transport_deferred_to_item": 113,
		},
		"live_smoke_required": []string{
			"local parser smoke for VMess AEAD JSON",
			"local parser smoke for legacy VMess",
			"local VMess metadata/header contract smoke",
		},
	}
}

func rebuildVMessLinkCase(t testing.TB, name string, raw string) map[string]any {
	t.Helper()

	vmess, err := outboundv2ray.ParseVmessURL(raw)
	if err != nil {
		t.Fatalf("ParseVmessURL(%q): %v", raw, err)
	}
	_, property, err := outboundv2ray.NewV2Ray(&outbounddialer.ExtraOption{}, noDialSocks5Dialer{}, raw)
	if err != nil {
		t.Fatalf("NewV2Ray(%q): %v", raw, err)
	}
	return map[string]any{
		"name":              name,
		"input":             raw,
		"ps":                vmess.Ps,
		"add":               vmess.Add,
		"port":              vmess.Port,
		"id":                vmess.ID,
		"aid":               vmess.Aid,
		"net":               vmess.Net,
		"type":              vmess.Type,
		"host":              vmess.Host,
		"sni":               vmess.SNI,
		"path":              vmess.Path,
		"tls":               vmess.TLS,
		"allowInsecure":     vmess.AllowInsecure,
		"protocol":          vmess.Protocol,
		"export":            vmess.ExportToURL(),
		"property_name":     property.Name,
		"property_address":  property.Address,
		"property_protocol": property.Protocol,
		"property_link":     property.Link,
	}
}

func rebuildVMessUnsupportedAidCase(t testing.TB) map[string]any {
	t.Helper()

	link := (&outboundv2ray.V2Ray{
		Ps:       "bad-aid",
		Add:      "example.com",
		Port:     "443",
		ID:       "7c12c745-63a5-433d-9e60-022e469b5bd4",
		Aid:      "1",
		Net:      "tcp",
		Type:     "none",
		TLS:      "none",
		Protocol: "vmess",
		V:        "2",
	}).ExportToURL()
	_, _, err := outboundv2ray.NewV2Ray(&outbounddialer.ExtraOption{}, noDialSocks5Dialer{}, link)
	return map[string]any{
		"input":          link,
		"ok":             err == nil,
		"error_contains": "we only support AEAD encryption",
	}
}

func rebuildVMessMetadataCase(t testing.TB, name string, network string, target string) map[string]any {
	t.Helper()

	meta, err := outboundprotocol.ParseMetadata(target)
	if err != nil {
		t.Fatalf("ParseMetadata(%q): %v", target, err)
	}
	vmessMeta := outboundvmess.Metadata{
		Metadata: meta,
		Network:  network,
	}
	buf := make([]byte, vmessMeta.AddrLen())
	n := vmessMeta.PutAddr(buf)
	return map[string]any{
		"name":         name,
		"network":      network,
		"network_byte": outboundvmess.NetworkToByte(network),
		"input":        target,
		"type":         outboundvmess.MetadataTypeToByte(meta.Type),
		"hostname":     meta.Hostname,
		"port":         meta.Port,
		"addr_len":     vmessMeta.AddrLen(),
		"packed_len":   n,
		"addr_hex":     hex.EncodeToString(buf[:n]),
	}
}

func outboundv2rayGetAutoCipher() string {
	return "auto"
}

func BenchmarkVMessNativeOptInParseLink(b *testing.B) {
	link := (&outboundv2ray.V2Ray{
		Ps:       "json-aead",
		Add:      "example.com",
		Port:     "443",
		ID:       "7c12c745-63a5-433d-9e60-022e469b5bd4",
		Aid:      "0",
		Net:      "ws",
		Type:     "none",
		Host:     "front.example",
		Path:     "/ws",
		TLS:      "tls",
		Protocol: "vmess",
		V:        "2",
	}).ExportToURL()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := outboundv2ray.ParseVmessURL(link); err != nil {
			b.Fatal(err)
		}
	}
}

var vmessNativeOptInBenchmarkSink int

func BenchmarkVMessNativeOptInMetadataBytes(b *testing.B) {
	meta, err := outboundprotocol.ParseMetadata("example.com:443")
	if err != nil {
		b.Fatal(err)
	}
	vmessMeta := outboundvmess.Metadata{Metadata: meta, Network: "tcp"}
	buf := make([]byte, vmessMeta.AddrLen())
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		n := vmessMeta.PutAddr(buf)
		vmessNativeOptInBenchmarkSink ^= n ^ int(buf[0])
	}
}

func BenchmarkVMessNativeOptInUUID5Compatibility(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = outboundcommon.StringToUUID5("short-id")
	}
}

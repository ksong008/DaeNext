/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"encoding/hex"
	"io"
	"strings"
	"testing"
	"time"

	outboundcommon "github.com/daeuniverse/outbound/common"
	outbounddialer "github.com/daeuniverse/outbound/dialer"
	outboundv2ray "github.com/daeuniverse/outbound/dialer/v2ray"
	outboundprotocol "github.com/daeuniverse/outbound/protocol"
	outboundvless "github.com/daeuniverse/outbound/protocol/vless"
	outboundvmess "github.com/daeuniverse/outbound/protocol/vmess"
)

func TestWriteVLESSNativeOptInGoldenFixture(t *testing.T) {
	writeOrCheckOutboundGolden(t,
		"../../testdata/rebuild-golden/outbound/protocol/vless_native_optin.json",
		rebuildGoldenNativeVLESSNativeOptIn(t),
	)
}

func rebuildGoldenNativeVLESSNativeOptIn(t testing.TB) any {
	t.Helper()

	tcpVision := (&outboundv2ray.V2Ray{
		Ps:          "tcp-vision",
		Add:         "example.com",
		Port:        "443",
		ID:          "7c12c745-63a5-433d-9e60-022e469b5bd4",
		Net:         "tcp",
		Type:        "none",
		TLS:         "tls",
		SNI:         "server.example",
		Fingerprint: "chrome",
		Alpn:        "h2,http/1.1",
		Flow:        outboundvless.XRV,
		Protocol:    "vless",
	}).ExportToURL()
	xhttpFlowNone := "vless://7c12c745-63a5-433d-9e60-022e469b5bd4@156.246.90.2:18447?type=xhttp&security=tls&host=office.mitsuha.me&headerType=none&sni=office.mitsuha.me&flow=none&allowInsecure=false&path=%2Fxhttp&mode=packet-up&alpn=h3&fp=chrome#xhttp-h3-packet-up-18447"
	xhttpReality := (&outboundv2ray.V2Ray{
		Ps:          "xhttp-reality",
		Add:         "example.com",
		Port:        "443",
		ID:          "7c12c745-63a5-433d-9e60-022e469b5bd4",
		Net:         "xhttp",
		Host:        "example.com",
		Path:        "/x",
		TLS:         "reality",
		SNI:         "server.example",
		Fingerprint: "chrome",
		PublicKey:   "pubkey",
		ShortId:     "abcd",
		SpiderX:     "/",
		XHTTPMode:   "auto",
		Protocol:    "vless",
	}).ExportToURL()
	grpc := (&outboundv2ray.V2Ray{
		Ps:       "grpc",
		Add:      "grpc.example",
		Port:     "443",
		ID:       "7c12c745-63a5-433d-9e60-022e469b5bd4",
		Net:      "grpc",
		Path:     "",
		Host:     "grpc-host.example",
		SNI:      "grpc-sni.example",
		TLS:      "tls",
		Protocol: "vless",
	}).ExportToURL()
	meek := (&outboundv2ray.V2Ray{
		Ps:       "meek",
		Add:      "example.com",
		Port:     "443",
		ID:       "7c12c745-63a5-433d-9e60-022e469b5bd4",
		Net:      "meek",
		Path:     "https://front.example/meek",
		TLS:      "tls",
		SNI:      "front.example",
		Protocol: "vless",
	}).ExportToURL()

	return map[string]any{
		"name": "vless-native-optin",
		"source": []string{
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.4",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.5",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.6",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.7",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.8",
			"/root/project/outbound/dialer/v2ray/v2ray.go",
			"/root/project/outbound/protocol/vless/dialer.go",
			"/root/project/outbound/protocol/vless/key.go",
			"/root/project/outbound/protocol/vless/conn.go",
			"/root/project/outbound/protocol/vless/vision",
		},
		"default_go_path":   true,
		"rust_adapter_mode": "native-opt-in",
		"protocol_scope": []string{
			"vless",
		},
		"deferred_protocol_scope": []string{
			"hysteria2",
			"tuic",
			"juicity",
			"anytls",
			"transport-combos",
		},
		"link_parser": []map[string]any{
			rebuildVLESSLinkCase(t, "tcp-tls-vision", tcpVision, true),
			rebuildVLESSLinkCase(t, "xhttp-flow-none-omitted", xhttpFlowNone, true),
			rebuildVLESSLinkCase(t, "xhttp-reality-contract", xhttpReality, false),
			rebuildVLESSLinkCase(t, "grpc-default-service", grpc, true),
			rebuildVLESSLinkCase(t, "meek-url-field", meek, true),
		},
		"allow_insecure_aliases": []map[string]any{
			rebuildVLESSAllowInsecureAlias(t, "skipVerify", "vless://uuid@example.com:443?type=tcp&security=tls&skipVerify=1#node"),
			rebuildVLESSAllowInsecureAlias(t, "allow_insecure", "vless://uuid@example.com:443?type=tcp&security=tls&allow_insecure=true#node"),
			rebuildVLESSAllowInsecureAlias(t, "allowinsecure", "vless://uuid@example.com:443?type=tcp&security=tls&allowinsecure=1#node"),
		},
		"unsupported": map[string]any{
			"unsupported_flow_error":    rebuildVLESSUnsupportedFlowCase(t),
			"server_mode_vision_error":  rebuildVLESSServerModeVisionCase(t),
			"tcp_bad_header_type_error": rebuildVLESSTCPBadHeaderTypeCase(t),
		},
		"key": map[string]any{
			"canonical":                     "7c12c745-63a5-433d-9e60-022e469b5bd4",
			"canonical_key_hex":             rebuildVLESSPassword2KeyHex(t, "7c12c745-63a5-433d-9e60-022e469b5bd4"),
			"short_input":                   "short-id",
			"short_uuid5":                   outboundcommon.StringToUUID5("short-id"),
			"short_key_hex":                 rebuildVLESSPassword2KeyHex(t, "short-id"),
			"uuid5_when_len_lt_32_or_gt_36": true,
		},
		"request_header": []map[string]any{
			rebuildVLESSRequestHeaderCase(t, "tcp-domain", "", "tcp", "example.com:443", false, "ping"),
			rebuildVLESSRequestHeaderCase(t, "tcp-vision-addons", outboundvless.XRV, "tcp", "example.com:443", false, "ping"),
			rebuildVLESSRequestHeaderCase(t, "udp-length-prefix", "", "udp", "1.2.3.4:53", false, "ping"),
			rebuildVLESSRequestHeaderCase(t, "mux-command", "", "tcp", "example.com:443", true, "ping"),
		},
		"transport_contract": map[string]any{
			"vision_flow":                         outboundvless.XRV,
			"vision_requires_tls_or_reality_hook": true,
			"flow_none_canonical_empty":           true,
			"reality_allowed_for_vless":           true,
			"grpc_default_service_name":           "GunService",
			"xhttp_mode_auto_export_omitted":      true,
			"shared_transport_deferred_to_item":   113,
		},
		"live_smoke_required": []string{
			"local parser smoke for VLESS TCP TLS Vision",
			"local parser smoke for VLESS xHTTP TLS and REALITY",
			"local VLESS key/request-header contract smoke",
		},
	}
}

func rebuildVLESSLinkCase(t testing.TB, name string, raw string, buildProperty bool) map[string]any {
	t.Helper()

	vless, err := outboundv2ray.ParseVlessURL(raw)
	if err != nil {
		t.Fatalf("ParseVlessURL(%q): %v", raw, err)
	}
	propertyName := vless.Ps
	propertyAddress := vless.Add + ":" + vless.Port
	propertyProtocol := vless.Protocol
	propertyLink := vless.ExportToURL()
	if buildProperty {
		_, property, err := outboundv2ray.NewV2Ray(&outbounddialer.ExtraOption{}, noDialSocks5Dialer{}, raw)
		if err != nil {
			t.Fatalf("NewV2Ray(%q): %v", raw, err)
		}
		propertyName = property.Name
		propertyAddress = property.Address
		propertyProtocol = property.Protocol
		propertyLink = property.Link
	}
	return map[string]any{
		"name":              name,
		"input":             raw,
		"ps":                vless.Ps,
		"add":               vless.Add,
		"port":              vless.Port,
		"id":                vless.ID,
		"net":               vless.Net,
		"type":              vless.Type,
		"host":              vless.Host,
		"sni":               vless.SNI,
		"path":              vless.Path,
		"mode":              vless.XHTTPMode,
		"extra":             vless.XHTTPExtra,
		"tls":               vless.TLS,
		"flow":              vless.Flow,
		"alpn":              vless.Alpn,
		"allowInsecure":     vless.AllowInsecure,
		"fp":                vless.Fingerprint,
		"pbk":               vless.PublicKey,
		"sid":               vless.ShortId,
		"spx":               vless.SpiderX,
		"protocol":          vless.Protocol,
		"export":            vless.ExportToURL(),
		"property_name":     propertyName,
		"property_address":  propertyAddress,
		"property_protocol": propertyProtocol,
		"property_link":     propertyLink,
	}
}

func rebuildVLESSAllowInsecureAlias(t testing.TB, name string, raw string) map[string]any {
	t.Helper()
	vless, err := outboundv2ray.ParseVlessURL(raw)
	if err != nil {
		t.Fatalf("ParseVlessURL(%q): %v", raw, err)
	}
	return map[string]any{
		"name":          name,
		"input":         raw,
		"allowInsecure": vless.AllowInsecure,
		"export":        vless.ExportToURL(),
	}
}

func rebuildVLESSUnsupportedFlowCase(t testing.TB) map[string]any {
	t.Helper()
	_, err := outboundvless.NewDialer(noDialSocks5Dialer{}, outboundprotocol.Header{
		ProxyAddress: "example.com:443",
		Password:     "00000000-0000-0000-0000-000000000000",
		IsClient:     true,
		Feature1:     "xtls-rprx-vision-udp443",
	})
	return map[string]any{
		"ok":             err == nil,
		"input_flow":     "xtls-rprx-vision-udp443",
		"error_contains": "unsupported xtls flow type",
	}
}

func rebuildVLESSServerModeVisionCase(t testing.TB) map[string]any {
	t.Helper()
	_, err := outboundvless.NewDialer(noDialSocks5Dialer{}, outboundprotocol.Header{
		ProxyAddress: "example.com:443",
		Password:     "00000000-0000-0000-0000-000000000000",
		IsClient:     false,
		Feature1:     outboundvless.XRV,
	})
	return map[string]any{
		"ok":             err == nil,
		"input_flow":     outboundvless.XRV,
		"error_contains": "unsupported server mode xtls flow type",
	}
}

func rebuildVLESSTCPBadHeaderTypeCase(t testing.TB) map[string]any {
	t.Helper()
	link := "vless://7c12c745-63a5-433d-9e60-022e469b5bd4@example.com:443?type=tcp&headerType=http&security=none#bad"
	_, _, err := outboundv2ray.NewV2Ray(&outbounddialer.ExtraOption{}, noDialSocks5Dialer{}, link)
	return map[string]any{
		"input":          link,
		"ok":             err == nil,
		"error_contains": "unexpected field",
	}
}

func rebuildVLESSPassword2KeyHex(t testing.TB, password string) string {
	t.Helper()
	key, err := outboundvless.Password2Key(password)
	if err != nil {
		t.Fatalf("Password2Key(%q): %v", password, err)
	}
	return hex.EncodeToString(key)
}

func rebuildVLESSRequestHeaderCase(t testing.TB, name string, flow string, network string, target string, mux bool, payload string) map[string]any {
	t.Helper()

	meta, err := outboundprotocol.ParseMetadata(target)
	if err != nil {
		t.Fatalf("ParseMetadata(%q): %v", target, err)
	}
	meta.IsClient = true
	key, err := outboundvless.Password2Key("7c12c745-63a5-433d-9e60-022e469b5bd4")
	if err != nil {
		t.Fatalf("Password2Key: %v", err)
	}
	capture := &captureVLESSConn{}
	conn, err := outboundvless.NewConn(capture, outboundvless.Metadata{
		Metadata: outboundvmess.Metadata{
			Metadata: meta,
			Network:  network,
		},
		Flow: flow,
		Mux:  mux,
	}, key)
	if err != nil {
		t.Fatalf("NewConn(%s): %v", name, err)
	}
	if _, err = conn.Write([]byte(payload)); err != nil {
		t.Fatalf("Write(%s): %v", name, err)
	}
	vmessMeta := outboundvmess.Metadata{Metadata: meta, Network: network}
	headerHex := hex.EncodeToString(capture.writes)
	return map[string]any{
		"name":              name,
		"flow":              flow,
		"network":           network,
		"target":            target,
		"mux":               mux,
		"payload_ascii":     payload,
		"key_hex":           hex.EncodeToString(key),
		"metadata_type":     outboundvmess.MetadataTypeToByte(meta.Type),
		"network_byte":      outboundvmess.NetworkToByte(network),
		"mux_network_byte":  outboundvmess.NetworkToByte("mux"),
		"addr_len":          vmessMeta.AddrLen(),
		"captured_hex":      headerHex,
		"contains_payload":  strings.Contains(headerHex, hex.EncodeToString([]byte(payload))),
		"addons_flow_bytes": hex.EncodeToString([]byte(flow)),
	}
}

type captureVLESSConn struct {
	writes []byte
}

func (c *captureVLESSConn) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (c *captureVLESSConn) Write(b []byte) (int, error) {
	c.writes = append(c.writes, b...)
	return len(b), nil
}

func (*captureVLESSConn) Close() error {
	return nil
}

func (*captureVLESSConn) SetDeadline(time.Time) error {
	return nil
}

func (*captureVLESSConn) SetReadDeadline(time.Time) error {
	return nil
}

func (*captureVLESSConn) SetWriteDeadline(time.Time) error {
	return nil
}

func BenchmarkVLESSNativeOptInParseLink(b *testing.B) {
	link := (&outboundv2ray.V2Ray{
		Ps:          "tcp-vision",
		Add:         "example.com",
		Port:        "443",
		ID:          "7c12c745-63a5-433d-9e60-022e469b5bd4",
		Net:         "tcp",
		Type:        "none",
		TLS:         "tls",
		SNI:         "server.example",
		Fingerprint: "chrome",
		Alpn:        "h2,http/1.1",
		Flow:        outboundvless.XRV,
		Protocol:    "vless",
	}).ExportToURL()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := outboundv2ray.ParseVlessURL(link); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVLESSNativeOptInPassword2Key(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := outboundvless.Password2Key("short-id"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVLESSNativeOptInRequestHeader(b *testing.B) {
	meta, err := outboundprotocol.ParseMetadata("1.2.3.4:53")
	if err != nil {
		b.Fatal(err)
	}
	meta.IsClient = true
	key, err := outboundvless.Password2Key("7c12c745-63a5-433d-9e60-022e469b5bd4")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		capture := &captureVLESSConn{}
		conn, err := outboundvless.NewConn(capture, outboundvless.Metadata{
			Metadata: outboundvmess.Metadata{
				Metadata: meta,
				Network:  "udp",
			},
		}, key)
		if err != nil {
			b.Fatal(err)
		}
		if _, err = conn.Write([]byte("ping")); err != nil {
			b.Fatal(err)
		}
	}
}

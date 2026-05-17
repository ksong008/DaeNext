/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

func TestWriteSharedTransportNativeOptInGoldenFixture(t *testing.T) {
	writeOrCheckOutboundGolden(t,
		"../../testdata/rebuild-golden/outbound/protocol/shared_transport_native_optin.json",
		rebuildGoldenStage15SharedTransportNativeOptIn(t),
	)
}

func rebuildGoldenStage15SharedTransportNativeOptIn(t testing.TB) any {
	t.Helper()

	pbkBytes := []byte{
		0xfb, 0xff, 0xfe, 0xfa, 0xef, 0xee, 0xab, 0xcd,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfb, 0xff, 0xfe, 0xfa, 0xef, 0xee, 0xab, 0xcd,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	}
	xhttpExtra := `{"downloadSettings":{"address":"download.example","port":443,"network":"xhttp","security":"reality","xhttpSettings":{"host":"download.example","path":"/download","extra":"{\"xmux\":{\"maxConnections\":\"3\",\"cMaxReuseTimes\":\"9\"}}"}},"xmux":{"maxConnections":"1"},"xPaddingBytes":"100-200"}`
	xhttpExtraCanonical := canonicalJSONForSharedTransportFixture(t, xhttpExtra)

	return map[string]any{
		"name": "stage15-shared-transport-native-optin",
		"source": []string{
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.7",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.8",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.18",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.20",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.21",
			"/root/project/outbound/transport/tls/{dialer.go,tls.go,utls.go,reality.go,fragment.go}",
			"/root/project/outbound/transport/ws/{ws.go,dialer.go,conn.go}",
			"/root/project/outbound/transport/grpc/grpc_client.go",
			"/root/project/outbound/transport/httpupgrade/httpupgrade.go",
			"/root/project/outbound/transport/meek/{dialer.go,config.go,httprt.go}",
			"/root/project/outbound/transport/simpleobfs/{simpleobfs.go,http.go,tls.go}",
			"/root/project/outbound/transport/mux/{mux.go,conn.go}",
			"/root/project/outbound/transport/xhttp/xhttp.go",
			"/root/project/outbound/dialer/v2ray/v2ray.go",
		},
		"default_go_path":   true,
		"rust_adapter_mode": "native-opt-in-contract",
		"protocol_scope": []string{
			"transport-combos",
		},
		"transport_scope": []string{
			"tls",
			"utls",
			"reality",
			"ws",
			"wss",
			"grpc",
			"simpleobfs",
			"httpupgrade",
			"meek",
			"mux",
			"xhttp",
		},
		"tls_transport": map[string]any{
			"schemes":                 []string{"tls", "utls"},
			"allow_insecure_aliases":  []string{"allowInsecure", "allow_insecure", "allowinsecure", "skipVerify"},
			"allow_insecure_samples":  rebuildSharedAllowInsecureCases(),
			"utls_imitate_query":      "utlsImitate",
			"global_tls_fragment":     true,
			"tcp_preserves_network":   true,
			"udp_passthrough_key":     "passthroughUdp",
			"udp_passthrough_true":    true,
			"udp_without_passthrough": "unsupported",
		},
		"reality_transport": map[string]any{
			"sid_input":                     "0123456789abcdef",
			"sid_decoded_hex":               hex.EncodeToString(sharedRealitySIDForFixture(t, "0123456789abcdef")),
			"pbk_input":                     base64.RawURLEncoding.EncodeToString(pbkBytes),
			"pbk_decoded_hex":               hex.EncodeToString(pbkBytes),
			"sni_nosni":                     "",
			"spx_default":                   "/",
			"spx_input":                     "/?p=10-20&c=30&t=40&i=50&r=60-70",
			"spider_y":                      sharedRealitySpiderYForFixture("/?p=10-20&c=30&t=40&i=50&r=60-70"),
			"requires_utls_handshake_state": true,
			"verify_peer_certificate":       true,
			"data_plane_deferred":           true,
		},
		"ws_transport": map[string]any{
			"schemes":                 []string{"ws", "wss"},
			"wss_uses_tls":            true,
			"wss_fragment":            true,
			"allow_insecure_aliases":  []string{"allowInsecure", "allow_insecure", "allowinsecure", "skipVerify"},
			"passthrough_udp_true":    true,
			"udp_without_passthrough": "unsupported",
		},
		"grpc_transport": map[string]any{
			"global_client_connection_cache": true,
			"clean_cache_hook":               "CleanGlobalClientConnectionCache",
			"cache_key_fields":               []string{"address", "serverName", "dialer_identity", "allowInsecure", "somark", "mptcp"},
			"sample_cache_key_a":             sharedGrpcCacheKeyForFixture("addr:443", "sni.example", "dialer-1", true, 1234, true),
			"sample_cache_key_b":             sharedGrpcCacheKeyForFixture("addr:443", "sni.example", "dialer-1", true, 1234, false),
			"mptcp_changes_key":              true,
			"somark_changes_key":             true,
			"backoff_base_ms":                500,
			"backoff_multiplier":             1.5,
			"backoff_jitter":                 0.2,
			"backoff_max_seconds":            19,
			"keepalive_seconds":              30,
			"keepalive_timeout_seconds":      10,
			"min_connect_timeout_seconds":    5,
		},
		"httpupgrade_transport": map[string]any{
			"https_wraps_tls":      true,
			"https_alpn":           []string{"http/1.1"},
			"request_method":       http.MethodGet,
			"connection_header":    "upgrade",
			"upgrade_header":       "websocket",
			"success_status":       101,
			"udp":                  "unsupported",
			"bufio_todo_preserved": true,
		},
		"meek_transport": map[string]any{
			"url_required":        true,
			"url_scheme_required": "https",
			"default_alpn":        []string{"h2", "http/1.1"},
			"tcp_only":            true,
			"max_write":           65536,
			"initial_polling_ms":  100,
			"max_polling_ms":      1000,
			"min_polling_ms":      10,
			"backoff":             1.5,
			"clean_cache_hook":    "CleanGlobalRoundTripperCache",
		},
		"simpleobfs_transport": map[string]any{
			"supported":       []string{"http", "tls"},
			"type_keys":       []string{"type", "obfs"},
			"host_key":        "host",
			"path_keys":       []string{"path", "uri"},
			"tcp_wraps_conn":  true,
			"udp_passthrough": true,
			"protocol_label":  "simpleobfs(http)",
		},
		"mux_transport": map[string]any{
			"request_header_hex":      "01020304",
			"new_conn_wraps_net_conn": true,
			"data_plane_deferred":     true,
		},
		"xhttp_transport": map[string]any{
			"mode_cases": []map[string]any{
				sharedXHTTPModeCase("auto tls", "auto", "https", "tls", false),
				sharedXHTTPModeCase("auto reality", "auto", "https", "reality", false),
				sharedXHTTPModeCase("auto reality download", "auto", "https", "reality", true),
				sharedXHTTPModeCase("auto http error", "auto", "http", "tls", false),
				sharedXHTTPModeCase("packet-up http error", "packet-up", "http", "tls", false),
			},
			"alpn_cases": []map[string]any{
				sharedXHTTPAlpnCase("h2", "tls", "h2"),
				sharedXHTTPAlpnCase("h3", "tls", "h3"),
				sharedXHTTPAlpnCase("http1", "tls", "http/1.1"),
				sharedXHTTPAlpnCase("bad", "tls", "hq"),
				sharedXHTTPAlpnCase("reality-h3", "reality", "h3"),
			},
			"extra_raw":                 xhttpExtra,
			"extra_canonical":           xhttpExtraCanonical,
			"extra_empty_omitted":       true,
			"path_cases":                sharedXHTTPPathCases(),
			"packet_max_bytes_default":  1 << 20,
			"packet_min_gap_ms_default": 30,
			"placement_defaults":        map[string]string{"session": "path", "seq": "path", "uplink_data": "body"},
			"unsupported_extra_fields":  []string{"noSSEHeader", "scMaxBufferedPosts", "downloadSettings.xhttpSettings.mode", "downloadSettings.xhttpSettings.extra except xmux"},
			"true_data_plane_deferred":  true,
		},
		"live_smoke_required": []string{
			"local transport IR contract smoke",
			"local xHTTP mode/ALPN/path/extra smoke",
			"local gRPC cache key and MagicNetwork contract smoke",
		},
	}
}

func rebuildSharedAllowInsecureCases() []map[string]any {
	return []map[string]any{
		{"key": "allowInsecure", "value": "1", "parsed": sharedParseBool("1")},
		{"key": "allow_insecure", "value": "true", "parsed": sharedParseBool("true")},
		{"key": "allowinsecure", "value": "0", "parsed": sharedParseBool("0")},
		{"key": "skipVerify", "value": "false", "parsed": sharedParseBool("false")},
	}
}

func sharedParseBool(value string) bool {
	switch value {
	case "1", "t", "T", "TRUE", "true", "True":
		return true
	default:
		return false
	}
}

func sharedRealitySIDForFixture(t testing.TB, input string) []byte {
	t.Helper()
	out := make([]byte, 8)
	if _, err := hex.Decode(out, []byte(input)); err != nil {
		t.Fatalf("decode sid: %v", err)
	}
	return out
}

func sharedRealitySpiderYForFixture(spx string) []int64 {
	out := make([]int64, 10)
	u, _ := url.Parse(spx)
	q := u.Query()
	parse := func(param string, index int) {
		if q.Get(param) == "" {
			return
		}
		parts := strings.Split(q.Get(param), "-")
		if len(parts) == 1 {
			out[index] = sharedAtoi64(parts[0])
			out[index+1] = out[index]
		} else {
			out[index] = sharedAtoi64(parts[0])
			out[index+1] = sharedAtoi64(parts[1])
		}
	}
	parse("p", 0)
	parse("c", 2)
	parse("t", 4)
	parse("i", 6)
	parse("r", 8)
	return out
}

func sharedAtoi64(input string) int64 {
	var out int64
	for _, ch := range input {
		if ch >= '0' && ch <= '9' {
			out = out*10 + int64(ch-'0')
		}
	}
	return out
}

func sharedGrpcCacheKeyForFixture(address, serverName, dialerID string, allowInsecure bool, mark uint32, mptcp bool) string {
	return strings.Join([]string{
		address,
		serverName,
		dialerID,
		boolString(allowInsecure),
		netproxy.MagicNetwork{Network: "tcp", Mark: mark, Mptcp: mptcp}.Encode(),
	}, "|")
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func sharedXHTTPModeCase(name, mode, scheme, security string, hasDownload bool) map[string]any {
	got, err := sharedNormalizeXHTTPMode(mode, scheme, security, hasDownload)
	return map[string]any{
		"name":           name,
		"mode":           mode,
		"scheme":         scheme,
		"security":       security,
		"hasDownload":    hasDownload,
		"normalized":     got,
		"ok":             err == "",
		"error_contains": err,
	}
}

func sharedNormalizeXHTTPMode(mode, scheme, security string, hasDownload bool) (string, string) {
	mode = strings.TrimSpace(strings.ToLower(mode))
	switch mode {
	case "", "auto":
		if scheme != "https" {
			return "", "auto mode without tls is not supported yet"
		}
		if strings.EqualFold(security, "reality") {
			if hasDownload {
				return "stream-up", ""
			}
			return "stream-one", ""
		}
		return "packet-up", ""
	case "stream-up":
		return mode, ""
	case "stream-one":
		if scheme == "https" {
			return mode, ""
		}
		return "", "stream-one without tls is not supported yet"
	case "packet-up":
		if scheme == "https" {
			return mode, ""
		}
		return "", "packet-up without tls is not supported yet"
	default:
		return "", "unsupported mode"
	}
}

func sharedXHTTPAlpnCase(name, security, alpn string) map[string]any {
	err := sharedValidateXHTTPAlpn(security, alpn)
	return map[string]any{
		"name":           name,
		"security":       security,
		"alpn":           alpn,
		"ok":             err == "",
		"use_h3":         strings.EqualFold(security, "tls") && sharedShouldUseH3(alpn),
		"error_contains": err,
	}
}

func sharedValidateXHTTPAlpn(security, alpn string) string {
	if !strings.EqualFold(security, "tls") && !strings.EqualFold(security, "reality") {
		return ""
	}
	if sharedShouldUseH3(alpn) || sharedShouldUseHTTP1(alpn) || sharedSupportsH2(alpn) {
		if strings.EqualFold(security, "reality") && sharedShouldUseH3(alpn) {
			return "reality with h3 is not supported"
		}
		return ""
	}
	return "alpn"
}

func sharedShouldUseH3(alpn string) bool {
	parts := strings.Split(alpn, ",")
	return len(parts) == 1 && strings.EqualFold(strings.TrimSpace(parts[0]), "h3")
}

func sharedShouldUseHTTP1(alpn string) bool {
	parts := strings.Split(alpn, ",")
	return len(parts) == 1 && strings.EqualFold(strings.TrimSpace(parts[0]), "http/1.1")
}

func sharedSupportsH2(alpn string) bool {
	if strings.TrimSpace(alpn) == "" {
		return true
	}
	for _, part := range strings.Split(alpn, ",") {
		if strings.EqualFold(strings.TrimSpace(part), "h2") {
			return true
		}
	}
	return false
}

func sharedXHTTPPathCases() []map[string]any {
	inputs := []string{"xhttp", "/xhttp", "/xhttp/", "/xhttp?ed=2048", "xhttp?ed=2048&foo=bar"}
	out := make([]map[string]any, 0, len(inputs))
	for _, input := range inputs {
		path, query := sharedNormalizeXHTTPPathAndQuery(input)
		out = append(out, map[string]any{"input": input, "path": path, "query": query})
	}
	return out
}

func sharedNormalizeXHTTPPathAndQuery(path string) (string, string) {
	parts := strings.SplitN(path, "?", 2)
	path = parts[0]
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	if len(parts) == 2 {
		return path, parts[1]
	}
	return path, ""
}

func canonicalJSONForSharedTransportFixture(t testing.TB, raw string) string {
	t.Helper()
	var value any
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	out, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return string(out)
}

func BenchmarkSharedTransportNativeOptInXHTTPMode(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = sharedNormalizeXHTTPMode("auto", "https", "reality", true)
	}
}

func BenchmarkSharedTransportNativeOptInGrpcCacheKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = sharedGrpcCacheKeyForFixture("addr:443", "sni.example", "dialer-1", true, 1234, true)
	}
}

func BenchmarkSharedTransportNativeOptInXHTTPPath(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = sharedNormalizeXHTTPPathAndQuery("xhttp?ed=2048&foo=bar")
	}
}

func BenchmarkSharedTransportNativeOptInCanonicalJSON(b *testing.B) {
	raw := `{"downloadSettings":{"address":"download.example","port":443,"network":"xhttp","security":"reality","xhttpSettings":{"host":"download.example","path":"/download","extra":"{\"xmux\":{\"maxConnections\":\"3\",\"cMaxReuseTimes\":\"9\"}}"}},"xmux":{"maxConnections":"1"},"xPaddingBytes":"100-200"}`
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = canonicalJSONForSharedTransportFixture(b, raw)
	}
}

func BenchmarkSharedTransportNativeOptInTimerConstants(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = 500*time.Millisecond + 19*time.Second + 30*time.Second + 10*time.Second + 5*time.Second
	}
}

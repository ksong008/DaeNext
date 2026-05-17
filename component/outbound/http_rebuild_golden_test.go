/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
	"testing"

	outboundhttpdialer "github.com/daeuniverse/outbound/dialer/http"
)

func TestWriteHTTPNativeOptInGoldenFixture(t *testing.T) {
	writeOrCheckOutboundGolden(t,
		"../../testdata/rebuild-golden/outbound/protocol/http_native_optin.json",
		rebuildGoldenStage15HTTPNativeOptIn(t),
	)
}

func rebuildGoldenStage15HTTPNativeOptIn(t testing.TB) any {
	t.Helper()

	return map[string]any{
		"name": "stage15-http-native-optin",
		"source": []string{
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.1",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.2",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.3",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.14",
			"/root/project/outbound/dialer/http/http.go",
			"/root/project/outbound/protocol/http/http.go",
			"/root/project/outbound/protocol/http/conn.go",
		},
		"default_go_path":   true,
		"rust_adapter_mode": "native-opt-in",
		"protocol_scope": []string{
			"http",
			"https",
		},
		"link_parser": []map[string]any{
			rebuildHTTPLinkCase(t, "http-default-port", "http://user:pass@proxy.example#node"),
			rebuildHTTPLinkCase(t, "https-flags", "https://proxy.example?sni=server.example&allow_insecure=true#node"),
			rebuildHTTPLinkCase(t, "https-skip-verify-alias", "https://proxy.example:443?skipVerify=1#alias"),
		},
		"connect": []map[string]any{
			rebuildHTTPConnectCase(t, "connect-no-auth", "example.com:443", "", "", "", false, "/"),
			rebuildHTTPConnectCase(t, "connect-basic-auth-host-override", "example.com:443", "user", "pass", "front.example", false, "/"),
			rebuildHTTPConnectCase(t, "transport-put-path", "example.com:443", "user", "pass", "", true, "/proxy-path"),
		},
		"http_request_passthrough": map[string]any{
			"target":                   "example.com:80",
			"input_hex":                hex.EncodeToString([]byte("GET /index.html HTTP/1.1\r\nHost: origin.example\r\nProxy-Connection: keep-alive\r\n\r\n")),
			"request_hex":              hex.EncodeToString(buildHTTPForwardRequest(t, "example.com:80", "GET /index.html HTTP/1.1\r\nHost: origin.example\r\nProxy-Connection: keep-alive\r\n\r\n")),
			"proxy_connection_removed": true,
		},
		"https_flags": map[string]any{
			"scheme":       "https",
			"default_port": 443,
			"default_sni":  "proxy.example",
			"explicit_sni": "server.example",
			"allow_insecure_aliases": []string{
				"allowInsecure",
				"allow_insecure",
				"allowinsecure",
				"skipVerify",
			},
			"tls_implementation_default": "tls",
			"alpn_default_query_value":   "h2,http/1.1",
			"utls_imitate_passthrough":   "chrome",
			"h2_route_context_required":  true,
		},
		"unsupported": map[string]any{
			"udp": "unsupported tunnel type",
		},
		"live_smoke_required": []string{
			"local fake HTTP proxy CONNECT",
			"local fake HTTP proxy CONNECT with Basic auth",
			"local fake HTTP transport PUT request",
		},
	}
}

func rebuildHTTPLinkCase(t testing.TB, name string, raw string) map[string]any {
	t.Helper()

	cfg, err := outboundhttpdialer.ParseHTTPURL(raw)
	if err != nil {
		t.Fatalf("ParseHTTPURL(%q): %v", raw, err)
	}
	return map[string]any{
		"name":          name,
		"input":         raw,
		"server":        cfg.Server,
		"port":          cfg.Port,
		"username":      cfg.Username,
		"password":      cfg.Password,
		"sni":           cfg.SNI,
		"protocol":      cfg.Protocol,
		"allowInsecure": cfg.AllowInsecure,
		"export":        cfg.ExportToURL(),
	}
}

func rebuildHTTPConnectCase(t testing.TB, name string, target string, username string, password string, host string, transport bool, path string) map[string]any {
	t.Helper()

	reqBytes := buildHTTPConnectRequest(t, target, username, password, host, transport, path)
	return map[string]any{
		"name":              name,
		"target":            target,
		"username":          username,
		"password":          password,
		"host_override":     host,
		"transport":         transport,
		"path":              path,
		"request_hex":       hex.EncodeToString(reqBytes),
		"basic_auth_header": basicAuthHeader(username, password),
	}
}

func buildHTTPConnectRequest(t testing.TB, target string, username string, password string, host string, transport bool, path string) []byte {
	t.Helper()

	reqURL, err := url.Parse("http://" + target)
	if err != nil {
		t.Fatalf("Parse target %q: %v", target, err)
	}
	method := http.MethodConnect
	if !transport {
		reqURL.Scheme = ""
	} else {
		method = http.MethodPut
		if path == "" {
			path = "/"
		}
		reqURL.Path = path
	}
	req, err := http.NewRequest(method, reqURL.String(), nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if host != "" {
		req.Host = host
	} else if transport {
		req.Host = "www.example.com"
	}
	req.Close = false
	if username != "" {
		req.Header.Set("Proxy-Authorization", basicAuthHeader(username, password))
	}
	var buf bytes.Buffer
	if err := req.WriteProxy(&buf); err != nil {
		t.Fatalf("WriteProxy: %v", err)
	}
	return buf.Bytes()
}

func buildHTTPForwardRequest(t testing.TB, target string, raw string) []byte {
	t.Helper()

	req, err := http.ReadRequest(bufioReader(raw))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	req.URL.Scheme = "http"
	req.URL.Host = target
	req.Close = false
	req.Header.Del("Proxy-Connection")
	var buf bytes.Buffer
	if err := req.WriteProxy(&buf); err != nil {
		t.Fatalf("WriteProxy: %v", err)
	}
	return buf.Bytes()
}

func bufioReader(raw string) *bufio.Reader {
	return bufio.NewReader(bytes.NewReader([]byte(raw)))
}

func basicAuthHeader(username string, password string) string {
	if username == "" {
		return ""
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}

func BenchmarkHTTPNativeOptInParseLink(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := outboundhttpdialer.ParseHTTPURL("https://user:pass@proxy.example:443?sni=server.example&allowInsecure=1#node"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHTTPNativeOptInConnectRequest(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = buildHTTPConnectRequest(b, "example.com:443", "user", "pass", "front.example", false, "/")
	}
}

func BenchmarkHTTPNativeOptInForwardRequest(b *testing.B) {
	raw := "GET /index.html HTTP/1.1\r\nHost: origin.example\r\nProxy-Connection: keep-alive\r\n\r\n"
	for i := 0; i < b.N; i++ {
		_ = buildHTTPForwardRequest(b, "example.com:80", raw)
	}
}

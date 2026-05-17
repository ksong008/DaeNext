/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRustUserspaceOptInDisabled(t *testing.T) {
	usedCases := []struct {
		name string
		run  func() (string, bool, error)
	}{
		{"route", func() (string, bool, error) {
			return RustUserspaceOptInRouteMatch("www.example.com", "203.0.113.42", "443")
		}},
		{"dns", func() (string, bool, error) {
			return RustUserspaceOptInDNSCacheKey("Example.COM", "1", "1")
		}},
		{"outbound", func() (string, bool, error) {
			return RustUserspaceOptInOutboundSelect("min", "tcp4")
		}},
		{"sniff", func() (string, bool, error) {
			return RustUserspaceOptInSniffTCP("http")
		}},
		{"magic", func() (string, bool, error) {
			return RustUserspaceOptInMagicNetwork("tcp", "1234", "true")
		}},
	}
	for _, tc := range usedCases {
		t.Run(tc.name, func(t *testing.T) {
			out, used, err := tc.run()
			if err != nil {
				t.Fatalf("%s error = %v", tc.name, err)
			}
			if used {
				t.Fatalf("%s used helper while opt-in disabled: %q", tc.name, out)
			}
			if out != "" {
				t.Fatalf("%s returned output while opt-in disabled: %q", tc.name, out)
			}
		})
	}
}

func TestRustUserspaceOptInHelperSuccess(t *testing.T) {
	helper := writeRustUserspaceHelper(t, false)
	t.Setenv(rustUserspaceOptInEnv, "1")
	t.Setenv(rustUserspaceHelperEnv, helper)

	route, used, err := RustUserspaceOptInRouteMatch("www.example.com", "203.0.113.42", "443")
	if err != nil {
		t.Fatalf("RustUserspaceOptInRouteMatch() error = %v", err)
	}
	if !used || !strings.Contains(route, `"outbound":"direct"`) {
		t.Fatalf("unexpected route output: used=%v out=%q", used, route)
	}

	dns, used, err := RustUserspaceOptInDNSCacheKey("Example.COM", "1", "1")
	if err != nil {
		t.Fatalf("RustUserspaceOptInDNSCacheKey() error = %v", err)
	}
	if !used || !strings.Contains(dns, `"key":"example.com.|1|1"`) {
		t.Fatalf("unexpected dns output: used=%v out=%q", used, dns)
	}

	outbound, used, err := RustUserspaceOptInOutboundSelect("min", "tcp4")
	if err != nil {
		t.Fatalf("RustUserspaceOptInOutboundSelect() error = %v", err)
	}
	if !used || !strings.Contains(outbound, `"selected_index":1`) {
		t.Fatalf("unexpected outbound output: used=%v out=%q", used, outbound)
	}

	sniff, used, err := RustUserspaceOptInSniffTCP("http")
	if err != nil {
		t.Fatalf("RustUserspaceOptInSniffTCP() error = %v", err)
	}
	if !used || !strings.Contains(sniff, `"domain":"example.com"`) {
		t.Fatalf("unexpected sniff output: used=%v out=%q", used, sniff)
	}

	magic, used, err := RustUserspaceOptInMagicNetwork("tcp", "1234", "true")
	if err != nil {
		t.Fatalf("RustUserspaceOptInMagicNetwork() error = %v", err)
	}
	if !used || !strings.Contains(magic, `"parsed_mark":1234`) || !strings.Contains(magic, `"parsed_mptcp":true`) {
		t.Fatalf("unexpected magic output: used=%v out=%q", used, magic)
	}
}

func TestRustUserspaceOptInHelperFailure(t *testing.T) {
	helper := writeRustUserspaceHelper(t, true)
	t.Setenv(rustUserspaceOptInEnv, "1")
	t.Setenv(rustUserspaceHelperEnv, helper)

	_, used, err := RustUserspaceOptInRouteMatch("www.example.com", "203.0.113.42", "443")
	if !used {
		t.Fatal("expected helper to be used")
	}
	if err == nil || !strings.Contains(err.Error(), "rust userspace helper failed: helper failed") {
		t.Fatalf("RustUserspaceOptInRouteMatch() error = %v", err)
	}
}

func BenchmarkRustUserspaceOptInRouteMatchHelper(b *testing.B) {
	helper := strings.TrimSpace(os.Getenv(rustUserspaceHelperEnv))
	if helper == "" {
		b.Skipf("%s is not set", rustUserspaceHelperEnv)
	}
	b.Setenv(rustUserspaceOptInEnv, "1")
	b.Setenv(rustUserspaceHelperEnv, helper)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		out, used, err := RustUserspaceOptInRouteMatch("www.example.com", "203.0.113.42", "443")
		if err != nil {
			b.Fatal(err)
		}
		if !used || !strings.Contains(out, `"outbound":"direct"`) {
			b.Fatalf("unexpected helper output: used=%v out=%q", used, out)
		}
	}
}

func BenchmarkRustUserspaceOptInDNSCacheKeyHelper(b *testing.B) {
	helper := strings.TrimSpace(os.Getenv(rustUserspaceHelperEnv))
	if helper == "" {
		b.Skipf("%s is not set", rustUserspaceHelperEnv)
	}
	b.Setenv(rustUserspaceOptInEnv, "1")
	b.Setenv(rustUserspaceHelperEnv, helper)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		out, used, err := RustUserspaceOptInDNSCacheKey("Example.COM", "1", "1")
		if err != nil {
			b.Fatal(err)
		}
		if !used || !strings.Contains(out, `"key":"example.com.|1|1"`) {
			b.Fatalf("unexpected helper output: used=%v out=%q", used, out)
		}
	}
}

func BenchmarkRustUserspaceOptInOutboundSelectHelper(b *testing.B) {
	helper := strings.TrimSpace(os.Getenv(rustUserspaceHelperEnv))
	if helper == "" {
		b.Skipf("%s is not set", rustUserspaceHelperEnv)
	}
	b.Setenv(rustUserspaceOptInEnv, "1")
	b.Setenv(rustUserspaceHelperEnv, helper)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		out, used, err := RustUserspaceOptInOutboundSelect("min", "tcp4")
		if err != nil {
			b.Fatal(err)
		}
		if !used || !strings.Contains(out, `"selected_index":1`) {
			b.Fatalf("unexpected helper output: used=%v out=%q", used, out)
		}
	}
}

func writeRustUserspaceHelper(t *testing.T, fail bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dae-cli-optin")
	failBlock := ""
	if fail {
		failBlock = "echo helper failed\nexit 7\n"
	}
	script := "#!/bin/sh\nset -eu\n" + failBlock + `
if [ "$1" = "userspace" ] && [ "$2" = "route-match" ]; then
  printf '{"domain":"www.example.com","dest":"203.0.113.42","dest_port":443,"outbound":"direct"}\n'
  exit 0
fi
if [ "$1" = "userspace" ] && [ "$2" = "dns-cache-key" ]; then
  printf '{"qname":"example.com.","qtype":1,"qclass":1,"key":"example.com.|1|1"}\n'
  exit 0
fi
if [ "$1" = "userspace" ] && [ "$2" = "outbound-select" ]; then
  printf '{"policy":"min","network":"tcp4","selected_index":1,"latency_ms":100}\n'
  exit 0
fi
if [ "$1" = "userspace" ] && [ "$2" = "sniff-tcp" ]; then
  printf '{"kind":"http","domain":"example.com"}\n'
  exit 0
fi
if [ "$1" = "userspace" ] && [ "$2" = "magic-network" ]; then
  printf '{"network":"tcp","mark":1234,"mptcp":true,"parsed_network":"tcp","parsed_mark":1234,"parsed_mptcp":true}\n'
  exit 0
fi
echo unsupported command
exit 2
`
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatalf("write helper: %v", err)
	}
	return path
}

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

func TestRustAPIOnlyOptInDisabled(t *testing.T) {
	used, err := RustAPIOnlyOptInDryRunSmoke()
	if err != nil {
		t.Fatalf("RustAPIOnlyOptInDryRunSmoke() error = %v", err)
	}
	if used {
		t.Fatal("RustAPIOnlyOptInDryRunSmoke() used helper while opt-in disabled")
	}
}

func TestRustAPIOnlyOptInHelperSuccess(t *testing.T) {
	helper := writeRustAPIOnlyHelper(t, false)
	t.Setenv(rustAPIOnlyOptInEnv, "1")
	t.Setenv(rustAPIOnlyHelperEnv, helper)

	used, err := RustAPIOnlyOptInDryRunSmoke()
	if err != nil {
		t.Fatalf("RustAPIOnlyOptInDryRunSmoke() error = %v", err)
	}
	if !used {
		t.Fatal("expected dry runtime smoke helper to be used")
	}

	route, used, err := RustAPIOnlyOptInRouteTarget("example.com", "443")
	if err != nil {
		t.Fatalf("RustAPIOnlyOptInRouteTarget() error = %v", err)
	}
	if !used {
		t.Fatal("expected route target helper to be used")
	}
	if !strings.Contains(route, `"domain":"example.com"`) || !strings.Contains(route, `"dest":"0.0.0.0:443"`) {
		t.Fatalf("unexpected route target output: %q", route)
	}

	overview, used, err := RustAPIOnlyOptInOverviewBasic()
	if err != nil {
		t.Fatalf("RustAPIOnlyOptInOverviewBasic() error = %v", err)
	}
	if !used {
		t.Fatal("expected overview helper to be used")
	}
	if !strings.Contains(overview, `"dns_cache_hit_total":101`) {
		t.Fatalf("unexpected overview output: %q", overview)
	}
}

func TestRustAPIOnlyOptInHelperFailure(t *testing.T) {
	helper := writeRustAPIOnlyHelper(t, true)
	t.Setenv(rustAPIOnlyOptInEnv, "1")
	t.Setenv(rustAPIOnlyHelperEnv, helper)

	used, err := RustAPIOnlyOptInDryRunSmoke()
	if !used {
		t.Fatal("expected helper to be used")
	}
	if err == nil || !strings.Contains(err.Error(), "rust api-only helper failed: helper failed") {
		t.Fatalf("RustAPIOnlyOptInDryRunSmoke() error = %v", err)
	}
}

func BenchmarkRustAPIOnlyOptInRouteTargetHelper(b *testing.B) {
	helper := strings.TrimSpace(os.Getenv(rustAPIOnlyHelperEnv))
	if helper == "" {
		b.Skipf("%s is not set", rustAPIOnlyHelperEnv)
	}
	b.Setenv(rustAPIOnlyOptInEnv, "1")
	b.Setenv(rustAPIOnlyHelperEnv, helper)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		out, used, err := RustAPIOnlyOptInRouteTarget("example.com", "443")
		if err != nil {
			b.Fatal(err)
		}
		if !used || !strings.Contains(out, `"dest":"0.0.0.0:443"`) {
			b.Fatalf("unexpected helper output: used=%v out=%q", used, out)
		}
	}
}

func BenchmarkRustAPIOnlyOptInOverviewBasicHelper(b *testing.B) {
	helper := strings.TrimSpace(os.Getenv(rustAPIOnlyHelperEnv))
	if helper == "" {
		b.Skipf("%s is not set", rustAPIOnlyHelperEnv)
	}
	b.Setenv(rustAPIOnlyOptInEnv, "1")
	b.Setenv(rustAPIOnlyHelperEnv, helper)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		out, used, err := RustAPIOnlyOptInOverviewBasic()
		if err != nil {
			b.Fatal(err)
		}
		if !used || !strings.Contains(out, `"dns_cache_hit_total":101`) {
			b.Fatalf("unexpected helper output: used=%v out=%q", used, out)
		}
	}
}

func writeRustAPIOnlyHelper(t *testing.T, fail bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dae-cli-optin")
	failBlock := ""
	if fail {
		failBlock = "echo helper failed\nexit 7\n"
	}
	script := "#!/bin/sh\nset -eu\n" + failBlock + `
if [ "$1" = "runtime" ] && [ "$2" = "dry-run-smoke" ]; then
  exit 0
fi
if [ "$1" = "runtime" ] && [ "$2" = "route-target" ]; then
  printf '{"domain":"example.com","dest":"0.0.0.0:443","dest_is_unspecified":true}\n'
  exit 0
fi
if [ "$1" = "runtime" ] && [ "$2" = "overview-basic" ]; then
  printf '{"dns_cache_hit_total":101}\n'
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

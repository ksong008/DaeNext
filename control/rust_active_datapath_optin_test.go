/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/config"
)

func TestRustActiveDatapathOptInDisabled(t *testing.T) {
	if err := rustActiveDatapathOptInPreflight(&config.Global{TproxyPort: 12345}); err != nil {
		t.Fatalf("rustActiveDatapathOptInPreflight() error = %v", err)
	}
	out, used, err := RustActiveDatapathOptInContract()
	if err != nil {
		t.Fatalf("RustActiveDatapathOptInContract() error = %v", err)
	}
	if used || out != "" {
		t.Fatalf("contract used helper while disabled: used=%v out=%q", used, out)
	}
}

func TestRustActiveDatapathOptInHelperSuccess(t *testing.T) {
	helper := writeRustActiveDatapathHelper(t, false)
	t.Setenv(rustActiveDatapathOptInEnv, "1")
	t.Setenv(rustActiveDatapathHelperEnv, helper)

	err := rustActiveDatapathOptInPreflight(&config.Global{
		TproxyPort:    12345,
		SoMarkFromDae: 1234,
		Mptcp:         true,
		LanInterface:  []string{"eth0"},
	})
	if err != nil {
		t.Fatalf("rustActiveDatapathOptInPreflight() error = %v", err)
	}

	contract, used, err := RustActiveDatapathOptInContract()
	if err != nil {
		t.Fatalf("RustActiveDatapathOptInContract() error = %v", err)
	}
	if !used || !strings.Contains(contract, `"reload_rollback_injects_old_bpf":true`) {
		t.Fatalf("unexpected contract output: used=%v out=%q", used, contract)
	}

	magic, used, err := RustActiveDatapathOptInMagicDial("tcp", "1234", "true")
	if err != nil {
		t.Fatalf("RustActiveDatapathOptInMagicDial() error = %v", err)
	}
	if !used || !strings.Contains(magic, `"parsed_mark":1234`) || !strings.Contains(magic, `"parsed_mptcp":true`) {
		t.Fatalf("unexpected magic output: used=%v out=%q", used, magic)
	}
}

func TestRustActiveDatapathOptInHelperFailure(t *testing.T) {
	helper := writeRustActiveDatapathHelper(t, true)
	t.Setenv(rustActiveDatapathOptInEnv, "1")
	t.Setenv(rustActiveDatapathHelperEnv, helper)

	err := rustActiveDatapathOptInPreflight(&config.Global{TproxyPort: 12345})
	if err == nil || !strings.Contains(err.Error(), "rust active datapath helper failed: helper failed") {
		t.Fatalf("rustActiveDatapathOptInPreflight() error = %v", err)
	}
}

func BenchmarkRustActiveDatapathOptInPreflightHelper(b *testing.B) {
	helper := strings.TrimSpace(os.Getenv(rustActiveDatapathHelperEnv))
	if helper == "" {
		b.Skipf("%s is not set", rustActiveDatapathHelperEnv)
	}
	b.Setenv(rustActiveDatapathOptInEnv, "1")
	b.Setenv(rustActiveDatapathHelperEnv, helper)
	global := &config.Global{TproxyPort: 12345, SoMarkFromDae: 1234, Mptcp: true}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := rustActiveDatapathOptInPreflight(global); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRustActiveDatapathOptInMagicDialHelper(b *testing.B) {
	helper := strings.TrimSpace(os.Getenv(rustActiveDatapathHelperEnv))
	if helper == "" {
		b.Skipf("%s is not set", rustActiveDatapathHelperEnv)
	}
	b.Setenv(rustActiveDatapathOptInEnv, "1")
	b.Setenv(rustActiveDatapathHelperEnv, helper)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		out, used, err := RustActiveDatapathOptInMagicDial("tcp", "1234", "true")
		if err != nil {
			b.Fatal(err)
		}
		if !used || !strings.Contains(out, `"parsed_mark":1234`) {
			b.Fatalf("unexpected helper output: used=%v out=%q", used, out)
		}
	}
}

func writeRustActiveDatapathHelper(t *testing.T, fail bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dae-cli-optin")
	failBlock := ""
	if fail {
		failBlock = "echo helper failed\nexit 7\n"
	}
	script := "#!/bin/sh\nset -eu\n" + failBlock + `
if [ "$1" = "active-datapath" ] && [ "$2" = "preflight" ]; then
  printf '{"allowed":true,"gates":{"root":true,"bpffs":true,"netns_permission":true,"memlock":true,"kernel_feature_version":true}}\n'
  exit 0
fi
if [ "$1" = "active-datapath" ] && [ "$2" = "contract" ]; then
  printf '{"reload_rollback_injects_old_bpf":true,"default_go_attach_path":true}\n'
  exit 0
fi
if [ "$1" = "active-datapath" ] && [ "$2" = "magic-dial" ]; then
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

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

func TestRustConfigOptInHelperSuccess(t *testing.T) {
	helper := writeRustConfigHelper(t, false)
	t.Setenv(rustConfigOptInEnv, "1")
	t.Setenv(rustConfigHelperEnv, helper)

	configPath := writeOptInConfig(t, "global {}\nrouting {}\n")
	if _, _, err := ReadConfigFile(configPath); err != nil {
		t.Fatalf("ReadConfigFile() with rust opt-in error = %v", err)
	}

	globalSection := "global { log_level: debug }"
	routingSection := "routing { fallback: must_direct }"
	if _, err := ParseConfig(&globalSection, nil, &routingSection); err != nil {
		t.Fatalf("ParseConfig() with rust opt-in error = %v", err)
	}

	out, used, err := RustConfigOptInExportOutline("test-version")
	if err != nil {
		t.Fatalf("RustConfigOptInExportOutline() error = %v", err)
	}
	if !used {
		t.Fatal("expected rust opt-in export to be used")
	}
	if !strings.Contains(out, `"version":"test-version"`) {
		t.Fatalf("unexpected helper export output: %q", out)
	}
}

func TestRustConfigOptInHelperFailure(t *testing.T) {
	helper := writeRustConfigHelper(t, true)
	t.Setenv(rustConfigOptInEnv, "1")
	t.Setenv(rustConfigHelperEnv, helper)

	configPath := writeOptInConfig(t, "global {}\nrouting {}\n")
	_, _, err := ReadConfigFile(configPath)
	if err == nil || !strings.Contains(err.Error(), "rust config helper failed: helper failed") {
		t.Fatalf("ReadConfigFile() error = %v", err)
	}
}

func writeRustConfigHelper(t *testing.T, fail bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dae-cli-optin")
	failBlock := ""
	if fail {
		failBlock = "echo helper failed\nexit 7\n"
	}
	script := "#!/bin/sh\nset -eu\n" + failBlock + `
if [ "$1" = "export" ]; then
  printf '{"version":"%s"}\n' "${DAE_CLI_VERSION:-unknown}"
  exit 0
fi
exit 0
`
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatalf("write helper: %v", err)
	}
	return path
}

func writeOptInConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.dae")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

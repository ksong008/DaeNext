/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package engine

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	rustConfigOptInEnv      = "DAE_RUST_CONFIG_OPTIN"
	rustConfigHelperEnv     = "DAE_RUST_CONFIG_HELPER"
	rustCliVersionEnv       = "DAE_CLI_VERSION"
	rustConfigHelperDefault = "dae-cli-optin"
	rustConfigHelperTimeout = 10 * time.Second
)

func rustConfigOptInEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(rustConfigOptInEnv))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func rustConfigHelperPath() string {
	if helper := strings.TrimSpace(os.Getenv(rustConfigHelperEnv)); helper != "" {
		return helper
	}
	return rustConfigHelperDefault
}

func rustConfigCheckReadFile(cfgFile string) error {
	if !rustConfigOptInEnabled() {
		return nil
	}
	return runRustConfigHelper(nil, "validate", "-c", cfgFile)
}

func rustConfigCheckParseConfig(globalSection string, dnsSection string, routingSection string) error {
	if !rustConfigOptInEnabled() {
		return nil
	}
	return runRustConfigHelper(nil,
		"config", "parse-api",
		"--global", globalSection,
		"--dns", dnsSection,
		"--routing", routingSection,
	)
}

func RustConfigOptInExportOutline(version string) (text string, used bool, err error) {
	if !rustConfigOptInEnabled() {
		return "", false, nil
	}
	env := []string{rustCliVersionEnv + "=" + version}
	out, err := runRustConfigHelperOutput(env, "export", "outline")
	return out, true, err
}

func runRustConfigHelper(extraEnv []string, args ...string) error {
	_, err := runRustConfigHelperOutput(extraEnv, args...)
	return err
}

func runRustConfigHelperOutput(extraEnv []string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rustConfigHelperTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, rustConfigHelperPath(), args...)
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("rust config helper timed out after %s", rustConfigHelperTimeout)
	}
	if err != nil {
		message := strings.TrimSpace(string(out))
		if message == "" {
			message = err.Error()
		}
		return "", fmt.Errorf("rust config helper failed: %s", message)
	}
	return string(out), nil
}

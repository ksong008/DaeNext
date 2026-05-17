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
	rustAPIOnlyOptInEnv      = "DAE_RUST_API_ONLY_OPTIN"
	rustAPIOnlyHelperEnv     = "DAE_RUST_API_ONLY_HELPER"
	rustAPIOnlyHelperDefault = "dae-cli-optin"
	rustAPIOnlyHelperTimeout = 10 * time.Second
)

func rustAPIOnlyOptInEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(rustAPIOnlyOptInEnv))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func rustAPIOnlyHelperPath() string {
	if helper := strings.TrimSpace(os.Getenv(rustAPIOnlyHelperEnv)); helper != "" {
		return helper
	}
	return rustAPIOnlyHelperDefault
}

func RustAPIOnlyOptInDryRunSmoke() (used bool, err error) {
	if !rustAPIOnlyOptInEnabled() {
		return false, nil
	}
	_, err = runRustAPIOnlyHelperOutput("runtime", "dry-run-smoke")
	return true, err
}

func RustAPIOnlyOptInRouteTarget(host string, port string) (text string, used bool, err error) {
	if !rustAPIOnlyOptInEnabled() {
		return "", false, nil
	}
	out, err := runRustAPIOnlyHelperOutput("runtime", "route-target", "--host", host, "--port", port)
	return out, true, err
}

func RustAPIOnlyOptInOverviewBasic() (text string, used bool, err error) {
	if !rustAPIOnlyOptInEnabled() {
		return "", false, nil
	}
	out, err := runRustAPIOnlyHelperOutput("runtime", "overview-basic")
	return out, true, err
}

func runRustAPIOnlyHelperOutput(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rustAPIOnlyHelperTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, rustAPIOnlyHelperPath(), args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("rust api-only helper timed out after %s", rustAPIOnlyHelperTimeout)
	}
	if err != nil {
		message := strings.TrimSpace(string(out))
		if message == "" {
			message = err.Error()
		}
		return "", fmt.Errorf("rust api-only helper failed: %s", message)
	}
	return string(out), nil
}

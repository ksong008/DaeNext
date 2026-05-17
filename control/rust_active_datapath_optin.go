/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/config"
)

const (
	rustActiveDatapathOptInEnv      = "DAE_RUST_ACTIVE_DATAPATH_OPTIN"
	rustActiveDatapathHelperEnv     = "DAE_RUST_ACTIVE_DATAPATH_HELPER"
	rustActiveDatapathHelperDefault = "dae-cli-optin"
	rustActiveDatapathHelperTimeout = 10 * time.Second
)

func rustActiveDatapathOptInEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(rustActiveDatapathOptInEnv))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func rustActiveDatapathHelperPath() string {
	if helper := strings.TrimSpace(os.Getenv(rustActiveDatapathHelperEnv)); helper != "" {
		return helper
	}
	return rustActiveDatapathHelperDefault
}

func rustActiveDatapathOptInPreflight(global *config.Global) error {
	if !rustActiveDatapathOptInEnabled() {
		return nil
	}
	if global == nil {
		global = &config.Global{}
	}
	_, err := runRustActiveDatapathHelperOutput(
		"active-datapath", "preflight",
		"--tproxy-port", strconv.Itoa(int(global.TproxyPort)),
		"--so-mark", strconv.FormatUint(uint64(global.SoMarkFromDae), 10),
		"--mptcp", strconv.FormatBool(global.Mptcp),
		"--lan-count", strconv.Itoa(len(global.LanInterface)),
		"--wan-count", strconv.Itoa(len(global.WanInterface)),
	)
	return err
}

func RustActiveDatapathOptInContract() (text string, used bool, err error) {
	if !rustActiveDatapathOptInEnabled() {
		return "", false, nil
	}
	out, err := runRustActiveDatapathHelperOutput("active-datapath", "contract")
	return out, true, err
}

func RustActiveDatapathOptInMagicDial(network string, mark string, mptcp string) (text string, used bool, err error) {
	if !rustActiveDatapathOptInEnabled() {
		return "", false, nil
	}
	out, err := runRustActiveDatapathHelperOutput("active-datapath", "magic-dial", "--network", network, "--mark", mark, "--mptcp", mptcp)
	return out, true, err
}

func runRustActiveDatapathHelperOutput(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rustActiveDatapathHelperTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, rustActiveDatapathHelperPath(), args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("rust active datapath helper timed out after %s", rustActiveDatapathHelperTimeout)
	}
	if err != nil {
		message := strings.TrimSpace(string(out))
		if message == "" {
			message = err.Error()
		}
		return "", fmt.Errorf("rust active datapath helper failed: %s", message)
	}
	return string(out), nil
}

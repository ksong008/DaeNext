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
	rustUserspaceOptInEnv      = "DAE_RUST_USERSPACE_OPTIN"
	rustUserspaceHelperEnv     = "DAE_RUST_USERSPACE_HELPER"
	rustUserspaceHelperDefault = "dae-cli-optin"
	rustUserspaceHelperTimeout = 10 * time.Second
)

func rustUserspaceOptInEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(rustUserspaceOptInEnv))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func rustUserspaceHelperPath() string {
	if helper := strings.TrimSpace(os.Getenv(rustUserspaceHelperEnv)); helper != "" {
		return helper
	}
	return rustUserspaceHelperDefault
}

func RustUserspaceOptInRouteMatch(domain string, dest string, port string) (text string, used bool, err error) {
	if !rustUserspaceOptInEnabled() {
		return "", false, nil
	}
	out, err := runRustUserspaceHelperOutput("userspace", "route-match", "--domain", domain, "--dest", dest, "--port", port)
	return out, true, err
}

func RustUserspaceOptInDNSCacheKey(qname string, qtype string, qclass string) (text string, used bool, err error) {
	if !rustUserspaceOptInEnabled() {
		return "", false, nil
	}
	out, err := runRustUserspaceHelperOutput("userspace", "dns-cache-key", "--qname", qname, "--qtype", qtype, "--qclass", qclass)
	return out, true, err
}

func RustUserspaceOptInOutboundSelect(policy string, network string) (text string, used bool, err error) {
	if !rustUserspaceOptInEnabled() {
		return "", false, nil
	}
	out, err := runRustUserspaceHelperOutput("userspace", "outbound-select", "--policy", policy, "--network", network)
	return out, true, err
}

func RustUserspaceOptInSniffTCP(kind string) (text string, used bool, err error) {
	if !rustUserspaceOptInEnabled() {
		return "", false, nil
	}
	out, err := runRustUserspaceHelperOutput("userspace", "sniff-tcp", "--kind", kind)
	return out, true, err
}

func RustUserspaceOptInMagicNetwork(network string, mark string, mptcp string) (text string, used bool, err error) {
	if !rustUserspaceOptInEnabled() {
		return "", false, nil
	}
	out, err := runRustUserspaceHelperOutput("userspace", "magic-network", "--network", network, "--mark", mark, "--mptcp", mptcp)
	return out, true, err
}

func runRustUserspaceHelperOutput(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rustUserspaceHelperTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, rustUserspaceHelperPath(), args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("rust userspace helper timed out after %s", rustUserspaceHelperTimeout)
	}
	if err != nil {
		message := strings.TrimSpace(string(out))
		if message == "" {
			message = err.Error()
		}
		return "", fmt.Errorf("rust userspace helper failed: %s", message)
	}
	return string(out), nil
}

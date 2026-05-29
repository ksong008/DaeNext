/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/vishvananda/netlink"
)

var activeRustTcLinks sync.Map

type trackedRustTcAttach struct {
	linkRoot string
	tcDel    func() error
	backend  tcAttachBackend
	once     sync.Once
	err      error
}

func (l *trackedRustTcAttach) Close() error {
	l.once.Do(func() {
		var errs []error
		if l.linkRoot != "" {
			if err := os.RemoveAll(l.linkRoot); err != nil {
				errs = append(errs, fmt.Errorf("remove Rust/Aya tc link root %s: %w", l.linkRoot, err))
			}
		}
		if l.backend == tcAttachBackendTc && l.tcDel != nil {
			if err := l.tcDel(); err != nil {
				errs = append(errs, err)
			}
		}
		l.err = errors.Join(errs...)
	})
	return l.err
}

type rustTcAttachReport struct {
	Backend            string  `json:"backend"`
	RequestedBackend   string  `json:"requested_backend"`
	FallbackUsed       bool    `json:"fallback_used"`
	FallbackError      *string `json:"fallback_error"`
	LinkPath           *string `json:"link_path"`
	TCFilterPersistent bool    `json:"tc_filter_persistent"`
	ProgramName        string  `json:"program_name"`
	Interface          string  `json:"iface"`
	Netns              *string `json:"netns"`
	Direction          string  `json:"direction"`
	Priority           uint16  `json:"priority"`
	Handle             uint32  `json:"handle"`
}

func (c *controlPlaneCore) attachIfaceFilterViaRustAya(ifname string, netnsName string, filter *netlink.BpfFilter, backend tcAttachBackend, tcDel func() error) error {
	programName, err := rustTcProgramNameForFilter(filter)
	if err != nil {
		return err
	}
	direction, err := rustTcDirectionForFilter(filter)
	if err != nil {
		return err
	}
	loaderPinRoot := rustAyaDefaultLoaderPinRoot()
	programRoot := filepath.Join(loaderPinRoot, "programs")
	if _, err := os.Stat(programRoot); err != nil {
		return fmt.Errorf("Rust/Aya pinned program root is not available: %w", err)
	}

	linkKey := rustTcAttachKey(netnsName, ifname, filter)
	if old, ok := activeRustTcLinks.LoadAndDelete(linkKey); ok {
		if err := old.(*trackedRustTcAttach).Close(); err != nil {
			c.log.Warnf("close stale Rust/Aya TC attach before reattach for %s on %s: %v", filter.Name, ifname, err)
		}
	}

	linkRoot := rustAyaTcLinkRoot(loaderPinRoot, os.Getpid(), time.Now(), netnsName, ifname, filter)
	args := []string{
		"tc-attach", "attach-pin",
		"--program-root", programRoot,
		"--link-root", linkRoot,
		"--program-name", programName,
		"--iface", ifname,
		"--direction", direction,
		"--priority", strconv.Itoa(int(filter.Priority)),
		"--handle", strconv.FormatUint(uint64(filter.Handle), 10),
		"--backend", rustTcAttachBackendArg(backend),
		"--filter-name", filter.Name,
	}
	if netnsName != "" {
		args = append(args, "--netns", netnsName)
	}
	out, err := runRustBpfLoaderHelperOutput(args...)
	if err != nil {
		_ = os.RemoveAll(linkRoot)
		return err
	}
	report, err := parseRustTcAttachReport(out)
	if err != nil {
		_ = os.RemoveAll(linkRoot)
		return err
	}
	actualBackend, err := rustTcAttachBackendFromReport(report.Backend)
	if err != nil {
		_ = os.RemoveAll(linkRoot)
		return err
	}

	c.log.Infof("Bind %s via Rust/Aya %s on %s", filter.Name, actualBackend, ifname)
	if report.FallbackUsed && report.FallbackError != nil && *report.FallbackError != "" {
		c.log.Warnf("Rust/Aya TCX attach fallback for %s on %s: %s", filter.Name, ifname, *report.FallbackError)
	}
	c.recordAttachBackend(filter, actualBackend)
	if actualBackend == tcAttachBackendTcx {
		if err := tcDel(); err != nil {
			c.log.Warnf("cleanup stale tc filter after Rust/Aya TCX attach for %s on %s: %v", filter.Name, ifname, err)
		}
	}

	tracked := &trackedRustTcAttach{
		linkRoot: linkRoot,
		tcDel:    tcDel,
		backend:  actualBackend,
	}
	activeRustTcLinks.Store(linkKey, tracked)
	c.deferFuncs = append(c.deferFuncs, func() error {
		if current, ok := activeRustTcLinks.Load(linkKey); ok && current == tracked {
			activeRustTcLinks.Delete(linkKey)
		}
		return tracked.Close()
	})
	return nil
}

func parseRustTcAttachReport(out string) (rustTcAttachReport, error) {
	var report rustTcAttachReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		return report, fmt.Errorf("parse Rust/Aya tc attach output: %w: %s", err, strings.TrimSpace(out))
	}
	return report, nil
}

func rustTcProgramNameForFilter(filter *netlink.BpfFilter) (string, error) {
	prefix := consts.AppName + "_"
	if !strings.HasPrefix(filter.Name, prefix) {
		return "", fmt.Errorf("cannot derive Rust/Aya program name from filter %q", filter.Name)
	}
	return "tproxy_" + strings.TrimPrefix(filter.Name, prefix), nil
}

func rustTcDirectionForFilter(filter *netlink.BpfFilter) (string, error) {
	switch filter.Parent {
	case netlink.HANDLE_MIN_INGRESS:
		return "ingress", nil
	case netlink.HANDLE_MIN_EGRESS:
		return "egress", nil
	default:
		return "", fmt.Errorf("unsupported tc parent %#x for Rust/Aya attach of %s", filter.Parent, filter.Name)
	}
}

func rustTcAttachBackendArg(backend tcAttachBackend) string {
	switch backend {
	case tcAttachBackendTcx:
		return "tcx"
	case tcAttachBackendTc:
		return "tc_netlink"
	default:
		return "auto"
	}
}

func rustTcAttachBackendFromReport(backend string) (tcAttachBackend, error) {
	switch strings.TrimSpace(strings.ToLower(backend)) {
	case "tcx":
		return tcAttachBackendTcx, nil
	case "tc", "tc_netlink", "tc-netlink":
		return tcAttachBackendTc, nil
	default:
		return "", fmt.Errorf("unsupported Rust/Aya tc attach backend %q", backend)
	}
}

func rustTcAttachKey(netnsName string, ifname string, filter *netlink.BpfFilter) string {
	return fmt.Sprintf("%s:%s:%d:%#x:%s", netnsName, ifname, filter.LinkIndex, filter.Parent, filter.Name)
}

func rustAyaTcLinkRoot(loaderPinRoot string, pid int, now time.Time, netnsName string, ifname string, filter *netlink.BpfFilter) string {
	return filepath.Join(
		loaderPinRoot,
		"tc_links",
		"cp_"+strconv.Itoa(pid)+"_"+strconv.FormatInt(now.UnixNano(), 10)+"_"+sanitizeRustTcLinkPart(netnsName)+"_"+sanitizeRustTcLinkPart(ifname)+"_"+sanitizeRustTcLinkPart(filter.Name),
	)
}

func sanitizeRustTcLinkPart(value string) string {
	if strings.TrimSpace(value) == "" {
		return "host"
	}
	var b strings.Builder
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('_')
	}
	if b.Len() == 0 {
		return "host"
	}
	return b.String()
}

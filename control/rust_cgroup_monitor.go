/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

const rustAyaLoaderPinDirName = "rust_aya_loader"

func rustAyaLoaderPinRoot(basePinPath string) string {
	return filepath.Join(basePinPath, rustAyaLoaderPinDirName)
}

func rustAyaDefaultLoaderPinRoot() string {
	return rustAyaLoaderPinRoot(filepath.Join(consts.BpfPinRoot, consts.AppName))
}

func rustAyaCgroupLinkRoot(loaderPinRoot string, pid int, now time.Time) string {
	return filepath.Join(
		loaderPinRoot,
		"cgroup_links",
		"cp_"+strconv.Itoa(pid)+"_"+strconv.FormatInt(now.UnixNano(), 10),
	)
}

func (c *controlPlaneCore) setupSkPidMonitorViaRustAya(cgroupPath string) error {
	loaderPinRoot := rustAyaDefaultLoaderPinRoot()
	programRoot := filepath.Join(loaderPinRoot, "programs")
	if _, err := os.Stat(programRoot); err != nil {
		return fmt.Errorf("Rust/Aya pinned program root is not available: %w", err)
	}

	linkRoot := rustAyaCgroupLinkRoot(loaderPinRoot, os.Getpid(), time.Now())
	out, err := runRustBpfLoaderHelperOutput(
		"cgroup-monitor", "attach-pin",
		"--program-root", programRoot,
		"--link-root", linkRoot,
		"--cgroup-path", cgroupPath,
	)
	if err != nil {
		_ = os.RemoveAll(linkRoot)
		return err
	}
	c.log.Debugf("Rust/Aya cgroup pname monitor attach output: %s", out)
	c.deferFuncs = append(c.deferFuncs, func() error {
		if err := os.RemoveAll(linkRoot); err != nil {
			return fmt.Errorf("remove Rust/Aya cgroup pname monitor links %s: %w", linkRoot, err)
		}
		return nil
	})
	return nil
}

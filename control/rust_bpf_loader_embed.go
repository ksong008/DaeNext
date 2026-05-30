//go:build embedallowed

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"crypto/sha256"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

//go:embed embedded/dae-aya-bpf-loader
var embeddedRustBpfLoaderFS embed.FS

var (
	embeddedRustBpfLoaderOnce sync.Once
	embeddedRustBpfLoaderFile string
	embeddedRustBpfLoaderErr  error
)

func embeddedRustBpfLoaderPath() (string, error) {
	embeddedRustBpfLoaderOnce.Do(func() {
		data, err := embeddedRustBpfLoaderFS.ReadFile("embedded/dae-aya-bpf-loader")
		if err != nil {
			embeddedRustBpfLoaderErr = fmt.Errorf("read embedded rust bpf loader: %w", err)
			return
		}
		if len(data) == 0 {
			embeddedRustBpfLoaderErr = errEmbeddedRustBpfLoaderUnavailable
			return
		}

		sum := sha256.Sum256(data)
		dir, err := embeddedRustBpfLoaderCacheDir()
		if err != nil {
			embeddedRustBpfLoaderErr = err
			return
		}

		path := filepath.Join(dir, fmt.Sprintf("dae-aya-bpf-loader-%x", sum[:8]))
		if existing, err := os.ReadFile(path); err == nil {
			existingSum := sha256.Sum256(existing)
			if existingSum == sum {
				if err := os.Chmod(path, 0700); err != nil {
					embeddedRustBpfLoaderErr = fmt.Errorf("chmod cached embedded rust bpf loader: %w", err)
					return
				}
				embeddedRustBpfLoaderFile = path
				return
			}
		}

		tmp, err := os.CreateTemp(dir, ".dae-aya-bpf-loader-*")
		if err != nil {
			embeddedRustBpfLoaderErr = fmt.Errorf("create embedded rust bpf loader temp file: %w", err)
			return
		}
		tmpPath := tmp.Name()
		defer func() {
			if embeddedRustBpfLoaderErr != nil {
				_ = os.Remove(tmpPath)
			}
		}()
		if _, err := tmp.Write(data); err != nil {
			_ = tmp.Close()
			embeddedRustBpfLoaderErr = fmt.Errorf("write embedded rust bpf loader: %w", err)
			return
		}
		if err := tmp.Chmod(0700); err != nil {
			_ = tmp.Close()
			embeddedRustBpfLoaderErr = fmt.Errorf("chmod embedded rust bpf loader: %w", err)
			return
		}
		if err := tmp.Close(); err != nil {
			embeddedRustBpfLoaderErr = fmt.Errorf("close embedded rust bpf loader: %w", err)
			return
		}
		if err := os.Rename(tmpPath, path); err != nil {
			embeddedRustBpfLoaderErr = fmt.Errorf("install embedded rust bpf loader: %w", err)
			return
		}
		embeddedRustBpfLoaderFile = path
	})
	return embeddedRustBpfLoaderFile, embeddedRustBpfLoaderErr
}

func embeddedRustBpfLoaderCacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		base = os.TempDir()
	}
	dir := filepath.Join(base, "dae", "embedded-helpers")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create embedded rust bpf loader cache dir: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return "", fmt.Errorf("chmod embedded rust bpf loader cache dir: %w", err)
	}
	return dir, nil
}

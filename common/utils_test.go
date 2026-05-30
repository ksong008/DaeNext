/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package common

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestEnsureFileInSubDirAllowsNormalPath(t *testing.T) {
	dir := t.TempDir()
	if err := EnsureFileInSubDir(filepath.Join(dir, "child", "file.txt"), dir); err != nil {
		t.Fatalf("EnsureFileInSubDir() returned error: %v", err)
	}
}

func TestEnsureFileInSubDirAllowsDotPrefixedChild(t *testing.T) {
	dir := t.TempDir()
	if err := EnsureFileInSubDir(filepath.Join(dir, "..sibling", "file.txt"), dir); err != nil {
		t.Fatalf("EnsureFileInSubDir() returned error: %v", err)
	}
}

func TestEnsureFileInSubDirRejectsLexicalEscape(t *testing.T) {
	dir := t.TempDir()
	if err := EnsureFileInSubDir(filepath.Join(dir, "..", "escape.txt"), dir); err == nil {
		t.Fatal("expected lexical escape to be rejected")
	}
}

func TestEnsureFileInSubDirRejectsSymlinkDirectoryEscape(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(dir, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink not available: %v", err)
	}

	if err := EnsureFileInSubDir(filepath.Join(link, "file.txt"), dir); err == nil {
		t.Fatal("expected symlink directory escape to be rejected")
	}
}

func TestEnsureFileInSubDirRejectsSymlinkFileEscape(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "target.txt")
	if err := os.WriteFile(target, []byte("outside"), 0600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not available: %v", err)
	}

	if err := EnsureFileInSubDir(link, dir); err == nil {
		t.Fatal("expected symlink file escape to be rejected")
	}
}

func TestRouteIsDefaultAcceptsNilAndZeroPrefix(t *testing.T) {
	_, v4Default, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		t.Fatalf("parse v4 default: %v", err)
	}
	_, v6Default, err := net.ParseCIDR("::/0")
	if err != nil {
		t.Fatalf("parse v6 default: %v", err)
	}
	_, v4Route, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatalf("parse non-default route: %v", err)
	}

	tests := []struct {
		name  string
		route netlink.Route
		want  bool
	}{
		{name: "nil destination", route: netlink.Route{}, want: true},
		{name: "ipv4 zero prefix", route: netlink.Route{Dst: v4Default}, want: true},
		{name: "ipv6 zero prefix", route: netlink.Route{Dst: v6Default}, want: true},
		{name: "non-default prefix", route: netlink.Route{Dst: v4Route}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := routeIsDefault(tt.route); got != tt.want {
				t.Fatalf("routeIsDefault() = %v, want %v", got, tt.want)
			}
		})
	}
}

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package internal

import "testing"

func TestBuildSudoArgsUsesPreserveEnvAllowlist(t *testing.T) {
	args := buildSudoArgs("/usr/bin/sudo")
	if len(args) != 5 {
		t.Fatalf("len(args) = %d, want 5", len(args))
	}
	if args[0] != "/usr/bin/sudo" {
		t.Fatalf("args[0] = %q, want /usr/bin/sudo", args[0])
	}
	if args[1] != "--preserve-env="+sudoPreserveEnv {
		t.Fatalf("args[1] = %q, want preserve-env allowlist", args[1])
	}
	if args[2] != "-p" {
		t.Fatalf("args[2] = %q, want -p", args[2])
	}
	if args[4] != "--" {
		t.Fatalf("args[4] = %q, want --", args[4])
	}
	for _, arg := range args {
		if arg == "-E" {
			t.Fatal("unexpected sudo -E in args")
		}
	}
}

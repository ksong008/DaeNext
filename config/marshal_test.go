/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestMarshal(t *testing.T) {
	abs, err := filepath.Abs("../example.dae")
	if err != nil {
		t.Fatal(err)
	}
	example, err := os.ReadFile(abs)
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()
	entry := filepath.Join(tmpDir, "example.dae")
	if err := os.WriteFile(entry, example, 0640); err != nil {
		t.Fatal(err)
	}

	merger := NewMerger(entry)
	sections, _, err := merger.Merge()
	if err != nil {
		t.Fatal(err)
	}
	conf1, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	b, err := conf1.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(b))
	// Read it again.
	roundTripPath := filepath.Join(tmpDir, "roundtrip.dae")
	if err = os.WriteFile(roundTripPath, b, 0640); err != nil {
		t.Fatal(err)
	}
	sections, _, err = NewMerger(roundTripPath).Merge()
	if err != nil {
		t.Fatal(err)
	}
	conf2, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(conf1, conf2) {
		t.Fatal("not equal")
	}
}

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func normalizeConfigForMarshalTest(conf *Config) *Config {
	if conf == nil {
		return nil
	}
	normalized := *conf
	if conf.Group != nil {
		normalized.Group = make([]Group, len(conf.Group))
		copy(normalized.Group, conf.Group)
		for i := range normalized.Group {
			normalized.Group[i].FilterAnnotation = nil
		}
	}
	return &normalized
}

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

	if !reflect.DeepEqual(normalizeConfigForMarshalTest(conf1), normalizeConfigForMarshalTest(conf2)) {
		t.Fatal("not equal")
	}
}

func TestMarshalKeyableStringWithNonBareTag(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
routing {}
node {
  "14.[SG]Oracle-Sg:vless://uuid@example.com:443?security=tls&type=tcp#%5BSG%5DOracle-Sg"
  node1: "vless://uuid@example.com:443"
}
`)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}

	b, err := conf.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if strings.Contains(text, `14.[SG]Oracle-Sg:"`) {
		t.Fatalf("non-bare tag must not be marshaled as a declaration:\n%s", text)
	}
	if !strings.Contains(text, `"14.[SG]Oracle-Sg:vless://uuid@example.com:443?security=tls&type=tcp#%5BSG%5DOracle-Sg"`) {
		t.Fatalf("non-bare tag was not preserved as a quoted literal:\n%s", text)
	}
	if !strings.Contains(text, `node1:"vless://uuid@example.com:443"`) {
		t.Fatalf("bare tag declaration changed unexpectedly:\n%s", text)
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "roundtrip.dae")
	if err := os.WriteFile(path, b, 0640); err != nil {
		t.Fatal(err)
	}
	sections, _, err = NewMerger(path).Merge()
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(conf.Node, roundTrip.Node) {
		t.Fatalf("node list did not round-trip:\nwant: %#v\n got: %#v", conf.Node, roundTrip.Node)
	}
}

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package config

import (
	"reflect"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestNewReturnsErrorForInvalidRoutingFallbackFunctionList(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}

routing {
	fallback: fixed(0) && fixed(1)
}
`)
	if err != nil {
		t.Fatalf("Parse() returned error: %v", err)
	}

	conf, err := New(sections)
	if err == nil {
		t.Fatalf("expected New() to reject invalid fallback function list, got config: %#v", conf)
	}
	if !strings.Contains(err.Error(), "invalid routing fallback") {
		t.Fatalf("expected routing fallback error, got: %v", err)
	}
}

func TestNewReturnsErrorForInvalidFallbackResolver(t *testing.T) {
	sections, err := config_parser.Parse(`
global {
	fallback_resolver: bad-resolver
}

routing {}
`)
	if err != nil {
		t.Fatalf("Parse() returned error: %v", err)
	}

	conf, err := New(sections)
	if err == nil {
		t.Fatalf("expected New() to reject invalid fallback_resolver, got config: %#v", conf)
	}
	if !strings.Contains(err.Error(), "invalid global.fallback_resolver") {
		t.Fatalf("expected fallback_resolver error, got: %v", err)
	}
}

func TestSectionParserRejectsUnsupportedPointerTarget(t *testing.T) {
	var unsupported int
	err := SectionParser(reflect.ValueOf(&unsupported), &config_parser.Section{Name: "test"})
	if err == nil {
		t.Fatal("expected unsupported target error")
	}
	if !strings.Contains(err.Error(), "unsupported section type") {
		t.Fatalf("unexpected error: %v", err)
	}
}

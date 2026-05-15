/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

func newFilterTestSet(t testing.TB, nodes map[string]string) *DialerSet {
	t.Helper()

	log := logrus.New()
	log.SetOutput(io.Discard)
	option := &dialer.GlobalOption{Log: log}

	set := &DialerSet{
		log:          log,
		dialers:      make([]*dialer.Dialer, 0, len(nodes)),
		nodeToTagMap: make(map[*dialer.Dialer]string, len(nodes)),
	}
	for name, subscriptionTag := range nodes {
		property := &dialer.Property{SubscriptionTag: subscriptionTag}
		property.Name = name
		d := dialer.NewDialer(nil, option, dialer.InstanceOption{DisableCheck: true}, property)
		set.dialers = append(set.dialers, d)
		set.nodeToTagMap[d] = subscriptionTag
	}
	t.Cleanup(func() {
		for _, d := range set.dialers {
			_ = d.Close()
		}
	})
	return set
}

func TestDialerSetFilterAndAnnotateMatchesCompiledFilters(t *testing.T) {
	set := newFilterTestSet(t, map[string]string{
		"HK-Netflix":  "premium-sub",
		"JP-Game":     "game-sub",
		"SG-Standard": "standard-sub",
		"US-Backup":   "backup-sub",
	})

	filters := [][]*config_parser.Function{
		{
			{
				Name: FilterInput_Name,
				Params: []*config_parser.Param{
					{Key: FilterKey_Name_Regex, Val: "^(HK|JP)-"},
				},
			},
			{
				Name: FilterInput_SubscriptionTag,
				Params: []*config_parser.Param{
					{Key: FilterInput_SubscriptionTag_Regex, Val: "premium|game"},
				},
			},
		},
		{
			{
				Name: FilterInput_Name,
				Params: []*config_parser.Param{
					{Key: FilterKey_Name_Keyword, Val: "Backup"},
				},
			},
		},
	}
	annotations := [][]*config_parser.Param{
		{{Key: dialer.AnnotationKey_AddLatency, Val: "10ms"}},
		{{Key: dialer.AnnotationKey_AddLatency, Val: "25ms"}},
	}

	gotDialers, gotAnnotations, err := set.FilterAndAnnotate(filters, annotations)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotDialers) != 3 {
		t.Fatalf("expected 3 matched dialers, got %d", len(gotDialers))
	}

	wantLatencyByName := map[string]time.Duration{
		"HK-Netflix": 10 * time.Millisecond,
		"JP-Game":    10 * time.Millisecond,
		"US-Backup":  25 * time.Millisecond,
	}
	for i, d := range gotDialers {
		name := d.Property().Name
		wantLatency, ok := wantLatencyByName[name]
		if !ok {
			t.Fatalf("unexpected matched dialer %q", name)
		}
		if gotAnnotations[i].AddLatency != wantLatency {
			t.Fatalf("annotation for %q = %v, want %v", name, gotAnnotations[i].AddLatency, wantLatency)
		}
		delete(wantLatencyByName, name)
	}
	if len(wantLatencyByName) != 0 {
		t.Fatalf("missing matched dialers: %v", wantLatencyByName)
	}
}

func TestDialerSetFilterAndAnnotateBadRegex(t *testing.T) {
	set := newFilterTestSet(t, map[string]string{
		"HK-Netflix": "premium-sub",
	})

	_, _, err := set.FilterAndAnnotate(
		[][]*config_parser.Function{
			{
				{
					Name: FilterInput_Name,
					Params: []*config_parser.Param{
						{Key: FilterKey_Name_Regex, Val: "["},
					},
				},
			},
		},
		[][]*config_parser.Param{{}},
	)
	if err == nil {
		t.Fatal("expected bad regex to fail")
	}
}

func TestDialerSetFilterAndAnnotateEmptySetDoesNotCompileFilters(t *testing.T) {
	set := &DialerSet{}

	_, _, err := set.FilterAndAnnotate(
		[][]*config_parser.Function{
			{
				{
					Name: FilterInput_Name,
					Params: []*config_parser.Param{
						{Key: FilterKey_Name_Regex, Val: "["},
					},
				},
			},
		},
		[][]*config_parser.Param{{}},
	)
	if err != nil {
		t.Fatalf("empty dialer set should keep previous lenient behavior, got %v", err)
	}
}

func BenchmarkDialerSetFilterAndAnnotateRegex(b *testing.B) {
	nodes := make(map[string]string, 1000)
	for i := 0; i < 1000; i++ {
		nodes[fmt.Sprintf("HK-Node-%04d", i)] = "premium-sub"
	}
	set := newFilterTestSet(b, nodes)

	filters := [][]*config_parser.Function{
		{
			{
				Name: FilterInput_Name,
				Params: []*config_parser.Param{
					{Key: FilterKey_Name_Regex, Val: "^HK-Node-"},
				},
			},
			{
				Name: FilterInput_SubscriptionTag,
				Params: []*config_parser.Param{
					{Key: FilterInput_SubscriptionTag_Regex, Val: "^premium-"},
				},
			},
		},
	}
	annotations := [][]*config_parser.Param{{}}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := set.FilterAndAnnotate(filters, annotations); err != nil {
			b.Fatal(err)
		}
	}
}

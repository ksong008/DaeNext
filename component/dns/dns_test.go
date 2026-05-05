/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

package dns

import (
	"errors"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/config"
	"github.com/sirupsen/logrus"
)

func TestNewRejectsDuplicateUpstreamTags(t *testing.T) {
	_, err := New(&config.Dns{
		Upstream: []config.KeyableString{
			"dup:udp://1.1.1.1:53",
			"dup:udp://8.8.8.8:53",
		},
		Routing: config.DnsRouting{
			Request:  config.DnsRequestRouting{Fallback: "dup"},
			Response: config.DnsResponseRouting{Fallback: "dup"},
		},
	}, &NewOption{Logger: logrus.New()})
	if !errors.Is(err, ErrBadUpstreamFormat) || !strings.Contains(err.Error(), "duplicated upstream tag") {
		t.Fatalf("New() error = %v, want duplicated upstream tag", err)
	}
}

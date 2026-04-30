/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package trace

import "testing"

func TestParseRingbufSizeBytes(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    uint32
		wantErr bool
	}{
		{name: "default when empty", input: "", want: DefaultRingbufSizeBytes()},
		{name: "parse mib suffix", input: "64MiB", want: 64 << 20},
		{name: "parse bytes", input: "67108864", want: 64 << 20},
		{name: "parse kib suffix", input: "4KiB", want: 4 << 10},
		{name: "reject non power of two", input: "96MiB", wantErr: true},
		{name: "reject below minimum", input: "2KiB", wantErr: true},
		{name: "reject invalid text", input: "nope", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseRingbufSizeBytes(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil and value %d", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("ParseRingbufSizeBytes(%q) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

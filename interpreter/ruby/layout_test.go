// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ruby

import "testing"

func TestRubyUses406Layout(t *testing.T) {
	for _, tc := range []struct {
		name        string
		version     uint32
		description string
		want        bool
	}{
		{
			name:        "pshopify 4.0.5 revision",
			version:     rubyVersion(4, 0, 5),
			description: "ruby 4.0.5 (2026-07-09 revision 21a2595676) [x86_64-linux]",
			want:        true,
		},
		{
			name:        "pshopify runtime description suffix",
			version:     rubyVersion(4, 0, 5),
			description: "ruby 4.0.5 (2026-07-09 revision 21a2595676) +PRISM [x86_64-linux]",
			want:        true,
		},
		{
			name:        "stock 4.0.5",
			version:     rubyVersion(4, 0, 5),
			description: "ruby 4.0.5 (2026-01-01 revision abcdef0123) [x86_64-linux]",
			want:        false,
		},
		{
			name:        "4.0.1 never matches revision exception",
			version:     rubyVersion(4, 0, 1),
			description: "ruby 4.0.1 (2026-01-01 revision 21a2595676) [x86_64-linux]",
			want:        false,
		},
		{name: "4.0.6", version: rubyVersion(4, 0, 6), want: true},
		{name: "4.0.7", version: rubyVersion(4, 0, 7), want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := rubyUses406Layout(tc.version, tc.description); got != tc.want {
				t.Fatalf("rubyUses406Layout(%#x, %q) = %v, want %v",
					tc.version, tc.description, got, tc.want)
			}
		})
	}
}

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

func TestRubyUses41Layout(t *testing.T) {
	const description = "ruby 4.1.0dev (2026-09-28T21:54:22Z shopify a68e42cfad) +ZJIT +PRISM [x86_64-linux]"
	for _, tc := range []struct {
		name        string
		version     uint32
		revision    string
		description string
		want        bool
	}{
		{name: "audited revision", version: rubyVersion(4, 1, 0), revision: ruby41Revision, want: true},
		{name: "other development revision", version: rubyVersion(4, 1, 0), revision: "8fdf434201a0a4e9b9a3d6c1f1b8dd4a4a4c5e51"},
		{name: "abbreviated revision", version: rubyVersion(4, 1, 0), revision: ruby41Revision[:10]},
		{name: "no revision or description", version: rubyVersion(4, 1, 0)},
		{name: "stripped revision, audited description", version: rubyVersion(4, 1, 0), description: description, want: true},
		{name: "revision wins over description", version: rubyVersion(4, 1, 0), revision: "other", description: description},
		{name: "description with short revision", version: rubyVersion(4, 1, 0), description: "ruby 4.1.0dev (date shopify a68e42cfa)"},
		{name: "release description", version: rubyVersion(4, 1, 0), description: "ruby 4.1.0 (date shopify a68e42cfad)"},
		{name: "4.0.7", version: rubyVersion(4, 0, 7), revision: ruby41Revision},
		{name: "4.1.1", version: rubyVersion(4, 1, 1), revision: ruby41Revision},
		{name: "4.2.0", version: rubyVersion(4, 2, 0), revision: ruby41Revision},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := rubyUses41Layout(tc.version, tc.revision, tc.description); got != tc.want {
				t.Fatalf("rubyUses41Layout(%#x, %q, %q) = %v, want %v",
					tc.version, tc.revision, tc.description, got, tc.want)
			}
		})
	}
}

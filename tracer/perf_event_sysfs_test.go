// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/elastic/go-perf"
	"github.com/stretchr/testify/require"
)

func TestReadPerfEventAttr(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "events"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "format"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "type"), []byte("4\n"), 0o644))
	require.NoError(t, os.WriteFile(
		filepath.Join(root, "events", "slots"), []byte("event=0x00,umask=0x04\n"), 0o644))
	require.NoError(t, os.WriteFile(
		filepath.Join(root, "format", "event"), []byte("config:0-7\n"), 0o644))
	require.NoError(t, os.WriteFile(
		filepath.Join(root, "format", "umask"), []byte("config:8-15\n"), 0o644))

	attr, err := readPerfEventAttr(root, "slots")
	require.NoError(t, err)
	require.Equal(t, "slots", attr.Label)
	require.Equal(t, perf.RawEvent, attr.Type)
	require.Equal(t, uint64(0x0400), attr.Config)
}

func TestApplyPerfEventFormatDiscontiguousBits(t *testing.T) {
	attr := new(perf.Attr)
	require.NoError(t, applyPerfEventFormat(attr, "config1:1,6-8", 0b1101))
	require.Equal(t, uint64(1<<1|0b110<<6), attr.Config1)
}

func TestApplyPerfEventFormatRejectsMoreThan64SourceBits(t *testing.T) {
	attr := new(perf.Attr)
	err := applyPerfEventFormat(attr, "config:0-63,0", 0)
	require.EqualError(t, err, "bit ranges exceed 64 source bits")
}

func TestReadPerfEventAttrRejectsUnknownEncodingField(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "events"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "format"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "type"), []byte("4\n"), 0o644))
	require.NoError(t, os.WriteFile(
		filepath.Join(root, "events", "slots"), []byte("unknown=1\n"), 0o644))

	_, err := readPerfEventAttr(root, "slots")
	require.ErrorContains(t, err, `read event "slots" format "unknown"`)
}
